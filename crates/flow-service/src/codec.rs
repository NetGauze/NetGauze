// Copyright (C) 2023-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use netgauze_flow_pkt::{
    ipfix, netflow,
    wire::{
        deserializer::{
            ipfix::{IpfixPacketParsingError, IPFIX_HEADER_LENGTH},
            netflow::NetFlowV9PacketParsingError,
        },
        serializer::{
            ipfix::IpfixPacketWritingError, netflow::NetFlowV9WritingError, FlowWritingError,
        },
    },
    FlowInfo,
};
use netgauze_parse_utils::{
    LocatedParsingError, ReadablePduWithOneInput, Span, WritablePduWithOneInput,
};
use nom::Needed;
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};
use tracing::instrument;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FlowInfoCodecDecoderError {
    IoError(String),
    Incomplete(Option<usize>),
    UnsupportedVersion(u16),
    IpfixParsingError(IpfixPacketParsingError),
    NetFlowV9ParingError(NetFlowV9PacketParsingError),
}

impl From<std::io::Error> for FlowInfoCodecDecoderError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

#[derive(Debug, Default)]
pub struct FlowInfoCodec {
    /// Helper to track in the decoder if we are inside a message or not
    in_message: bool,
    netflow_v9_templates_map: netflow::TemplatesMap,
    ipfix_templates_map: ipfix::TemplatesMap,
}

impl Encoder<ipfix::IpfixPacket> for FlowInfoCodec {
    type Error = IpfixPacketWritingError;

    fn encode(&mut self, pkt: ipfix::IpfixPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(4 + pkt.len(Some(self.ipfix_templates_map.clone())));
        let mut writer = dst.writer();
        pkt.write(&mut writer, Some(self.ipfix_templates_map.clone()))?;
        Ok(())
    }
}

impl Encoder<netflow::NetFlowV9Packet> for FlowInfoCodec {
    type Error = NetFlowV9WritingError;

    fn encode(
        &mut self,
        pkt: netflow::NetFlowV9Packet,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(4 + pkt.len(Some(self.netflow_v9_templates_map.clone())));
        let mut writer = dst.writer();
        pkt.write(&mut writer, Some(self.netflow_v9_templates_map.clone()))?;
        Ok(())
    }
}

impl Encoder<FlowInfo> for FlowInfoCodec {
    type Error = FlowWritingError;

    fn encode(&mut self, pkt: FlowInfo, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match pkt {
            FlowInfo::IPFIX(pkt) => self.encode(pkt, dst)?,
            FlowInfo::NetFlowV9(pkt) => self.encode(pkt, dst)?,
        }
        Ok(())
    }
}

#[instrument(skip_all)]
fn parse_ipfix(
    buf: &mut BytesMut,
    length: usize,
    templates_map: ipfix::TemplatesMap,
) -> Result<Option<FlowInfo>, FlowInfoCodecDecoderError> {
    let msg = match ipfix::IpfixPacket::from_wire(Span::new(buf), templates_map) {
        Ok((span, msg)) => {
            buf.advance(span.location_offset());
            msg
        }
        Err(error) => {
            let err = match error {
                nom::Err::Incomplete(needed) => {
                    let needed = match needed {
                        Needed::Unknown => None,
                        Needed::Size(size) => Some(size.get()),
                    };
                    FlowInfoCodecDecoderError::Incomplete(needed)
                }
                nom::Err::Error(error) | nom::Err::Failure(error) => {
                    FlowInfoCodecDecoderError::IpfixParsingError(error.error().clone())
                }
            };
            // Make sure we advance the buffer far enough, so we don't get stuck on
            // an error value.
            buf.advance(if length < 5 { 5 } else { length });
            return Err(err);
        }
    };
    Ok(Some(FlowInfo::IPFIX(msg)))
}

#[instrument(skip_all)]
fn parse_netflow_v9(
    buf: &mut BytesMut,
    templates_map: netflow::TemplatesMap,
) -> Result<Option<FlowInfo>, FlowInfoCodecDecoderError> {
    let msg = match netflow::NetFlowV9Packet::from_wire(Span::new(buf), templates_map) {
        Ok((span, msg)) => {
            buf.advance(span.location_offset());
            msg
        }
        Err(error) => {
            let err = match error {
                nom::Err::Incomplete(needed) => {
                    let needed = match needed {
                        Needed::Unknown => None,
                        Needed::Size(size) => Some(size.get()),
                    };
                    FlowInfoCodecDecoderError::Incomplete(needed)
                }
                nom::Err::Error(error) | nom::Err::Failure(error) => {
                    FlowInfoCodecDecoderError::NetFlowV9ParingError(error.error().clone())
                }
            };
            // Netflow v9 doesn't have a length component to tell us how many bytes
            // should skip for the next packet. Sadly, our best bet is to clear the
            // buffer and start over at the risk of discarding other good packets in
            // the buffer.
            buf.clear();
            return Err(err);
        }
    };
    Ok(Some(FlowInfo::NetFlowV9(msg)))
}

impl Decoder for FlowInfoCodec {
    type Item = FlowInfo;
    type Error = FlowInfoCodecDecoderError;

    #[instrument(skip_all)]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // We're using IPFIX_HEADER_LENGTH as criteria to start parsing since it's
        // smaller than NetFlow v9 header size.
        let header_length = IPFIX_HEADER_LENGTH as usize;
        if self.in_message || buf.len() >= header_length {
            let version: u16 = NetworkEndian::read_u16(&buf[0..2]);
            // Read the length (ipfix) or count (NetFlow v9), starting form after the
            // version
            let length = NetworkEndian::read_u16(&buf[2..4]) as usize;
            if buf.len() < length {
                // We still didn't read all the bytes for the message yet
                self.in_message = true;
                Ok(None)
            } else {
                self.in_message = false;
                if version == ipfix::IPFIX_VERSION {
                    parse_ipfix(buf, length, self.ipfix_templates_map.clone())
                } else if version == netflow::NETFLOW_V9_VERSION {
                    parse_netflow_v9(buf, self.netflow_v9_templates_map.clone())
                } else {
                    let err = FlowInfoCodecDecoderError::UnsupportedVersion(version);
                    buf.clear();
                    Err(err)
                }
            }
        } else {
            // We don't have enough data yet to start processing
            Ok(None)
        }
    }
}
