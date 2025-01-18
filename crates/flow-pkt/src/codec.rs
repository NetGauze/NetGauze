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

//! Code to handle decode/encoding of IPFIX and Netflow V9 packets
//! It works with [`FlowInfo`] which is enum that combine both IPFIX and Netflow
//! V9 into one object to make it easier to handle.

use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use nom::Needed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio_util::codec::{Decoder, Encoder};
use tracing::instrument;

use crate::{
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

/// [`FlowInfo`] is either IPFIX or Netflow V9 packet.
/// This struct keep track of the decode process, and keep a cache of the
/// templates sent by client.
#[derive(Debug, Default)]
pub struct FlowInfoCodec {
    /// Helper to track in the decoder if we are inside a message or not
    netflow_v9_templates_map: netflow::TemplatesMap,
    ipfix_templates_map: ipfix::TemplatesMap,
}

impl FlowInfoCodec {
    pub fn new() -> Self {
        Self {
            netflow_v9_templates_map: HashMap::new(),
            ipfix_templates_map: HashMap::new(),
        }
    }

    /// Get immutable reference to the Netflow V9 templates map
    pub const fn netflow_templates_map(&self) -> &netflow::TemplatesMap {
        &self.netflow_v9_templates_map
    }

    /// Get mutable reference to the Netflow V9 templates map
    pub fn netflow_templates_map_mut(&mut self) -> &mut netflow::TemplatesMap {
        &mut self.netflow_v9_templates_map
    }

    /// Get immutable reference to the IPFIX V10 templates map
    pub const fn ipfix_templates_map(&self) -> &ipfix::TemplatesMap {
        &self.ipfix_templates_map
    }

    /// Get mutable reference to the IPFIX V10 templates map
    pub fn ipfix_templates_map_mut(&mut self) -> &mut ipfix::TemplatesMap {
        &mut self.ipfix_templates_map
    }
}

impl Encoder<ipfix::IpfixPacket> for FlowInfoCodec {
    type Error = IpfixPacketWritingError;

    fn encode(&mut self, pkt: ipfix::IpfixPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(4 + pkt.len(Some(&self.ipfix_templates_map)));
        let mut writer = dst.writer();
        pkt.write(&mut writer, Some(&self.ipfix_templates_map))?;
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
        dst.reserve(4 + pkt.len(Some(&self.netflow_v9_templates_map)));
        let mut writer = dst.writer();
        pkt.write(&mut writer, Some(&self.netflow_v9_templates_map))?;
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
    templates_map: &mut ipfix::TemplatesMap,
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
    templates_map: &mut netflow::TemplatesMap,
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
        if buf.len() < header_length {
            // We don't have enough data yet to start processing
            return Ok(None);
        }
        let version: u16 = NetworkEndian::read_u16(&buf[0..2]);
        // Read the length (ipfix) or count (NetFlow v9), starting from after the
        // version
        let length = NetworkEndian::read_u16(&buf[2..4]) as usize;
        if buf.len() < length {
            // We still didn't read all the bytes for the message yet
            return Ok(None);
        }
        if version == ipfix::IPFIX_VERSION {
            parse_ipfix(buf, length, &mut self.ipfix_templates_map)
        } else if version == netflow::NETFLOW_V9_VERSION {
            parse_netflow_v9(buf, &mut self.netflow_v9_templates_map)
        } else {
            let err = FlowInfoCodecDecoderError::UnsupportedVersion(version);
            buf.clear();
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decode_partial_messages() {
        // Partial IPFIX packet
        let value1: Vec<u8> = vec![
            0x00, 0x0a, // Version
            0x00, 0x74, // Length = 116 bytes
            0x58, 0x3d, 0xe0, 0x59, // Export time
            0x00, 0x00, 0x0e, 0xe4, // Seq number
            0x00, 0x00, 0x00, 0x00, // Observation domain
            0xff,
            0x01, // Arbitrary values with length less than the 116 specified in the header
        ];
        // Second part of the packet is less than header length
        let value2: Vec<u8> = vec![0x01];
        let mut buf1 = BytesMut::from_iter(value1.iter());
        let mut buf2 = BytesMut::from_iter(value2.iter());

        let mut codec = FlowInfoCodec::new();
        let ret1 = codec.decode(&mut buf1);
        // message is incomplete, should be ignored
        assert_eq!(ret1, Ok(None));
        // message is incomplete, should be ignored
        let ret2 = codec.decode(&mut buf2);
        assert_eq!(ret2, Ok(None));
    }
}
