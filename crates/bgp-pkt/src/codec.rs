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
use nom::Needed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    BgpMessage,
    capabilities::BgpCapability,
    wire::{
        deserializer::{BgpMessageParsingError, BgpParsingContext, BgpParsingIgnoredErrors},
        serializer::BgpMessageWritingError,
    },
};
use netgauze_parse_utils::{LocatedParsingError, ReadablePduWithOneInput, Span, WritablePdu};

pub trait BgpCodecInitializer<Peer> {
    fn new(peer: &Peer) -> Self;
}

#[derive(Debug, Clone, Default)]
pub struct BgpCodec {
    asn4_sent: Option<bool>,
    asn4_received: Option<bool>,
    ctx: BgpParsingContext,
}

impl BgpCodec {
    pub fn new(asn4: bool) -> Self {
        Self {
            asn4_sent: Some(asn4),
            asn4_received: Some(asn4),
            ctx: BgpParsingContext::new(
                true,
                HashMap::new(),
                HashMap::new(),
                false,
                false,
                false,
                false,
            ),
        }
    }

    pub fn new_from_ctx(asn4: bool, ctx: BgpParsingContext) -> Self {
        Self {
            asn4_sent: Some(asn4),
            asn4_received: Some(asn4),
            ctx,
        }
    }
}

impl<Peer> BgpCodecInitializer<Peer> for BgpCodec {
    fn new(_peer: &Peer) -> Self {
        BgpCodec::default()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum BgpCodecDecoderError {
    IoError(String),
    Incomplete(Option<usize>),
    BgpMessageParsingError(BgpMessageParsingError),
}

impl From<std::io::Error> for BgpCodecDecoderError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

impl Decoder for BgpCodec {
    type Item = (BgpMessage, BgpParsingIgnoredErrors);
    type Error = BgpCodecDecoderError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() >= 19 {
            let length: u16 = NetworkEndian::read_u16(&buf[16..19]);
            let length = length as usize;
            if buf.len() < length {
                Ok(None)
            } else {
                if log::log_enabled!(log::Level::Debug) {
                    log::debug!("Decoding buffer message: {buf:?}")
                }
                // ASN4 capability is used only when both peers agree on enabling ASN4
                let asn4 = self.asn4_received.unwrap_or(false) && self.asn4_sent.unwrap_or(false);
                self.ctx.set_asn4(asn4);
                let ret = BgpMessage::from_wire(Span::new(buf), &mut self.ctx);
                let decoding_result = match ret {
                    Ok((_span, msg)) => {
                        buf.advance(length);
                        if let BgpMessage::Open(ref open) = msg {
                            let asn4 = open
                                .capabilities()
                                .into_iter()
                                .any(|cap| matches!(cap, BgpCapability::FourOctetAs(_)));
                            log::debug!("Sending ASN4 received to: {asn4}");
                            self.asn4_received = Some(asn4);
                        }
                        Ok(Some((msg, self.ctx.reset_parsing_errors())))
                    }
                    Err(error) => {
                        log::error!("Error: {:?} buf: {:?}", error, buf.to_vec());
                        let err = match error {
                            nom::Err::Incomplete(needed) => {
                                let needed = match needed {
                                    Needed::Unknown => None,
                                    Needed::Size(size) => Some(size.get()),
                                };
                                BgpCodecDecoderError::Incomplete(needed)
                            }
                            nom::Err::Error(error) | nom::Err::Failure(error) => {
                                BgpCodecDecoderError::BgpMessageParsingError(error.error().clone())
                            }
                        };
                        Err(err)
                    }
                };
                if log::log_enabled!(log::Level::Debug) {
                    log::debug!("Decoding buffer result is: {decoding_result:?}");
                }
                decoding_result
            }
        } else {
            Ok(None)
        }
    }
}

impl Encoder<BgpMessage> for BgpCodec {
    type Error = BgpMessageWritingError;

    fn encode(&mut self, msg: BgpMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if log::log_enabled!(log::Level::Debug) {
            log::debug!("Encoding message: {msg:?}")
        }
        if let BgpMessage::Open(ref open) = msg {
            let asn4 = open
                .capabilities()
                .into_iter()
                .any(|cap| matches!(cap, BgpCapability::FourOctetAs(_)));
            log::debug!("Sending ASN4 sent to: {asn4}");
            self.asn4_sent = Some(asn4);
        }
        msg.write(&mut dst.writer())
    }
}
