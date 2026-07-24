// Copyright (C) 2022-present The NetGauze Authors.
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

//! Deserializer library for BMP's wire protocol

pub mod v3;
pub mod v4;

use crate::iana::BmpVersion;
use crate::{BmpMessage, PeerKey};
use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFromWithOneInput;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

/// Counts the type+length+value tuples in a buffer using the 2-byte-type,
/// 2-byte-length TLV framing shared by BMP's Initiation, Termination,
/// Route Mirroring, Peer-Up, and Peer-Down information TLVs. Takes the
/// reader by value (`SliceReader` is `Copy`), so it peeks without
/// disturbing the caller's cursor, and never allocates.
///
/// Purely advisory: a malformed buffer stops the count early rather than
/// returning an error, so it only ever affects the capacity hint, never
/// what the real parsing loop reports.
#[inline]
pub(crate) fn count_tlvs_t16_l16(mut cur: SliceReader<'_>) -> usize {
    let mut count = 0usize;
    loop {
        if cur.is_empty() {
            return count;
        }
        let Ok(_tlv_type) = cur.read_u16_be() else {
            return count;
        };
        let Ok(tlv_length) = cur.read_u16_be() else {
            return count;
        };
        if cur.take_slice(tlv_length as usize).is_err() {
            return count;
        }
        count += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BmpMessageParsingError {
    #[error("while parsing BMP message: {0}")]
    Parse(#[from] ParseError),

    #[error("unsupported BMP version {value} at byte offset {offset} (expected 3 or 4)")]
    UndefinedBmpVersion { offset: usize, value: u8 },

    #[error(
        "invalid BMP message length {length} at byte offset {offset} (must be at least 5, the size of the common header)"
    )]
    InvalidBmpLength { offset: usize, length: u32 },

    #[error(
        "{unparsed_bytes} trailing byte(s) left unparsed at byte offset {offset} in a BMP message declaring length {length}"
    )]
    UnparseableBytes {
        offset: usize,
        length: u32,
        unparsed_bytes: usize,
    },

    #[error("in BMP v3 message: {0}")]
    BmpV3MessageValueError(#[from] v3::BmpMessageValueParsingError),

    #[error("in BMP v4 message: {0}")]
    BmpV4MessageValueError(#[from] v4::BmpMessageValueParsingError),
}

#[derive(Debug, Default, Clone)]
pub struct BmpParsingContext(HashMap<PeerKey, BgpParsingContext>);

impl BmpParsingContext {
    pub fn new(map: HashMap<PeerKey, BgpParsingContext>) -> Self {
        Self(map)
    }

    pub fn peer_count(&self) -> usize {
        self.len()
    }

    pub fn add_peer(&mut self, peer_key: PeerKey, parsing_context: BgpParsingContext) {
        self.insert(peer_key, parsing_context);
    }

    pub fn add_default_peer(&mut self, peer_key: PeerKey) {
        self.add_peer(peer_key, BgpParsingContext::default())
    }

    pub fn delete_peer(&mut self, peer_key: &PeerKey) {
        self.remove(peer_key);
    }

    pub fn get_peer(&mut self, peer_key: &PeerKey) -> Option<&mut BgpParsingContext> {
        self.get_mut(peer_key)
    }
}

impl Deref for BmpParsingContext {
    type Target = HashMap<PeerKey, BgpParsingContext>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BmpParsingContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for BmpMessage {
    type Error = BmpMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let version = cur.read_u8()?;
        let version = match BmpVersion::try_from(version) {
            Ok(version) => version,
            Err(err) => {
                return Err(BmpMessageParsingError::UndefinedBmpVersion {
                    offset: cur.offset() - 1,
                    value: err.0,
                });
            }
        };
        let length = cur.read_u32_be()?;
        let base_length = 5;
        if length < base_length {
            return Err(BmpMessageParsingError::InvalidBmpLength {
                offset: cur.offset() - 4,
                length,
            });
        }
        let mut buf = cur.take_slice(length as usize - 5)?;

        let msg = match version {
            BmpVersion::Version3 => {
                let v3_msg = crate::v3::BmpMessageValue::parse(&mut buf, ctx)?;
                BmpMessage::V3(v3_msg)
            }
            BmpVersion::Version4 => {
                let v4_msg = crate::v4::BmpMessageValue::parse(&mut buf, ctx)?;
                BmpMessage::V4(v4_msg)
            }
        };
        // Make sure bmp message is fully parsed according to it's length
        if !buf.is_empty() {
            return Err(BmpMessageParsingError::UnparseableBytes {
                offset: buf.offset(),
                length,
                unparsed_bytes: buf.remaining(),
            });
        }
        Ok(msg)
    }
}
