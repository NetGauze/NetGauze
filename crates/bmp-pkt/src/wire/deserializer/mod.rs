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

use crate::{
    iana::{BmpVersion, UndefinedBmpVersion},
    wire::deserializer::{
        v3::{BmpMessageValueParsingError, LocatedBmpMessageValueParsingError},
        v4::{BmpV4MessageValueParsingError, LocatedBmpV4MessageValueParsingError},
    },
    BmpMessage, PeerKey,
};
use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_parse_utils::{
    parse_into_located_one_input, ErrorKindSerdeDeref, ReadablePduWithOneInput, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

pub mod v3;
pub mod v4;

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BmpMessageParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpVersion(#[from_external] UndefinedBmpVersion),
    InvalidBmpLength(u32),
    BmpMessageValueError(#[from_located(module = "self")] BmpMessageValueParsingError),
    BmpV4MessageValueError(#[from_located(module = "self")] BmpV4MessageValueParsingError),
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

impl<'a> ReadablePduWithOneInput<'a, &mut BmpParsingContext, LocatedBmpMessageParsingError<'a>>
    for BmpMessage
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BmpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBmpMessageParsingError<'a>> {
        let (buf, version) = nom::combinator::map_res(be_u8, BmpVersion::try_from)(buf)?;
        let input = buf;
        let (buf, length) = be_u32(buf)?;
        let base_length = 5;
        if length < base_length {
            return Err(nom::Err::Error(LocatedBmpMessageParsingError::new(
                input,
                BmpMessageParsingError::InvalidBmpLength(length),
            )));
        }
        let (remainder, buf) = nom::bytes::complete::take(length - 5)(buf)?;

        let (buf, msg) = match version {
            BmpVersion::Version3 => {
                let (buf, value) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpMessage::V3(value))
            }
            BmpVersion::Version4 => {
                let (buf, value) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpMessage::V4(value))
            }
        };
        // Make sure bmp message is fully parsed according to it's length
        if !buf.is_empty() {
            return Err(nom::Err::Error(LocatedBmpMessageParsingError::new(
                buf,
                BmpMessageParsingError::NomError(ErrorKind::NonEmpty),
            )));
        }
        Ok((remainder, msg))
    }
}
