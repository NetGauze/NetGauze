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

use nom::{error::ErrorKind, number::complete::be_u8, IResult};
use serde::{Deserialize, Serialize};

use netgauze_parse_utils::{ErrorKindSerdeDeref, ReadablePDUWithOneInput, Span};
use netgauze_serde_macros::LocatedError;

use crate::community::UnknownExtendedCommunity;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UnknownExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePDUWithOneInput<'a, u8, LocatedUnknownExtendedCommunityParsingError<'a>>
    for UnknownExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
        code: u8,
    ) -> IResult<Span<'a>, Self, LocatedUnknownExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let input = buf;
        let (buf, value) = nom::multi::count(be_u8, 6)(buf)?;
        let len = value.len();
        let value: [u8; 6] = value.try_into().map_err(|_| {
            nom::Err::Error(LocatedUnknownExtendedCommunityParsingError::new(
                input,
                UnknownExtendedCommunityParsingError::InvalidValueLength(len),
            ))
        })?;
        Ok((buf, UnknownExtendedCommunity::new(code, sub_type, value)))
    }
}
