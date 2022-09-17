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

//! Deserializer for BGP Path Attributes

use crate::{
    iana::PathAttributeType,
    path_attribute::{Origin, PathAttribute, PathAttributeLength, UndefinedOrigin},
    serde::deserializer::{
        update::LocatedBGPUpdateMessageParsingError, BGPUpdateMessageParsingError,
    },
};
use netgauze_parse_utils::{ReadablePDU, ReadablePDUWithOneInput, Span};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u16, be_u8},
    IResult,
};

const OPTIONAL_PATH_ATTRIBUTE_MASK: u8 = 0x80;
const TRANSITIVE_PATH_ATTRIBUTE_MASK: u8 = 0x40;
const PARTIAL_PATH_ATTRIBUTE_MASK: u8 = 0x20;
const EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK: u8 = 0x10;
const ORIGIN_LEN: u16 = 1;

#[inline]
const fn check_length(attr_len: PathAttributeLength, expected: u16) -> bool {
    match attr_len {
        PathAttributeLength::U8(len) => len as u16 == expected,
        PathAttributeLength::U16(len) => len == expected,
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum PathAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    OriginError(OriginParsingError),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedPathAttributeParsingError<'a> {
    span: Span<'a>,
    error: PathAttributeParsingError,
}

impl<'a> LocatedPathAttributeParsingError<'a> {
    pub const fn new(span: Span<'a>, error: PathAttributeParsingError) -> Self {
        Self { span, error }
    }

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &PathAttributeParsingError {
        &self.error
    }

    pub const fn into_located_bgp_update_message_error(
        self,
    ) -> LocatedBGPUpdateMessageParsingError<'a> {
        let span = self.span;
        let error = self.error;
        LocatedBGPUpdateMessageParsingError::new(
            span,
            BGPUpdateMessageParsingError::PathAttributeError(error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, PathAttributeParsingError>
    for LocatedPathAttributeParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: PathAttributeParsingError,
    ) -> Self {
        LocatedPathAttributeParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedPathAttributeParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedPathAttributeParsingError::new(input, PathAttributeParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum OriginParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidOriginLength(PathAttributeLength),
    UndefinedOrigin(UndefinedOrigin),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedOriginParsingError<'a> {
    span: Span<'a>,
    error: OriginParsingError,
}

impl<'a> LocatedOriginParsingError<'a> {
    pub const fn new(span: Span<'a>, error: OriginParsingError) -> Self {
        Self { span, error }
    }

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &OriginParsingError {
        &self.error
    }

    pub const fn into_located_attribute_parsing_error(
        self,
    ) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::OriginError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, OriginParsingError> for LocatedOriginParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: OriginParsingError) -> Self {
        LocatedOriginParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedOrigin> for LocatedOriginParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: UndefinedOrigin) -> Self {
        LocatedOriginParsingError::new(input, OriginParsingError::UndefinedOrigin(error))
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedOriginParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedOriginParsingError::new(input, OriginParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedOriginParsingError<'a>> for Origin {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedOriginParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, ORIGIN_LEN) {
            return Err(nom::Err::Error(LocatedOriginParsingError::new(
                input,
                OriginParsingError::InvalidOriginLength(length),
            )));
        }
        let (buf, origin) = nom::combinator::map_res(be_u8, Origin::try_from)(buf)?;
        Ok((buf, origin))
    }
}

impl<'a> ReadablePDU<'a, LocatedPathAttributeParsingError<'a>> for PathAttribute {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedPathAttributeParsingError<'a>> {
        let (buf, attributes) = be_u8(buf)?;
        let buf_before_code = buf;
        let (buf, code) = be_u8(buf)?;
        let optional = attributes & OPTIONAL_PATH_ATTRIBUTE_MASK == OPTIONAL_PATH_ATTRIBUTE_MASK;
        let transitive =
            attributes & TRANSITIVE_PATH_ATTRIBUTE_MASK == TRANSITIVE_PATH_ATTRIBUTE_MASK;
        let partial = attributes & PARTIAL_PATH_ATTRIBUTE_MASK == PARTIAL_PATH_ATTRIBUTE_MASK;
        let extended_length =
            attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
        match PathAttributeType::try_from(code) {
            Ok(PathAttributeType::Origin) => {
                let (buf, origin) = match Origin::from_wire(buf, extended_length) {
                    Ok((buf, origin)) => (buf, origin),
                    Err(err) => {
                        return match err {
                            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                            nom::Err::Error(error) => Err(nom::Err::Error(
                                error.into_located_attribute_parsing_error(),
                            )),
                            nom::Err::Failure(failure) => Err(nom::Err::Failure(
                                failure.into_located_attribute_parsing_error(),
                            )),
                        }
                    }
                };
                let path_attr = PathAttribute::Origin {
                    extended_length,
                    value: origin,
                };
                Ok((buf, path_attr))
            }
            _ => todo!(),
        }
    }
}
