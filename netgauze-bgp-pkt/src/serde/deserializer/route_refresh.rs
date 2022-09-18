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

//! Deserializer for BGP Route Refresh message

use crate::{
    iana::{RouteRefreshSubcode, UndefinedRouteRefreshSubcode},
    serde::deserializer::{BGPMessageParsingError, LocatedBGPMessageParsingError},
    BGPRouteRefreshMessage,
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
    UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{IntoLocatedError, LocatedParsingError, ReadablePDU, Span};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u16, be_u8},
    IResult,
};

/// BGP Route Refresh Message Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPRouteRefreshMessageParsingError {
    NomError(ErrorKind),
    UndefinedOperation(UndefinedRouteRefreshSubcode),
    UndefinedAddressFamily(UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPRouteRefreshMessageParsingError<'a> {
    span: Span<'a>,
    error: BGPRouteRefreshMessageParsingError,
}

impl<'a> LocatedBGPRouteRefreshMessageParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPRouteRefreshMessageParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError<'a, BGPRouteRefreshMessageParsingError>
    for LocatedBGPRouteRefreshMessageParsingError<'a>
{
    fn span(&self) -> &Span<'a> {
        &self.span
    }

    fn error(&self) -> &BGPRouteRefreshMessageParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedError<'a, BGPMessageParsingError, LocatedBGPMessageParsingError<'a>>
    for LocatedBGPRouteRefreshMessageParsingError<'a>
{
    fn into_located(self) -> LocatedBGPMessageParsingError<'a> {
        LocatedBGPMessageParsingError::new(
            self.span,
            BGPMessageParsingError::BGPRouteRefreshMessageParsingError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedBGPRouteRefreshMessageParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedBGPRouteRefreshMessageParsingError::new(
            input,
            BGPRouteRefreshMessageParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, BGPRouteRefreshMessageParsingError>
    for LocatedBGPRouteRefreshMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPRouteRefreshMessageParsingError,
    ) -> Self {
        LocatedBGPRouteRefreshMessageParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedRouteRefreshSubcode>
    for LocatedBGPRouteRefreshMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedRouteRefreshSubcode,
    ) -> Self {
        LocatedBGPRouteRefreshMessageParsingError::new(
            input,
            BGPRouteRefreshMessageParsingError::UndefinedOperation(e),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedAddressFamily>
    for LocatedBGPRouteRefreshMessageParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, e: UndefinedAddressFamily) -> Self {
        LocatedBGPRouteRefreshMessageParsingError::new(
            input,
            BGPRouteRefreshMessageParsingError::UndefinedAddressFamily(e),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedSubsequentAddressFamily>
    for LocatedBGPRouteRefreshMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedSubsequentAddressFamily,
    ) -> Self {
        LocatedBGPRouteRefreshMessageParsingError::new(
            input,
            BGPRouteRefreshMessageParsingError::UndefinedSubsequentAddressFamily(e),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedBGPRouteRefreshMessageParsingError<'a>> for BGPRouteRefreshMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBGPRouteRefreshMessageParsingError<'a>> {
        let input = buf;
        let (buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(buf)?;
        let (buf, op) = nom::combinator::map_res(be_u8, RouteRefreshSubcode::try_from)(buf)?;
        let (buf, safi) = nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(buf)?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(val) => val,
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedBGPRouteRefreshMessageParsingError::new(
                        input,
                        BGPRouteRefreshMessageParsingError::InvalidAddressType(err),
                    ),
                ))
            }
        };
        Ok((buf, BGPRouteRefreshMessage::new(address_type, op)))
    }
}
