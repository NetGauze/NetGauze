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
    BGPRouteRefreshMessage,
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
    UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{ReadablePDU, Span};
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

use netgauze_serde_macros::LocatedError;

use crate::serde::deserializer::ErrorKindSerdeDeref;

/// BGP Route Refresh Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BGPRouteRefreshMessageParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedOperation(#[from_external] UndefinedRouteRefreshSubcode),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
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
