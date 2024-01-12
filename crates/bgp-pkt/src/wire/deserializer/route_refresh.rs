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
    BgpRouteRefreshMessage,
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
    UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{ReadablePdu, Span};
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

use netgauze_serde_macros::LocatedError;

use crate::notification::RouteRefreshError;
use netgauze_parse_utils::ErrorKindSerdeDeref;

/// BGP Route Refresh Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpRouteRefreshMessageParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedOperation(#[from_external] UndefinedRouteRefreshSubcode),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
}

impl<'a> ReadablePdu<'a, LocatedBgpRouteRefreshMessageParsingError<'a>> for BgpRouteRefreshMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBgpRouteRefreshMessageParsingError<'a>> {
        let input = buf;
        let (buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(buf)?;
        let (buf, op) = nom::combinator::map_res(be_u8, RouteRefreshSubcode::try_from)(buf)?;
        let (buf, safi) = nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(buf)?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(val) => val,
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedBgpRouteRefreshMessageParsingError::new(
                        input,
                        BgpRouteRefreshMessageParsingError::InvalidAddressType(err),
                    ),
                ))
            }
        };
        Ok((buf, BgpRouteRefreshMessage::new(address_type, op)))
    }
}

impl From<BgpRouteRefreshMessageParsingError> for RouteRefreshError {
    fn from(_value: BgpRouteRefreshMessageParsingError) -> Self {
        // Mapping all RouteRefresh errors to invalid length
        // TODO implement RFC 7313 error handling: If the length, excluding the
        // fixed-size message header, of the received ROUTE-REFRESH message with Message
        // Subtype 1 and 2 is not 4, then the BGP speaker MUST send a NOTIFICATION
        // message with the Error Code of "ROUTE-REFRESH Message Error" and the subcode
        // of "Invalid Message Length". The Data field of the NOTIFICATION message MUST
        // ontain the complete ROUTE-REFRESH message.
        RouteRefreshError::InvalidMessageLength { value: vec![] }
    }
}
