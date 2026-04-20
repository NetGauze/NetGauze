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

use crate::BgpRouteRefreshMessage;
use crate::iana::RouteRefreshSubcode;
use netgauze_iana::address_family::{AddressFamily, AddressType, SubsequentAddressFamily};

use netgauze_parse_utils::error::ParseError;
use serde::{Deserialize, Serialize};

use crate::notification::RouteRefreshError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFrom;

/// BGP Route Refresh Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpRouteRefreshMessageParsingError {
    #[error("BGP route refresh message parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("BGP route refresh message invalid address type: {code} at offset {offset}")]
    UndefinedOperation { offset: usize, code: u8 },

    #[error("BGP route refresh undefined address family {afi} at offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("BGP route refresh undefined subsequent address family {safi} at offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error(
        "BGP route refresh address type error at offset {offset} for address family {afi} and subsequent address family {safi}"
    )]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

impl<'a> ParseFrom<'a> for BgpRouteRefreshMessage {
    type Error = BgpRouteRefreshMessageParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let afi = AddressFamily::try_from(cur.read_u16_be()?).map_err(|err| {
            BgpRouteRefreshMessageParsingError::UndefinedAddressFamily {
                offset: cur.offset() - 2,
                afi: err.0,
            }
        })?;
        let op = cur.read_u8()?;
        let op = RouteRefreshSubcode::try_from(op).map_err(|err| {
            BgpRouteRefreshMessageParsingError::UndefinedOperation {
                offset: cur.offset() - 1,
                code: err.0,
            }
        })?;
        let safi = SubsequentAddressFamily::try_from(cur.read_u8()?).map_err(|err| {
            BgpRouteRefreshMessageParsingError::UndefinedSubsequentAddressFamily {
                offset: cur.offset() - 1,
                safi: err.0,
            }
        })?;

        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(BgpRouteRefreshMessageParsingError::AddressTypeError {
                    offset: cur.offset() - 3,
                    afi: err.address_family().into(),
                    safi: err.subsequent_address_family().into(),
                });
            }
        };
        Ok(BgpRouteRefreshMessage::new(address_type, op))
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
        // obtain the complete ROUTE-REFRESH message.
        RouteRefreshError::InvalidMessageLength { value: vec![] }
    }
}
