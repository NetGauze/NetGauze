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

use crate::{
    BgpRouteRefreshMessage,
    iana::{RouteRefreshSubcode, UndefinedRouteRefreshSubcode},
    wire::{
        deserializer::route_refresh::{
            BgpRouteRefreshMessageParsingError, LocatedBgpRouteRefreshMessageParsingError,
        },
        serializer::route_refresh::BgpRouteRefreshMessageWritingError,
    },
};
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{
    Span,
    test_helpers::{test_parse_error, test_parsed_completely, test_write},
};
use nom::error::ErrorKind;

#[test]
fn test_route_refresh_message() -> Result<(), BgpRouteRefreshMessageWritingError> {
    let good_normal_payload_wire = [0x00, 0x01, 0x00, 0x01];
    let good_borr_payload_wire = [0x00, 0x01, 0x01, 0x01];
    let good_eorr_payload_wire = [0x00, 0x01, 0x02, 0x01];
    let bad_undefined_wire = [0x00, 0x01, 0xff, 0x01];
    let bad_incomplete_wire = [0x00];

    let good_normal_payload =
        BgpRouteRefreshMessage::new(AddressType::Ipv4Unicast, RouteRefreshSubcode::NormalRequest);
    let good_borr_payload = BgpRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::BeginningOfRouteRefresh,
    );
    let good_eorr_payload = BgpRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::EndOfRouteRefresh,
    );
    let bad_undefined = LocatedBgpRouteRefreshMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_undefined_wire[2..]) },
        BgpRouteRefreshMessageParsingError::UndefinedOperation(UndefinedRouteRefreshSubcode(255)),
    );
    let bad_incomplete = LocatedBgpRouteRefreshMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_incomplete_wire) },
        BgpRouteRefreshMessageParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_normal_payload_wire, &good_normal_payload);
    test_parsed_completely(&good_borr_payload_wire, &good_borr_payload);
    test_parsed_completely(&good_eorr_payload_wire, &good_eorr_payload);
    test_parse_error::<BgpRouteRefreshMessage, LocatedBgpRouteRefreshMessageParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<BgpRouteRefreshMessage, LocatedBgpRouteRefreshMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good_normal_payload, &good_normal_payload_wire)?;
    test_write(&good_borr_payload, &good_borr_payload_wire)?;
    test_write(&good_eorr_payload, &good_eorr_payload_wire)?;
    Ok(())
}
