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

use netgauze_parse_utils::{
    test_helpers::{combine, test_parse_error, test_parsed_completely, test_write},
    Span,
};
use std::net::Ipv4Addr;

use crate::{
    capabilities::BGPCapability,
    open::{BGPOpenMessageParameter, BGP_VERSION},
    serde::{
        deserializer::open::{BGPOpenMessageParsingError, LocatedBGPOpenMessageParsingError},
        serializer::open::BGPOpenMessageWritingError,
        tests::{BGP_ID, HOLD_TIME, MY_AS},
    },
    BGPOpenMessage,
};

#[test]
fn test_parse_bgp_open_with_wrong_bpg_version() {
    let unsupported_version = 5;
    let bad_wire = combine(vec![
        &[unsupported_version],
        MY_AS,
        HOLD_TIME,
        BGP_ID,
        &[0x00u8],
    ]);
    let bad = LocatedBGPOpenMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_wire) },
        BGPOpenMessageParsingError::UnsupportedVersionNumber(unsupported_version),
    );
    test_parse_error::<BGPOpenMessage, LocatedBGPOpenMessageParsingError<'_>>(&bad_wire, &bad);
}

#[test]
fn test_bgp_open_no_params() -> Result<(), BGPOpenMessageWritingError> {
    let good_no_params_wire = combine(vec![&[BGP_VERSION], MY_AS, HOLD_TIME, BGP_ID, &[0x00u8]]);
    let good_no_params_msg = BGPOpenMessage::new(258, 772, Ipv4Addr::from(4278190081), vec![]);
    test_parsed_completely(&good_no_params_wire, &good_no_params_msg);
    test_write(&good_no_params_msg, &good_no_params_wire)?;
    Ok(())
}

#[test]
fn test_open_one_params() -> Result<(), BGPOpenMessageWritingError> {
    let good_wire = [
        0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, 0x04, 0x02, 0x02, 0x02, 0x00,
    ];

    let good = BGPOpenMessage::new(
        65033,
        180,
        Ipv4Addr::new(0xc0, 0xa8, 0x00, 0x0f),
        vec![BGPOpenMessageParameter::Capabilities(vec![
            BGPCapability::RouteRefresh,
        ])],
    );
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;

    Ok(())
}
