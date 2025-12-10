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
    Span,
    test_helpers::{
        combine, test_parse_error_with_one_input, test_parsed_completely_with_one_input, test_write,
    },
};
use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    BgpOpenMessage,
    capabilities::BgpCapability,
    open::{BGP_VERSION, BgpOpenMessageParameter},
    wire::{
        deserializer::{
            BgpParsingContext,
            capabilities::BgpCapabilityParsingError,
            open::{
                BgpOpenMessageParsingError, BgpParameterParsingError,
                LocatedBgpOpenMessageParsingError,
            },
        },
        serializer::open::BgpOpenMessageWritingError,
        tests::{BGP_ID, HOLD_TIME, MY_AS},
    },
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
    let bad = LocatedBgpOpenMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_wire) },
        BgpOpenMessageParsingError::UnsupportedVersionNumber(unsupported_version),
    );
    test_parse_error_with_one_input::<
        BgpOpenMessage,
        &mut BgpParsingContext,
        LocatedBgpOpenMessageParsingError<'_>,
    >(&bad_wire, &mut BgpParsingContext::default(), &bad);
}

#[test]
fn test_bgp_open_no_params() -> Result<(), BgpOpenMessageWritingError> {
    let good_no_params_wire = combine(vec![&[BGP_VERSION], MY_AS, HOLD_TIME, BGP_ID, &[0x00u8]]);
    let good_no_params_msg = BgpOpenMessage::new(258, 772, Ipv4Addr::from(4278190081), vec![]);
    test_parsed_completely_with_one_input(
        &good_no_params_wire,
        &mut BgpParsingContext::default(),
        &good_no_params_msg,
    );
    test_write(&good_no_params_msg, &good_no_params_wire)?;
    Ok(())
}

#[test]
fn test_open_one_params() -> Result<(), BgpOpenMessageWritingError> {
    let good_wire = [
        0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, 0x04, 0x02, 0x02, 0x02, 0x00,
    ];

    let good = BgpOpenMessage::new(
        65033,
        180,
        Ipv4Addr::new(0xc0, 0xa8, 0x00, 0x0f),
        vec![BgpOpenMessageParameter::Capabilities(vec![
            BgpCapability::RouteRefresh,
        ])],
    );
    test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_open_bad_capability_params() -> Result<(), BgpOpenMessageWritingError> {
    let bad_wire = [
        0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, 0x04, 0x02, 0x02, 0x02, 0x01,
    ];
    let cap_ignored_wire = [0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, 0x00];

    let cap_ignored =
        BgpOpenMessage::new(65033, 180, Ipv4Addr::new(0xc0, 0xa8, 0x00, 0x0f), vec![]);

    let bad = LocatedBgpOpenMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(13, &bad_wire[13..]) },
        BgpOpenMessageParsingError::ParameterError(BgpParameterParsingError::CapabilityError(
            BgpCapabilityParsingError::InvalidRouteRefreshLength(bad_wire[13]),
        )),
    );

    test_parse_error_with_one_input::<
        BgpOpenMessage,
        &mut BgpParsingContext,
        LocatedBgpOpenMessageParsingError<'_>,
    >(
        &bad_wire,
        &mut BgpParsingContext::new(true, HashMap::new(), HashMap::new(), true, true, true, true),
        &bad,
    );

    test_parsed_completely_with_one_input(
        &cap_ignored_wire,
        &mut BgpParsingContext::new(
            true,
            HashMap::new(),
            HashMap::new(),
            true,
            true,
            false,
            true,
        ),
        &cap_ignored,
    );
    test_write(&cap_ignored, &cap_ignored_wire)?;

    Ok(())
}
