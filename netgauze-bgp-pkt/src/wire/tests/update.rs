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
    update::{NetworkLayerReachabilityInformation, WithdrawRoute},
    wire::{
        deserializer::{
            update::{LocatedWithdrawRouteParsingError, WithdrawRouteParsingError},
            Ipv4PrefixParsingError,
        },
        serializer::{
            update::{NetworkLayerReachabilityInformationWritingError, WithdrawRouteWritingError},
            BGPMessageWritingError,
        },
    },
    BGPMessage, BGPUpdateMessage,
};
use ipnet::Ipv4Net;
use netgauze_parse_utils::{
    test_helpers::{
        test_parse_error, test_parsed_completely, test_parsed_completely_with_one_input, test_write,
    },
    Span,
};
use nom::error::ErrorKind;
use std::{net::Ipv4Addr, str::FromStr};

#[test]
fn test_withdraw_route() -> Result<(), WithdrawRouteWritingError> {
    let good_wire = [0x18, 0xac, 0x10, 0x01];
    let bad_overflow_wire = [0xff, 0xac, 0x10, 0x01];
    let bad_prefix_wire = [0x21, 0xac, 0x10, 0xff, 0xff, 0xff];

    let good = WithdrawRoute::new(Ipv4Net::from_str("172.16.1.0/24").unwrap());
    let bad_overflow = LocatedWithdrawRouteParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_overflow_wire[1..]) },
        WithdrawRouteParsingError::Ipv4PrefixParsingError(Ipv4PrefixParsingError::NomError(
            ErrorKind::Eof,
        )),
    );
    let bad_prefix = LocatedWithdrawRouteParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_prefix_wire) },
        WithdrawRouteParsingError::Ipv4PrefixParsingError(
            Ipv4PrefixParsingError::InvalidIpv4PrefixLen(33),
        ),
    );
    test_parsed_completely(&good_wire, &good);
    test_parse_error::<WithdrawRoute, LocatedWithdrawRouteParsingError<'_>>(
        &bad_overflow_wire,
        &bad_overflow,
    );
    test_parse_error::<WithdrawRoute, LocatedWithdrawRouteParsingError<'_>>(
        &bad_prefix_wire,
        &bad_prefix,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_nlri() -> Result<(), NetworkLayerReachabilityInformationWritingError> {
    let octet_boundary_wire = [0x18, 0xac, 0x10, 0x0b];
    let not_octet_boundary_wire = [0x13, 0xac, 0x10, 0x00];
    let not_octet_boundary2_wire = [23, 192, 168, 128];

    let octet_boundary = NetworkLayerReachabilityInformation::new(vec![Ipv4Net::from_str(
        "172.16.11.0/24",
    )
    .unwrap()]);
    let not_octet_boundary =
        NetworkLayerReachabilityInformation::new(vec![Ipv4Net::from_str("172.16.0.0/19").unwrap()]);
    let not_octet_boundary2 =
        NetworkLayerReachabilityInformation::new(vec![
            Ipv4Net::from_str("192.168.128.0/23").unwrap()
        ]);

    test_parsed_completely(&octet_boundary_wire, &octet_boundary);
    test_parsed_completely(&not_octet_boundary_wire, &not_octet_boundary);
    test_parsed_completely(&not_octet_boundary2_wire, &not_octet_boundary2);

    test_write(&octet_boundary, &octet_boundary_wire)?;
    test_write(&not_octet_boundary, &not_octet_boundary_wire)?;
    test_write(&not_octet_boundary2, &not_octet_boundary2_wire)?;
    Ok(())
}

#[test]
fn test_empty_update() -> Result<(), BGPMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];
    let good = BGPMessage::Update(BGPUpdateMessage::new(vec![], vec![], vec![]));
    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_withdraw_update() -> Result<(), BGPMessageWritingError> {
    let good_withdraw_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1b, 0x02, 0x00, 0x04, 0x18, 0xac, 0x10, 0x01, 0x00, 0x00,
    ];
    let good_withdraw = BGPMessage::Update(BGPUpdateMessage::new(
        vec![WithdrawRoute::new(
            Ipv4Net::new(Ipv4Addr::new(172, 16, 1, 0), 24).unwrap(),
        )],
        vec![],
        vec![],
    ));

    test_parsed_completely_with_one_input(&good_withdraw_wire, false, &good_withdraw);
    test_write(&good_withdraw, &good_withdraw_wire)?;
    Ok(())
}
