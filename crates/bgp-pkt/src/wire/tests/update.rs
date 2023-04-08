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
    nlri::{Ipv4Unicast, Ipv4UnicastAddress},
    wire::{
        deserializer::{
            nlri::{
                Ipv4UnicastAddressParsingError, Ipv4UnicastParsingError,
                LocatedIpv4UnicastAddressParsingError,
            },
            Ipv4PrefixParsingError,
        },
        serializer::{nlri::Ipv4UnicastAddressWritingError, BgpMessageWritingError},
    },
    BgpMessage, BgpUpdateMessage,
};
use ipnet::Ipv4Net;
use netgauze_parse_utils::{
    test_helpers::{
        test_parse_error_with_one_input, test_parsed_completely,
        test_parsed_completely_with_one_input, test_parsed_completely_with_two_inputs, test_write,
    },
    Span,
};
use nom::error::ErrorKind;
use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

#[test]
fn test_withdraw_route() -> Result<(), Ipv4UnicastAddressWritingError> {
    let good_wire = [0x18, 0xac, 0x10, 0x01];
    let bad_overflow_wire = [0xff, 0xac, 0x10, 0x01];
    let bad_prefix_wire = [0x21, 0xac, 0x10, 0xff, 0xff, 0xff];

    let good = Ipv4UnicastAddress::new_no_path_id(
        Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.1.0/24").unwrap()).unwrap(),
    );
    let bad_overflow = LocatedIpv4UnicastAddressParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_overflow_wire[1..]) },
        Ipv4UnicastAddressParsingError::Ipv4UnicastError(Ipv4UnicastParsingError::Ipv4PrefixError(
            Ipv4PrefixParsingError::NomError(ErrorKind::Eof),
        )),
    );
    let bad_prefix = LocatedIpv4UnicastAddressParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_prefix_wire) },
        Ipv4UnicastAddressParsingError::Ipv4UnicastError(Ipv4UnicastParsingError::Ipv4PrefixError(
            Ipv4PrefixParsingError::InvalidIpv4PrefixLen(33),
        )),
    );
    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<
        Ipv4UnicastAddress,
        bool,
        LocatedIpv4UnicastAddressParsingError<'_>,
    >(&bad_overflow_wire, false, &bad_overflow);
    test_parse_error_with_one_input::<
        Ipv4UnicastAddress,
        bool,
        LocatedIpv4UnicastAddressParsingError<'_>,
    >(&bad_prefix_wire, false, &bad_prefix);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_nlri() -> Result<(), Ipv4UnicastAddressWritingError> {
    let octet_boundary_wire = [0x18, 0xac, 0x10, 0x0b];
    let not_octet_boundary_wire = [0x13, 0xac, 0x10, 0x00];
    let not_octet_boundary2_wire = [23, 192, 168, 128];

    let octet_boundary =
        Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.11.0/24").unwrap()).unwrap();
    let not_octet_boundary =
        Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.0.0/19").unwrap()).unwrap();
    let not_octet_boundary2 =
        Ipv4Unicast::from_net(Ipv4Net::from_str("192.168.128.0/23").unwrap()).unwrap();

    test_parsed_completely(&octet_boundary_wire, &octet_boundary);
    test_parsed_completely(&not_octet_boundary_wire, &not_octet_boundary);
    test_parsed_completely(&not_octet_boundary2_wire, &not_octet_boundary2);

    test_write(&octet_boundary, &octet_boundary_wire)?;
    test_write(&not_octet_boundary, &not_octet_boundary_wire)?;
    test_write(&not_octet_boundary2, &not_octet_boundary2_wire)?;
    Ok(())
}

#[test]
fn test_empty_update() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];
    let good = BgpMessage::Update(BgpUpdateMessage::new(vec![], vec![], vec![]));
    test_parsed_completely_with_two_inputs(&good_wire, false, &HashMap::new(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_withdraw_update() -> Result<(), BgpMessageWritingError> {
    let good_withdraw_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1b, 0x02, 0x00, 0x04, 0x18, 0xac, 0x10, 0x01, 0x00, 0x00,
    ];
    let good_withdraw = BgpMessage::Update(BgpUpdateMessage::new(
        vec![Ipv4UnicastAddress::new_no_path_id(
            Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 1, 0), 24).unwrap()).unwrap(),
        )],
        vec![],
        vec![],
    ));

    test_parsed_completely_with_two_inputs(
        &good_withdraw_wire,
        false,
        &HashMap::new(),
        &good_withdraw,
    );
    test_write(&good_withdraw, &good_withdraw_wire)?;
    Ok(())
}
