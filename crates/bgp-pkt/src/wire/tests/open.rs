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

use netgauze_parse_utils::test_helpers::{
    combine, test_parse_error_with_one_input_bytes_reader,
    test_parsed_completely_with_one_input_bytes_reader, test_write,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;

use netgauze_iana::address_family::AddressType;

use crate::BgpOpenMessage;
use crate::capabilities::{
    BgpCapability, FourOctetAsCapability, MultiProtocolExtensionsCapability,
};
use crate::open::{BGP_VERSION, BgpOpenMessageParameter};
use crate::wire::deserializer::BgpParsingContext;
use crate::wire::deserializer::capabilities::BgpCapabilityParsingError;
use crate::wire::deserializer::open::{BgpOpenMessageParsingError, BgpParameterParsingError};
use crate::wire::serializer::open::BgpOpenMessageWritingError;
use crate::wire::tests::{BGP_ID, HOLD_TIME, MY_AS};

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
    let bad = BgpOpenMessageParsingError::UnsupportedVersionNumber {
        offset: 0,
        version: unsupported_version,
    };
    test_parse_error_with_one_input_bytes_reader::<
        BgpOpenMessage,
        &mut BgpParsingContext,
        BgpOpenMessageParsingError,
    >(&bad_wire, &mut BgpParsingContext::default(), &bad);
}

#[test]
fn test_bgp_open_no_params() -> Result<(), BgpOpenMessageWritingError> {
    let good_no_params_wire = combine(vec![&[BGP_VERSION], MY_AS, HOLD_TIME, BGP_ID, &[0x00u8]]);
    let good_no_params_msg = BgpOpenMessage::new(258, 772, Ipv4Addr::from(4278190081), vec![]);
    test_parsed_completely_with_one_input_bytes_reader(
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
        vec![BgpOpenMessageParameter::Capabilities(Box::new([
            BgpCapability::RouteRefresh,
        ]))],
    );
    test_parsed_completely_with_one_input_bytes_reader(
        &good_wire,
        &mut BgpParsingContext::default(),
        &good,
    );
    test_write(&good, &good_wire)?;

    Ok(())
}

/// [RFC5492](https://datatracker.ietf.org/doc/html/rfc5492) Section 4 allows a
/// single Capabilities Optional Parameter to carry more than one
/// <Capability Code, Capability Length, Capability Value> triple.
#[test]
fn test_open_multiple_capabilities_in_one_param() -> Result<(), BgpOpenMessageWritingError> {
    let good_wire = [
        0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, // header
        0x12, // optional parameters length
        0x02, 0x10, // capabilities parameter, 16 bytes of capabilities
        0x01, 0x04, 0x00, 0x01, 0x00, 0x01, // multi-protocol extensions: ipv4 unicast
        0x02, 0x00, // route refresh
        0x41, 0x04, 0x00, 0x00, 0xfe, 0x09, // four-octet AS: 65033
        0x46, 0x00, // enhanced route refresh
    ];

    let good = BgpOpenMessage::new(
        65033,
        180,
        Ipv4Addr::new(0xc0, 0xa8, 0x00, 0x0f),
        vec![BgpOpenMessageParameter::Capabilities(Box::new([
            BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
                AddressType::Ipv4Unicast,
            )),
            BgpCapability::RouteRefresh,
            BgpCapability::FourOctetAs(FourOctetAsCapability::new(65033)),
            BgpCapability::EnhancedRouteRefresh,
        ]))],
    );
    test_parsed_completely_with_one_input_bytes_reader(
        &good_wire,
        &mut BgpParsingContext::default(),
        &good,
    );
    test_write(&good, &good_wire)?;

    Ok(())
}

/// [RFC5492](https://datatracker.ietf.org/doc/html/rfc5492) Section 4 also
/// allows a BGP speaker to send more than one Capabilities Optional Parameter
/// in the same OPEN message, and the same capability to appear more than once.
#[test]
fn test_open_multiple_capability_params() -> Result<(), BgpOpenMessageWritingError> {
    let good_wire = [
        0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, // header
        0x14, // optional parameters length
        0x02, 0x06, // first capabilities parameter
        0x01, 0x04, 0x00, 0x01, 0x00, 0x01, // multi-protocol extensions: ipv4 unicast
        0x02, 0x02, // second capabilities parameter
        0x02, 0x00, // route refresh
        0x02, 0x06, // third capabilities parameter
        0x01, 0x04, 0x00, 0x02, 0x00, 0x01, // multi-protocol extensions: ipv6 unicast
    ];

    let good = BgpOpenMessage::new(
        65033,
        180,
        Ipv4Addr::new(0xc0, 0xa8, 0x00, 0x0f),
        vec![
            BgpOpenMessageParameter::Capabilities(Box::new([
                BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
                    AddressType::Ipv4Unicast,
                )),
            ])),
            BgpOpenMessageParameter::Capabilities(Box::new([BgpCapability::RouteRefresh])),
            BgpOpenMessageParameter::Capabilities(Box::new([
                BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
                    AddressType::Ipv6Unicast,
                )),
            ])),
        ],
    );
    test_parsed_completely_with_one_input_bytes_reader(
        &good_wire,
        &mut BgpParsingContext::default(),
        &good,
    );
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

    let bad =
        BgpOpenMessageParsingError::ParameterError(BgpParameterParsingError::CapabilityError(
            BgpCapabilityParsingError::InvalidRouteRefreshLength {
                offset: 13,
                length: bad_wire[13],
            },
        ));

    test_parse_error_with_one_input_bytes_reader::<
        BgpOpenMessage,
        &mut BgpParsingContext,
        BgpOpenMessageParsingError,
    >(
        &bad_wire,
        &mut BgpParsingContext::new(true, HashMap::new(), HashMap::new(), true, true, true, true),
        &bad,
    );

    test_parsed_completely_with_one_input_bytes_reader(
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
