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

use crate::capabilities::*;
use crate::iana::BgpRoleValue;
use crate::wire::deserializer::capabilities::*;
use crate::wire::serializer::capabilities::*;
use netgauze_iana::address_family::{AddressFamily, AddressType};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::test_helpers::{
    test_parse_error_bytes_reader, test_parsed_completely_bytes_reader, test_write,
};

#[test]
fn test_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x02, 0x00];
    let bad_wire = [0x02, 1];

    let good = BgpCapability::RouteRefresh;
    let bad = BgpCapabilityParsingError::InvalidRouteRefreshLength {
        offset: 1,
        length: 1,
    };

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_enhanced_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x46, 0x00];
    let bad_wire = [0x46, 1];

    let good = BgpCapability::EnhancedRouteRefresh;
    let bad = BgpCapabilityParsingError::InvalidEnhancedRouteRefreshLength {
        offset: 1,
        length: 1,
    };

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_unrecognized_capability() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x00, 0x01, 0x01];

    let good = BgpCapability::Unrecognized(UnrecognizedCapability::new(0, vec![1]));

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_four_octet_as() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x41, 0x04, 0x00, 0x00, 0x00, 0x064];
    let invalid_length_wire = [0x41, 0x03, 0x00, 0x00, 0x00, 0x064];
    let bad_incomplete_wire = [0x41, 0x04, 0x00, 0x00, 0x00];

    let good = BgpCapability::FourOctetAs(FourOctetAsCapability::new(100));
    let invalid_length = BgpCapabilityParsingError::FourOctetAsCapabilityError(
        FourOctetAsCapabilityParsingError::InvalidLength {
            offset: 1,
            length: invalid_length_wire[1],
        },
    );
    let bad_incomplete = BgpCapabilityParsingError::FourOctetAsCapabilityError(
        FourOctetAsCapabilityParsingError::Parse(ParseError::UnexpectedEof {
            offset: 2,
            needed: 4,
            available: 3,
        }),
    );

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &invalid_length_wire,
        &invalid_length,
    );
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_extended_message() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x06, 0x00];
    let bad_invalid_length_wire = [0x06, 0x01];
    let bad_incomplete_wire = [0x06];

    let good = BgpCapability::ExtendedMessage;
    let bad_invalid_length = BgpCapabilityParsingError::InvalidExtendedMessageLength {
        offset: 1,
        length: 1,
    };
    let bad_incomplete = BgpCapabilityParsingError::InvalidExtendedMessageLength {
        offset: 0,
        length: 0,
    };

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &bad_invalid_length_wire,
        &bad_invalid_length,
    );
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_multi_protocol_extension() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x01, 0x04, 0x00, 0x01, 0x00, 0x01];
    let bad_invalid_length_wire = [0x01, 0x03, 0x00, 0x01, 0x00, 0x01];
    let bad_incomplete_wire = [0x01, 0x04, 0x00, 0x01, 0x00];

    let good = BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
        AddressType::Ipv4Unicast,
    ));

    let bad_invalid_length = BgpCapabilityParsingError::MultiProtocolExtensionsCapabilityError(
        MultiProtocolExtensionsCapabilityParsingError::InvalidLength {
            offset: 1,
            length: bad_invalid_length_wire[1],
        },
    );
    let bad_incomplete = BgpCapabilityParsingError::MultiProtocolExtensionsCapabilityError(
        MultiProtocolExtensionsCapabilityParsingError::Parse(ParseError::UnexpectedEof {
            offset: 5,
            needed: 1,
            available: 0,
        }),
    );

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &bad_invalid_length_wire,
        &bad_invalid_length,
    );
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_graceful_restart() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x40, 0x02, 0xc0, 0x78];
    let good_address_family_wire = [0x40, 0x06, 0xc0, 0x78, 0x00, 0x01, 0x01, 0x80];

    let good = BgpCapability::GracefulRestartCapability(GracefulRestartCapability::new(
        true,
        true,
        120,
        vec![],
    ));
    let good_address_family =
        BgpCapability::GracefulRestartCapability(GracefulRestartCapability::new(
            true,
            true,
            120,
            vec![GracefulRestartAddressFamily::new(
                true,
                AddressType::Ipv4Unicast,
            )],
        ));

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parsed_completely_bytes_reader(&good_address_family_wire, &good_address_family);
    test_write(&good, &good_wire)?;
    test_write(&good_address_family, &good_address_family_wire)?;
    Ok(())
}

#[test]
fn test_parse_add_path() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x45, 0x04, 0x00, 0x02, 0x01, 0x03];
    let good_long_wire = [0x45, 0x08, 0x00, 0x01, 0x01, 0x02, 0x00, 0x02, 0x01, 0x01];
    let bad_send_receive_wire = [0x45, 0x04, 0x00, 0x02, 0x01, 0x04];
    let bad_incomplete_wire = [0x45, 0x03, 0x00, 0x02, 0x01, 0x03];

    let good = BgpCapability::AddPath(AddPathCapability::new(vec![AddPathAddressFamily::new(
        AddressType::Ipv6Unicast,
        true,
        true,
    )]));
    let good_long = BgpCapability::AddPath(AddPathCapability::new(vec![
        AddPathAddressFamily::new(AddressType::Ipv4Unicast, true, false),
        AddPathAddressFamily::new(AddressType::Ipv6Unicast, false, true),
    ]));
    let bad_send_receive = BgpCapabilityParsingError::AddPathCapabilityError(
        AddPathCapabilityParsingError::InvalidAddPathSendReceiveValue {
            offset: 5,
            value: bad_send_receive_wire[1],
        },
    );
    let bad_incomplete = BgpCapabilityParsingError::AddPathCapabilityError(
        AddPathCapabilityParsingError::Parse(ParseError::UnexpectedEof {
            offset: 5,
            needed: 1,
            available: 0,
        }),
    );

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parsed_completely_bytes_reader(&good_long_wire, &good_long);
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &bad_send_receive_wire,
        &bad_send_receive,
    );
    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_extended_next_hop_encoding() -> Result<(), ExtendedNextHopEncodingCapabilityWritingError> {
    let good_wire = [0x00, 0x01, 0x00, 0x01, 0x00, 0x02];
    let invalid_length_wire = [0x00, 0x01, 0x00, 0x01, 0x00];
    let invalid_afi_wire = [0xff, 0xfe, 0x00, 0x01, 0x00, 0x02];
    let invalid_safi_wire = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02];

    let good = ExtendedNextHopEncoding::new(AddressType::Ipv4Unicast, AddressFamily::IPv6);
    let invalid_length =
        ExtendedNextHopEncodingCapabilityParsingError::Parse(ParseError::UnexpectedEof {
            offset: 0,
            needed: 6,
            available: 5,
        });
    let invalid_afi = ExtendedNextHopEncodingCapabilityParsingError::UndefinedAddressFamily {
        offset: 0,
        afi: 65534,
    };
    let invalid_safi =
        ExtendedNextHopEncodingCapabilityParsingError::UndefinedSubsequentAddressFamily {
            offset: 3,
            safi: 0,
        };

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_parse_error_bytes_reader::<
        ExtendedNextHopEncoding,
        ExtendedNextHopEncodingCapabilityParsingError,
    >(&invalid_length_wire, &invalid_length);
    test_parse_error_bytes_reader::<
        ExtendedNextHopEncoding,
        ExtendedNextHopEncodingCapabilityParsingError,
    >(&invalid_afi_wire, &invalid_afi);
    test_parse_error_bytes_reader::<
        ExtendedNextHopEncoding,
        ExtendedNextHopEncodingCapabilityParsingError,
    >(&invalid_safi_wire, &invalid_safi);

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_extended_next_hop_encodings() -> Result<(), BGPCapabilityWritingError> {
    let good_zero_afi_wire = [0x00];
    let good_one_afi_wire = [0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02];
    let good_two_afi_wire = [
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
    ];

    let good_zero_afi = ExtendedNextHopEncodingCapability::new(vec![]);
    let good_one_afi = ExtendedNextHopEncodingCapability::new(vec![ExtendedNextHopEncoding::new(
        AddressType::Ipv4Unicast,
        AddressFamily::IPv6,
    )]);
    let good_two_afi = ExtendedNextHopEncodingCapability::new(vec![
        ExtendedNextHopEncoding::new(AddressType::Ipv4Unicast, AddressFamily::IPv6),
        ExtendedNextHopEncoding::new(AddressType::Ipv6Unicast, AddressFamily::IPv6),
    ]);

    test_parsed_completely_bytes_reader(&good_zero_afi_wire, &good_zero_afi);
    test_parsed_completely_bytes_reader(&good_one_afi_wire, &good_one_afi);
    test_parsed_completely_bytes_reader(&good_two_afi_wire, &good_two_afi);

    test_write(&good_zero_afi, &good_zero_afi_wire)?;
    test_write(&good_one_afi, &good_one_afi_wire)?;
    test_write(&good_two_afi, &good_two_afi_wire)?;
    Ok(())
}

#[test]
fn test_extended_next_hop_encoding_capability() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [
        5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2,
    ];

    let good =
        BgpCapability::ExtendedNextHopEncoding(ExtendedNextHopEncodingCapability::new(vec![
            ExtendedNextHopEncoding::new(AddressType::Ipv4Unicast, AddressFamily::IPv6),
            ExtendedNextHopEncoding::new(AddressType::Ipv4Multicast, AddressFamily::IPv6),
            ExtendedNextHopEncoding::new(AddressType::Ipv4MplsLabeledVpn, AddressFamily::IPv6),
        ]));

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bgp_role_capability() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [9, 1, 4];
    let undefined_role_wire = [9, 1, 255];
    let invalid_length_wire = [9, 255, 4];

    let good = BgpCapability::BgpRole(BgpRoleCapability::new(BgpRoleValue::Peer));
    let undefined_role = BgpCapabilityParsingError::BgpRoleCapabilityError(
        BgpRoleCapabilityParsingError::UndefinedBgpRoleValue {
            offset: 2,
            code: undefined_role_wire[2],
        },
    );
    let invalid_length = BgpCapabilityParsingError::BgpRoleCapabilityError(
        BgpRoleCapabilityParsingError::InvalidLength {
            offset: 1,
            length: invalid_length_wire[1],
        },
    );

    test_parsed_completely_bytes_reader(&good_wire, &good);

    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &undefined_role_wire,
        &undefined_role,
    );

    test_parse_error_bytes_reader::<BgpCapability, BgpCapabilityParsingError>(
        &invalid_length_wire,
        &invalid_length,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_experimental_capabilities() -> Result<(), BGPCapabilityWritingError> {
    // IANA defines the codes 239-254 as reserved for Experimental Use
    for code in 239..255 {
        let good_wire = [code, 0x01, 0x01];

        let code = ExperimentalCapabilityCode::from_repr(code).unwrap();
        let good = BgpCapability::Experimental(ExperimentalCapability::new(code, vec![1]));

        test_parsed_completely_bytes_reader(&good_wire, &good);
        test_write(&good, &good_wire)?;
    }
    Ok(())
}
