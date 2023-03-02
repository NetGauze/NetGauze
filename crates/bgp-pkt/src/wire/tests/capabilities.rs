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
    capabilities::*,
    wire::{deserializer::capabilities::*, serializer::capabilities::*},
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{
    test_helpers::{test_parse_error, test_parsed_completely, test_write},
    Span,
};
use nom::error::ErrorKind;

#[test]
fn test_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x02, 0x00];
    let bad_wire = [0x02, 1];

    let good = BgpCapability::RouteRefresh;
    let bad = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_wire[1..]) },
        BgpCapabilityParsingError::InvalidRouteRefreshLength(1),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_enhanced_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x46, 0x00];
    let bad_wire = [0x46, 1];

    let good = BgpCapability::EnhancedRouteRefresh;
    let bad = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_wire[1..]) },
        BgpCapabilityParsingError::InvalidEnhancedRouteRefreshLength(1),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_unrecognized_capability() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x80, 0x01, 0x01];

    let good = BgpCapability::Unrecognized(UnrecognizedCapability::new(128, vec![1]));

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_four_octet_as() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x41, 0x04, 0x00, 0x00, 0x00, 0x064];
    let invalid_length_wire = [0x41, 0x03, 0x00, 0x00, 0x00, 0x064];
    let bad_incomplete_wire = [0x41, 0x04, 0x00, 0x00, 0x00];

    let good = BgpCapability::FourOctetAs(FourOctetAsCapability::new(100));
    let invalid_length = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &invalid_length_wire[1..]) },
        BgpCapabilityParsingError::FourOctetAsCapabilityError(
            FourOctetAsCapabilityParsingError::InvalidLength(invalid_length_wire[1]),
        ),
    );
    let bad_incomplete = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_incomplete_wire[2..]) },
        BgpCapabilityParsingError::FourOctetAsCapabilityError(
            FourOctetAsCapabilityParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
        &invalid_length_wire,
        &invalid_length,
    );
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
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
    let bad_invalid_length = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_invalid_length_wire[1..]) },
        BgpCapabilityParsingError::InvalidExtendedMessageLength(1),
    );
    let bad_incomplete = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BgpCapabilityParsingError::NomError(ErrorKind::Eof),
    );
    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
        &bad_invalid_length_wire,
        &bad_invalid_length,
    );
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
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

    let bad_invalid_length = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_invalid_length_wire[1..]) },
        BgpCapabilityParsingError::MultiProtocolExtensionsCapabilityError(
            MultiProtocolExtensionsCapabilityParsingError::InvalidLength(
                bad_invalid_length_wire[1],
            ),
        ),
    );
    let bad_incomplete = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(5, &bad_incomplete_wire[5..]) },
        BgpCapabilityParsingError::MultiProtocolExtensionsCapabilityError(
            MultiProtocolExtensionsCapabilityParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
        &bad_invalid_length_wire,
        &bad_invalid_length,
    );
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
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

    test_parsed_completely(&good_wire, &good);
    test_parsed_completely(&good_address_family_wire, &good_address_family);
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
    let bad_send_receive = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(5, &bad_send_receive_wire[5..]) },
        BgpCapabilityParsingError::AddPathCapabilityError(
            AddPathCapabilityParsingError::InvalidAddPathSendReceiveValue(bad_send_receive_wire[1]),
        ),
    );
    let bad_incomplete = LocatedBgpCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(5, &bad_incomplete_wire[6..]) },
        BgpCapabilityParsingError::AddPathCapabilityError(AddPathCapabilityParsingError::NomError(
            ErrorKind::Eof,
        )),
    );

    test_parsed_completely(&good_wire, &good);
    test_parsed_completely(&good_long_wire, &good_long);
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
        &bad_send_receive_wire,
        &bad_send_receive,
    );
    test_parse_error::<BgpCapability, LocatedBgpCapabilityParsingError<'_>>(
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
    let invalid_length = LocatedExtendedNextHopEncodingCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &invalid_length_wire[0..]) },
        ExtendedNextHopEncodingCapabilityParsingError::NomError(ErrorKind::Eof),
    );

    let invalid_afi = LocatedExtendedNextHopEncodingCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &invalid_afi_wire[0..]) },
        ExtendedNextHopEncodingCapabilityParsingError::AddressFamilyError(UndefinedAddressFamily(
            65534,
        )),
    );

    let invalid_safi = LocatedExtendedNextHopEncodingCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &invalid_safi_wire[2..]) },
        ExtendedNextHopEncodingCapabilityParsingError::SubsequentAddressFamilyError(
            UndefinedSubsequentAddressFamily(0),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<
        ExtendedNextHopEncoding,
        LocatedExtendedNextHopEncodingCapabilityParsingError<'_>,
    >(&invalid_length_wire, &invalid_length);
    test_parse_error::<
        ExtendedNextHopEncoding,
        LocatedExtendedNextHopEncodingCapabilityParsingError<'_>,
    >(&invalid_afi_wire, &invalid_afi);
    test_parse_error::<
        ExtendedNextHopEncoding,
        LocatedExtendedNextHopEncodingCapabilityParsingError<'_>,
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

    test_parsed_completely(&good_zero_afi_wire, &good_zero_afi);
    test_parsed_completely(&good_one_afi_wire, &good_one_afi);
    test_parsed_completely(&good_two_afi_wire, &good_two_afi);

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

    test_parsed_completely(&good_wire, &good);
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

        test_parsed_completely(&good_wire, &good);
        test_write(&good, &good_wire)?;
    }
    Ok(())
}
