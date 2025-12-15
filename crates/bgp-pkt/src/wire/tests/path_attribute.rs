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

use crate::BgpMessage;
use crate::path_attribute::*;
use crate::wire::deserializer::path_attribute::*;
use crate::wire::serializer::path_attribute::*;

use crate::nlri::*;
use crate::wire::deserializer::Ipv4PrefixParsingError;
use crate::wire::deserializer::nlri::{
    Ipv4MulticastParsingError, Ipv4UnicastParsingError, Ipv6MulticastParsingError,
    Ipv6UnicastParsingError,
};
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, SubsequentAddressFamily, UndefinedAddressFamily,
    UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::Span;
use netgauze_parse_utils::test_helpers::*;

use crate::community::*;
use crate::iana::{BgpSidAttributeTypeError, IanaValueError, UndefinedRouteDistinguisherTypeCode};
use crate::update::BgpUpdateMessage;
use crate::wire::deserializer::BgpParsingContext;
use crate::wire::deserializer::nlri::{
    Ipv4MplsVpnUnicastAddressParsingError, Ipv4MulticastAddressParsingError,
    Ipv4UnicastAddressParsingError, Ipv6MulticastAddressParsingError,
    Ipv6UnicastAddressParsingError, RouteDistinguisherParsingError,
};
use crate::wire::serializer::BgpMessageWritingError;
use nom::error::ErrorKind;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[test]
fn test_origin_value() -> Result<(), OriginWritingError> {
    let good_igp_wire = [0x01, 0x00];
    let good_egp_wire = [0x01, 0x01];
    let good_incomplete_wire = [0x01, 0x02];
    let bad_zero_length_wire = [0x0, 0x02];
    let bad_long_length_wire = [0x2, 0x02];
    let bad_invalid_code_wire = [0x1, 0x03];

    let igp = Origin::IGP;
    let egp = Origin::EGP;
    let incomplete = Origin::Incomplete;
    let bad_zero_length = LocatedOriginParsingError::new(
        Span::new(&bad_zero_length_wire),
        OriginParsingError::InvalidOriginLength(PathAttributeLength::U8(0)),
    );

    let bad_long_length = LocatedOriginParsingError::new(
        Span::new(&bad_long_length_wire),
        OriginParsingError::InvalidOriginLength(PathAttributeLength::U8(2)),
    );

    let bad_invalid_code = LocatedOriginParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_invalid_code_wire[1..]) },
        OriginParsingError::UndefinedOrigin(UndefinedOrigin(3)),
    );

    test_parsed_completely_with_one_input(&good_igp_wire, false, &igp);
    test_parsed_completely_with_one_input(&good_egp_wire, false, &egp);
    test_parsed_completely_with_one_input(&good_incomplete_wire, false, &incomplete);
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_zero_length_wire,
        false,
        &bad_zero_length,
    );
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_long_length_wire,
        false,
        &bad_long_length,
    );
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_invalid_code_wire,
        false,
        &bad_invalid_code,
    );

    test_write_with_one_input(&igp, false, &good_igp_wire)?;
    test_write_with_one_input(&egp, false, &good_egp_wire)?;
    test_write_with_one_input(&incomplete, false, &good_incomplete_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_origin() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x01, 0x01, 0x00];
    let good_extended_wire = [0x50, 0x01, 0x00, 0x01, 0x00];
    let bad_extended_wire = [0x50, 0x01, 0x00, 0x01, 0x03];
    let bad_incomplete_wire = [0x40, 0x01, 0x01];

    let good = PathAttribute::from(
        false,
        true,
        false,
        false,
        PathAttributeValue::Origin(Origin::IGP),
    )
    .unwrap();
    let good_extended = PathAttribute::from(
        false,
        true,
        false,
        true,
        PathAttributeValue::Origin(Origin::IGP),
    )
    .unwrap();

    let bad_extended = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(4, &bad_extended_wire[4..]) },
        PathAttributeParsingError::OriginError(OriginParsingError::UndefinedOrigin(
            UndefinedOrigin(3),
        )),
    );

    let bad_incomplete = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &bad_incomplete_wire[3..]) },
        PathAttributeParsingError::OriginError(OriginParsingError::NomError(ErrorKind::Eof)),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_extended_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_extended_wire,
        &mut BgpParsingContext::asn2_default(),
        &bad_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_incomplete_wire,
        &mut BgpParsingContext::asn2_default(),
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_as2_path_segment() -> Result<(), AsPathWritingError> {
    let good_set_wire = [0x01, 0x01, 0x00, 0x01];
    let good_seq_wire = [0x02, 0x01, 0x00, 0x01];
    let bad_empty_wire = [0x01, 0x00];
    let bad_undefined_segment_type_wire = [0x00, 0x01, 0x00, 0x01];
    let bad_incomplete_wire = [0x01, 0x01, 0x00];

    let set = As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]);
    let seq = As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]);

    let bad_empty = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_empty_wire[1..]) },
        AsPathParsingError::ZeroSegmentLength,
    );

    let bad_undefined_segment_type = LocatedAsPathParsingError::new(
        Span::new(&bad_undefined_segment_type_wire),
        AsPathParsingError::UndefinedAsPathSegmentType(UndefinedAsPathSegmentType(0x00)),
    );
    let bad_incomplete = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_incomplete_wire[2..]) },
        AsPathParsingError::InvalidAsPathLength {
            expecting: 2,
            found: 1,
        },
    );

    test_parsed_completely(&good_set_wire, &set);
    test_parsed_completely(&good_seq_wire, &seq);
    test_parse_error::<As2PathSegment, LocatedAsPathParsingError<'_>>(&bad_empty_wire, &bad_empty);
    test_parse_error::<As2PathSegment, LocatedAsPathParsingError<'_>>(
        &bad_undefined_segment_type_wire,
        &bad_undefined_segment_type,
    );
    test_parse_error::<As2PathSegment, LocatedAsPathParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&set, &good_set_wire)?;
    test_write(&seq, &good_seq_wire)?;
    Ok(())
}

#[test]
fn test_as4_path_segment() -> Result<(), AsPathWritingError> {
    let good_set_wire = [0x01, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_seq_wire = [0x02, 0x01, 0x00, 0x00, 0x00, 0x01];
    let bad_empty_wire = [0x01, 0x00];
    let undefined_segment_type_wire = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01];

    let set = As4PathSegment::new(AsPathSegmentType::AsSet, vec![1]);
    let seq = As4PathSegment::new(AsPathSegmentType::AsSequence, vec![1]);

    let bad_empty = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_empty_wire[1..]) },
        AsPathParsingError::ZeroSegmentLength,
    );

    let undefined_segment_type = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &undefined_segment_type_wire) },
        AsPathParsingError::UndefinedAsPathSegmentType(UndefinedAsPathSegmentType(0x00)),
    );

    test_parsed_completely(&good_set_wire, &set);
    test_parsed_completely(&good_seq_wire, &seq);

    test_parse_error::<As4PathSegment, LocatedAsPathParsingError<'_>>(&bad_empty_wire, &bad_empty);
    test_parse_error::<As4PathSegment, LocatedAsPathParsingError<'_>>(
        &undefined_segment_type_wire,
        &undefined_segment_type,
    );

    test_write(&set, &good_set_wire)?;
    test_write(&seq, &good_seq_wire)?;
    Ok(())
}

#[test]
fn test_as2_path_segments() -> Result<(), AsPathWritingError> {
    let good_wire = [0x08, 0x01, 0x01, 0x00, 0x01, 0x02, 0x01, 0x00, 0x01];
    let good_extended_wire = [0x00, 0x08, 0x01, 0x01, 0x00, 0x01, 0x02, 0x01, 0x00, 0x01];
    let good_empty_wire = [0x00];
    let bad_underflow_wire = [0x08, 0x01, 0x01, 0x00, 0x01];
    let bad_overflow_wire = [0x08, 0x01, 0x02, 0x00, 0x01, 0x00, 0x02];

    let good = AsPath::As2PathSegments(vec![
        As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);
    let good_extended = AsPath::As2PathSegments(vec![
        As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);
    let good_empty = AsPath::As2PathSegments(vec![]);
    let bad_underflow = nom::Err::Incomplete(nom::Needed::new(4));
    let bad_overflow = nom::Err::Incomplete(nom::Needed::new(2));

    test_parsed_completely_with_two_inputs(&good_wire, false, false, &good);
    test_parsed_completely_with_two_inputs(&good_empty_wire, false, false, &good_empty);
    test_parsed_completely_with_two_inputs(&good_extended_wire, true, false, &good_extended);
    test_parse_error_with_two_inputs::<AsPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_underflow_wire,
        false,
        false,
        bad_underflow,
    );
    test_parse_error_with_two_inputs::<AsPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_overflow_wire,
        false,
        false,
        bad_overflow,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    test_write_with_one_input(&good_empty, false, &good_empty_wire)?;
    Ok(())
}

#[test]
fn test_as4_path_segments() -> Result<(), AsPathWritingError> {
    let good_empty_wire = [0x00, 0x00];
    let good_one_wire = [0x00, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_two_wire = [
        0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];
    let bad_underflow_wire = [0x00, 0x08, 0x01, 0x01, 0x00, 0x01];
    let bad_overflow_wire = [0x00, 0x08, 0x01, 0x02, 0x00, 0x01, 0x00, 0x02];

    let good_empty = AsPath::As4PathSegments(vec![]);
    let good_one = AsPath::As4PathSegments(vec![As4PathSegment::new(
        AsPathSegmentType::AsSequence,
        vec![1],
    )]);
    let good_two = AsPath::As4PathSegments(vec![
        As4PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As4PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);

    let bad_underflow = nom::Err::Incomplete(nom::Needed::new(4));
    let bad_overflow = nom::Err::Incomplete(nom::Needed::new(2));

    test_parsed_completely_with_two_inputs(&good_empty_wire, true, true, &good_empty);
    test_parsed_completely_with_two_inputs(&good_one_wire, true, true, &good_one);
    test_parsed_completely_with_two_inputs(&good_two_wire, true, true, &good_two);

    test_parse_error_with_two_inputs::<AsPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_underflow_wire,
        true,
        true,
        bad_underflow,
    );
    test_parse_error_with_two_inputs::<AsPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_overflow_wire,
        true,
        true,
        bad_overflow,
    );

    test_write_with_one_input(&good_empty, true, &good_empty_wire)?;
    test_write_with_one_input(&good_one, true, &good_one_wire)?;
    test_write_with_one_input(&good_two, true, &good_two_wire)?;

    Ok(())
}

#[test]
fn test_path_attribute_as2_path() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x02, 0x06, 0x02, 0x02, 0x00, 0x64, 0x01, 0x2c];
    let good_wire_extended = [0x50, 0x02, 0x00, 0x06, 0x02, 0x02, 0x00, 0x64, 0x01, 0x2c];
    let undefined_segment_type_wire = [0x50, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x64, 0x01, 0x2c];

    let good = PathAttribute::from(
        false,
        true,
        false,
        false,
        PathAttributeValue::AsPath(AsPath::As2PathSegments(vec![As2PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )])),
    )
    .unwrap();
    let good_extended = PathAttribute::from(
        false,
        true,
        false,
        true,
        PathAttributeValue::AsPath(AsPath::As2PathSegments(vec![As2PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )])),
    )
    .unwrap();

    let undefined_segment_type = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(4, &undefined_segment_type_wire[4..]) },
        PathAttributeParsingError::AsPathError(AsPathParsingError::UndefinedAsPathSegmentType(
            UndefinedAsPathSegmentType(0),
        )),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_wire_extended,
        &mut BgpParsingContext::asn2_default(),
        &good_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &undefined_segment_type_wire,
        &mut BgpParsingContext::asn2_default(),
        &undefined_segment_type,
    );
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_path_attribute_as4_path() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x40, 0x02, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_extended = [
        0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];

    let good = PathAttribute::from(
        false,
        true,
        false,
        false,
        PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )])),
    )
    .unwrap();

    let good_extended = PathAttribute::from(
        false,
        true,
        false,
        true,
        PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);
    test_parsed_completely_with_one_input(
        &good_wire_extended,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_path_attribute_as4_path_transitional() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x11, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_extended = [
        0xd0, 0x11, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_partial = [
        0xf0, 0x11, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];

    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::As4Path(As4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )])),
    )
    .unwrap();
    let good_extended = PathAttribute::from(
        true,
        true,
        false,
        true,
        PathAttributeValue::As4Path(As4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )])),
    )
    .unwrap();
    let good_partial = PathAttribute::from(
        true,
        true,
        true,
        true,
        PathAttributeValue::As4Path(As4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_wire_extended,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_parsed_completely_with_one_input(
        &good_wire_partial,
        &mut BgpParsingContext::default(),
        &good_partial,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    test_write(&good_partial, &good_wire_partial)?;
    Ok(())
}

#[test]
fn test_next_hop() -> Result<(), NextHopWritingError> {
    let good_wire = [0x04, 0xac, 0x10, 0x03, 0x02];
    let bad_wire = [0x05, 0xac, 0x10, 0x03, 0x02];

    let good = NextHop::new(Ipv4Addr::new(172, 16, 3, 2));
    let bad = LocatedNextHopParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_wire) },
        NextHopParsingError::InvalidNextHopLength(PathAttributeLength::U8(5)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<NextHop, bool, LocatedNextHopParsingError<'_>>(
        &bad_wire, false, &bad,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_next_hop() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x03, 0x04, 0xac, 0x10, 0x03, 0x01];
    let good_wire_extended = [0x50, 0x03, 0x00, 0x04, 0xac, 0x10, 0x03, 0x01];
    let bad_wire = [0x50, 0x03, 0x00, 0x03, 0xac, 0x10, 0x03, 0x01];

    let good = PathAttribute::from(
        false,
        true,
        false,
        false,
        PathAttributeValue::NextHop(NextHop::new(Ipv4Addr::new(172, 16, 3, 1))),
    )
    .unwrap();
    let good_extended = PathAttribute::from(
        false,
        true,
        false,
        true,
        PathAttributeValue::NextHop(NextHop::new(Ipv4Addr::new(172, 16, 3, 1))),
    )
    .unwrap();
    let bad = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_wire[2..]) },
        PathAttributeParsingError::NextHopError(NextHopParsingError::InvalidNextHopLength(
            PathAttributeLength::U16(3),
        )),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_wire_extended,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(&bad_wire, &mut BgpParsingContext::asn2_default(), &bad);
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_multi_exit_discriminator() -> Result<(), MultiExitDiscriminatorWritingError> {
    let good_wire = [0x04, 0x00, 0x00, 0x00, 0x01];
    let good_extended_wire = [0x00, 0x04, 0x00, 0x00, 0x00, 0x01];
    let bad_wire = [0x03, 0x00, 0x00, 0x00, 0x01];

    let good = MultiExitDiscriminator::new(1);
    let good_extended = MultiExitDiscriminator::new(1);
    let bad = LocatedMultiExitDiscriminatorParsingError::new(
        Span::new(&bad_wire),
        MultiExitDiscriminatorParsingError::InvalidLength(PathAttributeLength::U8(3)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<
        MultiExitDiscriminator,
        bool,
        LocatedMultiExitDiscriminatorParsingError<'_>,
    >(&bad_wire, false, &bad);

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_multi_exit_discriminator() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x01];
    let good_wire_extended = [0x90, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01];
    let bad_eof_wire = [0x80, 0x04, 0x04, 0x00, 0x00, 0x00];

    let good = PathAttribute::from(
        true,
        false,
        false,
        false,
        PathAttributeValue::MultiExitDiscriminator(MultiExitDiscriminator::new(1)),
    )
    .unwrap();
    let good_extended = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MultiExitDiscriminator(MultiExitDiscriminator::new(1)),
    )
    .unwrap();
    let bad_eof = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &bad_eof_wire[3..]) },
        PathAttributeParsingError::MultiExitDiscriminatorError(
            MultiExitDiscriminatorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_wire_extended,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_eof_wire,
        &mut BgpParsingContext::asn2_default(),
        &bad_eof,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_local_preference() -> Result<(), LocalPreferenceWritingError> {
    let good_wire = [0x04, 0x00, 0x00, 0x00, 0x01];
    let good_extended_wire = [0x00, 0x04, 0x00, 0x00, 0x00, 0x01];
    let bad_underflow_wire = [0x04, 0x00, 0x00, 0x01];
    let bad_length_wire = [0x03, 0x00, 0x00, 0x01];

    let good = LocalPreference::new(1);
    let good_extended = LocalPreference::new(1);
    let bad_underflow = LocatedLocalPreferenceParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_underflow_wire[1..]) },
        LocalPreferenceParsingError::NomError(ErrorKind::Eof),
    );
    let bad_length = LocatedLocalPreferenceParsingError::new(
        Span::new(&bad_length_wire),
        LocalPreferenceParsingError::InvalidLength(PathAttributeLength::U8(3)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<LocalPreference, bool, LocatedLocalPreferenceParsingError<'_>>(
        &bad_underflow_wire,
        false,
        &bad_underflow,
    );
    test_parse_error_with_one_input::<LocalPreference, bool, LocatedLocalPreferenceParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_local_preference() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64];
    let good_extended_wire = [0x50, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];

    let good = PathAttribute::from(
        false,
        true,
        false,
        false,
        PathAttributeValue::LocalPreference(LocalPreference::new(100)),
    )
    .unwrap();
    let good_extended = PathAttribute::from(
        false,
        true,
        false,
        true,
        PathAttributeValue::LocalPreference(LocalPreference::new(100)),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_extended_wire,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_atomic_aggregate() -> Result<(), AtomicAggregateWritingError> {
    let good_wire = [0x00];
    let good_extended_wire = [0x00, 0x00];
    let bad_length_wire = [0x01];
    let bad_extended_length_wire = [0x00, 0x01];

    let good = AtomicAggregate;
    let good_extended = AtomicAggregate;
    let bad_length = LocatedAtomicAggregateParsingError::new(
        Span::new(&bad_length_wire),
        AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U8(1)),
    );
    let bad_extended_length = LocatedAtomicAggregateParsingError::new(
        Span::new(&bad_extended_length_wire),
        AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U16(1)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<AtomicAggregate, bool, LocatedAtomicAggregateParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<AtomicAggregate, bool, LocatedAtomicAggregateParsingError<'_>>(
        &bad_extended_length_wire,
        true,
        &bad_extended_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_atomic_aggregate() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x06, 0x00];
    let good_extended_wire = [0x50, 0x06, 0x00, 0x00];
    let bad_length_wire = [0x40, 0x06, 0x01];
    let bad_extended_length_wire = [0x50, 0x06, 0x00, 0x01];

    let good = PathAttribute::from(
        false,
        true,
        false,
        false,
        PathAttributeValue::AtomicAggregate(AtomicAggregate),
    )
    .unwrap();

    let good_extended = PathAttribute::from(
        false,
        true,
        false,
        true,
        PathAttributeValue::AtomicAggregate(AtomicAggregate),
    )
    .unwrap();
    let bad_length = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_length_wire[2..]) },
        PathAttributeParsingError::AtomicAggregateError(
            AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U8(1)),
        ),
    );
    let bad_extended_length = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_extended_length_wire[2..]) },
        PathAttributeParsingError::AtomicAggregateError(
            AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U16(1)),
        ),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_extended_wire,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_length_wire,
        &mut BgpParsingContext::asn2_default(),
        &bad_length,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_extended_length_wire,
        &mut BgpParsingContext::default(),
        &bad_extended_length,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_as2_aggregator() -> Result<(), AggregatorWritingError> {
    let good_wire = [0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_length_wire = [0x05, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_extended_wire = [0x00, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_extended_length_wire = [0x00, 0x07, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];

    let good = As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));
    let good_extended = As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));

    let bad_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U8(5)),
    );

    let bad_extended_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_extended_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U16(7)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<As2Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<As2Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_extended_length_wire,
        true,
        &bad_extended_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_as4_aggregator() -> Result<(), AggregatorWritingError> {
    let good_wire = [0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_length_wire = [0x09, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_extended_wire = [0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_extended_length_wire = [0x00, 0x07, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];

    let good = As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));
    let good_extended = As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));

    let bad_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U8(9)),
    );

    let bad_extended_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_extended_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U16(7)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<As4Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<As4Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_extended_length_wire,
        true,
        &bad_extended_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_as2_aggregator() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0xc0, 0x07, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_partial_wire = [0xe0, 0x07, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_extended_wire = [0xd0, 0x07, 0x00, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_partial_extended_wire = [0xf0, 0x07, 0x00, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_length_wire = [0xc0, 0x07, 0x08, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_incomplete_wire = [0xc0, 0x07, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00];

    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::Aggregator(Aggregator::As2Aggregator(As2Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    let good_partial = PathAttribute::from(
        true,
        true,
        true,
        false,
        PathAttributeValue::Aggregator(Aggregator::As2Aggregator(As2Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    let good_extended = PathAttribute::from(
        true,
        true,
        false,
        true,
        PathAttributeValue::Aggregator(Aggregator::As2Aggregator(As2Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    let good_partial_extended = PathAttribute::from(
        true,
        true,
        true,
        true,
        PathAttributeValue::Aggregator(Aggregator::As2Aggregator(As2Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    let bad_length = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_length_wire[2..]) },
        PathAttributeParsingError::AggregatorError(AggregatorParsingError::InvalidLength(
            PathAttributeLength::U8(8),
        )),
    );

    let bad_incomplete = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(5, &bad_incomplete_wire[5..]) },
        PathAttributeParsingError::AggregatorError(AggregatorParsingError::NomError(
            ErrorKind::Eof,
        )),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(
        &good_partial_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_partial,
    );
    test_parsed_completely_with_one_input(
        &good_extended_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_extended,
    );
    test_parsed_completely_with_one_input(
        &good_partial_extended_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_partial_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_length_wire,
        &mut BgpParsingContext::asn2_default(),
        &bad_length,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_incomplete_wire,
        &mut BgpParsingContext::asn2_default(),
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_partial, &good_partial_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    test_write(&good_partial_extended, &good_partial_extended_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_as4_aggregator() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x07, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];
    let good_partial_wire = [
        0xe0, 0x07, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];
    let good_extended_wire = [
        0xd0, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];
    let good_partial_extended_wire = [
        0xf0, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];

    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::Aggregator(Aggregator::As4Aggregator(As4Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    let good_partial = PathAttribute::from(
        true,
        true,
        true,
        false,
        PathAttributeValue::Aggregator(Aggregator::As4Aggregator(As4Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    let good_extended = PathAttribute::from(
        true,
        true,
        false,
        true,
        PathAttributeValue::Aggregator(Aggregator::As4Aggregator(As4Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    let good_partial_extended = PathAttribute::from(
        true,
        true,
        true,
        true,
        PathAttributeValue::Aggregator(Aggregator::As4Aggregator(As4Aggregator::new(
            100,
            Ipv4Addr::new(172, 16, 0, 10),
        ))),
    )
    .unwrap();

    test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);
    test_parsed_completely_with_one_input(
        &good_partial_wire,
        &mut BgpParsingContext::default(),
        &good_partial,
    );
    test_parsed_completely_with_one_input(
        &good_extended_wire,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_parsed_completely_with_one_input(
        &good_partial_extended_wire,
        &mut BgpParsingContext::default(),
        &good_partial_extended,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_partial, &good_partial_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    test_write(&good_partial_extended, &good_partial_extended_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_communities() -> Result<(), PathAttributeWritingError> {
    let good_zero_wire = [0xc0, 0x08, 0x00];
    let good_one_wire = [0xc0, 0x08, 0x04, 0x00, 0x00, 0x00, 0x01];
    let good_two_wire = [
        0xc0, 0x08, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    ];
    let good_two_wire_extended = [
        0xd0, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    ];

    let good_zero = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::Communities(Communities::new(vec![])),
    )
    .unwrap();

    let good_one = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::Communities(Communities::new(vec![Community::new(1)])),
    )
    .unwrap();

    let good_two = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::Communities(Communities::new(vec![
            Community::new(1),
            Community::new(2),
        ])),
    )
    .unwrap();

    let good_two_extended = PathAttribute::from(
        true,
        true,
        false,
        true,
        PathAttributeValue::Communities(Communities::new(vec![
            Community::new(1),
            Community::new(2),
        ])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_zero_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_zero,
    );
    test_parsed_completely_with_one_input(
        &good_one_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_one,
    );
    test_parsed_completely_with_one_input(
        &good_two_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_two,
    );
    test_parsed_completely_with_one_input(
        &good_two_wire_extended,
        &mut BgpParsingContext::default(),
        &good_two_extended,
    );
    test_write(&good_zero, &good_zero_wire)?;
    test_write(&good_one, &good_one_wire)?;
    test_write(&good_two, &good_two_wire)?;
    test_write(&good_two_extended, &good_two_wire_extended)?;
    Ok(())
}

#[test]
fn test_mp_reach_nlri_ipv6() -> Result<(), MpReachWritingError> {
    let good_wire = [
        0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let good_extended_wire = [
        0x00, 0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00,
        0x01, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01,
        0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let unknown_address_type_wire = [
        0x40, 0x00, 0x0c, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let invalid_afi_wire = [
        0x40, 0x00, 0xff, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let invalid_safi_wire = [
        0x40, 0x00, 0x02, 0xff, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let good = MpReach::Ipv6Unicast {
        next_hop_global: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1),
        next_hop_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0xbff, 0xfe7e, 0)),
        nlri: vec![
            Ipv6UnicastAddress::new(
                None,
                Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:2::/64").unwrap()).unwrap(),
            ),
            Ipv6UnicastAddress::new(
                None,
                Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:1::/64").unwrap()).unwrap(),
            ),
            Ipv6UnicastAddress::new(
                None,
                Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1::/64").unwrap()).unwrap(),
            ),
        ],
    };

    let unknown_address_type = MpReach::Unknown {
        afi: AddressFamily::AppleTalk,
        safi: SubsequentAddressFamily::Unicast,
        value: unknown_address_type_wire[4..].to_vec(),
    };

    let invalid_afi = LocatedMpReachParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &invalid_afi_wire[1..]) },
        MpReachParsingError::UndefinedAddressFamily(UndefinedAddressFamily(0xff)),
    );

    let invalid_safi = LocatedMpReachParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &invalid_safi_wire[3..]) },
        MpReachParsingError::UndefinedSubsequentAddressFamily(UndefinedSubsequentAddressFamily(
            0xff,
        )),
    );

    assert_eq!(good.address_type(), Ok(AddressType::Ipv6Unicast));
    assert_eq!(good.afi(), AddressType::Ipv6Unicast.address_family());
    assert_eq!(
        good.safi(),
        AddressType::Ipv6Unicast.subsequent_address_family()
    );

    assert_eq!(
        unknown_address_type.address_type(),
        Err((AddressFamily::AppleTalk, SubsequentAddressFamily::Unicast))
    );
    assert_eq!(unknown_address_type.afi(), AddressFamily::AppleTalk);
    assert_eq!(
        unknown_address_type.safi(),
        SubsequentAddressFamily::Unicast
    );

    test_parsed_completely_with_three_inputs(
        &good_wire,
        false,
        &HashMap::new(),
        &HashMap::new(),
        &good,
    );
    test_parsed_completely_with_three_inputs(
        &good_extended_wire,
        true,
        &HashMap::new(),
        &HashMap::new(),
        &good,
    );
    test_parsed_completely_with_three_inputs(
        &unknown_address_type_wire,
        false,
        &HashMap::new(),
        &HashMap::new(),
        &unknown_address_type,
    );

    test_parse_error_with_three_inputs::<
        MpReach,
        bool,
        &HashMap<AddressType, u8>,
        &HashMap<AddressType, bool>,
        LocatedMpReachParsingError<'_>,
    >(
        &invalid_afi_wire,
        false,
        &HashMap::new(),
        &HashMap::new(),
        nom::Err::Error(invalid_afi),
    );
    test_parse_error_with_three_inputs::<
        MpReach,
        bool,
        &HashMap<AddressType, u8>,
        &HashMap<AddressType, bool>,
        LocatedMpReachParsingError<'_>,
    >(
        &invalid_safi_wire,
        false,
        &HashMap::new(),
        &HashMap::new(),
        nom::Err::Error(invalid_safi),
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_mp_reach_nlri_ipv4_ipv6_next_hop() -> Result<(), MpReachWritingError> {
    let good_no_link_local_wire = [
        0x00, 0x1a, 0x00, 0x01, 0x01, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x91, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0xc0, 0x00, 0x02, 0x0d,
    ];

    let good_link_local_wire = [
        0x00, 0x2a, 0x00, 0x01, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x0, 0x91, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8, 0x00, 0x20, 0xc0, 0x00, 0x02, 0x0d,
    ];

    let good_no_link_local = MpReach::Ipv4Unicast {
        next_hop: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x91, 0, 0, 0, 0, 0x1)),
        next_hop_local: None,
        nlri: vec![Ipv4UnicastAddress::new(
            None,
            Ipv4Unicast::from_net(Ipv4Net::from_str("192.0.2.13/32").unwrap()).unwrap(),
        )],
    };

    let good_link_local = MpReach::Ipv4Unicast {
        next_hop: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x91, 0, 0, 0, 0, 0x1)),
        next_hop_local: Some(Ipv6Addr::from_str("FE80::AB8").unwrap()),
        nlri: vec![Ipv4UnicastAddress::new(
            None,
            Ipv4Unicast::from_net(Ipv4Net::from_str("192.0.2.13/32").unwrap()).unwrap(),
        )],
    };

    test_parsed_completely_with_three_inputs(
        &good_no_link_local_wire,
        true,
        &HashMap::new(),
        &HashMap::new(),
        &good_no_link_local,
    );

    test_parsed_completely_with_three_inputs(
        &good_link_local_wire,
        true,
        &HashMap::new(),
        &HashMap::new(),
        &good_link_local,
    );

    test_write_with_one_input(&good_no_link_local, true, &good_no_link_local_wire)?;
    test_write_with_one_input(&good_link_local, true, &good_link_local_wire)?;
    Ok(())
}

#[test]
fn test_mp_reach_nlri_ipv4_mpls_labels_ipv6_next_hop() -> Result<(), MpReachWritingError> {
    let good_no_link_local_wire = [
        0x00, 0x1d, 0x00, 0x01, 0x04, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x91, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x38, 0x01, 0x03, 0x00, 0xc0, 0x00, 0x02,
        0x0d,
    ];

    let good_link_local_wire = [
        0x00, 0x2d, 0x00, 0x01, 0x04, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x91, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8, 0x00, 0x38, 0x01, 0x03, 0x00, 0xc0, 0x00,
        0x02, 0x0d,
    ];

    let good_no_link_local = MpReach::Ipv4NlriMplsLabels {
        next_hop: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x91, 0, 0, 0, 0, 0x1)),
        next_hop_local: None,
        nlri: vec![
            Ipv4NlriMplsLabelsAddress::from(
                None,
                vec![MplsLabel::new([1, 3, 0])],
                Ipv4Net::from_str("192.0.2.13/32").unwrap(),
            )
            .unwrap(),
        ],
    };

    let good_link_local = MpReach::Ipv4NlriMplsLabels {
        next_hop: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x91, 0, 0, 0, 0, 0x1)),
        next_hop_local: Some(Ipv6Addr::from_str("FE80::AB8").unwrap()),
        nlri: vec![
            Ipv4NlriMplsLabelsAddress::from(
                None,
                vec![MplsLabel::new([1, 3, 0])],
                Ipv4Net::from_str("192.0.2.13/32").unwrap(),
            )
            .unwrap(),
        ],
    };

    test_parsed_completely_with_three_inputs(
        &good_no_link_local_wire,
        true,
        &HashMap::new(),
        &HashMap::new(),
        &good_no_link_local,
    );

    test_parsed_completely_with_three_inputs(
        &good_link_local_wire,
        true,
        &HashMap::new(),
        &HashMap::new(),
        &good_link_local,
    );

    test_write_with_one_input(&good_no_link_local, true, &good_no_link_local_wire)?;
    test_write_with_one_input(&good_link_local, true, &good_link_local_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv4_unicast() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x01, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x10, 0xc0,
        0xa8,
    ];
    let invalid_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x01, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x30, 0xe0,
        0x00,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(MpReach::Ipv4Unicast {
            next_hop: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 20)),
            next_hop_local: None,
            nlri: vec![Ipv4UnicastAddress::new(
                None,
                Ipv4Unicast::from_net(Ipv4Net::from_str("192.168.0.0/16").unwrap()).unwrap(),
            )],
        }),
    )
    .unwrap();

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(14, &invalid_wire[14..]) },
        PathAttributeParsingError::MpReachErrorError(MpReachParsingError::Ipv4UnicastAddressError(
            Ipv4UnicastAddressParsingError::Ipv4UnicastError(
                Ipv4UnicastParsingError::Ipv4PrefixError(Ipv4PrefixParsingError::NomError(
                    ErrorKind::Eof,
                )),
            ),
        )),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &invalid_wire,
        &mut BgpParsingContext::asn2_default(),
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv4_multicast() -> Result<(), PathAttributeWritingError>
{
    let good_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x02, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x10, 0xe0,
        0x00,
    ];
    let invalid_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x02, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x30, 0xe0,
        0x00,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(MpReach::Ipv4Multicast {
            next_hop: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 20)),
            next_hop_local: None,
            nlri: vec![Ipv4MulticastAddress::new_no_path_id(
                Ipv4Multicast::from_net(Ipv4Net::from_str("224.0.0.0/16").unwrap()).unwrap(),
            )],
        }),
    )
    .unwrap();

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(14, &invalid_wire[14..]) },
        PathAttributeParsingError::MpReachErrorError(
            MpReachParsingError::Ipv4MulticastAddressError(
                Ipv4MulticastAddressParsingError::Ipv4MulticastError(
                    Ipv4MulticastParsingError::Ipv4PrefixError(Ipv4PrefixParsingError::NomError(
                        ErrorKind::Eof,
                    )),
                ),
            ),
        ),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &invalid_wire,
        &mut BgpParsingContext::asn2_default(),
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv6_unicast() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20,
        0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
    ];
    let invalid_addr_wire: [u8; 67] = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0xff, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x02, 0x40, 0xff, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0xff,
        0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        false,
        PathAttributeValue::MpReach(MpReach::Ipv6Unicast {
            next_hop_global: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1),
            next_hop_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0xbff, 0xfe7e, 0)),
            nlri: vec![
                Ipv6UnicastAddress::new(
                    None,
                    Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:2::/64").unwrap()).unwrap(),
                ),
                Ipv6UnicastAddress::new(
                    None,
                    Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:1::/64").unwrap()).unwrap(),
                ),
                Ipv6UnicastAddress::new(
                    None,
                    Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1::/64").unwrap()).unwrap(),
                ),
            ],
        }),
    )
    .unwrap();

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(40, &invalid_addr_wire[40..]) },
        PathAttributeParsingError::MpReachErrorError(MpReachParsingError::Ipv6UnicastAddressError(
            Ipv6UnicastAddressParsingError::Ipv6UnicastError(
                Ipv6UnicastParsingError::InvalidUnicastNetwork(InvalidIpv6UnicastNetwork(
                    Ipv6Net::from_str("ff01:db8:1:2::/64").unwrap(),
                )),
            ),
        )),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &invalid_addr_wire,
        &mut BgpParsingContext::asn2_default(),
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv6_multicast() -> Result<(), PathAttributeWritingError>
{
    let good_wire = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x02, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0xff, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x02, 0x40, 0xff, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0xff,
        0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let invalid_addr_wire = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x02, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x01, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x02, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20,
        0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        false,
        PathAttributeValue::MpReach(MpReach::Ipv6Multicast {
            next_hop_global: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1),
            next_hop_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0xbff, 0xfe7e, 0)),
            nlri: vec![
                Ipv6MulticastAddress::new_no_path_id(
                    Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8:1:2::/64").unwrap())
                        .unwrap(),
                ),
                Ipv6MulticastAddress::new_no_path_id(
                    Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8:1:1::/64").unwrap())
                        .unwrap(),
                ),
                Ipv6MulticastAddress::new_no_path_id(
                    Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8:1::/64").unwrap()).unwrap(),
                ),
            ],
        }),
    )
    .unwrap();

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(40, &invalid_addr_wire[40..]) },
        PathAttributeParsingError::MpReachErrorError(
            MpReachParsingError::Ipv6MulticastAddressError(
                Ipv6MulticastAddressParsingError::Ipv6MulticastError(
                    Ipv6MulticastParsingError::InvalidMulticastNetwork(
                        InvalidIpv6MulticastNetwork(
                            Ipv6Net::from_str("2001:db8:1:2::/64").unwrap(),
                        ),
                    ),
                ),
            ),
        ),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &invalid_addr_wire,
        &mut BgpParsingContext::asn2_default(),
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_unreach_nlri_ipv6_unicast() -> Result<(), PathAttributeWritingError>
{
    let good_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x40, 0xfd, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];
    let invalid_afi_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x01, 0x20, 0xff, 0x01, 0x0d, 0xb8, 0x40, 0xfd, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpUnreach(MpUnreach::Ipv6Unicast {
            nlri: vec![
                Ipv6UnicastAddress::new(
                    None,
                    Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8::/32").unwrap()).unwrap(),
                ),
                Ipv6UnicastAddress::new(
                    None,
                    Ipv6Unicast::from_net(Ipv6Net::from_str("fdfd:0:0:8bea::/64").unwrap())
                        .unwrap(),
                ),
            ],
        }),
    )
    .unwrap();

    let invalid_afi = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(7, &invalid_afi_wire[7..]) },
        PathAttributeParsingError::MpUnreachErrorError(
            MpUnreachParsingError::Ipv6UnicastAddressError(
                Ipv6UnicastAddressParsingError::Ipv6UnicastError(
                    Ipv6UnicastParsingError::InvalidUnicastNetwork(InvalidIpv6UnicastNetwork(
                        Ipv6Net::from_str("ff01:db8::/32").unwrap(),
                    )),
                ),
            ),
        ),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &invalid_afi_wire,
        &mut BgpParsingContext::asn2_default(),
        &invalid_afi,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_unreach_nlri_ipv6_multicast()
-> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x02, 0x20, 0xff, 0x01, 0x0d, 0xb8, 0x40, 0xff, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];
    let invalid_afi_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x02, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x40, 0xff, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpUnreach(MpUnreach::Ipv6Multicast {
            nlri: vec![
                Ipv6MulticastAddress::new_no_path_id(
                    Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8::/32").unwrap()).unwrap(),
                ),
                Ipv6MulticastAddress::new_no_path_id(
                    Ipv6Multicast::from_net(Ipv6Net::from_str("fffd:0:0:8bea::/64").unwrap())
                        .unwrap(),
                ),
            ],
        }),
    )
    .unwrap();

    let invalid_afi = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(7, &invalid_afi_wire[7..]) },
        PathAttributeParsingError::MpUnreachErrorError(
            MpUnreachParsingError::Ipv6MulticastAddressError(
                Ipv6MulticastAddressParsingError::Ipv6MulticastError(
                    Ipv6MulticastParsingError::InvalidMulticastNetwork(
                        InvalidIpv6MulticastNetwork(Ipv6Net::from_str("2001:db8::/32").unwrap()),
                    ),
                ),
            ),
        ),
    );

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &invalid_afi_wire,
        &mut BgpParsingContext::asn2_default(),
        &invalid_afi,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_mp_reach_labeled_vpn_ipv4() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x2c, 0x00, 0x01, 0x80, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x70, 0x00, 0x41, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0xc0, 0xa8, 0x01,
    ];

    let mp_reach = MpReach::Ipv4MplsVpnUnicast {
        next_hop: LabeledNextHop::Ipv6(LabeledIpv6NextHop::new(
            RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
            Ipv6Addr::from_str("fc00::1").unwrap(),
            None,
        )),
        nlri: vec![Ipv4MplsVpnUnicastAddress::new_no_path_id(
            RouteDistinguisher::As2Administrator { asn2: 1, number: 1 },
            vec![MplsLabel::new([0, 65, 1])],
            Ipv4Unicast::from_net(Ipv4Net::from_str("192.168.1.0/24").unwrap()).unwrap(),
        )],
    };
    assert_eq!(mp_reach.address_type(), Ok(AddressType::Ipv4MplsLabeledVpn));
    assert_eq!(
        mp_reach.afi(),
        AddressType::Ipv4MplsLabeledVpn.address_family()
    );
    assert_eq!(
        mp_reach.safi(),
        AddressType::Ipv4MplsLabeledVpn.subsequent_address_family()
    );

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(mp_reach),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_mp_reach_multi_labels_vp_ipv4() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        144, 14, 0, 47, 0, 1, 128, 24, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 136, 0, 65, 0, 0, 65, 1, 0, 0, 0, 1, 0, 0, 0, 1, 192, 168, 1,
    ];

    let mp_reach = MpReach::Ipv4MplsVpnUnicast {
        next_hop: LabeledNextHop::Ipv6(LabeledIpv6NextHop::new(
            RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
            Ipv6Addr::from_str("fc00::1").unwrap(),
            None,
        )),
        nlri: vec![Ipv4MplsVpnUnicastAddress::new_no_path_id(
            RouteDistinguisher::As2Administrator { asn2: 1, number: 1 },
            vec![MplsLabel::new([0, 65, 0]), MplsLabel::new([0, 65, 1])],
            Ipv4Unicast::from_net(Ipv4Net::from_str("192.168.1.0/24").unwrap()).unwrap(),
        )],
    };
    assert_eq!(mp_reach.address_type(), Ok(AddressType::Ipv4MplsLabeledVpn));
    assert_eq!(
        mp_reach.afi(),
        AddressType::Ipv4MplsLabeledVpn.address_family()
    );
    assert_eq!(
        mp_reach.safi(),
        AddressType::Ipv4MplsLabeledVpn.subsequent_address_family()
    );

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(mp_reach),
    )
    .unwrap();

    let limit_exceeded1 = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(37, &good_wire[37..]) },
        PathAttributeParsingError::MpReachErrorError(
            MpReachParsingError::Ipv4MplsVpnUnicastAddressError(
                Ipv4MplsVpnUnicastAddressParsingError::RouteDistinguisherError(
                    RouteDistinguisherParsingError::UndefinedRouteDistinguisherTypeCode(
                        UndefinedRouteDistinguisherTypeCode(65),
                    ),
                ),
            ),
        ),
    );

    let limit_exceeded2 = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(37, &good_wire[37..]) },
        PathAttributeParsingError::MpReachErrorError(
            MpReachParsingError::Ipv4MplsVpnUnicastAddressError(
                Ipv4MplsVpnUnicastAddressParsingError::RouteDistinguisherError(
                    RouteDistinguisherParsingError::UndefinedRouteDistinguisherTypeCode(
                        UndefinedRouteDistinguisherTypeCode(65),
                    ),
                ),
            ),
        ),
    );

    // Test valid input
    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::new(
            false,
            HashMap::from([(AddressType::Ipv4MplsLabeledVpn, 2)]),
            HashMap::new(),
            true,
            true,
            true,
            true,
        ),
        &good,
    );

    // Test with MAX limit
    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::new(
            false,
            HashMap::from([(AddressType::Ipv4MplsLabeledVpn, u8::MAX)]),
            HashMap::new(),
            true,
            true,
            true,
            true,
        ),
        &good,
    );

    // Test with no limit spec, should default to one label and fail since there's
    // two labels
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &limit_exceeded1,
    );

    // Test with with one label limit, should fail since there's two labels
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &good_wire,
        &mut BgpParsingContext::new(
            false,
            HashMap::from([(AddressType::Ipv4MplsLabeledVpn, 1)]),
            HashMap::new(),
            true,
            true,
            true,
            true,
        ),
        &limit_exceeded2,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_mp_reach_labeled_vpn_ipv6() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x4d, 0x00, 0x02, 0x80, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfd, 0xea, 0x3e, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0xd6, 0xe0, 0x08, 0x01, 0x00, 0x01, 0x0a, 0xd7, 0xb6, 0x30, 0x00, 0x03,
        0xfd, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x98, 0xe0, 0x08, 0x01, 0x00, 0x01, 0x0a, 0xd7, 0xb6, 0x30, 0x00, 0x03, 0xfd, 0x01,
        0xca, 0xfe, 0x00, 0x02, 0x00, 0x03,
    ];

    let mp_reach = MpReach::Ipv6MplsVpnUnicast {
        next_hop: LabeledNextHop::Ipv6(LabeledIpv6NextHop::new(
            RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
            Ipv6Addr::from_str("fdea:3e00:400::1").unwrap(),
            None,
        )),
        nlri: vec![
            Ipv6MplsVpnUnicastAddress::new_no_path_id(
                RouteDistinguisher::Ipv4Administrator {
                    ip: Ipv4Addr::new(10, 215, 182, 48),
                    number: 3,
                },
                vec![MplsLabel::new([0xe0, 0x08, 0x01])],
                Ipv6Unicast::from_net(Ipv6Net::from_str("fd00:2::4/126").unwrap()).unwrap(),
            ),
            Ipv6MplsVpnUnicastAddress::new_no_path_id(
                RouteDistinguisher::Ipv4Administrator {
                    ip: Ipv4Addr::new(10, 215, 182, 48),
                    number: 3,
                },
                vec![MplsLabel::new([0xe0, 0x08, 0x01])],
                Ipv6Unicast::from_net(Ipv6Net::from_str("fd01:cafe:2:3::/64").unwrap()).unwrap(),
            ),
        ],
    };

    assert_eq!(mp_reach.address_type(), Ok(AddressType::Ipv6MplsLabeledVpn));
    assert_eq!(
        mp_reach.afi(),
        AddressType::Ipv6MplsLabeledVpn.address_family()
    );
    assert_eq!(
        mp_reach.safi(),
        AddressType::Ipv6MplsLabeledVpn.subsequent_address_family()
    );

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(mp_reach),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_mp_reach_nlri_mpls_labels_ipv6() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x29, 0x00, 0x02, 0x04, 0x10, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x98, 0x05, 0xdc, 0x31, 0xfc,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(MpReach::Ipv6NlriMplsLabels {
            next_hop: IpAddr::V6(Ipv6Addr::from_str("fc00::3").unwrap()),
            next_hop_local: None,
            nlri: vec![
                Ipv6NlriMplsLabelsAddress::new_no_path_id(
                    vec![MplsLabel::new([0x05, 0xdc, 0x31])],
                    Ipv6Net::from_str("fc00::3/128").unwrap(),
                )
                .unwrap(),
            ],
        }),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_transitive_two_octet_extended_community() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x10, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];
    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
            ExtendedCommunity::TransitiveTwoOctet(
                TransitiveTwoOctetExtendedCommunity::RouteTarget {
                    global_admin: 1,
                    local_admin: 1,
                },
            ),
        ])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_non_transitive_two_octet_extended_community() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x10, 0x08, 0x40, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];
    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
            ExtendedCommunity::NonTransitiveTwoOctet(
                NonTransitiveTwoOctetExtendedCommunity::LinkBandwidth {
                    global_admin: 1,
                    local_admin: 1,
                },
            ),
        ])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_transitive_ipv4_extended_community() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x10, 0x08, 0x01, 0x02, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x2d,
    ];
    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
            ExtendedCommunity::TransitiveIpv4(TransitiveIpv4ExtendedCommunity::RouteTarget {
                global_admin: Ipv4Addr::new(10, 11, 12, 8),
                local_admin: 45,
            }),
        ])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_unknown_extended_community() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x10, 0x08, 0x33, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];
    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
            ExtendedCommunity::Unknown(UnknownExtendedCommunity::new(0x33, 2, [0, 1, 0, 0, 0, 1])),
        ])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_multiple_extended_communities() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x10, 0x18, 0x00, 0x03, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x04, 0x00, 0x64,
        0x4e, 0x08, 0x04, 0x8e, 0x01, 0x02, 0x0a, 0x0a, 0x08, 0x08, 0x00, 0x2d,
    ];
    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
            ExtendedCommunity::TransitiveTwoOctet(
                TransitiveTwoOctetExtendedCommunity::RouteOrigin {
                    global_admin: 100,
                    local_admin: 200,
                },
            ),
            ExtendedCommunity::TransitiveTwoOctet(
                TransitiveTwoOctetExtendedCommunity::Unassigned {
                    sub_type: 4,
                    global_admin: 100,
                    local_admin: 1309148302,
                },
            ),
            ExtendedCommunity::TransitiveIpv4(TransitiveIpv4ExtendedCommunity::RouteTarget {
                global_admin: Ipv4Addr::new(10, 10, 8, 8),
                local_admin: 45,
            }),
        ])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_large_community() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x20, 0x0c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x38,
    ];
    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::LargeCommunities(LargeCommunities::new(vec![LargeCommunity::new(
            12, 34, 56,
        )])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_originator() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x80, 0x09, 0x04, 0xd5, 0xb1, 0x7f, 0xbe];
    let good = PathAttribute::from(
        true,
        false,
        false,
        false,
        PathAttributeValue::Originator(Originator::new(Ipv4Addr::new(213, 177, 127, 190))),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_cluster_list() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x80, 0x0a, 0x04, 0x00, 0x00, 0x00, 0xc8];
    let good = PathAttribute::from(
        true,
        false,
        false,
        false,
        PathAttributeValue::ClusterList(ClusterList::new(vec![ClusterId::new(Ipv4Addr::new(
            0, 0, 0, 200,
        ))])),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_unknown_attribute() -> Result<(), UnknownAttributeWritingError> {
    let good_wire = [0x00, 0x04, 0xac, 0x10, 0x03, 0x02];
    let good_extended_wire = [0x00, 0x00, 0x04, 0xac, 0x10, 0x03, 0x02];

    let good = UnknownAttribute::new(0, vec![0xac, 0x10, 0x03, 0x02]);
    let good_extended = UnknownAttribute::new(0, vec![0xac, 0x10, 0x03, 0x02]);

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_unknown_attribute() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0xc0, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];
    let good_extended_wire = [0xd0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];
    let bad_incomplete_wire = [0xc0, 0x00, 0x04, 0x00, 0x00, 0x00];

    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::UnknownAttribute(UnknownAttribute::new(0, good_wire[3..].into())),
    )
    .unwrap();

    let good_extended = PathAttribute::from(
        true,
        true,
        false,
        true,
        PathAttributeValue::UnknownAttribute(UnknownAttribute::new(0, good_wire[3..].into())),
    )
    .unwrap();

    let bad_incomplete = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_incomplete_wire[2..]) },
        PathAttributeParsingError::UnknownAttributeError(
            UnknownAttributeParsingError::InvalidLength {
                expecting: 4,
                actual: 3,
            },
        ),
    );

    test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);
    test_parsed_completely_with_one_input(
        &good_extended_wire,
        &mut BgpParsingContext::default(),
        &good_extended,
    );
    test_parse_error_with_one_input::<
        PathAttribute,
        &mut BgpParsingContext,
        LocatedPathAttributeParsingError<'_>,
    >(
        &bad_incomplete_wire,
        &mut BgpParsingContext::asn2_default(),
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attr_route_target_membership() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x7d, 0x00, 0x01, 0x84, 0x10, 0xfd, 0x00, 0x3f, 0x00, 0x03, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x60, 0x00, 0x00, 0xff, 0xcc,
        0x00, 0x02, 0xff, 0xcc, 0x00, 0x00, 0x0f, 0xb2, 0x60, 0x00, 0x00, 0xff, 0xcc, 0x00, 0x02,
        0xff, 0xcc, 0x00, 0x00, 0x0f, 0xa3, 0x60, 0x00, 0x00, 0xff, 0xcc, 0x00, 0x02, 0xff, 0xcc,
        0x00, 0x00, 0x00, 0x02, 0x60, 0x00, 0x00, 0xff, 0xcc, 0x00, 0x02, 0xff, 0xcc, 0x00, 0x00,
        0x00, 0x01, 0x60, 0x00, 0x00, 0xff, 0xcc, 0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xd9,
        0x60, 0x00, 0x00, 0xff, 0xcc, 0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xd8, 0x60, 0x00,
        0x00, 0xff, 0xcc, 0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xc5, 0x60, 0x00, 0x00, 0xff,
        0xcc, 0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xc4,
    ];

    let mp_reach = MpReach::RouteTargetMembership {
        next_hop: IpAddr::V6(Ipv6Addr::from_str("fd00:3f00:302::1").unwrap()),
        nlri: vec![
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0xff, 0xcc, 0x00, 0x00, 0x0f, 0xb2],
                )),
            ),
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0xff, 0xcc, 0x00, 0x00, 0x0f, 0xa3],
                )),
            ),
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0xff, 0xcc, 0x00, 0x00, 0x00, 0x02],
                )),
            ),
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0xff, 0xcc, 0x00, 0x00, 0x00, 0x01],
                )),
            ),
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xd9],
                )),
            ),
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xd8],
                )),
            ),
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xc5],
                )),
            ),
            RouteTargetMembershipAddress::new(
                None,
                Some(RouteTargetMembership::new(
                    65484,
                    vec![0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x04, 0xc4],
                )),
            ),
        ],
    };
    assert_eq!(
        mp_reach.address_type(),
        Ok(AddressType::RouteTargetConstrains)
    );
    assert_eq!(
        mp_reach.afi(),
        AddressType::RouteTargetConstrains.address_family()
    );
    assert_eq!(
        mp_reach.safi(),
        AddressType::RouteTargetConstrains.subsequent_address_family()
    );

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(mp_reach),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_otc_path_attribute() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0xc0, 0x23, 0x04, 0x00, 0x00, 0xfd, 0xe9];
    let good = PathAttribute::from(
        true,
        true,
        false,
        false,
        PathAttributeValue::OnlyToCustomer(OnlyToCustomer::new(65001)),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_aigp_path_attribute() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x80, 0x1a, 0x0b, 0x01, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        false,
        PathAttributeValue::Aigp(Aigp::AccumulatedIgpMetric(4294967295)),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_nlri_mpls_labels_address() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x11, 0x00, 0x01, 0x04, 0x04, 0xc6, 0x33, 0x64, 0x47, 0x00, 0x37, 0x10,
        0x03, 0x31, 0xcb, 0x00, 0x71, 0xfe,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(MpReach::Ipv4NlriMplsLabels {
            next_hop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 71)),
            next_hop_local: None,
            nlri: vec![
                Ipv4NlriMplsLabelsAddress::from(
                    None,
                    vec![MplsLabel::new([16, 3, 49])],
                    Ipv4Net::from_str("203.0.113.254/31").unwrap(),
                )
                .unwrap(),
            ],
        }),
    )
    .unwrap();

    test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
#[test]
pub fn test_segment_identifier_label_index() -> Result<(), BgpMessageWritingError> {
    let good_wire: [u8; 89] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x59, 0x02, 0x00, 0x00, 0x00, 0x42, 0x90, 0x0e, 0x00, 0x0e, 0x00, 0x01, 0x01,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xcb, 0x00, 0x71, 0x5a, 0x40, 0x01, 0x01, 0x00,
        0x40, 0x02, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00,
        0x00, 0x64, 0x80, 0x1a, 0x0b, 0x01, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x28, 0x0a, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5a,
    ];

    let good = BgpMessage::Update(BgpUpdateMessage::new(
        vec![],
        vec![
            PathAttribute::from(
                true,
                false,
                false,
                true,
                PathAttributeValue::MpReach(MpReach::Ipv4Unicast {
                    next_hop: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    next_hop_local: None,
                    nlri: vec![Ipv4UnicastAddress::new(
                        None,
                        Ipv4Unicast::from_net(
                            Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 90), 32).unwrap(),
                        )
                        .unwrap(),
                    )],
                }),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::Origin(Origin::IGP),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![])),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::MultiExitDiscriminator(MultiExitDiscriminator::new(0)),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::LocalPreference(LocalPreference::new(100)),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::Aigp(Aigp::AccumulatedIgpMetric(0)),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                true,
                false,
                false,
                PathAttributeValue::PrefixSegmentIdentifier(PrefixSegmentIdentifier::new(vec![
                    BgpSidAttribute::LabelIndex {
                        flags: 0,
                        label_index: 90,
                    },
                ])),
            )
            .unwrap(),
        ],
        vec![],
    ));

    test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
pub fn test_segment_identifier_bad_tlv_type_error() {
    let bad_wire = [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 90];
    let bad = &LocatedSegmentIdentifierParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_wire[1..]) },
        SegmentIdentifierParsingError::BgpPrefixSidTlvError(
            BgpPrefixSidTlvParsingError::BadBgpPrefixSidTlvType(BgpSidAttributeTypeError(
                IanaValueError::Reserved(0),
            )),
        ),
    );
    test_parse_error_with_one_input::<
        PrefixSegmentIdentifier,
        bool,
        LocatedSegmentIdentifierParsingError<'_>,
    >(&bad_wire, false, bad);
}
