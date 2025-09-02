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

mod ipfix;
mod netflow;

#[cfg(feature = "codec")]
pub mod pcap_tests;

use chrono::{TimeZone, Timelike, Utc};
use netgauze_parse_utils::{test_helpers::*, Span};
use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    ie,
    ie::Field,
    ipfix::*,
    wire::{
        deserializer::{ie as ie_desr, ipfix::*},
        serializer::{ie as ie_ser, ipfix::*, *},
    },
    FieldSpecifier,
};

#[test]
fn test_template_record() -> Result<(), TemplateRecordWritingError> {
    let good_wire = [
        0x08, 0x01, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x10, 0x00, 0x1c, 0x00, 0x10,
    ];
    let bad_template_id_wire = [
        0x00, 0x00, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x10, 0x00, 0x1c, 0x00, 0x10,
    ];

    let good = TemplateRecord::new(
        2049,
        Box::new([
            FieldSpecifier::new(ie::IE::sourceIPv6Address, 16).unwrap(),
            FieldSpecifier::new(ie::IE::destinationIPv6Address, 16).unwrap(),
        ]),
    );

    let bad_template_id = LocatedTemplateRecordParsingError::new(
        Span::new(&bad_template_id_wire),
        TemplateRecordParsingError::InvalidTemplateId(0),
    );
    let mut templates_map = HashMap::new();
    test_parsed_completely_with_one_input(&good_wire, &mut templates_map, &good);
    test_parse_error_with_one_input::<
        TemplateRecord,
        &mut TemplatesMap,
        LocatedTemplateRecordParsingError<'_>,
    >(&bad_template_id_wire, &mut templates_map, &bad_template_id);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_field() -> Result<(), FieldSpecifierWritingError> {
    let good_ipv4_src_wire = [0x00, 0x08, 0x00, 0x04];
    let good_ipv4_src = FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap();
    test_parsed_completely(&good_ipv4_src_wire, &good_ipv4_src);
    test_write(&good_ipv4_src, &good_ipv4_src_wire)?;
    Ok(())
}

#[test]
fn test_u8_value() -> Result<(), ie_ser::FieldWritingError> {
    let value_wire = [123];
    let value = ie::Field::protocolIdentifier(ie::protocolIdentifier::PTP);
    let invalid_length = ie_desr::LocatedFieldParsingError::new(
        Span::new(&value_wire),
        ie_desr::FieldParsingError::InvalidLength {
            ie_name: "protocolIdentifier".to_string(),
            length: 2,
        },
    );
    test_parsed_completely_with_two_inputs(&value_wire, &ie::IE::protocolIdentifier, 1u16, &value);
    test_parse_error_with_two_inputs::<
        ie::Field,
        &ie::IE,
        u16,
        ie_desr::LocatedFieldParsingError<'_>,
    >(
        &value_wire,
        &ie::IE::protocolIdentifier,
        2,
        nom::Err::Error(invalid_length),
    );
    test_write_with_one_input(&value, None, &value_wire)?;
    Ok(())
}

#[test]
fn test_f64_value() -> Result<(), ie_ser::FieldWritingError> {
    let value_wire = [64, 94, 217, 153, 153, 153, 153, 154];
    let value = Field::samplingProbability(ordered_float::OrderedFloat::from(123.4));
    let invalid_length = ie_desr::LocatedFieldParsingError::new(
        Span::new(&value_wire),
        ie_desr::FieldParsingError::InvalidLength {
            ie_name: "samplingProbability".to_string(),
            length: 4,
        },
    );
    test_parsed_completely_with_two_inputs(&value_wire, &ie::IE::samplingProbability, 8u16, &value);
    test_parse_error_with_two_inputs::<
        ie::Field,
        &ie::IE,
        u16,
        ie_desr::LocatedFieldParsingError<'_>,
    >(
        &value_wire,
        &ie::IE::samplingProbability,
        4,
        nom::Err::Error(invalid_length),
    );
    test_write_with_one_input(&value, None, &value_wire)?;
    Ok(())
}

#[test]
fn test_mac_address_value() -> Result<(), ie_ser::FieldWritingError> {
    let value_wire = [0x12, 0xc6, 0x21, 0x12, 0x69, 0x32];
    let value = ie::Field::sourceMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]);
    let invalid_length = ie_desr::LocatedFieldParsingError::new(
        Span::new(&value_wire),
        ie_desr::FieldParsingError::InvalidLength {
            ie_name: "sourceMacAddress".to_string(),
            length: 2,
        },
    );
    test_parsed_completely_with_two_inputs(&value_wire, &ie::IE::sourceMacAddress, 6u16, &value);
    test_parse_error_with_two_inputs::<
        ie::Field,
        &ie::IE,
        u16,
        ie_desr::LocatedFieldParsingError<'_>,
    >(
        &value_wire,
        &ie::IE::sourceMacAddress,
        2u16,
        nom::Err::Error(invalid_length),
    );
    test_write_with_one_input(&value, None, &value_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_address_value() -> Result<(), ie_ser::FieldWritingError> {
    let good_wire = [0x46, 0x01, 0x73, 0x01];
    let value = ie::Field::sourceIPv4Address(Ipv4Addr::new(70, 1, 115, 1));
    let invalid_length = ie_desr::LocatedFieldParsingError::new(
        Span::new(&good_wire),
        ie_desr::FieldParsingError::InvalidLength {
            ie_name: "sourceIPv4Address".to_string(),
            length: 2,
        },
    );
    test_parsed_completely_with_two_inputs(&good_wire, &ie::IE::sourceIPv4Address, 4u16, &value);
    test_parse_error_with_two_inputs::<
        ie::Field,
        &ie::IE,
        u16,
        ie_desr::LocatedFieldParsingError<'_>,
    >(
        &good_wire,
        &ie::IE::sourceIPv4Address,
        2u16,
        nom::Err::Error(invalid_length),
    );
    test_write_with_one_input(&value, None, &good_wire)?;
    Ok(())
}

#[test]
fn test_pkg_record_value() -> Result<(), ie_ser::FieldWritingError> {
    let value_wire = [0x12, 0xc6, 0x21, 0x12, 0x69, 0x32];
    let value = ie::Field::sourceMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]);
    let invalid_length = nom::Err::Error(ie_desr::LocatedFieldParsingError::new(
        Span::new(&value_wire),
        ie_desr::FieldParsingError::InvalidLength {
            ie_name: "sourceMacAddress".to_string(),
            length: 2,
        },
    ));
    test_parsed_completely_with_two_inputs(&value_wire, &ie::IE::sourceMacAddress, 6u16, &value);
    test_parse_error_with_two_inputs::<
        ie::Field,
        &ie::IE,
        u16,
        ie_desr::LocatedFieldParsingError<'_>,
    >(&value_wire, &ie::IE::sourceMacAddress, 2u16, invalid_length);

    test_write_with_one_input(&value, None, &value_wire)?;
    Ok(())
}

#[test]
fn test_milli_value() -> Result<(), ie_ser::FieldWritingError> {
    let good_wire = [0, 0, 1, 88, 177, 177, 56, 255];
    let good = ie::Field::flowStartMilliseconds(
        Utc.with_ymd_and_hms(2016, 11, 29, 20, 5, 31)
            .unwrap()
            .with_nanosecond(519_000_000)
            .unwrap(),
    );
    test_parsed_completely_with_two_inputs(&good_wire, &ie::IE::flowStartMilliseconds, 8, &good);
    test_write_with_one_input(&good, None, &good_wire)?;
    Ok(())
}

#[test]
fn test_time_fraction_value() -> Result<(), ie_ser::FieldWritingError> {
    let good_full_wire = [0x58, 0x3d, 0xdf, 0xa7, 0xff, 0xff, 0xff, 0xff];
    let good_half_wire = [0x58, 0x3d, 0xdf, 0x8b, 0x7f, 0xff, 0xff, 0xff];
    let good_zero_wire = [0x58, 0x3d, 0xdf, 0x8b, 0x00, 0x00, 0x00, 0x00];

    let good_full = ie::Field::flowStartMicroseconds(
        Utc.with_ymd_and_hms(2016, 11, 29, 20, 5, 59)
            .unwrap()
            .with_nanosecond(1_000_000_000)
            .unwrap(),
    );
    let good_half = ie::Field::flowStartMicroseconds(
        Utc.with_ymd_and_hms(2016, 11, 29, 20, 5, 31)
            .unwrap()
            .with_nanosecond(500_000_000)
            .unwrap(),
    );
    // Due to floating point errors, we cannot retrieve the original value.
    let good_half_rounded = ie::Field::flowStartMicroseconds(
        Utc.with_ymd_and_hms(2016, 11, 29, 20, 5, 31)
            .unwrap()
            .with_nanosecond(499_999_999)
            .unwrap(),
    );
    let good_zero = ie::Field::flowStartMicroseconds(
        Utc.with_ymd_and_hms(2016, 11, 29, 20, 5, 31)
            .unwrap()
            .with_nanosecond(0)
            .unwrap(),
    );

    test_parsed_completely_with_two_inputs(
        &good_full_wire,
        &ie::IE::flowStartMicroseconds,
        8,
        &good_full,
    );
    test_parsed_completely_with_two_inputs(
        &good_half_wire,
        &ie::IE::flowStartMicroseconds,
        8,
        &good_half_rounded,
    );
    test_parsed_completely_with_two_inputs(
        &good_zero_wire,
        &ie::IE::flowStartMicroseconds,
        8,
        &good_zero,
    );
    test_write_with_one_input(&good_full, None, &good_full_wire)?;
    test_write_with_one_input(&good_half, None, &good_half_wire)?;
    test_write_with_one_input(&good_zero, None, &good_zero_wire)?;
    Ok(())
}

#[test]
fn test_string_value() -> Result<(), ie_ser::FieldWritingError> {
    let good_wire = [
        0x6c, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let good = ie::Field::interfaceName("lo".into());

    test_parsed_completely_with_two_inputs(
        &good_wire,
        &ie::IE::interfaceName,
        good_wire.len() as u16,
        &good,
    );
    test_write_with_one_input(&good, Some(good_wire.len() as u16), &good_wire)?;
    Ok(())
}

#[test]
fn test_record_value() -> Result<(), ie_ser::FieldWritingError> {
    let value_wire = [0x12, 0xc6, 0x21, 0x12, 0x69, 0x32];
    let value = ie::Field::sourceMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]);
    let invalid_length = nom::Err::Error(ie_desr::LocatedFieldParsingError::new(
        Span::new(&value_wire),
        ie_desr::FieldParsingError::InvalidLength {
            ie_name: "sourceMacAddress".to_string(),
            length: 2,
        },
    ));
    test_parsed_completely_with_two_inputs(&value_wire, &ie::IE::sourceMacAddress, 6u16, &value);
    test_parse_error_with_two_inputs::<
        ie::Field,
        &ie::IE,
        u16,
        ie_desr::LocatedFieldParsingError<'_>,
    >(&value_wire, &ie::IE::sourceMacAddress, 2u16, invalid_length);
    test_write_with_one_input(&value, None, &value_wire)?;
    Ok(())
}

#[test]
fn test_data_record_value() -> Result<(), DataRecordWritingError> {
    let value_wire = [
        0x12, 0xc6, 0x21, 0x12, 0x69, 0x32, 0x12, 0xc6, 0x21, 0x12, 0x69, 0x32,
    ];

    let flow = DataRecord::new(
        Box::new([]),
        Box::new([
            ie::Field::sourceMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]),
            ie::Field::destinationMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]),
        ]),
    );

    let fields = DecodingTemplate::new(
        Box::new([]),
        Box::new([
            FieldSpecifier::new(ie::IE::sourceMacAddress, 6).unwrap(),
            FieldSpecifier::new(ie::IE::destinationMacAddress, 6).unwrap(),
        ]),
    );
    test_parsed_completely_with_one_input::<
        DataRecord,
        &DecodingTemplate,
        LocatedDataRecordParsingError<'_>,
    >(&value_wire, &fields, &flow);
    test_write_with_one_input(&flow, Some(&fields), &value_wire)?;
    Ok(())
}

#[test]
fn test_set_template() -> Result<(), SetWritingError> {
    let good_wire = [
        0x00, 0x02, 0x00, 0x64, 0x01, 0x33, 0x00, 0x17, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0c, 0x00,
        0x04, 0x00, 0x05, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0b,
        0x00, 0x02, 0x00, 0x20, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x10, 0x00, 0x04, 0x00,
        0x11, 0x00, 0x04, 0x00, 0x12, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04,
        0x00, 0x02, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x0f, 0x00,
        0x04, 0x00, 0x09, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x3c,
        0x00, 0x01, 0x00, 0x98, 0x00, 0x08, 0x00, 0x99, 0x00, 0x08,
    ];

    let good = Set::Template(Box::new([TemplateRecord::new(
        307,
        Box::new([
            FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
            FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
            FieldSpecifier::new(ie::IE::ipClassOfService, 1).unwrap(),
            FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
            FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
            FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
            FieldSpecifier::new(ie::IE::icmpTypeCodeIPv4, 2).unwrap(),
            FieldSpecifier::new(ie::IE::ingressInterface, 4).unwrap(),
            FieldSpecifier::new(ie::IE::bgpSourceAsNumber, 4).unwrap(),
            FieldSpecifier::new(ie::IE::bgpDestinationAsNumber, 4).unwrap(),
            FieldSpecifier::new(ie::IE::bgpNextHopIPv4Address, 4).unwrap(),
            FieldSpecifier::new(ie::IE::egressInterface, 4).unwrap(),
            FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
            FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
            FieldSpecifier::new(ie::IE::flowStartSysUpTime, 4).unwrap(),
            FieldSpecifier::new(ie::IE::flowEndSysUpTime, 4).unwrap(),
            FieldSpecifier::new(ie::IE::ipNextHopIPv4Address, 4).unwrap(),
            FieldSpecifier::new(ie::IE::sourceIPv4PrefixLength, 1).unwrap(),
            FieldSpecifier::new(ie::IE::destinationIPv4PrefixLength, 1).unwrap(),
            FieldSpecifier::new(ie::IE::tcpControlBits, 1).unwrap(),
            FieldSpecifier::new(ie::IE::ipVersion, 1).unwrap(),
            FieldSpecifier::new(ie::IE::flowStartMilliseconds, 8).unwrap(),
            FieldSpecifier::new(ie::IE::flowEndMilliseconds, 8).unwrap(),
        ]),
    )]));
    let mut templates_map = HashMap::new();
    test_parsed_completely_with_one_input(&good_wire, &mut templates_map, &good);
    test_write_with_one_input(&good, None, &good_wire)?;
    Ok(())
}

#[test]
fn test_u64_reduced_size_encoding() -> Result<(), ie_ser::FieldWritingError> {
    let full_wire = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88];
    let seven_wire = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99];
    let six_wire = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    let five_wire = [0xff, 0xee, 0xdd, 0xcc, 0xbb];
    let four_wire = [0xff, 0xee, 0xdd, 0xcc];
    let three_wire = [0xff, 0xee, 0xdd];
    let two_wire = [0xff, 0xee];
    let one_wire = [0xff];

    let field_full = Some(8);
    let field_seven = Some(7);
    let field_six = Some(6);
    let field_five = Some(5);
    let field_four = Some(4);
    let field_three = Some(3);
    let field_two = Some(2);
    let field_one = Some(1);

    let full = ie::Field::packetDeltaCount(0xffeeddccbbaa9988);
    let seven = ie::Field::packetDeltaCount(0xffeeddccbbaa99);
    let six = ie::Field::packetDeltaCount(0xffeeddccbbaa);
    let five = ie::Field::packetDeltaCount(0xffeeddccbb);
    let four = ie::Field::packetDeltaCount(0xffeeddcc);
    let three = ie::Field::packetDeltaCount(0xffeedd);
    let two = ie::Field::packetDeltaCount(0xffee);
    let one = ie::Field::packetDeltaCount(0xff);

    test_parsed_completely_with_two_inputs(&full_wire, &ie::IE::packetDeltaCount, 8, &full);
    test_parsed_completely_with_two_inputs(&seven_wire, &ie::IE::packetDeltaCount, 7, &seven);
    test_parsed_completely_with_two_inputs(&six_wire, &ie::IE::packetDeltaCount, 6, &six);
    test_parsed_completely_with_two_inputs(&five_wire, &ie::IE::packetDeltaCount, 5, &five);
    test_parsed_completely_with_two_inputs(&four_wire, &ie::IE::packetDeltaCount, 4, &four);
    test_parsed_completely_with_two_inputs(&three_wire, &ie::IE::packetDeltaCount, 3, &three);
    test_parsed_completely_with_two_inputs(&two_wire, &ie::IE::packetDeltaCount, 2, &two);
    test_parsed_completely_with_two_inputs(&one_wire, &ie::IE::packetDeltaCount, 1, &one);

    test_write_with_one_input(&full, field_full, &full_wire)?;
    test_write_with_one_input(&seven, field_seven, &seven_wire)?;
    test_write_with_one_input(&six, field_six, &six_wire)?;
    test_write_with_one_input(&five, field_five, &five_wire)?;
    test_write_with_one_input(&four, field_four, &four_wire)?;
    test_write_with_one_input(&three, field_three, &three_wire)?;
    test_write_with_one_input(&two, field_two, &two_wire)?;
    test_write_with_one_input(&one, field_one, &one_wire)?;
    Ok(())
}

#[test]
fn test_u256_value() -> Result<(), ie_ser::FieldWritingError> {
    let value_wire = [0x11; 32];
    let reduced_wire = [0x11; 8];
    let value = ie::Field::ipv6ExtensionHeadersFull(Box::new([0x11; 32]));
    let reduced_value = ie::Field::ipv6ExtensionHeadersFull(Box::new([
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]));
    let invalid_length = nom::Err::Error(ie_desr::LocatedFieldParsingError::new(
        Span::new(&value_wire),
        ie_desr::FieldParsingError::InvalidLength {
            ie_name: "ipv6ExtensionHeadersFull".to_string(),
            length: 33,
        },
    ));
    test_parsed_completely_with_two_inputs(
        &value_wire,
        &ie::IE::ipv6ExtensionHeadersFull,
        32u16,
        &value,
    );
    test_parsed_completely_with_two_inputs(
        &reduced_wire,
        &ie::IE::ipv6ExtensionHeadersFull,
        8u16,
        &reduced_value,
    );
    test_parse_error_with_two_inputs::<
        ie::Field,
        &ie::IE,
        u16,
        ie_desr::LocatedFieldParsingError<'_>,
    >(
        &value_wire,
        &ie::IE::ipv6ExtensionHeadersFull,
        33u16,
        invalid_length,
    );
    test_write_with_one_input(&value, None, &value_wire)?;
    test_write_with_one_input(&reduced_value, Some(8), &reduced_wire)?;
    Ok(())
}

// #[test]
// fn test_u32_reduced_size_encoding() -> Result<(), ie_ser::FieldWritingError>
// {     let four_wire = [0xff, 0xee, 0xdd, 0xcc];
//     let three_wire = [0xff, 0xee, 0xdd];
//     let two_wire = [0xff, 0xee];
//     let one_wire = [0xff];
//
//     let field_four = Some(4);
//     let field_three = Some(3);
//     let field_two = Some(2);
//     let field_one = Some(1);
//
//     let four = ie::Field::packetDeltaCount(ie::packetDeltaCount(0xffeeddcc));
//     let three = ie::Field::packetDeltaCount(ie::packetDeltaCount(0xffeedd));
//     let two = ie::Field::packetDeltaCount(ie::packetDeltaCount(0xffee));
//     let one = ie::Field::packetDeltaCount(ie::packetDeltaCount(0xff));
//
//     test_parsed_completely_with_two_inputs(&four_wire,
// &ie::IE::packetDeltaCount, 4, &four);
//     test_parsed_completely_with_two_inputs(&three_wire,
// &ie::IE::packetDeltaCount, 3, &three);
//     test_parsed_completely_with_two_inputs(&two_wire,
// &ie::IE::packetDeltaCount, 2, &two);
//     test_parsed_completely_with_two_inputs(&one_wire,
// &ie::IE::packetDeltaCount, 1, &one);
//
//     test_write_with_one_input(&four, field_four, &four_wire)?;
//     test_write_with_one_input(&three, field_three, &three_wire)?;
//     test_write_with_one_input(&two, field_two, &two_wire)?;
//     test_write_with_one_input(&one, field_one, &one_wire)?;
//     Ok(())
// }
//
// #[test]
// fn test_u16_reduced_size_encoding() -> Result<(), ie_ser::FieldWritingError>
// {     let two_wire = [0xff, 0xee];
//     let one_wire = [0xff];
//
//     let field_two = Some(2);
//     let field_one = Some(1);
//
//     let two = ie::Field::packetDeltaCount(ie::packetDeltaCount(0xffee));
//     let one = ie::Field::packetDeltaCount(ie::packetDeltaCount(0xff));
//
//     test_parsed_completely_with_two_inputs(&two_wire,
// &ie::IE::packetDeltaCount, 2, &two);
//     test_parsed_completely_with_two_inputs(&one_wire,
// &ie::IE::packetDeltaCount, 1, &one);
//
//     test_write_with_one_input(&two, field_two, &two_wire)?;
//     test_write_with_one_input(&one, field_one, &one_wire)?;
//     Ok(())
// }
//
// #[test]
// fn test_i32_reduced_size_encoding() -> Result<(), ie_ser::FieldWritingError>
// {     let u32_max_wire = [0x7f, 0xff, 0xff, 0xff];
//     let u32_min_wire = [0x80, 0x00, 0x00, 0x00];
//     let u24_pos_wire = [0x00, 0x7f, 0xff];
//     let u24_neg_wire = [0xff, 0x80, 0x00];
//     let u16_max_wire = [0x7f, 0xff];
//     let u16_min_wire = [0x80, 0x00];
//     let u8_max_wire = [0x7f];
//     let u8_min_wire = [0x80];
//
//     let length_four = Some(4);
//     let length_three = Some(3);
//     let length_two = Some(2);
//     let length_one = Some(1);
//
//     let u32_max =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i32::MAX));
//     let u32_min =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i32::MIN));
//     let u16_max =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i16::MAX as i32));
//     let u24_pos =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i16::MAX as i32));
//     let u16_neg =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i16::MIN as i32));
//     let u24_min =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i16::MIN as i32));
//     let u8_max =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i8::MAX as i32));
//     let u8_min =
// ie::Field::mibObjectValueInteger(ie::mibObjectValueInteger(i8::MIN as i32));
//
//     test_parsed_completely_with_two_inputs(
//         &u32_max_wire,
//         &ie::IE::mibObjectValueInteger,
//         4,
//         &u32_max,
//     );
//     test_parsed_completely_with_two_inputs(
//         &u32_min_wire,
//         &ie::IE::mibObjectValueInteger,
//         4,
//         &u32_min,
//     );
//     test_parsed_completely_with_two_inputs(
//         &u24_pos_wire,
//         &ie::IE::mibObjectValueInteger,
//         3,
//         &u24_pos,
//     );
//     test_parsed_completely_with_two_inputs(
//         &u24_neg_wire,
//         &ie::IE::mibObjectValueInteger,
//         3,
//         &u24_min,
//     );
//     test_parsed_completely_with_two_inputs(
//         &u16_max_wire,
//         &ie::IE::mibObjectValueInteger,
//         2,
//         &u16_max,
//     );
//     test_parsed_completely_with_two_inputs(
//         &u16_min_wire,
//         &ie::IE::mibObjectValueInteger,
//         2,
//         &u16_neg,
//     );
//     test_parsed_completely_with_two_inputs(
//         &u8_max_wire,
//         &ie::IE::mibObjectValueInteger,
//         1,
//         &u8_max,
//     );
//     test_parsed_completely_with_two_inputs(
//         &u8_min_wire,
//         &ie::IE::mibObjectValueInteger,
//         1,
//         &u8_min,
//     );
//
//     test_write_with_one_input(&u32_max, length_four, &u32_max_wire)?;
//     test_write_with_one_input(&u32_min, length_four, &u32_min_wire)?;
//     test_write_with_one_input(&u24_pos, length_three, &u24_pos_wire)?;
//     test_write_with_one_input(&u24_min, length_three, &u24_neg_wire)?;
//     test_write_with_one_input(&u16_max, length_two, &u16_max_wire)?;
//     test_write_with_one_input(&u16_neg, length_two, &u16_min_wire)?;
//     test_write_with_one_input(&u8_max, length_one, &u8_max_wire)?;
//     test_write_with_one_input(&u8_min, length_one, &u8_min_wire)?;
//     Ok(())
// }
