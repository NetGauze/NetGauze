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
    ie,
    wire::deserializer::{ie as ie_desr, FieldParsingError},
    Field, InformationElementTemplate,
};
use netgauze_parse_utils::{test_helpers::*, Span};

#[test]
fn test_field() {
    let good_ipv4_src_wire = [0x00, 0x08, 0x00, 0x04];
    let good_ipv4_src = Field::new(
        ie::InformationElementId::IANA(ie::iana::InformationElementId::sourceIPv4Address),
        4,
    );
    test_parsed_completely(&good_ipv4_src_wire, &good_ipv4_src);
}

#[test]
fn test_u8_value() {
    let value_wire = [123];
    let value = ie::iana::protocolIdentifier(123);
    let invalid_length = ie_desr::iana::LocatedprotocolIdentifierParsingError::new(
        Span::new(&value_wire),
        ie_desr::iana::protocolIdentifierParsingError::InvalidLength(2),
    );
    test_parsed_completely_with_one_input(&value_wire, 1, &value);
    test_parse_error_with_one_input::<
        ie::iana::protocolIdentifier,
        u16,
        ie_desr::iana::LocatedprotocolIdentifierParsingError<'_>,
    >(&value_wire, 2, &invalid_length);
}

#[test]
fn test_mac_address_value() {
    let value_wire = [0x12, 0xc6, 0x21, 0x12, 0x69, 0x32];
    let value = ie::iana::sourceMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]);
    let invalid_length = ie_desr::iana::LocatedsourceMacAddressParsingError::new(
        Span::new(&value_wire),
        ie_desr::iana::sourceMacAddressParsingError::InvalidLength(2),
    );
    test_parsed_completely_with_one_input::<
        ie::iana::sourceMacAddress,
        u16,
        ie_desr::iana::LocatedsourceMacAddressParsingError<'_>,
    >(&value_wire, 6u16, &value);
    test_parse_error_with_one_input::<
        ie::iana::sourceMacAddress,
        u16,
        ie_desr::iana::LocatedsourceMacAddressParsingError<'_>,
    >(&value_wire, 2u16, &invalid_length);
}

#[test]
fn test_pkg_record_value() {
    let value_wire = [0x12, 0xc6, 0x21, 0x12, 0x69, 0x32];
    let value = ie::iana::Record::sourceMacAddress(ie::iana::sourceMacAddress([
        0x12, 0xc6, 0x21, 0x12, 0x69, 0x32,
    ]));
    let invalid_length = nom::Err::Error(ie_desr::iana::LocatedRecordParsingError::new(
        Span::new(&value_wire),
        ie_desr::iana::RecordParsingError::sourceMacAddressError(
            ie_desr::iana::sourceMacAddressParsingError::InvalidLength(2),
        ),
    ));
    test_parsed_completely_with_two_inputs::<
        ie::iana::Record,
        &ie::iana::InformationElementId,
        u16,
        ie_desr::iana::LocatedRecordParsingError<'_>,
    >(
        &value_wire,
        &ie::iana::InformationElementId::sourceMacAddress,
        6u16,
        &value,
    );
    test_parse_error_with_two_inputs::<
        ie::iana::Record,
        &ie::iana::InformationElementId,
        u16,
        ie_desr::iana::LocatedRecordParsingError<'_>,
    >(
        &value_wire,
        &ie::iana::InformationElementId::sourceMacAddress,
        2u16,
        invalid_length,
    );
}

#[test]
fn test_record_value() {
    let value_wire = [0x12, 0xc6, 0x21, 0x12, 0x69, 0x32];
    let value = ie::Record::IANA(ie::iana::Record::sourceMacAddress(
        ie::iana::sourceMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]),
    ));
    let invalid_length = nom::Err::Error(ie_desr::LocatedRecordParsingError::new(
        Span::new(&value_wire),
        ie_desr::RecordParsingError::IANAError(
            ie_desr::iana::RecordParsingError::sourceMacAddressError(
                ie_desr::iana::sourceMacAddressParsingError::InvalidLength(2),
            ),
        ),
    ));
    test_parsed_completely_with_two_inputs::<
        ie::Record,
        &ie::InformationElementId,
        u16,
        ie_desr::LocatedRecordParsingError<'_>,
    >(
        &value_wire,
        &ie::InformationElementId::IANA(ie::iana::InformationElementId::sourceMacAddress),
        6u16,
        &value,
    );
    test_parse_error_with_two_inputs::<
        ie::Record,
        &ie::InformationElementId,
        u16,
        ie_desr::LocatedRecordParsingError<'_>,
    >(
        &value_wire,
        &ie::InformationElementId::IANA(ie::iana::InformationElementId::sourceMacAddress),
        2u16,
        invalid_length,
    );
}
