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

use chrono::{TimeZone, Utc};
use netgauze_parse_utils::{test_helpers::*, Span};
use std::net::Ipv4Addr;

use crate::{
    ie,
    wire::{
        deserializer::{ie as ie_desr, *},
        serializer::*,
    },
    DataRecord, FieldSpecifier, Flow, IpfixHeader, IpfixPacket, Set, SetPayload, TemplateRecord,
};

#[test]
fn test_ipfix_header() -> Result<(), IpfixHeaderWritingError> {
    let good_wire = [
        0x00, 0x0a, 0x00, 0x10, 0x63, 0x4a, 0xe2, 0x9d, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x01,
    ];
    let bad_version_wire = [
        0x00, 0x00, 0x00, 0x10, 0x63, 0x4a, 0xe2, 0x9d, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x01,
    ];
    let bad_length_wire = [
        0x00, 0x0a, 0x00, 0x00, 0x63, 0x4a, 0xe2, 0x9d, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x01,
    ];

    let good = IpfixHeader::new(Utc.ymd(2022, 10, 15).and_hms(16, 41, 01), 6, 1);
    let bad_version = LocatedIpfixHeaderParsingError::new(
        Span::new(&bad_version_wire),
        IpfixHeaderParsingError::UnsupportedVersion(0),
    );
    let bad_length = LocatedIpfixHeaderParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_length_wire[2..]) },
        IpfixHeaderParsingError::InvalidLength(0),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<IpfixHeader, LocatedIpfixHeaderParsingError<'_>>(
        &bad_version_wire,
        &bad_version,
    );
    test_parse_error::<IpfixHeader, LocatedIpfixHeaderParsingError<'_>>(
        &bad_length_wire,
        &bad_length,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_field() {
    let good_ipv4_src_wire = [0x00, 0x08, 0x00, 0x04];
    let good_ipv4_src = FieldSpecifier::new(
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

#[test]
fn test_flow_value() {
    let value_wire = [
        0x12, 0xc6, 0x21, 0x12, 0x69, 0x32, 0x12, 0xc6, 0x21, 0x12, 0x69, 0x32,
    ];

    let flow = Flow::new(vec![
        ie::Record::IANA(ie::iana::Record::sourceMacAddress(
            ie::iana::sourceMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]),
        )),
        ie::Record::IANA(ie::iana::Record::destinationMacAddress(
            ie::iana::destinationMacAddress([0x12, 0xc6, 0x21, 0x12, 0x69, 0x32]),
        )),
    ]);

    let fields = [
        FieldSpecifier::new(
            ie::InformationElementId::IANA(ie::iana::InformationElementId::sourceMacAddress),
            6,
        ),
        FieldSpecifier::new(
            ie::InformationElementId::IANA(ie::iana::InformationElementId::destinationMacAddress),
            6,
        ),
    ];
    test_parsed_completely_with_one_input::<
        Flow,
        &[FieldSpecifier],
        crate::wire::deserializer::LocatedFlowParsingError<'_>,
    >(&value_wire, &fields, &flow);
}

#[test]
fn test_data_template_packet() {
    let _good_wire = [
        0x00, 0x0a, 0x00, 0x60, 0x58, 0x3d, 0xe0, 0x59, 0x00, 0x00, 0x0e, 0xe4, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x33, 0x00, 0x50, 0x46, 0x01, 0x73, 0x01, 0x32, 0x00, 0x47, 0x01, 0x00, 0x3d,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x3b, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x03, 0xcc, 0x2a, 0x6e, 0x65, 0x00, 0x00, 0x03, 0x56, 0x00, 0x00, 0x05, 0x20,
        0x00, 0x00, 0x00, 0x09, 0xb3, 0xf9, 0x06, 0xee, 0xb3, 0xfb, 0xaf, 0x3c, 0xcc, 0x2a, 0x6e,
        0xbd, 0x18, 0x18, 0x00, 0x04, 0x00, 0x00, 0x01, 0x58, 0xb1, 0xb1, 0x38, 0xff, 0x00, 0x00,
        0x01, 0x58, 0xb1, 0xb3, 0xe1, 0x4d,
    ];

    let _good = IpfixPacket::new(
        IpfixHeader::new(Utc.ymd(2016, 11, 29).and_hms(20, 08, 55), 3791, 0),
        vec![Set::new(
            2,
            vec![SetPayload::Template(TemplateRecord::new(
                307,
                vec![
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::sourceIPv4Address,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::destinationIPv4Address,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::ipClassOfService,
                        ),
                        1,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::protocolIdentifier,
                        ),
                        1,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::sourceTransportPort,
                        ),
                        2,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::destinationTransportPort,
                        ),
                        2,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::icmpTypeCodeIPv4,
                        ),
                        2,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::ingressInterface,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::bgpSourceAsNumber,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::bgpDestinationAsNumber,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::bgpNextHopIPv4Address,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::egressInterface,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::octetDeltaCount,
                        ),
                        1,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::packetDeltaCount,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::flowStartSysUpTime,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::flowEndSysUpTime,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::ipNextHopIPv4Address,
                        ),
                        4,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::sourceIPv4PrefixLength,
                        ),
                        1,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::destinationIPv4PrefixLength,
                        ),
                        1,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::tcpControlBits,
                        ),
                        1,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(ie::iana::InformationElementId::ipVersion),
                        1,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::flowStartMilliseconds,
                        ),
                        8,
                    ),
                    FieldSpecifier::new(
                        ie::InformationElementId::IANA(
                            ie::iana::InformationElementId::flowEndMilliseconds,
                        ),
                        8,
                    ),
                ],
            ))],
        )],
    );
}

#[test]
fn test_data_packet() {
    let _good_wire = [
        0x00, 0x0a, 0x00, 0x60, 0x58, 0x3d, 0xe0, 0x59, 0x00, 0x00, 0x0e, 0xe4, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x33, 0x00, 0x50, 0x46, 0x01, 0x73, 0x01, 0x32, 0x00, 0x47, 0x01, 0x00, 0x3d,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x3b, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x03, 0xcc, 0x2a, 0x6e, 0x65, 0x00, 0x00, 0x03, 0x56, 0x00, 0x00, 0x05, 0x20,
        0x00, 0x00, 0x00, 0x09, 0xb3, 0xf9, 0x06, 0xee, 0xb3, 0xfb, 0xaf, 0x3c, 0xcc, 0x2a, 0x6e,
        0xbd, 0x18, 0x18, 0x00, 0x04, 0x00, 0x00, 0x01, 0x58, 0xb1, 0xb1, 0x38, 0xff, 0x00, 0x00,
        0x01, 0x58, 0xb1, 0xb3, 0xe1, 0x4d,
    ];

    let _good = IpfixPacket::new(
        IpfixHeader::new(Utc.ymd(2016, 11, 29).and_hms(20, 08, 57), 3812, 0),
        vec![Set::new(
            307,
            vec![SetPayload::Data(DataRecord::new(
                307,
                vec![Flow::new(vec![
                    ie::Record::IANA(ie::iana::Record::sourceIPv4Address(
                        ie::iana::sourceIPv4Address(Ipv4Addr::new(70, 1, 115, 1)),
                    )),
                    ie::Record::IANA(ie::iana::Record::destinationIPv4Address(
                        ie::iana::destinationIPv4Address(Ipv4Addr::new(50, 0, 71, 1)),
                    )),
                    ie::Record::IANA(ie::iana::Record::ipClassOfService(
                        ie::iana::ipClassOfService(0),
                    )),
                    ie::Record::IANA(ie::iana::Record::protocolIdentifier(
                        ie::iana::protocolIdentifier(61),
                    )),
                    ie::Record::IANA(ie::iana::Record::sourceTransportPort(
                        ie::iana::sourceTransportPort(0),
                    )),
                    ie::Record::IANA(ie::iana::Record::destinationTransportPort(
                        ie::iana::destinationTransportPort(0),
                    )),
                    ie::Record::IANA(ie::iana::Record::icmpTypeCodeIPv4(
                        ie::iana::icmpTypeCodeIPv4(0),
                    )),
                    ie::Record::IANA(ie::iana::Record::ingressInterface(
                        ie::iana::ingressInterface(827),
                    )),
                    ie::Record::IANA(ie::iana::Record::bgpSourceAsNumber(
                        ie::iana::bgpSourceAsNumber(2),
                    )),
                    ie::Record::IANA(ie::iana::Record::bgpDestinationAsNumber(
                        ie::iana::bgpDestinationAsNumber(3),
                    )),
                    ie::Record::IANA(ie::iana::Record::bgpNextHopIPv4Address(
                        ie::iana::bgpNextHopIPv4Address(Ipv4Addr::new(204, 42, 110, 101)),
                    )),
                    ie::Record::IANA(ie::iana::Record::egressInterface(
                        ie::iana::egressInterface(854),
                    )),
                    ie::Record::IANA(ie::iana::Record::octetDeltaCount(
                        ie::iana::octetDeltaCount(1312),
                    )),
                    ie::Record::IANA(ie::iana::Record::packetDeltaCount(
                        ie::iana::packetDeltaCount(9),
                    )),
                    ie::Record::IANA(ie::iana::Record::flowStartSysUpTime(
                        ie::iana::flowStartSysUpTime(0xb3f906ee),
                    )),
                    ie::Record::IANA(ie::iana::Record::flowEndSysUpTime(
                        ie::iana::flowEndSysUpTime(0xb3f9af3c),
                    )),
                    ie::Record::IANA(ie::iana::Record::ipNextHopIPv4Address(
                        ie::iana::ipNextHopIPv4Address(Ipv4Addr::new(204, 42, 110, 189)),
                    )),
                    ie::Record::IANA(ie::iana::Record::sourceIPv4PrefixLength(
                        ie::iana::sourceIPv4PrefixLength(24),
                    )),
                    ie::Record::IANA(ie::iana::Record::destinationIPv4PrefixLength(
                        ie::iana::destinationIPv4PrefixLength(24),
                    )),
                    ie::Record::IANA(ie::iana::Record::tcpControlBits(ie::iana::tcpControlBits(
                        0,
                    ))),
                    ie::Record::IANA(ie::iana::Record::ipVersion(ie::iana::ipVersion(4))),
                    ie::Record::IANA(ie::iana::Record::flowStartMilliseconds(
                        ie::iana::flowStartMilliseconds(
                            Utc.ymd(2016, 11, 29).and_hms_milli(20, 05, 31, 519),
                        ),
                    )),
                    ie::Record::IANA(ie::iana::Record::flowEndMilliseconds(
                        ie::iana::flowEndMilliseconds(
                            Utc.ymd(2016, 11, 29).and_hms_milli(20, 08, 25, 677),
                        ),
                    )),
                ])],
            ))],
        )],
    );
}
