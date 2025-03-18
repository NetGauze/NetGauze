// Copyright (C) 2023-present The NetGauze Authors.
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

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use chrono::{TimeZone, Utc};
use netgauze_iana::tcp::*;
use netgauze_parse_utils::{test_helpers::*, ReadablePduWithOneInput, Span};

use crate::{
    ie,
    netflow::*,
    wire::{
        deserializer::netflow::{
            LocatedNetFlowV9PacketParsingError, NetFlowV9PacketParsingError, SetParsingError,
        },
        serializer::netflow::*,
    },
    DataSetId, FieldSpecifier,
};

#[test]
fn test_netflow9_template_record() -> Result<(), NetFlowV9WritingError> {
    let good_wire = [
        0x00, 0x09, 0x00, 0x01, 0x00, 0x06, 0x14, 0x8b, 0x59, 0x77, 0x3e, 0x3d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x04, 0x00, 0x00, 0x0d, 0x00, 0x08,
        0x00, 0x04, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04, 0x00,
        0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04,
        0x00, 0x07, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0x00,
        0x01, 0x00, 0x3c, 0x00, 0x01,
    ];

    let good = NetFlowV9Packet::new(
        398475,
        Utc.with_ymd_and_hms(2017, 7, 25, 12, 49, 1).unwrap(),
        0,
        0,
        Box::new([Set::Template(Box::new([TemplateRecord::new(
            1024,
            Box::new([
                FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::flowEndSysUpTime, 4).unwrap(),
                FieldSpecifier::new(ie::IE::flowStartSysUpTime, 4).unwrap(),
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::ingressInterface, 4).unwrap(),
                FieldSpecifier::new(ie::IE::egressInterface, 4).unwrap(),
                FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
                FieldSpecifier::new(ie::IE::tcpControlBits, 1).unwrap(),
                FieldSpecifier::new(ie::IE::ipVersion, 1).unwrap(),
            ]),
        )]))]),
    );
    let mut templates_map = HashMap::new();
    test_parsed_completely_with_one_input(&good_wire, &mut templates_map, &good);
    test_write_with_two_inputs(&good, None, true, &good_wire)?;
    Ok(())
}

#[test]
fn test_netflow9_data_record() -> Result<(), NetFlowV9WritingError> {
    let good_wire = [
        0x00, 0x09, 0x00, 0x04, 0x00, 0x06, 0xfe, 0xc9, 0x59, 0x77, 0x3e, 0x79, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0xa0, 0xc0, 0xa8, 0x01, 0x64, 0xd8, 0x3a,
        0xd3, 0x63, 0x00, 0x01, 0xa2, 0xa5, 0x00, 0x01, 0xa1, 0xec, 0x00, 0x00, 0x00, 0x42, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x85, 0x01, 0xbb,
        0x11, 0x00, 0x04, 0xd8, 0x3a, 0xd3, 0x63, 0xc0, 0xa8, 0x01, 0x64, 0x00, 0x01, 0xa2, 0xa5,
        0x00, 0x01, 0xa1, 0xec, 0x00, 0x00, 0x05, 0x62, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xbb, 0xcc, 0x85, 0x11, 0x00, 0x04, 0xc0, 0xa8, 0x01,
        0x64, 0xd8, 0x3a, 0xd3, 0x6e, 0x00, 0x01, 0xcb, 0x55, 0x00, 0x01, 0xcb, 0x55, 0x00, 0x00,
        0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf6,
        0x87, 0x01, 0xbb, 0x11, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x64, 0xd8, 0x3a, 0xd3, 0x6e, 0x00,
        0x02, 0x38, 0x75, 0x00, 0x02, 0x38, 0x75, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7, 0x29, 0x01, 0xbb, 0x11, 0x00, 0x04,
    ];

    let fields = [
        FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
        FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
        FieldSpecifier::new(ie::IE::flowEndSysUpTime, 4).unwrap(),
        FieldSpecifier::new(ie::IE::flowStartSysUpTime, 4).unwrap(),
        FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(ie::IE::ingressInterface, 4).unwrap(),
        FieldSpecifier::new(ie::IE::egressInterface, 4).unwrap(),
        FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
        FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
        FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
        FieldSpecifier::new(ie::IE::tcpControlBits, 1).unwrap(),
        FieldSpecifier::new(ie::IE::ipVersion, 1).unwrap(),
    ];

    let decoding_template = DecodingTemplate {
        scope_fields_specs: Box::new([]),
        fields_specs: Box::new(fields),
    };
    let mut templates_map = HashMap::from([(1024, decoding_template)]);

    let good = NetFlowV9Packet::new(
        458441,
        Utc.with_ymd_and_hms(2017, 7, 25, 12, 50, 1).unwrap(),
        1,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(1024).unwrap(),
            records: Box::new([
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        ie::Field::sourceIPv4Address(Ipv4Addr::new(192, 168, 1, 100)),
                        ie::Field::destinationIPv4Address(Ipv4Addr::new(216, 58, 211, 99)),
                        ie::Field::flowEndSysUpTime(107173),
                        ie::Field::flowStartSysUpTime(106988),
                        ie::Field::octetDeltaCount(66),
                        ie::Field::packetDeltaCount(1),
                        ie::Field::ingressInterface(0),
                        ie::Field::egressInterface(0),
                        ie::Field::sourceTransportPort(52357),
                        ie::Field::destinationTransportPort(443),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier::UDP),
                        ie::Field::tcpControlBits(TCPHeaderFlags::new(
                            false, false, false, false, false, false, false, false,
                        )),
                        ie::Field::ipVersion(4),
                    ]),
                ),
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        ie::Field::sourceIPv4Address(Ipv4Addr::new(216, 58, 211, 99)),
                        ie::Field::destinationIPv4Address(Ipv4Addr::new(192, 168, 1, 100)),
                        ie::Field::flowEndSysUpTime(107173),
                        ie::Field::flowStartSysUpTime(106988),
                        ie::Field::octetDeltaCount(1378),
                        ie::Field::packetDeltaCount(1),
                        ie::Field::ingressInterface(0),
                        ie::Field::egressInterface(0),
                        ie::Field::sourceTransportPort(443),
                        ie::Field::destinationTransportPort(52357),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier::UDP),
                        ie::Field::tcpControlBits(TCPHeaderFlags::new(
                            false, false, false, false, false, false, false, false,
                        )),
                        ie::Field::ipVersion(4),
                    ]),
                ),
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        ie::Field::sourceIPv4Address(Ipv4Addr::new(192, 168, 1, 100)),
                        ie::Field::destinationIPv4Address(Ipv4Addr::new(216, 58, 211, 110)),
                        ie::Field::flowEndSysUpTime(117589),
                        ie::Field::flowStartSysUpTime(117589),
                        ie::Field::octetDeltaCount(66),
                        ie::Field::packetDeltaCount(1),
                        ie::Field::ingressInterface(0),
                        ie::Field::egressInterface(0),
                        ie::Field::sourceTransportPort(63111),
                        ie::Field::destinationTransportPort(443),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier::UDP),
                        ie::Field::tcpControlBits(TCPHeaderFlags::new(
                            false, false, false, false, false, false, false, false,
                        )),
                        ie::Field::ipVersion(4),
                    ]),
                ),
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        ie::Field::sourceIPv4Address(Ipv4Addr::new(192, 168, 1, 100)),
                        ie::Field::destinationIPv4Address(Ipv4Addr::new(216, 58, 211, 110)),
                        ie::Field::flowEndSysUpTime(145525),
                        ie::Field::flowStartSysUpTime(145525),
                        ie::Field::octetDeltaCount(51),
                        ie::Field::packetDeltaCount(1),
                        ie::Field::ingressInterface(0),
                        ie::Field::egressInterface(0),
                        ie::Field::sourceTransportPort(63273),
                        ie::Field::destinationTransportPort(443),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier::UDP),
                        ie::Field::tcpControlBits(TCPHeaderFlags::new(
                            false, false, false, false, false, false, false, false,
                        )),
                        ie::Field::ipVersion(4),
                    ]),
                ),
            ]),
        }]),
    );

    test_parsed_completely_with_one_input(&good_wire, &mut templates_map, &good);
    test_write_with_two_inputs(&good, Some(&templates_map), true, &good_wire)?;
    Ok(())
}

#[test]
fn test_data_packet() -> Result<(), NetFlowV9WritingError> {
    let good_wire = [
        0x00, 0x09, 0x00, 0x02, 0x0c, 0x0a, 0x0b, 0x0e, 0x63, 0xd5, 0x45, 0x99, 0x00, 0xe3, 0xbd,
        0x93, 0x00, 0x00, 0x08, 0x21, 0x01, 0x39, 0x00, 0xec, 0x05, 0xde, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xcf, 0x00, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x02, 0x0c, 0x09,
        0xce, 0xb5, 0x0c, 0x09, 0xca, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xd5, 0x03, 0xc4, 0x22, 0x8a, 0xbb, 0x6f, 0x74, 0x97, 0x3e,
        0x00, 0x35, 0x00, 0x00, 0x40, 0x00, 0x00, 0x06, 0x02, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00,
        0x60, 0x00, 0x00, 0x05, 0x05, 0xde, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcf, 0x00, 0x00, 0x00, 0xa1,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x02, 0x0c, 0x09, 0xce, 0xb5, 0x0c, 0x09, 0xca,
        0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd5, 0x03, 0xc4, 0x22, 0x8a, 0xbb, 0x6f, 0x74, 0x97, 0x42, 0x00, 0x35, 0x00, 0x00, 0x40,
        0x00, 0x00, 0x06, 0x02, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x05, 0x00,
        0x00,
    ];

    let field_specifiers = [
        FieldSpecifier::new(ie::IE::mplsTopLabelStackSection, 3).unwrap(),
        FieldSpecifier::new(ie::IE::mplsLabelStackSection2, 3).unwrap(),
        FieldSpecifier::new(ie::IE::mplsLabelStackSection3, 3).unwrap(),
        FieldSpecifier::new(ie::IE::mplsLabelStackSection4, 3).unwrap(),
        FieldSpecifier::new(ie::IE::mplsLabelStackSection5, 3).unwrap(),
        FieldSpecifier::new(ie::IE::mplsLabelStackSection6, 3).unwrap(),
        FieldSpecifier::new(ie::IE::ingressInterface, 4).unwrap(),
        FieldSpecifier::new(ie::IE::egressInterface, 4).unwrap(),
        FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(ie::IE::flowEndSysUpTime, 4).unwrap(),
        FieldSpecifier::new(ie::IE::flowStartSysUpTime, 4).unwrap(),
        FieldSpecifier::new(ie::IE::mplsTopLabelIPv4Address, 4).unwrap(),
        FieldSpecifier::new(ie::IE::sourceIPv6Address, 16).unwrap(),
        FieldSpecifier::new(ie::IE::destinationIPv6Address, 16).unwrap(),
        FieldSpecifier::new(ie::IE::flowLabelIPv6, 4).unwrap(),
        FieldSpecifier::new(ie::IE::ipv6ExtensionHeaders, 4).unwrap(),
        FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
        FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
        FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
        FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
        FieldSpecifier::new(ie::IE::mplsTopLabelPrefixLength, 1).unwrap(),
        FieldSpecifier::new(ie::IE::mplsTopLabelType, 1).unwrap(),
        FieldSpecifier::new(ie::IE::forwardingStatus, 1).unwrap(),
        FieldSpecifier::new(ie::IE::flowDirection, 1).unwrap(),
        FieldSpecifier::new(ie::IE::ipClassOfService, 1).unwrap(),
        FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
        FieldSpecifier::new(ie::IE::tcpControlBits, 1).unwrap(),
        FieldSpecifier::new(ie::IE::samplerId, 2).unwrap(),
        FieldSpecifier::new(ie::IE::ingressVRFID, 4).unwrap(),
        FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap(),
    ];

    let decoding_template = DecodingTemplate {
        scope_fields_specs: Box::new([]),
        fields_specs: Box::new(field_specifiers),
    };
    let mut templates_map = HashMap::from([(313, decoding_template)]);

    let good = NetFlowV9Packet::new(
        201984782,
        Utc.with_ymd_and_hms(2023, 1, 28, 15, 56, 9).unwrap(),
        14925203,
        2081,
        Box::new([Set::Data {
            id: DataSetId::new(313).unwrap(),
            records: Box::new([
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        ie::Field::mplsTopLabelStackSection(Box::new([0x05, 0xde, 0x01])),
                        ie::Field::mplsLabelStackSection2(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection3(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection4(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection5(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection6(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::ingressInterface(207),
                        ie::Field::egressInterface(161),
                        ie::Field::octetDeltaCount(128),
                        ie::Field::packetDeltaCount(2),
                        ie::Field::flowEndSysUpTime(0x0c09ceb5),
                        ie::Field::flowStartSysUpTime(0x0c09cac2),
                        ie::Field::mplsTopLabelIPv4Address(Ipv4Addr::new(0, 0, 0, 0)),
                        ie::Field::sourceIPv6Address(Ipv6Addr::from(0)),
                        ie::Field::destinationIPv6Address(Ipv6Addr::from(0)),
                        ie::Field::flowLabelIPv6(0),
                        ie::Field::ipv6ExtensionHeaders(0),
                        ie::Field::sourceIPv4Address(Ipv4Addr::new(213, 3, 196, 34)),
                        ie::Field::destinationIPv4Address(Ipv4Addr::new(138, 187, 111, 116)),
                        ie::Field::sourceTransportPort(38718),
                        ie::Field::destinationTransportPort(53),
                        ie::Field::mplsTopLabelPrefixLength(0),
                        ie::Field::mplsTopLabelType(ie::mplsTopLabelType::Unknown),
                        ie::Field::forwardingStatus(ie::forwardingStatus::Forwarded(
                            ie::forwardingStatusForwardedReason::Unknown,
                        )),
                        ie::Field::flowDirection(ie::flowDirection::ingress),
                        ie::Field::ipClassOfService(0),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier::TCP),
                        ie::Field::tcpControlBits(TCPHeaderFlags::new(
                            false, true, false, false, false, false, false, false,
                        )),
                        ie::Field::samplerId(1),
                        ie::Field::ingressVRFID(1610612736),
                        ie::Field::egressVRFID(1610612741),
                    ]),
                ),
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        ie::Field::mplsTopLabelStackSection(Box::new([0x05, 0xde, 0x01])),
                        ie::Field::mplsLabelStackSection2(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection3(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection4(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection5(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::mplsLabelStackSection6(Box::new([0x00, 0x00, 0x00])),
                        ie::Field::ingressInterface(207),
                        ie::Field::egressInterface(161),
                        ie::Field::octetDeltaCount(128),
                        ie::Field::packetDeltaCount(2),
                        ie::Field::flowEndSysUpTime(0x0c09ceb5),
                        ie::Field::flowStartSysUpTime(0x0c09cac3),
                        ie::Field::mplsTopLabelIPv4Address(Ipv4Addr::new(0, 0, 0, 0)),
                        ie::Field::sourceIPv6Address(Ipv6Addr::from(0)),
                        ie::Field::destinationIPv6Address(Ipv6Addr::from(0)),
                        ie::Field::flowLabelIPv6(0),
                        ie::Field::ipv6ExtensionHeaders(0),
                        ie::Field::sourceIPv4Address(Ipv4Addr::new(213, 3, 196, 34)),
                        ie::Field::destinationIPv4Address(Ipv4Addr::new(138, 187, 111, 116)),
                        ie::Field::sourceTransportPort(38722),
                        ie::Field::destinationTransportPort(53),
                        ie::Field::mplsTopLabelPrefixLength(0),
                        ie::Field::mplsTopLabelType(ie::mplsTopLabelType::Unknown),
                        ie::Field::forwardingStatus(ie::forwardingStatus::Forwarded(
                            ie::forwardingStatusForwardedReason::Unknown,
                        )),
                        ie::Field::flowDirection(ie::flowDirection::ingress),
                        ie::Field::ipClassOfService(0),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier::TCP),
                        ie::Field::tcpControlBits(TCPHeaderFlags::new(
                            false, true, false, false, false, false, false, false,
                        )),
                        ie::Field::samplerId(1),
                        ie::Field::ingressVRFID(1610612736),
                        ie::Field::egressVRFID(1610612741),
                    ]),
                ),
            ]),
        }]),
    );

    test_parsed_completely_with_one_input(&good_wire, &mut templates_map, &good);
    test_write_with_two_inputs(&good, Some(&templates_map), true, &good_wire)?;
    Ok(())
}

#[test]
fn test_mix_option_template_set() -> Result<(), SetWritingError> {
    let good_wire = [
        0x00, 0x01, 0x00, 0x1a, 0x01, 0x15, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x04, 0x00,
        0x0a, 0x00, 0x02, 0x00, 0x52, 0x00, 0x10, 0x00, 0x53, 0x00, 0x20,
    ];
    let good = Set::OptionsTemplate(Box::new([OptionsTemplateRecord::new(
        277,
        Box::new([ScopeFieldSpecifier::new(ScopeIE::System, 4)]),
        Box::new([
            FieldSpecifier::new(ie::IE::ingressInterface, 2).unwrap(),
            FieldSpecifier::new(ie::IE::interfaceName, 16).unwrap(),
            FieldSpecifier::new(ie::IE::interfaceDescription, 32).unwrap(),
        ]),
    )]));

    let mut templates_map = HashMap::new();
    test_parsed_completely_with_one_input(&good_wire, &mut templates_map, &good);
    test_write_with_two_inputs(&good, Some(&templates_map), false, &good_wire)?;
    Ok(())
}

#[test]
fn test_mix_option_template_set2() -> Result<(), SetWritingError> {
    let good_wire = [
        0x00, 0x01, 0x00, 0x18, 0x01, 0x4e, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 0x00,
        0xea, 0x00, 0x04, 0x00, 0xec, 0x00, 0x20, 0x00, 0x00,
    ];
    let good = Set::OptionsTemplate(Box::new([OptionsTemplateRecord::new(
        334,
        Box::new([ScopeFieldSpecifier::new(ScopeIE::System, 4)]),
        Box::new([
            FieldSpecifier::new(ie::IE::ingressVRFID, 4).unwrap(),
            FieldSpecifier::new(ie::IE::VRFname, 32).unwrap(),
        ]),
    )]));

    let mut templates_map = HashMap::new();
    test_parsed_completely_with_one_input(&good_wire, &mut templates_map, &good);
    test_write_with_two_inputs(&good, Some(&templates_map), true, &good_wire)?;
    Ok(())
}

#[test]
fn test_padding() -> Result<(), NetFlowV9WritingError> {
    let good_no_padding_wire = [
        0x00, 0x09, // Version
        0x00, 0x02, // Count
        0x0f, 0x5e, 0x5c, 0x6b, // Sys up time
        0x63, 0xd5, 0x45, 0x85, // Timestamp
        0x00, 0x09, 0x43, 0x2a, // seq
        0x00, 0x00, 0x00, 0x06, // Source Id
        0x00, 0x01, // Options Template
        0x00, 0x1e, // Length
        0x01, 0x02, // Options template ID
        0x00, 0x04, // Scope Length
        0x00, 0x10, // Options Length
        0x00, 0x01, 0x00, 0x04, 0x00, 0x30, 0x00, 0x04, 0x00, 0x54, 0x00, 0x28, 0x00, 0x31, 0x00,
        0x01, 0x00, 0x32, 0x00, 0x02, 0x01, 0x02, // Flow Set ID
        0x00, 0x37, // Flow Set Length
        0xd5, 0x03, 0xdf, 0x23, // Scope System
        0x00, 0x00, 0x00, 0x02, // Sampler ID
        0x4e, 0x45, 0x54, 0x46, // Sampler Name
        0x4c, 0x4f, 0x57, 0x2d, // Sampler Name
        0x53, 0x41, 0x4d, 0x50, // Sampler Name
        0x4c, 0x45, 0x52, 0x2d, // Sampler Name
        0x4d, 0x41, 0x50, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x02, // Random
        0x01, 0x00, // Sampler Random Interval
    ];

    let good_with_padding_wire = [
        0x00, 0x09, // Version
        0x00, 0x02, // Count
        0x0f, 0x5e, 0x5c, 0x6b, // Sys up time
        0x63, 0xd5, 0x45, 0x85, // Timestamp
        0x00, 0x09, 0x43, 0x2a, // seq
        0x00, 0x00, 0x00, 0x06, // Source Id
        0x00, 0x01, // Options Template
        0x00, 0x20, // Length
        0x01, 0x02, // Options template ID
        0x00, 0x04, // Scope Length
        0x00, 0x10, // Options Length
        0x00, 0x01, 0x00, 0x04, // Scope
        0x00, 0x30, 0x00, 0x04, // Field
        0x00, 0x54, 0x00, 0x28, // Field
        0x00, 0x31, 0x00, 0x01, // Field
        0x00, 0x32, 0x00, 0x02, 0x00, 0x00, // Padding
        0x01, 0x02, // Flow Set ID
        0x00, 0x3a, // Flow Set Length
        0xd5, 0x03, 0xdf, 0x23, // Scope System
        0x00, 0x00, 0x00, 0x02, // Sampler ID
        0x4e, 0x45, 0x54, 0x46, // Sampler Name
        0x4c, 0x4f, 0x57, 0x2d, // Sampler Name
        0x53, 0x41, 0x4d, 0x50, // Sampler Name
        0x4c, 0x45, 0x52, 0x2d, // Sampler Name
        0x4d, 0x41, 0x50, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x02, // Random
        0x01, 0x00, // Sampler Random Interval
        0x00, 0x00, 0x00, // Padding
    ];

    let bad_padding_options_wire = [
        0x00, 0x09, // Version
        0x00, 0x02, // Count
        0x0f, 0x5e, 0x5c, 0x6b, // Sys up time
        0x63, 0xd5, 0x45, 0x85, // Timestamp
        0x00, 0x09, 0x43, 0x2a, // seq
        0x00, 0x00, 0x00, 0x06, // Source Id
        0x00, 0x01, // Options Template
        0x00, 0x20, // Length
        0x01, 0x02, // Options template ID
        0x00, 0x04, // Scope Length
        0x00, 0x10, // Options Length
        0x00, 0x01, 0x00, 0x04, // Scope
        0x00, 0x30, 0x00, 0x04, // Field
        0x00, 0x54, 0x00, 0x28, // Field
        0x00, 0x31, 0x00, 0x01, // Field
        0x00, 0x32, 0x00, 0x02, 0x00, 0x11, // Padding
        0x01, 0x02, // Flow Set ID
        0x00, 0x3a, // Flow Set Length
        0xd5, 0x03, 0xdf, 0x23, // Scope System
        0x00, 0x00, 0x00, 0x02, // Sampler ID
        0x4e, 0x45, 0x54, 0x46, // Sampler Name
        0x4c, 0x4f, 0x57, 0x2d, // Sampler Name
        0x53, 0x41, 0x4d, 0x50, // Sampler Name
        0x4c, 0x45, 0x52, 0x2d, // Sampler Name
        0x4d, 0x41, 0x50, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x02, // Random
        0x01, 0x00, // Sampler Random Interval
        0x00, 0x00, 0x00, // Padding
    ];

    let bad_padding_data_wire = [
        0x00, 0x09, // Version
        0x00, 0x02, // Count
        0x0f, 0x5e, 0x5c, 0x6b, // Sys up time
        0x63, 0xd5, 0x45, 0x85, // Timestamp
        0x00, 0x09, 0x43, 0x2a, // seq
        0x00, 0x00, 0x00, 0x06, // Source Id
        0x00, 0x01, // Options Template
        0x00, 0x20, // Length
        0x01, 0x02, // Options template ID
        0x00, 0x04, // Scope Length
        0x00, 0x10, // Options Length
        0x00, 0x01, 0x00, 0x04, // Scope
        0x00, 0x30, 0x00, 0x04, // Field
        0x00, 0x54, 0x00, 0x28, // Field
        0x00, 0x31, 0x00, 0x01, // Field
        0x00, 0x32, 0x00, 0x02, 0x00, 0x00, // Padding
        0x01, 0x02, // Flow Set ID
        0x00, 0x3a, // Flow Set Length
        0xd5, 0x03, 0xdf, 0x23, // Scope System
        0x00, 0x00, 0x00, 0x02, // Sampler ID
        0x4e, 0x45, 0x54, 0x46, // Sampler Name
        0x4c, 0x4f, 0x57, 0x2d, // Sampler Name
        0x53, 0x41, 0x4d, 0x50, // Sampler Name
        0x4c, 0x45, 0x52, 0x2d, // Sampler Name
        0x4d, 0x41, 0x50, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x00, 0x00, 0x00, 0x00, // Sampler Name
        0x02, // Random
        0x01, 0x00, // Sampler Random Interval
        0x01, 0x00, 0x00, // Padding
    ];

    let bad_options_template_padding = LocatedNetFlowV9PacketParsingError::new(
        unsafe { Span::new_from_raw_offset(51, &[17]) },
        NetFlowV9PacketParsingError::SetError(SetParsingError::InvalidPaddingValue(17)),
    );

    let bad_data_padding = LocatedNetFlowV9PacketParsingError::new(
        unsafe { Span::new_from_raw_offset(107, &[0x01, 0x00, 0x00]) },
        NetFlowV9PacketParsingError::SetError(SetParsingError::InvalidPaddingValue(1)),
    );
    let mut templates_no_padding_map = HashMap::new();
    let mut templates_with_padding_map = HashMap::new();
    let mut template_bad_map = HashMap::new();

    let (_, good_no_padding) = NetFlowV9Packet::from_wire(
        Span::new(&good_no_padding_wire),
        &mut templates_no_padding_map,
    )
    .unwrap();
    let (_, good_with_padding) = NetFlowV9Packet::from_wire(
        Span::new(&good_with_padding_wire),
        &mut templates_with_padding_map,
    )
    .unwrap();

    test_parse_error_with_one_input::<
        NetFlowV9Packet,
        &mut TemplatesMap,
        LocatedNetFlowV9PacketParsingError<'_>,
    >(
        &bad_padding_options_wire,
        &mut template_bad_map,
        &bad_options_template_padding,
    );
    test_parse_error_with_one_input::<
        NetFlowV9Packet,
        &mut TemplatesMap,
        LocatedNetFlowV9PacketParsingError<'_>,
    >(
        &bad_padding_data_wire,
        &mut template_bad_map,
        &bad_data_padding,
    );

    // Packets should be equal regardless of the padding
    test_parsed_completely_with_one_input(
        &good_no_padding_wire,
        &mut templates_no_padding_map,
        &good_with_padding,
    );
    test_parsed_completely_with_one_input(
        &good_with_padding_wire,
        &mut templates_with_padding_map,
        &good_no_padding,
    );

    test_write_with_two_inputs(
        &good_no_padding,
        Some(&templates_no_padding_map),
        false,
        &good_no_padding_wire,
    )?;
    test_write_with_two_inputs(
        &good_with_padding,
        Some(&templates_with_padding_map),
        true,
        &good_with_padding_wire,
    )?;
    Ok(())
}

#[test]
fn test_with_iana_subregs() -> Result<(), NetFlowV9WritingError> {
    let good_template_wire = [
        0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x66, 0x8b, 0xe2, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x01, 0x90, 0x00, 0x19, 0x00, 0x08,
        0x00, 0x04, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x02, 0x00,
        0x94, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
        0x00, 0x2e, 0x00, 0x01, 0x00, 0x59, 0x00, 0x04, 0x00, 0x65, 0x00, 0x01, 0x00, 0x88, 0x00,
        0x01, 0x00, 0xe5, 0x00, 0x01, 0x00, 0xe9, 0x00, 0x01, 0x00, 0xef, 0x00, 0x01, 0x01, 0x15,
        0x00, 0x01, 0x01, 0x1e, 0x00, 0x02, 0x01, 0x29, 0x00, 0x01, 0x01, 0x80, 0x00, 0x01, 0x01,
        0x86, 0x00, 0x02, 0x01, 0x98, 0x00, 0x02, 0x01, 0xc0, 0x00, 0x01, 0x01, 0xd2, 0x00, 0x01,
        0x01, 0xd3, 0x00, 0x01, 0x01, 0xf4, 0x00, 0x01,
    ];

    let good_data_wire = [
        0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x66, 0x8b, 0xe2, 0xd0, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x90, 0x00, 0x38, 0x0a, 0x64, 0x00, 0x01, 0x0a, 0x64,
        0x00, 0x97, 0x27, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x21, 0x12, 0x01,
        0x00, 0x00, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x86, 0x12, 0x05,
        0x0f, 0x02, 0x03, 0x01, 0x00, 0x06, 0x05, 0x04, 0x00, 0x04, 0x00, 0x0a, 0x04, 0x04, 0x01,
        0x05,
    ];

    let good_template = NetFlowV9Packet::new(
        120,
        Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
        0,
        0,
        Box::new([Set::Template(Box::new([TemplateRecord::new(
            400,
            Box::new([
                FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::flowId, 8).unwrap(),
                FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::mplsTopLabelType, 1).unwrap(),
                FieldSpecifier::new(ie::IE::forwardingStatus, 4).unwrap(),
                FieldSpecifier::new(ie::IE::classificationEngineId, 1).unwrap(),
                FieldSpecifier::new(ie::IE::flowEndReason, 1).unwrap(),
                FieldSpecifier::new(ie::IE::natOriginatingAddressRealm, 1).unwrap(),
                FieldSpecifier::new(ie::IE::firewallEvent, 1).unwrap(),
                FieldSpecifier::new(ie::IE::biflowDirection, 1).unwrap(),
                FieldSpecifier::new(ie::IE::observationPointType, 1).unwrap(),
                FieldSpecifier::new(ie::IE::anonymizationTechnique, 2).unwrap(),
                FieldSpecifier::new(ie::IE::natType, 1).unwrap(),
                FieldSpecifier::new(ie::IE::valueDistributionMethod, 1).unwrap(),
                FieldSpecifier::new(ie::IE::flowSelectorAlgorithm, 2).unwrap(),
                FieldSpecifier::new(ie::IE::dataLinkFrameType, 2).unwrap(),
                FieldSpecifier::new(ie::IE::mibCaptureTimeSemantics, 1).unwrap(),
                FieldSpecifier::new(ie::IE::natQuotaExceededEvent, 1).unwrap(),
                FieldSpecifier::new(ie::IE::natThresholdEvent, 1).unwrap(),
                FieldSpecifier::new(ie::IE::srhIPv6ActiveSegmentType, 1).unwrap(),
            ]),
        )]))]),
    );

    let good_data = NetFlowV9Packet::new(
        120,
        Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
        1,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(400).unwrap(),
            records: Box::new([DataRecord::new(
                Box::new([]),
                Box::new([
                    ie::Field::sourceIPv4Address(Ipv4Addr::new(10, 100, 0, 1)),
                    ie::Field::destinationIPv4Address(Ipv4Addr::new(10, 100, 0, 151)),
                    ie::Field::sourceTransportPort(10004),
                    ie::Field::destinationTransportPort(1),
                    ie::Field::flowId(10101010),
                    ie::Field::protocolIdentifier(ie::protocolIdentifier::ICMP),
                    ie::Field::octetDeltaCount(1200),
                    ie::Field::packetDeltaCount(1),
                    ie::Field::mplsTopLabelType(ie::mplsTopLabelType::Unknown),
                    ie::Field::forwardingStatus(ie::forwardingStatus::Dropped(
                        ie::forwardingStatusDroppedReason::Badheaderchecksum,
                    )),
                    ie::Field::classificationEngineId(ie::classificationEngineId::ETHERTYPE),
                    ie::Field::flowEndReason(ie::flowEndReason::lackofresources),
                    ie::Field::natOriginatingAddressRealm(
                        ie::natOriginatingAddressRealm::Unassigned(15),
                    ),
                    ie::Field::firewallEvent(ie::firewallEvent::FlowDeleted),
                    ie::Field::biflowDirection(ie::biflowDirection::perimeter),
                    ie::Field::observationPointType(ie::observationPointType::Physicalport),
                    ie::Field::anonymizationTechnique(
                        ie::anonymizationTechnique::StructuredPermutation,
                    ),
                    ie::Field::natType(ie::natType::NAT66translated),
                    ie::Field::valueDistributionMethod(
                        ie::valueDistributionMethod::SimpleUniformDistribution,
                    ),
                    ie::Field::flowSelectorAlgorithm(
                        ie::flowSelectorAlgorithm::UniformprobabilisticSampling,
                    ),
                    ie::Field::dataLinkFrameType(ie::dataLinkFrameType::Unassigned(10)),
                    ie::Field::mibCaptureTimeSemantics(ie::mibCaptureTimeSemantics::average),
                    ie::Field::natQuotaExceededEvent(
                        ie::natQuotaExceededEvent::Maximumactivehostsorsubscribers,
                    ),
                    ie::Field::natThresholdEvent(
                        ie::natThresholdEvent::Addresspoolhighthresholdevent,
                    ),
                    ie::Field::srhIPv6ActiveSegmentType(
                        ie::srhIPv6ActiveSegmentType::BGPSegmentRoutingPrefixSID,
                    ),
                ]),
            )]),
        }]),
    );

    let mut templates_map = HashMap::new();
    test_parsed_completely_with_one_input(&good_template_wire, &mut templates_map, &good_template);
    test_parsed_completely_with_one_input(&good_data_wire, &mut templates_map, &good_data);

    test_write_with_one_input(&good_template, Some(&templates_map), &good_template_wire)?;
    test_write_with_one_input(&good_data, Some(&templates_map), &good_data_wire)?;

    Ok(())
}

#[test]
fn test_zero_length_fields() {
    let good_template_wire = [
        0, 9, 75, 9, 0, 0, 96, 0, 33, 0, 0, 0, 47, 0, 9, 1, 0, 0, 0, 0, 0, 1, 0, 15, 91, 0, 0, 4,
        0, 0, 91, 0, 0, 0, 0, 91, 0, 0, 4, 0, 0, 0, 0, 32, 0, 0,
    ];
    let mut templates_map = HashMap::new();
    // The test here will produce invalid packet, but what we are testing for is not
    // crashing due to divide by zero
    let ret = NetFlowV9Packet::from_wire(Span::new(&good_template_wire), &mut templates_map);
    assert!(ret.is_err());
}

#[test]
fn test_records_len_larger_than_count() {
    let good_template_wire = [
        0, 9, 0, 64, 16, 1, 0, 0, 42, 0, 0, 64, 16, 0, 53, 255, 255, 1, 1, 0, 0, 1, 0, 150, 158, 0,
        0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 158, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 171, 0, 0, 8, 0, 0, 0,
        0, 0, 8, 0, 122, 0, 148, 251, 0, 0, 0, 0, 0, 158, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 171, 0,
        0, 8, 0, 0, 0, 0, 0, 8, 64, 0, 0, 1, 251, 0, 0, 0, 0, 0, 158, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
        0, 171, 0, 0, 8, 0, 0, 0, 176, 251, 0, 0, 0, 0, 0, 158, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
        171, 0, 0, 24, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 251, 0, 0, 0, 0, 9, 9, 255, 255, 0, 0, 0, 6,
        0, 0, 0, 0, 0, 171, 0, 1, 8, 0, 0, 0, 0, 171, 0, 0, 123, 255, 0, 0, 123, 123, 123, 255, 0,
        0, 0, 0, 0, 0, 0, 171, 0, 0, 24, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 123, 123, 123, 123, 123,
        255, 0, 41, 212, 251, 0, 0, 0, 0, 0, 0, 50, 0, 6, 0, 123, 123, 123, 123, 123, 255, 0, 0, 0,
        0, 0, 0, 0, 50, 0, 6, 0, 123, 123, 123, 123, 123, 255, 0, 0, 0, 41, 212, 251, 0, 0, 0, 0,
        0, 0, 50, 0, 6, 0, 123, 123, 123, 123, 123, 255, 0, 41, 212, 251, 0, 0, 0, 0, 0, 0, 50, 0,
        6, 0, 123, 123, 123, 123, 123, 255, 0, 0, 123, 123, 123, 255, 0, 0, 0, 0, 0, 0, 0, 123,
        123, 123, 255, 0, 41, 212, 251, 0, 0, 0, 0, 0, 0, 50, 0, 6, 0, 123, 123, 123, 123, 123,
        255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 41, 212, 0, 123, 123, 123, 123, 123, 255, 0, 41,
        212, 251, 0, 0, 0, 0, 0, 0, 50, 0, 6, 0, 123, 123, 123, 123, 123, 255, 0, 0, 123, 0, 0, 0,
        0, 0, 50, 0, 6, 0, 123, 123, 123, 123, 123, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 41,
        212, 0, 123, 123, 123, 123, 123, 255, 0, 41, 212, 251, 0, 0, 0, 0, 0, 0, 50, 0, 6, 0, 123,
        123, 123, 123, 123, 255, 0, 0,
    ];
    let mut templates_map = HashMap::new();
    // The test here will produce invalid packet, but what we are testing for is not
    // crashing due subtracting count of records from the templates
    let ret = NetFlowV9Packet::from_wire(Span::new(&good_template_wire), &mut templates_map);
    assert!(ret.is_err());
}
