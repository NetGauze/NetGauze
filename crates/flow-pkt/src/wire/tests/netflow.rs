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
    cell::RefCell,
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use chrono::{TimeZone, Utc};

use netgauze_parse_utils::test_helpers::*;

use crate::{ie, ie::*, netflow::*, wire::serializer::netflow::*, DataSetId, FieldSpecifier};

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
        vec![Set::Template(vec![TemplateRecord::new(
            1024,
            vec![
                FieldSpecifier::new(InformationElementId::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::flowEndSysUpTime, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::flowStartSysUpTime, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::packetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::ingressInterface, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::egressInterface, 4).unwrap(),
                FieldSpecifier::new(InformationElementId::sourceTransportPort, 2).unwrap(),
                FieldSpecifier::new(InformationElementId::destinationTransportPort, 2).unwrap(),
                FieldSpecifier::new(InformationElementId::protocolIdentifier, 1).unwrap(),
                FieldSpecifier::new(InformationElementId::tcpControlBits, 1).unwrap(),
                FieldSpecifier::new(InformationElementId::ipVersion, 1).unwrap(),
            ],
        )])],
    );
    let templates_map = Rc::new(RefCell::new(HashMap::new()));
    test_parsed_completely_with_one_input(&good_wire, templates_map, &good);
    test_write_with_one_input(&good, None, &good_wire)?;
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

    let fields = vec![
        FieldSpecifier::new(InformationElementId::sourceIPv4Address, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::destinationIPv4Address, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::flowEndSysUpTime, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::flowStartSysUpTime, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::octetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::packetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::ingressInterface, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::egressInterface, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::sourceTransportPort, 2).unwrap(),
        FieldSpecifier::new(InformationElementId::destinationTransportPort, 2).unwrap(),
        FieldSpecifier::new(InformationElementId::protocolIdentifier, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::tcpControlBits, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::ipVersion, 1).unwrap(),
    ];

    let templates_map = Rc::new(RefCell::new(HashMap::from([(
        1024,
        Rc::new((vec![], fields.clone())),
    )])));

    let good = NetFlowV9Packet::new(
        458441,
        Utc.with_ymd_and_hms(2017, 7, 25, 12, 50, 1).unwrap(),
        1,
        0,
        vec![Set::Data {
            id: DataSetId::new(1024).unwrap(),
            records: vec![
                DataRecord::new(
                    vec![],
                    vec![
                        Field::sourceIPv4Address(sourceIPv4Address(Ipv4Addr::new(
                            192, 168, 1, 100,
                        ))),
                        Field::destinationIPv4Address(destinationIPv4Address(Ipv4Addr::new(
                            216, 58, 211, 99,
                        ))),
                        Field::flowEndSysUpTime(flowEndSysUpTime(107173)),
                        Field::flowStartSysUpTime(flowStartSysUpTime(106988)),
                        Field::octetDeltaCount(octetDeltaCount(66)),
                        Field::packetDeltaCount(packetDeltaCount(1)),
                        Field::ingressInterface(ingressInterface(0)),
                        Field::egressInterface(egressInterface(0)),
                        Field::sourceTransportPort(sourceTransportPort(52357)),
                        Field::destinationTransportPort(destinationTransportPort(443)),
                        Field::protocolIdentifier(protocolIdentifier(17)),
                        Field::tcpControlBits(tcpControlBits(0)),
                        Field::ipVersion(ipVersion(4)),
                    ],
                ),
                DataRecord::new(
                    vec![],
                    vec![
                        Field::sourceIPv4Address(sourceIPv4Address(Ipv4Addr::new(
                            216, 58, 211, 99,
                        ))),
                        Field::destinationIPv4Address(destinationIPv4Address(Ipv4Addr::new(
                            192, 168, 1, 100,
                        ))),
                        Field::flowEndSysUpTime(flowEndSysUpTime(107173)),
                        Field::flowStartSysUpTime(flowStartSysUpTime(106988)),
                        Field::octetDeltaCount(octetDeltaCount(1378)),
                        Field::packetDeltaCount(packetDeltaCount(1)),
                        Field::ingressInterface(ingressInterface(0)),
                        Field::egressInterface(egressInterface(0)),
                        Field::sourceTransportPort(sourceTransportPort(443)),
                        Field::destinationTransportPort(destinationTransportPort(52357)),
                        Field::protocolIdentifier(protocolIdentifier(17)),
                        Field::tcpControlBits(tcpControlBits(0)),
                        Field::ipVersion(ipVersion(4)),
                    ],
                ),
                DataRecord::new(
                    vec![],
                    vec![
                        Field::sourceIPv4Address(sourceIPv4Address(Ipv4Addr::new(
                            192, 168, 1, 100,
                        ))),
                        Field::destinationIPv4Address(destinationIPv4Address(Ipv4Addr::new(
                            216, 58, 211, 110,
                        ))),
                        Field::flowEndSysUpTime(flowEndSysUpTime(117589)),
                        Field::flowStartSysUpTime(flowStartSysUpTime(117589)),
                        Field::octetDeltaCount(octetDeltaCount(66)),
                        Field::packetDeltaCount(packetDeltaCount(1)),
                        Field::ingressInterface(ingressInterface(0)),
                        Field::egressInterface(egressInterface(0)),
                        Field::sourceTransportPort(sourceTransportPort(63111)),
                        Field::destinationTransportPort(destinationTransportPort(443)),
                        Field::protocolIdentifier(protocolIdentifier(17)),
                        Field::tcpControlBits(tcpControlBits(0)),
                        Field::ipVersion(ipVersion(4)),
                    ],
                ),
                DataRecord::new(
                    vec![],
                    vec![
                        Field::sourceIPv4Address(sourceIPv4Address(Ipv4Addr::new(
                            192, 168, 1, 100,
                        ))),
                        Field::destinationIPv4Address(destinationIPv4Address(Ipv4Addr::new(
                            216, 58, 211, 110,
                        ))),
                        Field::flowEndSysUpTime(flowEndSysUpTime(145525)),
                        Field::flowStartSysUpTime(flowStartSysUpTime(145525)),
                        Field::octetDeltaCount(octetDeltaCount(51)),
                        Field::packetDeltaCount(packetDeltaCount(1)),
                        Field::ingressInterface(ingressInterface(0)),
                        Field::egressInterface(egressInterface(0)),
                        Field::sourceTransportPort(sourceTransportPort(63273)),
                        Field::destinationTransportPort(destinationTransportPort(443)),
                        Field::protocolIdentifier(protocolIdentifier(17)),
                        Field::tcpControlBits(tcpControlBits(0)),
                        Field::ipVersion(ipVersion(4)),
                    ],
                ),
            ],
        }],
    );

    test_parsed_completely_with_one_input(&good_wire, templates_map.clone(), &good);
    test_write_with_one_input(&good, Some(templates_map.clone()), &good_wire)?;
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

    let field_specifiers = vec![
        FieldSpecifier::new(InformationElementId::mplsTopLabelStackSection, 3).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsLabelStackSection2, 3).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsLabelStackSection3, 3).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsLabelStackSection4, 3).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsLabelStackSection5, 3).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsLabelStackSection6, 3).unwrap(),
        FieldSpecifier::new(InformationElementId::ingressInterface, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::egressInterface, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::octetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::packetDeltaCount, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::flowEndSysUpTime, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::flowStartSysUpTime, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsTopLabelIPv4Address, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::sourceIPv6Address, 16).unwrap(),
        FieldSpecifier::new(InformationElementId::destinationIPv6Address, 16).unwrap(),
        FieldSpecifier::new(InformationElementId::flowLabelIPv6, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::ipv6ExtensionHeaders, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::sourceIPv4Address, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::destinationIPv4Address, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::sourceTransportPort, 2).unwrap(),
        FieldSpecifier::new(InformationElementId::destinationTransportPort, 2).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsTopLabelPrefixLength, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::mplsTopLabelType, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::forwardingStatus, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::flowDirection, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::ipClassOfService, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::protocolIdentifier, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::tcpControlBits, 1).unwrap(),
        FieldSpecifier::new(InformationElementId::samplerId, 2).unwrap(),
        FieldSpecifier::new(InformationElementId::ingressVRFID, 4).unwrap(),
        FieldSpecifier::new(InformationElementId::egressVRFID, 4).unwrap(),
    ];

    let fields = Rc::new((vec![], field_specifiers.clone()));
    let templates_map = Rc::new(RefCell::new(HashMap::from([(313, fields)])));

    let good = NetFlowV9Packet::new(
        201984782,
        Utc.with_ymd_and_hms(2023, 1, 28, 15, 56, 09).unwrap(),
        14925203,
        2081,
        vec![Set::Data {
            id: DataSetId::new(313).unwrap(),
            records: vec![
                DataRecord::new(
                    vec![],
                    vec![
                        ie::Field::mplsTopLabelStackSection(ie::mplsTopLabelStackSection(vec![
                            0x05, 0xde, 0x01,
                        ])),
                        ie::Field::mplsLabelStackSection2(ie::mplsLabelStackSection2(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection3(ie::mplsLabelStackSection3(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection4(ie::mplsLabelStackSection4(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection5(ie::mplsLabelStackSection5(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection6(ie::mplsLabelStackSection6(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::ingressInterface(ie::ingressInterface(207)),
                        ie::Field::egressInterface(ie::egressInterface(161)),
                        ie::Field::octetDeltaCount(ie::octetDeltaCount(128)),
                        ie::Field::packetDeltaCount(ie::packetDeltaCount(2)),
                        ie::Field::flowEndSysUpTime(ie::flowEndSysUpTime(0x0c09ceb5)),
                        ie::Field::flowStartSysUpTime(ie::flowStartSysUpTime(0x0c09cac2)),
                        ie::Field::mplsTopLabelIPv4Address(ie::mplsTopLabelIPv4Address(
                            Ipv4Addr::new(0, 0, 0, 0),
                        )),
                        ie::Field::sourceIPv6Address(ie::sourceIPv6Address(Ipv6Addr::from(0))),
                        ie::Field::destinationIPv6Address(ie::destinationIPv6Address(
                            Ipv6Addr::from(0),
                        )),
                        ie::Field::flowLabelIPv6(ie::flowLabelIPv6(0)),
                        ie::Field::ipv6ExtensionHeaders(ie::ipv6ExtensionHeaders(0)),
                        ie::Field::sourceIPv4Address(ie::sourceIPv4Address(Ipv4Addr::new(
                            213, 3, 196, 34,
                        ))),
                        ie::Field::destinationIPv4Address(ie::destinationIPv4Address(
                            Ipv4Addr::new(138, 187, 111, 116),
                        )),
                        ie::Field::sourceTransportPort(ie::sourceTransportPort(38718)),
                        ie::Field::destinationTransportPort(ie::destinationTransportPort(53)),
                        ie::Field::mplsTopLabelPrefixLength(ie::mplsTopLabelPrefixLength(0)),
                        ie::Field::mplsTopLabelType(ie::mplsTopLabelType(0)),
                        ie::Field::forwardingStatus(ie::forwardingStatus(0x40)),
                        ie::Field::flowDirection(ie::flowDirection(0)),
                        ie::Field::ipClassOfService(ie::ipClassOfService(0)),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier(6)),
                        ie::Field::tcpControlBits(ie::tcpControlBits(2)),
                        ie::Field::samplerId(ie::samplerId(1)),
                        ie::Field::ingressVRFID(ie::ingressVRFID(1610612736)),
                        ie::Field::egressVRFID(ie::egressVRFID(1610612741)),
                    ],
                ),
                DataRecord::new(
                    vec![],
                    vec![
                        ie::Field::mplsTopLabelStackSection(ie::mplsTopLabelStackSection(vec![
                            0x05, 0xde, 0x01,
                        ])),
                        ie::Field::mplsLabelStackSection2(ie::mplsLabelStackSection2(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection3(ie::mplsLabelStackSection3(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection4(ie::mplsLabelStackSection4(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection5(ie::mplsLabelStackSection5(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::mplsLabelStackSection6(ie::mplsLabelStackSection6(vec![
                            0x00, 0x00, 0x00,
                        ])),
                        ie::Field::ingressInterface(ie::ingressInterface(207)),
                        ie::Field::egressInterface(ie::egressInterface(161)),
                        ie::Field::octetDeltaCount(ie::octetDeltaCount(128)),
                        ie::Field::packetDeltaCount(ie::packetDeltaCount(2)),
                        ie::Field::flowEndSysUpTime(ie::flowEndSysUpTime(0x0c09ceb5)),
                        ie::Field::flowStartSysUpTime(ie::flowStartSysUpTime(0x0c09cac3)),
                        ie::Field::mplsTopLabelIPv4Address(ie::mplsTopLabelIPv4Address(
                            Ipv4Addr::new(0, 0, 0, 0),
                        )),
                        ie::Field::sourceIPv6Address(ie::sourceIPv6Address(Ipv6Addr::from(0))),
                        ie::Field::destinationIPv6Address(ie::destinationIPv6Address(
                            Ipv6Addr::from(0),
                        )),
                        ie::Field::flowLabelIPv6(ie::flowLabelIPv6(0)),
                        ie::Field::ipv6ExtensionHeaders(ie::ipv6ExtensionHeaders(0)),
                        ie::Field::sourceIPv4Address(ie::sourceIPv4Address(Ipv4Addr::new(
                            213, 3, 196, 34,
                        ))),
                        ie::Field::destinationIPv4Address(ie::destinationIPv4Address(
                            Ipv4Addr::new(138, 187, 111, 116),
                        )),
                        ie::Field::sourceTransportPort(ie::sourceTransportPort(38722)),
                        ie::Field::destinationTransportPort(ie::destinationTransportPort(53)),
                        ie::Field::mplsTopLabelPrefixLength(ie::mplsTopLabelPrefixLength(0)),
                        ie::Field::mplsTopLabelType(ie::mplsTopLabelType(0)),
                        ie::Field::forwardingStatus(ie::forwardingStatus(0x40)),
                        ie::Field::flowDirection(ie::flowDirection(0)),
                        ie::Field::ipClassOfService(ie::ipClassOfService(0)),
                        ie::Field::protocolIdentifier(ie::protocolIdentifier(6)),
                        ie::Field::tcpControlBits(ie::tcpControlBits(2)),
                        ie::Field::samplerId(ie::samplerId(1)),
                        ie::Field::ingressVRFID(ie::ingressVRFID(1610612736)),
                        ie::Field::egressVRFID(ie::egressVRFID(1610612741)),
                    ],
                ),
            ],
        }],
    );

    test_parsed_completely_with_one_input(&good_wire, templates_map.clone(), &good);
    test_write_with_one_input(&good, Some(templates_map.clone()), &good_wire)?;
    Ok(())
}
