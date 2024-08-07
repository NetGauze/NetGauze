use std::{cell::RefCell, collections::HashMap, io::Cursor, net::Ipv4Addr, rc::Rc};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, ipfix::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

fn main() {
    // Cache to share the templates for decoding data packets
    let templates_map = Rc::new(RefCell::new(HashMap::new()));

    // IPFIX template packet
    let ipfix_template = IpfixPacket::new(
        Utc.with_ymd_and_hms(2024, 7, 08, 10, 0, 0).unwrap(),
        0,
        0,
        vec![Set::Template(vec![TemplateRecord::new(
            400,
            vec![
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
            ],
        )])],
    );

    println!(
        "JSON representation of IPFIX Template packet: {}",
        serde_json::to_string(&ipfix_template).unwrap()
    );
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    ipfix_template.write(&mut cursor, None).unwrap();
    assert_eq!(
        buf,
        vec![
            0x00, 0x0a, 0x00, 0x7c, 0x66, 0x8b, 0xb8, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x6c, 0x01, 0x90, 0x00, 0x19, 0x00, 0x08, 0x00, 0x04,
            0x00, 0x0c, 0x00, 0x04, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x94,
            0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
            0x00, 0x2e, 0x00, 0x01, 0x00, 0x59, 0x00, 0x04, 0x00, 0x65, 0x00, 0x01, 0x00, 0x88,
            0x00, 0x01, 0x00, 0xe5, 0x00, 0x01, 0x00, 0xe9, 0x00, 0x01, 0x00, 0xef, 0x00, 0x01,
            0x01, 0x15, 0x00, 0x01, 0x01, 0x1e, 0x00, 0x02, 0x01, 0x29, 0x00, 0x01, 0x01, 0x80,
            0x00, 0x01, 0x01, 0x86, 0x00, 0x02, 0x01, 0x98, 0x00, 0x02, 0x01, 0xc0, 0x00, 0x01,
            0x01, 0xd2, 0x00, 0x01, 0x01, 0xd3, 0x00, 0x01, 0x01, 0xf4, 0x00, 0x01
        ]
    );
    // Deserialize the message from binary format (this will also add the Template
    // to templates_map, otherwise the packet will be generated with all the
    // default lengths)
    let (_, msg_back) = IpfixPacket::from_wire(Span::new(&buf), Rc::clone(&templates_map)).unwrap();
    assert_eq!(ipfix_template, msg_back);

    // IPFIX data packet
    let ipfix_data = IpfixPacket::new(
        Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
        0,
        0,
        vec![Set::Data {
            id: DataSetId::new(400).unwrap(),
            records: vec![DataRecord::new(
                vec![],
                vec![
                    ie::Field::sourceIPv4Address(ie::sourceIPv4Address(Ipv4Addr::new(
                        10, 100, 0, 1,
                    ))),
                    ie::Field::destinationIPv4Address(ie::destinationIPv4Address(Ipv4Addr::new(
                        10, 100, 0, 151,
                    ))),
                    ie::Field::sourceTransportPort(ie::sourceTransportPort(10004)),
                    ie::Field::destinationTransportPort(ie::destinationTransportPort(1)),
                    ie::Field::flowId(ie::flowId(10101010)),
                    ie::Field::protocolIdentifier(ie::protocolIdentifier::ICMP),
                    ie::Field::octetDeltaCount(ie::octetDeltaCount(1200)),
                    ie::Field::packetDeltaCount(ie::packetDeltaCount(1)),
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
                ],
            )],
        }],
    );

    println!(
        "JSON representation of IPFIX Data packet: {}",
        serde_json::to_string(&ipfix_data).unwrap()
    );

    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    ipfix_data
        .write(&mut cursor, Some(Rc::clone(&templates_map)))
        .unwrap();
    assert_eq!(
        buf,
        vec![
            0x00, 0x0a, 0x00, 0x48, 0x66, 0x74, 0x35, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x90, 0x00, 0x38, 0x0a, 0x64, 0x00, 0x01, 0x0a, 0x64, 0x00, 0x97,
            0x27, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x21, 0x12, 0x01, 0x00,
            0x00, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x86, 0x12, 0x05,
            0x0f, 0x02, 0x03, 0x01, 0x00, 0x06, 0x05, 0x04, 0x00, 0x04, 0x00, 0x0a, 0x04, 0x04,
            0x01, 0x05
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = IpfixPacket::from_wire(Span::new(&buf), Rc::clone(&templates_map)).unwrap();
    assert_eq!(ipfix_data, msg_back);
}
