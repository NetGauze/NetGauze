use std::{collections::HashMap, io::Cursor, net::Ipv4Addr};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, netflow::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

fn main() {
    // Cache to share the templates for decoding data packets
    let mut templates_map = HashMap::new();

    // NetFlow v9 template packet
    let netflow_template = NetFlowV9Packet::new(
        120,
        Utc.with_ymd_and_hms(2024, 7, 08, 13, 0, 0).unwrap(),
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

    println!(
        "JSON representation of Netflow V9 Template packet: {}",
        serde_json::to_string(&netflow_template).unwrap()
    );
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    netflow_template.write(&mut cursor, None).unwrap();
    assert_eq!(
        buf,
        vec![
            0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x66, 0x8b, 0xe2, 0xd0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x01, 0x90, 0x00, 0x19,
            0x00, 0x08, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0b,
            0x00, 0x02, 0x00, 0x94, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04,
            0x00, 0x02, 0x00, 0x04, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x59, 0x00, 0x04, 0x00, 0x65,
            0x00, 0x01, 0x00, 0x88, 0x00, 0x01, 0x00, 0xe5, 0x00, 0x01, 0x00, 0xe9, 0x00, 0x01,
            0x00, 0xef, 0x00, 0x01, 0x01, 0x15, 0x00, 0x01, 0x01, 0x1e, 0x00, 0x02, 0x01, 0x29,
            0x00, 0x01, 0x01, 0x80, 0x00, 0x01, 0x01, 0x86, 0x00, 0x02, 0x01, 0x98, 0x00, 0x02,
            0x01, 0xc0, 0x00, 0x01, 0x01, 0xd2, 0x00, 0x01, 0x01, 0xd3, 0x00, 0x01, 0x01, 0xf4,
            0x00, 0x01
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = NetFlowV9Packet::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(netflow_template, msg_back);

    // Netflow v9 data packet
    let netflow_data = NetFlowV9Packet::new(
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

    println!(
        "JSON representation of Netflow v9 Data packet: {}",
        serde_json::to_string(&netflow_data).unwrap()
    );

    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    netflow_data
        .write(&mut cursor, Some(&mut templates_map))
        .unwrap();
    assert_eq!(
        buf,
        vec![
            0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x66, 0x8b, 0xe2, 0xd0, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x90, 0x00, 0x38, 0x0a, 0x64, 0x00, 0x01,
            0x0a, 0x64, 0x00, 0x97, 0x27, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a,
            0x21, 0x12, 0x01, 0x00, 0x00, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x86, 0x12, 0x05, 0x0f, 0x02, 0x03, 0x01, 0x00, 0x06, 0x05, 0x04, 0x00, 0x04,
            0x00, 0x0a, 0x04, 0x04, 0x01, 0x05
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = NetFlowV9Packet::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(netflow_data, msg_back);
}
