use std::{collections::HashMap, io::Cursor, net::Ipv4Addr};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, ie::*, ipfix::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

fn main() {
    // Cache to share the templates for decoding data packets
    let mut templates_map = HashMap::new();

    // IPFIX template packet
    let ipfix_template = IpfixPacket::new(
        Utc.with_ymd_and_hms(2024, 7, 08, 10, 0, 0).unwrap(),
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
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::ingressInterfaceAttr), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::egressInterfaceAttr), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::vxlanExportRole), 1).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantSourceIPv4), 4).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantDestIPv4), 4).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantSourcePort), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantDestPort), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantProtocol), 1).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::flowDirection), 1).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::virtualObsID), 65535).unwrap(),
            ]),
        )]))]),
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
            0x00, 0x0a, 0x00, 0x88, 0x66, 0x8b, 0xb8, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x78, 0x01, 0x90, 0x00, 0x12, 0x00, 0x08, 0x00, 0x04,
            0x00, 0x0c, 0x00, 0x04, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x94,
            0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
            0x83, 0x7a, 0x00, 0x02, 0x00, 0x00, 0x1a, 0xdc, 0x83, 0x78, 0x00, 0x02, 0x00, 0x00,
            0x1a, 0xdc, 0x83, 0x79, 0x00, 0x01, 0x00, 0x00, 0x1a, 0xdc, 0x83, 0x71, 0x00, 0x04,
            0x00, 0x00, 0x1a, 0xdc, 0x83, 0x72, 0x00, 0x04, 0x00, 0x00, 0x1a, 0xdc, 0x83, 0x76,
            0x00, 0x02, 0x00, 0x00, 0x1a, 0xdc, 0x83, 0x77, 0x00, 0x02, 0x00, 0x00, 0x1a, 0xdc,
            0x83, 0x70, 0x00, 0x01, 0x00, 0x00, 0x1a, 0xdc, 0x83, 0xba, 0x00, 0x01, 0x00, 0x00,
            0x1a, 0xdc, 0x83, 0x82, 0xff, 0xff, 0x00, 0x00, 0x1a, 0xdc
        ]
    );

    // Deserialize the message from binary format (this will also add the Template
    // to templates_map, otherwise the packet will be generated with all the
    // default lengths)
    let (_, msg_back) = IpfixPacket::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(ipfix_template, msg_back);

    // IPFIX data packet
    let ipfix_data = IpfixPacket::new(
        Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
        0,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(400).unwrap(),
            records: Box::new([DataRecord::new(
                Box::new([]),
                Box::new([
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
                    ie::Field::VMWare(vmware::Field::ingressInterfaceAttr(
                        vmware::ingressInterfaceAttr(10),
                    )),
                    ie::Field::VMWare(vmware::Field::egressInterfaceAttr(
                        vmware::egressInterfaceAttr(12),
                    )),
                    ie::Field::VMWare(vmware::Field::vxlanExportRole(vmware::vxlanExportRole(0))),
                    ie::Field::VMWare(vmware::Field::tenantSourceIPv4(vmware::tenantSourceIPv4(
                        Ipv4Addr::new(192, 168, 140, 6),
                    ))),
                    ie::Field::VMWare(vmware::Field::tenantDestIPv4(vmware::tenantDestIPv4(
                        Ipv4Addr::new(192, 168, 140, 68),
                    ))),
                    ie::Field::VMWare(vmware::Field::tenantSourcePort(vmware::tenantSourcePort(
                        20023,
                    ))),
                    ie::Field::VMWare(vmware::Field::tenantDestPort(vmware::tenantDestPort(443))),
                    ie::Field::VMWare(vmware::Field::tenantProtocol(vmware::tenantProtocol::TCP)),
                    ie::Field::VMWare(vmware::Field::flowDirection(vmware::flowDirection::ingress)),
                    ie::Field::VMWare(vmware::Field::virtualObsID(vmware::virtualObsID(
                        String::from("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                    ))),
                ]),
            )]),
        }]),
    );

    println!(
        "JSON representation of IPFIX Data packet: {}",
        serde_json::to_string(&ipfix_data).unwrap()
    );

    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    ipfix_data
        .write(&mut cursor, Some(&mut templates_map))
        .unwrap();
    assert_eq!(
        buf,
        vec![
            0x00, 0x0a, 0x00, 0x6a, 0x66, 0x74, 0x35, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x90, 0x00, 0x5a, 0x0a, 0x64, 0x00, 0x01, 0x0a, 0x64, 0x00, 0x97,
            0x27, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x21, 0x12, 0x01, 0x00,
            0x00, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0xc0, 0xa8,
            0x8c, 0x06, 0xc0, 0xa8, 0x8c, 0x44, 0x4e, 0x37, 0x01, 0xbb, 0x06, 0x00, 0x24, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x2d, 0x62, 0x62, 0x62, 0x62, 0x2d, 0x63,
            0x63, 0x63, 0x63, 0x2d, 0x64, 0x64, 0x64, 0x64, 0x2d, 0x65, 0x65, 0x65, 0x65, 0x65,
            0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x00
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = IpfixPacket::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(ipfix_data, msg_back);
}
