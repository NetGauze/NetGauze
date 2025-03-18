use std::{collections::HashMap, io::Cursor, net::Ipv4Addr};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, ipfix::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

fn main() {
    // Cache to share the templates for decoding data packets
    let mut templates_map = HashMap::new();

    // IPFIX template packet
    let ipfix_template = IpfixPacket::new(
        Utc.with_ymd_and_hms(2023, 3, 4, 12, 0, 0).unwrap(),
        3812,
        0,
        Box::new([Set::Template(Box::new([TemplateRecord::new(
            307,
            Box::new([
                FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
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
            0, 10, 0, 40, 100, 3, 50, 192, 0, 0, 14, 228, 0, 0, 0, 0, 0, 2, 0, 24, 1, 51, 0, 4, 0,
            8, 0, 4, 0, 12, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4,
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = IpfixPacket::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(ipfix_template, msg_back);

    // IPFIX data packet
    let ipfix_data = IpfixPacket::new(
        Utc.with_ymd_and_hms(2023, 3, 4, 12, 0, 1).unwrap(),
        3812,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(307).unwrap(),
            records: Box::new([DataRecord::new(
                Box::new([]),
                Box::new([
                    ie::Field::sourceIPv4Address(Ipv4Addr::new(70, 1, 115, 1)),
                    ie::Field::destinationIPv4Address(Ipv4Addr::new(50, 0, 71, 1)),
                    ie::Field::octetDeltaCount(1312),
                    ie::Field::packetDeltaCount(9),
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
            0, 10, 0, 36, 100, 3, 50, 193, 0, 0, 14, 228, 0, 0, 0, 0, 1, 51, 0, 20, 70, 1, 115, 1,
            50, 0, 71, 1, 0, 0, 5, 32, 0, 0, 0, 9
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = IpfixPacket::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(ipfix_data, msg_back);
}
