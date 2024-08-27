use std::{collections::HashMap, io::Cursor, net::Ipv4Addr};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, netflow::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

fn main() {
    // Cache to share the templates for decoding data packets
    let mut templates_map = HashMap::new();

    // Netflow V9 template packet
    let netflow_template = NetFlowV9Packet::new(
        45646,
        Utc.with_ymd_and_hms(2023, 3, 4, 12, 0, 0).unwrap(),
        3812,
        0,
        vec![Set::Template(vec![TemplateRecord::new(
            307,
            vec![
                FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
            ],
        )])],
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
            0, 9, 0, 1, 0, 0, 178, 78, 100, 3, 50, 192, 0, 0, 14, 228, 0, 0, 0, 0, 0, 0, 0, 24, 1,
            51, 0, 4, 0, 8, 0, 4, 0, 12, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = NetFlowV9Packet::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(netflow_template, msg_back);

    // Netflow v9 data packet
    let netflow_data = NetFlowV9Packet::new(
        45647,
        Utc.with_ymd_and_hms(2023, 3, 4, 12, 0, 1).unwrap(),
        3812,
        0,
        vec![Set::Data {
            id: DataSetId::new(307).unwrap(),
            records: vec![DataRecord::new(
                vec![],
                vec![
                    ie::Field::sourceIPv4Address(ie::sourceIPv4Address(Ipv4Addr::new(
                        70, 1, 115, 1,
                    ))),
                    ie::Field::destinationIPv4Address(ie::destinationIPv4Address(Ipv4Addr::new(
                        50, 0, 71, 1,
                    ))),
                    ie::Field::octetDeltaCount(ie::octetDeltaCount(1312)),
                    ie::Field::packetDeltaCount(ie::packetDeltaCount(9)),
                ],
            )],
        }],
    );

    println!(
        "JSON representation of Netflow V9 Data packet: {}",
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
            0, 9, 0, 1, 0, 0, 178, 79, 100, 3, 50, 193, 0, 0, 14, 228, 0, 0, 0, 0, 1, 51, 0, 20,
            70, 1, 115, 1, 50, 0, 71, 1, 0, 0, 5, 32, 0, 0, 0, 9
        ]
    );
    // Deserialize the message from binary format
    let (_, msg_back) = NetFlowV9Packet::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(netflow_data, msg_back);
}
