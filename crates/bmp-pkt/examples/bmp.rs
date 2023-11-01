//! Simple example of constructing BMP packet
//! in addition to serializing and deserializing BMP packet from wire format.

use chrono::{TimeZone, Utc};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bmp_pkt::{
    iana::RouteMirroringInformation, BmpMessage, BmpMessageValue, BmpPeerType, PeerHeader,
    RouteMirroringMessage, RouteMirroringValue,
};
use netgauze_parse_utils::{ReadablePduWithTwoInputs, Span, WritablePdu};
use std::{
    collections::HashMap,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

fn main() {
    let bmp_msg = BmpMessage::V3(BmpMessageValue::RouteMirroring(RouteMirroringMessage::new(
        PeerHeader::new(
            BmpPeerType::LocRibInstancePeer { filtered: false },
            None,
            Some(IpAddr::V6(Ipv6Addr::from_str("2001::1").unwrap())),
            65000,
            Ipv4Addr::new(172, 10, 0, 1),
            Some(Utc.with_ymd_and_hms(2023, 01, 01, 01, 00, 00).unwrap()),
        ),
        vec![
            RouteMirroringValue::Information(RouteMirroringInformation::Experimental65531),
            RouteMirroringValue::BgpMessage(BgpMessage::KeepAlive),
        ],
    )));

    println!(
        "JSON representation of BMP packet: {}",
        serde_json::to_string(&bmp_msg).unwrap()
    );

    // Serialize the message into it's BGP binary format
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    bmp_msg.write(&mut cursor).unwrap();
    assert_eq!(
        buf,
        vec![
            3, 0, 0, 0, 77, 6, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 253, 232, 172, 10, 0, 1, 99, 176, 219, 16, 0, 0, 0, 0, 0, 1, 0, 2,
            255, 251, 0, 0, 0, 19, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 0, 19, 4
        ]
    );

    // Deserialize the message from binary format
    let (_, bmp_msg_back) =
        BmpMessage::from_wire(Span::new(&buf), &HashMap::new(), &HashMap::new()).unwrap();
    assert_eq!(bmp_msg, bmp_msg_back);
}
