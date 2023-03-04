//! Simple example of constructing BGP packet
//! in addition to serializing and deserializing BGP packet from wire format.

use std::{io::Cursor, net::Ipv4Addr};

use netgauze_bgp_pkt::{capabilities::*, open::*, *};
use netgauze_iana::address_family::*;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePdu};

pub fn main() {
    // Construct a new BGP message
    let msg = BgpMessage::Open(BgpOpenMessage::new(
        100,
        180,
        Ipv4Addr::new(5, 5, 5, 5),
        vec![
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4MplsLabeledVpn),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::Unrecognized(
                UnrecognizedCapability::new(128, vec![]),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::RouteRefresh]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                FourOctetAsCapability::new(100),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::ExtendedNextHopEncoding(
                ExtendedNextHopEncodingCapability::new(vec![
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Unicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Multicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(
                        AddressType::Ipv4MplsLabeledVpn,
                        AddressFamily::IPv6,
                    ),
                ]),
            )]),
        ],
    ));

    // Serialize the message into it's BGP binary format
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    msg.write(&mut cursor).unwrap();
    assert_eq!(
        buf,
        vec![
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 83,
            1, 4, 0, 100, 0, 180, 5, 5, 5, 5, 54, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 128,
            2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 0, 100, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0,
            1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2
        ]
    );

    // Deserialize the message from binary format
    let (_, msg_back) = BgpMessage::from_wire(Span::new(&buf), true).unwrap();
    assert_eq!(msg, msg_back);
}
