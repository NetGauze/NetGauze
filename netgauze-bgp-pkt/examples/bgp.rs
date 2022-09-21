//! Simple example of constructing BGP packet
//! in addition to serializing and deserializing BGP packet from wire format.

use std::{io::Cursor, net::Ipv4Addr};

use netgauze_bgp_pkt::{capabilities::*, open::*, *};
use netgauze_iana::address_family::*;
use netgauze_parse_utils::{ReadablePDUWithOneInput, Span, WritablePDU};

pub fn main() {
    // Construct a new BGP message
    let msg = BGPMessage::Open(BGPOpenMessage::new(
        100,
        180,
        Ipv4Addr::new(5, 5, 5, 5),
        vec![
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::IpPv4MplsLabeledVpn),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::Unrecognized(
                UnrecognizedCapability::new(128, vec![]),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::RouteRefresh]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::FourOctetAS(
                FourOctetASCapability::new(100),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::ExtendedNextHopEncoding(
                ExtendedNextHopEncodingCapability::new(vec![
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Unicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Multicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(
                        AddressType::IpPv4MplsLabeledVpn,
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
    let (_, msg_back) = BGPMessage::from_wire(Span::new(&buf), true).unwrap();
    assert_eq!(msg, msg_back);
}
