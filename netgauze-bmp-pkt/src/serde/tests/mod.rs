// Copyright (C) 2022-present The NetGauze Authors.
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

use chrono::{TimeZone, Utc};
use ipnet::Ipv4Net;
use netgauze_bgp_pkt::{
    capabilities::{
        BGPCapability, ExtendedNextHopEncoding, ExtendedNextHopEncodingCapability,
        FourOctetASCapability, MultiProtocolExtensionsCapability, UnrecognizedCapability,
    },
    open::{BGPOpenMessage, BGPOpenMessageParameter},
    path_attribute::{ASPath, As4PathSegment, AsPathSegmentType, NextHop, Origin, PathAttribute},
    update::{BGPUpdateMessage, NetworkLayerReachabilityInformation},
    BGPMessage,
};
use netgauze_iana::address_family::{AddressFamily, AddressType};
use netgauze_parse_utils::test_helpers::{test_parsed_completely, test_write};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    serde::serializer::{BmpMessageWritingError, PeerHeaderWritingError},
    BmpMessage, BmpPeerType, InitiationInformation, InitiationMessage, PeerDownNotificationMessage,
    PeerDownNotificationReason, PeerHeader, PeerUpNotificationMessage, RouteMonitoringMessage,
};

#[test]
fn test_bmp_init() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x03, 0x00, 0x00, 0x00, 0x17, 0x04, 0x00, 0x01, 0x00, 0x06, 0x74, 0x65, 0x73, 0x74, 0x31,
        0x31, 0x00, 0x02, 0x00, 0x03, 0x50, 0x45, 0x32,
    ];

    let good = BmpMessage::Initiation(InitiationMessage::new(vec![
        InitiationInformation::SystemDescription("test11".to_string()),
        InitiationInformation::SystemName("PE2".to_string()),
    ]));
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_peer_header() -> Result<(), PeerHeaderWritingError> {
    let good_ipv4_wire = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c,
    ];
    let good_ipv6_wire = [
        0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c,
    ];
    let good_post_policy_wire = [
        0x02, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c,
    ];
    let good_adj_rip_out_wire = [
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c,
    ];
    let good_asn2_wire = [
        0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c,
    ];
    let good_filtered_wire = [
        0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c,
    ];

    let good_ipv4 = PeerHeader::new(
        BmpPeerType::GlobalInstancePeer {
            ipv6: false,
            post_policy: false,
            asn2: false,
            adj_rib_out: false,
        },
        None,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 20))),
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        Some(Utc.timestamp(1664656357, 746092000)),
    );

    let good_ipv6 = PeerHeader::new(
        BmpPeerType::RdInstancePeer {
            ipv6: true,
            post_policy: false,
            asn2: false,
            adj_rib_out: false,
        },
        None,
        Some(IpAddr::V6(Ipv6Addr::from_str("2001:db8::ac10:14").unwrap())),
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        Some(Utc.timestamp(1664656357, 746092000)),
    );

    let good_post_policy = PeerHeader::new(
        BmpPeerType::LocalInstancePeer {
            ipv6: true,
            post_policy: true,
            asn2: false,
            adj_rib_out: false,
        },
        None,
        Some(IpAddr::V6(Ipv6Addr::from_str("2001:db8::ac10:14").unwrap())),
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        Some(Utc.timestamp(1664656357, 746092000)),
    );

    let good_adj_rip_out = PeerHeader::new(
        BmpPeerType::GlobalInstancePeer {
            ipv6: false,
            post_policy: false,
            asn2: false,
            adj_rib_out: true,
        },
        None,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 20))),
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        Some(Utc.timestamp(1664656357, 746092000)),
    );

    let good_asn2 = PeerHeader::new(
        BmpPeerType::GlobalInstancePeer {
            ipv6: false,
            post_policy: false,
            asn2: true,
            adj_rib_out: false,
        },
        None,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 20))),
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        Some(Utc.timestamp(1664656357, 746092000)),
    );

    let good_filtered = PeerHeader::new(
        BmpPeerType::LocRibInstancePeer { filtered: true },
        None,
        None,
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        Some(Utc.timestamp(1664656357, 746092000)),
    );

    test_parsed_completely(&good_ipv4_wire, &good_ipv4);
    test_parsed_completely(&good_ipv6_wire, &good_ipv6);
    test_parsed_completely(&good_post_policy_wire, &good_post_policy);
    test_parsed_completely(&good_adj_rip_out_wire, &good_adj_rip_out);
    test_parsed_completely(&good_asn2_wire, &good_asn2);
    test_parsed_completely(&good_filtered_wire, &good_filtered);

    test_write(&good_ipv4, &good_ipv4_wire)?;
    test_write(&good_ipv6, &good_ipv6_wire)?;
    test_write(&good_post_policy, &good_post_policy_wire)?;
    test_write(&good_adj_rip_out, &good_adj_rip_out_wire)?;
    test_write(&good_asn2, &good_asn2_wire)?;
    test_write(&good_filtered, &good_filtered_wire)?;
    Ok(())
}

#[test]
fn test_route_monitoring() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x03, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10,
        0x00, 0x14, 0x00, 0x00, 0x00, 0xc8, 0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00,
        0x0b, 0x62, 0x6c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x38, 0x02, 0x00, 0x00, 0x00, 0x1d, 0x40, 0x01, 0x01, 0x00,
        0x50, 0x02, 0x00, 0x0e, 0x02, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, 0x00,
        0x00, 0x00, 0x64, 0x40, 0x03, 0x04, 0xac, 0x10, 0x00, 0x14, 0x18, 0xac, 0x10, 0x01,
    ];

    let good = BmpMessage::RouteMonitoring(RouteMonitoringMessage::new(
        PeerHeader::new(
            BmpPeerType::GlobalInstancePeer {
                ipv6: false,
                post_policy: false,
                asn2: false,
                adj_rib_out: false,
            },
            None,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 20))),
            200,
            Ipv4Addr::new(172, 16, 0, 20),
            Some(Utc.timestamp(1664656357, 746092000)),
        ),
        vec![BGPUpdateMessage::new(
            vec![],
            vec![
                PathAttribute::Origin {
                    extended_length: false,
                    value: Origin::IGP,
                },
                PathAttribute::ASPath {
                    extended_length: true,
                    value: ASPath::As4PathSegments(vec![As4PathSegment::new(
                        AsPathSegmentType::AsSequence,
                        vec![100, 200, 100],
                    )]),
                },
                PathAttribute::NextHop {
                    extended_length: false,
                    value: NextHop::new(Ipv4Addr::new(172, 16, 0, 20)),
                },
            ],
            vec![NetworkLayerReachabilityInformation::new(vec![
                Ipv4Net::from_str("172.16.1.0/24").unwrap(),
            ])],
        )],
    ));

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_peer_up_notification() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x03, 0x00, 0x00, 0x00, 0xda, 0x03, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0xfc, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x42, 0x00,
        0x09, 0xd9, 0xd9, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x00, 0xb3, 0x74, 0x8a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x4b, 0x01, 0x04, 0xfc, 0x00,
        0x00, 0xb4, 0x0a, 0x00, 0x00, 0x03, 0x2e, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80,
        0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfc,
        0x00, 0x02, 0x14, 0x05, 0x12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x4b, 0x01, 0x04, 0xfc, 0x00,
        0x00, 0xb4, 0x0a, 0x00, 0x00, 0x01, 0x2e, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80,
        0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfc,
        0x00, 0x02, 0x14, 0x05, 0x12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00, 0x02,
    ];

    let good = BmpMessage::PeerUpNotification(
        PeerUpNotificationMessage::build(
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: true,
                    post_policy: false,
                    asn2: false,
                    adj_rib_out: false,
                },
                None,
                Some(IpAddr::V6(Ipv6Addr::from_str("fc00::1").unwrap())),
                64512,
                Ipv4Addr::new(10, 0, 0, 1),
                Some(Utc.timestamp(1664821826, 645593000)),
            ),
            IpAddr::V6(Ipv6Addr::from_str("fc00::3").unwrap()),
            Some(179),
            Some(29834),
            BGPMessage::Open(BGPOpenMessage::new(
                64512,
                180,
                Ipv4Addr::new(10, 0, 0, 3),
                vec![
                    BGPOpenMessageParameter::Capabilities(vec![
                        BGPCapability::MultiProtocolExtensions(
                            MultiProtocolExtensionsCapability::new(AddressType::Ipv4MplsLabeledVpn),
                        ),
                    ]),
                    BGPOpenMessageParameter::Capabilities(vec![BGPCapability::Unrecognized(
                        UnrecognizedCapability::new(128, vec![]),
                    )]),
                    BGPOpenMessageParameter::Capabilities(vec![BGPCapability::RouteRefresh]),
                    BGPOpenMessageParameter::Capabilities(vec![BGPCapability::FourOctetAS(
                        FourOctetASCapability::new(64512),
                    )]),
                    BGPOpenMessageParameter::Capabilities(vec![
                        BGPCapability::ExtendedNextHopEncoding(
                            ExtendedNextHopEncodingCapability::new(vec![
                                ExtendedNextHopEncoding::new(
                                    AddressType::Ipv4Unicast,
                                    AddressFamily::IPv6,
                                ),
                                ExtendedNextHopEncoding::new(
                                    AddressType::Ipv4Multicast,
                                    AddressFamily::IPv6,
                                ),
                                ExtendedNextHopEncoding::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                    AddressFamily::IPv6,
                                ),
                            ]),
                        ),
                    ]),
                ],
            )),
            BGPMessage::Open(BGPOpenMessage::new(
                64512,
                180,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![
                    BGPOpenMessageParameter::Capabilities(vec![
                        BGPCapability::MultiProtocolExtensions(
                            MultiProtocolExtensionsCapability::new(AddressType::Ipv4MplsLabeledVpn),
                        ),
                    ]),
                    BGPOpenMessageParameter::Capabilities(vec![BGPCapability::Unrecognized(
                        UnrecognizedCapability::new(128, vec![]),
                    )]),
                    BGPOpenMessageParameter::Capabilities(vec![BGPCapability::RouteRefresh]),
                    BGPOpenMessageParameter::Capabilities(vec![BGPCapability::FourOctetAS(
                        FourOctetASCapability::new(64512),
                    )]),
                    BGPOpenMessageParameter::Capabilities(vec![
                        BGPCapability::ExtendedNextHopEncoding(
                            ExtendedNextHopEncodingCapability::new(vec![
                                ExtendedNextHopEncoding::new(
                                    AddressType::Ipv4Unicast,
                                    AddressFamily::IPv6,
                                ),
                                ExtendedNextHopEncoding::new(
                                    AddressType::Ipv4Multicast,
                                    AddressFamily::IPv6,
                                ),
                                ExtendedNextHopEncoding::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                    AddressFamily::IPv6,
                                ),
                            ]),
                        ),
                    ]),
                ],
            )),
            vec![],
        )
        .unwrap(),
    );

    test_parsed_completely(&good_wire, &good);

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_peer_down_notification() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x03, 0x00, 0x00, 0x00, 0x33, 0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0xfc, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x53, 0x00,
        0x07, 0x71, 0xe3, 0x02, 0x00, 0x02,
    ];

    let good = BmpMessage::PeerDownNotification(
        PeerDownNotificationMessage::build(
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: true,
                    post_policy: false,
                    asn2: false,
                    adj_rib_out: false,
                },
                None,
                Some(IpAddr::V6(Ipv6Addr::from_str("fc00::1").unwrap())),
                64512,
                Ipv4Addr::new(10, 0, 0, 1),
                Some(Utc.timestamp(1664821843, 487907000)),
            ),
            PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(2),
        )
        .unwrap(),
    );

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;

    Ok(())
}
