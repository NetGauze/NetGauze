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

use crate::{
    v3::PeerDownNotificationReason,
    v4::{
        BmpV4PeerDownTlv, BmpV4RouteMonitoringMessage, BmpV4RouteMonitoringTlv,
        BmpV4RouteMonitoringTlvValue, BMPV4_TLV_GROUP_GBIT,
    },
    wire::{
        deserializer::{
            v3::*,
            v4::{BmpV4MessageValueParsingError, BmpV4RouteMonitoringMessageParsingError},
            BmpMessageParsingError, BmpParsingContext, LocatedBmpMessageParsingError,
        },
        serializer::BmpMessageWritingError,
    },
    *,
};
#[cfg(not(feature = "fuzz"))]
use chrono::TimeZone;
use ipnet::Ipv4Net;
use netgauze_bgp_pkt::{
    capabilities::{AddPathAddressFamily, AddPathCapability, BgpCapability},
    nlri::{Ipv4Unicast, Ipv4UnicastAddress},
    path_attribute::{
        As4PathSegment, AsPath, AsPathSegmentType, Origin, PathAttribute, PathAttributeValue,
    },
    update::BgpUpdateMessage,
    wire::deserializer::{
        update::BgpUpdateMessageParsingError, BgpMessageParsingError, BgpParsingContext,
        Ipv4PrefixParsingError,
    },
};
use netgauze_parse_utils::{
    test_helpers::{
        test_parse_error_with_one_input, test_parsed_completely_with_one_input, test_write,
    },
    Span,
};
use nom::error::ErrorKind;
use std::{collections::HashMap, net::Ipv6Addr, str::FromStr};

#[test]
fn test_bmp_v4_route_monitoring() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x04, 0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
        0x02, 0x34, 0x00, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x34, 0x64, 0x91, 0xa6, 0xa2, 0x00,
        0x0d, 0x51, 0x52, 0x00, 0x03, 0x00, 0x06, 0x00, 0x00, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
        0x00, 0x09, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x32, 0x00,
        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x32, 0x02, 0x00, 0x00, 0x00, 0x16, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02,
        0x00, 0x0e, 0x02, 0x03, 0x00, 0x01, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x13, 0x20, 0xc6, 0x33, 0x64, 0x13,
    ];

    let good = BmpMessage::V4(BmpV4MessageValue::RouteMonitoring(
        BmpV4RouteMonitoringMessage::build(
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: false,
                    post_policy: true,
                    asn2: false,
                    adj_rib_out: false,
                },
                None,
                Some(IpAddr::V4(Ipv4Addr::from_str("192.0.2.52").unwrap())),
                65536,
                Ipv4Addr::new(192, 0, 2, 52),
                Some(Utc.timestamp_opt(1687266978, 872786000).unwrap()),
            ),
            BgpMessage::Update(BgpUpdateMessage::new(
                vec![],
                vec![
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        false,
                        PathAttributeValue::Origin(Origin::IGP),
                    )
                    .unwrap(),
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        true,
                        PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![
                            As4PathSegment::new(
                                AsPathSegmentType::AsSequence,
                                vec![65592, 65536, 65555],
                            ),
                        ])),
                    )
                    .unwrap(),
                ],
                vec![Ipv4UnicastAddress::new_no_path_id(
                    Ipv4Unicast::from_net(
                        Ipv4Net::new(Ipv4Addr::from_str("198.51.100.19").unwrap(), 32).unwrap(),
                    )
                    .unwrap(),
                )],
            )),
            vec![
                BmpV4RouteMonitoringTlv::build(
                    0,
                    BmpV4RouteMonitoringTlvValue::VrfTableName("global".to_string()),
                )
                .unwrap(),
                BmpV4RouteMonitoringTlv::build(
                    0,
                    BmpV4RouteMonitoringTlvValue::Unknown {
                        code: 9,
                        value: vec![0x00, 0x00, 0x00, 0x0a],
                    },
                )
                .unwrap(),
            ],
        )
        .unwrap(),
    ));

    test_parsed_completely_with_one_input(&good_wire, &mut Default::default(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bmp_v4_route_monitoring_with_groups() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x04, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
        0x02, 0x34, 0x00, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x34, 0x64, 0x91, 0xa6, 0xa2, 0x00,
        0x0d, 0x51, 0x52, 0x00, 0x00, 0x00, 0x08, 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
        0x00, 0x04, 0x00, 0x03, 0x00, 0x06, 0x00, 0x00, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x00,
        0x09, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x32, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x32, 0x02, 0x00, 0x00, 0x00, 0x16, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00,
        0x0e, 0x02, 0x03, 0x00, 0x01, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x13,
        0x20, 0xc6, 0x33, 0x64, 0x13,
    ];

    let good = BmpMessage::V4(BmpV4MessageValue::RouteMonitoring(
        BmpV4RouteMonitoringMessage::build(
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: false,
                    post_policy: true,
                    asn2: false,
                    adj_rib_out: false,
                },
                None,
                Some(IpAddr::V4(Ipv4Addr::from_str("192.0.2.52").unwrap())),
                65536,
                Ipv4Addr::new(192, 0, 2, 52),
                Some(Utc.timestamp_opt(1687266978, 872786000).unwrap()),
            ),
            BgpMessage::Update(BgpUpdateMessage::new(
                vec![],
                vec![
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        false,
                        PathAttributeValue::Origin(Origin::IGP),
                    )
                    .unwrap(),
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        true,
                        PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![
                            As4PathSegment::new(
                                AsPathSegmentType::AsSequence,
                                vec![65592, 65536, 65555],
                            ),
                        ])),
                    )
                    .unwrap(),
                ],
                vec![Ipv4UnicastAddress::new_no_path_id(
                    Ipv4Unicast::from_net(
                        Ipv4Net::new(Ipv4Addr::from_str("198.51.100.19").unwrap(), 32).unwrap(),
                    )
                    .unwrap(),
                )],
            )),
            vec![
                BmpV4RouteMonitoringTlv::build(
                    BMPV4_TLV_GROUP_GBIT + 1024,
                    BmpV4RouteMonitoringTlvValue::GroupTlv(vec![1, 2, 3, 4]),
                )
                .unwrap(),
                BmpV4RouteMonitoringTlv::build(
                    0,
                    BmpV4RouteMonitoringTlvValue::VrfTableName("global".to_string()),
                )
                .unwrap(),
                BmpV4RouteMonitoringTlv::build(
                    0,
                    BmpV4RouteMonitoringTlvValue::Unknown {
                        code: 9,
                        value: vec![0x00, 0x00, 0x00, 0x0a],
                    },
                )
                .unwrap(),
            ],
        )
        .unwrap(),
    ));

    test_parsed_completely_with_one_input(&good_wire, &mut Default::default(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bmp_v4_route_monitoring_with_stateless_parsing() -> Result<(), BmpMessageWritingError> {
    let good_wire: [u8; 120] = [
        4, 0, 0, 0, 120, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192,
        0, 2, 52, 0, 1, 0, 0, 192, 0, 2, 52, 100, 145, 166, 162, 0, 13, 81, 82, 0, 1, 0, 6, 0, 0,
        69, 4, 0, 1, 1, 3, 0, 2, 0, 54, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 0, 54, 2, 0, 0, 0, 22, 64, 1, 1, 0, 80, 2, 0, 14, 2, 3, 0, 1,
        0, 56, 0, 1, 0, 0, 0, 1, 0, 19, 0, 0, 0, 69, 32, 198, 51, 100, 19,
    ];

    let good = BmpMessage::V4(BmpV4MessageValue::RouteMonitoring(
        BmpV4RouteMonitoringMessage::build(
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: false,
                    post_policy: true,
                    asn2: false,
                    adj_rib_out: false,
                },
                None,
                Some(IpAddr::V4(Ipv4Addr::from_str("192.0.2.52").unwrap())),
                65536,
                Ipv4Addr::new(192, 0, 2, 52),
                Some(Utc.timestamp_opt(1687266978, 872786000).unwrap()),
            ),
            BgpMessage::Update(BgpUpdateMessage::new(
                vec![],
                vec![
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        false,
                        PathAttributeValue::Origin(Origin::IGP),
                    )
                    .unwrap(),
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        true,
                        PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![
                            As4PathSegment::new(
                                AsPathSegmentType::AsSequence,
                                vec![65592, 65536, 65555],
                            ),
                        ])),
                    )
                    .unwrap(),
                ],
                vec![Ipv4UnicastAddress::new(
                    Some(69),
                    Ipv4Unicast::from_net(
                        Ipv4Net::new(Ipv4Addr::from_str("198.51.100.19").unwrap(), 32).unwrap(),
                    )
                    .unwrap(),
                )],
            )),
            vec![BmpV4RouteMonitoringTlv::build(
                0,
                BmpV4RouteMonitoringTlvValue::StatelessParsing(BgpCapability::AddPath(
                    AddPathCapability::new(vec![AddPathAddressFamily::new(
                        AddressType::Ipv4Unicast,
                        true,
                        true,
                    )]),
                )),
            )
            .unwrap()],
        )
        .unwrap(),
    ));

    test_parsed_completely_with_one_input(&good_wire, &mut Default::default(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bmp_v4_route_monitoring_without_stateless_parsing() -> Result<(), BmpMessageWritingError> {
    let good_wire: [u8; 108] = [
        4, 0, 0, 0, 108, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192,
        0, 2, 52, 0, 1, 0, 0, 192, 0, 2, 52, 100, 145, 166, 162, 0, 13, 81, 82, 0, 2, 0, 54, 0, 0,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 54, 2,
        0, 0, 0, 22, 64, 1, 1, 0, 80, 2, 0, 14, 2, 3, 0, 1, 0, 56, 0, 1, 0, 0, 0, 1, 0, 19, 0, 0,
        0, 69, 32, 198, 51, 100, 19,
    ];

    let good = BmpMessage::V4(BmpV4MessageValue::RouteMonitoring(
        BmpV4RouteMonitoringMessage::build(
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: false,
                    post_policy: true,
                    asn2: false,
                    adj_rib_out: false,
                },
                None,
                Some(IpAddr::V4(Ipv4Addr::from_str("192.0.2.52").unwrap())),
                65536,
                Ipv4Addr::new(192, 0, 2, 52),
                Some(Utc.timestamp_opt(1687266978, 872786000).unwrap()),
            ),
            BgpMessage::Update(BgpUpdateMessage::new(
                vec![],
                vec![
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        false,
                        PathAttributeValue::Origin(Origin::IGP),
                    )
                    .unwrap(),
                    PathAttribute::from(
                        false,
                        true,
                        false,
                        true,
                        PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![
                            As4PathSegment::new(
                                AsPathSegmentType::AsSequence,
                                vec![65592, 65536, 65555],
                            ),
                        ])),
                    )
                    .unwrap(),
                ],
                vec![Ipv4UnicastAddress::new(
                    Some(69),
                    Ipv4Unicast::from_net(
                        Ipv4Net::new(Ipv4Addr::from_str("198.51.100.19").unwrap(), 32).unwrap(),
                    )
                    .unwrap(),
                )],
            )),
            vec![],
        )
        .unwrap(),
    ));

    let error = LocatedBmpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(102, &good_wire[102..]) },
        BmpMessageParsingError::BmpV4MessageValueError(
            BmpV4MessageValueParsingError::RouteMonitoringMessageError(
                BmpV4RouteMonitoringMessageParsingError::BgpMessage(
                    BgpMessageParsingError::BgpUpdateMessageParsingError(
                        BgpUpdateMessageParsingError::Ipv4PrefixError(
                            Ipv4PrefixParsingError::InvalidIpv4PrefixLen(69),
                        ),
                    ),
                ),
            ),
        ),
    );

    let mut no_context = Default::default();
    test_parse_error_with_one_input::<
        BmpMessage,
        &mut BmpParsingContext,
        LocatedBmpMessageParsingError<'_>,
    >(&good_wire, &mut no_context, &error);

    let mut good_context = BmpParsingContext::default();
    let per_peer_header = match &good {
        BmpMessage::V4(BmpV4MessageValue::RouteMonitoring(BmpV4RouteMonitoringMessage {
            peer_header,
            ..
        })) => peer_header,
        _ => unreachable!(),
    };

    good_context.add_peer(
        PeerKey::from_peer_header(per_peer_header),
        BgpParsingContext::new(
            true,
            Default::default(),
            HashMap::from([(AddressType::Ipv4Unicast, true)]),
            true,
            true,
            true,
            true,
        ),
    );

    test_parsed_completely_with_one_input(&good_wire, &mut good_context, &good);
    Ok(())
}

#[test]
fn test_bmp_v4_peer_down_notification() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x04, 0x00, 0x00, 0x00, 0x3f, 0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0xfc, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x53, 0x00,
        0x07, 0x71, 0xe3, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07,
    ];
    let bad_eof_wire = [];

    let good = BmpMessage::V4(BmpV4MessageValue::PeerDownNotification {
        v3_notif: PeerDownNotificationMessage::build(
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
                Some(Utc.timestamp_opt(1664821843, 487907000).unwrap()),
            ),
            PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(2),
        )
        .unwrap(),
        tlvs: vec![BmpV4PeerDownTlv::Unknown {
            code: 16,
            value: vec![0, 1, 2, 3, 4, 5, 6, 7],
        }],
    });

    let bad_eof = LocatedBmpMessageValueParsingError::new(
        Span::new(&bad_eof_wire),
        BmpMessageValueParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely_with_one_input(&good_wire, &mut Default::default(), &good);

    test_parse_error_with_one_input::<
        BmpV3MessageValue,
        &mut BmpParsingContext,
        LocatedBmpMessageValueParsingError<'_>,
    >(&bad_eof_wire, &mut Default::default(), &bad_eof);

    test_write(&good, &good_wire)?;

    Ok(())
}
