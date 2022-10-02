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
    path_attribute::{ASPath, As4PathSegment, AsPathSegmentType, NextHop, Origin, PathAttribute},
    update::{BGPUpdateMessage, NetworkLayerReachabilityInformation},
};
use netgauze_parse_utils::test_helpers::test_parsed_completely;
use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use crate::{BmpMessage, BmpPeerType, PeerHeader, RouteMonitoringMessage};

#[test]
fn test_route_monitoring() -> Result<(), ()> {
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

    Ok(())
}
