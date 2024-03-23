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
    nlri::*,
    wire::{deserializer::nlri::*, serializer::nlri::*},
};
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_parse_utils::{
    test_helpers::{
        test_parse_error, test_parsed_completely, test_parsed_completely_with_one_input,
        test_parsed_completely_with_three_inputs, test_write,
    },
    Span,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[test]
fn test_ipv6_unicast() -> Result<(), Ipv6UnicastWritingError> {
    let good_wire = [0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];
    let bad_multicast_wire = [0x40, 0xff, 0x00, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];

    let unicast_net = Ipv6Net::from_str("2001:db8:2::/64").unwrap();
    let multicast_net = Ipv6Net::from_str("ff00:db8:2::/64").unwrap();
    let good = Ipv6Unicast::from_net(unicast_net).unwrap();
    let bad_multicast = LocatedIpv6UnicastParsingError::new(
        Span::new(&bad_multicast_wire),
        Ipv6UnicastParsingError::InvalidUnicastNetwork(InvalidIpv6UnicastNetwork(multicast_net)),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv6Unicast, LocatedIpv6UnicastParsingError<'_>>(
        &bad_multicast_wire,
        &bad_multicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv6_multicast() -> Result<(), Ipv6MulticastWritingError> {
    let good_wire = [0x40, 0xff, 0x00, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];
    let bad_unicast_wire = [0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00];

    let unicast_net = Ipv6Net::from_str("2001:db8:2::/64").unwrap();
    let multicast_net = Ipv6Net::from_str("ff00:db8:2::/64").unwrap();
    let good = Ipv6Multicast::from_net(multicast_net).unwrap();
    let bad_unicast = LocatedIpv6MulticastParsingError::new(
        Span::new(&bad_unicast_wire),
        Ipv6MulticastParsingError::InvalidMulticastNetwork(InvalidIpv6MulticastNetwork(
            unicast_net,
        )),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv6Multicast, LocatedIpv6MulticastParsingError<'_>>(
        &bad_unicast_wire,
        &bad_unicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_unicast() -> Result<(), Ipv4UnicastWritingError> {
    let good_wire = [24, 192, 168, 56];
    let bad_multicast_wire = [24, 224, 0, 0];

    let unicast_net = Ipv4Net::from_str("192.168.56.0/24").unwrap();
    let multi_net = Ipv4Net::from_str("224.0.0.0/24").unwrap();
    let good = Ipv4Unicast::from_net(unicast_net).unwrap();
    let bad_multicast = LocatedIpv4UnicastParsingError::new(
        Span::new(&bad_multicast_wire),
        Ipv4UnicastParsingError::InvalidUnicastNetwork(InvalidIpv4UnicastNetwork(multi_net)),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv4Unicast, LocatedIpv4UnicastParsingError<'_>>(
        &bad_multicast_wire,
        &bad_multicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_multicast() -> Result<(), Ipv4MulticastWritingError> {
    let good_wire = [24, 224, 0, 0];
    let bad_unicast_wire = [24, 192, 168, 56];

    let unicast_net = Ipv4Net::from_str("192.168.56.0/24").unwrap();
    let multicast_net = Ipv4Net::from_str("224.0.0.0/24").unwrap();
    let good = Ipv4Multicast::from_net(multicast_net).unwrap();
    let bad_unicast = LocatedIpv4MulticastParsingError::new(
        Span::new(&bad_unicast_wire),
        Ipv4MulticastParsingError::InvalidMulticastNetwork(InvalidIpv4MulticastNetwork(
            unicast_net,
        )),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Ipv4Multicast, LocatedIpv4MulticastParsingError<'_>>(
        &bad_unicast_wire,
        &bad_unicast,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_route_distinguisher() -> Result<(), RouteDistinguisherWritingError> {
    let good_wire = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let good = RouteDistinguisher::As2Administrator { asn2: 0, number: 0 };
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_labeled_ipv6_next_hop() -> Result<(), LabeledNextHopWritingError> {
    let good_wire = [
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let good = LabeledNextHop::Ipv6(LabeledIpv6NextHop::new(
        RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
        Ipv6Addr::from_str("fc00::1").unwrap(),
        None,
    ));
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_mpls_vpn_unicast() -> Result<(), Ipv4MplsVpnUnicastAddressWritingError> {
    let good_wire = [
        0x70, 0x00, 0x41, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xa8, 0x01,
    ];

    let good = Ipv4MplsVpnUnicastAddress::new_no_path_id(
        RouteDistinguisher::As2Administrator { asn2: 1, number: 1 },
        vec![MplsLabel::new([0x00, 0x41, 0x01])],
        Ipv4Unicast::from_net(Ipv4Net::from_str("192.168.1.0/24").unwrap()).unwrap(),
    );
    test_parsed_completely_with_three_inputs(&good_wire, false, false, 1, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv6_mpls_vpn_unicast() -> Result<(), Ipv6MplsVpnUnicastAddressWritingError> {
    let good_wire = [
        0xd6, 0xe0, 0x08, 0x01, 0x00, 0x01, 0x0a, 0xd0, 0xb6, 0x30, 0x00, 0x03, 0xfd, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    ];

    let good = Ipv6MplsVpnUnicastAddress::new_no_path_id(
        RouteDistinguisher::Ipv4Administrator {
            ip: Ipv4Addr::new(10, 208, 182, 48),
            number: 3,
        },
        vec![MplsLabel::new([0xe0, 0x08, 0x01])],
        Ipv6Unicast::from_net(Ipv6Net::from_str("fd00:2::4/126").unwrap()).unwrap(),
    );
    test_parsed_completely_with_three_inputs(&good_wire, false, false, 1, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_mac_address() -> Result<(), MacAddressWritingError> {
    let good_wire = [0x00, 0x0c, 0x29, 0xde, 0xe3, 0x64];

    let good = MacAddress([0x00, 0x0c, 0x29, 0xde, 0xe3, 0x64]);
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ethernet_tag() -> Result<(), EthernetTagWritingError> {
    let good_wire = [0x01, 0x02, 0x03, 0x04];

    let good = EthernetTag(16909060);
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ethernet_segment_id() -> Result<(), EthernetSegmentIdentifierWritingError> {
    let good_wire = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];

    let good =
        EthernetSegmentIdentifier([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]);
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ethernet_auto_discovery() -> Result<(), EthernetAutoDiscoveryWritingError> {
    let good_wire = [
        0x00, 0x01, 0x78, 0x00, 0x02, 0x05, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x49, 0x35, 0x01,
    ];

    let good = EthernetAutoDiscovery::new(
        RouteDistinguisher::Ipv4Administrator {
            ip: Ipv4Addr::new(120, 0, 2, 5),
            number: 100,
        },
        EthernetSegmentIdentifier([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05]),
        EthernetTag(0),
        MplsLabel::new([0x49, 0x35, 0x01]),
    );
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_mac_ip_advertisement() -> Result<(), MacIpAdvertisementWritingError> {
    let good_wire = [
        0x00, 0x01, 0x78, 0x00, 0x02, 0x05, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x30, 0x00, 0x0c, 0x29, 0x82, 0xc2, 0xa9, 0x00,
        0x49, 0x30, 0x01,
    ];

    let good = MacIpAdvertisement::new(
        RouteDistinguisher::Ipv4Administrator {
            ip: Ipv4Addr::new(120, 0, 2, 5),
            number: 100,
        },
        EthernetSegmentIdentifier([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        EthernetTag(100),
        MacAddress([0x00, 0x0c, 0x29, 0x82, 0xc2, 0xa9]),
        None,
        MplsLabel::new([0x49, 0x30, 0x01]),
        None,
    );
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_inclusive_multicast_ethernet_tag_route(
) -> Result<(), InclusiveMulticastEthernetTagRouteWritingError> {
    let good_wire = [
        0x00, 0x01, 0xac, 0x10, 0x00, 0xc8, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x20, 0xac, 0x10,
        0x00, 0xc8,
    ];

    let good = InclusiveMulticastEthernetTagRoute::new(
        RouteDistinguisher::Ipv4Administrator {
            ip: Ipv4Addr::new(172, 16, 0, 200),
            number: 4,
        },
        EthernetTag(0),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 200)),
    );
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ethernet_segment_route() -> Result<(), EthernetSegmentRouteWritingError> {
    let good_wire = [
        0x00, 0x01, 0x78, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x05, 0x20, 0x78, 0x00, 0x02, 0x05,
    ];

    let good = EthernetSegmentRoute::new(
        RouteDistinguisher::Ipv4Administrator {
            ip: Ipv4Addr::new(120, 0, 2, 5),
            number: 0,
        },
        EthernetSegmentIdentifier([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05]),
        IpAddr::V4(Ipv4Addr::new(120, 0, 2, 5)),
    );
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_l2_evpn_route() -> Result<(), L2EvpnRouteWritingError> {
    let good_ad_wire = [
        0x01, 0x19, 0x00, 0x01, 0x78, 0x00, 0x02, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x49, 0x35, 0x01,
    ];

    let good_ip_prefix_wire = [
        0x05, 0x22, 0x00, 0x01, 0x0a, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x0a, 0x00, 0x0a, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
    ];

    let good_ad = L2EvpnRoute::EthernetAutoDiscovery(EthernetAutoDiscovery::new(
        RouteDistinguisher::Ipv4Administrator {
            ip: Ipv4Addr::new(120, 0, 2, 1),
            number: 100,
        },
        EthernetSegmentIdentifier([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05]),
        EthernetTag(0),
        MplsLabel::new([0x49, 0x35, 0x01]),
    ));

    let good_ip_prefix =
        L2EvpnRoute::IpPrefixRoute(L2EvpnIpPrefixRoute::V4(L2EvpnIpv4PrefixRoute::new(
            RouteDistinguisher::Ipv4Administrator {
                ip: Ipv4Addr::new(10, 0, 10, 1),
                number: 2,
            },
            EthernetSegmentIdentifier([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            EthernetTag(0),
            Ipv4Net::from_str("10.0.10.0/24").unwrap(),
            Ipv4Addr::from(0),
            MplsLabel::new([0, 0, 100]),
        )));
    test_parsed_completely(&good_ad_wire, &good_ad);
    test_parsed_completely(&good_ip_prefix_wire, &good_ip_prefix);
    test_write(&good_ad, &good_ad_wire)?;
    test_write(&good_ip_prefix, &good_ip_prefix_wire)?;
    Ok(())
}

#[test]
fn test_route_target_membership() -> Result<(), RouteTargetMembershipWritingError> {
    let good_wire = [
        0x00, 0x00, 0xfd, 0xc9, 0x00, 0x02, 0xfd, 0xc9, 0x00, 0x00, 0x0f, 0xb2,
    ];
    let good =
        RouteTargetMembership::new(64969, vec![0x00, 0x02, 0xfd, 0xc9, 0x00, 0x00, 0x0f, 0xb2]);
    test_parsed_completely_with_one_input(&good_wire, 96, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_route_target_membership_address() -> Result<(), RouteTargetMembershipAddressWritingError> {
    let good_wire = [
        0x60, 0x00, 0x00, 0xfd, 0xc9, 0x00, 0x02, 0xfd, 0xc9, 0x00, 0x00, 0x0f, 0xb2,
    ];

    let good_short_wire = [
        0x58, 0x00, 0x00, 0xfd, 0xc9, 0x00, 0x02, 0xfd, 0xc9, 0x00, 0x00, 0x0f,
    ];
    let good = RouteTargetMembershipAddress::new(
        None,
        Some(RouteTargetMembership::new(
            64969,
            vec![0x00, 0x02, 0xfd, 0xc9, 0x00, 0x00, 0x0f, 0xb2],
        )),
    );
    let good_short = RouteTargetMembershipAddress::new(
        None,
        Some(RouteTargetMembership::new(
            64969,
            vec![0x00, 0x02, 0xfd, 0xc9, 0x00, 0x00, 0x0f],
        )),
    );
    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_short_wire, false, &good_short);
    test_write(&good, &good_wire)?;
    test_write(&good_short, &good_short_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_nlri_mpls_labels_address() -> Result<(), Ipv4NlriMplsLabelsAddressWritingError> {
    let good_wire = [0x37, 0x10, 0x03, 0x31, 0xcb, 0x00, 0x71, 0xfe];
    let good = Ipv4NlriMplsLabelsAddress::from(
        None,
        vec![MplsLabel::new([16, 3, 49])],
        Ipv4Net::from_str("203.0.113.254/31").unwrap(),
    )
    .unwrap();
    test_parsed_completely_with_three_inputs(&good_wire, false, false, 1, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
