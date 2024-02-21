// Copyright (C) 2023-present The NetGauze Authors.
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
    iana::{BgpLsProtocolId, BgpLsSidAttributeFlags},
    nlri::{
        BgpLsLinkDescriptor, BgpLsNlri, BgpLsNlriIpPrefix, BgpLsNlriLink, BgpLsNlriNode,
        BgpLsNlriValue, BgpLsNodeDescriptorSubTlv, BgpLsNodeDescriptor,
        BgpLsPrefixDescriptor, BgpLsVpnNlri, IpReachabilityInformationData, MultiTopologyId,
        MultiTopologyIdData, OspfRouteType,
    },
    path_attribute::{
        BgpLsAttribute, BgpLsAttributeValue, BgpLsPeerSid, MpReach, MpUnreach, PathAttribute,
        PathAttributeValue,
    },
};
use netgauze_parse_utils::test_helpers::{
    test_parsed_completely_with_one_input, test_parsed_completely_with_three_inputs, test_write,
    test_write_with_one_input,
};
use std::collections::HashMap;

use crate::{
    nlri::MplsLabel,
    wire::{
        deserializer::BgpParsingContext, serializer::path_attribute::PathAttributeWritingError,
    },
};
use netgauze_iana::address_family::AddressType;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    nlri::{LabeledIpv4NextHop, LabeledNextHop, RouteDistinguisher},
    wire::serializer::{
        bgp_ls::BgpLsWritingError,
        path_attribute::{MpReachWritingError, MpUnreachWritingError},
    },
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[test]
fn test_wire() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x6d, 0x40, 0x04, 0x47, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x28, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x02, 0x00, 0x00,
        0x04, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
        0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x01, 0x00, 0x01, 0x00, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x02, 0x00, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
    ];

    let good = PathAttribute::from(
        true,
        false,
        false,
        true,
        PathAttributeValue::MpReach(MpReach::BgpLs {
            next_hop: IpAddr::V6(Ipv6Addr::from_str("2001:db8:1::1").unwrap()),
            nlri: vec![
                BgpLsNlri {
                    path_id: None,
                    value: BgpLsNlriValue::Node(BgpLsNlriNode {
                        protocol_id: BgpLsProtocolId::IsIsLevel1,
                        identifier: 0,
                        local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                            BgpLsNodeDescriptorSubTlv::AutonomousSystem(65536),
                            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(0),
                            BgpLsNodeDescriptorSubTlv::IgpRouterId(vec![0, 0, 0, 0, 0, 9, 1]),
                        ]),
                    }),
                },
                BgpLsNlri {
                    path_id: None,
                    value: BgpLsNlriValue::Node(BgpLsNlriNode {
                        protocol_id: BgpLsProtocolId::IsIsLevel1,
                        identifier: 0,
                        local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                            BgpLsNodeDescriptorSubTlv::AutonomousSystem(65536),
                            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(0),
                            BgpLsNodeDescriptorSubTlv::IgpRouterId(vec![0, 0, 0, 0, 0, 1, 3]),
                        ]),
                    }),
                },
            ],
        }),
    )
    .unwrap();

    test_parsed_completely_with_one_input(
        &good_wire,
        &mut BgpParsingContext::new(
            true,
            HashMap::new(),
            HashMap::new(),
            false,
            false,
            false,
            false,
        ),
        &good,
    );
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_attr_parse() -> Result<(), BgpLsWritingError> {
    let good_wire = [
        17, 4, 74, 0, 13, 77, 121, 32, 83, 117, 112, 101, 114, 32, 76, 105, 110, 107,
    ];

    let good = BgpLsAttribute {
        attributes: vec![BgpLsAttributeValue::LinkName("My Super Link".to_string())],
    };

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write_with_one_input(&good, false, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_nlri_parse() -> Result<(), BgpLsWritingError> {
    let good_wire = [
        0, 2, 0, 41, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 1, 0, 8,
        2, 2, 0, 4, 0, 0, 0, 21, 1, 3, 0, 4, 1, 2, 3, 4,
    ];
    let good = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Link(BgpLsNlriLink {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            remote_node_descriptors: BgpLsNodeDescriptor::Remote(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(21),
            ]),
            link_descriptors: vec![BgpLsLinkDescriptor::IPv4InterfaceAddress(
                Ipv4Addr::new(1, 2, 3, 4),
            )],
        }),
    };

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_nlri_ipv4_parse() -> Result<(), BgpLsWritingError> {
    let good_wire = [
        0, 3, 0, 43, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 5,
        32, 1, 2, 3, 4, 1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4,
    ];

    let good = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Ipv4Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptors: vec![
                BgpLsPrefixDescriptor::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V4(Ipv4Net::new(Ipv4Addr::new(1, 2, 3, 4), 32).unwrap()),
                )),
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptor::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_nlri_ipv6_parse() -> Result<(), BgpLsWritingError> {
    let good_wire = [
        0, 4, 0, 55, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17,
        128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1,
        4,
    ];

    let good = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptors: vec![
                BgpLsPrefixDescriptor::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptor::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_mp_reach() -> Result<(), MpReachWritingError> {
    let good_wire = [
        186, 64, 4, 71, 4, 1, 2, 3, 4, 0, 0, 4, 0, 55, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8, 2,
        2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 1,
        7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4, 0, 4, 0, 55, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8,
        2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8,
        1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4, 0, 4, 0, 55, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0,
        8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0,
        8, 1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4,
    ];

    let ls_nlri = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptors: vec![
                BgpLsPrefixDescriptor::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptor::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let good = MpReach::BgpLs {
        next_hop: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        nlri: vec![ls_nlri.clone(), ls_nlri.clone(), ls_nlri],
    };

    test_parsed_completely_with_three_inputs(
        &good_wire,
        false,
        &HashMap::new(),
        &HashMap::new(),
        &good,
    );
    test_write_with_one_input(&good, false, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_vpn_mp_reach() -> Result<(), MpReachWritingError> {
    let good_wire = [
        218, 64, 4, 72, 12, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 4, 0, 63, 0, 2, 0, 0, 3, 242,
        7, 228, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17, 128,
        0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4, 0,
        4, 0, 63, 0, 2, 0, 0, 3, 242, 7, 228, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8, 2, 2, 0, 4,
        0, 0, 0, 18, 1, 9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 1, 7, 0, 4,
        0, 69, 0, 21, 1, 8, 0, 1, 4, 0, 4, 0, 63, 0, 2, 0, 0, 3, 242, 7, 228, 1, 0, 0, 0, 0, 0, 0,
        0, 69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5,
        0, 6, 0, 7, 0, 8, 1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4,
    ];

    let ls_nlri = BgpLsVpnNlri {
        path_id: None,
        rd: RouteDistinguisher::As4Administrator {
            asn4: 1010,
            number: 2020,
        },
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptors: vec![
                BgpLsPrefixDescriptor::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptor::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let good = MpReach::BgpLsVpn {
        next_hop: LabeledNextHop::Ipv4(LabeledIpv4NextHop::new(
            RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
            Ipv4Addr::new(1, 2, 3, 4),
        )),
        nlri: vec![ls_nlri.clone(), ls_nlri.clone(), ls_nlri],
    };

    test_parsed_completely_with_three_inputs(
        &good_wire,
        false,
        &HashMap::new(),
        &HashMap::new(),
        &good,
    );
    test_write_with_one_input(&good, false, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_vpn_mp_unreach() -> Result<(), MpUnreachWritingError> {
    let good_wire = [
        216, 64, 4, 72, 0, 0, 0, 18, 0, 4, 0, 63, 0, 2, 0, 0, 3, 242, 7, 228, 1, 0, 0, 0, 0, 0, 0,
        0, 69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5,
        0, 6, 0, 7, 0, 8, 1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4, 0, 0, 0, 18, 0, 4, 0, 63, 0, 2,
        0, 0, 3, 242, 7, 228, 1, 0, 0, 0, 0, 0, 0, 0, 69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1,
        9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 1, 7, 0, 4, 0, 69, 0, 21, 1,
        8, 0, 1, 4, 0, 0, 0, 18, 0, 4, 0, 63, 0, 2, 0, 0, 3, 242, 7, 228, 1, 0, 0, 0, 0, 0, 0, 0,
        69, 1, 0, 0, 8, 2, 2, 0, 4, 0, 0, 0, 18, 1, 9, 0, 17, 128, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0,
        6, 0, 7, 0, 8, 1, 7, 0, 4, 0, 69, 0, 21, 1, 8, 0, 1, 4,
    ];

    let ls_nlri = BgpLsVpnNlri {
        path_id: Some(18),
        rd: RouteDistinguisher::As4Administrator {
            asn4: 1010,
            number: 2020,
        },
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptor::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptors: vec![
                BgpLsPrefixDescriptor::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptor::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let good = MpUnreach::BgpLsVpn {
        nlri: vec![ls_nlri.clone(), ls_nlri.clone(), ls_nlri],
    };

    let mut add_path_map = HashMap::new();
    add_path_map.insert(AddressType::BgpLsVpn, true);

    test_parsed_completely_with_three_inputs(
        &good_wire,
        false,
        &HashMap::new(),
        &add_path_map,
        &good,
    );
    test_write_with_one_input(&good, false, &good_wire)?;

    Ok(())
}

#[test]
pub fn test_bgp_ls_sid() -> Result<(), BgpLsWritingError> {
    let good_wire = [
        35, 4, 77, 0, 8, 32, 69, 0, 0, 0, 0, 0, 32, 4, 78, 0, 8, 32, 169, 0, 0, 0, 0, 0, 64, 4, 79,
        0, 7, 160, 69, 0, 0, 1, 2, 3,
    ];

    let good = BgpLsAttribute {
        attributes: vec![
            BgpLsAttributeValue::PeerNodeSid(BgpLsPeerSid::new_index_value(
                BgpLsSidAttributeFlags::BackupFlag as u8,
                69,
                32,
            )),
            BgpLsAttributeValue::PeerAdjSid(BgpLsPeerSid::new_index_value(
                BgpLsSidAttributeFlags::BackupFlag as u8,
                169,
                64,
            )),
            BgpLsAttributeValue::PeerSetSid(BgpLsPeerSid::new_label_value(
                BgpLsSidAttributeFlags::BackupFlag as u8,
                69,
                MplsLabel::new([1, 2, 3]),
            )),
        ],
    };
    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write_with_one_input(&good, false, &good_wire)?;

    Ok(())
}
