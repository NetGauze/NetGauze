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
    bgp_ls::{
        BgpLsAttribute, BgpLsAttributeTlv, BgpLsLinkDescriptorTlv, BgpLsNlri, BgpLsNlriIpPrefix,
        BgpLsNlriLink, BgpLsNlriNode, BgpLsNlriValue, BgpLsNodeDescriptorSubTlv,
        BgpLsNodeDescriptorTlv, BgpLsPeerSid, BgpLsPrefixDescriptorTlv, BgpLsVpnNlri,
        IpReachabilityInformationData, MultiTopologyId, MultiTopologyIdData, OspfRouteType,
    },
    iana::{BgpLsProtocolId, BgpLsSidAttributeFlags},
    path_attribute::{MpReach, MpUnreach, PathAttribute, PathAttributeValue},
};
use netgauze_parse_utils::test_helpers::{test_parsed_completely_with_one_input, test_write};
use std::{collections::HashMap, io::BufWriter};

use crate::{
    nlri::MplsLabel,
    wire::{
        deserializer::BgpParsingContext, serializer::path_attribute::PathAttributeWritingError,
    },
};
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{
    ReadablePduWithOneInput, ReadablePduWithThreeInputs, Span, WritablePduWithOneInput,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::nlri::{LabeledIpv4NextHop, LabeledNextHop, RouteDistinguisher};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netgauze_parse_utils::WritablePdu;

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
                        local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
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
                        local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
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
pub fn test_bgp_ls_attr_parse() {
    let value = BgpLsAttribute {
        tlvs: vec![BgpLsAttributeTlv::LinkName("My Super Link".to_string())],
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsAttribute::from_wire(span, false).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_nlri_parse() {
    let value = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Link(BgpLsNlriLink {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            remote_node_descriptors: BgpLsNodeDescriptorTlv::Remote(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(21),
            ]),
            link_descriptor_tlvs: vec![BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(
                Ipv4Addr::new(1, 2, 3, 4),
            )],
        }),
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsNlri::from_wire(span, false).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_nlri_ipv4_parse() {
    let value = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Ipv4Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V4(Ipv4Net::new(Ipv4Addr::new(1, 2, 3, 4), 32).unwrap()),
                )),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsNlri::from_wire(span, false).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_nlri_ipv6_parse() {
    let value = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsNlri::from_wire(span, false).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_mp_reach() {
    let ls_nlri = BgpLsNlri {
        path_id: None,
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let value = MpReach::BgpLs {
        next_hop: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        nlri: vec![ls_nlri.clone(), ls_nlri.clone(), ls_nlri],
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);
    println!("written {:?} {:#?}", buf, buf.len());

    let span = Span::new(&buf);
    let result =
        MpReach::from_wire(span, false, &HashMap::new(), &HashMap::new()).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_vpn_mp_reach() {
    let ls_nlri = BgpLsVpnNlri {
        path_id: None,
        rd: RouteDistinguisher::As4Administrator {
            asn4: 1010,
            number: 2020,
        },
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let value = MpReach::BgpLsVpn {
        next_hop: LabeledNextHop::Ipv4(LabeledIpv4NextHop::new(
            RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
            Ipv4Addr::new(1, 2, 3, 4),
        )),
        nlri: vec![ls_nlri.clone(), ls_nlri.clone(), ls_nlri],
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);
    println!("written {:?}", buf);

    let span = Span::new(&buf);
    let result =
        MpReach::from_wire(span, false, &HashMap::new(), &HashMap::new()).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_vpn_mp_unreach() {
    let ls_nlri = BgpLsVpnNlri {
        path_id: Some(18),
        rd: RouteDistinguisher::As4Administrator {
            asn4: 1010,
            number: 2020,
        },
        value: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18),
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(
                    IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()),
                )),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        }),
    };

    let value = MpUnreach::BgpLsVpn {
        nlri: vec![ls_nlri.clone(), ls_nlri.clone(), ls_nlri],
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);
    println!("written {:?}", buf);

    let span = Span::new(&buf);
    let mut add_path_map = HashMap::new();
    add_path_map.insert(AddressType::BgpLsVpn, true);
    let result =
        MpUnreach::from_wire(span, false, &HashMap::new(), &add_path_map).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_sid() {
    let value = BgpLsAttribute {
        tlvs: vec![
            BgpLsAttributeTlv::PeerNodeSid(BgpLsPeerSid::new_index_value(
                BgpLsSidAttributeFlags::BackupFlag as u8,
                69,
                32,
            )),
            BgpLsAttributeTlv::PeerAdjSid(BgpLsPeerSid::new_index_value(
                BgpLsSidAttributeFlags::BackupFlag as u8,
                169,
                64,
            )),
            BgpLsAttributeTlv::PeerSetSid(BgpLsPeerSid::new_label_value(
                BgpLsSidAttributeFlags::BackupFlag as u8,
                69,
                MplsLabel::new([1, 2, 3]),
            )),
        ],
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);
    println!("written {:?}", buf);

    let span = Span::new(&buf);
    let result = BgpLsAttribute::from_wire(span, false).expect("I CAN READ");

    assert_eq!(result.1, value)
}
