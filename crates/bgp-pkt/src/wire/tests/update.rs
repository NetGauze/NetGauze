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

use crate::nlri::{
    BgpLsLocalNodeDescriptors, BgpLsNlri, BgpLsNlriNode, BgpLsNlriValue, BgpLsNodeDescriptorSubTlv,
    BgpLsNodeDescriptors, Ipv4Unicast, Ipv4UnicastAddress,
};
use crate::path_attribute::{
    As4PathSegment, AsPath, AsPathSegmentType, BgpLsAttribute, BgpLsAttributeValue,
    LocalPreference, MpReach, NextHop, Origin, PathAttribute, PathAttributeValue,
};
use crate::wire::deserializer::nlri::{Ipv4UnicastAddressParsingError, Ipv4UnicastParsingError};
use crate::wire::deserializer::update::BgpUpdateMessageParsingError;
use crate::wire::deserializer::{BgpMessageParsingError, BgpParsingContext};
use crate::wire::serializer::BgpMessageWritingError;
use crate::wire::serializer::nlri::Ipv4UnicastAddressWritingError;
use crate::{BgpMessage, BgpUpdateMessage};
use ipnet::Ipv4Net;

use crate::iana::BgpLsProtocolId;
use netgauze_parse_utils::common::Ipv4PrefixParsingError;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::test_helpers::{
    test_parse_error_with_one_input_bytes_reader, test_parsed_completely_bytes_reader,
    test_parsed_completely_with_one_input_bytes_reader, test_write,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[test]
fn test_withdraw_route() -> Result<(), Ipv4UnicastAddressWritingError> {
    let good_wire = [0x18, 0xac, 0x10, 0x01];
    let bad_overflow_wire = [0xff, 0xac, 0x10, 0x01];
    let bad_prefix_wire = [0x21, 0xac, 0x10, 0xff, 0xff, 0xff];

    let good = Ipv4UnicastAddress::new_no_path_id(
        Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.1.0/24").unwrap()).unwrap(),
    );
    let bad_overflow =
        Ipv4UnicastAddressParsingError::Ipv4UnicastError(Ipv4UnicastParsingError::Ipv4PrefixError(
            Ipv4PrefixParsingError::Parse(ParseError::UnexpectedEof {
                offset: 1,
                needed: 4,
                available: 3,
            }),
        ));
    let bad_prefix = Ipv4UnicastAddressParsingError::Ipv4UnicastError(
        Ipv4UnicastParsingError::Ipv4PrefixError(Ipv4PrefixParsingError::InvalidIpv4PrefixLen {
            offset: 0,
            prefix_len: 33,
        }),
    );

    test_parsed_completely_with_one_input_bytes_reader(&good_wire, false, &good);
    test_parse_error_with_one_input_bytes_reader::<
        Ipv4UnicastAddress,
        bool,
        Ipv4UnicastAddressParsingError,
    >(&bad_overflow_wire, false, &bad_overflow);
    test_parse_error_with_one_input_bytes_reader::<
        Ipv4UnicastAddress,
        bool,
        Ipv4UnicastAddressParsingError,
    >(&bad_prefix_wire, false, &bad_prefix);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_ipv4_nlri() -> Result<(), Ipv4UnicastAddressWritingError> {
    let octet_boundary_wire = [0x18, 0xac, 0x10, 0x0b];
    let not_octet_boundary_wire = [0x13, 0xac, 0x10, 0x00];
    let not_octet_boundary2_wire = [23, 192, 168, 128];

    let octet_boundary =
        Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.11.0/24").unwrap()).unwrap();
    let not_octet_boundary =
        Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.0.0/19").unwrap()).unwrap();
    let not_octet_boundary2 =
        Ipv4Unicast::from_net(Ipv4Net::from_str("192.168.128.0/23").unwrap()).unwrap();

    test_parsed_completely_bytes_reader(&octet_boundary_wire, &octet_boundary);
    test_parsed_completely_bytes_reader(&not_octet_boundary_wire, &not_octet_boundary);
    test_parsed_completely_bytes_reader(&not_octet_boundary2_wire, &not_octet_boundary2);

    test_write(&octet_boundary, &octet_boundary_wire)?;
    test_write(&not_octet_boundary, &not_octet_boundary_wire)?;
    test_write(&not_octet_boundary2, &not_octet_boundary2_wire)?;
    Ok(())
}

#[test]
fn test_empty_update() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];
    let good = BgpMessage::Update(BgpUpdateMessage::new(vec![], vec![], vec![]));
    test_parsed_completely_with_one_input_bytes_reader(
        &good_wire,
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_withdraw_update() -> Result<(), BgpMessageWritingError> {
    let good_withdraw_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1b, 0x02, 0x00, 0x04, 0x18, 0xac, 0x10, 0x01, 0x00, 0x00,
    ];
    let good_withdraw = BgpMessage::Update(BgpUpdateMessage::new(
        vec![Ipv4UnicastAddress::new_no_path_id(
            Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 1, 0), 24).unwrap()).unwrap(),
        )],
        vec![],
        vec![],
    ));

    test_parsed_completely_with_one_input_bytes_reader(
        &good_withdraw_wire,
        &mut BgpParsingContext::asn2_default(),
        &good_withdraw,
    );
    test_write(&good_withdraw, &good_withdraw_wire)?;
    Ok(())
}

#[test]
fn test_update_non_unicast_nlri() -> Result<(), BgpMessageWritingError> {
    let good_update_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x40, 0x02, 0x00, 0x08, 0x18, 0xac, 0x10, 0x03, 0x18, 0xac, 0x10, 0x04, 0x00,
        0x19, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0xc8,
        0x00, 0x00, 0x00, 0x64, 0x40, 0x03, 0x04, 0xac, 0x10, 0x00, 0x14, 0x18, 0xac, 0x10, 0x01,
        0x18, 0xac, 0x10, 0x02,
    ];

    let bad_multicast_nlri_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x40, 0x02, 0x00, 0x08, 0x18, 0xe0, 0x01, 0x01, 0x18, 0xac, 0x10, 0x04, 0x00,
        0x19, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0xc8,
        0x00, 0x00, 0x00, 0x64, 0x40, 0x03, 0x04, 0xac, 0x10, 0x00, 0x14, 0x18, 0xe0, 0x10, 0x01,
        0x18, 0xac, 0x10, 0x02,
    ];
    let good_update = BgpMessage::Update(BgpUpdateMessage::new(
        vec![
            Ipv4UnicastAddress::new_no_path_id(
                Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 3, 0), 24).unwrap())
                    .unwrap(),
            ),
            Ipv4UnicastAddress::new_no_path_id(
                Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 4, 0), 24).unwrap())
                    .unwrap(),
            ),
        ],
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
                PathAttributeValue::AsPath(AsPath::as4_path_segments([As4PathSegment::new(
                    AsPathSegmentType::AsSequence,
                    [200, 100],
                )])),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::NextHop(NextHop::new(Ipv4Addr::new(172, 16, 0, 20))),
            )
            .unwrap(),
        ],
        vec![
            Ipv4UnicastAddress::new_no_path_id(
                Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 1, 0), 24).unwrap())
                    .unwrap(),
            ),
            Ipv4UnicastAddress::new_no_path_id(
                Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 2, 0), 24).unwrap())
                    .unwrap(),
            ),
        ],
    ));

    let good_update_without_multicast = BgpMessage::Update(BgpUpdateMessage::new(
        vec![Ipv4UnicastAddress::new_no_path_id(
            Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 4, 0), 24).unwrap()).unwrap(),
        )],
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
                PathAttributeValue::AsPath(AsPath::as4_path_segments([As4PathSegment::new(
                    AsPathSegmentType::AsSequence,
                    [200, 100],
                )])),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::NextHop(NextHop::new(Ipv4Addr::new(172, 16, 0, 20))),
            )
            .unwrap(),
        ],
        vec![Ipv4UnicastAddress::new_no_path_id(
            Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 2, 0), 24).unwrap()).unwrap(),
        )],
    ));
    let invalid_nlri_address = BgpMessageParsingError::BgpUpdateMessageParsingError(
        BgpUpdateMessageParsingError::InvalidIpv4UnicastNetwork {
            offset: 21,
            network: Ipv4Net::from_str("224.1.1.0/24").unwrap(),
        },
    );

    test_parsed_completely_with_one_input_bytes_reader(
        &good_update_wire,
        &mut BgpParsingContext::default(),
        &good_update,
    );

    test_write(&good_update, &good_update_wire)?;

    test_parse_error_with_one_input_bytes_reader::<
        BgpMessage,
        &mut BgpParsingContext,
        BgpMessageParsingError,
    >(
        &bad_multicast_nlri_wire,
        &mut BgpParsingContext::new(
            true,
            HashMap::new(),
            HashMap::new(),
            true,
            false,
            false,
            false,
        ),
        &invalid_nlri_address,
    );

    test_parsed_completely_with_one_input_bytes_reader(
        &bad_multicast_nlri_wire,
        &mut BgpParsingContext::new(
            true,
            HashMap::new(),
            HashMap::new(),
            false,
            false,
            false,
            false,
        ),
        &good_update_without_multicast,
    );
    Ok(())
}

#[test]
fn test_update_bad_length() -> Result<(), BgpMessageWritingError> {
    let bad_withdraw_length_short_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x40, 0x02, 0x00, 0x07, 0x18, 0xac, 0x10, 0x03, 0x18, 0xac, 0x10, 0x04, 0x00,
        0x19, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0xc8,
        0x00, 0x00, 0x00, 0x64, 0x40, 0x03, 0x04, 0xac, 0x10, 0x00, 0x14, 0x18, 0xac, 0x10, 0x01,
        0x18, 0xac, 0x10, 0x02,
    ];

    let bad_withdraw_length_short = BgpMessageParsingError::BgpUpdateMessageParsingError(
        BgpUpdateMessageParsingError::Ipv4PrefixError(Ipv4PrefixParsingError::Parse(
            ParseError::UnexpectedEof {
                offset: 26,
                needed: 3,
                available: 2,
            },
        )),
    );

    test_parse_error_with_one_input_bytes_reader::<
        BgpMessage,
        &mut BgpParsingContext,
        BgpMessageParsingError,
    >(
        &bad_withdraw_length_short_wire,
        &mut BgpParsingContext::default(),
        &bad_withdraw_length_short,
    );
    Ok(())
}

/// MP_REACH(BgpLs) was silently dropped after BGP_LS_ATTRIBUTE
/// See https://github.com/NetGauze/NetGauze/pull/518
#[test]
fn test_bgp_ls_attribute_does_not_swallow_subsequent_attributes()
-> Result<(), BgpMessageWritingError> {
    let junos_bgp_ls_update: &[u8] = &[
        // BGP header
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, //
        0x00, 0xdf, // length = 223
        0x02, // type = UPDATE
        // Withdrawn routes length
        0x00, 0x00, //
        // Total path attribute length = 200
        0x00, 0xc8, //
        // PA: Origin (IGP)
        0x40, 0x01, 0x01, 0x00, //
        // PA: AS_PATH (empty as4)
        0x40, 0x02, 0x00, //
        // PA: LOCAL_PREF = 100
        0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, //
        // PA: BGP_LS_ATTRIBUTE (TLV 29), extended-length=5, NodeFlagBits TLV 1024
        0x90, 0x1d, 0x00, 0x05, 0x04, 0x00, 0x00, 0x01, 0x00, //
        // PA: MP_REACH_NLRI (TLV 14), extended-length, length 173
        0x90, 0x0e, 0x00, 0xad, //
        //   AFI=16388 (BGP-LS), SAFI=71, NextHopLen=4, NextHop=100.100.100.1, Reserved
        0x40, 0x04, 0x47, 0x04, 0x64, 0x64, 0x64, 0x01, 0x00, //
        //   NLRI #1: Node NLRI for 100.100.100.1
        0x00, 0x01, 0x00, 0x25, //
        0x03, // ProtocolID OSPFv2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Identifier
        0x01, 0x00, 0x00, 0x18, // Local Node Descriptors TLV
        0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, // AS = 65000
        0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // Area = 0
        0x02, 0x03, 0x00, 0x04, 0x64, 0x64, 0x64, 0x01, // IGP Router-ID = 100.100.100.1
        //   NLRIs #2-#4: same shape with router-ids 100.100.100.2/3/255
        0x00, 0x01, 0x00, 0x25, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, 0x02, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x04, 0x64, 0x64, 0x64, 0x02, //
        0x00, 0x01, 0x00, 0x25, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, 0x02, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x04, 0x64, 0x64, 0x64, 0x03, //
        0x00, 0x01, 0x00, 0x25, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, 0x02, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x04, 0x64, 0x64, 0x64, 0xff, //
    ];

    let expected_update = BgpMessage::Update(BgpUpdateMessage::new(
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
                false,
                PathAttributeValue::AsPath(AsPath::as4_path_segments([])),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::LocalPreference(LocalPreference::new(100)),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                true,
                PathAttributeValue::BgpLs(BgpLsAttribute::new(vec![
                    BgpLsAttributeValue::NodeFlagBits {
                        overload: false,
                        attached: false,
                        external: false,
                        abr: false,
                        router: false,
                        v6: false,
                    },
                ])),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                true,
                PathAttributeValue::MpReach(MpReach::BgpLs {
                    next_hop: IpAddr::from_str("100.100.100.1").unwrap(),
                    nlri: Box::new([
                        BgpLsNlri::new(
                            None,
                            BgpLsNlriValue::Node(BgpLsNlriNode::new(
                                BgpLsProtocolId::OspfV2,
                                0,
                                BgpLsLocalNodeDescriptors::new(BgpLsNodeDescriptors::new(vec![
                                    BgpLsNodeDescriptorSubTlv::AutonomousSystem(65000),
                                    BgpLsNodeDescriptorSubTlv::OspfAreaId(0),
                                    BgpLsNodeDescriptorSubTlv::IgpRouterId(vec![100, 100, 100, 1]),
                                ])),
                            )),
                        ),
                        BgpLsNlri::new(
                            None,
                            BgpLsNlriValue::Node(BgpLsNlriNode::new(
                                BgpLsProtocolId::OspfV2,
                                0,
                                BgpLsLocalNodeDescriptors::new(BgpLsNodeDescriptors::new(vec![
                                    BgpLsNodeDescriptorSubTlv::AutonomousSystem(65000),
                                    BgpLsNodeDescriptorSubTlv::OspfAreaId(0),
                                    BgpLsNodeDescriptorSubTlv::IgpRouterId(vec![100, 100, 100, 2]),
                                ])),
                            )),
                        ),
                        BgpLsNlri::new(
                            None,
                            BgpLsNlriValue::Node(BgpLsNlriNode::new(
                                BgpLsProtocolId::OspfV2,
                                0,
                                BgpLsLocalNodeDescriptors::new(BgpLsNodeDescriptors::new(vec![
                                    BgpLsNodeDescriptorSubTlv::AutonomousSystem(65000),
                                    BgpLsNodeDescriptorSubTlv::OspfAreaId(0),
                                    BgpLsNodeDescriptorSubTlv::IgpRouterId(vec![100, 100, 100, 3]),
                                ])),
                            )),
                        ),
                        BgpLsNlri::new(
                            None,
                            BgpLsNlriValue::Node(BgpLsNlriNode::new(
                                BgpLsProtocolId::OspfV2,
                                0,
                                BgpLsLocalNodeDescriptors::new(BgpLsNodeDescriptors::new(vec![
                                    BgpLsNodeDescriptorSubTlv::AutonomousSystem(65000),
                                    BgpLsNodeDescriptorSubTlv::OspfAreaId(0),
                                    BgpLsNodeDescriptorSubTlv::IgpRouterId(vec![
                                        100, 100, 100, 255,
                                    ]),
                                ])),
                            )),
                        ),
                    ]),
                }),
            )
            .unwrap(),
        ],
        vec![],
    ));

    let mut ctx = BgpParsingContext::default();

    test_parsed_completely_with_one_input_bytes_reader(
        junos_bgp_ls_update,
        &mut ctx,
        &expected_update,
    );
    test_write(&expected_update, junos_bgp_ls_update)?;
    Ok(())
}
