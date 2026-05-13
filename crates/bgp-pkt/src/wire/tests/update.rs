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

use crate::nlri::{InvalidIpv4UnicastNetwork, Ipv4Unicast, Ipv4UnicastAddress};
use crate::path_attribute::{
    As4PathSegment, AsPath, AsPathSegmentType, MpReach, NextHop, Origin, PathAttribute,
    PathAttributeValue,
};
use crate::wire::deserializer::nlri::{
    Ipv4UnicastAddressParsingError, Ipv4UnicastParsingError, LocatedIpv4UnicastAddressParsingError,
};
use crate::wire::deserializer::update::BgpUpdateMessageParsingError;
use crate::wire::deserializer::{
    BgpMessageParsingError, BgpParsingContext, Ipv4PrefixParsingError,
    LocatedBgpMessageParsingError,
};
use crate::wire::serializer::BgpMessageWritingError;
use crate::wire::serializer::nlri::Ipv4UnicastAddressWritingError;
use crate::{BgpMessage, BgpUpdateMessage};
use ipnet::Ipv4Net;
use netgauze_parse_utils::test_helpers::{
    test_parse_error_with_one_input, test_parsed_completely, test_parsed_completely_with_one_input,
    test_write,
};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};
use nom::error::ErrorKind;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[test]
fn test_withdraw_route() -> Result<(), Ipv4UnicastAddressWritingError> {
    let good_wire = [0x18, 0xac, 0x10, 0x01];
    let bad_overflow_wire = [0xff, 0xac, 0x10, 0x01];
    let bad_prefix_wire = [0x21, 0xac, 0x10, 0xff, 0xff, 0xff];

    let good = Ipv4UnicastAddress::new_no_path_id(
        Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.1.0/24").unwrap()).unwrap(),
    );
    let bad_overflow = LocatedIpv4UnicastAddressParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_overflow_wire[1..]) },
        Ipv4UnicastAddressParsingError::Ipv4UnicastError(Ipv4UnicastParsingError::Ipv4PrefixError(
            Ipv4PrefixParsingError::NomError(ErrorKind::Eof),
        )),
    );
    let bad_prefix = LocatedIpv4UnicastAddressParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_prefix_wire) },
        Ipv4UnicastAddressParsingError::Ipv4UnicastError(Ipv4UnicastParsingError::Ipv4PrefixError(
            Ipv4PrefixParsingError::InvalidIpv4PrefixLen(33),
        )),
    );
    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<
        Ipv4UnicastAddress,
        bool,
        LocatedIpv4UnicastAddressParsingError<'_>,
    >(&bad_overflow_wire, false, &bad_overflow);
    test_parse_error_with_one_input::<
        Ipv4UnicastAddress,
        bool,
        LocatedIpv4UnicastAddressParsingError<'_>,
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

    test_parsed_completely(&octet_boundary_wire, &octet_boundary);
    test_parsed_completely(&not_octet_boundary_wire, &not_octet_boundary);
    test_parsed_completely(&not_octet_boundary2_wire, &not_octet_boundary2);

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
    test_parsed_completely_with_one_input(
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

    test_parsed_completely_with_one_input(
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
                PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![As4PathSegment::new(
                    AsPathSegmentType::AsSequence,
                    vec![200, 100],
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
                PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![As4PathSegment::new(
                    AsPathSegmentType::AsSequence,
                    vec![200, 100],
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
    let invalid_nlri_address = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(21, &bad_multicast_nlri_wire[21..21 + 8]) },
        BgpMessageParsingError::BgpUpdateMessageParsingError(
            BgpUpdateMessageParsingError::InvalidIpv4UnicastNetwork(InvalidIpv4UnicastNetwork(
                Ipv4Net::from_str("224.1.1.0/24").unwrap(),
            )),
        ),
    );

    test_parsed_completely_with_one_input(
        &good_update_wire,
        &mut BgpParsingContext::default(),
        &good_update,
    );

    test_write(&good_update, &good_update_wire)?;

    test_parse_error_with_one_input::<
        BgpMessage,
        &mut BgpParsingContext,
        LocatedBgpMessageParsingError<'_>,
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

    test_parsed_completely_with_one_input(
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

    let bad_withdraw_length_short = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(26, &bad_withdraw_length_short_wire[26..26 + 2]) },
        BgpMessageParsingError::BgpUpdateMessageParsingError(
            BgpUpdateMessageParsingError::Ipv4PrefixError(Ipv4PrefixParsingError::NomError(
                ErrorKind::Eof,
            )),
        ),
    );

    test_parse_error_with_one_input::<
        BgpMessage,
        &mut BgpParsingContext,
        LocatedBgpMessageParsingError<'_>,
    >(
        &bad_withdraw_length_short_wire,
        &mut BgpParsingContext::default(),
        &bad_withdraw_length_short,
    );
    Ok(())
}

#[test]
fn test_bgp_ls_attribute_does_not_swallow_subsequent_attributes() {
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

    let mut ctx = BgpParsingContext::default();
    let (_, msg) = BgpMessage::from_wire(Span::new(junos_bgp_ls_update), &mut ctx)
        .expect("JunOS-captured BGP-LS UPDATE should parse");
    let BgpMessage::Update(upd) = msg else {
        panic!("expected UPDATE, got {msg:?}")
    };

    let mp_reach_present = upd.path_attributes().iter().any(|pa| {
        matches!(
            pa.value(),
            PathAttributeValue::MpReach(MpReach::BgpLs { .. })
        )
    });

    assert!(
        mp_reach_present,
        "MP_REACH(BgpLs) was silently dropped after BGP_LS_ATTRIBUTE — \
         BgpLsAttribute::from_wire is returning the inner span instead of the outer remainder. \
         Parsed attributes: {:?}",
        upd.path_attributes()
            .iter()
            .map(|pa| pa.value())
            .collect::<Vec<_>>(),
    );
}
