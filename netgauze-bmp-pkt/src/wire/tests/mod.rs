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
    iana::{BGPMessageType, UndefinedBgpMessageType},
    notification::{BGPNotificationMessage, CeaseError},
    open::{BGPOpenMessage, BGPOpenMessageParameter},
    path_attribute::{
        ASPath, As4PathSegment, AsPathSegmentType, NextHop, Origin, PathAttribute,
        PathAttributeValue,
    },
    update::{BGPUpdateMessage, NetworkLayerReachabilityInformation},
    wire::deserializer::{nlri::RouteDistinguisherParsingError, BGPMessageParsingError},
    BGPMessage,
};
use netgauze_iana::address_family::{AddressFamily, AddressType};
use netgauze_parse_utils::{
    test_helpers::{test_parse_error, test_parsed_completely, test_write},
    Span,
};
use nom::error::ErrorKind;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    iana::*,
    wire::{deserializer::*, serializer::*},
    *,
};

#[test]
fn test_peer_type() -> Result<(), PeerHeaderWritingError> {
    let good_global_instance_ipv4_wire = [0x00, 0x00];
    let good_global_instance_ipv6_wire = [0x00, 0x80];
    let good_global_instance_post_wire = [0x00, 0x40];
    let good_global_asn2_wire = [0x00, 0x20];
    let good_global_adj_out_wire = [0x00, 0x10];
    let good_rd_instance_all_wire = [0x01, 0xf0];
    let good_local_instance_all_wire = [0x02, 0xf0];
    let good_loc_rib_instance_wire = [0x03, 0x00];
    let good_loc_rib_instance_filtered_wire = [0x03, 0x80];
    let good_experimental_251_wire = [0xfb, 0xff];
    let good_experimental_252_wire = [0xfc, 0xff];
    let good_experimental_253_wire = [0xfd, 0xff];
    let good_experimental_254_wire = [0xfe, 0xff];
    let bad_eof_wire = [0x00];
    let bad_reserved_wire = [0xff, 0xff];

    let good_global_instance_ipv4 = BmpPeerType::GlobalInstancePeer {
        ipv6: false,
        post_policy: false,
        asn2: false,
        adj_rib_out: false,
    };
    let good_global_instance_ipv6 = BmpPeerType::GlobalInstancePeer {
        ipv6: true,
        post_policy: false,
        asn2: false,
        adj_rib_out: false,
    };

    let good_global_instance_post = BmpPeerType::GlobalInstancePeer {
        ipv6: false,
        post_policy: true,
        asn2: false,
        adj_rib_out: false,
    };

    let good_global_asn2 = BmpPeerType::GlobalInstancePeer {
        ipv6: false,
        post_policy: false,
        asn2: true,
        adj_rib_out: false,
    };

    let good_global_adj_out = BmpPeerType::GlobalInstancePeer {
        ipv6: false,
        post_policy: false,
        asn2: false,
        adj_rib_out: true,
    };

    let good_rd_instance_all = BmpPeerType::RdInstancePeer {
        ipv6: true,
        post_policy: true,
        asn2: true,
        adj_rib_out: true,
    };

    let good_local_instance_all = BmpPeerType::LocalInstancePeer {
        ipv6: true,
        post_policy: true,
        asn2: true,
        adj_rib_out: true,
    };

    let good_loc_rib_instance = BmpPeerType::LocRibInstancePeer { filtered: false };
    let good_loc_rib_instance_filtered = BmpPeerType::LocRibInstancePeer { filtered: true };

    let good_experimental_251 = BmpPeerType::Experimental251 { flags: 0xff };
    let good_experimental_252 = BmpPeerType::Experimental252 { flags: 0xff };
    let good_experimental_253 = BmpPeerType::Experimental253 { flags: 0xff };
    let good_experimental_254 = BmpPeerType::Experimental254 { flags: 0xff };

    let bad_eof = LocatedBmpPeerTypeParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_eof_wire[1..]) },
        BmpPeerTypeParsingError::NomError(ErrorKind::Eof),
    );
    let bad_reserved = LocatedBmpPeerTypeParsingError::new(
        Span::new(&bad_reserved_wire),
        BmpPeerTypeParsingError::UndefinedBmpPeerTypeCode(UndefinedBmpPeerTypeCode(0xff)),
    );

    test_parsed_completely(&good_global_instance_ipv4_wire, &good_global_instance_ipv4);
    test_parsed_completely(&good_global_instance_ipv6_wire, &good_global_instance_ipv6);
    test_parsed_completely(&good_global_instance_post_wire, &good_global_instance_post);
    test_parsed_completely(&good_global_asn2_wire, &good_global_asn2);
    test_parsed_completely(&good_global_adj_out_wire, &good_global_adj_out);
    test_parsed_completely(&good_rd_instance_all_wire, &good_rd_instance_all);
    test_parsed_completely(&good_loc_rib_instance_wire, &good_loc_rib_instance);
    test_parsed_completely(&good_local_instance_all_wire, &good_local_instance_all);
    test_parsed_completely(
        &good_loc_rib_instance_filtered_wire,
        &good_loc_rib_instance_filtered,
    );
    test_parsed_completely(&good_experimental_251_wire, &good_experimental_251);
    test_parsed_completely(&good_experimental_252_wire, &good_experimental_252);
    test_parsed_completely(&good_experimental_253_wire, &good_experimental_253);
    test_parsed_completely(&good_experimental_254_wire, &good_experimental_254);
    test_parse_error::<BmpPeerType, LocatedBmpPeerTypeParsingError<'_>>(&bad_eof_wire, &bad_eof);
    test_parse_error::<BmpPeerType, LocatedBmpPeerTypeParsingError<'_>>(
        &bad_reserved_wire,
        &bad_reserved,
    );

    test_write(&good_global_instance_ipv4, &good_global_instance_ipv4_wire)?;
    test_write(&good_global_instance_ipv6, &good_global_instance_ipv6_wire)?;
    test_write(&good_global_instance_post, &good_global_instance_post_wire)?;
    test_write(&good_global_asn2, &good_global_asn2_wire)?;
    test_write(&good_global_adj_out, &good_global_adj_out_wire)?;
    test_write(&good_rd_instance_all, &good_rd_instance_all_wire)?;
    test_write(&good_local_instance_all, &good_local_instance_all_wire)?;
    test_write(&good_loc_rib_instance, &good_loc_rib_instance_wire)?;
    test_write(
        &good_loc_rib_instance_filtered,
        &good_loc_rib_instance_filtered_wire,
    )?;
    test_write(&good_experimental_251, &good_experimental_251_wire)?;
    test_write(&good_experimental_252, &good_experimental_252_wire)?;
    test_write(&good_experimental_253, &good_experimental_253_wire)?;
    test_write(&good_experimental_254, &good_experimental_254_wire)?;
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
        0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00,
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
        0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let bad_eof_wire = [0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

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
        Some(Utc.timestamp_opt(1664656357, 746092000).unwrap()),
    );

    let good_ipv6 = PeerHeader::new(
        BmpPeerType::RdInstancePeer {
            ipv6: true,
            post_policy: false,
            asn2: false,
            adj_rib_out: false,
        },
        Some(RouteDistinguisher::As2Administrator { asn2: 0, number: 1 }),
        Some(IpAddr::V6(Ipv6Addr::from_str("2001:db8::ac10:14").unwrap())),
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        Some(Utc.timestamp_opt(1664656357, 746092000).unwrap()),
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
        Some(Utc.timestamp_opt(1664656357, 746092000).unwrap()),
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
        Some(Utc.timestamp_opt(1664656357, 746092000).unwrap()),
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
        Some(Utc.timestamp_opt(1664656357, 746092000).unwrap()),
    );

    let good_filtered = PeerHeader::new(
        BmpPeerType::LocRibInstancePeer { filtered: true },
        None,
        None,
        200,
        Ipv4Addr::new(172, 16, 0, 20),
        None,
    );
    let bad_eof = LocatedPeerHeaderParsingError::new(
        unsafe { Span::new_from_raw_offset(10, &bad_eof_wire[10..]) },
        PeerHeaderParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_ipv4_wire, &good_ipv4);
    test_parsed_completely(&good_ipv6_wire, &good_ipv6);
    test_parsed_completely(&good_post_policy_wire, &good_post_policy);
    test_parsed_completely(&good_adj_rip_out_wire, &good_adj_rip_out);
    test_parsed_completely(&good_asn2_wire, &good_asn2);
    test_parsed_completely(&good_filtered_wire, &good_filtered);
    test_parse_error::<PeerHeader, LocatedPeerHeaderParsingError<'_>>(&bad_eof_wire, &bad_eof);

    test_write(&good_ipv4, &good_ipv4_wire)?;
    test_write(&good_ipv6, &good_ipv6_wire)?;
    test_write(&good_post_policy, &good_post_policy_wire)?;
    test_write(&good_adj_rip_out, &good_adj_rip_out_wire)?;
    test_write(&good_asn2, &good_asn2_wire)?;
    test_write(&good_filtered, &good_filtered_wire)?;
    Ok(())
}

#[test]
fn test_initiation_information() -> Result<(), InitiationInformationWritingError> {
    let good_string_wire = [0x00, 0x00, 0x00, 0x02, 0x41, 0x42];
    let good_sys_descr_wire = [0x00, 0x01, 0x00, 0x02, 0x41, 0x42];
    let good_sys_name_wire = [0x00, 0x02, 0x00, 0x02, 0x41, 0x42];
    let good_vrf_table_wire = [0x00, 0x03, 0x00, 0x02, 0x41, 0x42];
    let good_admin_label_wire = [0x00, 0x04, 0x00, 0x02, 0x41, 0x42];
    let good_experimental_65531_wire = [0xff, 0xfb, 0x00, 0x02, 0x01, 0x02];
    let good_experimental_65532_wire = [0xff, 0xfc, 0x00, 0x02, 0x01, 0x02];
    let good_experimental_65533_wire = [0xff, 0xfd, 0x00, 0x02, 0x01, 0x02];
    let good_experimental_65534_wire = [0xff, 0xfe, 0x00, 0x02, 0x01, 0x02];
    let bad_eof_wire = [];
    let bad_undefined_type_wire = [0xff, 0xff];

    let good_string = InitiationInformation::String("AB".to_string());
    let good_sys_descr = InitiationInformation::SystemDescription("AB".to_string());
    let good_sys_name = InitiationInformation::SystemName("AB".to_string());
    let good_vrf_table = InitiationInformation::VrfTableName("AB".to_string());
    let good_admin_label = InitiationInformation::AdminLabel("AB".to_string());
    let good_experimental_65531 = InitiationInformation::Experimental65531(vec![0x01, 0x02]);
    let good_experimental_65532 = InitiationInformation::Experimental65532(vec![0x01, 0x02]);
    let good_experimental_65533 = InitiationInformation::Experimental65533(vec![0x01, 0x02]);
    let good_experimental_65534 = InitiationInformation::Experimental65534(vec![0x01, 0x02]);

    let bad_eof = LocatedInitiationInformationParsingError::new(
        Span::new(&bad_eof_wire),
        InitiationInformationParsingError::NomError(ErrorKind::Eof),
    );

    let bad_undefined_type = LocatedInitiationInformationParsingError::new(
        Span::new(&bad_undefined_type_wire),
        InitiationInformationParsingError::UndefinedType(UndefinedInitiationInformationTlvType(
            0xffff,
        )),
    );

    test_parsed_completely(&good_string_wire, &good_string);
    test_parsed_completely(&good_sys_descr_wire, &good_sys_descr);
    test_parsed_completely(&good_sys_name_wire, &good_sys_name);
    test_parsed_completely(&good_vrf_table_wire, &good_vrf_table);
    test_parsed_completely(&good_admin_label_wire, &good_admin_label);
    test_parsed_completely(&good_experimental_65531_wire, &good_experimental_65531);
    test_parsed_completely(&good_experimental_65532_wire, &good_experimental_65532);
    test_parsed_completely(&good_experimental_65533_wire, &good_experimental_65533);
    test_parsed_completely(&good_experimental_65534_wire, &good_experimental_65534);

    test_parse_error::<InitiationInformation, LocatedInitiationInformationParsingError<'_>>(
        &bad_eof_wire,
        &bad_eof,
    );
    test_parse_error::<InitiationInformation, LocatedInitiationInformationParsingError<'_>>(
        &bad_undefined_type_wire,
        &bad_undefined_type,
    );

    test_write(&good_string, &good_string_wire)?;
    test_write(&good_sys_descr, &good_sys_descr_wire)?;
    test_write(&good_sys_name, &good_sys_name_wire)?;
    test_write(&good_vrf_table, &good_vrf_table_wire)?;
    test_write(&good_admin_label, &good_admin_label_wire)?;
    test_write(&good_experimental_65531, &good_experimental_65531_wire)?;
    test_write(&good_experimental_65532, &good_experimental_65532_wire)?;
    test_write(&good_experimental_65533, &good_experimental_65533_wire)?;
    test_write(&good_experimental_65534, &good_experimental_65534_wire)?;
    Ok(())
}

#[test]
fn test_initiation_message() -> Result<(), InitiationMessageWritingError> {
    let good_wire = [
        0x00, 0x01, 0x00, 0x02, 0x41, 0x42, 0x00, 0x02, 0x00, 0x02, 0x43, 0x44,
    ];
    let bad_info_wire = [0xff, 0xff];

    let good = InitiationMessage::new(vec![
        InitiationInformation::SystemDescription("AB".to_string()),
        InitiationInformation::SystemName("CD".to_string()),
    ]);

    let bad_info = LocatedInitiationMessageParsingError::new(
        Span::new(&bad_info_wire),
        InitiationMessageParsingError::InitiationInformationError(
            InitiationInformationParsingError::UndefinedType(
                UndefinedInitiationInformationTlvType(0xffff),
            ),
        ),
    );

    test_parsed_completely(&good_wire, &good);

    test_parse_error::<InitiationMessage, LocatedInitiationMessageParsingError<'_>>(
        &bad_info_wire,
        &bad_info,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bmp_value_initiation_message() -> Result<(), BmpMessageValueWritingError> {
    let good_wire = [
        0x04, 0x00, 0x01, 0x00, 0x06, 0x74, 0x65, 0x73, 0x74, 0x31, 0x31, 0x00, 0x02, 0x00, 0x03,
        0x50, 0x45, 0x32,
    ];
    let bad_information_wire = [
        0x04, 0xff, 0xff, 0x00, 0x06, 0x74, 0x65, 0x73, 0x74, 0x31, 0x31, 0x00, 0x02, 0x00, 0x03,
        0x50, 0x45, 0x32,
    ];

    let good = BmpMessageValue::Initiation(InitiationMessage::new(vec![
        InitiationInformation::SystemDescription("test11".to_string()),
        InitiationInformation::SystemName("PE2".to_string()),
    ]));
    let bad_information = LocatedBmpMessageValueParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_information_wire[1..]) },
        BmpMessageValueParsingError::InitiationMessageError(
            InitiationMessageParsingError::InitiationInformationError(
                InitiationInformationParsingError::UndefinedType(
                    UndefinedInitiationInformationTlvType(0xffff),
                ),
            ),
        ),
    );
    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BmpMessageValue, LocatedBmpMessageValueParsingError<'_>>(
        &bad_information_wire,
        &bad_information,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_route_monitoring_message() -> Result<(), RouteMonitoringMessageWritingError> {
    let good_wire = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x38,
        0x02, 0x00, 0x00, 0x00, 0x1d, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0e, 0x02, 0x03,
        0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x64, 0x40, 0x03, 0x04,
        0xac, 0x10, 0x00, 0x14, 0x18, 0xac, 0x10, 0x01,
    ];
    let bad_peer_header_wire = [];
    let bad_bgp_wire = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xee, 0xee,
    ];
    let bad_bgp_type_wire = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
        0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x15,
        0x03, 0x06, 0x03,
    ];

    let good = RouteMonitoringMessage::build(
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
            Some(Utc.timestamp_opt(1664656357, 746092000).unwrap()),
        ),
        vec![BGPMessage::Update(BGPUpdateMessage::new(
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
                    PathAttributeValue::ASPath(ASPath::As4PathSegments(vec![As4PathSegment::new(
                        AsPathSegmentType::AsSequence,
                        vec![100, 200, 100],
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
            vec![NetworkLayerReachabilityInformation::new(vec![
                Ipv4Net::from_str("172.16.1.0/24").unwrap(),
            ])],
        ))],
    )
    .unwrap();
    let bad_peer_header = LocatedRouteMonitoringMessageParsingError::new(
        Span::new(&bad_peer_header_wire),
        RouteMonitoringMessageParsingError::PeerHeaderError(
            PeerHeaderParsingError::BmpPeerTypeError(BmpPeerTypeParsingError::NomError(
                ErrorKind::Eof,
            )),
        ),
    );
    let bad_bgp = LocatedRouteMonitoringMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(58, &bad_bgp_wire[58..]) },
        RouteMonitoringMessageParsingError::BgpMessageError(
            BGPMessageParsingError::BadMessageLength(61166),
        ),
    );
    let bad_bgp_type = LocatedRouteMonitoringMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(42, &bad_bgp_type_wire[42..]) },
        RouteMonitoringMessageParsingError::RouteMonitoringMessageError(
            RouteMonitoringMessageError::UnexpectedMessageType(BGPMessageType::Notification),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<RouteMonitoringMessage, LocatedRouteMonitoringMessageParsingError<'_>>(
        &bad_peer_header_wire,
        &bad_peer_header,
    );
    test_parse_error::<RouteMonitoringMessage, LocatedRouteMonitoringMessageParsingError<'_>>(
        &bad_bgp_wire,
        &bad_bgp,
    );
    test_parse_error::<RouteMonitoringMessage, LocatedRouteMonitoringMessageParsingError<'_>>(
        &bad_bgp_type_wire,
        &bad_bgp_type,
    );

    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_bmp_value_route_monitoring() -> Result<(), BmpMessageValueWritingError> {
    let good_wire = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00,
        0xc8, 0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x38, 0x02, 0x00, 0x00, 0x00, 0x1d, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0e, 0x02,
        0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x64, 0x40, 0x03,
        0x04, 0xac, 0x10, 0x00, 0x14, 0x18, 0xac, 0x10, 0x01,
    ];

    let bad_wire = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00,
        0xc8, 0xac, 0x10, 0x00, 0x14, 0x63, 0x38, 0xa3, 0xe5, 0x00, 0x0b, 0x62, 0x6c, 0xff,
    ];

    let good = BmpMessageValue::RouteMonitoring(
        RouteMonitoringMessage::build(
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
                Some(Utc.timestamp_opt(1664656357, 746092000).unwrap()),
            ),
            vec![BGPMessage::Update(BGPUpdateMessage::new(
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
                        PathAttributeValue::ASPath(ASPath::As4PathSegments(vec![
                            As4PathSegment::new(AsPathSegmentType::AsSequence, vec![100, 200, 100]),
                        ])),
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
                vec![NetworkLayerReachabilityInformation::new(vec![
                    Ipv4Net::from_str("172.16.1.0/24").unwrap(),
                ])],
            ))],
        )
        .unwrap(),
    );

    let bad = LocatedBmpMessageValueParsingError::new(
        unsafe { Span::new_from_raw_offset(43, &bad_wire[43..]) },
        BmpMessageValueParsingError::RouteMonitoringMessageError(
            RouteMonitoringMessageParsingError::BgpMessageError(BGPMessageParsingError::NomError(
                ErrorKind::Eof,
            )),
        ),
    );
    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BmpMessageValue, LocatedBmpMessageValueParsingError<'_>>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_bmp_value_peer_up_notification() -> Result<(), BmpMessageValueWritingError> {
    let good_wire = [
        0x03, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xfc,
        0x00, 0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x42, 0x00, 0x09, 0xd9, 0xd9, 0xfc, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
        0xb3, 0x74, 0x8a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x4b, 0x01, 0x04, 0xfc, 0x00, 0x00, 0xb4, 0x0a, 0x00, 0x00,
        0x03, 0x2e, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x02, 0x80, 0x00, 0x02,
        0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfc, 0x00, 0x02, 0x14, 0x05, 0x12,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00,
        0x80, 0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x4b, 0x01, 0x04, 0xfc, 0x00, 0x00, 0xb4, 0x0a, 0x00, 0x00,
        0x01, 0x2e, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x02, 0x80, 0x00, 0x02,
        0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfc, 0x00, 0x02, 0x14, 0x05, 0x12,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00,
        0x80, 0x00, 0x02,
    ];

    let bad_wire = [0x03, 0x00, 0x80];

    let good = BmpMessageValue::PeerUpNotification(
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
                Some(Utc.timestamp_opt(1664821826, 645593000).unwrap()),
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

    let bad = LocatedBmpMessageValueParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &bad_wire[3..]) },
        BmpMessageValueParsingError::PeerUpNotificationMessageError(
            PeerUpNotificationMessageParsingError::PeerHeaderError(
                PeerHeaderParsingError::RouteDistinguisherError(
                    RouteDistinguisherParsingError::NomError(ErrorKind::Eof),
                ),
            ),
        ),
    );
    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BmpMessageValue, LocatedBmpMessageValueParsingError<'_>>(&bad_wire, &bad);

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_peer_down_reason() -> Result<(), PeerDownNotificationReasonWritingError> {
    let notif = BGPMessage::Notification(BGPNotificationMessage::CeaseError(
        CeaseError::PeerDeConfigured { value: vec![] },
    ));
    let good_local_pdu_wire = [
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x15, 0x03, 0x06, 0x03,
    ];
    let bad_local_pdu_bgp_wire = [
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x15, 0xff, 0x06, 0x03,
    ];
    let good_local_fsm_wire = [0x02, 0x00, 0x02];
    let bad_remote_pdu_bgp_wire = [
        0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x15, 0x03, 0x06, 0x03,
    ];
    let good_remote_no_data_wire = [0x04];
    let good_peer_de_configured_wire = [0x05];
    let good_local_system_closed_wire = [0x06, 0x00, 0x03, 0x00, 0x04, 0x76, 0x72, 0x66, 0x31];
    let bad_local_system_closed_wire = [0x06, 0x00, 0xff, 0x00, 0x04, 0x76, 0x72, 0x66, 0x31];
    let good_experimental_251_wire = [0xfb, 0x01, 0x03];
    let good_experimental_252_wire = [0xfc, 0x01, 0x03];
    let good_experimental_253_wire = [0xfd, 0x01, 0x03];
    let good_experimental_254_wire = [0xfe, 0x01, 0x03];
    let bad_eof_wire = [];
    let bad_undefined_reason_code_wire = [0xff];

    let good_local_fsm = PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(2);
    let good_local_pdu =
        PeerDownNotificationReason::LocalSystemClosedNotificationPduFollows(notif.clone());
    let good_remote_pdu =
        PeerDownNotificationReason::RemoteSystemClosedNotificationPduFollows(notif.clone());
    let good_remote_no_data = PeerDownNotificationReason::RemoteSystemClosedNoData;
    let good_peer_de_configured = PeerDownNotificationReason::PeerDeConfigured;
    let good_local_system_closed = PeerDownNotificationReason::LocalSystemClosedTlvDataFollows(
        InitiationInformation::VrfTableName("vrf1".to_string()),
    );
    let good_experimental_251 = PeerDownNotificationReason::Experimental251(vec![1, 3]);
    let good_experimental_252 = PeerDownNotificationReason::Experimental252(vec![1, 3]);
    let good_experimental_253 = PeerDownNotificationReason::Experimental253(vec![1, 3]);
    let good_experimental_254 = PeerDownNotificationReason::Experimental254(vec![1, 3]);

    let bad_local_pdu_bgp = LocatedPeerDownNotificationReasonParsingError::new(
        unsafe { Span::new_from_raw_offset(19, &bad_local_pdu_bgp_wire[19..]) },
        PeerDownNotificationReasonParsingError::BgpMessageError(
            BGPMessageParsingError::UndefinedBgpMessageType(UndefinedBgpMessageType(255)),
        ),
    );
    let bad_local_system_closed = LocatedPeerDownNotificationReasonParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_local_system_closed_wire[1..]) },
        PeerDownNotificationReasonParsingError::InitiationInformationError(
            InitiationInformationParsingError::UndefinedType(
                UndefinedInitiationInformationTlvType(255),
            ),
        ),
    );
    let bad_eof = LocatedPeerDownNotificationReasonParsingError::new(
        Span::new(&bad_eof_wire),
        PeerDownNotificationReasonParsingError::NomError(ErrorKind::Eof),
    );
    let bad_undefined_reason_code = LocatedPeerDownNotificationReasonParsingError::new(
        Span::new(&bad_undefined_reason_code_wire),
        PeerDownNotificationReasonParsingError::UndefinedPeerDownReasonCode(
            UndefinedPeerDownReasonCode(255),
        ),
    );

    test_parsed_completely(&good_local_fsm_wire, &good_local_fsm);
    test_parsed_completely(&good_local_pdu_wire, &good_local_pdu);
    test_parsed_completely(&bad_remote_pdu_bgp_wire, &good_remote_pdu);
    test_parsed_completely(&good_remote_no_data_wire, &good_remote_no_data);
    test_parsed_completely(&good_peer_de_configured_wire, &good_peer_de_configured);
    test_parsed_completely(&good_local_system_closed_wire, &good_local_system_closed);
    test_parsed_completely(&good_experimental_251_wire, &good_experimental_251);
    test_parsed_completely(&good_experimental_252_wire, &good_experimental_252);
    test_parsed_completely(&good_experimental_253_wire, &good_experimental_253);
    test_parsed_completely(&good_experimental_254_wire, &good_experimental_254);

    test_parse_error::<PeerDownNotificationReason, LocatedPeerDownNotificationReasonParsingError<'_>>(
        &bad_local_pdu_bgp_wire,
        &bad_local_pdu_bgp,
    );
    test_parse_error::<PeerDownNotificationReason, LocatedPeerDownNotificationReasonParsingError<'_>>(
        &bad_local_system_closed_wire,
        &bad_local_system_closed,
    );
    test_parse_error::<PeerDownNotificationReason, LocatedPeerDownNotificationReasonParsingError<'_>>(
        &bad_eof_wire,
        &bad_eof,
    );
    test_parse_error::<PeerDownNotificationReason, LocatedPeerDownNotificationReasonParsingError<'_>>(
        &bad_undefined_reason_code_wire,
        &bad_undefined_reason_code,
    );

    test_write(&good_local_fsm, &good_local_fsm_wire)?;
    test_write(&good_local_pdu, &good_local_pdu_wire)?;
    test_write(&good_remote_pdu, &bad_remote_pdu_bgp_wire)?;
    test_write(&good_remote_no_data, &good_remote_no_data_wire)?;
    test_write(&good_peer_de_configured, &good_peer_de_configured_wire)?;
    test_write(&good_local_system_closed, &good_local_system_closed_wire)?;
    test_write(&good_experimental_251, &good_experimental_251_wire)?;
    test_write(&good_experimental_252, &good_experimental_252_wire)?;
    test_write(&good_experimental_253, &good_experimental_253_wire)?;
    test_write(&good_experimental_254, &good_experimental_254_wire)?;
    Ok(())
}

#[test]
fn test_peer_down_notification() -> Result<(), PeerDownNotificationMessageWritingError> {
    let good_wire = [
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xfc, 0x00,
        0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x53, 0x00, 0x07, 0x71, 0xe3, 0x02, 0x00, 0x02,
    ];
    let bad_information_wire = [
        0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        252, 0, 10, 0, 0, 1, 99, 59, 42, 83, 0, 7, 113, 227, 6, 0, 0, 0, 1, 101,
    ];
    let bad_peer_header_wire = [];
    let bad_peer_reason_wire = [
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xfc, 0x00,
        0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x53, 0x00, 0x07, 0x71, 0xe3, 0xff, 0x00, 0x02,
    ];

    let good = PeerDownNotificationMessage::build(
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
    .unwrap();

    let bad_information = LocatedPeerDownNotificationMessageParsingError::new(
        Span::new(&bad_information_wire),
        PeerDownNotificationMessageParsingError::PeerDownMessageError(
            PeerDownNotificationMessageError::UnexpectedInitiationInformationTlvType(
                InitiationInformationTlvType::String,
            ),
        ),
    );
    let bad_peer_header = LocatedPeerDownNotificationMessageParsingError::new(
        Span::new(&bad_peer_header_wire),
        PeerDownNotificationMessageParsingError::PeerHeaderError(
            PeerHeaderParsingError::BmpPeerTypeError(BmpPeerTypeParsingError::NomError(
                ErrorKind::Eof,
            )),
        ),
    );
    let bad_peer_reason = LocatedPeerDownNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(42, &bad_peer_reason_wire[42..]) },
        PeerDownNotificationMessageParsingError::PeerDownNotificationReasonError(
            PeerDownNotificationReasonParsingError::UndefinedPeerDownReasonCode(
                UndefinedPeerDownReasonCode(255),
            ),
        ),
    );
    test_parsed_completely(&good_wire, &good);
    test_parse_error::<
        PeerDownNotificationMessage,
        LocatedPeerDownNotificationMessageParsingError<'_>,
    >(&bad_information_wire, &bad_information);
    test_parse_error::<
        PeerDownNotificationMessage,
        LocatedPeerDownNotificationMessageParsingError<'_>,
    >(&bad_peer_header_wire, &bad_peer_header);
    test_parse_error::<
        PeerDownNotificationMessage,
        LocatedPeerDownNotificationMessageParsingError<'_>,
    >(&bad_peer_reason_wire, &bad_peer_reason);

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bmp_peer_down_notification() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x03, 0x00, 0x00, 0x00, 0x33, 0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0xfc, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x53, 0x00,
        0x07, 0x71, 0xe3, 0x02, 0x00, 0x02,
    ];
    let bad_eof_wire = [];

    let good = BmpMessage::V3(BmpMessageValue::PeerDownNotification(
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
                Some(Utc.timestamp_opt(1664821843, 487907000).unwrap()),
            ),
            PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(2),
        )
        .unwrap(),
    ));

    let bad_eof = LocatedBmpMessageValueParsingError::new(
        Span::new(&bad_eof_wire),
        BmpMessageValueParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_wire, &good);

    test_parse_error::<BmpMessageValue, LocatedBmpMessageValueParsingError<'_>>(
        &bad_eof_wire,
        &bad_eof,
    );

    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_router_mirroring_value() -> Result<(), RouteMirroringValueWritingError> {
    let good_bgp_wire = [
        0x00, 0x00, 0x00, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04,
    ];
    let good_information_wire = [0, 1, 0, 2, 0, 0];
    let good_experimental_65531_wire = [0xff, 0xfb, 0, 2, 1, 2];
    let good_experimental_65532_wire = [0xff, 0xfc, 0, 2, 1, 2];
    let good_experimental_65533_wire = [0xff, 0xfd, 0, 2, 1, 2];
    let good_experimental_65534_wire = [0xff, 0xfe, 0, 2, 1, 2];

    let good_bgp = RouteMirroringValue::BgpMessage(BGPMessage::KeepAlive);
    let good_information = RouteMirroringValue::Information(RouteMirroringInformation::ErroredPdu);
    let good_experimental_65531 = RouteMirroringValue::Experimental65531(vec![1, 2]);
    let good_experimental_65532 = RouteMirroringValue::Experimental65532(vec![1, 2]);
    let good_experimental_65533 = RouteMirroringValue::Experimental65533(vec![1, 2]);
    let good_experimental_65534 = RouteMirroringValue::Experimental65534(vec![1, 2]);

    test_parsed_completely(&good_bgp_wire, &good_bgp);
    test_parsed_completely(&good_information_wire, &good_information);
    test_parsed_completely(&good_experimental_65531_wire, &good_experimental_65531);
    test_parsed_completely(&good_experimental_65532_wire, &good_experimental_65532);
    test_parsed_completely(&good_experimental_65533_wire, &good_experimental_65533);
    test_parsed_completely(&good_experimental_65534_wire, &good_experimental_65534);

    test_write(&good_bgp, &good_bgp_wire)?;
    test_write(&good_information, &good_information_wire)?;
    test_write(&good_experimental_65531, &good_experimental_65531_wire)?;
    test_write(&good_experimental_65532, &good_experimental_65532_wire)?;
    test_write(&good_experimental_65533, &good_experimental_65533_wire)?;
    test_write(&good_experimental_65534, &good_experimental_65534_wire)?;
    Ok(())
}

#[test]
fn test_bmp_router_mirroring() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x03, 0x00, 0x00, 0x00, 0x47, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x10,
        0x00, 0x14, 0x00, 0x00, 0x00, 0xc8, 0xac, 0x10, 0x00, 0x14, 0x63, 0x3c, 0x98, 0x8b, 0x00,
        0x04, 0x5a, 0xae, 0x00, 0x00, 0x00, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04,
    ];

    let good = BmpMessage::V3(BmpMessageValue::RouteMirroring(RouteMirroringMessage::new(
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
            Some(Utc.timestamp_opt(1664915595, 285358000).unwrap()),
        ),
        vec![RouteMirroringValue::BgpMessage(BGPMessage::KeepAlive)],
    )));
    test_parsed_completely(&good_wire, &good);

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_termination_information() -> Result<(), TerminationInformationWritingError> {
    let good_string_wire = [0, 0, 0, 4, 116, 101, 115, 116];
    let good_reason_wire = [0, 1, 0, 2, 0, 0];
    let good_experimental_65531_wire = [0xff, 0xfb, 0, 4, 116, 101, 115, 116];
    let good_experimental_65532_wire = [0xff, 0xfc, 0, 4, 116, 101, 115, 116];
    let good_experimental_65533_wire = [0xff, 0xfd, 0, 4, 116, 101, 115, 116];
    let good_experimental_65534_wire = [0xff, 0xfe, 0, 4, 116, 101, 115, 116];

    let good_string = TerminationInformation::String("test".to_string());
    let good_reason = TerminationInformation::Reason(PeerTerminationCode::AdministrativelyClosed);
    let good_experimental_65531 =
        TerminationInformation::Experimental65531(vec![116, 101, 115, 116]);
    let good_experimental_65532 =
        TerminationInformation::Experimental65532(vec![116, 101, 115, 116]);
    let good_experimental_65533 =
        TerminationInformation::Experimental65533(vec![116, 101, 115, 116]);
    let good_experimental_65534 =
        TerminationInformation::Experimental65534(vec![116, 101, 115, 116]);

    test_parsed_completely(&good_string_wire, &good_string);
    test_parsed_completely(&good_reason_wire, &good_reason);
    test_parsed_completely(&good_experimental_65531_wire, &good_experimental_65531);
    test_parsed_completely(&good_experimental_65532_wire, &good_experimental_65532);
    test_parsed_completely(&good_experimental_65533_wire, &good_experimental_65533);
    test_parsed_completely(&good_experimental_65534_wire, &good_experimental_65534);

    test_write(&good_string, &good_string_wire)?;
    test_write(&good_reason, &good_reason_wire)?;
    test_write(&good_experimental_65531, &good_experimental_65531_wire)?;
    test_write(&good_experimental_65532, &good_experimental_65532_wire)?;
    test_write(&good_experimental_65533, &good_experimental_65533_wire)?;
    test_write(&good_experimental_65534, &good_experimental_65534_wire)?;
    Ok(())
}

#[test]
fn test_termination_message() -> Result<(), TerminationMessageWritingError> {
    let good_wire = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0,
        200, 172, 16, 0, 20, 99, 60, 152, 139, 0, 4, 90, 174, 0, 0, 0, 4, 116, 101, 115, 116,
    ];

    let good = TerminationMessage::new(
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
            Some(Utc.timestamp_opt(1664915595, 285358000).unwrap()),
        ),
        vec![TerminationInformation::String("test".to_string())],
    );
    test_parsed_completely(&good_wire, &good);

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bmp_termination() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        3, 0, 0, 0, 56, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172,
        16, 0, 20, 0, 0, 0, 200, 172, 16, 0, 20, 99, 60, 152, 139, 0, 4, 90, 174, 0, 0, 0, 4, 116,
        101, 115, 116,
    ];

    let good = BmpMessage::V3(BmpMessageValue::Termination(TerminationMessage::new(
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
            Some(Utc.timestamp_opt(1664915595, 285358000).unwrap()),
        ),
        vec![TerminationInformation::String("test".to_string())],
    )));
    test_parsed_completely(&good_wire, &good);

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bmp_statistics_report() -> Result<(), BmpMessageWritingError> {
    let good_wire = [
        0x03, 0x00, 0x00, 0x00, 0x6c, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfd, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x8b, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0xc8, 0xac, 0x10, 0x00, 0x14, 0x63, 0x3c, 0x99, 0x78, 0x00,
        0x04, 0x73, 0x3f, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0xff, 0xfb, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00,
    ];
    let good = BmpMessage::V3(BmpMessageValue::StatisticsReport(
        StatisticsReportMessage::new(
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: true,
                    post_policy: false,
                    asn2: false,
                    adj_rib_out: false,
                },
                None,
                Some(IpAddr::V6(Ipv6Addr::from_str("fdfd:0:0:8bea::2").unwrap())),
                200,
                Ipv4Addr::new(172, 16, 0, 20),
                Some(Utc.timestamp_opt(1664915832, 291647000).unwrap()),
            ),
            vec![
                StatisticsCounter::NumberOfPrefixesRejectedByInboundPolicy(CounterU32::new(0)),
                StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsPathLoop(CounterU32::new(2)),
                StatisticsCounter::NumberOfUpdatesInvalidatedDueToOriginatorId(CounterU32::new(0)),
                StatisticsCounter::NumberOfUpdatesInvalidatedDueToClusterListLoop(CounterU32::new(
                    0,
                )),
                StatisticsCounter::NumberOfDuplicateWithdraws(CounterU32::new(0)),
                StatisticsCounter::NumberOfUpdatesSubjectedToTreatAsWithdraw(CounterU32::new(6)),
                StatisticsCounter::Experimental65531(vec![0, 0, 0, 0]),
            ],
        ),
    ));
    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;

    Ok(())
}
