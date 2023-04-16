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

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use ipnet::{Ipv4Net, Ipv6Net};
use nom::error::ErrorKind;

use netgauze_iana::address_family::{AddressFamily, AddressType};
use netgauze_parse_utils::{
    test_helpers::{
        combine, test_parse_error_with_two_inputs, test_parsed_completely,
        test_parsed_completely_with_two_inputs, test_write,
    },
    Span,
};

use crate::{
    capabilities::{
        AddPathAddressFamily, AddPathCapability, BgpCapability, ExtendedNextHopEncoding,
        ExtendedNextHopEncodingCapability, FourOctetAsCapability, GracefulRestartCapability,
        MultiProtocolExtensionsCapability, UnrecognizedCapability,
    },
    community::{
        ExtendedCommunity, TransitiveFourOctetExtendedCommunity, TransitiveOpaqueExtendedCommunity,
        TransitiveTwoOctetExtendedCommunity,
    },
    iana::{
        RouteRefreshSubcode, UndefinedBgpErrorNotificationCode, UndefinedBgpMessageType,
        UndefinedCeaseErrorSubCode, UndefinedRouteRefreshSubcode,
    },
    nlri::*,
    notification::CeaseError,
    open::{BgpOpenMessageParameter, BGP_VERSION},
    path_attribute::*,
    update::BgpUpdateMessage,
    wire::{
        deserializer::{
            notification::{BgpNotificationMessageParsingError, CeaseErrorParsingError},
            route_refresh::BgpRouteRefreshMessageParsingError,
            BgpMessageParsingError, LocatedBgpMessageParsingError,
        },
        serializer::BgpMessageWritingError,
    },
    BgpMessage, BgpNotificationMessage, BgpOpenMessage, BgpRouteRefreshMessage,
};

mod capabilities;
mod community;
mod keepalive;
mod nlri;
mod notification;
mod open;
mod path_attribute;
mod route_refresh;
mod update;

pub(crate) const BGP_MARKER: &[u8] = &[0xff; 16];
pub(crate) const MY_AS: &[u8] = &[0x01, 0x02];
pub(crate) const HOLD_TIME: &[u8] = &[0x03, 0x04];
pub(crate) const BGP_ID: &[u8] = &[0xFF, 0x00, 0x00, 0x01];

#[test]
fn test_bgp_message_not_synchronized_marker() {
    let bad_marker = [0x00; 16];
    let invalid_wire = combine(vec![&bad_marker, &[0x00, 0x13, 0x04]]);

    let invalid = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &invalid_wire[0..]) },
        BgpMessageParsingError::ConnectionNotSynchronized(0u128),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &invalid_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(invalid),
    );
}

#[test]
fn test_bgp_message_length_bounds() {
    // The shortest message is a keepalive message to test with
    let good_wire = combine(vec![BGP_MARKER, &[0x00, 0x13, 0x04]]);

    // Available input is less than the stated input in the message
    let open_underflow_wire = combine(vec![BGP_MARKER, &[0x00, 0x14, 0x01]]);

    // The length is less the min BGP length
    let open_less_than_min_wire = combine(vec![BGP_MARKER, &[0x00, 0x12, 0x01]]);
    let update_less_than_min_wire = combine(vec![BGP_MARKER, &[0x00, 0x12, 0x02]]);
    let notification_less_than_min_wire = combine(vec![BGP_MARKER, &[0x00, 0x12, 0x03]]);
    let keepalive_less_than_min_wire = combine(vec![BGP_MARKER, &[0x00, 0x12, 0x04]]);
    let route_refresh_less_than_min_wire = combine(vec![BGP_MARKER, &[0x00, 0x12, 0x05]]);

    // The message length contains more data than is actually parsed
    let overflow_wire = combine(vec![BGP_MARKER, &[0x00, 0x14, 0x04, 0x00]]);

    // Using length more than 4,096 for keepalive message
    let keepalive_overflow_extended_wire =
        combine(vec![BGP_MARKER, &[0x10, 0x01, 0x04], &[0x00; 0x0fee]]);

    // Using length more than 4,096 for keepalive message
    let open_overflow_extended_wire =
        combine(vec![BGP_MARKER, &[0x10, 0x01, 0x01], &[0x00; 0x0fee]]);

    let good = BgpMessage::KeepAlive;
    let open_underflow = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &open_underflow_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(20),
    );
    let open_less_than_min = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &open_less_than_min_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(18),
    );
    let update_less_than_min = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &update_less_than_min_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(18),
    );
    let notification_less_than_min = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &notification_less_than_min_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(18),
    );
    let keepalive_less_than_min = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &keepalive_less_than_min_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(18),
    );
    let route_refresh_less_than_min = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &route_refresh_less_than_min_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(18),
    );

    let overflow = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(19, &overflow_wire[19..]) },
        BgpMessageParsingError::NomError(ErrorKind::NonEmpty),
    );
    let keepalive_overflow_extended = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &keepalive_overflow_extended_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(4097),
    );

    let open_overflow_extended = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &open_overflow_extended_wire[16..]) },
        BgpMessageParsingError::BadMessageLength(4097),
    );

    test_parsed_completely_with_two_inputs(&good_wire[..], true, &HashMap::new(), &good);
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &open_underflow_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(open_underflow),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &open_less_than_min_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(open_less_than_min),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &update_less_than_min_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(update_less_than_min),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &notification_less_than_min_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(notification_less_than_min),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &keepalive_less_than_min_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(keepalive_less_than_min),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &route_refresh_less_than_min_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(route_refresh_less_than_min),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &overflow_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(overflow),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &keepalive_overflow_extended_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(keepalive_overflow_extended),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &open_overflow_extended_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(open_overflow_extended),
    );
}

#[test]
fn test_bgp_message_undefined_message_type() {
    let invalid_wire = combine(vec![BGP_MARKER, &[0x00, 0x13, 0xff]]);
    let invalid = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(18, &invalid_wire[18..]) },
        BgpMessageParsingError::UndefinedBgpMessageType(UndefinedBgpMessageType(0xff)),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &invalid_wire,
        true,
        &HashMap::new(),
        nom::Err::Error(invalid),
    );
}

#[test]
fn test_bgp_message_open_no_params() -> Result<(), BgpMessageWritingError> {
    let good_no_params_wire = combine(vec![&[BGP_VERSION], MY_AS, HOLD_TIME, BGP_ID, &[0x00u8]]);
    let good_no_params_msg = BgpOpenMessage::new(258, 772, Ipv4Addr::from(4278190081), vec![]);
    test_parsed_completely(&good_no_params_wire, &good_no_params_msg);
    test_write(&good_no_params_msg, &good_no_params_wire)?;
    Ok(())
}

#[test]
fn test_bgp_message_notification() -> Result<(), BgpMessageWritingError> {
    let good_cease_wire = combine(vec![
        BGP_MARKER,
        &[0x00, 0x17, 0x03, 0x06, 0x09, 0x06, 0x03],
    ]);
    let bad_undefined_notif_wire = combine(vec![
        BGP_MARKER,
        &[0x00, 0x17, 0x03, 0xff, 0x09, 0x06, 0x03],
    ]);
    let bad_undefined_cease_wire = combine(vec![
        BGP_MARKER,
        &[0x00, 0x17, 0x03, 0x06, 0xff, 0x06, 0x03],
    ]);

    let good_cease =
        BgpMessage::Notification(BgpNotificationMessage::CeaseError(CeaseError::HardReset {
            value: vec![6, 3],
        }));
    let bad_undefined_notif = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(19, &bad_undefined_notif_wire[19..]) },
        BgpMessageParsingError::BgpNotificationMessageParsingError(
            BgpNotificationMessageParsingError::UndefinedBgpErrorNotificationCode(
                UndefinedBgpErrorNotificationCode(0xff),
            ),
        ),
    );
    let bad_undefined_cease = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(20, &bad_undefined_cease_wire[20..]) },
        BgpMessageParsingError::BgpNotificationMessageParsingError(
            BgpNotificationMessageParsingError::CeaseError(CeaseErrorParsingError::Undefined(
                UndefinedCeaseErrorSubCode(0xff),
            )),
        ),
    );

    test_parsed_completely_with_two_inputs(&good_cease_wire, false, &HashMap::new(), &good_cease);
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &bad_undefined_notif_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(bad_undefined_notif),
    );
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(
        &bad_undefined_cease_wire,
        false,
        &HashMap::new(),
        nom::Err::Error(bad_undefined_cease),
    );

    test_write(&good_cease, &good_cease_wire)?;
    Ok(())
}

#[test]
fn test_bgp_message_route_refresh() -> Result<(), BgpMessageWritingError> {
    let good_normal_payload_wire = [0x00, 0x01, 0x00, 0x01];
    let good_normal_wire = combine(vec![BGP_MARKER, &[0x00, 23, 5], &good_normal_payload_wire]);
    let bad_payload_wire = [0x00, 0x01, 0xff, 0x01];
    let bad_wire = combine(vec![BGP_MARKER, &[0x00, 23, 5], &bad_payload_wire]);

    let good_normal = BgpMessage::RouteRefresh(BgpRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::NormalRequest,
    ));

    let bad = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(21, &bad_wire[21..]) },
        BgpMessageParsingError::BgpRouteRefreshMessageParsingError(
            BgpRouteRefreshMessageParsingError::UndefinedOperation(UndefinedRouteRefreshSubcode(
                255,
            )),
        ),
    );

    test_parsed_completely_with_two_inputs(&good_normal_wire, false, &HashMap::new(), &good_normal);
    test_parse_error_with_two_inputs::<
        BgpMessage,
        bool,
        &HashMap<AddressType, bool>,
        LocatedBgpMessageParsingError<'_>,
    >(&bad_wire, false, &HashMap::new(), nom::Err::Error(bad));
    test_write(&good_normal, &good_normal_wire)?;

    Ok(())
}

#[test]
fn test_bgp_message_open1() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x53, 0x01, 0x04, 0x00, 0x64, 0x00, 0xb4, 0x05, 0x05, 0x05, 0x05, 0x36, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80,
        0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00,
        0x64, 0x02, 0x14, 0x05, 0x12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00, 0x02,
    ];

    let good = BgpMessage::Open(BgpOpenMessage::new(
        100,
        180,
        Ipv4Addr::new(5, 5, 5, 5),
        vec![
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4MplsLabeledVpn),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::Unrecognized(
                UnrecognizedCapability::new(128, vec![]),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::RouteRefresh]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                FourOctetAsCapability::new(100),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::ExtendedNextHopEncoding(
                ExtendedNextHopEncodingCapability::new(vec![
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Unicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(AddressType::Ipv4Multicast, AddressFamily::IPv6),
                    ExtendedNextHopEncoding::new(
                        AddressType::Ipv4MplsLabeledVpn,
                        AddressFamily::IPv6,
                    ),
                ]),
            )]),
        ],
    ));

    test_parsed_completely_with_two_inputs(&good_wire, false, &HashMap::new(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bgp_message_open_multi_protocol() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x71, 0x01, 0x04, 0x00, 0xc8, 0x00, 0xb4, 0xac, 0x10, 0x00, 0x14, 0x54, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02,
        0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41,
        0x04, 0x00, 0x00, 0x00, 0xc8, 0x02, 0x02, 0x06, 0x00, 0x02, 0x0a, 0x45, 0x08, 0x00, 0x01,
        0x01, 0x01, 0x00, 0x01, 0x02, 0x01, 0x02, 0x06, 0x49, 0x04, 0x02, 0x72, 0x32, 0x00, 0x02,
        0x04, 0x40, 0x02, 0xc0, 0x78, 0x02, 0x10, 0x47, 0x0e, 0x00, 0x01, 0x01, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x02, 0x80, 0x00, 0x00, 0x00,
    ];

    let good = BgpMessage::Open(BgpOpenMessage::new(
        200,
        180,
        Ipv4Addr::new(172, 16, 0, 20),
        vec![
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Multicast),
            )]),
            // Cisco Route Refresh
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::Unrecognized(
                UnrecognizedCapability::new(128, vec![]),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::RouteRefresh]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::EnhancedRouteRefresh]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                FourOctetAsCapability::new(200),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::ExtendedMessage]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::AddPath(
                AddPathCapability::new(vec![
                    AddPathAddressFamily::new(AddressType::Ipv4Unicast, false, true),
                    AddPathAddressFamily::new(AddressType::Ipv4Multicast, false, true),
                ]),
            )]),
            // FQDN
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::Unrecognized(
                UnrecognizedCapability::new(73, vec![0x02, 0x72, 0x32, 0x00]),
            )]),
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::GracefulRestartCapability(
                GracefulRestartCapability::new(true, true, 120, vec![]),
            )]),
            // Long Lived Graceful Restart
            BgpOpenMessageParameter::Capabilities(vec![BgpCapability::Unrecognized(
                UnrecognizedCapability::new(71, vec![0, 1, 1, 128, 0, 0, 0, 0, 1, 2, 128, 0, 0, 0]),
            )]),
        ],
    ));

    test_parsed_completely_with_two_inputs(&good_wire, false, &HashMap::new(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_rd_withdraw() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x2e, 0x02, 0x00, 0x00, 0x00, 0x17, 0x90, 0x0f, 0x00, 0x13, 0x00, 0x01, 0x80,
        0x78, 0x16, 0x98, 0x91, 0x00, 0x02, 0x00, 0x64, 0x00, 0xc8, 0x01, 0x2c, 0x01, 0x01, 0x01,
        0x01,
    ];

    let good = BgpMessage::Update(BgpUpdateMessage::new(
        vec![],
        vec![PathAttribute::from(
            true,
            false,
            false,
            true,
            PathAttributeValue::MpUnreach(MpUnreach::Ipv4MplsVpnUnicast {
                nlri: vec![Ipv4MplsVpnUnicastAddress::new_no_path_id(
                    RouteDistinguisher::As4Administrator {
                        asn4: 6553800,
                        number: 300,
                    },
                    vec![MplsLabel::new([22, 152, 145])],
                    Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(1, 1, 1, 1), 32).unwrap())
                        .unwrap(),
                )],
            }),
        )
        .unwrap()],
        vec![],
    ));

    test_parsed_completely_with_two_inputs(&good_wire, false, &HashMap::new(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_rd_announce() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x53, 0x40, 0x01, 0x01, 0x02, 0x40, 0x02, 0x00,
        0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80,
        0x09, 0x04, 0xd5, 0xb1, 0x7f, 0xbe, 0x80, 0x0a, 0x04, 0x00, 0x00, 0x00, 0xc8, 0xc0, 0x10,
        0x08, 0x02, 0x02, 0x00, 0x64, 0x00, 0xc8, 0x01, 0x2c, 0x90, 0x0e, 0x00, 0x21, 0x00, 0x01,
        0x80, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd5, 0xb1, 0x7f, 0xbe, 0x00,
        0x78, 0x02, 0xc0, 0x51, 0x00, 0x02, 0x00, 0x64, 0x00, 0xc8, 0x01, 0x2c, 0x01, 0x01, 0x01,
        0x01,
    ];

    let good = BgpMessage::Update(BgpUpdateMessage::new(
        vec![],
        vec![
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::Origin(Origin::Incomplete),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::AsPath(AsPath::As2PathSegments(vec![])),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::MultiExitDiscriminator(MultiExitDiscriminator::new(0)),
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
                false,
                PathAttributeValue::Originator(Originator::new(Ipv4Addr::new(213, 177, 127, 190))),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::ClusterList(ClusterList::new(vec![ClusterId::new(
                    Ipv4Addr::new(0, 0, 0, 200),
                )])),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                true,
                false,
                false,
                PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
                    ExtendedCommunity::TransitiveFourOctet(
                        TransitiveFourOctetExtendedCommunity::RouteTarget {
                            global_admin: 6553800,
                            local_admin: 300,
                        },
                    ),
                ])),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                true,
                PathAttributeValue::MpReach(MpReach::Ipv4MplsVpnUnicast {
                    next_hop: LabeledNextHop::Ipv4(LabeledIpv4NextHop::new(
                        RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
                        Ipv4Addr::new(213, 177, 127, 190),
                    )),
                    nlri: vec![Ipv4MplsVpnUnicastAddress::new_no_path_id(
                        RouteDistinguisher::As4Administrator {
                            asn4: 6553800,
                            number: 300,
                        },
                        vec![MplsLabel::new([2, 192, 81])],
                        Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(1, 1, 1, 1), 32).unwrap())
                            .unwrap(),
                    )],
                }),
            )
            .unwrap(),
        ],
        vec![],
    ));

    test_parsed_completely_with_two_inputs(&good_wire, false, &HashMap::new(), &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bgp_add_path() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x59, 0x02, 0x00, 0x00, 0x00, 0x30, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x06,
        0x02, 0x01, 0x00, 0x00, 0xfb, 0xff, 0x40, 0x03, 0x04, 0x0a, 0x00, 0x0e, 0x01, 0x80, 0x04,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x0a, 0x04,
        0x0a, 0x00, 0x22, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x20, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x01, 0x20, 0xc0, 0xa8, 0x01, 0x05,
    ];

    let good = BgpMessage::Update(BgpUpdateMessage::new(
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
                PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![As4PathSegment::new(
                    AsPathSegmentType::AsSequence,
                    vec![64511],
                )])),
            )
            .unwrap(),
            PathAttribute::from(
                false,
                true,
                false,
                false,
                PathAttributeValue::NextHop(NextHop::new(Ipv4Addr::new(10, 0, 14, 1))),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::MultiExitDiscriminator(MultiExitDiscriminator::new(0)),
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
                false,
                PathAttributeValue::ClusterList(ClusterList::new(vec![ClusterId::new(
                    Ipv4Addr::new(10, 0, 34, 4),
                )])),
            )
            .unwrap(),
            PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::Originator(Originator::new(Ipv4Addr::new(10, 0, 15, 1))),
            )
            .unwrap(),
        ],
        vec![
            Ipv4UnicastAddress::new(
                Some(1),
                Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(5, 5, 5, 5), 32).unwrap())
                    .unwrap(),
            ),
            Ipv4UnicastAddress::new(
                Some(1),
                Ipv4Unicast::from_net(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 5), 32).unwrap())
                    .unwrap(),
            ),
        ],
    ));

    test_parsed_completely_with_two_inputs(
        &good_wire,
        true,
        &HashMap::from([(AddressType::Ipv4Unicast, true)]),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bgp_add_path_withdraw() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1f, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x18, 0xac, 0x10, 0x64, 0x00,
        0x00,
    ];

    let good = BgpMessage::Update(BgpUpdateMessage::new(
        vec![Ipv4UnicastAddress::new(
            Some(4),
            Ipv4Unicast::from_net(Ipv4Net::from_str("172.16.100.0/24").unwrap()).unwrap(),
        )],
        vec![],
        vec![],
    ));

    test_parsed_completely_with_two_inputs(
        &good_wire,
        true,
        &HashMap::from([(AddressType::Ipv4Unicast, true)]),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_bgp_add_path_mp_ipv6_unicast() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x5f, 0x02, 0x00, 0x00, 0x00, 0x48, 0x90, 0x0e, 0x00, 0x32, 0x00, 0x02, 0x01,
        0x20, 0xfd, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, 0xfe,
        0xed, 0xd3, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x02, 0x40, 0xfd, 0x10, 0xee, 0xee, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x00, 0x03, 0xe8,
    ];

    let good = BgpMessage::Update(BgpUpdateMessage::new(
        vec![],
        vec![
            PathAttribute::from(
                true,
                false,
                false,
                true,
                PathAttributeValue::MpReach(MpReach::Ipv6Unicast {
                    next_hop_global: Ipv6Addr::from_str("fd10:1::2").unwrap(),
                    next_hop_local: Some(Ipv6Addr::from_str("fe80::a00:27ff:feed:d34a").unwrap()),
                    nlri: vec![Ipv6UnicastAddress::new(
                        Some(2),
                        Ipv6Unicast::from_net(Ipv6Net::from_str("fd10:eeee::/64").unwrap())
                            .unwrap(),
                    )],
                }),
            )
            .unwrap(),
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
                    vec![100, 1000],
                )])),
            )
            .unwrap(),
        ],
        vec![],
    ));

    test_parsed_completely_with_two_inputs(
        &good_wire,
        true,
        &HashMap::from([(AddressType::Ipv6Unicast, true)]),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_evpn() -> Result<(), BgpMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x69, 0x02, 0x00, 0x00, 0x00, 0x52, 0x90, 0x0e, 0x00, 0x2c, 0x00, 0x19, 0x46,
        0x04, 0xac, 0x10, 0x00, 0x64, 0x00, 0x02, 0x21, 0x00, 0x01, 0xac, 0x10, 0x00, 0x64, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x30, 0x08, 0x00, 0x27, 0x81, 0xd5, 0x67, 0x00, 0x00, 0x00, 0x6f, 0x40, 0x01, 0x01, 0x00,
        0x50, 0x02, 0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0xc0, 0x10, 0x10, 0x03,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x6f,
    ];

    let _good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x72, 0x01, 0x04, 0x03, 0xe8, 0x00, 0xb4, 0xac, 0x10, 0x00, 0x64, 0x55, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x19, 0x00, 0x46,
        0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41,
        0x04, 0x00, 0x00, 0x03, 0xe8, 0x02, 0x02, 0x06, 0x00, 0x02, 0x0a, 0x45, 0x08, 0x00, 0x02,
        0x01, 0x01, 0x00, 0x19, 0x46, 0x01, 0x02, 0x07, 0x49, 0x05, 0x03, 0x70, 0x65, 0x31, 0x00,
        0x02, 0x04, 0x40, 0x02, 0x40, 0x78, 0x02, 0x10, 0x47, 0x0e, 0x00, 0x02, 0x01, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x19, 0x46, 0x80, 0x00, 0x00, 0x00,
    ];

    let good = BgpMessage::Update(BgpUpdateMessage::new(
        vec![],
        vec![
            PathAttribute::from(
                true,
                false,
                false,
                true,
                PathAttributeValue::MpReach(MpReach::L2Evpn {
                    next_hop: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 100)),
                    nlri: L2EvpnAddress::new(
                        None,
                        L2EvpnRoute::MacIpAdvertisement(MacIpAdvertisement::new(
                            RouteDistinguisher::Ipv4Administrator {
                                ip: Ipv4Addr::new(172, 16, 0, 100),
                                number: 2,
                            },
                            EthernetSegmentIdentifier([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                            EthernetTag(0),
                            MacAddress([8, 0, 39, 129, 213, 103]),
                            None,
                            MplsLabel::new([0, 0, 111]),
                            None,
                        )),
                    ),
                }),
            )
            .unwrap(),
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
                PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![])),
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
                true,
                false,
                false,
                PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
                    ExtendedCommunity::TransitiveOpaque(
                        TransitiveOpaqueExtendedCommunity::Unassigned {
                            sub_type: 12,
                            value: [0, 0, 0, 0, 0, 8],
                        },
                    ),
                    ExtendedCommunity::TransitiveTwoOctet(
                        TransitiveTwoOctetExtendedCommunity::RouteTarget {
                            global_admin: 1000,
                            local_admin: 111,
                        },
                    ),
                ])),
            )
            .unwrap(),
        ],
        vec![],
    ));

    test_parsed_completely_with_two_inputs(
        &good_wire,
        true,
        &HashMap::from([(AddressType::Ipv6Unicast, true)]),
        &good,
    );
    test_write(&good, &good_wire)?;
    Ok(())
}
