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
    capabilities::{
        AddPathAddressFamily, AddPathCapability, BgpCapability, ExtendedNextHopEncoding,
        ExtendedNextHopEncodingCapability, FourOctetAsCapability, GracefulRestartCapability,
        MultiProtocolExtensionsCapability, UnrecognizedCapability,
    },
    iana::{
        RouteRefreshSubcode, UndefinedBgpErrorNotificationCode, UndefinedBgpMessageType,
        UndefinedCeaseErrorSubCode, UndefinedRouteRefreshSubcode,
    },
    notification::CeaseError,
    open::{BgpOpenMessageParameter, BGP_VERSION},
    wire::{
        deserializer::{
            notification::{BgpNotificationMessageParsingError, CeaseErrorParsingError},
            route_refresh::BgpRouteRefreshMessageParsingError,
            BgpMessageParsingError, LocatedBgpMessageParsingError,
        },
        serializer::BgpMessageWritingError,
    },
    BgpOpenMessage, BgpMessage, BgpNotificationMessage, BgpRouteRefreshMessage,
};
use netgauze_iana::address_family::{AddressFamily, AddressType};
use netgauze_parse_utils::{
    test_helpers::{
        combine, test_parse_error_with_one_input, test_parsed_completely,
        test_parsed_completely_with_one_input, test_write,
    },
    Span,
};
use nom::error::ErrorKind;
use std::net::Ipv4Addr;

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
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &invalid_wire,
        false,
        &invalid,
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

    test_parsed_completely_with_one_input(&good_wire[..], true, &good);
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &open_underflow_wire,
        false,
        &open_underflow,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &open_less_than_min_wire,
        false,
        &open_less_than_min,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &update_less_than_min_wire,
        false,
        &update_less_than_min,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &notification_less_than_min_wire,
        false,
        &notification_less_than_min,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &keepalive_less_than_min_wire,
        false,
        &keepalive_less_than_min,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &route_refresh_less_than_min_wire,
        false,
        &route_refresh_less_than_min,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &overflow_wire,
        false,
        &overflow,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &keepalive_overflow_extended_wire,
        false,
        &keepalive_overflow_extended,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &open_overflow_extended_wire,
        false,
        &open_overflow_extended,
    );
}

#[test]
fn test_bgp_message_undefined_message_type() {
    let invalid_wire = combine(vec![BGP_MARKER, &[0x00, 0x13, 0xff]]);
    let invalid = LocatedBgpMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(18, &invalid_wire[18..]) },
        BgpMessageParsingError::UndefinedBgpMessageType(UndefinedBgpMessageType(0xff)),
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &invalid_wire,
        true,
        &invalid,
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

    test_parsed_completely_with_one_input(&good_cease_wire, false, &good_cease);
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &bad_undefined_notif_wire,
        false,
        &bad_undefined_notif,
    );
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &bad_undefined_cease_wire,
        false,
        &bad_undefined_cease,
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

    test_parsed_completely_with_one_input(&good_normal_wire, false, &good_normal);
    test_parse_error_with_one_input::<BgpMessage, bool, LocatedBgpMessageParsingError<'_>>(
        &bad_wire, false, &bad,
    );
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

    test_parsed_completely_with_one_input(&good_wire, false, &good);
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

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
