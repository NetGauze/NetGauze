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
        AddPathAddressFamily, AddPathCapability, BGPCapability, ExtendedNextHopEncoding,
        ExtendedNextHopEncodingCapability, FourOctetASCapability, GracefulRestartCapability,
        MultiProtocolExtensionsCapability, UnrecognizedCapability,
    },
    iana::{
        RouteRefreshSubcode, UndefinedBGPErrorNotificationCode, UndefinedBgpMessageType,
        UndefinedCeaseErrorSubCode, UndefinedRouteRefreshSubcode,
    },
    notification::CeaseError,
    open::{BGPOpenMessageParameter, BGP_VERSION},
    wire::{
        deserializer::{
            notification::{BGPNotificationMessageParsingError, CeaseErrorParsingError},
            route_refresh::BGPRouteRefreshMessageParsingError,
            BGPMessageParsingError, LocatedBGPMessageParsingError,
        },
        serializer::BGPMessageWritingError,
    },
    BGPMessage, BGPNotificationMessage, BGPOpenMessage, BGPRouteRefreshMessage,
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

    let invalid = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &invalid_wire[0..]) },
        BGPMessageParsingError::ConnectionNotSynchronized(0u128),
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
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

    let good = BGPMessage::KeepAlive;
    let open_underflow = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &open_underflow_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(20),
    );
    let open_less_than_min = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &open_less_than_min_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(18),
    );
    let update_less_than_min = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &update_less_than_min_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(18),
    );
    let notification_less_than_min = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &notification_less_than_min_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(18),
    );
    let keepalive_less_than_min = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &keepalive_less_than_min_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(18),
    );
    let route_refresh_less_than_min = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &route_refresh_less_than_min_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(18),
    );

    let overflow = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(19, &overflow_wire[19..]) },
        BGPMessageParsingError::NomError(ErrorKind::NonEmpty),
    );
    let keepalive_overflow_extended = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &keepalive_overflow_extended_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(4097),
    );

    let open_overflow_extended = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(16, &open_overflow_extended_wire[16..]) },
        BGPMessageParsingError::BadMessageLength(4097),
    );

    test_parsed_completely_with_one_input(&good_wire[..], true, &good);
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &open_underflow_wire,
        false,
        &open_underflow,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &open_less_than_min_wire,
        false,
        &open_less_than_min,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &update_less_than_min_wire,
        false,
        &update_less_than_min,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &notification_less_than_min_wire,
        false,
        &notification_less_than_min,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &keepalive_less_than_min_wire,
        false,
        &keepalive_less_than_min,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &route_refresh_less_than_min_wire,
        false,
        &route_refresh_less_than_min,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &overflow_wire,
        false,
        &overflow,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &keepalive_overflow_extended_wire,
        false,
        &keepalive_overflow_extended,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &open_overflow_extended_wire,
        false,
        &open_overflow_extended,
    );
}

#[test]
fn test_bgp_message_undefined_message_type() {
    let invalid_wire = combine(vec![BGP_MARKER, &[0x00, 0x13, 0xff]]);
    let invalid = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(18, &invalid_wire[18..]) },
        BGPMessageParsingError::UndefinedBgpMessageType(UndefinedBgpMessageType(0xff)),
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &invalid_wire,
        true,
        &invalid,
    );
}

#[test]
fn test_bgp_message_open_no_params() -> Result<(), BGPMessageWritingError> {
    let good_no_params_wire = combine(vec![&[BGP_VERSION], MY_AS, HOLD_TIME, BGP_ID, &[0x00u8]]);
    let good_no_params_msg = BGPOpenMessage::new(258, 772, Ipv4Addr::from(4278190081), vec![]);
    test_parsed_completely(&good_no_params_wire, &good_no_params_msg);
    test_write(&good_no_params_msg, &good_no_params_wire)?;
    Ok(())
}

#[test]
fn test_bgp_message_notification() -> Result<(), BGPMessageWritingError> {
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
        BGPMessage::Notification(BGPNotificationMessage::CeaseError(CeaseError::HardReset {
            value: vec![6, 3],
        }));
    let bad_undefined_notif = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(19, &bad_undefined_notif_wire[19..]) },
        BGPMessageParsingError::BGPNotificationMessageParsingError(
            BGPNotificationMessageParsingError::UndefinedBGPErrorNotificationCode(
                UndefinedBGPErrorNotificationCode(0xff),
            ),
        ),
    );
    let bad_undefined_cease = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(20, &bad_undefined_cease_wire[20..]) },
        BGPMessageParsingError::BGPNotificationMessageParsingError(
            BGPNotificationMessageParsingError::CeaseError(CeaseErrorParsingError::Undefined(
                UndefinedCeaseErrorSubCode(0xff),
            )),
        ),
    );

    test_parsed_completely_with_one_input(&good_cease_wire, false, &good_cease);
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &bad_undefined_notif_wire,
        false,
        &bad_undefined_notif,
    );
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &bad_undefined_cease_wire,
        false,
        &bad_undefined_cease,
    );

    test_write(&good_cease, &good_cease_wire)?;
    Ok(())
}

#[test]
fn test_bgp_message_route_refresh() -> Result<(), BGPMessageWritingError> {
    let good_normal_payload_wire = [0x00, 0x01, 0x00, 0x01];
    let good_normal_wire = combine(vec![BGP_MARKER, &[0x00, 23, 5], &good_normal_payload_wire]);
    let bad_payload_wire = [0x00, 0x01, 0xff, 0x01];
    let bad_wire = combine(vec![BGP_MARKER, &[0x00, 23, 5], &bad_payload_wire]);

    let good_normal = BGPMessage::RouteRefresh(BGPRouteRefreshMessage::new(
        AddressType::Ipv4Unicast,
        RouteRefreshSubcode::NormalRequest,
    ));

    let bad = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(21, &bad_wire[21..]) },
        BGPMessageParsingError::BGPRouteRefreshMessageParsingError(
            BGPRouteRefreshMessageParsingError::UndefinedOperation(UndefinedRouteRefreshSubcode(
                255,
            )),
        ),
    );

    test_parsed_completely_with_one_input(&good_normal_wire, false, &good_normal);
    test_parse_error_with_one_input::<BGPMessage, bool, LocatedBGPMessageParsingError<'_>>(
        &bad_wire, false, &bad,
    );
    test_write(&good_normal, &good_normal_wire)?;

    Ok(())
}

#[test]
fn test_bgp_message_open1() -> Result<(), BGPMessageWritingError> {
    let good_wire = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x53, 0x01, 0x04, 0x00, 0x64, 0x00, 0xb4, 0x05, 0x05, 0x05, 0x05, 0x36, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80,
        0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00,
        0x64, 0x02, 0x14, 0x05, 0x12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00, 0x02,
    ];

    let good = BGPMessage::Open(BGPOpenMessage::new(
        100,
        180,
        Ipv4Addr::new(5, 5, 5, 5),
        vec![
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4MplsLabeledVpn),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::Unrecognized(
                UnrecognizedCapability::new(128, vec![]),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::RouteRefresh]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::FourOctetAS(
                FourOctetASCapability::new(100),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::ExtendedNextHopEncoding(
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
fn test_bgp_message_open_multi_protocol() -> Result<(), BGPMessageWritingError> {
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

    let good = BGPMessage::Open(BGPOpenMessage::new(
        200,
        180,
        Ipv4Addr::new(172, 16, 0, 20),
        vec![
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Unicast),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::MultiProtocolExtensions(
                MultiProtocolExtensionsCapability::new(AddressType::Ipv4Multicast),
            )]),
            // Cisco Route Refresh
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::Unrecognized(
                UnrecognizedCapability::new(128, vec![]),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::RouteRefresh]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::EnhancedRouteRefresh]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::FourOctetAS(
                FourOctetASCapability::new(200),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::ExtendedMessage]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::AddPath(
                AddPathCapability::new(vec![
                    AddPathAddressFamily::new(AddressType::Ipv4Unicast, false, true),
                    AddPathAddressFamily::new(AddressType::Ipv4Multicast, false, true),
                ]),
            )]),
            // FQDN
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::Unrecognized(
                UnrecognizedCapability::new(73, vec![0x02, 0x72, 0x32, 0x00]),
            )]),
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::GracefulRestartCapability(
                GracefulRestartCapability::new(true, true, 120, vec![]),
            )]),
            // Long Lived Graceful Restart
            BGPOpenMessageParameter::Capabilities(vec![BGPCapability::Unrecognized(
                UnrecognizedCapability::new(71, vec![0, 1, 1, 128, 0, 0, 0, 0, 1, 2, 128, 0, 0, 0]),
            )]),
        ],
    ));

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
