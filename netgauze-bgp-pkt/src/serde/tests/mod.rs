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
    iana::UndefinedBgpMessageType,
    open::BGP_VERSION,
    serde::{
        deserializer::{BGPMessageParsingError, LocatedBGPMessageParsingError},
        serializer::BGPMessageWritingError,
    },
    BGPMessage, BGPOpenMessage,
};
use netgauze_parse_utils::{
    test_helpers::{combine, test_parse_error, test_parsed_completely, test_write},
    Span,
};
use nom::error::ErrorKind;
use std::net::Ipv4Addr;

mod capabilities;
mod keepalive;
mod open;
mod path_attribute;
mod update;

pub(crate) const BGP_MARKER: &'static [u8] = &[0xff; 16];
pub(crate) const MY_AS: &'static [u8] = &[0x01, 0x02];
pub(crate) const HOLD_TIME: &'static [u8] = &[0x03, 0x04];
pub(crate) const BGP_ID: &'static [u8] = &[0xFF, 0x00, 0x00, 0x01];

#[test]
fn test_bgp_message_not_synchronized_marker() {
    let bad_marker = [0x00; 16];
    let invalid_wire = combine(vec![&bad_marker, &[0x00, 0x13, 0x04]]);

    let invalid = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &invalid_wire[0..]) },
        BGPMessageParsingError::ConnectionNotSynchronized(0u128),
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(&invalid_wire, &invalid);
}

#[test]
fn test_bgp_message_length_bounds() {
    // The shortest message is a keepalive message to test with
    let good_wire = combine(vec![&BGP_MARKER, &[0x00, 0x13, 0x04]]);

    // Available input is less than the stated input in the message
    let open_underflow_wire = combine(vec![&BGP_MARKER, &[0x00, 0x14, 0x01]]);

    // The length is less the min BGP length
    let open_less_than_min_wire = combine(vec![&BGP_MARKER, &[0x00, 0x12, 0x01]]);
    let update_less_than_min_wire = combine(vec![&BGP_MARKER, &[0x00, 0x12, 0x02]]);
    let notification_less_than_min_wire = combine(vec![&BGP_MARKER, &[0x00, 0x12, 0x03]]);
    let keepalive_less_than_min_wire = combine(vec![&BGP_MARKER, &[0x00, 0x12, 0x04]]);
    let route_refresh_less_than_min_wire = combine(vec![&BGP_MARKER, &[0x00, 0x12, 0x05]]);

    // The message length contains more data than is actually parsed
    let overflow_wire = combine(vec![&BGP_MARKER, &[0x00, 0x14, 0x04, 0x00]]);

    // Using length more than 4,096 for keepalive message
    let keepalive_overflow_extended_wire =
        combine(vec![&BGP_MARKER, &[0x10, 0x01, 0x04], &[0x00; 0x0fee]]);

    // Using length more than 4,096 for keepalive message
    let open_overflow_extended_wire =
        combine(vec![&BGP_MARKER, &[0x10, 0x01, 0x01], &[0x00; 0x0fee]]);

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

    test_parsed_completely(&good_wire[..], &good);
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &open_underflow_wire,
        &open_underflow,
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &open_less_than_min_wire,
        &open_less_than_min,
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &update_less_than_min_wire,
        &update_less_than_min,
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &notification_less_than_min_wire,
        &notification_less_than_min,
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &keepalive_less_than_min_wire,
        &keepalive_less_than_min,
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &route_refresh_less_than_min_wire,
        &route_refresh_less_than_min,
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(&overflow_wire, &overflow);
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &keepalive_overflow_extended_wire,
        &keepalive_overflow_extended,
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(
        &open_overflow_extended_wire,
        &open_overflow_extended,
    );
}

#[test]
fn test_bgp_message_undefined_message_type() {
    let invalid_wire = combine(vec![&BGP_MARKER, &[0x00, 0x13, 0xff]]);
    let invalid = LocatedBGPMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(18, &invalid_wire[18..]) },
        BGPMessageParsingError::UndefinedBgpMessageType(UndefinedBgpMessageType(0xff)),
    );
    test_parse_error::<BGPMessage, LocatedBGPMessageParsingError<'_>>(&invalid_wire, &invalid);
}

#[test]
fn test_bgp_message_open_no_params() -> Result<(), BGPMessageWritingError> {
    let good_no_params_wire = combine(vec![&[BGP_VERSION], MY_AS, HOLD_TIME, BGP_ID, &[0x00u8]]);
    let good_no_params_msg = BGPOpenMessage::new(258, 772, Ipv4Addr::from(4278190081), vec![]);
    test_parsed_completely(&good_no_params_wire, &good_no_params_msg);
    test_write(&good_no_params_msg, &good_no_params_wire)?;
    Ok(())
}
