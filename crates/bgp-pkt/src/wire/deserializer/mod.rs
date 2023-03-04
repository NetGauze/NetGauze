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

//! Deserializer library for BGP's wire protocol

pub mod capabilities;
pub mod community;
pub mod nlri;
pub mod notification;
pub mod open;
pub mod path_attribute;
pub mod route_refresh;
pub mod update;

use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, ErrorKindSerdeDeref, ReadablePdu,
    ReadablePduWithOneInput, ReadablePduWithTwoInputs, Span,
};

use crate::{
    iana::{BgpMessageType, UndefinedBgpMessageType},
    wire::deserializer::{
        notification::BgpNotificationMessageParsingError, open::BgpOpenMessageParsingError,
        route_refresh::BgpRouteRefreshMessageParsingError, update::BgpUpdateMessageParsingError,
    },
    BgpMessage,
};
use netgauze_serde_macros::LocatedError;

/// Min message size in BGP is 19 octets. They're counted from
/// 16-octets synchronization header, 2-octets length, and 1 octet for type.
pub const BGP_MIN_MESSAGE_LENGTH: u16 = 19;

/// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271) defined max length as 4096.
/// *Note*, this only applies to [`BgpMessage::Open`] and
/// [`BgpMessage::KeepAlive`] according to the updated
/// [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654)
pub const BGP_MAX_MESSAGE_LENGTH: u16 = 4096;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4PrefixParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidIpv4PrefixLen(u8),
}

impl<'a> ReadablePdu<'a, LocatedIpv4PrefixParsingError<'a>> for Ipv4Net {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4PrefixParsingError<'a>> {
        let input = buf;
        let (buf, prefix_len) = be_u8(buf)?;
        <Self as ReadablePduWithTwoInputs<u8, Span<'_>, LocatedIpv4PrefixParsingError<'_>>>::from_wire(
            buf, prefix_len, input
        )
    }
}

impl<'a> ReadablePduWithTwoInputs<'a, u8, Span<'a>, LocatedIpv4PrefixParsingError<'a>> for Ipv4Net {
    /// A second version that assumes the prefix length has been read else where
    /// in the message Useful for Labeled VPN NLRI
    fn from_wire(
        buf: Span<'a>,
        prefix_len: u8,
        prefix_location: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv4PrefixParsingError<'a>> {
        // The prefix value must fall into the octet boundary, even if the prefix_len
        // doesn't. For example,
        // prefix_len=24 => prefix_size=24 while prefix_len=19 => prefix_size=24
        let prefix_size = if prefix_len >= u8::MAX - 7 {
            u8::MAX
        } else {
            (prefix_len + 7) / 8
        };
        let (buf, prefix) = nom::bytes::complete::take(prefix_size.min(4))(buf)?;
        // Fill the rest of bits with zeros if
        let mut network = [0; 4];
        prefix.iter().enumerate().for_each(|(i, v)| network[i] = *v);
        let addr = Ipv4Addr::from(network);

        match Ipv4Net::new(addr, prefix_len) {
            Ok(net) => Ok((buf, net)),
            Err(_) => Err(nom::Err::Error(LocatedIpv4PrefixParsingError::new(
                prefix_location,
                Ipv4PrefixParsingError::InvalidIpv4PrefixLen(prefix_len),
            ))),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6PrefixParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidIpv6PrefixLen(u8),
}

impl<'a> ReadablePdu<'a, LocatedIpv6PrefixParsingError<'a>> for Ipv6Net {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6PrefixParsingError<'a>> {
        let input = buf;
        let (buf, prefix_len) = be_u8(buf)?;
        <Self as ReadablePduWithTwoInputs<u8, Span<'_>, LocatedIpv6PrefixParsingError<'_>>>::from_wire(
            buf, prefix_len, input
        )
    }
}

impl<'a> ReadablePduWithTwoInputs<'a, u8, Span<'a>, LocatedIpv6PrefixParsingError<'a>> for Ipv6Net {
    fn from_wire(
        buf: Span<'a>,
        prefix_len: u8,
        prefix_location: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv6PrefixParsingError<'a>> {
        // The prefix value must fall into the octet boundary, even if the prefix_len
        // doesn't. For example,
        // prefix_len=24 => prefix_size=24 while prefix_len=19 => prefix_size=24
        let prefix_size = if prefix_len >= u8::MAX - 7 {
            u8::MAX
        } else {
            (prefix_len + 7) / 8
        };
        let (buf, prefix) = nom::bytes::complete::take(prefix_size.min(16))(buf)?;
        // Fill the rest of bits with zeros if
        let mut network = [0; 16];
        prefix.iter().enumerate().for_each(|(i, v)| network[i] = *v);
        let addr = Ipv6Addr::from(network);

        match Ipv6Net::new(addr, prefix_len) {
            Ok(net) => Ok((buf, net)),
            Err(_) => Err(nom::Err::Error(LocatedIpv6PrefixParsingError::new(
                prefix_location,
                Ipv6PrefixParsingError::InvalidIpv6PrefixLen(prefix_len),
            ))),
        }
    }
}

/// BGP Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),

    /// The first 16-bytes of a BGP message is NOT all set to `1`
    /// For simplicity, we carry the equivalent [`u128`] value that was invalid
    /// instead of the whole buffer
    ConnectionNotSynchronized(u128),

    /// Couldn't recognize the type octet in the BGPMessage, see
    /// [UndefinedBgpMessageType]
    UndefinedBgpMessageType(#[from_external] UndefinedBgpMessageType),

    /// BGP Message length is not in the defined \[min, max\] range for the
    /// given message type
    BadMessageLength(u16),

    BgpOpenMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::open")] BgpOpenMessageParsingError,
    ),

    BgpUpdateMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::update")] BgpUpdateMessageParsingError,
    ),

    BgpNotificationMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::notification")]
        BgpNotificationMessageParsingError,
    ),

    BgpRouteRefreshMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::route_refresh")]
        BgpRouteRefreshMessageParsingError,
    ),
}

/// Parse [`BgpMessage`] length and type, then check that the length of a BGP
/// message is valid according to it's type. Takes into consideration both rules at [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
/// and [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654).
fn parse_bgp_message_length_and_type(
    buf: Span<'_>,
) -> IResult<Span<'_>, (u16, BgpMessageType, Span<'_>), LocatedBgpMessageParsingError<'_>> {
    let pre_len_buf = buf;
    let (buf, length) = be_u16(buf)?;

    // Fail early if the message length is not valid
    if length < BGP_MIN_MESSAGE_LENGTH {
        return Err(nom::Err::Error(LocatedBgpMessageParsingError::new(
            pre_len_buf,
            BgpMessageParsingError::BadMessageLength(length),
        )));
    }

    // Only read the subset that is defined by the length
    // Check the message size before doing any math on it
    let reminder_result = nom::bytes::complete::take::<
        u16,
        Span<'_>,
        LocatedBgpMessageParsingError<'_>,
    >(length - 18)(buf);
    let (reminder_buf, buf) = match reminder_result {
        Ok((reminder_buf, buf)) => (reminder_buf, buf),
        Err(_) => {
            return Err(nom::Err::Error(LocatedBgpMessageParsingError::new(
                pre_len_buf,
                BgpMessageParsingError::BadMessageLength(length),
            )));
        }
    };
    let (buf, message_type) = nom::combinator::map_res(be_u8, BgpMessageType::try_from)(buf)?;

    match message_type {
        BgpMessageType::Open | BgpMessageType::KeepAlive => {
            if !(BGP_MIN_MESSAGE_LENGTH..=BGP_MAX_MESSAGE_LENGTH).contains(&length) {
                return Err(nom::Err::Error(LocatedBgpMessageParsingError::new(
                    pre_len_buf,
                    BgpMessageParsingError::BadMessageLength(length),
                )));
            }
        }
        BgpMessageType::Update | BgpMessageType::Notification | BgpMessageType::RouteRefresh => {}
    }
    Ok((buf, (length, message_type, reminder_buf)))
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedBgpMessageParsingError<'a>> for BgpMessage {
    fn from_wire(
        buf: Span<'a>,
        asn4: bool,
    ) -> IResult<Span<'a>, Self, LocatedBgpMessageParsingError<'a>> {
        let (buf, _) = nom::combinator::map_res(be_u128, |x| {
            if x == u128::MAX {
                Ok(x)
            } else {
                Err(BgpMessageParsingError::ConnectionNotSynchronized(x))
            }
        })(buf)?;

        // Parse both length and type together, since we need to do input validation on
        // the length based on the type of the message
        let (buf, (_, message_type, reminder_buf)) = parse_bgp_message_length_and_type(buf)?;
        let (buf, msg) = match message_type {
            BgpMessageType::Open => {
                let (buf, open) = parse_into_located(buf)?;
                (buf, BgpMessage::Open(open))
            }
            BgpMessageType::Update => {
                let (buf, update) = parse_into_located_one_input(buf, asn4)?;
                (buf, BgpMessage::Update(update))
            }
            BgpMessageType::Notification => {
                let (buf, notification) = parse_into_located(buf)?;
                (buf, BgpMessage::Notification(notification))
            }
            BgpMessageType::KeepAlive => (buf, BgpMessage::KeepAlive),
            BgpMessageType::RouteRefresh => {
                let (buf, route_refresh) = parse_into_located(buf)?;
                (buf, BgpMessage::RouteRefresh(route_refresh))
            }
        };

        // Make sure we consumed the full BGP message as specified by its length
        if !buf.is_empty() {
            return Err(nom::Err::Error(LocatedBgpMessageParsingError::new(
                buf,
                BgpMessageParsingError::NomError(ErrorKind::NonEmpty),
            )));
        }
        Ok((reminder_buf, msg))
    }
}
