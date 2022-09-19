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
pub mod notification;
pub mod open;
pub mod path_attribute;
pub mod route_refresh;
pub mod update;

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u128, be_u16, be_u8},
    IResult,
};

use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, IntoLocatedError, LocatedParsingError,
    ReadablePDUWithOneInput, Span,
};

use crate::{
    iana::{BGPMessageType, UndefinedBgpMessageType},
    serde::deserializer::{
        notification::BGPNotificationMessageParsingError,
        open::BGPOpenMessageParsingError,
        route_refresh::BGPRouteRefreshMessageParsingError,
        update::{
            BGPUpdateMessageParsingError, LocatedNetworkLayerReachabilityInformationParsingError,
            LocatedWithdrawRouteParsingError, NetworkLayerReachabilityInformationParsingError,
            WithdrawRouteParsingError,
        },
    },
    BGPMessage,
};

/// Min message size in BGP is 19 octets. They're counted from
/// 16-octets synchronization header, 2-octets length, and 1 octet for type.
pub const BGP_MIN_MESSAGE_LENGTH: u16 = 19;

/// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271) defined max length as 4096.
/// *Note*, this only applies to [BGPMessage::Open] and [BGPMessage::KeepAlive]
/// according to the updated
/// [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654)
pub const BGP_MAX_MESSAGE_LENGTH: u16 = 4096;

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Ipv4PrefixParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidIpv4PrefixLen(u8),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedIpv4PrefixParsingError<'a> {
    span: Span<'a>,
    error: Ipv4PrefixParsingError,
}

impl<'a> LocatedIpv4PrefixParsingError<'a> {
    pub const fn new(span: Span<'a>, error: Ipv4PrefixParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedIpv4PrefixParsingError<'a> {
    type Span = Span<'a>;
    type Error = Ipv4PrefixParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedWithdrawRouteParsingError<'a>>
    for LocatedIpv4PrefixParsingError<'a>
{
    fn into_located(self) -> LocatedWithdrawRouteParsingError<'a> {
        LocatedWithdrawRouteParsingError::new(
            self.span,
            WithdrawRouteParsingError::Ipv4PrefixParsingError(self.error),
        )
    }
}

impl<'a> IntoLocatedError<LocatedNetworkLayerReachabilityInformationParsingError<'a>>
    for LocatedIpv4PrefixParsingError<'a>
{
    fn into_located(self) -> LocatedNetworkLayerReachabilityInformationParsingError<'a> {
        LocatedNetworkLayerReachabilityInformationParsingError::new(
            self.span,
            NetworkLayerReachabilityInformationParsingError::Ipv4PrefixParsingError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedIpv4PrefixParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedIpv4PrefixParsingError::new(input, Ipv4PrefixParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

/// Parse IPv4 prefix
pub(crate) fn ipv4_network_from_wire(
    buf: Span<'_>,
) -> IResult<Span<'_>, Ipv4Net, LocatedIpv4PrefixParsingError<'_>> {
    let input = buf;
    let (buf, prefix_len) = be_u8(buf)?;
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
            input,
            Ipv4PrefixParsingError::InvalidIpv4PrefixLen(prefix_len),
        ))),
    }
}

/// BGP Message Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),

    /// The first 16-bytes of a BGP message is NOT all set to `1`
    /// For simplicity, we carry the equivalent [u128] value that was invalid
    /// instead of the whole buffer
    ConnectionNotSynchronized(u128),

    /// Couldn't recognize the type octet in the BGPMessage, see
    /// [UndefinedBgpMessageType]
    UndefinedBgpMessageType(UndefinedBgpMessageType),

    /// BGP Message length is not in the defined \[min, max\] range for the
    /// given message type
    BadMessageLength(u16),

    BGPOpenMessageParsingError(BGPOpenMessageParsingError),

    BGPUpdateMessageParsingError(BGPUpdateMessageParsingError),

    BGPNotificationMessageParsingError(BGPNotificationMessageParsingError),

    BGPRouteRefreshMessageParsingError(BGPRouteRefreshMessageParsingError),
}

/// BGP Message Parsing errors  with the input location of where it occurred in
/// the input byte stream being parsed
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPMessageParsingError<'a> {
    span: Span<'a>,
    error: BGPMessageParsingError,
}

impl<'a> LocatedBGPMessageParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPMessageParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedBGPMessageParsingError<'a> {
    type Span = Span<'a>;
    type Error = BGPMessageParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedBGPMessageParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedBGPMessageParsingError::new(input, BGPMessageParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, BGPMessageParsingError> for LocatedBGPMessageParsingError<'a> {
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPMessageParsingError,
    ) -> Self {
        LocatedBGPMessageParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedBgpMessageType>
    for LocatedBGPMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedBgpMessageType,
    ) -> Self {
        LocatedBGPMessageParsingError::new(
            input,
            BGPMessageParsingError::UndefinedBgpMessageType(error),
        )
    }
}

/// Parse [BGPMessage] length and type, then check that the length of a BGP
/// message is valid according to it's type. Takes into consideration both rules at [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
/// and [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654).
fn parse_bgp_message_length_and_type<'a>(
    buf: Span<'a>,
) -> IResult<Span<'a>, (u16, BGPMessageType, Span<'a>), LocatedBGPMessageParsingError<'_>> {
    let pre_len_buf = buf;
    let (buf, length) = be_u16(buf)?;

    // Fail early if the message length is not valid
    if length < BGP_MIN_MESSAGE_LENGTH {
        return Err(nom::Err::Error(LocatedBGPMessageParsingError::new(
            pre_len_buf,
            BGPMessageParsingError::BadMessageLength(length),
        )));
    }

    // Only read the subset that is defined by the length
    // Check the message size before doing any math on it
    let reminder_result = nom::bytes::complete::take::<
        u16,
        Span<'_>,
        LocatedBGPMessageParsingError<'_>,
    >(length - 18)(buf);
    let (reminder_buf, buf) = match reminder_result {
        Ok((reminder_buf, buf)) => (reminder_buf, buf),
        Err(_) => {
            return Err(nom::Err::Error(LocatedBGPMessageParsingError::new(
                pre_len_buf,
                BGPMessageParsingError::BadMessageLength(length),
            )));
        }
    };
    let (buf, message_type) = nom::combinator::map_res(be_u8, BGPMessageType::try_from)(buf)?;

    match message_type {
        BGPMessageType::Open | BGPMessageType::KeepAlive => {
            if !(BGP_MIN_MESSAGE_LENGTH..=BGP_MAX_MESSAGE_LENGTH).contains(&length) {
                return Err(nom::Err::Error(LocatedBGPMessageParsingError::new(
                    pre_len_buf,
                    BGPMessageParsingError::BadMessageLength(length),
                )));
            }
        }
        BGPMessageType::Update | BGPMessageType::Notification | BGPMessageType::RouteRefresh => {}
    }
    Ok((buf, (length, message_type, reminder_buf)))
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedBGPMessageParsingError<'a>> for BGPMessage {
    fn from_wire(
        buf: Span<'a>,
        asn4: bool,
    ) -> IResult<Span<'a>, Self, LocatedBGPMessageParsingError<'a>> {
        let (buf, _) = nom::combinator::map_res(be_u128, |x| {
            if x == u128::MAX {
                Ok(x)
            } else {
                Err(BGPMessageParsingError::ConnectionNotSynchronized(x))
            }
        })(buf)?;

        // Parse both length and type together, since we need to do input validation on
        // the length based on the type of the message
        let (buf, (_, message_type, reminder_buf)) = parse_bgp_message_length_and_type(buf)?;
        let (buf, msg) = match message_type {
            BGPMessageType::Open => {
                let (buf, open) = parse_into_located(buf)?;
                (buf, BGPMessage::Open(open))
            }
            BGPMessageType::Update => {
                let (buf, update) = parse_into_located_one_input(buf, asn4)?;
                (buf, BGPMessage::Update(update))
            }
            BGPMessageType::Notification => {
                let (buf, notification) = parse_into_located(buf)?;
                (buf, BGPMessage::Notification(notification))
            }
            BGPMessageType::KeepAlive => (buf, BGPMessage::KeepAlive),
            BGPMessageType::RouteRefresh => {
                let (buf, route_refresh) = parse_into_located(buf)?;
                (buf, BGPMessage::RouteRefresh(route_refresh))
            }
        };

        // Make sure we consumed the full BGP message as specified by its length
        if !buf.is_empty() {
            return Err(nom::Err::Error(LocatedBGPMessageParsingError::new(
                buf,
                BGPMessageParsingError::NomError(ErrorKind::NonEmpty),
            )));
        }
        Ok((reminder_buf, msg))
    }
}
