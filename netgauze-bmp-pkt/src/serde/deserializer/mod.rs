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

//! Deserializer library for BMP's wire protocol

use chrono::{LocalResult, TimeZone, Utc};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    string::FromUtf8Error,
};

use netgauze_bgp_pkt::{
    iana::BGPMessageType, serde::deserializer::BGPMessageParsingError, BGPMessage,
};
use netgauze_iana::address_family::{
    AddressFamily, InvalidAddressType, SubsequentAddressFamily, UndefinedAddressFamily,
    UndefinedSubsequentAddressFamily,
};
use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u64, be_u8},
    IResult,
};

use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_till_empty_into_located, ReadablePDU,
    Span,
};
use netgauze_serde_macros::LocatedError;

use crate::{iana::*, *};

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpVersion(#[from_external] UndefinedBmpVersion),
    InvalidBmpLength(u32),
    BmpMessageValueError(#[from_located(module = "self")] BmpMessageValueParsingError),
}

impl<'a> ReadablePDU<'a, LocatedBmpMessageParsingError<'a>> for BmpMessage {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBmpMessageParsingError<'a>> {
        let (buf, version) = nom::combinator::map_res(be_u8, BmpVersion::try_from)(buf)?;
        let input = buf;
        let (buf, length) = be_u32(buf)?;
        let base_length = 5;
        if length < base_length {
            return Err(nom::Err::Error(LocatedBmpMessageParsingError::new(
                input,
                BmpMessageParsingError::InvalidBmpLength(length),
            )));
        }
        let (reminder, buf) = nom::bytes::complete::take(length - 5)(buf)?;

        let (buf, msg) = match version {
            BmpVersion::Version3 => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessage::V3(value))
            }
        };
        // Make sure bmp message is fully parsed according to it's length
        if !buf.is_empty() {
            return Err(nom::Err::Error(LocatedBmpMessageParsingError::new(
                buf,
                BmpMessageParsingError::NomError(ErrorKind::NonEmpty),
            )));
        }
        Ok((reminder, msg))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageValueParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpMessageType(#[from_external] UndefinedBmpMessageType),
    RouteMonitoringMessageError(
        #[from_located(module = "self")] RouteMonitoringMessageParsingError,
    ),
    InitiationMessageError(#[from_located(module = "self")] InitiationMessageParsingError),
    PeerUpNotificationMessageError(
        #[from_located(module = "self")] PeerUpNotificationMessageParsingError,
    ),
    PeerDownNotificationMessageError(
        #[from_located(module = "self")] PeerDownNotificationMessageParsingError,
    ),
    RouteMirroringMessageError(#[from_located(module = "self")] RouteMirroringMessageParsingError),
    TerminationMessageError(#[from_located(module = "self")] TerminationMessageParsingError),
    StatisticsReportMessageError(
        #[from_located(module = "self")] StatisticsReportMessageParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedBmpMessageValueParsingError<'a>> for BmpMessageValue {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBmpMessageValueParsingError<'a>> {
        let (buf, msg_type) = nom::combinator::map_res(be_u8, BmpMessageType::try_from)(buf)?;
        let (buf, msg) = match msg_type {
            BmpMessageType::RouteMonitoring => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessageValue::RouteMonitoring(value))
            }
            BmpMessageType::StatisticsReport => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessageValue::StatisticsReport(value))
            }
            BmpMessageType::PeerDownNotification => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessageValue::PeerDownNotification(value))
            }
            BmpMessageType::PeerUpNotification => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessageValue::PeerUpNotification(value))
            }
            BmpMessageType::Initiation => {
                let (buf, init) = parse_into_located(buf)?;
                (buf, BmpMessageValue::Initiation(init))
            }
            BmpMessageType::Termination => {
                let (buf, init) = parse_into_located(buf)?;
                (buf, BmpMessageValue::Termination(init))
            }
            BmpMessageType::RouteMirroring => {
                let (buf, init) = parse_into_located(buf)?;
                (buf, BmpMessageValue::RouteMirroring(init))
            }
            BmpMessageType::Experimental251 => {
                (buf, BmpMessageValue::Experimental252(buf.to_vec()))
            }
            BmpMessageType::Experimental252 => {
                (buf, BmpMessageValue::Experimental252(buf.to_vec()))
            }
            BmpMessageType::Experimental253 => {
                (buf, BmpMessageValue::Experimental253(buf.to_vec()))
            }
            BmpMessageType::Experimental254 => {
                (buf, BmpMessageValue::Experimental254(buf.to_vec()))
            }
        };
        Ok((buf, msg))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum InitiationMessageParsingError {
    InitiationInformationError(#[from_located(module = "self")] InitiationInformationParsingError),
}

impl<'a> ReadablePDU<'a, LocatedInitiationMessageParsingError<'a>> for InitiationMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedInitiationMessageParsingError<'a>> {
        let (buf, information) = parse_till_empty_into_located(buf)?;
        Ok((buf, InitiationMessage::new(information)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum InitiationInformationParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedType(#[from_external] UndefinedInitiationInformationTlvType),
    FromUtf8Error(#[from_external] FromUtf8Error),
}

impl<'a> ReadablePDU<'a, LocatedInitiationInformationParsingError<'a>> for InitiationInformation {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedInitiationInformationParsingError<'a>> {
        let (buf, tlv_type) =
            nom::combinator::map_res(be_u16, InitiationInformationTlvType::try_from)(buf)?;
        let (buf, length) = be_u16(buf)?;
        let (reminder, buf) = nom::bytes::complete::take(length)(buf)?;
        match tlv_type {
            InitiationInformationTlvType::String => {
                let (_, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(buf)?;
                Ok((reminder, InitiationInformation::String(str)))
            }
            InitiationInformationTlvType::SystemDescription => {
                let (_, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(buf)?;
                Ok((reminder, InitiationInformation::SystemDescription(str)))
            }
            InitiationInformationTlvType::SystemName => {
                let (_, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(buf)?;
                Ok((reminder, InitiationInformation::SystemName(str)))
            }
            InitiationInformationTlvType::VrfTableName => {
                let (_, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(buf)?;
                Ok((reminder, InitiationInformation::VrfTableName(str)))
            }
            InitiationInformationTlvType::AdminLabel => {
                let (_, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(buf)?;
                Ok((reminder, InitiationInformation::AdminLabel(str)))
            }
            InitiationInformationTlvType::Experimental65531 => Ok((
                reminder,
                InitiationInformation::Experimental65531(buf.to_vec()),
            )),
            InitiationInformationTlvType::Experimental65532 => Ok((
                reminder,
                InitiationInformation::Experimental65532(buf.to_vec()),
            )),
            InitiationInformationTlvType::Experimental65533 => Ok((
                reminder,
                InitiationInformation::Experimental65533(buf.to_vec()),
            )),
            InitiationInformationTlvType::Experimental65534 => Ok((
                reminder,
                InitiationInformation::Experimental65534(buf.to_vec()),
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringMessageParsingError {
    RouteMonitoringMessageError(RouteMonitoringMessageError),
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    BgpMessageError(
        #[from_located(module = "netgauze_bgp_pkt::serde::deserializer")] BGPMessageParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedRouteMonitoringMessageParsingError<'a>> for RouteMonitoringMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedRouteMonitoringMessageParsingError<'a>> {
        let (mut buf, peer_header) = parse_into_located(buf)?;
        let input = buf;
        let mut bgp_messages = vec![];
        while !buf.is_empty() {
            let marker = buf;
            let (t, msg): (Span<'_>, BGPMessage) = parse_into_located_one_input(buf, true)?;
            if msg.get_type() != BGPMessageType::Update {
                return Err(nom::Err::Error(
                    LocatedRouteMonitoringMessageParsingError::new(
                        marker,
                        RouteMonitoringMessageParsingError::RouteMonitoringMessageError(
                            RouteMonitoringMessageError::UnexpectedMessageType(msg.get_type()),
                        ),
                    ),
                ));
            }
            bgp_messages.push(msg);
            buf = t;
        }
        match RouteMonitoringMessage::build(peer_header, bgp_messages) {
            Ok(msg) => Ok((buf, msg)),
            Err(err) => Err(nom::Err::Error(
                LocatedRouteMonitoringMessageParsingError::new(
                    input,
                    RouteMonitoringMessageParsingError::RouteMonitoringMessageError(err),
                ),
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BmpPeerTypeParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpPeerTypeCode(#[from_external] UndefinedBmpPeerTypeCode),
}

impl<'a> ReadablePDU<'a, LocatedBmpPeerTypeParsingError<'a>> for BmpPeerType {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBmpPeerTypeParsingError<'a>> {
        let (buf, peer_type_code) =
            nom::combinator::map_res(be_u8, BmpPeerTypeCode::try_from)(buf)?;
        let (buf, flags) = be_u8(buf)?;
        let ipv6 = flags & PEER_FLAGS_IS_IPV6 == PEER_FLAGS_IS_IPV6;
        let post_policy = flags & PEER_FLAGS_IS_POST_POLICY == PEER_FLAGS_IS_POST_POLICY;
        let asn2 = flags & PEER_FLAGS_IS_ASN2 == PEER_FLAGS_IS_ASN2;
        let adj_rib_out = flags & PEER_FLAGS_IS_ADJ_RIB_OUT == PEER_FLAGS_IS_ADJ_RIB_OUT;
        let filtered = flags & PEER_FLAGS_IS_FILTERED == PEER_FLAGS_IS_FILTERED;
        let peer_type = match peer_type_code {
            BmpPeerTypeCode::GlobalInstancePeer => BmpPeerType::GlobalInstancePeer {
                ipv6,
                post_policy,
                asn2,
                adj_rib_out,
            },
            BmpPeerTypeCode::RdInstancePeer => BmpPeerType::RdInstancePeer {
                ipv6,
                post_policy,
                asn2,
                adj_rib_out,
            },
            BmpPeerTypeCode::LocalInstancePeer => BmpPeerType::LocalInstancePeer {
                ipv6,
                post_policy,
                asn2,
                adj_rib_out,
            },
            BmpPeerTypeCode::LocRibInstancePeer => BmpPeerType::LocRibInstancePeer { filtered },
            BmpPeerTypeCode::Experimental251 => BmpPeerType::Experimental251 { flags },
            BmpPeerTypeCode::Experimental252 => BmpPeerType::Experimental252 { flags },
            BmpPeerTypeCode::Experimental253 => BmpPeerType::Experimental253 { flags },
            BmpPeerTypeCode::Experimental254 => BmpPeerType::Experimental254 { flags },
        };
        Ok((buf, peer_type))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum PeerHeaderParsingError {
    NomError(#[from_nom] ErrorKind),
    BmpPeerTypeError(#[from_located(module = "self")] BmpPeerTypeParsingError),
    InvalidTime(u32, u32),
}

impl<'a> ReadablePDU<'a, LocatedPeerHeaderParsingError<'a>> for PeerHeader {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedPeerHeaderParsingError<'a>> {
        let (buf, peer_type) = parse_into_located(buf)?;
        let (buf, distinguisher) = be_u64(buf)?;
        let distinguisher = if distinguisher == 0 {
            None
        } else {
            Some(distinguisher)
        };
        let (buf, peer_address) = be_u128(buf)?;
        let address = if peer_address == 0u128 {
            None
        } else if check_is_ipv6(&peer_type).unwrap_or(true) {
            Some(IpAddr::V6(Ipv6Addr::from(peer_address)))
        } else {
            Some(IpAddr::V4(Ipv4Addr::from(peer_address as u32)))
        };
        let (buf, peer_as) = be_u32(buf)?;
        let (buf, bgp_id) = be_u32(buf)?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        let input = buf;
        let (buf, timestamp_secs) = be_u32(buf)?;
        let (buf, timestamp_micro) = be_u32(buf)?;
        let time = if timestamp_secs != 0 && timestamp_micro != 0 {
            let time_opt = Utc.timestamp_opt(
                timestamp_secs.into(),
                timestamp_micro.checked_mul(1_000).unwrap_or(u32::MAX),
            );
            let time = if let LocalResult::Single(time) = time_opt {
                time
            } else {
                return Err(nom::Err::Error(LocatedPeerHeaderParsingError::new(
                    Span::new(&input),
                    PeerHeaderParsingError::InvalidTime(timestamp_secs, timestamp_micro),
                )));
            };
            Some(time)
        } else {
            None
        };
        let peer_header = PeerHeader::new(peer_type, distinguisher, address, peer_as, bgp_id, time);
        Ok((buf, peer_header))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum PeerUpNotificationMessageParsingError {
    NomError(#[from_nom] ErrorKind),
    PeerUpMessageError(PeerUpNotificationMessageError),
    UnexpectedPeerType(BmpPeerTypeCode),
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    BgpMessageError(
        #[from_located(module = "netgauze_bgp_pkt::serde::deserializer")] BGPMessageParsingError,
    ),
    InitiationInformationError(#[from_located(module = "self")] InitiationInformationParsingError),
}

/// Check if the V flag is enabled in the peer header. Or return error of the
/// peer type that don't have a peer flag defined. Currently, only
/// GlobalInstancePeer, RdInstancePeer, and LocalInstancePeer have V flag
/// defined.
///
/// For experimental we assume ipv6 since this will not fail and still parse all
/// the information
#[inline]
const fn check_is_ipv6(peer_type: &BmpPeerType) -> Result<bool, BmpPeerTypeCode> {
    match peer_type {
        BmpPeerType::GlobalInstancePeer { ipv6, .. } => Ok(*ipv6),
        BmpPeerType::RdInstancePeer { ipv6, .. } => Ok(*ipv6),
        BmpPeerType::LocalInstancePeer { ipv6, .. } => Ok(*ipv6),
        BmpPeerType::LocRibInstancePeer { .. } => Err(peer_type.get_type()),
        BmpPeerType::Experimental251 { .. } => Ok(true),
        BmpPeerType::Experimental252 { .. } => Ok(true),
        BmpPeerType::Experimental253 { .. } => Ok(true),
        BmpPeerType::Experimental254 { .. } => Ok(true),
    }
}

impl<'a> ReadablePDU<'a, LocatedPeerUpNotificationMessageParsingError<'a>>
    for PeerUpNotificationMessage
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedPeerUpNotificationMessageParsingError<'a>> {
        let input = buf;
        let (buf, peer_header): (Span<'_>, PeerHeader) = parse_into_located(buf)?;
        let ipv6 = match check_is_ipv6(&peer_header.peer_type) {
            Ok(ipv6) => ipv6,
            Err(code) => {
                return Err(nom::Err::Error(
                    LocatedPeerUpNotificationMessageParsingError::new(
                        input,
                        PeerUpNotificationMessageParsingError::UnexpectedPeerType(code),
                    ),
                ))
            }
        };
        let (buf, address) = be_u128(buf)?;
        let local_address = if ipv6 {
            IpAddr::V6(Ipv6Addr::from(address))
        } else {
            // the upper bits should be zero and can be ignored
            IpAddr::V4(Ipv4Addr::from(address as u32))
        };
        let (buf, local_port) = be_u16(buf)?;
        let local_port = if local_port == 0 {
            None
        } else {
            Some(local_port)
        };
        let (buf, remote_port) = be_u16(buf)?;
        let remote_port = if remote_port == 0 {
            None
        } else {
            Some(remote_port)
        };
        let (buf, sent_message) = parse_into_located_one_input(buf, true)?;
        let (buf, received_message) = parse_into_located_one_input(buf, true)?;
        let (buf, information) = parse_till_empty_into_located(buf)?;
        let peer_up_msg = PeerUpNotificationMessage::build(
            peer_header,
            local_address,
            local_port,
            remote_port,
            sent_message,
            received_message,
            information,
        );
        match peer_up_msg {
            Ok(msg) => Ok((buf, msg)),
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedPeerUpNotificationMessageParsingError::new(
                        input,
                        PeerUpNotificationMessageParsingError::PeerUpMessageError(err),
                    ),
                ))
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum PeerDownNotificationMessageParsingError {
    PeerDownMessageError(PeerDownNotificationMessageError),
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    PeerDownNotificationReasonError(
        #[from_located(module = "self")] PeerDownNotificationReasonParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedPeerDownNotificationMessageParsingError<'a>>
    for PeerDownNotificationMessage
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedPeerDownNotificationMessageParsingError<'a>> {
        let input = buf;
        let (buf, peer_header) = parse_into_located(buf)?;
        let (buf, reason) = parse_into_located(buf)?;
        let msg = PeerDownNotificationMessage::build(peer_header, reason);
        match msg {
            Ok(msg) => Ok((buf, msg)),
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedPeerDownNotificationMessageParsingError::new(
                        input,
                        PeerDownNotificationMessageParsingError::PeerDownMessageError(err),
                    ),
                ))
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum PeerDownNotificationReasonParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedPeerDownReasonCode(#[from_external] UndefinedPeerDownReasonCode),
    BgpMessageError(
        #[from_located(module = "netgauze_bgp_pkt::serde::deserializer")] BGPMessageParsingError,
    ),
    InitiationInformationError(#[from_located(module = "self")] InitiationInformationParsingError),
}

impl<'a> ReadablePDU<'a, LocatedPeerDownNotificationReasonParsingError<'a>>
    for PeerDownNotificationReason
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedPeerDownNotificationReasonParsingError<'a>> {
        let (buf, reason_code) =
            nom::combinator::map_res(be_u8, PeerDownReasonCode::try_from)(buf)?;
        match reason_code {
            PeerDownReasonCode::LocalSystemClosedNotificationPduFollows => {
                let (buf, msg) = parse_into_located_one_input(buf, true)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::LocalSystemClosedNotificationPduFollows(msg),
                ))
            }
            PeerDownReasonCode::LocalSystemClosedFsmEventFollows => {
                let (buf, value) = be_u16(buf)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(value),
                ))
            }
            PeerDownReasonCode::RemoteSystemClosedNotificationPduFollows => {
                let (buf, msg) = parse_into_located_one_input(buf, true)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::RemoteSystemClosedNotificationPduFollows(msg),
                ))
            }
            PeerDownReasonCode::RemoteSystemClosedNoData => {
                Ok((buf, PeerDownNotificationReason::RemoteSystemClosedNoData))
            }
            PeerDownReasonCode::PeerDeConfigured => {
                Ok((buf, PeerDownNotificationReason::PeerDeConfigured))
            }
            PeerDownReasonCode::LocalSystemClosedTlvDataFollows => {
                let (buf, information) = parse_into_located(buf)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::LocalSystemClosedTlvDataFollows(information),
                ))
            }
            PeerDownReasonCode::Experimental251 => {
                let (buf, data) = nom::bytes::complete::take(buf.len())(buf)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::Experimental251(data.to_vec()),
                ))
            }
            PeerDownReasonCode::Experimental252 => {
                let (buf, data) = nom::bytes::complete::take(buf.len())(buf)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::Experimental252(data.to_vec()),
                ))
            }
            PeerDownReasonCode::Experimental253 => {
                let (buf, data) = nom::bytes::complete::take(buf.len())(buf)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::Experimental253(data.to_vec()),
                ))
            }
            PeerDownReasonCode::Experimental254 => {
                let (buf, data) = nom::bytes::complete::take(buf.len())(buf)?;
                Ok((
                    buf,
                    PeerDownNotificationReason::Experimental254(data.to_vec()),
                ))
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMirroringMessageParsingError {
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    RouteMirroringValueError(#[from_located(module = "self")] RouteMirroringValueParsingError),
}

impl<'a> ReadablePDU<'a, LocatedRouteMirroringMessageParsingError<'a>> for RouteMirroringMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedRouteMirroringMessageParsingError<'a>> {
        let (buf, peer_header) = parse_into_located(buf)?;
        let (buf, mirrored) = parse_till_empty_into_located(buf)?;
        Ok((buf, RouteMirroringMessage::new(peer_header, mirrored)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMirroringValueParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedRouteMirroringTlvType(#[from_external] UndefinedRouteMirroringTlvType),
    UndefinedRouteMirroringInformation(#[from_external] UndefinedRouteMirroringInformation),
    BgpMessageError(
        #[from_located(module = "netgauze_bgp_pkt::serde::deserializer")] BGPMessageParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedRouteMirroringValueParsingError<'a>> for RouteMirroringValue {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedRouteMirroringValueParsingError<'a>> {
        let (buf, code) = nom::combinator::map_res(be_u16, RouteMirroringTlvType::try_from)(buf)?;
        let (_, length): (_, u16) = nom::combinator::peek(be_u16)(buf)?;
        let (reminder, buf) = nom::multi::length_data(be_u16)(buf)?;
        let (buf, value) = match code {
            RouteMirroringTlvType::BgpMessage => {
                let (buf, msg) = parse_into_located_one_input(buf, true)?;
                (buf, RouteMirroringValue::BgpMessage(msg))
            }
            RouteMirroringTlvType::Information => {
                let (buf, information) =
                    nom::combinator::map_res(be_u16, RouteMirroringInformation::try_from)(buf)?;
                (buf, RouteMirroringValue::Information(information))
            }
            RouteMirroringTlvType::Experimental65531 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = RouteMirroringValue::Experimental65531(data.to_vec());
                (buf, value)
            }
            RouteMirroringTlvType::Experimental65532 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = RouteMirroringValue::Experimental65532(data.to_vec());
                (buf, value)
            }
            RouteMirroringTlvType::Experimental65533 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = RouteMirroringValue::Experimental65533(data.to_vec());
                (buf, value)
            }
            RouteMirroringTlvType::Experimental65534 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = RouteMirroringValue::Experimental65534(data.to_vec());
                (buf, value)
            }
        };
        if !buf.is_empty() {
            return Err(nom::Err::Error(
                LocatedRouteMirroringValueParsingError::new(
                    buf,
                    RouteMirroringValueParsingError::NomError(ErrorKind::NonEmpty),
                ),
            ));
        }
        Ok((reminder, value))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum TerminationMessageParsingError {
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    TerminationInformationError(
        #[from_located(module = "self")] TerminationInformationParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedTerminationMessageParsingError<'a>> for TerminationMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTerminationMessageParsingError<'a>> {
        let (buf, peer_header) = parse_into_located(buf)?;
        let (buf, information) = parse_till_empty_into_located(buf)?;
        Ok((buf, TerminationMessage::new(peer_header, information)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum TerminationInformationParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedTerminationInformationTlvType(#[from_external] UndefinedTerminationInformationTlvType),
    UndefinedPeerTerminationCode(#[from_external] UndefinedPeerTerminationCode),
    FromUtf8Error(#[from_external] FromUtf8Error),
}

impl<'a> ReadablePDU<'a, LocatedTerminationInformationParsingError<'a>> for TerminationInformation {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTerminationInformationParsingError<'a>> {
        let (buf, code) =
            nom::combinator::map_res(be_u16, TerminationInformationTlvType::try_from)(buf)?;
        let (_, length): (_, u16) = nom::combinator::peek(be_u16)(buf)?;
        let (reminder, buf) = nom::multi::length_data(be_u16)(buf)?;
        let (buf, value) = match code {
            TerminationInformationTlvType::String => {
                let (buf, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(buf)?;
                (buf, TerminationInformation::String(str))
            }
            TerminationInformationTlvType::Reason => {
                let (buf, reason) =
                    nom::combinator::map_res(be_u16, PeerTerminationCode::try_from)(buf)?;
                (buf, TerminationInformation::Reason(reason))
            }
            TerminationInformationTlvType::Experimental65531 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = TerminationInformation::Experimental65531(data.to_vec());
                (buf, value)
            }
            TerminationInformationTlvType::Experimental65532 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = TerminationInformation::Experimental65532(data.to_vec());
                (buf, value)
            }
            TerminationInformationTlvType::Experimental65533 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = TerminationInformation::Experimental65533(data.to_vec());
                (buf, value)
            }
            TerminationInformationTlvType::Experimental65534 => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                let value = TerminationInformation::Experimental65534(data.to_vec());
                (buf, value)
            }
        };
        if !buf.is_empty() {
            return Err(nom::Err::Error(
                LocatedTerminationInformationParsingError::new(
                    buf,
                    TerminationInformationParsingError::NomError(ErrorKind::NonEmpty),
                ),
            ));
        }
        Ok((reminder, value))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum StatisticsReportMessageParsingError {
    NomError(#[from_nom] ErrorKind),
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    StatisticsCounterError(#[from_located(module = "self")] StatisticsCounterParsingError),
}

impl<'a> ReadablePDU<'a, LocatedStatisticsReportMessageParsingError<'a>>
    for StatisticsReportMessage
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedStatisticsReportMessageParsingError<'a>> {
        let (buf, peer_header) = parse_into_located(buf)?;
        let (mut buf, stats_count) = be_u32(buf)?;
        let mut counters = vec![];
        for _ in 0..stats_count {
            let (t, counter) = parse_into_located(buf)?;
            buf = t;
            counters.push(counter);
        }
        Ok((buf, StatisticsReportMessage::new(peer_header, counters)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum StatisticsCounterParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
}

#[inline]
fn parse_address_type(
    buf: Span<'_>,
) -> IResult<Span<'_>, AddressType, LocatedStatisticsCounterParsingError<'_>> {
    let input = buf;
    let (buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(buf)?;
    let (buf, safi) = nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(buf)?;
    let address_type = match AddressType::from_afi_safi(afi, safi) {
        Ok(address_type) => address_type,
        Err(err) => {
            return Err(nom::Err::Error(LocatedStatisticsCounterParsingError::new(
                input,
                StatisticsCounterParsingError::InvalidAddressType(err),
            )))
        }
    };
    Ok((buf, address_type))
}

impl<'a> ReadablePDU<'a, LocatedStatisticsCounterParsingError<'a>> for StatisticsCounter {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedStatisticsCounterParsingError<'a>> {
        let (buf, code) = be_u16(buf)?;
        let (buf, length) = nom::combinator::peek(be_u16)(buf)?;
        let (reminder, buf) = nom::multi::length_data(be_u16)(buf)?;
        let (buf, counter) = match BmpStatisticsType::try_from(code) {
            Ok(code) => match code {
                BmpStatisticsType::NumberOfPrefixesRejectedByInboundPolicy => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfPrefixesRejectedByInboundPolicy(CounterU32(
                            value,
                        )),
                    )
                }
                BmpStatisticsType::NumberOfDuplicatePrefixAdvertisements => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfDuplicatePrefixAdvertisements(CounterU32(value)),
                    )
                }
                BmpStatisticsType::NumberOfDuplicateWithdraws => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfDuplicateWithdraws(CounterU32(value)),
                    )
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToClusterListLoop => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfUpdatesInvalidatedDueToClusterListLoop(
                            CounterU32(value),
                        ),
                    )
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToAsPathLoop => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsPathLoop(CounterU32(
                            value,
                        )),
                    )
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToOriginatorId => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfUpdatesInvalidatedDueToOriginatorId(CounterU32(
                            value,
                        )),
                    )
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToAsConfederationLoop => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsConfederationLoop(
                            CounterU32(value),
                        ),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInAdjRibIn => {
                    let (buf, value) = be_u64(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInAdjRibIn(GaugeU64(value)),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInLocRib => {
                    let (buf, value) = be_u64(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInLocRib(GaugeU64(value)),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiAdjRibIn => {
                    let (buf, address_type) = parse_address_type(buf)?;
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInPerAfiSafiAdjRibIn(
                            address_type,
                            CounterU32::new(value),
                        ),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiLocRib => {
                    let (buf, address_type) = parse_address_type(buf)?;
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInPerAfiSafiLocRib(
                            address_type,
                            CounterU32::new(value),
                        ),
                    )
                }
                BmpStatisticsType::NumberOfUpdatesSubjectedToTreatAsWithdraw => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfUpdatesSubjectedToTreatAsWithdraw(CounterU32(
                            value,
                        )),
                    )
                }
                BmpStatisticsType::NumberOfPrefixesSubjectedToTreatAsWithdraw => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfPrefixesSubjectedToTreatAsWithdraw(CounterU32(
                            value,
                        )),
                    )
                }
                BmpStatisticsType::NumberOfDuplicateUpdateMessagesReceived => {
                    let (buf, value) = be_u32(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfDuplicateUpdateMessagesReceived(CounterU32(
                            value,
                        )),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInPrePolicyAdjRibOut => {
                    let (buf, value) = be_u64(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInPrePolicyAdjRibOut(GaugeU64(value)),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInPostPolicyAdjRibOut => {
                    let (buf, value) = be_u64(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInPostPolicyAdjRibOut(GaugeU64(value)),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut => {
                    let (buf, address_type) = parse_address_type(buf)?;
                    let (buf, value) = be_u64(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(
                            address_type,
                            GaugeU64::new(value),
                        ),
                    )
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut => {
                    let (buf, address_type) = parse_address_type(buf)?;
                    let (buf, value) = be_u64(buf)?;
                    (
                        buf,
                        StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(
                            address_type,
                            GaugeU64::new(value),
                        ),
                    )
                }
                BmpStatisticsType::Experimental65531 => {
                    let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                    (buf, StatisticsCounter::Experimental65531(data.to_vec()))
                }
                BmpStatisticsType::Experimental65532 => {
                    let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                    (buf, StatisticsCounter::Experimental65532(data.to_vec()))
                }
                BmpStatisticsType::Experimental65533 => {
                    let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                    (buf, StatisticsCounter::Experimental65533(data.to_vec()))
                }
                BmpStatisticsType::Experimental65534 => {
                    let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                    (buf, StatisticsCounter::Experimental65534(data.to_vec()))
                }
            },
            Err(code) => {
                let (buf, data) = nom::bytes::complete::take(length)(buf)?;
                (buf, StatisticsCounter::Unknown(code.0, data.to_vec()))
            }
        };
        if !buf.is_empty() {
            return Err(nom::Err::Error(LocatedStatisticsCounterParsingError::new(
                buf,
                StatisticsCounterParsingError::NomError(ErrorKind::NonEmpty),
            )));
        }
        Ok((reminder, counter))
    }
}
