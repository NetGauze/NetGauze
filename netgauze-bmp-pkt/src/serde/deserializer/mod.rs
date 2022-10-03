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

use chrono::{TimeZone, Utc};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    string::FromUtf8Error,
};

use netgauze_bgp_pkt::{serde::deserializer::BGPMessageParsingError, BGPMessage};
use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u64, be_u8},
    IResult,
};

use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_till_empty_into_located,
    parse_till_empty_into_with_one_input_located, ReadablePDU, Span,
};
use netgauze_serde_macros::LocatedError;

use crate::{
    iana::{
        BmpMessageType, InitiationInformationTlvType, UndefinedBmpMessageType,
        UndefinedBmpPeerTypeCode, UndefinedInitiationInformationTlvType, BMP_VERSION,
        PEER_FLAGS_IS_ADJ_RIB_OUT, PEER_FLAGS_IS_ASN2, PEER_FLAGS_IS_FILTERED, PEER_FLAGS_IS_IPV6,
        PEER_FLAGS_IS_POST_POLICY,
    },
    BmpMessage, BmpPeerType, BmpPeerTypeCode, InitiationInformation, InitiationMessage, PeerHeader,
    PeerUpNotificationMessage, PeerUpNotificationMessageError, RouteMonitoringMessage,
};

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageParsingError {
    NomError(#[from_nom] ErrorKind),
    UnsupportedBmpVersion(u8),
    UndefinedBmpMessageType(#[from_external] UndefinedBmpMessageType),
    UndefinedPeerType(#[from_external] UndefinedBmpPeerTypeCode),
    RouteMonitoringMessageError(
        #[from_located(module = "self")] RouteMonitoringMessageParsingError,
    ),
    InitiationMessageError(#[from_located(module = "self")] InitiationMessageParsingError),
    PeerUpNotificationMessageError(
        #[from_located(module = "self")] PeerUpNotificationMessageParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedBmpMessageParsingError<'a>> for BmpMessage {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBmpMessageParsingError<'a>> {
        let input = buf;
        let (buf, version) = be_u8(buf)?;
        if version != BMP_VERSION {
            return Err(nom::Err::Error(LocatedBmpMessageParsingError::new(
                input,
                BmpMessageParsingError::UnsupportedBmpVersion(version),
            )));
        }
        let (buf, length) = be_u32(buf)?;
        let (reminder, buf) = nom::bytes::complete::take(length - 5)(buf)?;
        let (buf, msg_type) = nom::combinator::map_res(be_u8, BmpMessageType::try_from)(buf)?;
        let (buf, msg) = match msg_type {
            BmpMessageType::RouteMonitoring => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessage::RouteMonitoring(value))
            }
            BmpMessageType::StatisticsReport => todo!(),
            BmpMessageType::PeerDownNotification => todo!(),
            BmpMessageType::PeerUpNotification => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessage::PeerUpNotification(value))
            }
            BmpMessageType::Initiation => {
                let (buf, init) = parse_into_located(buf)?;
                (buf, BmpMessage::Initiation(init))
            }
            BmpMessageType::Termination => todo!(),
            BmpMessageType::RouteMirroring => todo!(),
            BmpMessageType::Experimental251 => (buf, BmpMessage::Experimental251(buf.to_vec())),
            BmpMessageType::Experimental252 => (buf, BmpMessage::Experimental252(buf.to_vec())),
            BmpMessageType::Experimental253 => (buf, BmpMessage::Experimental253(buf.to_vec())),
            BmpMessageType::Experimental254 => (buf, BmpMessage::Experimental254(buf.to_vec())),
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
pub enum InitiationMessageParsingError {
    NomError(#[from_nom] ErrorKind),
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
    FromUtf8Error(FromUtf8Error),
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
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
                Ok((reminder, InitiationInformation::String(str)))
            }
            InitiationInformationTlvType::SystemDescription => {
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
                Ok((reminder, InitiationInformation::SystemDescription(str)))
            }
            InitiationInformationTlvType::SystemName => {
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
                Ok((reminder, InitiationInformation::SystemName(str)))
            }
            InitiationInformationTlvType::VrfTableName => {
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
                Ok((reminder, InitiationInformation::VrfTableName(str)))
            }
            InitiationInformationTlvType::AdminLabel => {
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
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
    NomError(#[from_nom] ErrorKind),
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    BgpMessageError(
        #[from_located(module = "netgauze_bgp_pkt::serde::deserializer")] BGPMessageParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedRouteMonitoringMessageParsingError<'a>> for RouteMonitoringMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedRouteMonitoringMessageParsingError<'a>> {
        let (buf, peer_header) = parse_into_located(buf)?;
        let (buf, bgp_messages): (Span<'a>, Vec<BGPMessage>) =
            parse_till_empty_into_with_one_input_located(buf, true)?;
        let mut updates = vec![];
        for msg in bgp_messages {
            match msg {
                BGPMessage::Open(_) => {}
                BGPMessage::Update(update) => {
                    updates.push(update);
                }
                BGPMessage::Notification(_) => {}
                BGPMessage::KeepAlive => {}
                BGPMessage::RouteRefresh(_) => {}
            }
        }
        Ok((buf, RouteMonitoringMessage::new(peer_header, updates)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum PeerHeaderParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpPeerTypeCode(#[from_external] UndefinedBmpPeerTypeCode),
}

impl<'a> ReadablePDU<'a, LocatedPeerHeaderParsingError<'a>> for PeerHeader {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedPeerHeaderParsingError<'a>> {
        let (buf, peer_type) = nom::combinator::map_res(be_u8, BmpPeerTypeCode::try_from)(buf)?;
        let (buf, peer_flags) = be_u8(buf)?;
        let ipv6 = peer_flags & PEER_FLAGS_IS_IPV6 == PEER_FLAGS_IS_IPV6;
        let post_policy = peer_flags & PEER_FLAGS_IS_POST_POLICY == PEER_FLAGS_IS_POST_POLICY;
        let asn2 = peer_flags & PEER_FLAGS_IS_ASN2 == PEER_FLAGS_IS_ASN2;
        let adj_rib_out = peer_flags & PEER_FLAGS_IS_ADJ_RIB_OUT == PEER_FLAGS_IS_ADJ_RIB_OUT;
        let filtered = peer_flags & PEER_FLAGS_IS_FILTERED == PEER_FLAGS_IS_FILTERED;
        let (buf, distinguisher) = be_u64(buf)?;
        let distinguisher = if distinguisher == 0 {
            None
        } else {
            Some(distinguisher)
        };
        let (buf, peer_address) = be_u128(buf)?;
        let address = if peer_address == 0u128 {
            None
        } else if ipv6 {
            Some(IpAddr::V6(Ipv6Addr::from(peer_address)))
        } else {
            Some(IpAddr::V4(Ipv4Addr::from(peer_address as u32)))
        };
        let (buf, peer_as) = be_u32(buf)?;
        let (buf, bgp_id) = be_u32(buf)?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        let (buf, timestamp_secs) = be_u32(buf)?;
        let (buf, timestamp_milli) = be_u32(buf)?;
        let time = if timestamp_secs != 0 && timestamp_milli != 0 {
            Some(Utc.timestamp(timestamp_secs.into(), timestamp_milli * 1000))
        } else {
            None
        };
        let peer_header = match peer_type {
            BmpPeerTypeCode::GlobalInstancePeer => PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6,
                    post_policy,
                    asn2,
                    adj_rib_out,
                },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::RdInstancePeer => PeerHeader::new(
                BmpPeerType::RdInstancePeer {
                    ipv6,
                    post_policy,
                    asn2,
                    adj_rib_out,
                },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::LocalInstancePeer => PeerHeader::new(
                BmpPeerType::LocalInstancePeer {
                    ipv6,
                    post_policy,
                    asn2,
                    adj_rib_out,
                },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::LocRibInstancePeer => PeerHeader::new(
                BmpPeerType::LocRibInstancePeer { filtered },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::Experimental251 => PeerHeader::new(
                BmpPeerType::Experimental251 { flags: peer_flags },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::Experimental252 => PeerHeader::new(
                BmpPeerType::Experimental252 { flags: peer_flags },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::Experimental253 => PeerHeader::new(
                BmpPeerType::Experimental253 { flags: peer_flags },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::Experimental254 => PeerHeader::new(
                BmpPeerType::Experimental254 { flags: peer_flags },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
        };
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
const fn check_is_ipv6(peer_header: &PeerHeader) -> Result<bool, BmpPeerTypeCode> {
    match peer_header.peer_type {
        BmpPeerType::GlobalInstancePeer { ipv6, .. } => Ok(ipv6),
        BmpPeerType::RdInstancePeer { ipv6, .. } => Ok(ipv6),
        BmpPeerType::LocalInstancePeer { ipv6, .. } => Ok(ipv6),
        BmpPeerType::LocRibInstancePeer { .. } => Err(peer_header.peer_type.get_type()),
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
        let ipv6 = match check_is_ipv6(&peer_header) {
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
