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

use chrono::{LocalResult, TimeZone, Utc};

use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::iana::BgpMessageType;
use netgauze_bgp_pkt::nlri::RouteDistinguisher;
use netgauze_bgp_pkt::wire::deserializer::nlri::RouteDistinguisherParsingError;
use netgauze_bgp_pkt::wire::deserializer::{BgpMessageParsingError, BgpParsingContext};
use netgauze_iana::address_family::{AddressFamily, AddressType, SubsequentAddressFamily};

use crate::iana::*;
use crate::wire::deserializer::{BmpParsingContext, count_tlvs_t16_l16};
use crate::{BmpPeerType, CounterU32, GaugeU64, PeerHeader, PeerKey, v3};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BmpMessageValueParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown BMP message type {code} at byte offset {offset}")]
    UndefinedBmpMessageType { offset: usize, code: u8 },

    #[error("in route monitoring message: {0}")]
    RouteMonitoringMessageError(#[from] RouteMonitoringMessageParsingError),

    #[error("in initiation message: {0}")]
    InitiationMessageError(#[from] InitiationMessageParsingError),

    #[error("in peer-up notification message: {0}")]
    PeerUpNotificationMessageError(#[from] PeerUpNotificationMessageParsingError),

    #[error("in peer-down notification message: {0}")]
    PeerDownNotificationMessageError(#[from] PeerDownNotificationMessageParsingError),

    #[error("in route mirroring message: {0}")]
    RouteMirroringMessageError(#[from] RouteMirroringMessageParsingError),

    #[error("in termination message: {0}")]
    TerminationMessageError(#[from] TerminationMessageParsingError),

    #[error("in statistics report message: {0}")]
    StatisticsReportMessageError(#[from] StatisticsReportMessageParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v3::BmpMessageValue {
    type Error = BmpMessageValueParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let msg_type = cur.read_u8()?;
        let msg_type = match BmpMessageType::from_repr(msg_type) {
            Some(msg_type) => msg_type,
            None => {
                return Err(BmpMessageValueParsingError::UndefinedBmpMessageType {
                    offset: cur.offset() - 1,
                    code: msg_type,
                });
            }
        };
        let msg = match msg_type {
            BmpMessageType::RouteMonitoring => {
                let value = v3::RouteMonitoringMessage::parse(cur, ctx)?;
                v3::BmpMessageValue::RouteMonitoring(value)
            }
            BmpMessageType::StatisticsReport => {
                let value = v3::StatisticsReportMessage::parse(cur)?;
                v3::BmpMessageValue::StatisticsReport(value)
            }
            BmpMessageType::PeerDownNotification => {
                let value = v3::PeerDownNotificationMessage::parse(cur, ctx)?;
                v3::BmpMessageValue::PeerDownNotification(value)
            }
            BmpMessageType::PeerUpNotification => {
                let value = v3::PeerUpNotificationMessage::parse(cur, ctx)?;
                v3::BmpMessageValue::PeerUpNotification(value)
            }
            BmpMessageType::Initiation => {
                let init = v3::InitiationMessage::parse(cur)?;
                v3::BmpMessageValue::Initiation(init)
            }
            BmpMessageType::Termination => {
                let terminate = v3::TerminationMessage::parse(cur)?;
                v3::BmpMessageValue::Termination(terminate)
            }
            BmpMessageType::RouteMirroring => {
                let value = v3::RouteMirroringMessage::parse(cur, ctx)?;
                v3::BmpMessageValue::RouteMirroring(value)
            }
            BmpMessageType::Experimental251 => {
                let value = cur.read_bytes(cur.remaining())?;
                v3::BmpMessageValue::Experimental251(value.into())
            }
            BmpMessageType::Experimental252 => {
                let value = cur.read_bytes(cur.remaining())?;
                v3::BmpMessageValue::Experimental252(value.into())
            }
            BmpMessageType::Experimental253 => {
                let value = cur.read_bytes(cur.remaining())?;
                v3::BmpMessageValue::Experimental253(value.into())
            }
            BmpMessageType::Experimental254 => {
                let value = cur.read_bytes(cur.remaining())?;
                v3::BmpMessageValue::Experimental254(value.into())
            }
        };
        Ok(msg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum InitiationMessageParsingError {
    #[error("in initiation information: {0}")]
    InitiationInformationError(#[from] InitiationInformationParsingError),
}

impl<'a> ParseFrom<'a> for v3::InitiationMessage {
    type Error = InitiationMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let mut information = Vec::with_capacity(count_tlvs_t16_l16(*cur));
        while !cur.is_empty() {
            let info = v3::InitiationInformation::parse(cur)?;
            information.push(info);
        }
        Ok(v3::InitiationMessage::new(information))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum InitiationInformationParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown initiation information TLV type {code} at byte offset {offset}")]
    UndefinedType { offset: usize, code: u16 },

    #[error("invalid UTF-8 in initiation information TLV at byte offset {offset}: {error}")]
    FromUtf8Error { offset: usize, error: String },
}

impl<'a> ParseFrom<'a> for v3::InitiationInformation {
    type Error = InitiationInformationParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let code = cur.read_u16_be()?;
        let tlv_type = match InitiationInformationTlvType::try_from(code) {
            Ok(tlv_type) => tlv_type,
            Err(_) => {
                return Err(InitiationInformationParsingError::UndefinedType {
                    offset: cur.offset() - 2,
                    code,
                });
            }
        };
        let length = cur.read_u16_be()?;
        let mut buf = cur.take_slice(length as usize)?;

        match tlv_type {
            InitiationInformationTlvType::String => {
                let offset = buf.offset();
                match String::from_utf8(buf.read_bytes(buf.remaining())?.to_vec()) {
                    Ok(s) => Ok(v3::InitiationInformation::String(s.into_boxed_str())),
                    Err(error) => Err(InitiationInformationParsingError::FromUtf8Error {
                        offset,
                        error: error.to_string(),
                    }),
                }
            }
            InitiationInformationTlvType::SystemDescription => {
                let offset = buf.offset();
                match String::from_utf8(buf.read_bytes(buf.remaining())?.to_vec()) {
                    Ok(s) => Ok(v3::InitiationInformation::SystemDescription(
                        s.into_boxed_str(),
                    )),
                    Err(error) => Err(InitiationInformationParsingError::FromUtf8Error {
                        offset,
                        error: error.to_string(),
                    }),
                }
            }
            InitiationInformationTlvType::SystemName => {
                let offset = buf.offset();
                match String::from_utf8(buf.read_bytes(buf.remaining())?.to_vec()) {
                    Ok(s) => Ok(v3::InitiationInformation::SystemName(s.into_boxed_str())),
                    Err(error) => Err(InitiationInformationParsingError::FromUtf8Error {
                        offset,
                        error: error.to_string(),
                    }),
                }
            }
            InitiationInformationTlvType::VrfTableName => {
                let offset = buf.offset();
                match String::from_utf8(buf.read_bytes(buf.remaining())?.to_vec()) {
                    Ok(s) => Ok(v3::InitiationInformation::VrfTableName(s.into_boxed_str())),
                    Err(error) => Err(InitiationInformationParsingError::FromUtf8Error {
                        offset,
                        error: error.to_string(),
                    }),
                }
            }
            InitiationInformationTlvType::AdminLabel => {
                let offset = buf.offset();
                match String::from_utf8(buf.read_bytes(buf.remaining())?.to_vec()) {
                    Ok(s) => Ok(v3::InitiationInformation::AdminLabel(s.into_boxed_str())),
                    Err(error) => Err(InitiationInformationParsingError::FromUtf8Error {
                        offset,
                        error: error.to_string(),
                    }),
                }
            }
            InitiationInformationTlvType::Experimental65531 => {
                Ok(v3::InitiationInformation::Experimental65531(
                    buf.read_bytes(buf.remaining())?.into(),
                ))
            }
            InitiationInformationTlvType::Experimental65532 => {
                Ok(v3::InitiationInformation::Experimental65532(
                    buf.read_bytes(buf.remaining())?.into(),
                ))
            }
            InitiationInformationTlvType::Experimental65533 => {
                Ok(v3::InitiationInformation::Experimental65533(
                    buf.read_bytes(buf.remaining())?.into(),
                ))
            }
            InitiationInformationTlvType::Experimental65534 => {
                Ok(v3::InitiationInformation::Experimental65534(
                    buf.read_bytes(buf.remaining())?.into(),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteMonitoringMessageParsingError {
    #[error("malformed route monitoring message at byte offset {offset}: {error}")]
    RouteMonitoringMessageError {
        offset: usize,
        error: v3::RouteMonitoringMessageError,
    },

    #[error("in peer header: {0}")]
    PeerHeaderError(#[from] PeerHeaderParsingError),

    #[error("in BGP message: {0}")]
    BgpMessageError(#[from] BgpMessageParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v3::RouteMonitoringMessage {
    type Error = RouteMonitoringMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let peer_header = PeerHeader::parse(cur)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());
        let offset = cur.offset();
        let update_message = BgpMessage::parse(cur, bgp_ctx)?;
        if update_message.get_type() != BgpMessageType::Update {
            return Err(
                RouteMonitoringMessageParsingError::RouteMonitoringMessageError {
                    offset,
                    error: v3::RouteMonitoringMessageError::UnexpectedMessageType(
                        update_message.get_type(),
                    ),
                },
            );
        }
        match v3::RouteMonitoringMessage::build(peer_header, update_message) {
            Ok(msg) => Ok(msg),
            Err(error) => Err(
                RouteMonitoringMessageParsingError::RouteMonitoringMessageError { offset, error },
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BmpPeerTypeParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown BMP peer type {code} at byte offset {offset}")]
    UndefinedBmpPeerTypeCode { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for BmpPeerType {
    type Error = BmpPeerTypeParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let code = cur.read_u8()?;
        let peer_type_code = match BmpPeerTypeCode::try_from(code) {
            Ok(peer_type_code) => peer_type_code,
            Err(_) => {
                return Err(BmpPeerTypeParsingError::UndefinedBmpPeerTypeCode {
                    offset: cur.offset() - 1,
                    code,
                });
            }
        };
        let flags = cur.read_u8()?;
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
        Ok(peer_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PeerHeaderParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("in BMP peer type: {0}")]
    BmpPeerTypeError(#[from] BmpPeerTypeParsingError),

    #[error("in route distinguisher: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),

    #[error(
        "invalid peer header timestamp at byte offset {offset} (seconds={timestamp_secs}, microseconds={timestamp_micro})"
    )]
    InvalidTime {
        offset: usize,
        timestamp_secs: u32,
        timestamp_micro: u32,
    },
}

impl<'a> ParseFrom<'a> for PeerHeader {
    type Error = PeerHeaderParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let peer_type = BmpPeerType::parse(cur)?;
        let rd = RouteDistinguisher::parse(cur)?;
        let zero = RouteDistinguisher::As2Administrator { asn2: 0, number: 0 };
        let rd = if rd == zero { None } else { Some(rd) };
        let peer_address = cur.read_u128_be()?;
        let address = if peer_address == 0u128 {
            None
        } else if check_is_ipv6(&peer_type).unwrap_or(true) {
            Some(IpAddr::V6(Ipv6Addr::from(peer_address)))
        } else {
            Some(IpAddr::V4(Ipv4Addr::from(peer_address as u32)))
        };
        let peer_as = cur.read_u32_be()?;
        let bgp_id = cur.read_u32_be()?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        let timestamp_secs = cur.read_u32_be()?;
        let timestamp_micro = cur.read_u32_be()?;
        let time = if timestamp_secs != 0 || timestamp_micro != 0 {
            let time_opt =
                Utc.timestamp_opt(timestamp_secs.into(), timestamp_micro.saturating_mul(1_000));
            let time = if let LocalResult::Single(time) = time_opt {
                time
            } else {
                return Err(PeerHeaderParsingError::InvalidTime {
                    offset: cur.offset() - 8,
                    timestamp_secs,
                    timestamp_micro,
                });
            };
            Some(time)
        } else {
            None
        };
        let peer_header = PeerHeader::new(peer_type, rd, address, peer_as, bgp_id, time);
        Ok(peer_header)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PeerUpNotificationMessageParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("malformed peer-up notification at byte offset {offset}: {error}")]
    PeerUpMessageError {
        offset: usize,
        error: v3::PeerUpNotificationMessageError,
    },

    #[error("unexpected peer type {peer_type} in peer-up notification at byte offset {offset}")]
    UnexpectedPeerType {
        offset: usize,
        peer_type: BmpPeerTypeCode,
    },

    #[error("in peer header: {0}")]
    PeerHeaderError(#[from] PeerHeaderParsingError),

    #[error("in BGP message: {0}")]
    BgpMessageError(#[from] BgpMessageParsingError),

    #[error("in initiation information: {0}")]
    InitiationInformationError(#[from] InitiationInformationParsingError),
}

/// Check if the V flag is enabled in the peer header. Or return error of the
/// peer type that don't have a peer flag defined. Currently, only
/// `GlobalInstancePeer`, `RdInstancePeer`, and `LocalInstancePeer` have V flag
/// defined.
///
/// For `LocRibInstancePeer` and experimental we assume ipv6 since this will not
/// fail and still parse all the information
#[inline]
const fn check_is_ipv6(peer_type: &BmpPeerType) -> Result<bool, BmpPeerTypeCode> {
    match peer_type {
        BmpPeerType::GlobalInstancePeer { ipv6, .. } => Ok(*ipv6),
        BmpPeerType::RdInstancePeer { ipv6, .. } => Ok(*ipv6),
        BmpPeerType::LocalInstancePeer { ipv6, .. } => Ok(*ipv6),
        BmpPeerType::LocRibInstancePeer { .. } => Ok(true),
        BmpPeerType::Experimental251 { .. } => Ok(true),
        BmpPeerType::Experimental252 { .. } => Ok(true),
        BmpPeerType::Experimental253 { .. } => Ok(true),
        BmpPeerType::Experimental254 { .. } => Ok(true),
    }
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v3::PeerUpNotificationMessage {
    type Error = PeerUpNotificationMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let peer_header = PeerHeader::parse(cur)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let ipv6 = match check_is_ipv6(&peer_header.peer_type) {
            Ok(ipv6) => ipv6,
            Err(peer_type) => {
                return Err(PeerUpNotificationMessageParsingError::UnexpectedPeerType {
                    offset,
                    peer_type,
                });
            }
        };
        let address = cur.read_u128_be()?;
        let local_address = if address == 0u128 {
            None
        } else if ipv6 {
            Some(IpAddr::V6(Ipv6Addr::from(address)))
        } else {
            // the upper bits should be zero and can be ignored
            Some(IpAddr::V4(Ipv4Addr::from(address as u32)))
        };
        let local_port = cur.read_u16_be()?;
        let local_port = if local_port == 0 {
            None
        } else {
            Some(local_port)
        };
        let remote_port = cur.read_u16_be()?;
        let remote_port = if remote_port == 0 {
            None
        } else {
            Some(remote_port)
        };
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());
        let sent_message = BgpMessage::parse(cur, bgp_ctx)?;
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());
        let received_message = BgpMessage::parse(cur, bgp_ctx)?;
        let mut information = Vec::with_capacity(count_tlvs_t16_l16(*cur));
        while !cur.is_empty() {
            let info = v3::InitiationInformation::parse(cur)?;
            information.push(info);
        }
        let peer_up_msg = v3::PeerUpNotificationMessage::build(
            peer_header,
            local_address,
            local_port,
            remote_port,
            sent_message,
            received_message,
            information,
        );
        match peer_up_msg {
            Ok(msg) => Ok(msg),
            Err(error) => {
                Err(PeerUpNotificationMessageParsingError::PeerUpMessageError { offset, error })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PeerDownNotificationMessageParsingError {
    #[error("malformed peer-down notification at byte offset {offset}: {error}")]
    PeerDownMessageError {
        offset: usize,
        error: v3::PeerDownNotificationMessageError,
    },

    #[error("in peer header: {0}")]
    PeerHeaderError(#[from] PeerHeaderParsingError),

    #[error("in peer-down notification reason: {0}")]
    PeerDownNotificationReasonError(#[from] PeerDownNotificationReasonParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v3::PeerDownNotificationMessage {
    type Error = PeerDownNotificationMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let peer_header = PeerHeader::parse(cur)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());
        let reason = v3::PeerDownNotificationReason::parse(cur, bgp_ctx)?;
        let msg = v3::PeerDownNotificationMessage::build(peer_header, reason);
        match msg {
            Ok(msg) => Ok(msg),
            Err(error) => {
                Err(PeerDownNotificationMessageParsingError::PeerDownMessageError { offset, error })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PeerDownNotificationReasonParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown peer-down reason code {code} at byte offset {offset}")]
    UndefinedPeerDownReasonCode { offset: usize, code: u8 },

    #[error("in BGP message: {0}")]
    BgpMessageError(#[from] BgpMessageParsingError),

    #[error("in initiation information: {0}")]
    InitiationInformationError(#[from] InitiationInformationParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for v3::PeerDownNotificationReason {
    type Error = PeerDownNotificationReasonParsingError;
    fn parse(
        cur: &mut SliceReader<'a>,
        bgp_ctx: &mut BgpParsingContext,
    ) -> Result<Self, Self::Error> {
        let code = cur.read_u8()?;
        let reason_code = match PeerDownReasonCode::try_from(code) {
            Ok(reason_code) => reason_code,
            Err(_) => {
                return Err(
                    PeerDownNotificationReasonParsingError::UndefinedPeerDownReasonCode {
                        offset: cur.offset() - 1,
                        code,
                    },
                );
            }
        };
        match reason_code {
            PeerDownReasonCode::LocalSystemClosedNotificationPduFollows => {
                let msg = BgpMessage::parse(cur, bgp_ctx)?;
                Ok(v3::PeerDownNotificationReason::LocalSystemClosedNotificationPduFollows(msg))
            }
            PeerDownReasonCode::LocalSystemClosedFsmEventFollows => {
                let value = cur.read_u16_be()?;
                Ok(v3::PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(value))
            }
            PeerDownReasonCode::RemoteSystemClosedNotificationPduFollows => {
                let msg = BgpMessage::parse(cur, bgp_ctx)?;
                Ok(v3::PeerDownNotificationReason::RemoteSystemClosedNotificationPduFollows(msg))
            }
            PeerDownReasonCode::RemoteSystemClosedNoData => {
                Ok(v3::PeerDownNotificationReason::RemoteSystemClosedNoData)
            }
            PeerDownReasonCode::PeerDeConfigured => {
                Ok(v3::PeerDownNotificationReason::PeerDeConfigured)
            }
            PeerDownReasonCode::LocalSystemClosedTlvDataFollows => {
                let information = v3::InitiationInformation::parse(cur)?;
                Ok(v3::PeerDownNotificationReason::LocalSystemClosedTlvDataFollows(information))
            }
            PeerDownReasonCode::Experimental251 => {
                Ok(v3::PeerDownNotificationReason::Experimental251(
                    cur.take_slice(cur.remaining())?.as_slice().into(),
                ))
            }
            PeerDownReasonCode::Experimental252 => {
                Ok(v3::PeerDownNotificationReason::Experimental252(
                    cur.take_slice(cur.remaining())?.as_slice().into(),
                ))
            }
            PeerDownReasonCode::Experimental253 => {
                Ok(v3::PeerDownNotificationReason::Experimental253(
                    cur.take_slice(cur.remaining())?.as_slice().into(),
                ))
            }
            PeerDownReasonCode::Experimental254 => {
                Ok(v3::PeerDownNotificationReason::Experimental254(
                    cur.take_slice(cur.remaining())?.as_slice().into(),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteMirroringMessageParsingError {
    #[error("in peer header: {0}")]
    PeerHeaderError(#[from] PeerHeaderParsingError),

    #[error("in route mirroring value: {0}")]
    RouteMirroringValueError(#[from] RouteMirroringValueParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v3::RouteMirroringMessage {
    type Error = RouteMirroringMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let peer_header = PeerHeader::parse(cur)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());
        let mut mirrored = Vec::with_capacity(count_tlvs_t16_l16(*cur));
        while !cur.is_empty() {
            let element = v3::RouteMirroringValue::parse(cur, bgp_ctx)?;
            mirrored.push(element);
        }
        Ok(v3::RouteMirroringMessage::new(peer_header, mirrored))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteMirroringValueParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown route mirroring TLV type {code} at byte offset {offset}")]
    UndefinedRouteMirroringTlvType { offset: usize, code: u16 },

    #[error("unknown route mirroring information code {code} at byte offset {offset}")]
    UndefinedRouteMirroringInformation { offset: usize, code: u16 },

    #[error(
        "{unparsed_bytes} trailing byte(s) left unparsed at byte offset {offset} in a route mirroring value declaring length {length}"
    )]
    UnparseableBytes {
        offset: usize,
        length: u16,
        unparsed_bytes: usize,
    },

    #[error("in BGP message: {0}")]
    BgpMessageError(#[from] BgpMessageParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for v3::RouteMirroringValue {
    type Error = RouteMirroringValueParsingError;
    fn parse(
        cur: &mut SliceReader<'a>,
        bgp_ctx: &mut BgpParsingContext,
    ) -> Result<Self, Self::Error> {
        let code = cur.read_u16_be()?;
        let code = match RouteMirroringTlvType::try_from(code) {
            Ok(code) => code,
            Err(_) => {
                return Err(
                    RouteMirroringValueParsingError::UndefinedRouteMirroringTlvType {
                        offset: cur.offset() - 2,
                        code,
                    },
                );
            }
        };
        let length = cur.read_u16_be()?;
        let mut buf = cur.take_slice(length as usize)?;
        let value = match code {
            RouteMirroringTlvType::BgpMessage => {
                let msg = BgpMessage::parse(&mut buf, bgp_ctx)?;
                v3::RouteMirroringValue::BgpMessage(v3::MirroredBgpMessage::Parsed(msg))
            }
            RouteMirroringTlvType::Information => {
                let code = buf.read_u16_be()?;
                let information =
                    match RouteMirroringInformation::try_from(code) {
                        Ok(information) => information,
                        Err(_) => return Err(
                            RouteMirroringValueParsingError::UndefinedRouteMirroringInformation {
                                offset: buf.offset() - 2,
                                code,
                            },
                        ),
                    };
                v3::RouteMirroringValue::Information(information)
            }
            RouteMirroringTlvType::Experimental65531 => {
                let data = buf.take_slice(length as usize)?;
                v3::RouteMirroringValue::Experimental65531(data.as_slice().into())
            }
            RouteMirroringTlvType::Experimental65532 => {
                let data = buf.take_slice(length as usize)?;
                v3::RouteMirroringValue::Experimental65532(data.as_slice().into())
            }
            RouteMirroringTlvType::Experimental65533 => {
                let data = buf.take_slice(length as usize)?;
                v3::RouteMirroringValue::Experimental65533(data.as_slice().into())
            }
            RouteMirroringTlvType::Experimental65534 => {
                let data = buf.take_slice(length as usize)?;
                v3::RouteMirroringValue::Experimental65534(data.as_slice().into())
            }
        };
        if !buf.is_empty() {
            return Err(RouteMirroringValueParsingError::UnparseableBytes {
                offset: buf.offset(),
                length,
                unparsed_bytes: buf.remaining(),
            });
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TerminationMessageParsingError {
    #[error("in peer header: {0}")]
    PeerHeaderError(#[from] PeerHeaderParsingError),

    #[error("in termination information: {0}")]
    TerminationInformationError(#[from] TerminationInformationParsingError),
}

impl<'a> ParseFrom<'a> for v3::TerminationMessage {
    type Error = TerminationMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let mut information = Vec::with_capacity(count_tlvs_t16_l16(*cur));
        while !cur.is_empty() {
            let info = v3::TerminationInformation::parse(cur)?;
            information.push(info);
        }
        Ok(v3::TerminationMessage::new(information))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TerminationInformationParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown termination information TLV type {code} at byte offset {offset}")]
    UndefinedTerminationInformationTlvType { offset: usize, code: u16 },

    #[error("unknown termination reason code {code} at byte offset {offset}")]
    UndefinedPeerTerminationCode { offset: usize, code: u16 },

    #[error("invalid UTF-8 in termination information TLV at byte offset {offset}: {error}")]
    FromUtf8Error { offset: usize, error: String },

    #[error(
        "{unparsed_bytes} trailing byte(s) left unparsed at byte offset {offset} in termination information declaring length {length}"
    )]
    UnparseableBytes {
        offset: usize,
        length: u16,
        unparsed_bytes: usize,
    },
}

impl<'a> ParseFrom<'a> for v3::TerminationInformation {
    type Error = TerminationInformationParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let code = cur.read_u16_be()?;
        let code =
            match TerminationInformationTlvType::try_from(code) {
                Ok(code) => code,
                Err(_) => return Err(
                    TerminationInformationParsingError::UndefinedTerminationInformationTlvType {
                        offset: cur.offset() - 2,
                        code,
                    },
                ),
            };
        let length = cur.read_u16_be()?;
        let mut buf = cur.take_slice(length as usize)?;
        let value = match code {
            TerminationInformationTlvType::String => {
                let offset = buf.offset();
                match String::from_utf8(buf.read_bytes(buf.remaining())?.to_vec()) {
                    Ok(s) => v3::TerminationInformation::String(s.into_boxed_str()),
                    Err(error) => {
                        return Err(TerminationInformationParsingError::FromUtf8Error {
                            offset,
                            error: error.to_string(),
                        });
                    }
                }
            }
            TerminationInformationTlvType::Reason => {
                let code = buf.read_u16_be()?;
                let reason = match PeerTerminationCode::try_from(code) {
                    Ok(reason) => reason,
                    Err(_) => {
                        return Err(
                            TerminationInformationParsingError::UndefinedPeerTerminationCode {
                                offset: buf.offset() - 2,
                                code,
                            },
                        );
                    }
                };
                v3::TerminationInformation::Reason(reason)
            }
            TerminationInformationTlvType::Experimental65531 => {
                v3::TerminationInformation::Experimental65531(
                    buf.read_bytes(buf.remaining())?.into(),
                )
            }
            TerminationInformationTlvType::Experimental65532 => {
                v3::TerminationInformation::Experimental65532(
                    buf.read_bytes(buf.remaining())?.into(),
                )
            }
            TerminationInformationTlvType::Experimental65533 => {
                v3::TerminationInformation::Experimental65533(
                    buf.read_bytes(buf.remaining())?.into(),
                )
            }
            TerminationInformationTlvType::Experimental65534 => {
                v3::TerminationInformation::Experimental65534(
                    buf.read_bytes(buf.remaining())?.into(),
                )
            }
        };
        if !buf.is_empty() {
            return Err(TerminationInformationParsingError::UnparseableBytes {
                offset: buf.offset(),
                length,
                unparsed_bytes: buf.remaining(),
            });
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum StatisticsReportMessageParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("in peer header: {0}")]
    PeerHeaderError(#[from] PeerHeaderParsingError),

    #[error("in statistics counter: {0}")]
    StatisticsCounterError(#[from] StatisticsCounterParsingError),
}

impl<'a> ParseFrom<'a> for v3::StatisticsReportMessage {
    type Error = StatisticsReportMessageParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let peer_header = PeerHeader::parse(cur)?;
        let stats_count = cur.read_u32_be()?;
        // Clamp the declared count against the smallest possible counter
        // (a 4-byte T16/L16 header) so a malformed count can't request a
        // huge allocation up front.
        let capacity = (stats_count as usize).min(cur.remaining() / 4);
        let mut counters = Vec::with_capacity(capacity);
        for _ in 0..stats_count {
            let counter = v3::StatisticsCounter::parse(cur)?;
            counters.push(counter);
        }
        Ok(v3::StatisticsReportMessage::new(peer_header, counters))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum StatisticsCounterParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown address family {afi} in statistics counter at byte offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error(
        "unknown subsequent address family {safi} in statistics counter at byte offset {offset}"
    )]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error(
        "unsupported address family pair (afi {afi}, safi {safi}) in statistics counter at byte offset {offset}"
    )]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },

    #[error(
        "{unparsed_bytes} trailing byte(s) left unparsed at byte offset {offset} in a statistics counter declaring length {length}"
    )]
    UnparseableBytes {
        offset: usize,
        length: u16,
        unparsed_bytes: usize,
    },
}

#[inline]
fn parse_address_type(
    cur: &mut SliceReader<'_>,
) -> Result<AddressType, StatisticsCounterParsingError> {
    let afi = AddressFamily::try_from(cur.read_u16_be()?).map_err(|err| {
        StatisticsCounterParsingError::UndefinedAddressFamily {
            offset: cur.offset() - 2,
            afi: err.0,
        }
    })?;
    let safi = SubsequentAddressFamily::try_from(cur.read_u8()?).map_err(|err| {
        StatisticsCounterParsingError::UndefinedSubsequentAddressFamily {
            offset: cur.offset() - 1,
            safi: err.0,
        }
    })?;
    let address_type = match AddressType::from_afi_safi(afi, safi) {
        Ok(address_type) => address_type,
        Err(err) => {
            return Err(StatisticsCounterParsingError::AddressTypeError {
                offset: cur.offset() - 3,
                afi: err.address_family().into(),
                safi: err.subsequent_address_family().into(),
            });
        }
    };
    Ok(address_type)
}

impl<'a> ParseFrom<'a> for v3::StatisticsCounter {
    type Error = StatisticsCounterParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let code = cur.read_u16_be()?;
        let length = cur.read_u16_be()?;
        let mut buf = cur.take_slice(length as usize)?;
        let  counter = match BmpStatisticsType::try_from(code) {
            Ok(code) => match code {
                BmpStatisticsType::NumberOfPrefixesRejectedByInboundPolicy => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfPrefixesRejectedByInboundPolicy(CounterU32(
                        value,
                    ))
                }
                BmpStatisticsType::NumberOfDuplicatePrefixAdvertisements => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfDuplicatePrefixAdvertisements(CounterU32(
                        value,
                    ))
                }
                BmpStatisticsType::NumberOfDuplicateWithdraws => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfDuplicateWithdraws(CounterU32(
                        value,
                    ))
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToClusterListLoop => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfUpdatesInvalidatedDueToClusterListLoop(CounterU32(
                        value,
                    ))
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToAsPathLoop => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsPathLoop(CounterU32(value))
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToOriginatorId => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfUpdatesInvalidatedDueToOriginatorId(CounterU32(
                        value,
                    ))
                }
                BmpStatisticsType::NumberOfUpdatesInvalidatedDueToAsConfederationLoop => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsConfederationLoop(CounterU32(
                        value,
                    ))
                }
                BmpStatisticsType::NumberOfRoutesInAdjRibIn => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInAdjRibIn(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInLocRib => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInLocRib(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiAdjRibIn => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiAdjRibIn(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiLocRib => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiLocRib(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfUpdatesSubjectedToTreatAsWithdraw => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfUpdatesSubjectedToTreatAsWithdraw(CounterU32(value))
                }
                BmpStatisticsType::NumberOfPrefixesSubjectedToTreatAsWithdraw => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfPrefixesSubjectedToTreatAsWithdraw(CounterU32(value))
                }
                BmpStatisticsType::NumberOfDuplicateUpdateMessagesReceived => {
                    let value = buf.read_u32_be()?;
                    v3::StatisticsCounter::NumberOfDuplicateUpdateMessagesReceived(CounterU32(value))
                }
                BmpStatisticsType::NumberOfRoutesInPrePolicyAdjRibOut => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPrePolicyAdjRibOut(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPostPolicyAdjRibOut => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPostPolicyAdjRibOut(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPrePolicyAdjRibIn => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPrePolicyAdjRibIn(GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibIn => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibIn(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPostPolicyAdjRibIn => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPostPolicyAdjRibIn(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibIn => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibIn(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibInRejected => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibInRejected(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInAccepted => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInAccepted(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiSuppressedByDamping => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiSuppressedByDamping(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiMarkedStaleByGr => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiMarkedStaleByGr(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiMarkedStaleByLlgr => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiMarkedStaleByLlgr(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPostPolicyAdjRibInBeforeThreshold => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPostPolicyAdjRibInBeforeThreshold(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInBeforeThreshold => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInBeforeThreshold(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPostPolicyAdjRibInOrLocRibBeforeLicenseThreshold => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPostPolicyAdjRibInOrLocRibBeforeLicenseThreshold(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInOrLocRibBeforeLicenseThreshold => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInOrLocRibBeforeLicenseThreshold(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPrePolicyAdjRibInRejectedDueToAsPathLength => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPrePolicyAdjRibInRejectedDueToAsPathLength(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibInRejectedDueToAsPathLength => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibInRejectedDueToAsPathLength(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInInvalidatedByRpki => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInInvalidatedByRpki(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInValidatedByRpki => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInValidatedByRpki(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInRpkiNotFound => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInRpkiNotFound(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOutRejected => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOutRejected(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPrePolicyAdjRibOutFilteredDueToAsPathLength => {
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPrePolicyAdjRibOutFilteredDueToAsPathLength(GaugeU64(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOutFilteredDueToAsPathLength => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOutFilteredDueToAsPathLength(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutInvalidatedByRpki => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutInvalidatedByRpki(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutValidatedByRpki => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutValidatedByRpki(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutRpkiNotFound => {
                    let address_type = parse_address_type(&mut buf)?;
                    let value = buf.read_u64_be()?;
                    v3::StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutRpkiNotFound(address_type, GaugeU64::new(value))
                }
                BmpStatisticsType::Experimental65531 => {
                    v3::StatisticsCounter::Experimental65531(buf.take_slice(buf.remaining())?.as_slice().into())
                }
                BmpStatisticsType::Experimental65532 => {
                    v3::StatisticsCounter::Experimental65532(buf.take_slice(buf.remaining())?.as_slice().into())
                }
                BmpStatisticsType::Experimental65533 => {
                    v3::StatisticsCounter::Experimental65533(buf.take_slice(buf.remaining())?.as_slice().into())
                }
                BmpStatisticsType::Experimental65534 => {
                    v3::StatisticsCounter::Experimental65534(buf.take_slice(buf.remaining())?.as_slice().into())
                }
            },
            Err(code) => {
                v3::StatisticsCounter::Unknown(code.0, buf.take_slice(buf.remaining())?.as_slice().into())
            }
        };
        if !buf.is_empty() {
            return Err(StatisticsCounterParsingError::UnparseableBytes {
                offset: buf.offset(),
                length,
                unparsed_bytes: buf.remaining(),
            });
        }
        Ok(counter)
    }
}
