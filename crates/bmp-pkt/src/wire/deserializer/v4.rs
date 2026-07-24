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

use crate::iana::BmpMessageType;
use crate::wire::deserializer::{BmpParsingContext, count_tlvs_t16_l16};
use crate::{BmpPeerType, PeerHeader, PeerKey, v3, v4};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::wire::deserializer::capabilities::BgpCapabilityParsingError;
use netgauze_bgp_pkt::wire::deserializer::{
    BgpMessageParsingError, BgpParsingContext, read_tlv_header_t16_l16,
};

use crate::wire::deserializer::v3::{
    InitiationMessageParsingError, PeerDownNotificationReasonParsingError, PeerHeaderParsingError,
    PeerUpNotificationMessageParsingError, RouteMirroringMessageParsingError,
    StatisticsReportMessageParsingError, TerminationMessageParsingError,
};

use netgauze_bgp_pkt::capabilities::BgpCapability;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput, ParseFromWithTwoInputs};
use serde::{Deserialize, Serialize};

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

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v4::BmpMessageValue {
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
                let value = v4::RouteMonitoringMessage::parse(cur, ctx)?;
                v4::BmpMessageValue::RouteMonitoring(value)
            }
            BmpMessageType::StatisticsReport => {
                let value = v3::StatisticsReportMessage::parse(cur)?;
                v4::BmpMessageValue::StatisticsReport(value)
            }
            BmpMessageType::PeerDownNotification => {
                let value = v4::PeerDownNotificationMessage::parse(cur, ctx)?;
                v4::BmpMessageValue::PeerDownNotification(value)
            }
            BmpMessageType::PeerUpNotification => {
                let value = v3::PeerUpNotificationMessage::parse(cur, ctx)?;
                v4::BmpMessageValue::PeerUpNotification(value)
            }
            BmpMessageType::Initiation => {
                let value = v3::InitiationMessage::parse(cur)?;
                v4::BmpMessageValue::Initiation(value)
            }
            BmpMessageType::Termination => {
                let value = v3::TerminationMessage::parse(cur)?;
                v4::BmpMessageValue::Termination(value)
            }
            BmpMessageType::RouteMirroring => {
                let value = v3::RouteMirroringMessage::parse(cur, ctx)?;
                v4::BmpMessageValue::RouteMirroring(value)
            }
            BmpMessageType::Experimental251 => {
                let value = cur.read_bytes(cur.remaining())?;
                v4::BmpMessageValue::Experimental251(value.into())
            }
            BmpMessageType::Experimental252 => {
                let value = cur.read_bytes(cur.remaining())?;
                v4::BmpMessageValue::Experimental252(value.into())
            }
            BmpMessageType::Experimental253 => {
                let value = cur.read_bytes(cur.remaining())?;
                v4::BmpMessageValue::Experimental253(value.into())
            }
            BmpMessageType::Experimental254 => {
                let value = cur.read_bytes(cur.remaining())?;
                v4::BmpMessageValue::Experimental254(value.into())
            }
        };
        Ok(msg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PeerDownTlvParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for v4::PeerDownTlv {
    type Error = PeerDownTlvParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let (tlv_type, _length, mut value) =
            read_tlv_header_t16_l16::<PeerDownTlvParsingError>(cur)?;
        Ok(Self::Unknown {
            code: tlv_type,
            value: value.read_bytes(value.remaining())?.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteMonitoringMessageParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("malformed route monitoring message at byte offset {offset}: {error}")]
    RouteMonitoringMessage {
        offset: usize,
        error: v4::RouteMonitoringError,
    },

    #[error("route monitoring message carries no BGP UPDATE at byte offset {offset}")]
    MissingBgpPdu { offset: usize },

    #[error("in peer header: {0}")]
    PeerHeader(#[from] PeerHeaderParsingError),

    #[error("in BGP message: {0}")]
    BgpMessage(#[from] BgpMessageParsingError),

    #[error("in route monitoring TLV: {0}")]
    RouteMonitoringTlvParsing(#[from] RouteMonitoringTlvParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v4::RouteMonitoringMessage {
    type Error = RouteMonitoringMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let peer_header = PeerHeader::parse(cur)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());

        // Determine if we need to track Adj-RIB-Out based on Peer Type,
        // which is useful to select ADD-Path behavior for either sending or receive
        let adj_rib_out = match peer_header.peer_type() {
            BmpPeerType::GlobalInstancePeer { adj_rib_out, .. }
            | BmpPeerType::RdInstancePeer { adj_rib_out, .. }
            | BmpPeerType::LocalInstancePeer { adj_rib_out, .. } => adj_rib_out,
            _ => false,
        };

        // Context represents what we learnt from the BGP Open
        // We do not want to alter it permanently based on TLVs that are punctual in the
        // messages
        let mut ctx_clone = bgp_ctx.clone();

        let (update_pdu, tlvs) = {
            let mut tlvs = Vec::new();
            let mut bgp_pdu = None;
            while !cur.is_empty() {
                // Peek the TLV Type, if we have a BGP PDU we keep it for later and we'll decode
                // it when we've decoded all the Stateless Parsing TLVs on which
                // the PDU decoding depends
                match cur.peek_u16_be()? {
                    tlv_type if tlv_type == v4::RouteMonitoringTlvType::BgpUpdatePdu as u16 => {
                        let _tlv_type = cur.read_u16_be()?;
                        let length = cur.read_u16_be()?;
                        let _index = cur.read_u16_be()?;
                        let bgp_pdu_buf = cur.take_slice(length as usize)?;
                        bgp_pdu = Some(bgp_pdu_buf);
                        // Check again that we should still be parsing
                        // (buf is empty?)
                        continue;
                    }
                    _ => {}
                }

                let element = v4::RouteMonitoringTlv::parse(cur, &mut ctx_clone, adj_rib_out)?;
                tlvs.push(element);
            }

            // Parse the PDU
            match bgp_pdu {
                Some(mut bgp_pdu) => {
                    let bgp_pdu = BgpMessage::parse(&mut bgp_pdu, &mut ctx_clone)?;
                    (bgp_pdu, tlvs)
                }
                None => {
                    return Err(RouteMonitoringMessageParsingError::MissingBgpPdu {
                        offset: cur.offset(),
                    });
                }
            }
        };

        match Self::build(peer_header, update_pdu, tlvs) {
            Ok(rm) => Ok(rm),
            Err(error) => {
                Err(RouteMonitoringMessageParsingError::RouteMonitoringMessage { offset, error })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteMonitoringTlvParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "invalid route monitoring TLV length {actual} at byte offset {offset} (expected {expected})"
    )]
    InvalidTlvLength {
        offset: usize,
        expected: u16,
        actual: u16,
    },

    #[error("in BGP message: {0}")]
    BgpMessage(#[from] BgpMessageParsingError),

    #[error("invalid UTF-8 in route monitoring TLV at byte offset {offset}: {error}")]
    FromUtf8Error { offset: usize, error: String },

    #[error("in BGP capability: {0}")]
    BgpCapability(#[from] BgpCapabilityParsingError),

    #[error("malformed route monitoring message at byte offset {offset}: {error}")]
    InvalidRouteMonitoringTlv {
        offset: usize,
        error: v4::RouteMonitoringTlvError,
    },

    #[error("in path marking: {0}")]
    PathMarking(#[from] PathMarkingParsingError),
}

impl<'a> ParseFromWithTwoInputs<'a, &mut BgpParsingContext, bool> for v4::RouteMonitoringTlv {
    type Error = RouteMonitoringTlvParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        ctx: &mut BgpParsingContext,
        adj_rib_out: bool,
    ) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        // Can't use read_tlv_header_t16_l16 because Index is in the middle of the
        // header and not counted in Length
        let tlv_type = cur.read_u16_be()?;
        let tlv_length = cur.read_u16_be()?;
        let index = cur.read_u16_be()?;
        if cur.remaining() < tlv_length as usize {
            return Err(RouteMonitoringTlvParsingError::InvalidTlvLength {
                offset: cur.offset() - 6,
                expected: tlv_length,
                actual: cur.remaining() as u16,
            });
        }
        let mut data = cur.take_slice(tlv_length as usize)?;

        let value = match v4::RouteMonitoringTlvType::from_repr(tlv_type) {
            Some(tlv_type) => match tlv_type {
                v4::RouteMonitoringTlvType::VrfTableName => {
                    let offset = data.offset();
                    match String::from_utf8(data.as_slice().to_vec()) {
                        Ok(s) => v4::RouteMonitoringTlvValue::VrfTableName(s.into_boxed_str()),
                        Err(error) => {
                            return Err(RouteMonitoringTlvParsingError::FromUtf8Error {
                                offset,
                                error: error.to_string(),
                            });
                        }
                    }
                }
                v4::RouteMonitoringTlvType::BgpUpdatePdu => {
                    let pdu = BgpMessage::parse(&mut data, ctx)?;
                    v4::RouteMonitoringTlvValue::BgpUpdate(pdu)
                }
                v4::RouteMonitoringTlvType::GroupTlv => {
                    let mut values = Vec::with_capacity(data.remaining() / 2);
                    while !data.is_empty() {
                        values.push(data.read_u16_be()?);
                    }
                    v4::RouteMonitoringTlvValue::GroupTlv(values.into())
                }
                v4::RouteMonitoringTlvType::StatelessParsing => {
                    let bgp_capability = BgpCapability::parse(&mut data)?;
                    ctx.update_capabilities(&bgp_capability, adj_rib_out);
                    v4::RouteMonitoringTlvValue::StatelessParsing(bgp_capability)
                }
                v4::RouteMonitoringTlvType::PathMarking => {
                    let path_marking = v4::PathMarking::parse(&mut data)?;
                    v4::RouteMonitoringTlvValue::PathMarking(path_marking)
                }
            },
            None => v4::RouteMonitoringTlvValue::Unknown {
                code: tlv_type,
                value: data.as_slice().into(),
            },
        };

        match v4::RouteMonitoringTlv::build(index, value) {
            Ok(tlv) => Ok(tlv),
            Err(error) => {
                Err(RouteMonitoringTlvParsingError::InvalidRouteMonitoringTlv { offset, error })
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

    #[error("in peer-down TLV: {0}")]
    PeerDownTlvError(#[from] PeerDownTlvParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BmpParsingContext> for v4::PeerDownNotificationMessage {
    type Error = PeerDownNotificationMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BmpParsingContext) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let peer_header = PeerHeader::parse(cur)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());
        let reason = v3::PeerDownNotificationReason::parse(cur, bgp_ctx)?;
        let mut tlvs = Vec::with_capacity(count_tlvs_t16_l16(*cur));
        while !cur.is_empty() {
            let tlv = v4::PeerDownTlv::parse(cur)?;
            tlvs.push(tlv);
        }
        let msg = v4::PeerDownNotificationMessage::build(peer_header, reason, tlvs);
        match msg {
            Ok(msg) => Ok(msg),
            Err(error) => {
                Err(PeerDownNotificationMessageParsingError::PeerDownMessageError { offset, error })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PathMarkingParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid path marking reason code length {length} at byte offset {offset}")]
    ReasonCodeBadLength { offset: usize, length: usize },
}

impl<'a> ParseFrom<'a> for v4::PathMarking {
    type Error = PathMarkingParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let path_status_u32 = cur.read_u32_be()?;
        let path_status = v4::PathStatus::from_bits_truncate(path_status_u32);

        let offset = cur.offset();
        let reason_code_len = cur.remaining();
        let reason_code = match reason_code_len {
            0 => None,
            2 => {
                let reason_code = cur.read_u16_be()?;
                Some(reason_code)
            }
            _ => {
                return Err(PathMarkingParsingError::ReasonCodeBadLength {
                    offset,
                    length: reason_code_len,
                });
            }
        };

        Ok(v4::PathMarking::new(
            path_status,
            reason_code.map(v4::PathMarkingReason::from_code),
        ))
    }
}
