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
    iana::{BmpMessageType, UndefinedBmpMessageType},
    v3,
    v4::{
        BmpMessageValue, PathMarking, PeerDownNotificationMessage, PeerDownTlv,
        RouteMonitoringError, RouteMonitoringMessage, RouteMonitoringTlv, RouteMonitoringTlvError,
        RouteMonitoringTlvType, RouteMonitoringTlvValue,
    },
    wire::deserializer::{v3::*, BmpParsingContext},
    PeerHeader, PeerKey,
};
use netgauze_bgp_pkt::{
    wire::deserializer::{
        capabilities::{BgpCapabilityParsingError, LocatedBgpCapabilityParsingError},
        read_tlv_header_t16_l16, BgpMessageParsingError, BgpParsingContext,
    },
    BgpMessage,
};

use crate::v4::PathMarkingReason;
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_till_empty_into_located,
    ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BmpMessageValueParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpMessageType(#[from_external] UndefinedBmpMessageType),
    RouteMonitoringMessageError(
        #[from_located(module = "self")] RouteMonitoringMessageParsingError,
    ),
    InitiationMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")] InitiationMessageParsingError,
    ),
    PeerUpNotificationMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")]
        PeerUpNotificationMessageParsingError,
    ),
    PeerDownNotificationMessageError(
        #[from_located(module = "self")] PeerDownNotificationMessageParsingError,
    ),
    PeerDownNotificationTlvError(#[from_located(module = "self")] PeerDownTlvParsingError),
    RouteMirroringMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")] RouteMirroringMessageParsingError,
    ),
    TerminationMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")] TerminationMessageParsingError,
    ),
    StatisticsReportMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")]
        StatisticsReportMessageParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, &mut BmpParsingContext, LocatedBmpMessageValueParsingError<'a>>
    for BmpMessageValue
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BmpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBmpMessageValueParsingError<'a>> {
        let (buf, msg_type) = nom::combinator::map_res(be_u8, BmpMessageType::try_from)(buf)?;
        let (buf, msg) = match msg_type {
            BmpMessageType::RouteMonitoring => {
                let (buf, value) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpMessageValue::RouteMonitoring(value))
            }
            BmpMessageType::StatisticsReport => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessageValue::StatisticsReport(value))
            }
            BmpMessageType::PeerDownNotification => {
                let (buf, notif) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpMessageValue::PeerDownNotification(notif))
            }
            BmpMessageType::PeerUpNotification => {
                let (buf, value) = parse_into_located_one_input(buf, ctx)?;
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
                let (buf, init) = parse_into_located_one_input(buf, ctx)?;
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum PeerDownTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedPeerDownTlvParsingError<'a>> for PeerDownTlv {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedPeerDownTlvParsingError<'a>>
    where
        Self: Sized,
    {
        let (tlv_type, _length, value, remainder) = read_tlv_header_t16_l16(buf)?;

        Ok((
            remainder,
            Self::Unknown {
                code: tlv_type,
                value: value.to_vec(),
            },
        ))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum RouteMonitoringMessageParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteMonitoringMessage(RouteMonitoringError),
    PeerHeader(#[from_located(module = "crate::wire::deserializer::v3")] PeerHeaderParsingError),
    BgpMessage(
        #[from_located(module = "netgauze_bgp_pkt::wire::deserializer")] BgpMessageParsingError,
    ),
    RouteMonitoringTlvParsing(#[from_located(module = "self")] RouteMonitoringTlvParsingError),
    MissingBgpPdu,
}

impl<'a>
    ReadablePduWithOneInput<
        'a,
        &mut BmpParsingContext,
        LocatedRouteMonitoringMessageParsingError<'a>,
    > for RouteMonitoringMessage
{
    fn from_wire(
        input: Span<'a>,
        ctx: &mut BmpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedRouteMonitoringMessageParsingError<'a>> {
        let (buf, peer_header): (Span<'_>, PeerHeader) = parse_into_located(input)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());

        // Context represents what we learnt from the BGP Open
        // We do not want to alter it permanently based on TLVs that are punctual in the
        // messages
        let mut ctx_clone = bgp_ctx.clone();

        // Can't use parse_till_empty_into_with_one_input_located because
        //  - &mut BgpParsingContext is not Clone
        //  - we don't want to Clone our context
        let (remainder, update_pdu, tlvs) = {
            let mut buf = buf;
            let mut tlvs = Vec::new();
            let mut bgp_pdu = None;
            while !buf.is_empty() {
                // Peek the TLV Type, if we have a BGP PDU we keep it for later and we'll decode
                // it when we've decoded all the Stateless Parsing TLVs on which
                // the PDU decoding depends
                match nom::combinator::peek(be_u16)(buf)? {
                    (_, tlv_type) if tlv_type == RouteMonitoringTlvType::BgpUpdatePdu as u16 => {
                        let (tmp, _tlv_type) = be_u16(buf)?;
                        let (tmp, length) = be_u16(tmp)?;
                        let (tmp, _index) = be_u16(tmp)?;

                        let (after_pdu, bgp_pdu_buf) = nom::bytes::complete::take(length)(tmp)?;

                        buf = after_pdu;
                        bgp_pdu = Some(bgp_pdu_buf);
                        continue; // Check again that we should still be parsing
                                  // (buf is empty?)
                    }
                    _ => {}
                }

                let (tmp, element) = parse_into_located_one_input(buf, &mut ctx_clone)?;
                tlvs.push(element);
                buf = tmp;
            }

            // Parse the PDU
            match bgp_pdu {
                Some(bgp_pdu) => {
                    let (_, bgp_pdu): (_, BgpMessage) =
                        parse_into_located_one_input(bgp_pdu, &mut ctx_clone)?;
                    (buf, bgp_pdu, tlvs)
                }
                None => {
                    return Err(nom::Err::Error(
                        LocatedRouteMonitoringMessageParsingError::new(
                            input,
                            RouteMonitoringMessageParsingError::MissingBgpPdu,
                        ),
                    ))
                }
            }
        };

        match Self::build(peer_header, update_pdu, tlvs) {
            Ok(rm) => Ok((remainder, rm)),
            Err(err) => Err(nom::Err::Error(
                LocatedRouteMonitoringMessageParsingError::new(
                    input,
                    RouteMonitoringMessageParsingError::RouteMonitoringMessage(err),
                ),
            )),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum RouteMonitoringTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    BgpMessage(
        #[from_located(module = "netgauze_bgp_pkt::wire::deserializer")] BgpMessageParsingError,
    ),
    FromUtf8Error(String),
    BgpCapability(#[from_located(module = "self")] BgpCapabilityParsingError),
    InvalidRouteMonitoringTlv(RouteMonitoringTlvError),
    PathMarking(#[from_located(module = "self")] PathMarkingParsingError),
}

impl<'a> FromExternalError<Span<'a>, FromUtf8Error> for LocatedRouteMonitoringTlvParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: FromUtf8Error) -> Self {
        LocatedRouteMonitoringTlvParsingError::new(
            input,
            RouteMonitoringTlvParsingError::FromUtf8Error(error.to_string()),
        )
    }
}

impl<'a>
    ReadablePduWithOneInput<'a, &mut BgpParsingContext, LocatedRouteMonitoringTlvParsingError<'a>>
    for RouteMonitoringTlv
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedRouteMonitoringTlvParsingError<'a>> {
        // Can't use read_tlv_header_t16_l16 because Index is in the middle of the
        // header and not counted in Length
        let (span, tlv_type) = be_u16(buf)?;
        let (span, tlv_length) = be_u16(span)?;
        let (span, index) = be_u16(span)?;
        let (remainder, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let value = match RouteMonitoringTlvType::from_repr(tlv_type) {
            Some(tlv_type) => match tlv_type {
                RouteMonitoringTlvType::VrfTableName => {
                    let (_, str) = nom::combinator::map_res(
                        nom::bytes::complete::take(tlv_length),
                        |x: Span<'_>| String::from_utf8(x.to_vec()),
                    )(data)?;
                    RouteMonitoringTlvValue::VrfTableName(str)
                }
                RouteMonitoringTlvType::BgpUpdatePdu => {
                    let (_, pdu) = parse_into_located_one_input(data, ctx)?;
                    RouteMonitoringTlvValue::BgpUpdate(pdu)
                }
                RouteMonitoringTlvType::GroupTlv => {
                    let (_, values) = nom::multi::many0(be_u16)(data)?;
                    RouteMonitoringTlvValue::GroupTlv(values)
                }
                RouteMonitoringTlvType::StatelessParsing => {
                    let (_, bgp_capability) = parse_into_located(data)?;
                    ctx.update_capabilities(&bgp_capability);
                    RouteMonitoringTlvValue::StatelessParsing(bgp_capability)
                }
                RouteMonitoringTlvType::PathMarking => {
                    let (_, path_marking) = parse_into_located(data)?;
                    RouteMonitoringTlvValue::PathMarking(path_marking)
                }
            },
            None => RouteMonitoringTlvValue::Unknown {
                code: tlv_type,
                value: data.to_vec(),
            },
        };

        match RouteMonitoringTlv::build(index, value) {
            Ok(tlv) => Ok((remainder, tlv)),
            Err(err) => Err(nom::Err::Error(LocatedRouteMonitoringTlvParsingError {
                span: buf,
                error: RouteMonitoringTlvParsingError::InvalidRouteMonitoringTlv(err),
            })),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum PeerDownNotificationMessageParsingError {
    PeerDownMessageError(v3::PeerDownNotificationMessageError),
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    PeerDownNotificationReasonError(
        #[from_located(module = "self")] PeerDownNotificationReasonParsingError,
    ),
    PeerDownTlvError(#[from_located(module = "self")] PeerDownTlvParsingError),
}

impl<'a>
    ReadablePduWithOneInput<
        'a,
        &mut BmpParsingContext,
        LocatedPeerDownNotificationMessageParsingError<'a>,
    > for PeerDownNotificationMessage
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BmpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedPeerDownNotificationMessageParsingError<'a>> {
        let input = buf;
        let (buf, peer_header): (Span<'_>, PeerHeader) = parse_into_located(buf)?;
        let peer_key = PeerKey::from_peer_header(&peer_header);
        let bgp_ctx = ctx.entry(peer_key).or_default();
        bgp_ctx.set_asn4(peer_header.is_asn4());
        let (buf, reason) = parse_into_located_one_input(buf, bgp_ctx)?;
        let (buf, tlvs) = parse_till_empty_into_located(buf)?;
        let msg = PeerDownNotificationMessage::build(peer_header, reason, tlvs);
        match msg {
            Ok(msg) => Ok((buf, msg)),
            Err(err) => Err(nom::Err::Error(
                LocatedPeerDownNotificationMessageParsingError::new(
                    input,
                    PeerDownNotificationMessageParsingError::PeerDownMessageError(err),
                ),
            )),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize, Eq)]
pub enum PathMarkingParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    ReasonCodeBadLength(usize),
}

impl<'a> ReadablePdu<'a, LocatedPathMarkingParsingError<'a>> for PathMarking {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedPathMarkingParsingError<'a>>
    where
        Self: Sized,
    {
        let (data, path_status) = be_u32(buf)?;

        let reason_code_len = data.len();
        let (data, reason_code) = match reason_code_len {
            0 => (data, None),
            2 => {
                let (data, reason_code) = be_u16(data)?;
                (data, Some(reason_code))
            }
            _ => {
                return Err(nom::Err::Error(LocatedPathMarkingParsingError::new(
                    data,
                    PathMarkingParsingError::ReasonCodeBadLength(reason_code_len),
                )))
            }
        };

        Ok((
            data,
            PathMarking::new(path_status, reason_code.map(PathMarkingReason::from_code)),
        ))
    }
}
