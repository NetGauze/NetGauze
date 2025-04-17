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
    v4::{
        BmpV4MessageValue, BmpV4PeerDownTlv, BmpV4RouteMonitoringError,
        BmpV4RouteMonitoringMessage, BmpV4RouteMonitoringTlv, BmpV4RouteMonitoringTlvError,
        BmpV4RouteMonitoringTlvType, BmpV4RouteMonitoringTlvValue, PathMarking, PathMarkingReason,
    },
    wire::deserializer::{
        v3::{
            InitiationMessageParsingError, PeerDownNotificationMessageParsingError,
            PeerHeaderParsingError, PeerUpNotificationMessageParsingError,
            RouteMirroringMessageParsingError, StatisticsReportMessageParsingError,
            TerminationMessageParsingError,
        },
        *,
    },
    PeerHeader, PeerKey,
};
use netgauze_bgp_pkt::{
    wire::deserializer::{
        capabilities::{BgpCapabilityParsingError, LocatedBgpCapabilityParsingError},
        read_tlv_header_t16_l16, BgpMessageParsingError,
    },
    BgpMessage,
};

use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_till_empty_into_located, ReadablePdu,
    ReadablePduWithOneInput, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u16, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BmpV4MessageValueParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpMessageType(#[from_external] UndefinedBmpMessageType),
    RouteMonitoringMessageError(
        #[from_located(module = "self")] BmpV4RouteMonitoringMessageParsingError,
    ),
    InitiationMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")] InitiationMessageParsingError,
    ),
    PeerUpNotificationMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")]
        PeerUpNotificationMessageParsingError,
    ),
    PeerDownNotificationMessageError(
        #[from_located(module = "crate::wire::deserializer::v3")]
        PeerDownNotificationMessageParsingError,
    ),
    PeerDownNotificationTlvError(#[from_located(module = "self")] BmpV4PeerDownTlvParsingError),
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

impl<'a>
    ReadablePduWithOneInput<'a, &mut BmpParsingContext, LocatedBmpV4MessageValueParsingError<'a>>
    for BmpV4MessageValue
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BmpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBmpV4MessageValueParsingError<'a>> {
        let (buf, msg_type) = nom::combinator::map_res(be_u8, BmpMessageType::try_from)(buf)?;
        let (buf, msg) = match msg_type {
            BmpMessageType::RouteMonitoring => {
                let (buf, value) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpV4MessageValue::RouteMonitoring(value))
            }
            BmpMessageType::StatisticsReport => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpV4MessageValue::StatisticsReport(value))
            }
            BmpMessageType::PeerDownNotification => {
                let (buf, v3_notif) = parse_into_located_one_input(buf, ctx)?;
                let (buf, tlvs) = parse_till_empty_into_located(buf)?;
                (
                    buf,
                    BmpV4MessageValue::PeerDownNotification { v3_notif, tlvs },
                )
            }
            BmpMessageType::PeerUpNotification => {
                let (buf, value) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpV4MessageValue::PeerUpNotification(value))
            }
            BmpMessageType::Initiation => {
                let (buf, init) = parse_into_located(buf)?;
                (buf, BmpV4MessageValue::Initiation(init))
            }
            BmpMessageType::Termination => {
                let (buf, init) = parse_into_located(buf)?;
                (buf, BmpV4MessageValue::Termination(init))
            }
            BmpMessageType::RouteMirroring => {
                let (buf, init) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpV4MessageValue::RouteMirroring(init))
            }
            BmpMessageType::Experimental251 => {
                (buf, BmpV4MessageValue::Experimental252(buf.to_vec()))
            }
            BmpMessageType::Experimental252 => {
                (buf, BmpV4MessageValue::Experimental252(buf.to_vec()))
            }
            BmpMessageType::Experimental253 => {
                (buf, BmpV4MessageValue::Experimental253(buf.to_vec()))
            }
            BmpMessageType::Experimental254 => {
                (buf, BmpV4MessageValue::Experimental254(buf.to_vec()))
            }
        };
        Ok((buf, msg))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BmpV4PeerDownTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedBmpV4PeerDownTlvParsingError<'a>> for BmpV4PeerDownTlv {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBmpV4PeerDownTlvParsingError<'a>>
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
pub enum BmpV4RouteMonitoringMessageParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteMonitoringMessage(BmpV4RouteMonitoringError),
    PeerHeader(#[from_located(module = "crate::wire::deserializer::v3")] PeerHeaderParsingError),
    BgpMessage(
        #[from_located(module = "netgauze_bgp_pkt::wire::deserializer")] BgpMessageParsingError,
    ),
    RouteMonitoringTlvParsing(#[from_located(module = "self")] BmpV4RouteMonitoringTlvParsingError),
    MissingBgpPdu,
}

impl<'a>
    ReadablePduWithOneInput<
        'a,
        &mut BmpParsingContext,
        LocatedBmpV4RouteMonitoringMessageParsingError<'a>,
    > for BmpV4RouteMonitoringMessage
{
    fn from_wire(
        input: Span<'a>,
        ctx: &mut BmpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBmpV4RouteMonitoringMessageParsingError<'a>> {
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
                    (_, tlv_type)
                        if tlv_type == BmpV4RouteMonitoringTlvType::BgpUpdatePdu as u16 =>
                    {
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
                        LocatedBmpV4RouteMonitoringMessageParsingError::new(
                            input,
                            BmpV4RouteMonitoringMessageParsingError::MissingBgpPdu,
                        ),
                    ))
                }
            }
        };

        match Self::build(peer_header, update_pdu, tlvs) {
            Ok(rm) => Ok((remainder, rm)),
            Err(err) => Err(nom::Err::Error(
                LocatedBmpV4RouteMonitoringMessageParsingError::new(
                    input,
                    BmpV4RouteMonitoringMessageParsingError::RouteMonitoringMessage(err),
                ),
            )),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BmpV4RouteMonitoringTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    BgpMessage(
        #[from_located(module = "netgauze_bgp_pkt::wire::deserializer")] BgpMessageParsingError,
    ),
    FromUtf8Error(String),
    BgpCapability(#[from_located(module = "self")] BgpCapabilityParsingError),
    InvalidBmpV4RouteMonitoringTlv(BmpV4RouteMonitoringTlvError),
    PathMarking(#[from_located(module = "self")] PathMarkingParsingError),
}

impl<'a> FromExternalError<Span<'a>, FromUtf8Error>
    for LocatedBmpV4RouteMonitoringTlvParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: FromUtf8Error) -> Self {
        LocatedBmpV4RouteMonitoringTlvParsingError::new(
            input,
            BmpV4RouteMonitoringTlvParsingError::FromUtf8Error(error.to_string()),
        )
    }
}

impl<'a>
    ReadablePduWithOneInput<
        'a,
        &mut BgpParsingContext,
        LocatedBmpV4RouteMonitoringTlvParsingError<'a>,
    > for BmpV4RouteMonitoringTlv
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBmpV4RouteMonitoringTlvParsingError<'a>> {
        // Can't use read_tlv_header_t16_l16 because Index is in the middle of the
        // header and not counted in Length
        let (span, tlv_type) = be_u16(buf)?;
        let (span, tlv_length) = be_u16(span)?;
        let (span, index) = be_u16(span)?;
        let (remainder, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let value = match BmpV4RouteMonitoringTlvType::from_repr(tlv_type) {
            Some(tlv_type) => match tlv_type {
                BmpV4RouteMonitoringTlvType::VrfTableName => {
                    let (_, str) = nom::combinator::map_res(
                        nom::bytes::complete::take(tlv_length),
                        |x: Span<'_>| String::from_utf8(x.to_vec()),
                    )(data)?;
                    BmpV4RouteMonitoringTlvValue::VrfTableName(str)
                }
                BmpV4RouteMonitoringTlvType::BgpUpdatePdu => {
                    let (_, pdu) = parse_into_located_one_input(data, ctx)?;
                    BmpV4RouteMonitoringTlvValue::BgpUpdatePdu(pdu)
                }
                BmpV4RouteMonitoringTlvType::GroupTlv => {
                    let (_, values) = nom::multi::many0(be_u16)(data)?;
                    BmpV4RouteMonitoringTlvValue::GroupTlv(values)
                }
                BmpV4RouteMonitoringTlvType::StatelessParsing => {
                    let (_, bgp_capability) = parse_into_located(data)?;
                    ctx.update_capabilities(&bgp_capability);
                    BmpV4RouteMonitoringTlvValue::StatelessParsing(bgp_capability)
                }
                BmpV4RouteMonitoringTlvType::PathMarking => {
                    let (_, path_marking) = parse_into_located(data)?;
                    BmpV4RouteMonitoringTlvValue::PathMarking(path_marking)
                }
            },
            None => BmpV4RouteMonitoringTlvValue::Unknown {
                code: tlv_type,
                value: data.to_vec(),
            },
        };

        match BmpV4RouteMonitoringTlv::build(index, value) {
            Ok(tlv) => Ok((remainder, tlv)),
            Err(err) => Err(nom::Err::Error(
                LocatedBmpV4RouteMonitoringTlvParsingError {
                    span: buf,
                    error: BmpV4RouteMonitoringTlvParsingError::InvalidBmpV4RouteMonitoringTlv(err),
                },
            )),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize, Eq)]
pub enum PathMarkingParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    ReasonCodeBadLength(usize),
    UnknownPathMarkingReason(u16),
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

                let reason_code = PathMarkingReason::from_repr(reason_code).ok_or_else(|| {
                    nom::Err::Error(LocatedPathMarkingParsingError::new(
                        data,
                        PathMarkingParsingError::UnknownPathMarkingReason(reason_code),
                    ))
                })?;

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
            PathMarking {
                path_status,
                reason_code,
            },
        ))
    }
}
