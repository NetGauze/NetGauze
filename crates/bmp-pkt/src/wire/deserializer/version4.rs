use crate::{
    iana::{BmpMessageType, UndefinedBmpMessageType},
    version4::{
        BmpStatelessParsingCapability, BmpV4MessageValue, BmpV4RouteMonitoringError,
        BmpV4RouteMonitoringMessage, BmpV4RouteMonitoringTlv, BmpV4RouteMonitoringTlvError,
        BmpV4RouteMonitoringTlvType, BmpV4RouteMonitoringTlvValue, StatelessParsingTlv,
        UnknownBmpStatelessParsingCapability,
    },
    wire::deserializer::*,
    PeerHeader, PeerKey,
};
use crate::wire::deserializer::*;
use netgauze_bgp_pkt::wire::deserializer::{read_tlv_header_t16_l16, BgpMessageParsingError};
use netgauze_bgp_pkt::wire::deserializer::BgpMessageParsingError;
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, ReadablePduWithOneInput, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{error::ErrorKind, number::complete::be_u8, IResult};
use serde::{Deserialize, Serialize};
use either::Either;

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BmpV4MessageValueParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpMessageType(#[from_external] UndefinedBmpMessageType),
    RouteMonitoringMessageError(
        #[from_located(module = "self")] BmpV4RouteMonitoringMessageParsingError,
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
                let (buf, value) = parse_into_located_one_input(buf, ctx)?;
                (buf, BmpV4MessageValue::PeerDownNotification(value))
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
pub enum BmpV4RouteMonitoringMessageParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteMonitoringMessage(BmpV4RouteMonitoringError),
    PeerHeader(#[from_located(module = "self")] PeerHeaderParsingError),
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

                let (tmp, element) = parse_into_located_one_input(buf, &mut *bgp_ctx)?;
                tlvs.push(element);
                buf = tmp;
            }

            // Parse the PDU
            match bgp_pdu {
                Some(bgp_pdu) => {
                    let (_, bgp_pdu): (_, BgpMessage) =
                        parse_into_located_one_input(bgp_pdu, &mut *bgp_ctx)?;
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
    StatelessParsingTlv(#[from_located(module = "self")] StatelessParsingTlvParsingError),
    InvalidBmpV4RouteMonitoringTlv(BmpV4RouteMonitoringTlvError),
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
                    let (_, stateless_parsing_tlv) = parse_into_located_one_input(data, ctx)?;
                    BmpV4RouteMonitoringTlvValue::StatelessParsing(stateless_parsing_tlv)
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum StatelessParsingTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidAddressType(InvalidAddressType),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    UnknownBmpStatelessParsingCapability(#[from_external] UnknownBmpStatelessParsingCapability),
}

impl<'a>
    ReadablePduWithOneInput<'a, &mut BgpParsingContext, LocatedStatelessParsingTlvParsingError<'a>>
    for StatelessParsingTlv
{
    fn from_wire(
        input: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedStatelessParsingTlvParsingError<'a>> {
        let buf = input;
        let (buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(buf)?;
        let (buf, safi) = nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(buf)?;

        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(val) => val,
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedStatelessParsingTlvParsingError::new(
                        input,
                        StatelessParsingTlvParsingError::InvalidAddressType(err),
                    ),
                ))
            }
        };

        let (buf, capability) =
            nom::combinator::map_res(be_u16, BmpStatelessParsingCapability::try_from)(buf)?;
        let (buf, enabled) = be_u8(buf)?;
        let enabled = enabled == 1;

        match capability {
            BmpStatelessParsingCapability::AddPath => {
                ctx.add_path_mut().insert(address_type, enabled);
            }
            BmpStatelessParsingCapability::MultipleLabels => {
                ctx.multiple_labels_mut()
                    .insert(address_type, if enabled { u8::MAX } else { 0 });
            }
        }

        Ok((
            buf,
            StatelessParsingTlv {
                address_type,
                capability,
                enabled,
            },
        ))
    }
}
