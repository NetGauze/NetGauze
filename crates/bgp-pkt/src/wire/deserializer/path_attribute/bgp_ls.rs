// Copyright (C) 2023-present The NetGauze Authors.
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
    iana::{BgpLsAttributeType, BgpLsAttributeTypeError, BgpLsIanaValueError, BgpLsNodeFlagsBits},
    nlri::{
        IgpFlags, MplsProtocolMask, MultiTopologyId, MultiTopologyIdData, SharedRiskLinkGroupValue,
    },
    path_attribute::{BgpLsAttribute, BgpLsAttributeValue, BgpLsPeerSid, LinkProtectionType},
    wire::{
        deserializer::{nlri::MplsLabelParsingError, read_tlv_header},
        serializer::nlri::{IPV4_LEN, IPV6_LEN},
    },
};
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_till_empty_into_located,
    ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_f32, be_u128, be_u16, be_u32, be_u64, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::BitAnd,
    string::FromUtf8Error,
};

/// BGP Link-State Attribute Parsing Errors
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpLsAttributeParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UnknownTlvType(#[from_external] BgpLsAttributeTypeError),
    Utf8Error(String),
    WrongIpAddrLength(usize),
    BadUnreservedBandwidthLength(usize),
    MplsLabelParsingError(
        #[from_located(module = "crate::wire::deserializer::nlri")] MplsLabelParsingError,
    ),
    BadSidValue(u8),
}

impl<'a> FromExternalError<Span<'a>, FromUtf8Error> for LocatedBgpLsAttributeParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: FromUtf8Error) -> Self {
        LocatedBgpLsAttributeParsingError::new(
            input,
            BgpLsAttributeParsingError::Utf8Error(error.to_string()),
        )
    }
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedBgpLsAttributeParsingError<'a>>
    for BgpLsAttribute
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        let (_buf, ls_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };

        let (span, attributes) = parse_till_empty_into_located(ls_buf)?;

        Ok((span, BgpLsAttribute { attributes }))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for BgpLsAttributeValue {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        let (tlv_type, tlv_length, data, remainder) = read_tlv_header(buf)?;

        let tlv_type = match BgpLsAttributeType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpLsAttributeTypeError(BgpLsIanaValueError::Unknown(value))) => {
                return Ok((
                    remainder,
                    BgpLsAttributeValue::Unknown {
                        code: value,
                        value: data.to_vec(),
                    },
                ))
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedBgpLsAttributeParsingError::new(
                    buf,
                    BgpLsAttributeParsingError::UnknownTlvType(error),
                )));
            }
        };

        let tlv = match tlv_type {
            BgpLsAttributeType::MultiTopologyIdentifier => {
                let (_, mtid) = parse_into_located::<
                    LocatedBgpLsAttributeParsingError<'_>,
                    LocatedBgpLsAttributeParsingError<'_>,
                    MultiTopologyIdData,
                >(data)?;
                BgpLsAttributeValue::MultiTopologyIdentifier(mtid)
            }
            BgpLsAttributeType::NodeFlagBits => {
                let (_, flags) = be_u8(data)?;
                BgpLsAttributeValue::NodeFlagBits {
                    overload: flags.bitand(BgpLsNodeFlagsBits::Overload as u8)
                        == BgpLsNodeFlagsBits::Overload as u8,
                    attached: flags.bitand(BgpLsNodeFlagsBits::Attached as u8)
                        == BgpLsNodeFlagsBits::Attached as u8,
                    external: flags.bitand(BgpLsNodeFlagsBits::External as u8)
                        == BgpLsNodeFlagsBits::External as u8,
                    abr: flags.bitand(BgpLsNodeFlagsBits::Abr as u8)
                        == BgpLsNodeFlagsBits::Abr as u8,
                    router: flags.bitand(BgpLsNodeFlagsBits::Router as u8)
                        == BgpLsNodeFlagsBits::Router as u8,
                    v6: flags.bitand(BgpLsNodeFlagsBits::V6 as u8) == BgpLsNodeFlagsBits::V6 as u8,
                }
            }
            BgpLsAttributeType::OpaqueNodeAttribute => {
                BgpLsAttributeValue::OpaqueNodeAttribute(data.to_vec())
            }
            BgpLsAttributeType::NodeNameTlv => {
                let (_, str) = nom::combinator::map_res(
                    nom::bytes::complete::take(tlv_length),
                    |x: Span<'_>| String::from_utf8(x.to_vec()),
                )(data)?;
                BgpLsAttributeValue::NodeNameTlv(str)
            }
            BgpLsAttributeType::IsIsArea => BgpLsAttributeValue::IsIsArea(data.to_vec()),
            BgpLsAttributeType::LocalNodeIpv4RouterId => {
                let (_, address) = be_u32(data)?;
                BgpLsAttributeValue::LocalNodeIpv4RouterId(Ipv4Addr::from(address))
            }
            BgpLsAttributeType::LocalNodeIpv6RouterId => {
                let (_, address) = be_u128(data)?;
                BgpLsAttributeValue::LocalNodeIpv6RouterId(Ipv6Addr::from(address))
            }
            BgpLsAttributeType::RemoteNodeIpv4RouterId => {
                let (_, address) = be_u32(data)?;
                BgpLsAttributeValue::RemoteNodeIpv4RouterId(Ipv4Addr::from(address))
            }
            BgpLsAttributeType::RemoteNodeIpv6RouterId => {
                let (_, address) = be_u128(data)?;
                BgpLsAttributeValue::RemoteNodeIpv6RouterId(Ipv6Addr::from(address))
            }
            BgpLsAttributeType::RemoteNodeAdministrativeGroupColor => {
                let (_, color) = be_u32(data)?;
                BgpLsAttributeValue::RemoteNodeAdministrativeGroupColor(color)
            }
            BgpLsAttributeType::MaximumLinkBandwidth => {
                let (_, bandwidth) = be_f32(data)?;
                BgpLsAttributeValue::MaximumLinkBandwidth(bandwidth)
            }
            BgpLsAttributeType::MaximumReservableLinkBandwidth => {
                let (_, bandwidth) = be_f32(data)?;
                BgpLsAttributeValue::MaximumReservableLinkBandwidth(bandwidth)
            }
            BgpLsAttributeType::UnreservedBandwidth => {
                let (_, vec) = nom::multi::count(be_f32, 8)(data)?;
                let len = vec.len();
                let value: [f32; 8] = vec.try_into().map_err(|_| {
                    nom::Err::Error(LocatedBgpLsAttributeParsingError::new(
                        data,
                        BgpLsAttributeParsingError::BadUnreservedBandwidthLength(len),
                    ))
                })?;
                BgpLsAttributeValue::UnreservedBandwidth(value)
            }
            BgpLsAttributeType::TeDefaultMetric => {
                let (_, metric) = be_u32(data)?;
                BgpLsAttributeValue::TeDefaultMetric(metric)
            }
            BgpLsAttributeType::LinkProtectionType => {
                let (_, flags) = be_u16(data)?;
                BgpLsAttributeValue::LinkProtectionType {
                    extra_traffic: flags.bitand(LinkProtectionType::ExtraTraffic as u16)
                        == LinkProtectionType::ExtraTraffic as u16,
                    unprotected: flags.bitand(LinkProtectionType::Unprotected as u16)
                        == LinkProtectionType::Unprotected as u16,
                    shared: flags.bitand(LinkProtectionType::Shared as u16)
                        == LinkProtectionType::Shared as u16,
                    dedicated1c1: flags.bitand(LinkProtectionType::Dedicated1c1 as u16)
                        == LinkProtectionType::Dedicated1c1 as u16,
                    dedicated1p1: flags.bitand(LinkProtectionType::Dedicated1p1 as u16)
                        == LinkProtectionType::Dedicated1p1 as u16,
                    enhanced: flags.bitand(LinkProtectionType::Enhanced as u16)
                        == LinkProtectionType::Enhanced as u16,
                }
            }
            BgpLsAttributeType::MplsProtocolMask => {
                let (_, flags) = be_u8(data)?;
                BgpLsAttributeValue::MplsProtocolMask {
                    ldp: flags.bitand(MplsProtocolMask::LabelDistributionProtocol as u8)
                        == MplsProtocolMask::LabelDistributionProtocol as u8,
                    rsvp_te: flags.bitand(MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8)
                        == MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8,
                }
            }
            BgpLsAttributeType::IgpMetric => BgpLsAttributeValue::IgpMetric(data.to_vec()),
            BgpLsAttributeType::SharedRiskLinkGroup => {
                let (_, values) = parse_till_empty_into_located(data)?;
                BgpLsAttributeValue::SharedRiskLinkGroup(values)
            }
            BgpLsAttributeType::OpaqueLinkAttribute => {
                BgpLsAttributeValue::OpaqueLinkAttribute(data.to_vec())
            }
            BgpLsAttributeType::LinkName => {
                let (_, str) = nom::combinator::map_res(
                    nom::bytes::complete::take(tlv_length),
                    |x: Span<'_>| String::from_utf8(x.to_vec()),
                )(data)?;
                BgpLsAttributeValue::LinkName(str)
            }
            BgpLsAttributeType::IgpFlags => {
                let (_, flags) = be_u8(data)?;
                BgpLsAttributeValue::IgpFlags {
                    isis_up_down: flags.bitand(IgpFlags::IsIsUp as u8) == IgpFlags::IsIsUp as u8,
                    ospf_no_unicast: flags.bitand(IgpFlags::OspfNoUnicast as u8)
                        == IgpFlags::OspfNoUnicast as u8,
                    ospf_local_address: flags.bitand(IgpFlags::OspfLocalAddress as u8)
                        == IgpFlags::OspfLocalAddress as u8,
                    ospf_propagate_nssa: flags.bitand(IgpFlags::OspfPropagateNssa as u8)
                        == IgpFlags::OspfPropagateNssa as u8,
                }
            }
            BgpLsAttributeType::IgpRouteTag => {
                let (_, vec) = parse_till_empty_into_located(data)?;
                BgpLsAttributeValue::IgpRouteTag(vec)
            }
            BgpLsAttributeType::IgpExtendedRouteTag => {
                let (_, vec) = parse_till_empty_into_located(data)?;
                BgpLsAttributeValue::IgpExtendedRouteTag(vec)
            }
            BgpLsAttributeType::PrefixMetric => {
                let (_, metric) = be_u32(data)?;
                BgpLsAttributeValue::PrefixMetric(metric)
            }
            BgpLsAttributeType::OspfForwardingAddress => {
                let address = if tlv_length == IPV4_LEN as u16 {
                    let (_, ip) = be_u32(data)?;
                    IpAddr::V4(Ipv4Addr::from(ip))
                } else if tlv_length == IPV6_LEN as u16 {
                    let (_, ip) = be_u128(data)?;
                    IpAddr::V6(Ipv6Addr::from(ip))
                } else {
                    return Err(nom::Err::Error(LocatedBgpLsAttributeParsingError::new(
                        data,
                        BgpLsAttributeParsingError::WrongIpAddrLength(tlv_length.into()),
                    )));
                };

                BgpLsAttributeValue::OspfForwardingAddress(address)
            }
            BgpLsAttributeType::OpaquePrefixAttribute => {
                BgpLsAttributeValue::OpaquePrefixAttribute(data.to_vec())
            }
            BgpLsAttributeType::PeerNodeSid => {
                let (_, value) = parse_into_located_one_input(data, tlv_length)?;
                BgpLsAttributeValue::PeerNodeSid(value)
            }
            BgpLsAttributeType::PeerAdjSid => {
                let (_, value) = parse_into_located_one_input(data, tlv_length)?;
                BgpLsAttributeValue::PeerAdjSid(value)
            }
            BgpLsAttributeType::PeerSetSid => {
                let (_, value) = parse_into_located_one_input(data, tlv_length)?;
                BgpLsAttributeValue::PeerSetSid(value)
            }
        };

        Ok((remainder, tlv))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for u32 {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        be_u32(buf)
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for u64 {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        be_u64(buf)
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for SharedRiskLinkGroupValue {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, value) = be_u32(buf)?;
        Ok((span, SharedRiskLinkGroupValue(value)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for MultiTopologyIdData {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, value) = parse_till_empty_into_located::<
            LocatedBgpLsAttributeParsingError<'_>,
            LocatedBgpLsAttributeParsingError<'_>,
            MultiTopologyId,
        >(buf)?;
        Ok((span, MultiTopologyIdData(value)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for MultiTopologyId {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        let (buf, mtid) = be_u16(buf)?;

        Ok((buf, MultiTopologyId::from(mtid)))
    }
}

impl<'a> ReadablePduWithOneInput<'a, u16, LocatedBgpLsAttributeParsingError<'a>> for BgpLsPeerSid {
    fn from_wire(
        buf: Span<'a>,
        length: u16,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, flags) = be_u8(buf)?;
        let (span, weight) = be_u8(span)?;
        let (span, _reserved) = be_u16(span)?;

        if length == 7 && Self::flags_have_v_flag(flags) {
            let (span, label) = parse_into_located(span)?;

            // TODO check if max 20 rightmost bits are set

            Ok((
                span,
                BgpLsPeerSid::LabelValue {
                    flags,
                    weight,
                    label,
                },
            ))
        } else if length == 8 && !Self::flags_have_v_flag(flags) {
            let (span, index) = be_u32(span)?;
            Ok((
                span,
                BgpLsPeerSid::IndexValue {
                    flags,
                    weight,
                    index,
                },
            ))
        } else {
            Err(nom::Err::Error(LocatedBgpLsAttributeParsingError::new(
                buf,
                BgpLsAttributeParsingError::BadSidValue(flags),
            )))
        }
    }
}
