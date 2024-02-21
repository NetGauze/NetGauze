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
    iana,
    iana::{
        BgpLsAttributeType, BgpLsAttributeTypeError, BgpLsIanaValueError,
        BgpLsLinkDescriptorType, BgpLsNlriType, BgpLsNodeDescriptorSubType,
        BgpLsNodeDescriptorType, BgpLsNodeDescriptorTypeError, BgpLsNodeFlagsBits,
        BgpLsPrefixDescriptorType, BgpLsProtocolIdError, LinkDescriptorTypeError,
        NodeDescriptorSubTypeError, PrefixDescriptorTypeError, UnknownBgpLsNlriType,
    },
    nlri::{
        BgpLsLinkDescriptor, BgpLsNlri, BgpLsNlriIpPrefix, BgpLsNlriLink, BgpLsNlriNode,
        BgpLsNlriValue, BgpLsNodeDescriptorSubTlv, BgpLsNodeDescriptor,
        BgpLsPrefixDescriptor, BgpLsVpnNlri, IgpFlags, IpReachabilityInformationData,
        MplsProtocolMask, MultiTopologyId, MultiTopologyIdData, OspfRouteType,
        SharedRiskLinkGroupValue, UnknownOspfRouteType,
    },
    path_attribute::{BgpLsAttribute, BgpLsAttributeValue, BgpLsPeerSid},
    wire::{
        deserializer::{
            nlri::{MplsLabelParsingError, RouteDistinguisherParsingError},
            Ipv4PrefixParsingError, Ipv6PrefixParsingError,
        },
        serializer::nlri::{IPV4_LEN, IPV6_LEN},
    },
};
use ipnet::IpNet;
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_till_empty_into_located,
    parse_till_empty_into_with_one_input_located, ErrorKindSerdeDeref, ReadablePdu,
    ReadablePduWithOneInput, Span,
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
use crate::path_attribute::LinkProtectionType;

/// BGP Link-State Attribute Parsing Errors
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpLsAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    MultiTopologyIdLengthError(usize),
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

/// BGP Link-State NLRI Parsing Errors
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpLsNlriParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UnknownNlriType(#[from_external] UnknownBgpLsNlriType),
    RouteDistinguisherParsingError(
        #[from_located(module = "crate::wire::deserializer::nlri")] RouteDistinguisherParsingError,
    ),
    UnknownProtocolId(#[from_external] BgpLsProtocolIdError),
    UnknownDescriptorTlvType(#[from_external] BgpLsNodeDescriptorTypeError),
    UnknownNodeDescriptorSubTlvType(#[from_external] NodeDescriptorSubTypeError),
    UnknownPrefixDescriptorTlvType(#[from_external] PrefixDescriptorTypeError),
    UnknownOspfRouteType(#[from_external] UnknownOspfRouteType),
    BadNodeDescriptorTlvType(BgpLsNodeDescriptorType),
    UnknownLinkDescriptorTlvType(#[from_external] LinkDescriptorTypeError),
    BadTlvTypeInNlri(BgpLsNlriType),
    Ipv4PrefixError(#[from_located(module = "crate::wire::deserializer")] Ipv4PrefixParsingError),
    Ipv6PrefixError(#[from_located(module = "crate::wire::deserializer")] Ipv6PrefixParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlri {
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (buf, path_id) = if add_path {
            let (tmp, add_path) = be_u32(buf)?;
            (tmp, Some(add_path))
        } else {
            (buf, None)
        };
        let (buf, nlri_type) = nom::combinator::map_res(be_u16, BgpLsNlriType::try_from)(buf)?;
        let (buf, nlri_len) = be_u16(buf)?;
        let (buf, data) = nom::bytes::complete::take(nlri_len)(buf)?;

        let (_, value) = BgpLsNlriValue::from_wire(data, nlri_type)?;

        Ok((buf, BgpLsNlri { path_id, value }))
    }
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedBgpLsNlriParsingError<'a>> for BgpLsVpnNlri {
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (buf, path_id) = if add_path {
            let (tmp, add_path) = be_u32(buf)?;
            (tmp, Some(add_path))
        } else {
            (buf, None)
        };

        let (buf, nlri_type) = nom::combinator::map_res(be_u16, BgpLsNlriType::try_from)(buf)?;
        let (buf, nlri_len) = be_u16(buf)?;
        let (buf, data) = nom::bytes::complete::take(nlri_len)(buf)?;

        let (data, rd) = parse_into_located(data)?;
        let (_, nlri) = BgpLsNlriValue::from_wire(data, nlri_type)?;

        Ok((
            buf,
            BgpLsVpnNlri {
                path_id,
                rd,
                value: nlri,
            },
        ))
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>>
    for BgpLsNlriValue
{
    fn from_wire(
        buf: Span<'a>,
        nlri_type: BgpLsNlriType,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let result = match nlri_type {
            BgpLsNlriType::Node => {
                let (span, nlri_value) = BgpLsNlriNode::from_wire(buf)?;
                (span, BgpLsNlriValue::Node(nlri_value))
            }
            BgpLsNlriType::Link => {
                let (span, nlri_value) = BgpLsNlriLink::from_wire(buf)?;
                (span, BgpLsNlriValue::Link(nlri_value))
            }
            BgpLsNlriType::Ipv4TopologyPrefix => {
                let (span, nlri_value) =
                    BgpLsNlriIpPrefix::from_wire(buf, BgpLsNlriType::Ipv4TopologyPrefix)?;
                (span, BgpLsNlriValue::Ipv4Prefix(nlri_value))
            }
            BgpLsNlriType::Ipv6TopologyPrefix => {
                let (span, nlri_value) =
                    BgpLsNlriIpPrefix::from_wire(buf, BgpLsNlriType::Ipv6TopologyPrefix)?;
                (span, BgpLsNlriValue::Ipv6Prefix(nlri_value))
            }
            BgpLsNlriType::TePolicy => unimplemented!(),
            BgpLsNlriType::Srv6Sid => unimplemented!(),
        };

        Ok(result)
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlriLink {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;

        let (span, local_node_descriptors) = parse_into_located(span)?;

        if !matches!(local_node_descriptors, BgpLsNodeDescriptor::Local(_)) {
            return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                span,
                BgpLsNlriParsingError::BadNodeDescriptorTlvType(
                    BgpLsNodeDescriptorType::RemoteNodeDescriptor,
                ),
            )));
        }

        let (span, remote_node_descriptors) = parse_into_located(span)?;

        if !matches!(remote_node_descriptors, BgpLsNodeDescriptor::Remote(_)) {
            return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                span,
                BgpLsNlriParsingError::BadNodeDescriptorTlvType(
                    BgpLsNodeDescriptorType::RemoteNodeDescriptor,
                ),
            )));
        }

        let (span, link_descriptors) = parse_till_empty_into_located(span)?;

        Ok((
            span,
            BgpLsNlriLink {
                protocol_id,
                identifier,
                local_node_descriptors,
                remote_node_descriptors,
                link_descriptors,
            },
        ))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsLinkDescriptor {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header(buf)?;

        let tlv_type = match BgpLsLinkDescriptorType::try_from(tlv_type) {
            Ok(value) => value,
            Err(LinkDescriptorTypeError(BgpLsIanaValueError::Unknown(value))) => {
                return Ok((
                    remainder,
                    BgpLsLinkDescriptor::Unknown {
                        code: value,
                        value: data.to_vec(),
                    },
                ))
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                    buf,
                    BgpLsNlriParsingError::UnknownLinkDescriptorTlvType(error),
                )));
            }
        };

        let tlv = match tlv_type {
            BgpLsLinkDescriptorType::LinkLocalRemoteIdentifiers => {
                let (remainder, link_local_identifier) = be_u32(data)?;
                let (_remainder, link_remote_identifier) = be_u32(remainder)?;
                BgpLsLinkDescriptor::LinkLocalRemoteIdentifiers {
                    link_local_identifier,
                    link_remote_identifier,
                }
            }
            BgpLsLinkDescriptorType::IPv4InterfaceAddress => {
                let (_remainder, ipv4) = be_u32(data)?;
                BgpLsLinkDescriptor::IPv4InterfaceAddress(Ipv4Addr::from(ipv4))
            }
            BgpLsLinkDescriptorType::IPv4NeighborAddress => {
                let (_remainder, ipv4) = be_u32(data)?;
                BgpLsLinkDescriptor::IPv4NeighborAddress(Ipv4Addr::from(ipv4))
            }
            BgpLsLinkDescriptorType::IPv6InterfaceAddress => {
                let (_remainder, ipv6) = be_u128(data)?;
                // TODO CHECK NOT LOCAL-LINK
                BgpLsLinkDescriptor::IPv6InterfaceAddress(Ipv6Addr::from(ipv6))
            }
            BgpLsLinkDescriptorType::IPv6NeighborAddress => {
                let (_remainder, ipv6) = be_u128(data)?;
                // TODO CHECK NOT LOCAL-LINK
                BgpLsLinkDescriptor::IPv6NeighborAddress(Ipv6Addr::from(ipv6))
            }
            BgpLsLinkDescriptorType::MultiTopologyIdentifier => {
                let (_remainder, mtid) = parse_into_located::<
                    LocatedBgpLsNlriParsingError<'a>,
                    LocatedBgpLsNlriParsingError<'a>,
                    MultiTopologyIdData,
                >(data)?;
                BgpLsLinkDescriptor::MultiTopologyIdentifier(mtid)
            }
        };

        Ok((remainder, tlv))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlriNode {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;

        let (span, local_node_descriptors) = parse_into_located(span)?;

        if !matches!(local_node_descriptors, BgpLsNodeDescriptor::Local(_)) {
            return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                span,
                BgpLsNlriParsingError::BadNodeDescriptorTlvType(
                    BgpLsNodeDescriptorType::RemoteNodeDescriptor,
                ),
            )));
        }

        Ok((
            span,
            BgpLsNlriNode {
                protocol_id,
                identifier,
                local_node_descriptors,
            },
        ))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNodeDescriptor {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, tlv_type) =
            nom::combinator::map_res(be_u16, iana::BgpLsNodeDescriptorType::try_from)(span)?;
        let (span, tlv_length) = be_u16(span)?;
        let (span, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let (_, subtlvs) = parse_till_empty_into_located(data)?;

        let descriptor = match tlv_type {
            BgpLsNodeDescriptorType::LocalNodeDescriptor => {
                BgpLsNodeDescriptor::Local(subtlvs)
            }
            BgpLsNodeDescriptorType::RemoteNodeDescriptor => {
                BgpLsNodeDescriptor::Remote(subtlvs)
            }
        };

        Ok((span, descriptor))
    }
}

fn read_tlv_header<'a, E, T>(buf: Span<'a>) -> Result<(u16, u16, Span<'a>, Span<'a>), E>
where
    E: From<nom::Err<T>>,
    T: nom::error::ParseError<netgauze_locate::BinarySpan<&'a [u8]>>,
{
    let (span, tlv_type) = be_u16(buf)?;
    let (span, tlv_length) = be_u16(span)?;
    let (remainder, data) = nom::bytes::complete::take(tlv_length)(span)?;

    Ok((tlv_type, tlv_length, data, remainder))
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNodeDescriptorSubTlv {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header(buf)?;

        let tlv_type = match BgpLsNodeDescriptorSubType::try_from(tlv_type) {
            Ok(value) => value,
            Err(NodeDescriptorSubTypeError(BgpLsIanaValueError::Unknown(value))) => {
                return Ok((
                    remainder,
                    BgpLsNodeDescriptorSubTlv::Unknown {
                        code: value,
                        value: data.to_vec(),
                    },
                ))
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                    buf,
                    BgpLsNlriParsingError::UnknownNodeDescriptorSubTlvType(error),
                )));
            }
        };

        let result = match tlv_type {
            BgpLsNodeDescriptorSubType::AutonomousSystem => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::AutonomousSystem(value)
            }
            BgpLsNodeDescriptorSubType::BgpLsIdentifier => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(value)
            }
            BgpLsNodeDescriptorSubType::OspfAreaId => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::OspfAreaId(value)
            }
            BgpLsNodeDescriptorSubType::IgpRouterId => {
                BgpLsNodeDescriptorSubTlv::IgpRouterId(data.to_vec())
            }
            BgpLsNodeDescriptorSubType::BgpRouterIdentifier => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::BgpRouterIdentifier(value)
            }
            BgpLsNodeDescriptorSubType::MemberAsNumber => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::MemberAsNumber(value)
            }
        };

        Ok((remainder, result))
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>>
    for BgpLsNlriIpPrefix
{
    fn from_wire(
        span: Span<'a>,
        nlri_type: BgpLsNlriType,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;

        let (span, local_node_descriptors) = parse_into_located(span)?;

        if !matches!(local_node_descriptors, BgpLsNodeDescriptor::Local(_)) {
            return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                span,
                BgpLsNlriParsingError::BadNodeDescriptorTlvType(
                    BgpLsNodeDescriptorType::RemoteNodeDescriptor,
                ),
            )));
        }

        let (span, prefix_descriptors) =
            parse_till_empty_into_with_one_input_located(span, nlri_type)?;

        Ok((
            span,
            BgpLsNlriIpPrefix {
                protocol_id,
                identifier,
                local_node_descriptors,
                prefix_descriptors,
            },
        ))
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>>
    for BgpLsPrefixDescriptor
{
    fn from_wire(
        buf: Span<'a>,
        nlri_type: BgpLsNlriType,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header(buf)?;

        let tlv_type = match BgpLsPrefixDescriptorType::try_from(tlv_type) {
            Ok(value) => value,
            Err(PrefixDescriptorTypeError(BgpLsIanaValueError::Unknown(value))) => {
                return Ok((
                    remainder,
                    BgpLsPrefixDescriptor::Unknown {
                        code: value,
                        value: data.to_vec(),
                    },
                ))
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                    buf,
                    BgpLsNlriParsingError::UnknownPrefixDescriptorTlvType(error),
                )));
            }
        };

        let tlv = match tlv_type {
            BgpLsPrefixDescriptorType::MultiTopologyIdentifier => {
                let (_, mtid) = parse_into_located::<
                    LocatedBgpLsNlriParsingError<'a>,
                    LocatedBgpLsNlriParsingError<'a>,
                    MultiTopologyIdData,
                >(data)?;
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(mtid)
            }
            BgpLsPrefixDescriptorType::OspfRouteType => {
                let (_, ospf_route_type) = parse_into_located(data)?;
                BgpLsPrefixDescriptor::OspfRouteType(ospf_route_type)
            }
            BgpLsPrefixDescriptorType::IpReachabilityInformation => {
                let (_, ip_reachability_info) = parse_into_located_one_input(data, nlri_type)?;
                BgpLsPrefixDescriptor::IpReachabilityInformation(ip_reachability_info)
            }
        };

        Ok((remainder, tlv))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for MultiTopologyIdData {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, ids) = parse_till_empty_into_located::<
            LocatedBgpLsNlriParsingError<'_>,
            LocatedBgpLsNlriParsingError<'_>,
            MultiTopologyId,
        >(span)?;
        Ok((span, MultiTopologyIdData(ids)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for MultiTopologyId {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        let (span, id) = be_u16(span)?;
        Ok((span, MultiTopologyId::from(id)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for OspfRouteType {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        nom::combinator::map_res(be_u8, OspfRouteType::try_from)(span)
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>>
    for IpReachabilityInformationData
{
    fn from_wire(
        span: Span<'a>,
        nlri_type: BgpLsNlriType,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>>
    where
        Self: Sized,
    {
        match nlri_type {
            BgpLsNlriType::Ipv4TopologyPrefix => {
                let (remainder, ipv4) = parse_into_located(span)?;
                Ok((remainder, IpReachabilityInformationData(IpNet::V4(ipv4))))
            }
            BgpLsNlriType::Ipv6TopologyPrefix => {
                let (remainder, ipv6) = parse_into_located(span)?;
                Ok((remainder, IpReachabilityInformationData(IpNet::V6(ipv6))))
            }
            BgpLsNlriType::Node
            | BgpLsNlriType::Link
            | BgpLsNlriType::TePolicy
            | BgpLsNlriType::Srv6Sid => {
                return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                    span,
                    BgpLsNlriParsingError::BadTlvTypeInNlri(nlri_type),
                )));
            }
        }
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

        return if length == 7 && Self::flags_have_v_flag(flags) {
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
        };
    }
}
