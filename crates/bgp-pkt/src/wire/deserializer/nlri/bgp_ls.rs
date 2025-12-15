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

use crate::iana;
use crate::iana::{
    BgpLsLinkDescriptorType, BgpLsNlriType, BgpLsNodeDescriptorSubType, BgpLsNodeDescriptorType,
    BgpLsNodeDescriptorTypeError, BgpLsPrefixDescriptorType, BgpLsProtocolIdError, IanaValueError,
    LinkDescriptorTypeError, NodeDescriptorSubTypeError, PrefixDescriptorTypeError,
    UnknownBgpLsNlriType,
};
use crate::nlri::{
    BgpLsLinkDescriptor, BgpLsLocalNodeDescriptors, BgpLsNlri, BgpLsNlriIpPrefix, BgpLsNlriLink,
    BgpLsNlriNode, BgpLsNlriValue, BgpLsNodeDescriptorSubTlv, BgpLsNodeDescriptors,
    BgpLsPrefixDescriptor, BgpLsRemoteNodeDescriptors, BgpLsVpnNlri, IpReachabilityInformationData,
    MultiTopologyId, MultiTopologyIdData, OspfRouteType, UnknownOspfRouteType,
};
use crate::wire::deserializer::nlri::RouteDistinguisherParsingError;
use crate::wire::deserializer::{
    Ipv4PrefixParsingError, Ipv6PrefixParsingError, read_tlv_header_t16_l16,
};
use ipnet::IpNet;
use netgauze_parse_utils::{
    ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput, Span, parse_into_located,
    parse_into_located_one_input, parse_till_empty_into_located,
    parse_till_empty_into_with_one_input_located,
};
use netgauze_serde_macros::LocatedError;
use nom::IResult;
use nom::error::ErrorKind;
use nom::number::complete::{be_u8, be_u16, be_u32, be_u64, be_u128};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

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
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
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
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
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
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
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
            BgpLsNlriType::TePolicy | BgpLsNlriType::Srv6Sid => {
                let (buf, value): (Span<'_>, Span<'_>) =
                    nom::bytes::complete::take(buf.len())(buf)?;
                (
                    buf,
                    BgpLsNlriValue::Unknown {
                        code: nlri_type.into(),
                        value: value.to_vec(),
                    },
                )
            }
        };

        Ok(result)
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlriLink {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;
        let (span, local_node_descriptors) = parse_into_located(span)?;
        let (span, remote_node_descriptors) = parse_into_located(span)?;
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
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header_t16_l16(buf)?;

        let tlv_type = match BgpLsLinkDescriptorType::try_from(tlv_type) {
            Ok(value) => value,
            Err(LinkDescriptorTypeError(IanaValueError::Unknown(value))) => {
                return Ok((
                    remainder,
                    BgpLsLinkDescriptor::Unknown {
                        code: value,
                        value: data.to_vec(),
                    },
                ));
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
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;
        let (span, local_node_descriptors) = parse_into_located(span)?;

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

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsLocalNodeDescriptors {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, value) =
            parse_into_located_one_input(buf, BgpLsNodeDescriptorType::LocalNodeDescriptor)?;

        Ok((span, BgpLsLocalNodeDescriptors(value)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsRemoteNodeDescriptors {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, value) =
            parse_into_located_one_input(buf, BgpLsNodeDescriptorType::RemoteNodeDescriptor)?;

        Ok((span, BgpLsRemoteNodeDescriptors(value)))
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNodeDescriptorType, LocatedBgpLsNlriParsingError<'a>>
    for BgpLsNodeDescriptors
{
    fn from_wire(
        span: Span<'a>,
        input: BgpLsNodeDescriptorType,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, tlv_type) =
            nom::combinator::map_res(be_u16, iana::BgpLsNodeDescriptorType::try_from)(span)?;

        if tlv_type != input {
            return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                span,
                BgpLsNlriParsingError::BadNodeDescriptorTlvType(tlv_type),
            )));
        }

        let (span, tlv_length) = be_u16(span)?;
        let (span, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let (_, subtlvs) = parse_till_empty_into_located(data)?;

        Ok((span, BgpLsNodeDescriptors(subtlvs)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNodeDescriptorSubTlv {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header_t16_l16(buf)?;

        let tlv_type = match BgpLsNodeDescriptorSubType::try_from(tlv_type) {
            Ok(value) => value,
            Err(NodeDescriptorSubTypeError(IanaValueError::Unknown(value))) => {
                return Ok((
                    remainder,
                    BgpLsNodeDescriptorSubTlv::Unknown {
                        code: value,
                        value: data.to_vec(),
                    },
                ));
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
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;
        let (span, local_node_descriptors) = parse_into_located(span)?;
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
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header_t16_l16(buf)?;

        let tlv_type = match BgpLsPrefixDescriptorType::try_from(tlv_type) {
            Ok(value) => value,
            Err(PrefixDescriptorTypeError(IanaValueError::Unknown(value))) => {
                return Ok((
                    remainder,
                    BgpLsPrefixDescriptor::Unknown {
                        code: value,
                        value: data.to_vec(),
                    },
                ));
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
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, ids) = parse_till_empty_into_located::<
            LocatedBgpLsNlriParsingError<'_>,
            LocatedBgpLsNlriParsingError<'_>,
            MultiTopologyId,
        >(span)?;
        Ok((span, MultiTopologyIdData(ids)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for MultiTopologyId {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        let (span, id) = be_u16(span)?;
        Ok((span, MultiTopologyId::from(id)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for OspfRouteType {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
        nom::combinator::map_res(be_u8, OspfRouteType::try_from)(span)
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>>
    for IpReachabilityInformationData
{
    fn from_wire(
        span: Span<'a>,
        nlri_type: BgpLsNlriType,
    ) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> {
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
            | BgpLsNlriType::Srv6Sid => Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(
                span,
                BgpLsNlriParsingError::BadTlvTypeInNlri(nlri_type),
            ))),
        }
    }
}
