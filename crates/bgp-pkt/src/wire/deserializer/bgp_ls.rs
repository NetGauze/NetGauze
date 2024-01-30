use std::collections::HashMap;
use std::io::BufWriter;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::BitAnd;
use std::string::FromUtf8Error;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use nom::error::{ErrorKind, FromExternalError};
use nom::IResult;
use nom::number::complete::{be_f32, be_u128, be_u16, be_u32, be_u64, be_u8};
use serde::{Deserialize, Serialize};
use netgauze_parse_utils::{parse_into_located, parse_into_located_one_input, parse_till_empty_into_located, parse_till_empty_into_with_one_input_located, ReadablePdu, ReadablePduWithOneInput, ReadablePduWithThreeInputs, Span, WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::LocatedError;
use crate::bgp_ls::{BgpLsAttribute, BgpLsAttributeTlv, IpReachabilityInformationData, BgpLsNlriValue, BgpLsNlriIpPrefix, BgpLsNlriLink, BgpLsNlriNode, BgpLsNodeDescriptorSubTlv, BgpLsNodeDescriptorTlv, BgpLsPrefixDescriptorTlv, IgpFlags, LinkProtectionType, MplsProtocolMask, MultiTopologyId, MultiTopologyIdData, NodeFlagsBits, OspfRouteType, UnknownOspfRouteType, BgpLsLinkDescriptorTlv, BgpLsNlri, BgpLsVpnNlri, SharedRiskLinkGroupValue};
use netgauze_parse_utils::ErrorKindSerdeDeref;
use crate::iana;
use crate::iana::{BgpLsNodeDescriptorTlvType, BgpLsNlriType, BgpLsProtocolId, UnknownBgpLsAttributeTlvType, UnknownBgpLsNodeDescriptorTlvType, UnknownBgpLsProtocolId, UnknownNodeDescriptorSubTlvType, BgpLsPrefixDescriptorTlvType, UnknownPrefixDescriptorTlvType, BgpLsLinkDescriptorTlvType, UnknownLinkDescriptorTlvType, UnknownBgpLsNlriType};
use crate::nlri::{LabeledIpv4NextHop, LabeledNextHop, RouteDistinguisher};
use crate::path_attribute::MpReach;
use crate::wire::deserializer::{Ipv4PrefixParsingError, Ipv6PrefixParsingError};
use crate::wire::deserializer::nlri::RouteDistinguisherParsingError;
use crate::wire::serializer::nlri::{IPV4_LEN, IPV6_LEN};


/// BGP Capability Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpLsAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    MultiTopologyIdLengthError(usize),
    UnknownTlvType(#[from_external] UnknownBgpLsAttributeTlvType),
    Utf8Error(String),
    WrongIpAddrLength(usize),
    BadUnreservedBandwidthLength(usize),
}


impl<'a> FromExternalError<Span<'a>, FromUtf8Error>
for LocatedBgpLsAttributeParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: FromUtf8Error) -> Self {
        LocatedBgpLsAttributeParsingError::new(
            input,
            BgpLsAttributeParsingError::Utf8Error(error.to_string()),
        )
    }
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedBgpLsAttributeParsingError<'a>> for BgpLsAttribute {
    fn from_wire(buf: Span<'a>, extended_length: bool) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        let (_buf, ls_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };

        let (span, tlvs) = parse_till_empty_into_located(ls_buf)?;

        Ok((span, BgpLsAttribute { tlvs }))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for BgpLsAttributeTlv {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        let (remainder, tlv_type) = nom::combinator::map_res(be_u16, iana::BgpLsAttributeTlv::try_from)(buf)?;
        let (remainder, tlv_length) = be_u16(remainder)?;
        let (remainder, data) = nom::bytes::complete::take(tlv_length)(remainder)?;

        let tlv = match tlv_type {
            iana::BgpLsAttributeTlv::MultiTopologyIdentifier => {
                let (_, mtid) = parse_into_located(data)?;
                BgpLsAttributeTlv::MultiTopologyIdentifier(mtid)
            }
            iana::BgpLsAttributeTlv::NodeFlagBits => {
                let (_, flags) = be_u8(data)?;
                BgpLsAttributeTlv::NodeFlagBits {
                    overload: flags.bitand(NodeFlagsBits::Overload as u8) == NodeFlagsBits::Overload as u8,
                    attached: flags.bitand(NodeFlagsBits::Attached as u8) == NodeFlagsBits::Attached as u8,
                    external: flags.bitand(NodeFlagsBits::External as u8) == NodeFlagsBits::External as u8,
                    abr: flags.bitand(NodeFlagsBits::Abr as u8) == NodeFlagsBits::Abr as u8,
                    router: flags.bitand(NodeFlagsBits::Router as u8) == NodeFlagsBits::Router as u8,
                    v6: flags.bitand(NodeFlagsBits::V6 as u8) == NodeFlagsBits::V6 as u8,
                }
            }
            iana::BgpLsAttributeTlv::OpaqueNodeAttribute => {
                BgpLsAttributeTlv::OpaqueNodeAttribute(data.to_vec())
            }
            iana::BgpLsAttributeTlv::NodeNameTlv => {
                let (_, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(tlv_length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(data)?;
                BgpLsAttributeTlv::NodeNameTlv(str)
            }
            iana::BgpLsAttributeTlv::IsIsArea => {
                BgpLsAttributeTlv::IsIsArea(data.to_vec())
            }
            iana::BgpLsAttributeTlv::LocalNodeIpv4RouterId => {
                let (_, address) = be_u32(data)?;
                BgpLsAttributeTlv::LocalNodeIpv4RouterId(Ipv4Addr::from(address))
            }
            iana::BgpLsAttributeTlv::LocalNodeIpv6RouterId => {
                let (_, address) = be_u128(data)?;
                BgpLsAttributeTlv::LocalNodeIpv6RouterId(Ipv6Addr::from(address))
            }
            iana::BgpLsAttributeTlv::RemoteNodeIpv4RouterId => {
                let (_, address) = be_u32(data)?;
                BgpLsAttributeTlv::RemoteNodeIpv4RouterId(Ipv4Addr::from(address))
            }
            iana::BgpLsAttributeTlv::RemoteNodeIpv6RouterId => {
                let (_, address) = be_u128(data)?;
                BgpLsAttributeTlv::RemoteNodeIpv6RouterId(Ipv6Addr::from(address))
            }
            iana::BgpLsAttributeTlv::RemoteNodeAdministrativeGroupColor => {
                let (_, color) = be_u32(data)?;
                BgpLsAttributeTlv::RemoteNodeAdministrativeGroupColor(color)
            }
            iana::BgpLsAttributeTlv::MaximumLinkBandwidth => {
                let (_, bandwidth) = be_f32(data)?;
                BgpLsAttributeTlv::MaximumLinkBandwidth(bandwidth)
            }
            iana::BgpLsAttributeTlv::MaximumReservableLinkBandwidth => {
                let (_, bandwidth) = be_f32(data)?;
                BgpLsAttributeTlv::MaximumReservableLinkBandwidth(bandwidth)
            }
            iana::BgpLsAttributeTlv::UnreservedBandwidth => {
                let (_, vec) = nom::multi::count(be_f32, 8)(data)?;
                let len = vec.len();
                let value: [f32; 8] = vec.try_into().map_err(|_| {
                    nom::Err::Error(
                        LocatedBgpLsAttributeParsingError::new(
                            data,
                            BgpLsAttributeParsingError::BadUnreservedBandwidthLength(len),
                        ),
                    )
                })?;
                BgpLsAttributeTlv::UnreservedBandwidth(value)
            }
            iana::BgpLsAttributeTlv::TeDefaultMetric => {
                let (_, metric) = be_u32(data)?;
                BgpLsAttributeTlv::TeDefaultMetric(metric)
            }
            iana::BgpLsAttributeTlv::LinkProtectionType => {
                let (_, flags) = be_u16(data)?;
                BgpLsAttributeTlv::LinkProtectionType {
                    extra_traffic: flags.bitand(LinkProtectionType::ExtraTraffic as u16) == LinkProtectionType::ExtraTraffic as u16,
                    unprotected: flags.bitand(LinkProtectionType::Unprotected as u16) == LinkProtectionType::Unprotected as u16,
                    shared: flags.bitand(LinkProtectionType::Shared as u16) == LinkProtectionType::Shared as u16,
                    dedicated1c1: flags.bitand(LinkProtectionType::Dedicated1c1 as u16) == LinkProtectionType::Dedicated1c1 as u16,
                    dedicated1p1: flags.bitand(LinkProtectionType::Dedicated1p1 as u16) == LinkProtectionType::Dedicated1p1 as u16,
                    enhanced: flags.bitand(LinkProtectionType::Enhanced as u16) == LinkProtectionType::Enhanced as u16,
                }
            }
            iana::BgpLsAttributeTlv::MplsProtocolMask => {
                let (_, flags) = be_u8(data)?;
                BgpLsAttributeTlv::MplsProtocolMask {
                    ldp: flags.bitand(MplsProtocolMask::LabelDistributionProtocol as u8) == MplsProtocolMask::LabelDistributionProtocol as u8,
                    rsvp_te: flags.bitand(MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8) == MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8,
                }
            }
            iana::BgpLsAttributeTlv::IgpMetric => {
                BgpLsAttributeTlv::IgpMetric(data.to_vec())
            }
            iana::BgpLsAttributeTlv::SharedRiskLinkGroup => {
                let (_, values) = parse_till_empty_into_located(data)?;
                BgpLsAttributeTlv::SharedRiskLinkGroup(values)
            },
            iana::BgpLsAttributeTlv::OpaqueLinkAttribute => {
                BgpLsAttributeTlv::OpaqueLinkAttribute(data.to_vec())
            }
            iana::BgpLsAttributeTlv::LinkName => {
                let (_, str) =
                    nom::combinator::map_res(nom::bytes::complete::take(tlv_length), |x: Span<'_>| {
                        String::from_utf8(x.to_vec())
                    })(data)?;
                BgpLsAttributeTlv::LinkName(str)
            }
            iana::BgpLsAttributeTlv::IgpFlags => {
                let (_, flags) = be_u8(data)?;
                BgpLsAttributeTlv::IgpFlags {
                    isis_up_down: flags.bitand(IgpFlags::IsIsUp as u8) == IgpFlags::IsIsUp as u8,
                    ospf_no_unicast: flags.bitand(IgpFlags::OspfNoUnicast as u8) == IgpFlags::OspfNoUnicast as u8,
                    ospf_local_address: flags.bitand(IgpFlags::OspfLocalAddress as u8) == IgpFlags::OspfLocalAddress as u8,
                    ospf_propagate_nssa: flags.bitand(IgpFlags::OspfPropagateNssa as u8) == IgpFlags::OspfPropagateNssa as u8,
                }
            }
            iana::BgpLsAttributeTlv::IgpRouteTag => {
                let (_, vec) = parse_till_empty_into_located(data)?;
                BgpLsAttributeTlv::IgpRouteTag(vec)
            }
            iana::BgpLsAttributeTlv::IgpExtendedRouteTag => {
                let (_, vec) = parse_till_empty_into_located(data)?;
                BgpLsAttributeTlv::IgpExtendedRouteTag(vec)
            }
            iana::BgpLsAttributeTlv::PrefixMetric => {
                let (_, metric) = be_u32(data)?;
                BgpLsAttributeTlv::PrefixMetric(metric)
            }
            iana::BgpLsAttributeTlv::OspfForwardingAddress => {
                let address = if tlv_length == IPV4_LEN as u16 {
                    let (_, ip) = be_u32(data)?;
                    IpAddr::V4(Ipv4Addr::from(ip))
                } else if tlv_length == IPV6_LEN as u16 {
                    let (_, ip) = be_u128(data)?;
                    IpAddr::V6(Ipv6Addr::from(ip))
                } else {
                    return Err(nom::Err::Error(LocatedBgpLsAttributeParsingError::new(data,
                                                                                      BgpLsAttributeParsingError::WrongIpAddrLength(tlv_length.into()),
                    )));
                };

                BgpLsAttributeTlv::OspfForwardingAddress(address)
            }
            iana::BgpLsAttributeTlv::OpaquePrefixAttribute => {
                BgpLsAttributeTlv::OpaquePrefixAttribute(data.to_vec())
            }
        };

        Ok((remainder, tlv))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for u32 {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        Ok(be_u32(buf)?)
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for u64 {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        Ok(be_u64(buf)?)
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for SharedRiskLinkGroupValue {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        let (span, value) = be_u32(buf)?;
        Ok((span, SharedRiskLinkGroupValue(value)))
    }
}
impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for MultiTopologyIdData {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        let (span, value) = parse_till_empty_into_located(buf)?;
        Ok((span, MultiTopologyIdData(value)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for MultiTopologyId {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        let (buf, mtid) = be_u16(buf)?;

        Ok((buf, MultiTopologyId::from(mtid)))
    }
}

#[test]
pub fn test_bgp_ls_attr_parse() {
    let value = BgpLsAttribute {
        tlvs: vec![
            BgpLsAttributeTlv::LinkName("My Super Link".to_string())
        ]
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsAttribute::from_wire(span, false).expect("I CAN READ");

    assert_eq!(result.1, value)
}


/// BGP Capability Parsing errors
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpLsNlriParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UnknownNlriType(#[from_external] UnknownBgpLsNlriType),
    RouteDistinguisherParsingError(#[from_located(module = "crate::wire::deserializer::nlri")] RouteDistinguisherParsingError),
    UnknownProtocolId(#[from_external] UnknownBgpLsProtocolId),
    UnknownDescriptorTlvType(#[from_external] UnknownBgpLsNodeDescriptorTlvType),
    UnknownNodeDescriptorSubTlvType(#[from_external] UnknownNodeDescriptorSubTlvType),
    UnknownPrefixDescriptorTlvType(#[from_external] UnknownPrefixDescriptorTlvType),
    UnknownOspfRouteType(#[from_external] UnknownOspfRouteType),
    BadNodeDescriptorTlvType(BgpLsNodeDescriptorTlvType),
    UnknownLinkDescriptorTlvType(#[from_external] UnknownLinkDescriptorTlvType),
    BadTlvTypeInNlri(BgpLsNlriType),
    Ipv4PrefixError(#[from_located(module = "crate::wire::deserializer")] Ipv4PrefixParsingError),
    Ipv6PrefixError(#[from_located(module = "crate::wire::deserializer")] Ipv6PrefixParsingError),
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlri {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (buf, nlri_type) = nom::combinator::map_res(be_u16, BgpLsNlriType::try_from)(buf)?;
        let (buf, nlri_len) = be_u16(buf)?;
        let (buf, data) = nom::bytes::complete::take(nlri_len)(buf)?;

        let (_, nlri) = BgpLsNlriValue::from_wire(data, nlri_type)?;

        Ok((buf, BgpLsNlri(nlri)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsVpnNlri {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (buf, nlri_type) = nom::combinator::map_res(be_u16, BgpLsNlriType::try_from)(buf)?;
        let (buf, nlri_len) = be_u16(buf)?;
        let (buf, data) = nom::bytes::complete::take(nlri_len)(buf)?;

        let (data, rd) = parse_into_located(data)?;
        let (_, nlri) = BgpLsNlriValue::from_wire(data, nlri_type)?;

        Ok((buf, BgpLsVpnNlri {
            rd,
            nlri,
        }))
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlriValue {
    fn from_wire(buf: Span<'a>, nlri_type: BgpLsNlriType) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
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
                let (span, nlri_value) = BgpLsNlriIpPrefix::from_wire(buf, BgpLsNlriType::Ipv4TopologyPrefix)?;
                (span, BgpLsNlriValue::Ipv4Prefix(nlri_value))
            }
            BgpLsNlriType::Ipv6TopologyPrefix => {
                let (span, nlri_value) = BgpLsNlriIpPrefix::from_wire(buf, BgpLsNlriType::Ipv6TopologyPrefix)?;
                (span, BgpLsNlriValue::Ipv6Prefix(nlri_value))
            }
            BgpLsNlriType::TePolicy => unimplemented!(),
            BgpLsNlriType::Srv6Sid => unimplemented!(),
        };

        Ok(result)
    }
}


impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlriLink {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;

        let (span, local_node_descriptors) = parse_into_located(span)?;

        if !matches!(local_node_descriptors, BgpLsNodeDescriptorTlv::Local(_)) {
            return Err(
                nom::Err::Error(
                    LocatedBgpLsNlriParsingError::new(
                        span,
                        BgpLsNlriParsingError::BadNodeDescriptorTlvType(BgpLsNodeDescriptorTlvType::RemoteNodeDescriptor
                        ),
                    )
                )
            );
        }

        let (span, remote_node_descriptors) = parse_into_located(span)?;

        if !matches!(remote_node_descriptors, BgpLsNodeDescriptorTlv::Remote(_)) {
            return Err(
                nom::Err::Error(
                    LocatedBgpLsNlriParsingError::new(
                        span,
                        BgpLsNlriParsingError::BadNodeDescriptorTlvType(BgpLsNodeDescriptorTlvType::RemoteNodeDescriptor
                        ),
                    )
                )
            );
        }

        let (span, link_descriptor_tlvs) = parse_till_empty_into_located(span)?;

        Ok((span, BgpLsNlriLink {
            protocol_id,
            identifier,
            local_node_descriptors,
            remote_node_descriptors,
            link_descriptor_tlvs,
        }))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsLinkDescriptorTlv {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, tlv_type) = nom::combinator::map_res(be_u16, iana::BgpLsLinkDescriptorTlvType::try_from)(span)?;
        let (span, tlv_length) = be_u16(span)?;
        let (span, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let tlv = match tlv_type {
            BgpLsLinkDescriptorTlvType::LinkLocalRemoteIdentifiers => {
                let (remainder, link_local_identifier) = be_u32(data)?;
                let (_remainder, link_remote_identifier) = be_u32(remainder)?;
                BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers {
                    link_local_identifier,
                    link_remote_identifier,
                }
            }
            BgpLsLinkDescriptorTlvType::IPv4InterfaceAddress => {
                let (_remainder, ipv4) = be_u32(data)?;
                BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(Ipv4Addr::from(ipv4))
            }
            BgpLsLinkDescriptorTlvType::IPv4NeighborAddress => {
                let (_remainder, ipv4) = be_u32(data)?;
                BgpLsLinkDescriptorTlv::IPv4NeighborAddress(Ipv4Addr::from(ipv4))
            }
            BgpLsLinkDescriptorTlvType::IPv6InterfaceAddress => {
                let (_remainder, ipv6) = be_u128(data)?;
                // TODO CHECK NOT LOCAL-LINK
                BgpLsLinkDescriptorTlv::IPv6InterfaceAddress(Ipv6Addr::from(ipv6))
            }
            BgpLsLinkDescriptorTlvType::IPv6NeighborAddress => {
                let (_remainder, ipv6) = be_u128(data)?;
                // TODO CHECK NOT LOCAL-LINK
                BgpLsLinkDescriptorTlv::IPv6NeighborAddress(Ipv6Addr::from(ipv6))
            }
            BgpLsLinkDescriptorTlvType::MultiTopologyIdentifier => {
                let (_remainder, mtid) = parse_into_located::<LocatedBgpLsNlriParsingError<'a>, LocatedBgpLsNlriParsingError<'a>, MultiTopologyIdData>(data)?;
                BgpLsLinkDescriptorTlv::MultiTopologyIdentifier(mtid)
            }
        };

        Ok((span, tlv))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlriNode {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;

        let (span, local_node_descriptors) = parse_into_located(span)?;

        if !matches!(local_node_descriptors, BgpLsNodeDescriptorTlv::Local(_)) {
            return Err(
                nom::Err::Error(
                    LocatedBgpLsNlriParsingError::new(
                        span,
                        BgpLsNlriParsingError::BadNodeDescriptorTlvType(BgpLsNodeDescriptorTlvType::RemoteNodeDescriptor
                        ),
                    )
                )
            );
        }

        Ok((span, BgpLsNlriNode {
            protocol_id,
            identifier,
            local_node_descriptors,
        }))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNodeDescriptorTlv {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, tlv_type) = nom::combinator::map_res(be_u16, iana::BgpLsNodeDescriptorTlvType::try_from)(span)?;
        let (span, tlv_length) = be_u16(span)?;
        let (span, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let (_, subtlvs) = parse_till_empty_into_located(data)?;


        let descriptor = match tlv_type {
            BgpLsNodeDescriptorTlvType::LocalNodeDescriptor => BgpLsNodeDescriptorTlv::Local(subtlvs),
            BgpLsNodeDescriptorTlvType::RemoteNodeDescriptor => BgpLsNodeDescriptorTlv::Remote(subtlvs),
        };

        Ok((span, descriptor))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for BgpLsNodeDescriptorSubTlv {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, tlv_type) = nom::combinator::map_res(be_u16, iana::BgpLsNodeDescriptorSubTlv::try_from)(span)?;
        let (span, tlv_length) = be_u16(span)?;
        let (span, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let result = match tlv_type {
            iana::BgpLsNodeDescriptorSubTlv::AutonomousSystem => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::AutonomousSystem(value)
            }
            iana::BgpLsNodeDescriptorSubTlv::BgpLsIdentifier => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(value)
            }
            iana::BgpLsNodeDescriptorSubTlv::OspfAreaId => {
                let (_, value) = be_u32(data)?;
                BgpLsNodeDescriptorSubTlv::OspfAreaId(value)
            }
            iana::BgpLsNodeDescriptorSubTlv::IgpRouterId => {
                BgpLsNodeDescriptorSubTlv::IgpRouterId(data.to_vec())
            }
        };

        Ok((span, result))
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>> for BgpLsNlriIpPrefix {
    fn from_wire(span: Span<'a>, nlri_type: BgpLsNlriType) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, protocol_id) =
            nom::combinator::map_res(be_u8, iana::BgpLsProtocolId::try_from)(span)?;
        let (span, identifier) = be_u64(span)?;

        let (span, local_node_descriptors) = parse_into_located(span)?;

        if !matches!(local_node_descriptors, BgpLsNodeDescriptorTlv::Local(_)) {
            return Err(
                nom::Err::Error(
                    LocatedBgpLsNlriParsingError::new(
                        span,
                        BgpLsNlriParsingError::BadNodeDescriptorTlvType(BgpLsNodeDescriptorTlvType::RemoteNodeDescriptor
                        ),
                    )
                )
            );
        }

        let (span, prefix_descriptor_tlvs) = parse_till_empty_into_with_one_input_located(span, nlri_type)?;

        Ok((span, BgpLsNlriIpPrefix {
            protocol_id,
            identifier,
            local_node_descriptors,
            prefix_descriptor_tlvs,
        }))
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>> for BgpLsPrefixDescriptorTlv {
    fn from_wire(span: Span<'a>, nlri_type: BgpLsNlriType) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, tlv_type) = nom::combinator::map_res(be_u16, iana::BgpLsPrefixDescriptorTlvType::try_from)(span)?;
        let (span, tlv_length) = be_u16(span)?;
        let (span, data) = nom::bytes::complete::take(tlv_length)(span)?;

        let tlv = match tlv_type {
            BgpLsPrefixDescriptorTlvType::MultiTopologyIdentifier => {
                let (_, mtid) = parse_into_located::<LocatedBgpLsNlriParsingError<'a>, LocatedBgpLsNlriParsingError<'a>, MultiTopologyIdData>(data)?;
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(mtid)
            }
            BgpLsPrefixDescriptorTlvType::OspfRouteType => {
                let (_, ospf_route_type) = parse_into_located(data)?;
                BgpLsPrefixDescriptorTlv::OspfRouteType(ospf_route_type)
            }
            BgpLsPrefixDescriptorTlvType::IpReachabilityInformation => {
                let (_, ip_reachability_info) = parse_into_located_one_input(data, nlri_type)?;
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(ip_reachability_info)
            }
        };

        Ok((span, tlv))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for MultiTopologyIdData {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, ids) = parse_till_empty_into_located::<LocatedBgpLsNlriParsingError<'_>, LocatedBgpLsNlriParsingError<'_>, MultiTopologyId>(span)?;
        Ok((span, MultiTopologyIdData(ids)))
    }
}


impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for MultiTopologyId {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        let (span, id) = be_u16(span)?;
        Ok((span, MultiTopologyId::from(id)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpLsNlriParsingError<'a>> for OspfRouteType {
    fn from_wire(span: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
        nom::combinator::map_res(be_u8, OspfRouteType::try_from)(span)
    }
}

impl<'a> ReadablePduWithOneInput<'a, BgpLsNlriType, LocatedBgpLsNlriParsingError<'a>> for IpReachabilityInformationData {
    fn from_wire(span: Span<'a>, nlri_type: BgpLsNlriType) -> IResult<Span<'a>, Self, LocatedBgpLsNlriParsingError<'a>> where Self: Sized {
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
                return Err(nom::Err::Error(LocatedBgpLsNlriParsingError::new(span, BgpLsNlriParsingError::BadTlvTypeInNlri(nlri_type))));
            }
        }
    }
}

#[test]
pub fn test_bgp_ls_nlri_parse() {
    let value = BgpLsNlri(
        BgpLsNlriValue::Link(BgpLsNlriLink {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors: BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18)
            ]),
            remote_node_descriptors: BgpLsNodeDescriptorTlv::Remote(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(21)
            ]),
            link_descriptor_tlvs: vec![
                BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(Ipv4Addr::new(1, 2, 3, 4))
            ],
        })
    );

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsNlri::from_wire(span).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_nlri_ipv4_parse() {
    let value = BgpLsNlri(
        BgpLsNlriValue::Ipv4Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors:
            BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18)
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(IpNet::V4(Ipv4Net::new(Ipv4Addr::new(1, 2, 3, 4), 32).unwrap()))),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        })
    );

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsNlri::from_wire(span).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_nlri_ipv6_parse() {
    let value = BgpLsNlri(
        BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors:
            BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18)
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()))),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        })
    );

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsNlri::from_wire(span).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_mp_reach() {
    let ls_nlri = BgpLsNlri(
        BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors:
            BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18)
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()))),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        })
    );

    let value = MpReach::BgpLs {
        next_hop: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        nlri: vec![
            ls_nlri.clone(),
            ls_nlri.clone(),
            ls_nlri,
        ],
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);
    println!("written {:?} {:#?}", buf, buf.len());

    let span = Span::new(&buf);
    let result = MpReach::from_wire(span, false, &HashMap::new(), &HashMap::new()).expect("I CAN READ");

    assert_eq!(result.1, value)
}

#[test]
pub fn test_bgp_ls_vpn_mp_reach() {
    let ls_nlri = BgpLsVpnNlri {
        rd: RouteDistinguisher::As4Administrator {
            asn4: 1010,
            number: 2020,
        },
        nlri: BgpLsNlriValue::Ipv6Prefix(BgpLsNlriIpPrefix {
            protocol_id: BgpLsProtocolId::IsIsLevel1,
            identifier: 69,
            local_node_descriptors:
            BgpLsNodeDescriptorTlv::Local(vec![
                BgpLsNodeDescriptorSubTlv::OspfAreaId(18)
            ]),
            prefix_descriptor_tlvs: vec![
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(IpReachabilityInformationData(IpNet::V6(Ipv6Net::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap()))),
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(MultiTopologyIdData(vec![
                    MultiTopologyId(69),
                    MultiTopologyId(21),
                ])),
                BgpLsPrefixDescriptorTlv::OspfRouteType(OspfRouteType::External2),
            ],
        })
    };

    let value = MpReach::BgpLsVpn {
        next_hop: LabeledNextHop::Ipv4(LabeledIpv4NextHop::new(
            RouteDistinguisher::As2Administrator {
                asn2: 0,
                number: 0
            },
            Ipv4Addr::new(1, 2, 3, 4))
        ),
        nlri: vec![
            ls_nlri.clone(),
            ls_nlri.clone(),
            ls_nlri
        ],
    };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);
    println!("written {:?}", buf);

    let span = Span::new(&buf);
    let result = MpReach::from_wire(span, false, &HashMap::new(), &HashMap::new()).expect("I CAN READ");

    assert_eq!(result.1, value)
}