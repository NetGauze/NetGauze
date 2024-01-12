use std::io::BufWriter;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::BitAnd;
use std::string::FromUtf8Error;
use nom::error::{ErrorKind, FromExternalError};
use nom::IResult;
use nom::number::complete::{be_f32, be_u128, be_u16, be_u32, be_u64, be_u8};
use serde::{Deserialize, Serialize};
use netgauze_parse_utils::{parse_into_located, parse_till_empty_into_located, ReadablePdu, ReadablePduWithOneInput, Span, WritablePduWithOneInput};
use netgauze_serde_macros::LocatedError;
use crate::bgp_ls::{BgpLsAttribute, BgpLsAttributeTlv, IgpFlags, LinkProtectionType, MplsProtocolMask, MultiTopologyId, MultiTopologyIdData, NodeFlagsBits};
use netgauze_parse_utils::ErrorKindSerdeDeref;
use crate::iana;
use crate::iana::UnknownBgpLsAttributeTlvType;
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
            iana::BgpLsAttributeTlv::SharedRiskLinkGroup => unimplemented!(),
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

impl<'a> ReadablePdu<'a, LocatedBgpLsAttributeParsingError<'a>> for MultiTopologyIdData {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpLsAttributeParsingError<'a>> where Self: Sized {
        let (span, value) = parse_till_empty_into_located(buf)?;
        Ok((span, MultiTopologyIdData(value)))
    }
}

impl From<u16> for MultiTopologyId {
    fn from(value: u16) -> Self {
        // ignore 4 first reserved bits
        Self(value.bitand(!(0b1111u16 << 12)))
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

    let value = BgpLsAttribute { tlvs: vec![
        BgpLsAttributeTlv::LinkName("My Super Link".to_string())
    ] };

    let mut buf = Vec::<u8>::new();
    let mut writer = BufWriter::new(&mut buf);
    value.write(&mut writer, false).expect("I CAN WRITE");
    drop(writer);

    let span = Span::new(&buf);
    let result = BgpLsAttribute::from_wire(span, false).expect("I CAN READ");

    assert_eq!(result.1, value)
}