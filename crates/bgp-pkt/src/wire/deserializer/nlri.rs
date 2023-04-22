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
    iana::{L2EvpnRouteTypeCode, RouteDistinguisherTypeCode, UndefinedRouteDistinguisherTypeCode},
    nlri::*,
    wire::{
        deserializer::{Ipv4PrefixParsingError, Ipv6PrefixParsingError},
        serializer::nlri::{
            IPV4_LEN_BITS, IPV6_LEN_BITS, LABELED_IPV4_LEN, LABELED_IPV6_LEN, MAC_ADDRESS_LEN_BITS,
            MPLS_LABEL_LEN_BITS, RD_LEN,
        },
    },
};
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_into_located_two_inputs,
    ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput, ReadablePduWithTwoInputs, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP Prefix route type for IPv4 has the Length field set to 34
/// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
pub(crate) const L2_EVPN_IPV4_PREFIX_ROUTE_LEN: usize = 34;
/// An IP Prefix route type for IPv6 has the Length field set to 58
/// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
pub(crate) const L2_EVPN_IPV6_PREFIX_ROUTE_LEN: usize = 58;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MplsLabelParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedMplsLabelParsingError<'a>> for MplsLabel {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedMplsLabelParsingError<'a>> {
        let (buf, p1) = be_u8(buf)?;
        let (buf, p2) = be_u8(buf)?;
        let (buf, p3) = be_u8(buf)?;
        Ok((buf, MplsLabel::new([p1, p2, p3])))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum RouteDistinguisherParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedRouteDistinguisherTypeCode(#[from_external] UndefinedRouteDistinguisherTypeCode),
    /// LeafAdRoutes is expected to be all `1`
    InvalidLeafAdRoutes(u16, u32),
}

impl<'a> ReadablePdu<'a, LocatedRouteDistinguisherParsingError<'a>> for RouteDistinguisher {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedRouteDistinguisherParsingError<'a>> {
        let (buf, rd_type) =
            nom::combinator::map_res(be_u16, RouteDistinguisherTypeCode::try_from)(buf)?;
        match rd_type {
            RouteDistinguisherTypeCode::As2Administrator => {
                let (buf, asn2) = be_u16(buf)?;
                let (buf, number) = be_u32(buf)?;
                Ok((buf, RouteDistinguisher::As2Administrator { asn2, number }))
            }
            RouteDistinguisherTypeCode::Ipv4Administrator => {
                let (buf, ip) = be_u32(buf)?;
                let ip = Ipv4Addr::from(ip);
                let (buf, number) = be_u16(buf)?;
                Ok((buf, RouteDistinguisher::Ipv4Administrator { ip, number }))
            }
            RouteDistinguisherTypeCode::As4Administrator => {
                let (buf, asn4) = be_u32(buf)?;
                let (buf, number) = be_u16(buf)?;
                Ok((buf, RouteDistinguisher::As4Administrator { asn4, number }))
            }
            RouteDistinguisherTypeCode::LeafAdRoutes => {
                let input = buf;
                let (buf, num1) = be_u16(buf)?;
                let (buf, num2) = be_u32(buf)?;
                if num1 != u16::MAX || num2 != u32::MAX {
                    Err(nom::Err::Error(LocatedRouteDistinguisherParsingError::new(
                        input,
                        RouteDistinguisherParsingError::InvalidLeafAdRoutes(num1, num2),
                    )))
                } else {
                    Ok((buf, RouteDistinguisher::LeafAdRoutes))
                }
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LabeledIpv4NextHopParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
}

impl<'a> ReadablePdu<'a, LocatedLabeledIpv4NextHopParsingError<'a>> for LabeledIpv4NextHop {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedLabeledIpv4NextHopParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, ip) = be_u32(buf)?;
        let ip = Ipv4Addr::from(ip);
        Ok((buf, LabeledIpv4NextHop::new(rd, ip)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LabeledIpv6NextHopParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
}

impl<'a> ReadablePdu<'a, LocatedLabeledIpv6NextHopParsingError<'a>> for LabeledIpv6NextHop {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedLabeledIpv6NextHopParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, ip) = be_u128(buf)?;
        let ip = Ipv6Addr::from(ip);
        Ok((buf, LabeledIpv6NextHop::new(rd, ip)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LabeledNextHopParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(u8),
    LabeledIpv4NextHopError(#[from_located(module = "self")] LabeledIpv4NextHopParsingError),
    LabeledIpv6NextHopError(#[from_located(module = "self")] LabeledIpv6NextHopParsingError),
}

impl<'a> ReadablePdu<'a, LocatedLabeledNextHopParsingError<'a>> for LabeledNextHop {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedLabeledNextHopParsingError<'a>> {
        let input = buf;
        let (buf, len) = be_u8(buf)?;
        if len == LABELED_IPV4_LEN {
            let (buf, labeled_ipv4) = parse_into_located(buf)?;
            Ok((buf, LabeledNextHop::Ipv4(labeled_ipv4)))
        } else if len == LABELED_IPV6_LEN {
            let (buf, labeled_ipv6) = parse_into_located(buf)?;
            Ok((buf, LabeledNextHop::Ipv6(labeled_ipv6)))
        } else {
            Err(nom::Err::Error(LocatedLabeledNextHopParsingError::new(
                input,
                LabeledNextHopParsingError::InvalidLength(len),
            )))
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4MplsVpnUnicastAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidPrefixLength(u8),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    Ipv4UnicastError(#[from_located(module = "self")] Ipv4UnicastParsingError),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedIpv4MplsVpnUnicastAddressParsingError<'a>>
    for Ipv4MplsVpnUnicastAddress
{
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedIpv4MplsVpnUnicastAddressParsingError<'a>> {
        let input = buf;
        let (mut buf, prefix_len) = be_u8(buf)?;
        let mut label_stack = vec![];
        let mut is_bottom = false;
        while !is_bottom {
            let (t, label): (Span<'_>, MplsLabel) = parse_into_located(buf)?;
            buf = t;
            is_bottom = label.is_bottom();
            label_stack.push(label);
        }
        let (buf, path_id) = if add_path {
            let (buf, path_id) = be_u32(buf)?;
            (buf, Some(path_id))
        } else {
            (buf, None)
        };
        let (buf, rd) = parse_into_located(buf)?;
        let read_prefix = RD_LEN * 8 + label_stack.len() as u8 * MPLS_LABEL_LEN_BITS;
        // Check subtraction operation is safe first
        let reminder_prefix_len = match prefix_len.checked_sub(read_prefix) {
            None => {
                return Err(nom::Err::Error(
                    LocatedIpv4MplsVpnUnicastAddressParsingError::new(
                        input,
                        Ipv4MplsVpnUnicastAddressParsingError::InvalidPrefixLength(prefix_len),
                    ),
                ));
            }
            Some(val) => val,
        };
        let (buf, network) = parse_into_located_two_inputs(buf, reminder_prefix_len, input)?;
        Ok((
            buf,
            Ipv4MplsVpnUnicastAddress::new(path_id, rd, label_stack, network),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6MplsVpnUnicastAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    InvalidPrefixLength(u8),
    Ipv6UnicastError(#[from_located(module = "self")] Ipv6UnicastParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedIpv6MplsVpnUnicastAddressParsingError<'a>>
    for Ipv6MplsVpnUnicastAddress
{
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedIpv6MplsVpnUnicastAddressParsingError<'a>> {
        let input = buf;
        let (mut buf, prefix_len) = be_u8(buf)?;
        let mut label_stack = vec![];
        let mut is_bottom = false;
        while !is_bottom {
            let (t, label): (Span<'_>, MplsLabel) = parse_into_located(buf)?;
            buf = t;
            is_bottom = label.is_bottom();
            label_stack.push(label);
        }
        let (buf, path_id) = if add_path {
            let (buf, path_id) = be_u32(buf)?;
            (buf, Some(path_id))
        } else {
            (buf, None)
        };
        let (buf, rd) = parse_into_located(buf)?;
        let read_prefix = RD_LEN * 8 + label_stack.len() as u8 * MPLS_LABEL_LEN_BITS;
        // Check subtraction operation is safe first
        let reminder_prefix_len = match prefix_len.checked_sub(read_prefix) {
            None => {
                return Err(nom::Err::Error(
                    LocatedIpv6MplsVpnUnicastAddressParsingError::new(
                        input,
                        Ipv6MplsVpnUnicastAddressParsingError::InvalidPrefixLength(prefix_len),
                    ),
                ));
            }
            Some(val) => val,
        };
        let (buf, network) = parse_into_located_two_inputs(buf, reminder_prefix_len, input)?;
        Ok((
            buf,
            Ipv6MplsVpnUnicastAddress::new(path_id, rd, label_stack, network),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6UnicastParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Ipv6PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv6PrefixParsingError,
    ),
    InvalidUnicastNetwork(#[from_external] InvalidIpv6UnicastNetwork),
}

impl<'a> ReadablePdu<'a, LocatedIpv6UnicastParsingError<'a>> for Ipv6Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

impl<'a> ReadablePduWithTwoInputs<'a, u8, Span<'a>, LocatedIpv6UnicastParsingError<'a>>
    for Ipv6Unicast
{
    fn from_wire(
        buf: Span<'a>,
        prefix_len: u8,
        prefix_input: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv6UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(
            |span| parse_into_located_two_inputs(span, prefix_len, prefix_input),
            Self::from_net,
        )(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6UnicastAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Ipv6UnicastError(#[from_located(module = "self")] Ipv6UnicastParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedIpv6UnicastAddressParsingError<'a>>
    for Ipv6UnicastAddress
{
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedIpv6UnicastAddressParsingError<'a>> {
        let (buf, path_id) = if add_path {
            let (buf, path_id) = be_u32(buf)?;
            (buf, Some(path_id))
        } else {
            (buf, None)
        };
        let (buf, net) = parse_into_located(buf)?;
        Ok((buf, Ipv6UnicastAddress::new(path_id, net)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6MulticastParsingError {
    Ipv6PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv6PrefixParsingError,
    ),
    InvalidMulticastNetwork(#[from_external] InvalidIpv6MulticastNetwork),
}

impl<'a> ReadablePdu<'a, LocatedIpv6MulticastParsingError<'a>> for Ipv6Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6MulticastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6MulticastAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Ipv6MulticastError(#[from_located(module = "self")] Ipv6MulticastParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedIpv6MulticastAddressParsingError<'a>>
    for Ipv6MulticastAddress
{
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedIpv6MulticastAddressParsingError<'a>> {
        let (buf, path_id) = if add_path {
            let (buf, path_id) = be_u32(buf)?;
            (buf, Some(path_id))
        } else {
            (buf, None)
        };
        let (buf, net) = parse_into_located(buf)?;
        Ok((buf, Ipv6MulticastAddress::new(path_id, net)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4UnicastParsingError {
    Ipv4PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv4PrefixParsingError,
    ),
    InvalidUnicastNetwork(#[from_external] InvalidIpv4UnicastNetwork),
}

impl<'a> ReadablePdu<'a, LocatedIpv4UnicastParsingError<'a>> for Ipv4Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

impl<'a> ReadablePduWithTwoInputs<'a, u8, Span<'a>, LocatedIpv4UnicastParsingError<'a>>
    for Ipv4Unicast
{
    fn from_wire(
        buf: Span<'a>,
        prefix_len: u8,
        prefix_input: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv4UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(
            |span| parse_into_located_two_inputs(span, prefix_len, prefix_input),
            Self::from_net,
        )(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4UnicastAddressParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Ipv4UnicastError(#[from_located(module = "self")] Ipv4UnicastParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedIpv4UnicastAddressParsingError<'a>>
    for Ipv4UnicastAddress
{
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedIpv4UnicastAddressParsingError<'a>> {
        let (buf, path_id) = if add_path {
            let (buf, add_path) = be_u32(buf)?;
            (buf, Some(add_path))
        } else {
            (buf, None)
        };
        let (buf, net) = parse_into_located(buf)?;
        Ok((buf, Ipv4UnicastAddress::new(path_id, net)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4MulticastParsingError {
    Ipv4PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv4PrefixParsingError,
    ),
    InvalidMulticastNetwork(#[from_external] InvalidIpv4MulticastNetwork),
}

impl<'a> ReadablePdu<'a, LocatedIpv4MulticastParsingError<'a>> for Ipv4Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4MulticastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4MulticastAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Ipv4MulticastError(#[from_located(module = "self")] Ipv4MulticastParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedIpv4MulticastAddressParsingError<'a>>
    for Ipv4MulticastAddress
{
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedIpv4MulticastAddressParsingError<'a>> {
        let (buf, path_id) = if add_path {
            let (buf, path_id) = be_u32(buf)?;
            (buf, Some(path_id))
        } else {
            (buf, None)
        };
        let (buf, net) = parse_into_located(buf)?;
        Ok((buf, Ipv4MulticastAddress::new(path_id, net)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MacAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}
impl<'a> ReadablePdu<'a, LocatedMacAddressParsingError<'a>> for MacAddress {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedMacAddressParsingError<'a>> {
        let (buf, byte0) = be_u8(buf)?;
        let (buf, byte1) = be_u8(buf)?;
        let (buf, byte2) = be_u8(buf)?;
        let (buf, byte3) = be_u8(buf)?;
        let (buf, byte4) = be_u8(buf)?;
        let (buf, byte5) = be_u8(buf)?;
        Ok((buf, MacAddress([byte0, byte1, byte2, byte3, byte4, byte5])))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum EthernetSegmentIdentifierParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedEthernetSegmentIdentifierParsingError<'a>>
    for EthernetSegmentIdentifier
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedEthernetSegmentIdentifierParsingError<'a>> {
        let (buf, byte0) = be_u8(buf)?;
        let (buf, byte1) = be_u8(buf)?;
        let (buf, byte2) = be_u8(buf)?;
        let (buf, byte3) = be_u8(buf)?;
        let (buf, byte4) = be_u8(buf)?;
        let (buf, byte5) = be_u8(buf)?;
        let (buf, byte6) = be_u8(buf)?;
        let (buf, byte7) = be_u8(buf)?;
        let (buf, byte8) = be_u8(buf)?;
        let (buf, byte9) = be_u8(buf)?;
        Ok((
            buf,
            EthernetSegmentIdentifier([
                byte0, byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8, byte9,
            ]),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum EthernetTagParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedEthernetTagParsingError<'a>> for EthernetTag {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedEthernetTagParsingError<'a>> {
        let (buf, tag) = be_u32(buf)?;
        Ok((buf, EthernetTag(tag)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum EthernetAutoDiscoveryParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    EthernetSegmentIdentifierError(
        #[from_located(module = "self")] EthernetSegmentIdentifierParsingError,
    ),
    EthernetTagError(#[from_located(module = "self")] EthernetTagParsingError),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
}

impl<'a> ReadablePdu<'a, LocatedEthernetAutoDiscoveryParsingError<'a>> for EthernetAutoDiscovery {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedEthernetAutoDiscoveryParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, segment_id) = parse_into_located(buf)?;
        let (buf, tag) = parse_into_located(buf)?;
        let (buf, mpls_label) = parse_into_located(buf)?;
        Ok((
            buf,
            EthernetAutoDiscovery::new(rd, segment_id, tag, mpls_label),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MacIpAdvertisementParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidMacAddressLength(u8),
    InvalidIpAddressAddressLength(u8),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    EthernetSegmentIdentifierError(
        #[from_located(module = "self")] EthernetSegmentIdentifierParsingError,
    ),
    EthernetTagError(#[from_located(module = "self")] EthernetTagParsingError),
    MacAddressError(#[from_located(module = "self")] MacAddressParsingError),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
}

impl<'a> ReadablePdu<'a, LocatedMacIpAdvertisementParsingError<'a>> for MacIpAdvertisement {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedMacIpAdvertisementParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, segment_id) = parse_into_located(buf)?;
        let (buf, tag) = parse_into_located(buf)?;
        let input = buf;
        let (buf, mac_len) = be_u8(buf)?;
        if mac_len != MAC_ADDRESS_LEN_BITS {
            return Err(nom::Err::Error(LocatedMacIpAdvertisementParsingError::new(
                input,
                MacIpAdvertisementParsingError::InvalidMacAddressLength(mac_len),
            )));
        }
        let (buf, mac) = parse_into_located(buf)?;
        let input = buf;
        let (buf, ip_len) = be_u8(buf)?;
        let (buf, ip) = match ip_len {
            0 => (buf, None),
            IPV4_LEN_BITS => {
                let (buf, ip) = be_u32(buf)?;
                (buf, Some(IpAddr::V4(Ipv4Addr::from(ip))))
            }
            IPV6_LEN_BITS => {
                let (buf, ip) = be_u128(buf)?;
                (buf, Some(IpAddr::V6(Ipv6Addr::from(ip))))
            }
            _ => {
                return Err(nom::Err::Error(LocatedMacIpAdvertisementParsingError::new(
                    input,
                    MacIpAdvertisementParsingError::InvalidIpAddressAddressLength(ip_len),
                )));
            }
        };

        let (buf, mpls_label) = parse_into_located(buf)?;
        let (buf, mpls_label2) = if buf.len() > 0 {
            let (buf, mpls_label2) = parse_into_located(buf)?;
            (buf, Some(mpls_label2))
        } else {
            (buf, None)
        };
        Ok((
            buf,
            MacIpAdvertisement::new(rd, segment_id, tag, mac, ip, mpls_label, mpls_label2),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum InclusiveMulticastEthernetTagRouteParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidIpAddressAddressLength(u8),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    EthernetTagError(#[from_located(module = "self")] EthernetTagParsingError),
}

impl<'a> ReadablePdu<'a, LocatedInclusiveMulticastEthernetTagRouteParsingError<'a>>
    for InclusiveMulticastEthernetTagRoute
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedInclusiveMulticastEthernetTagRouteParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, tag) = parse_into_located(buf)?;
        let input = buf;
        let (buf, ip_len) = be_u8(buf)?;
        let (buf, ip) = match ip_len {
            IPV4_LEN_BITS => {
                let (buf, ip) = be_u32(buf)?;
                (buf, IpAddr::V4(Ipv4Addr::from(ip)))
            }
            IPV6_LEN_BITS => {
                let (buf, ip) = be_u128(buf)?;
                (buf, IpAddr::V6(Ipv6Addr::from(ip)))
            }
            _ => {
                return Err(nom::Err::Error(
                    LocatedInclusiveMulticastEthernetTagRouteParsingError::new(
                        input,
                        InclusiveMulticastEthernetTagRouteParsingError::InvalidIpAddressAddressLength(ip_len),
                    ),
                ));
            }
        };
        Ok((buf, InclusiveMulticastEthernetTagRoute::new(rd, tag, ip)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum EthernetSegmentRouteParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidIpAddressAddressLength(u8),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    EthernetSegmentIdentifierError(
        #[from_located(module = "self")] EthernetSegmentIdentifierParsingError,
    ),
}

impl<'a> ReadablePdu<'a, LocatedEthernetSegmentRouteParsingError<'a>> for EthernetSegmentRoute {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedEthernetSegmentRouteParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, segment_id) = parse_into_located(buf)?;
        let input = buf;
        let (buf, ip_len) = be_u8(buf)?;
        let (buf, ip) = match ip_len {
            IPV4_LEN_BITS => {
                let (buf, ip) = be_u32(buf)?;
                (buf, IpAddr::V4(Ipv4Addr::from(ip)))
            }
            IPV6_LEN_BITS => {
                let (buf, ip) = be_u128(buf)?;
                (buf, IpAddr::V6(Ipv6Addr::from(ip)))
            }
            _ => {
                return Err(nom::Err::Error(
                    LocatedEthernetSegmentRouteParsingError::new(
                        input,
                        EthernetSegmentRouteParsingError::InvalidIpAddressAddressLength(ip_len),
                    ),
                ));
            }
        };
        Ok((buf, EthernetSegmentRoute::new(rd, segment_id, ip)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum L2EvpnRouteParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    EthernetAutoDiscoveryError(#[from_located(module = "self")] EthernetAutoDiscoveryParsingError),
    MacIpAdvertisementError(#[from_located(module = "self")] MacIpAdvertisementParsingError),
    InclusiveMulticastEthernetTagRouteError(
        #[from_located(module = "self")] InclusiveMulticastEthernetTagRouteParsingError,
    ),
    EthernetSegmentRouteError(#[from_located(module = "self")] EthernetSegmentRouteParsingError),
    L2EvpnIpPrefixRouteError(#[from_located(module = "self")] L2EvpnIpPrefixRouteParsingError),
}

impl<'a> ReadablePdu<'a, LocatedL2EvpnRouteParsingError<'a>> for L2EvpnRoute {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedL2EvpnRouteParsingError<'a>> {
        let (buf, typ_code) = be_u8(buf)?;
        let (buf, len) = be_u8(buf)?;
        let (buf, route_buf) = nom::bytes::complete::take(len)(buf)?;
        let typ = L2EvpnRouteTypeCode::try_from(typ_code);
        let (_buf, value) = match typ {
            Ok(L2EvpnRouteTypeCode::EthernetAutoDiscovery) => {
                let (buf, value) = parse_into_located(route_buf)?;
                (buf, L2EvpnRoute::EthernetAutoDiscovery(value))
            }
            Ok(L2EvpnRouteTypeCode::MacIpAdvertisement) => {
                let (buf, value) = parse_into_located(route_buf)?;
                (buf, L2EvpnRoute::MacIpAdvertisement(value))
            }
            Ok(L2EvpnRouteTypeCode::InclusiveMulticastEthernetTagRoute) => {
                let (buf, value) = parse_into_located(route_buf)?;
                (buf, L2EvpnRoute::InclusiveMulticastEthernetTagRoute(value))
            }
            Ok(L2EvpnRouteTypeCode::EthernetSegmentRoute) => {
                let (buf, value) = parse_into_located(route_buf)?;
                (buf, L2EvpnRoute::EthernetSegmentRoute(value))
            }
            Ok(L2EvpnRouteTypeCode::IpPrefix) => {
                let (buf, value) = parse_into_located(route_buf)?;
                (buf, L2EvpnRoute::IpPrefixRoute(value))
            }
            Ok(_) | Err(_) => {
                let (buf, len) = be_u8(buf)?;
                let (buf, value): (Span<'_>, Span<'_>) = nom::bytes::complete::take(len)(buf)?;
                (
                    buf,
                    L2EvpnRoute::Unknown {
                        code: typ_code,
                        value: value.to_vec(),
                    },
                )
            }
        };
        Ok((buf, value))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum L2EvpnAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    L2EvpnRouteError(#[from_located(module = "self")] L2EvpnRouteParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedL2EvpnAddressParsingError<'a>> for L2EvpnAddress {
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedL2EvpnAddressParsingError<'a>> {
        let (buf, path_id) = if add_path {
            let (buf, path_id) = be_u32(buf)?;
            (buf, Some(path_id))
        } else {
            (buf, None)
        };
        let (buf, route) = parse_into_located(buf)?;
        Ok((buf, L2EvpnAddress::new(path_id, route)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum L2EvpnIpv4PrefixRouteParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    EthernetSegmentIdentifierError(
        #[from_located(module = "self")] EthernetSegmentIdentifierParsingError,
    ),
    EthernetTagError(#[from_located(module = "self")] EthernetTagParsingError),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
    Ipv4PrefixError(#[from_located(module = "crate::wire::deserializer")] Ipv4PrefixParsingError),
}

impl<'a> ReadablePdu<'a, LocatedL2EvpnIpv4PrefixRouteParsingError<'a>> for L2EvpnIpv4PrefixRoute {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedL2EvpnIpv4PrefixRouteParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, segment_id) = parse_into_located(buf)?;
        let (buf, tag) = parse_into_located(buf)?;
        let input = buf;
        let (buf, prefix_len) = be_u8(buf)?;
        let (buf, network) = be_u32(buf)?;
        let prefix = match Ipv4Net::new(Ipv4Addr::from(network), prefix_len) {
            Ok(prefix) => prefix,
            Err(_) => {
                return Err(nom::Err::Error(
                    LocatedL2EvpnIpv4PrefixRouteParsingError::new(
                        input,
                        L2EvpnIpv4PrefixRouteParsingError::Ipv4PrefixError(
                            Ipv4PrefixParsingError::InvalidIpv4PrefixLen(prefix_len),
                        ),
                    ),
                ))
            }
        };
        let (buf, gateway) = be_u32(buf)?;
        let gateway = Ipv4Addr::from(gateway);
        let (buf, mpls_label) = parse_into_located(buf)?;
        Ok((
            buf,
            L2EvpnIpv4PrefixRoute::new(rd, segment_id, tag, prefix, gateway, mpls_label),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum L2EvpnIpv6PrefixRouteParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    EthernetSegmentIdentifierError(
        #[from_located(module = "self")] EthernetSegmentIdentifierParsingError,
    ),
    EthernetTagError(#[from_located(module = "self")] EthernetTagParsingError),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
    Ipv6PrefixError(#[from_located(module = "crate::wire::deserializer")] Ipv6PrefixParsingError),
}

impl<'a> ReadablePdu<'a, LocatedL2EvpnIpv6PrefixRouteParsingError<'a>> for L2EvpnIpv6PrefixRoute {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedL2EvpnIpv6PrefixRouteParsingError<'a>> {
        let (buf, rd) = parse_into_located(buf)?;
        let (buf, segment_id) = parse_into_located(buf)?;
        let (buf, tag) = parse_into_located(buf)?;
        let input = buf;
        let (buf, prefix_len) = be_u8(buf)?;
        let (buf, network) = be_u128(buf)?;
        let prefix = match Ipv6Net::new(Ipv6Addr::from(network), prefix_len) {
            Ok(prefix) => prefix,
            Err(_) => {
                return Err(nom::Err::Error(
                    LocatedL2EvpnIpv6PrefixRouteParsingError::new(
                        input,
                        L2EvpnIpv6PrefixRouteParsingError::Ipv6PrefixError(
                            Ipv6PrefixParsingError::InvalidIpv6PrefixLen(prefix_len),
                        ),
                    ),
                ))
            }
        };
        let (buf, gateway) = be_u128(buf)?;
        let gateway = Ipv6Addr::from(gateway);
        let (buf, mpls_label) = parse_into_located(buf)?;
        Ok((
            buf,
            L2EvpnIpv6PrefixRoute::new(rd, segment_id, tag, prefix, gateway, mpls_label),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum L2EvpnIpPrefixRouteParsingError {
    InvalidBufferLength(usize),
    L2EvpnIpv4PrefixRouteError(#[from_located(module = "self")] L2EvpnIpv4PrefixRouteParsingError),
    L2EvpnIpv6PrefixRouteError(#[from_located(module = "self")] L2EvpnIpv6PrefixRouteParsingError),
}

impl<'a> ReadablePdu<'a, LocatedL2EvpnIpPrefixRouteParsingError<'a>> for L2EvpnIpPrefixRoute {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedL2EvpnIpPrefixRouteParsingError<'a>> {
        match buf.len() {
            L2_EVPN_IPV4_PREFIX_ROUTE_LEN => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, L2EvpnIpPrefixRoute::V4(value)))
            }
            L2_EVPN_IPV6_PREFIX_ROUTE_LEN => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, L2EvpnIpPrefixRoute::V6(value)))
            }
            _ => Err(nom::Err::Error(
                LocatedL2EvpnIpPrefixRouteParsingError::new(
                    buf,
                    L2EvpnIpPrefixRouteParsingError::InvalidBufferLength(buf.len()),
                ),
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum RouteTargetMembershipAddressParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidPrefixLen(u8),
    LocatedRouteTargetMembershipParsingError(
        #[from_located(module = "self")] RouteTargetMembershipParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedRouteTargetMembershipAddressParsingError<'a>>
    for RouteTargetMembershipAddress
{
    fn from_wire(
        buf: Span<'a>,
        add_path: bool,
    ) -> IResult<Span<'a>, Self, LocatedRouteTargetMembershipAddressParsingError<'a>> {
        let (buf, path_id) = if add_path {
            let (buf, path_id) = be_u32(buf)?;
            (buf, Some(path_id))
        } else {
            (buf, None)
        };
        let input = buf;
        let (buf, prefix_len) = be_u8(buf)?;
        let (buf, membership) = if prefix_len == 0 {
            (buf, None)
        } else if !(32..=96).contains(&prefix_len) {
            return Err(nom::Err::Error(
                LocatedRouteTargetMembershipAddressParsingError::new(
                    input,
                    RouteTargetMembershipAddressParsingError::InvalidPrefixLen(prefix_len),
                ),
            ));
        } else {
            let (buf, membership) = parse_into_located_one_input(buf, prefix_len)?;
            (buf, Some(membership))
        };
        Ok((buf, RouteTargetMembershipAddress::new(path_id, membership)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum RouteTargetMembershipParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePduWithOneInput<'a, u8, LocatedRouteTargetMembershipParsingError<'a>>
    for RouteTargetMembership
{
    fn from_wire(
        buf: Span<'a>,
        prefix_len: u8,
    ) -> IResult<Span<'a>, Self, LocatedRouteTargetMembershipParsingError<'a>> {
        let (buf, origin_as) = be_u32(buf)?;
        let (buf, route_target) = nom::multi::count(be_u8, ((prefix_len - 32) / 8) as usize)(buf)?;
        Ok((buf, RouteTargetMembership::new(origin_as, route_target)))
    }
}
