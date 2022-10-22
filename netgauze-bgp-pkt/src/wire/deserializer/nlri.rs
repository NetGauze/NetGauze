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
    iana::{RouteDistinguisherTypeCode, UndefinedRouteDistinguisherTypeCode},
    nlri::{
        InvalidIpv4MulticastNetwork, InvalidIpv4UnicastNetwork, InvalidIpv6MulticastNetwork,
        InvalidIpv6UnicastNetwork, Ipv4MplsVpnUnicast, Ipv4Multicast, Ipv4Unicast,
        Ipv6MplsVpnUnicast, Ipv6Multicast, Ipv6Unicast, LabeledIpv4NextHop, LabeledIpv6NextHop,
        LabeledNextHop, MplsLabel, RouteDistinguisher,
    },
    wire::{
        deserializer::{ErrorKindSerdeDeref, Ipv4PrefixParsingError, Ipv6PrefixParsingError},
        serializer::nlri::{LABELED_IPV4_LEN, LABELED_IPV6_LEN, RD_LEN},
    },
};
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_two_inputs, ReadablePDU, ReadablePDUWithTwoInputs, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const MPLS_LABEL_LEN_BITS: u8 = 24;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MplsLabelParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedMplsLabelParsingError<'a>> for MplsLabel {
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

impl<'a> ReadablePDU<'a, LocatedRouteDistinguisherParsingError<'a>> for RouteDistinguisher {
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

impl<'a> ReadablePDU<'a, LocatedLabeledIpv4NextHopParsingError<'a>> for LabeledIpv4NextHop {
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

impl<'a> ReadablePDU<'a, LocatedLabeledIpv6NextHopParsingError<'a>> for LabeledIpv6NextHop {
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

impl<'a> ReadablePDU<'a, LocatedLabeledNextHopParsingError<'a>> for LabeledNextHop {
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
pub enum Ipv4MplsVpnUnicastParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidPrefixLength(u8),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    Ipv4UnicastError(#[from_located(module = "self")] Ipv4UnicastParsingError),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
}

impl<'a> ReadablePDU<'a, LocatedIpv4MplsVpnUnicastParsingError<'a>> for Ipv4MplsVpnUnicast {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv4MplsVpnUnicastParsingError<'a>> {
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
        let (buf, rd) = parse_into_located(buf)?;
        let read_prefix = RD_LEN * 8 + label_stack.len() as u8 * MPLS_LABEL_LEN_BITS;
        // Check subtraction operation is safe first
        let reminder_prefix_len = match prefix_len.checked_sub(read_prefix) {
            None => {
                return Err(nom::Err::Error(LocatedIpv4MplsVpnUnicastParsingError::new(
                    input,
                    Ipv4MplsVpnUnicastParsingError::InvalidPrefixLength(prefix_len),
                )));
            }
            Some(val) => val,
        };
        let (buf, network) = parse_into_located_two_inputs(buf, reminder_prefix_len, input)?;
        Ok((buf, Ipv4MplsVpnUnicast::new(rd, label_stack, network)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6MplsVpnUnicastParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    MplsLabelError(#[from_located(module = "self")] MplsLabelParsingError),
    RouteDistinguisherError(#[from_located(module = "self")] RouteDistinguisherParsingError),
    InvalidPrefixLength(u8),
    Ipv6UnicastError(#[from_located(module = "self")] Ipv6UnicastParsingError),
}

impl<'a> ReadablePDU<'a, LocatedIpv6MplsVpnUnicastParsingError<'a>> for Ipv6MplsVpnUnicast {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv6MplsVpnUnicastParsingError<'a>> {
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
        let (buf, rd) = parse_into_located(buf)?;
        let read_prefix = RD_LEN * 8 + label_stack.len() as u8 * MPLS_LABEL_LEN_BITS;
        // Check subtraction operation is safe first
        let reminder_prefix_len = match prefix_len.checked_sub(read_prefix) {
            None => {
                return Err(nom::Err::Error(LocatedIpv6MplsVpnUnicastParsingError::new(
                    input,
                    Ipv6MplsVpnUnicastParsingError::InvalidPrefixLength(prefix_len),
                )));
            }
            Some(val) => val,
        };
        let (buf, network) = parse_into_located_two_inputs(buf, reminder_prefix_len, input)?;
        Ok((buf, Ipv6MplsVpnUnicast::new(rd, label_stack, network)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6UnicastParsingError {
    Ipv6PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv6PrefixParsingError,
    ),
    InvalidUnicastNetwork(#[from_external] InvalidIpv6UnicastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv6UnicastParsingError<'a>> for Ipv6Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

impl<'a> ReadablePDUWithTwoInputs<'a, u8, Span<'a>, LocatedIpv6UnicastParsingError<'a>>
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
pub enum Ipv6MulticastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    Ipv6PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv6PrefixParsingError,
    ),
    InvalidMulticastNetwork(#[from_external] InvalidIpv6MulticastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv6MulticastParsingError<'a>> for Ipv6Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6MulticastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4UnicastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    Ipv4PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv4PrefixParsingError,
    ),
    InvalidUnicastNetwork(#[from_external] InvalidIpv4UnicastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv4UnicastParsingError<'a>> for Ipv4Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

impl<'a> ReadablePDUWithTwoInputs<'a, u8, Span<'a>, LocatedIpv4UnicastParsingError<'a>>
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
pub enum Ipv4MulticastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    Ipv4PrefixError(
        #[from_external]
        #[from_located(module = "crate::wire::deserializer")]
        Ipv4PrefixParsingError,
    ),
    InvalidMulticastNetwork(#[from_external] InvalidIpv4MulticastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv4MulticastParsingError<'a>> for Ipv4Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4MulticastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}
