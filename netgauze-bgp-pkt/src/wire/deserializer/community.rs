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

use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use netgauze_parse_utils::{ErrorKindSerdeDeref, ReadablePDU, ReadablePDUWithOneInput, Span};
use netgauze_serde_macros::LocatedError;

use crate::{
    community::*,
    iana::{
        NonTransitiveTwoOctetExtendedCommunitySubType, TransitiveFourOctetExtendedCommunitySubType,
        TransitiveIpv4ExtendedCommunitySubType, TransitiveIpv6ExtendedCommunitySubType,
        TransitiveTwoOctetExtendedCommunitySubType,
    },
};

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveTwoOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedTransitiveTwoOctetExtendedCommunityParsingError<'a>>
    for TransitiveTwoOctetExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTransitiveTwoOctetExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u16(buf)?;
        let (buf, local_admin) = be_u32(buf)?;
        let ret = match TransitiveTwoOctetExtendedCommunitySubType::try_from(sub_type) {
            Ok(TransitiveTwoOctetExtendedCommunitySubType::RouteTarget) => {
                TransitiveTwoOctetExtendedCommunity::RouteTarget {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::RouteOrigin) => {
                TransitiveTwoOctetExtendedCommunity::RouteOrigin {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::OspfDomainIdentifier) => {
                TransitiveTwoOctetExtendedCommunity::OspfDomainIdentifier {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::BgpDataCollection) => {
                TransitiveTwoOctetExtendedCommunity::BgpDataCollection {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::SourceAs) => {
                TransitiveTwoOctetExtendedCommunity::SourceAs {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::L2VpnIdentifier) => {
                TransitiveTwoOctetExtendedCommunity::L2VpnIdentifier {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::CiscoVpnDistinguisher) => {
                TransitiveTwoOctetExtendedCommunity::CiscoVpnDistinguisher {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::RouteTargetRecord) => {
                TransitiveTwoOctetExtendedCommunity::RouteTargetRecord {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::RtDerivedEc) => {
                TransitiveTwoOctetExtendedCommunity::RtDerivedEc {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveTwoOctetExtendedCommunitySubType::VirtualNetworkIdentifier) => {
                TransitiveTwoOctetExtendedCommunity::VirtualNetworkIdentifier {
                    global_admin,
                    local_admin,
                }
            }
            Err(_) => TransitiveTwoOctetExtendedCommunity::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            },
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveTwoOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedNonTransitiveTwoOctetExtendedCommunityParsingError<'a>>
    for NonTransitiveTwoOctetExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedNonTransitiveTwoOctetExtendedCommunityParsingError<'a>>
    {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u16(buf)?;
        let (buf, local_admin) = be_u32(buf)?;
        let ret = match NonTransitiveTwoOctetExtendedCommunitySubType::try_from(sub_type) {
            Ok(NonTransitiveTwoOctetExtendedCommunitySubType::LinkBandwidth) => {
                NonTransitiveTwoOctetExtendedCommunity::LinkBandwidth {
                    global_admin,
                    local_admin,
                }
            }
            Ok(NonTransitiveTwoOctetExtendedCommunitySubType::VirtualNetworkIdentifier) => {
                NonTransitiveTwoOctetExtendedCommunity::VirtualNetworkIdentifier {
                    global_admin,
                    local_admin,
                }
            }
            Err(_) => NonTransitiveTwoOctetExtendedCommunity::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            },
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveIpv4ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedTransitiveIpv4ExtendedCommunityParsingError<'a>>
    for TransitiveIpv4ExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTransitiveIpv4ExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u32(buf)?;
        let global_admin = Ipv4Addr::from(global_admin);
        let (buf, local_admin) = be_u16(buf)?;
        let ret = match TransitiveIpv4ExtendedCommunitySubType::try_from(sub_type) {
            Ok(TransitiveIpv4ExtendedCommunitySubType::RouteTarget) => {
                TransitiveIpv4ExtendedCommunity::RouteTarget {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::RouteOrigin) => {
                TransitiveIpv4ExtendedCommunity::RouteOrigin {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::Ipv4Ifit) => {
                TransitiveIpv4ExtendedCommunity::Ipv4Ifit {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::OspfDomainIdentifier) => {
                TransitiveIpv4ExtendedCommunity::OspfDomainIdentifier {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::OspfRouteID) => {
                TransitiveIpv4ExtendedCommunity::OspfRouteID {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::NodeTarget) => {
                TransitiveIpv4ExtendedCommunity::NodeTarget {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::L2VpnIdentifier) => {
                TransitiveIpv4ExtendedCommunity::L2VpnIdentifier {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::VrfRouteImport) => {
                TransitiveIpv4ExtendedCommunity::VrfRouteImport {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::FlowSpecRedirectToIpv4) => {
                TransitiveIpv4ExtendedCommunity::FlowSpecRedirectToIpv4 {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::CiscoVpnDistinguisher) => {
                TransitiveIpv4ExtendedCommunity::CiscoVpnDistinguisher {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::InterAreaP2MpSegmentedNextHop) => {
                TransitiveIpv4ExtendedCommunity::InterAreaP2MpSegmentedNextHop {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::RouteTargetRecord) => {
                TransitiveIpv4ExtendedCommunity::RouteTargetRecord {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::VrfRecursiveNextHop) => {
                TransitiveIpv4ExtendedCommunity::VrfRecursiveNextHop {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::RtDerivedEc) => {
                TransitiveIpv4ExtendedCommunity::RtDerivedEc {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv4ExtendedCommunitySubType::MulticastVpnRpAddress) => {
                TransitiveIpv4ExtendedCommunity::MulticastVpnRpAddress {
                    global_admin,
                    local_admin,
                }
            }
            Err(_) => TransitiveIpv4ExtendedCommunity::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            },
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveIpv4ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedNonTransitiveIpv4ExtendedCommunityParsingError<'a>>
    for NonTransitiveIpv4ExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedNonTransitiveIpv4ExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u32(buf)?;
        let global_admin = Ipv4Addr::from(global_admin);
        let (buf, local_admin) = be_u16(buf)?;
        let ret = NonTransitiveIpv4ExtendedCommunity::Unassigned {
            sub_type,
            global_admin,
            local_admin,
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveFourOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedTransitiveFourOctetExtendedCommunityParsingError<'a>>
    for TransitiveFourOctetExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTransitiveFourOctetExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u32(buf)?;
        let (buf, local_admin) = be_u16(buf)?;
        let ret = match TransitiveFourOctetExtendedCommunitySubType::try_from(sub_type) {
            Ok(TransitiveFourOctetExtendedCommunitySubType::RouteTarget) => {
                TransitiveFourOctetExtendedCommunity::RouteTarget {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveFourOctetExtendedCommunitySubType::RouteOrigin) => {
                TransitiveFourOctetExtendedCommunity::RouteOrigin {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveFourOctetExtendedCommunitySubType::OspfDomainIdentifier) => {
                TransitiveFourOctetExtendedCommunity::OspfDomainIdentifier {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveFourOctetExtendedCommunitySubType::BgpDataCollection) => {
                TransitiveFourOctetExtendedCommunity::BgpDataCollection {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveFourOctetExtendedCommunitySubType::SourceAs) => {
                TransitiveFourOctetExtendedCommunity::SourceAs {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveFourOctetExtendedCommunitySubType::CiscoVpnDistinguisher) => {
                TransitiveFourOctetExtendedCommunity::CiscoVpnDistinguisher {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveFourOctetExtendedCommunitySubType::RouteTargetRecord) => {
                TransitiveFourOctetExtendedCommunity::RouteTargetRecord {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveFourOctetExtendedCommunitySubType::RtDerivedEc) => {
                TransitiveFourOctetExtendedCommunity::RtDerivedEc {
                    global_admin,
                    local_admin,
                }
            }
            Err(_) => TransitiveFourOctetExtendedCommunity::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            },
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveFourOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedNonTransitiveFourOctetExtendedCommunityParsingError<'a>>
    for NonTransitiveFourOctetExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedNonTransitiveFourOctetExtendedCommunityParsingError<'a>>
    {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u32(buf)?;
        let (buf, local_admin) = be_u16(buf)?;
        let ret = NonTransitiveFourOctetExtendedCommunity::Unassigned {
            sub_type,
            global_admin,
            local_admin,
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveOpaqueExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePDU<'a, LocatedTransitiveOpaqueExtendedCommunityParsingError<'a>>
    for TransitiveOpaqueExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTransitiveOpaqueExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let input = buf;
        let (buf, value) = nom::multi::count(be_u8, 6)(buf)?;
        let len = value.len();
        let value: [u8; 6] = value.try_into().map_err(|_| {
            nom::Err::Error(LocatedTransitiveOpaqueExtendedCommunityParsingError::new(
                input,
                TransitiveOpaqueExtendedCommunityParsingError::InvalidValueLength(len),
            ))
        })?;
        Ok((
            buf,
            TransitiveOpaqueExtendedCommunity::Unassigned { sub_type, value },
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveOpaqueExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePDU<'a, LocatedNonTransitiveOpaqueExtendedCommunityParsingError<'a>>
    for NonTransitiveOpaqueExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedNonTransitiveOpaqueExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let input = buf;
        let (buf, value) = nom::multi::count(be_u8, 6)(buf)?;
        let len = value.len();
        let value: [u8; 6] = value.try_into().map_err(|_| {
            nom::Err::Error(
                LocatedNonTransitiveOpaqueExtendedCommunityParsingError::new(
                    input,
                    NonTransitiveOpaqueExtendedCommunityParsingError::InvalidValueLength(len),
                ),
            )
        })?;
        Ok((
            buf,
            NonTransitiveOpaqueExtendedCommunity::Unassigned { sub_type, value },
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExperimentalExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePDUWithOneInput<'a, u8, LocatedExperimentalExtendedCommunityParsingError<'a>>
    for ExperimentalExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
        code: u8,
    ) -> IResult<Span<'a>, Self, LocatedExperimentalExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let input = buf;
        let (buf, value) = nom::multi::count(be_u8, 6)(buf)?;
        let len = value.len();
        let value: [u8; 6] = value.try_into().map_err(|_| {
            nom::Err::Error(LocatedExperimentalExtendedCommunityParsingError::new(
                input,
                ExperimentalExtendedCommunityParsingError::InvalidValueLength(len),
            ))
        })?;
        Ok((
            buf,
            ExperimentalExtendedCommunity::new(code, sub_type, value),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UnknownExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePDUWithOneInput<'a, u8, LocatedUnknownExtendedCommunityParsingError<'a>>
    for UnknownExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
        code: u8,
    ) -> IResult<Span<'a>, Self, LocatedUnknownExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let input = buf;
        let (buf, value) = nom::multi::count(be_u8, 6)(buf)?;
        let len = value.len();
        let value: [u8; 6] = value.try_into().map_err(|_| {
            nom::Err::Error(LocatedUnknownExtendedCommunityParsingError::new(
                input,
                UnknownExtendedCommunityParsingError::InvalidValueLength(len),
            ))
        })?;
        Ok((buf, UnknownExtendedCommunity::new(code, sub_type, value)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveIpv6ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedTransitiveIpv6ExtendedCommunityParsingError<'a>>
    for TransitiveIpv6ExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTransitiveIpv6ExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u128(buf)?;
        let global_admin = Ipv6Addr::from(global_admin);
        let (buf, local_admin) = be_u16(buf)?;
        let ret = match TransitiveIpv6ExtendedCommunitySubType::try_from(sub_type) {
            Ok(TransitiveIpv6ExtendedCommunitySubType::RouteTarget) => {
                TransitiveIpv6ExtendedCommunity::RouteTarget {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::RouteOrigin) => {
                TransitiveIpv6ExtendedCommunity::RouteOrigin {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::Ipv6Ifit) => {
                TransitiveIpv6ExtendedCommunity::Ipv6Ifit {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::VrfRouteImport) => {
                TransitiveIpv6ExtendedCommunity::VrfRouteImport {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::FlowSpecRedirectToIpv6) => {
                TransitiveIpv6ExtendedCommunity::FlowSpecRedirectToIpv6 {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::FlowSpecRtRedirectToIpv6) => {
                TransitiveIpv6ExtendedCommunity::FlowSpecRtRedirectToIpv6 {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::CiscoVpnDistinguisher) => {
                TransitiveIpv6ExtendedCommunity::CiscoVpnDistinguisher {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::InterAreaP2MpSegmentedNextHop) => {
                TransitiveIpv6ExtendedCommunity::InterAreaP2MpSegmentedNextHop {
                    global_admin,
                    local_admin,
                }
            }
            Ok(TransitiveIpv6ExtendedCommunitySubType::RtDerivedEc) => {
                TransitiveIpv6ExtendedCommunity::RtDerivedEc {
                    global_admin,
                    local_admin,
                }
            }
            Err(_) => TransitiveIpv6ExtendedCommunity::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            },
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveIpv6ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedNonTransitiveIpv6ExtendedCommunityParsingError<'a>>
    for NonTransitiveIpv6ExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedNonTransitiveIpv6ExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, global_admin) = be_u128(buf)?;
        let global_admin = Ipv6Addr::from(global_admin);
        let (buf, local_admin) = be_u16(buf)?;
        let ret = NonTransitiveIpv6ExtendedCommunity::Unassigned {
            sub_type,
            global_admin,
            local_admin,
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UnknownExtendedCommunityIpv6ParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePDUWithOneInput<'a, u8, LocatedUnknownExtendedCommunityIpv6ParsingError<'a>>
    for UnknownExtendedCommunityIpv6
{
    fn from_wire(
        buf: Span<'a>,
        code: u8,
    ) -> IResult<Span<'a>, Self, LocatedUnknownExtendedCommunityIpv6ParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let input = buf;
        let (buf, value) = nom::multi::count(be_u8, 18)(buf)?;
        let len = value.len();
        let value: [u8; 18] = value.try_into().map_err(|_| {
            nom::Err::Error(LocatedUnknownExtendedCommunityIpv6ParsingError::new(
                input,
                UnknownExtendedCommunityIpv6ParsingError::InvalidValueLength(len),
            ))
        })?;
        Ok((
            buf,
            UnknownExtendedCommunityIpv6::new(code, sub_type, value),
        ))
    }
}
