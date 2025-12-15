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

use nom::IResult;
use nom::error::ErrorKind;
use nom::number::complete::{be_u8, be_u16, be_u32, be_u128};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use netgauze_parse_utils::{
    ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput, Span, parse_into_located,
    parse_into_located_one_input,
};
use netgauze_serde_macros::LocatedError;

use crate::community::*;
use crate::iana::*;
use crate::wire::deserializer::nlri::MacAddressParsingError;

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum CommunityParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedCommunityParsingError<'a>> for Community {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedCommunityParsingError<'a>> {
        let (buf, value) = be_u32(buf)?;
        Ok((buf, Community::new(value)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    TransitiveTwoOctetExtendedCommunityError(
        #[from_located(module = "self")] TransitiveTwoOctetExtendedCommunityParsingError,
    ),
    NonTransitiveTwoOctetExtendedCommunityError(
        #[from_located(module = "self")] NonTransitiveTwoOctetExtendedCommunityParsingError,
    ),
    TransitiveIpv4ExtendedCommunityError(
        #[from_located(module = "self")] TransitiveIpv4ExtendedCommunityParsingError,
    ),
    NonTransitiveIpv4ExtendedCommunityError(
        #[from_located(module = "self")] NonTransitiveIpv4ExtendedCommunityParsingError,
    ),
    TransitiveFourOctetExtendedCommunityError(
        #[from_located(module = "self")] TransitiveFourOctetExtendedCommunityParsingError,
    ),
    NonTransitiveFourOctetExtendedCommunityError(
        #[from_located(module = "self")] NonTransitiveFourOctetExtendedCommunityParsingError,
    ),
    TransitiveOpaqueExtendedCommunityError(
        #[from_located(module = "self")] TransitiveOpaqueExtendedCommunityParsingError,
    ),
    NonTransitiveOpaqueExtendedCommunityError(
        #[from_located(module = "self")] NonTransitiveOpaqueExtendedCommunityParsingError,
    ),
    EvpnExtendedCommunityError(#[from_located(module = "self")] EvpnExtendedCommunityParsingError),
    ExperimentalExtendedCommunityError(
        #[from_located(module = "self")] ExperimentalExtendedCommunityParsingError,
    ),
    UnknownExtendedCommunityError(
        #[from_located(module = "self")] UnknownExtendedCommunityParsingError,
    ),
}

impl<'a> ReadablePdu<'a, LocatedExtendedCommunityParsingError<'a>> for ExtendedCommunity {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedExtendedCommunityParsingError<'a>> {
        let (buf, code) = be_u8(buf)?;
        let comm_type = BgpExtendedCommunityType::try_from(code);
        let (buf, ret) = match comm_type {
            Ok(BgpExtendedCommunityType::TransitiveTwoOctet) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::TransitiveTwoOctet(value))
            }
            Ok(BgpExtendedCommunityType::NonTransitiveTwoOctet) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::NonTransitiveTwoOctet(value))
            }
            Ok(BgpExtendedCommunityType::TransitiveIpv4) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::TransitiveIpv4(value))
            }
            Ok(BgpExtendedCommunityType::NonTransitiveIpv4) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::NonTransitiveIpv4(value))
            }
            Ok(BgpExtendedCommunityType::TransitiveFourOctet) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::TransitiveFourOctet(value))
            }
            Ok(BgpExtendedCommunityType::NonTransitiveFourOctet) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::NonTransitiveFourOctet(value))
            }
            Ok(BgpExtendedCommunityType::TransitiveOpaque) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::TransitiveOpaque(value))
            }
            Ok(BgpExtendedCommunityType::NonTransitiveOpaque) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::NonTransitiveOpaque(value))
            }
            Ok(BgpExtendedCommunityType::TransitiveQosMarking) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::NonTransitiveQosMarking) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::CosCapability) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::Evpn) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunity::Evpn(value))
            }
            Ok(BgpExtendedCommunityType::FlowSpecNextHop) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::FlowSpecIndirectionId) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::TransitiveTransportClass) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::NonTransitiveTransportClass) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::ServiceFunctionChain) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::Srv6MobileUserPlane) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::GenericPart1) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::GenericPart2) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::GenericPart3) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
            Ok(BgpExtendedCommunityType::Experimental83)
            | Ok(BgpExtendedCommunityType::Experimental84)
            | Ok(BgpExtendedCommunityType::Experimental85)
            | Ok(BgpExtendedCommunityType::Experimental86)
            | Ok(BgpExtendedCommunityType::Experimental87)
            | Ok(BgpExtendedCommunityType::Experimental88)
            | Ok(BgpExtendedCommunityType::Experimental89)
            | Ok(BgpExtendedCommunityType::Experimental8A)
            | Ok(BgpExtendedCommunityType::Experimental8B)
            | Ok(BgpExtendedCommunityType::Experimental8C)
            | Ok(BgpExtendedCommunityType::Experimental8D)
            | Ok(BgpExtendedCommunityType::Experimental8E)
            | Ok(BgpExtendedCommunityType::Experimental8F)
            | Ok(BgpExtendedCommunityType::ExperimentalC0)
            | Ok(BgpExtendedCommunityType::ExperimentalC1)
            | Ok(BgpExtendedCommunityType::ExperimentalC2)
            | Ok(BgpExtendedCommunityType::ExperimentalC3)
            | Ok(BgpExtendedCommunityType::ExperimentalC4)
            | Ok(BgpExtendedCommunityType::ExperimentalC5)
            | Ok(BgpExtendedCommunityType::ExperimentalC6)
            | Ok(BgpExtendedCommunityType::ExperimentalC7)
            | Ok(BgpExtendedCommunityType::ExperimentalC8)
            | Ok(BgpExtendedCommunityType::ExperimentalC9)
            | Ok(BgpExtendedCommunityType::ExperimentalCa)
            | Ok(BgpExtendedCommunityType::ExperimentalCb)
            | Ok(BgpExtendedCommunityType::ExperimentalCc)
            | Ok(BgpExtendedCommunityType::ExperimentalCd)
            | Ok(BgpExtendedCommunityType::ExperimentalCe)
            | Ok(BgpExtendedCommunityType::ExperimentalCf) => {
                let (buf, value) = parse_into_located_one_input(buf, code)?;
                (buf, ExtendedCommunity::Experimental(value))
            }
            Err(err) => {
                let (buf, value) = parse_into_located_one_input(buf, err.0)?;
                (buf, ExtendedCommunity::Unknown(value))
            }
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LargeCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedLargeCommunityParsingError<'a>> for LargeCommunity {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedLargeCommunityParsingError<'a>> {
        let (buf, global_admin) = be_u32(buf)?;
        let (buf, local_data1) = be_u32(buf)?;
        let (buf, local_data2) = be_u32(buf)?;
        Ok((
            buf,
            LargeCommunity::new(global_admin, local_data1, local_data2),
        ))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveTwoOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedTransitiveTwoOctetExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunityIpv6ParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    TransitiveIpv6ExtendedCommunityError(
        #[from_located(module = "self")] TransitiveIpv6ExtendedCommunityParsingError,
    ),
    NonTransitiveIpv6ExtendedCommunityError(
        #[from_located(module = "self")] NonTransitiveIpv6ExtendedCommunityParsingError,
    ),
    UnknownExtendedCommunityIpv6Error(
        #[from_located(module = "self")] UnknownExtendedCommunityIpv6ParsingError,
    ),
}

impl<'a> ReadablePdu<'a, LocatedExtendedCommunityIpv6ParsingError<'a>> for ExtendedCommunityIpv6 {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedExtendedCommunityIpv6ParsingError<'a>> {
        let (buf, code) = be_u8(buf)?;
        let comm_type = BgpExtendedCommunityIpv6Type::try_from(code);
        let (buf, ret) = match comm_type {
            Ok(BgpExtendedCommunityIpv6Type::TransitiveIpv6) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunityIpv6::TransitiveIpv6(value))
            }
            Ok(BgpExtendedCommunityIpv6Type::NonTransitiveIpv6) => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, ExtendedCommunityIpv6::NonTransitiveIpv6(value))
            }
            Err(err) => {
                let (buf, value) = parse_into_located_one_input(buf, err.0)?;
                (buf, ExtendedCommunityIpv6::Unknown(value))
            }
        };
        Ok((buf, ret))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveTwoOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedNonTransitiveTwoOctetExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveIpv4ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedTransitiveIpv4ExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveIpv4ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedNonTransitiveIpv4ExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveFourOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedTransitiveFourOctetExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveFourOctetExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedNonTransitiveFourOctetExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveOpaqueExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedTransitiveOpaqueExtendedCommunityParsingError<'a>>
    for TransitiveOpaqueExtendedCommunity
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedTransitiveOpaqueExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, community) = match TransitiveOpaqueExtendedCommunitySubType::try_from(sub_type) {
            Ok(TransitiveOpaqueExtendedCommunitySubType::DefaultGateway) => {
                let (buf, _) = be_u16(buf)?;
                let (buf, _) = be_u32(buf)?;
                (buf, TransitiveOpaqueExtendedCommunity::DefaultGateway)
            }
            Err(_) => {
                let (buf, p1) = be_u16(buf)?;
                let (buf, p2) = be_u32(buf)?;
                let p1 = p1.to_be_bytes();
                let p2 = p2.to_be_bytes();
                let value: [u8; 6] = [p1[0], p1[1], p2[0], p2[1], p2[2], p2[3]];
                (
                    buf,
                    TransitiveOpaqueExtendedCommunity::Unassigned { sub_type, value },
                )
            }
        };
        Ok((buf, community))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveOpaqueExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePdu<'a, LocatedNonTransitiveOpaqueExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum EvpnExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    MacAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] MacAddressParsingError,
    ),
}

impl<'a> ReadablePdu<'a, LocatedEvpnExtendedCommunityParsingError<'a>> for EvpnExtendedCommunity {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedEvpnExtendedCommunityParsingError<'a>> {
        let (buf, sub_type) = be_u8(buf)?;
        let (buf, community) = match EvpnExtendedCommunitySubType::try_from(sub_type) {
            Ok(EvpnExtendedCommunitySubType::MacMobility) => {
                let (buf, flags) = be_u8(buf)?;
                let (buf, _reserved) = be_u8(buf)?;
                let (buf, seq_no) = be_u32(buf)?;
                (buf, EvpnExtendedCommunity::MacMobility { flags, seq_no })
            }
            Ok(EvpnExtendedCommunitySubType::EsiLabel) => {
                let (buf, flags) = be_u8(buf)?;
                let (buf, _reserved) = be_u16(buf)?;
                let (buf, p1) = be_u16(buf)?;
                let (buf, p2) = be_u8(buf)?;
                let p1 = p1.to_be_bytes();
                let esi_label: [u8; 3] = [p1[0], p1[1], p2];
                (buf, EvpnExtendedCommunity::EsiLabel { flags, esi_label })
            }
            Ok(EvpnExtendedCommunitySubType::EsImportRouteTarget) => {
                let (buf, p1) = be_u32(buf)?;
                let (buf, p2) = be_u16(buf)?;
                let p1 = p1.to_be_bytes();
                let p2 = p2.to_be_bytes();
                let route_target: [u8; 6] = [p1[0], p1[1], p1[2], p1[2], p2[0], p2[1]];
                (
                    buf,
                    EvpnExtendedCommunity::EsImportRouteTarget { route_target },
                )
            }
            Ok(EvpnExtendedCommunitySubType::EvpnRoutersMac) => {
                let (buf, mac) = parse_into_located(buf)?;
                (buf, EvpnExtendedCommunity::EvpnRoutersMac { mac })
            }
            Ok(EvpnExtendedCommunitySubType::EvpnL2Attribute) => {
                let (buf, control_flags) = be_u16(buf)?;
                let (buf, l2_mtu) = be_u16(buf)?;
                // Reserved 2-octets
                let (buf, _) = be_u16(buf)?;
                (
                    buf,
                    EvpnExtendedCommunity::EvpnL2Attribute {
                        control_flags,
                        l2_mtu,
                    },
                )
            }
            Ok(_) | Err(_) => {
                let (buf, p1) = be_u32(buf)?;
                let (buf, p2) = be_u16(buf)?;
                let p1 = p1.to_be_bytes();
                let p2 = p2.to_be_bytes();
                let value: [u8; 6] = [p1[0], p1[1], p1[2], p1[2], p2[0], p2[1]];
                (buf, EvpnExtendedCommunity::Unassigned { sub_type, value })
            }
        };
        Ok((buf, community))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExperimentalExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePduWithOneInput<'a, u8, LocatedExperimentalExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UnknownExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePduWithOneInput<'a, u8, LocatedUnknownExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TransitiveIpv6ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedTransitiveIpv6ExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NonTransitiveIpv6ExtendedCommunityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedNonTransitiveIpv6ExtendedCommunityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UnknownExtendedCommunityIpv6ParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidValueLength(usize),
}

impl<'a> ReadablePduWithOneInput<'a, u8, LocatedUnknownExtendedCommunityIpv6ParsingError<'a>>
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
