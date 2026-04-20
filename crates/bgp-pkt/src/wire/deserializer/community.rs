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

use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::BytesReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::community::*;
use crate::iana::*;
use crate::nlri::MacAddress;
use crate::wire::deserializer::nlri::MacAddressParsingError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum CommunityParsingError {
    #[error("Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for Community {
    type Error = CommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let value = cur.read_u32_be()?;
        Ok(Community::new(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ExtendedCommunityParsingError {
    #[error("Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Extended Community error: {0}")]
    TransitiveTwoOctetExtendedCommunityError(
        #[from] TransitiveTwoOctetExtendedCommunityParsingError,
    ),
    #[error("Extended Community error: {0}")]
    NonTransitiveTwoOctetExtendedCommunityError(
        #[from] NonTransitiveTwoOctetExtendedCommunityParsingError,
    ),
    #[error("Extended Community error: {0}")]
    TransitiveIpv4ExtendedCommunityError(#[from] TransitiveIpv4ExtendedCommunityParsingError),
    #[error("Extended Community error: {0}")]
    NonTransitiveIpv4ExtendedCommunityError(#[from] NonTransitiveIpv4ExtendedCommunityParsingError),
    #[error("Extended Community error: {0}")]
    TransitiveFourOctetExtendedCommunityError(
        #[from] TransitiveFourOctetExtendedCommunityParsingError,
    ),
    #[error("Extended Community error: {0}")]
    NonTransitiveFourOctetExtendedCommunityError(
        #[from] NonTransitiveFourOctetExtendedCommunityParsingError,
    ),
    #[error("Extended Community error: {0}")]
    TransitiveOpaqueExtendedCommunityError(#[from] TransitiveOpaqueExtendedCommunityParsingError),
    #[error("Extended Community error: {0}")]
    NonTransitiveOpaqueExtendedCommunityError(
        #[from] NonTransitiveOpaqueExtendedCommunityParsingError,
    ),
    #[error("Extended Community error: {0}")]
    EvpnExtendedCommunityError(#[from] EvpnExtendedCommunityParsingError),
    #[error("Extended Community error: {0}")]
    ExperimentalExtendedCommunityError(#[from] ExperimentalExtendedCommunityParsingError),
    #[error("Extended Community error: {0}")]
    UnknownExtendedCommunityError(#[from] UnknownExtendedCommunityParsingError),
}

impl<'a> ParseFrom<'a> for ExtendedCommunity {
    type Error = ExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let code = cur.read_u8()?;
        let comm_type = BgpExtendedCommunityType::try_from(code);
        let ret = match comm_type {
            Ok(BgpExtendedCommunityType::TransitiveTwoOctet) => {
                let value = TransitiveTwoOctetExtendedCommunity::parse(cur)?;
                ExtendedCommunity::TransitiveTwoOctet(value)
            }
            Ok(BgpExtendedCommunityType::NonTransitiveTwoOctet) => {
                let value = NonTransitiveTwoOctetExtendedCommunity::parse(cur)?;
                ExtendedCommunity::NonTransitiveTwoOctet(value)
            }
            Ok(BgpExtendedCommunityType::TransitiveIpv4) => {
                let value = TransitiveIpv4ExtendedCommunity::parse(cur)?;
                ExtendedCommunity::TransitiveIpv4(value)
            }
            Ok(BgpExtendedCommunityType::NonTransitiveIpv4) => {
                let value = NonTransitiveIpv4ExtendedCommunity::parse(cur)?;
                ExtendedCommunity::NonTransitiveIpv4(value)
            }
            Ok(BgpExtendedCommunityType::TransitiveFourOctet) => {
                let value = TransitiveFourOctetExtendedCommunity::parse(cur)?;
                ExtendedCommunity::TransitiveFourOctet(value)
            }
            Ok(BgpExtendedCommunityType::NonTransitiveFourOctet) => {
                let value = NonTransitiveFourOctetExtendedCommunity::parse(cur)?;
                ExtendedCommunity::NonTransitiveFourOctet(value)
            }
            Ok(BgpExtendedCommunityType::TransitiveOpaque) => {
                let value = TransitiveOpaqueExtendedCommunity::parse(cur)?;
                ExtendedCommunity::TransitiveOpaque(value)
            }
            Ok(BgpExtendedCommunityType::NonTransitiveOpaque) => {
                let value = NonTransitiveOpaqueExtendedCommunity::parse(cur)?;
                ExtendedCommunity::NonTransitiveOpaque(value)
            }
            Ok(BgpExtendedCommunityType::TransitiveQosMarking) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::NonTransitiveQosMarking) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::CosCapability) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::Evpn) => {
                let value = EvpnExtendedCommunity::parse(cur)?;
                ExtendedCommunity::Evpn(value)
            }
            Ok(BgpExtendedCommunityType::FlowSpecNextHop) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::FlowSpecIndirectionId) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::TransitiveTransportClass) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::NonTransitiveTransportClass) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::ServiceFunctionChain) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::Srv6MobileUserPlane) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::GenericPart1) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::GenericPart2) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
            }
            Ok(BgpExtendedCommunityType::GenericPart3) => {
                let value = UnknownExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Unknown(value)
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
                let value = ExperimentalExtendedCommunity::parse(cur, code)?;
                ExtendedCommunity::Experimental(value)
            }
            Err(err) => {
                let value = UnknownExtendedCommunity::parse(cur, err.0)?;
                ExtendedCommunity::Unknown(value)
            }
        };
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LargeCommunityParsingError {
    #[error("Large Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for LargeCommunity {
    type Error = LargeCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let global_admin = cur.read_u32_be()?;
        let local_data1 = cur.read_u32_be()?;
        let local_data2 = cur.read_u32_be()?;
        Ok(LargeCommunity::new(global_admin, local_data1, local_data2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TransitiveTwoOctetExtendedCommunityParsingError {
    #[error("Transitive Two Octet Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for TransitiveTwoOctetExtendedCommunity {
    type Error = TransitiveTwoOctetExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u16_be()?;
        let local_admin = cur.read_u32_be()?;

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
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ExtendedCommunityIpv6ParsingError {
    #[error("Extended Community IPv6 parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Extended Community IPv6 error: {0}")]
    TransitiveIpv6ExtendedCommunityError(#[from] TransitiveIpv6ExtendedCommunityParsingError),
    #[error("Extended Community IPv6 error: {0}")]
    NonTransitiveIpv6ExtendedCommunityError(#[from] NonTransitiveIpv6ExtendedCommunityParsingError),
    #[error("Extended Community IPv6 error: {0}")]
    UnknownExtendedCommunityIpv6Error(#[from] UnknownExtendedCommunityIpv6ParsingError),
}

impl<'a> ParseFrom<'a> for ExtendedCommunityIpv6 {
    type Error = ExtendedCommunityIpv6ParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let code = cur.read_u8()?;
        let comm_type = BgpExtendedCommunityIpv6Type::try_from(code);
        let ret = match comm_type {
            Ok(BgpExtendedCommunityIpv6Type::TransitiveIpv6) => {
                let value = TransitiveIpv6ExtendedCommunity::parse(cur)?;
                ExtendedCommunityIpv6::TransitiveIpv6(value)
            }
            Ok(BgpExtendedCommunityIpv6Type::NonTransitiveIpv6) => {
                let value = NonTransitiveIpv6ExtendedCommunity::parse(cur)?;
                ExtendedCommunityIpv6::NonTransitiveIpv6(value)
            }
            Err(err) => {
                let value = UnknownExtendedCommunityIpv6::parse(cur, err.0)?;
                ExtendedCommunityIpv6::Unknown(value)
            }
        };
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NonTransitiveTwoOctetExtendedCommunityParsingError {
    #[error("Non Transitive Two Octet Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for NonTransitiveTwoOctetExtendedCommunity {
    type Error = NonTransitiveTwoOctetExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u16_be()?;
        let local_admin = cur.read_u32_be()?;
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
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TransitiveIpv4ExtendedCommunityParsingError {
    #[error("Transitive IPv4 Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for TransitiveIpv4ExtendedCommunity {
    type Error = TransitiveIpv4ExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u32_be()?;
        let global_admin = Ipv4Addr::from(global_admin);
        let local_admin = cur.read_u16_be()?;
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
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NonTransitiveIpv4ExtendedCommunityParsingError {
    #[error("Non Transitive IPv4 Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for NonTransitiveIpv4ExtendedCommunity {
    type Error = NonTransitiveIpv4ExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u32_be()?;
        let global_admin = Ipv4Addr::from(global_admin);
        let local_admin = cur.read_u16_be()?;
        let ret = NonTransitiveIpv4ExtendedCommunity::Unassigned {
            sub_type,
            global_admin,
            local_admin,
        };
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TransitiveFourOctetExtendedCommunityParsingError {
    #[error("Transitive Four Octet Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for TransitiveFourOctetExtendedCommunity {
    type Error = TransitiveFourOctetExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u32_be()?;
        let local_admin = cur.read_u16_be()?;
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
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NonTransitiveFourOctetExtendedCommunityParsingError {
    #[error("Non Transitive Four Octet Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for NonTransitiveFourOctetExtendedCommunity {
    type Error = NonTransitiveFourOctetExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u32_be()?;
        let local_admin = cur.read_u16_be()?;
        let ret = NonTransitiveFourOctetExtendedCommunity::Unassigned {
            sub_type,
            global_admin,
            local_admin,
        };
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TransitiveOpaqueExtendedCommunityParsingError {
    #[error("Transitive Opaque Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for TransitiveOpaqueExtendedCommunity {
    type Error = TransitiveOpaqueExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let community = match TransitiveOpaqueExtendedCommunitySubType::try_from(sub_type) {
            Ok(TransitiveOpaqueExtendedCommunitySubType::DefaultGateway) => {
                let _ = cur.read_bytes(6)?;
                TransitiveOpaqueExtendedCommunity::DefaultGateway
            }
            Err(_) => {
                let value = cur.read_array()?;
                TransitiveOpaqueExtendedCommunity::Unassigned { sub_type, value }
            }
        };
        Ok(community)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NonTransitiveOpaqueExtendedCommunityParsingError {
    #[error("Non Transitive Opaque Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for NonTransitiveOpaqueExtendedCommunity {
    type Error = NonTransitiveOpaqueExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let value = cur.read_array()?;
        Ok(NonTransitiveOpaqueExtendedCommunity::Unassigned { sub_type, value })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum EvpnExtendedCommunityParsingError {
    #[error("EVPN Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("EVPN Extended Community error: {0}")]
    MacAddressError(#[from] MacAddressParsingError),
}

impl<'a> ParseFrom<'a> for EvpnExtendedCommunity {
    type Error = EvpnExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let community = match EvpnExtendedCommunitySubType::try_from(sub_type) {
            Ok(EvpnExtendedCommunitySubType::MacMobility) => {
                let flags = cur.read_u8()?;
                let _reserved = cur.read_u8()?;
                let seq_no = cur.read_u32_be()?;
                EvpnExtendedCommunity::MacMobility { flags, seq_no }
            }
            Ok(EvpnExtendedCommunitySubType::EsiLabel) => {
                let flags = cur.read_u8()?;
                let _reserved = cur.read_u16_be()?;
                let esi_label: [u8; 3] = cur.read_array()?;
                EvpnExtendedCommunity::EsiLabel { flags, esi_label }
            }
            Ok(EvpnExtendedCommunitySubType::EsImportRouteTarget) => {
                let route_target: [u8; 6] = cur.read_array()?;
                EvpnExtendedCommunity::EsImportRouteTarget { route_target }
            }
            Ok(EvpnExtendedCommunitySubType::EvpnRoutersMac) => {
                let mac = MacAddress::parse(cur)?;
                EvpnExtendedCommunity::EvpnRoutersMac { mac }
            }
            Ok(EvpnExtendedCommunitySubType::EvpnL2Attribute) => {
                let control_flags = cur.read_u16_be()?;
                let l2_mtu = cur.read_u16_be()?;
                let _reserved = cur.read_u16_be()?;
                EvpnExtendedCommunity::EvpnL2Attribute {
                    control_flags,
                    l2_mtu,
                }
            }
            Ok(_) | Err(_) => {
                let value: [u8; 6] = cur.read_array()?;
                EvpnExtendedCommunity::Unassigned { sub_type, value }
            }
        };
        Ok(community)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ExperimentalExtendedCommunityParsingError {
    #[error("Experimental Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFromWithOneInput<'a, u8> for ExperimentalExtendedCommunity {
    type Error = ExperimentalExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader, code: u8) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let value: [u8; 6] = cur.read_array()?;
        Ok(ExperimentalExtendedCommunity::new(code, sub_type, value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum UnknownExtendedCommunityParsingError {
    #[error("Unknown Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFromWithOneInput<'a, u8> for UnknownExtendedCommunity {
    type Error = UnknownExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader, code: u8) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let value: [u8; 6] = cur.read_array()?;
        Ok(UnknownExtendedCommunity::new(code, sub_type, value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TransitiveIpv6ExtendedCommunityParsingError {
    #[error("Transitive IPv6 Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for TransitiveIpv6ExtendedCommunity {
    type Error = TransitiveIpv6ExtendedCommunityParsingError;

    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u128_be()?;
        let global_admin = Ipv6Addr::from(global_admin);
        let local_admin = cur.read_u16_be()?;
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
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NonTransitiveIpv6ExtendedCommunityParsingError {
    #[error("Non Transitive IPv6 Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for NonTransitiveIpv6ExtendedCommunity {
    type Error = NonTransitiveIpv6ExtendedCommunityParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let global_admin = cur.read_u128_be()?;
        let global_admin = Ipv6Addr::from(global_admin);
        let local_admin = cur.read_u16_be()?;
        let ret = NonTransitiveIpv6ExtendedCommunity::Unassigned {
            sub_type,
            global_admin,
            local_admin,
        };
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum UnknownExtendedCommunityIpv6ParsingError {
    #[error("Unknown IPv6 Extended Community parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFromWithOneInput<'a, u8> for UnknownExtendedCommunityIpv6 {
    type Error = UnknownExtendedCommunityIpv6ParsingError;
    fn parse(cur: &mut BytesReader, code: u8) -> Result<Self, Self::Error> {
        let sub_type = cur.read_u8()?;
        let value: [u8; 18] = cur.read_array()?;
        Ok(UnknownExtendedCommunityIpv6::new(code, sub_type, value))
    }
}
