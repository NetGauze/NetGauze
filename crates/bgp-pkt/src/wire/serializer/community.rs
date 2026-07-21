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

use crate::community::*;
use crate::iana::{
    BgpExtendedCommunityIpv6Type, BgpExtendedCommunityType, EvpnExtendedCommunitySubType,
    NonTransitiveTwoOctetExtendedCommunitySubType, TransitiveFourOctetExtendedCommunitySubType,
    TransitiveIpv4ExtendedCommunitySubType, TransitiveIpv6ExtendedCommunitySubType,
    TransitiveOpaqueExtendedCommunitySubType, TransitiveTwoOctetExtendedCommunitySubType,
};
use crate::wire::serializer::nlri::MacAddressWritingError;
use netgauze_parse_utils::{WritablePdu, impl_from_io_error};

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum CommunityWritingError {
    #[error("IO error while writing community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(CommunityWritingError);

impl WritablePdu<CommunityWritingError> for Community {
    // u32 community value
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), CommunityWritingError> {
        writer.write_all(&self.value().to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum ExtendedCommunityWritingError {
    #[error("IO error while writing extended community: {0}")]
    StdIOError(Box<str>),

    #[error("in transitive two-octet extended community: {0}")]
    TransitiveTwoOctetExtendedCommunityError(
        #[from] TransitiveTwoOctetExtendedCommunityWritingError,
    ),

    #[error("in non-transitive two-octet extended community: {0}")]
    NonTransitiveTwoOctetExtendedCommunityError(
        #[from] NonTransitiveTwoOctetExtendedCommunityWritingError,
    ),

    #[error("in transitive IPv4 extended community: {0}")]
    TransitiveIpv4ExtendedCommunityError(#[from] TransitiveIpv4ExtendedCommunityWritingError),

    #[error("in non-transitive IPv4 extended community: {0}")]
    NonTransitiveIpv4ExtendedCommunityError(#[from] NonTransitiveIpv4ExtendedCommunityWritingError),

    #[error("in transitive four-octet extended community: {0}")]
    TransitiveFourOctetExtendedCommunityError(
        #[from] TransitiveFourOctetExtendedCommunityWritingError,
    ),

    #[error("in non-transitive four-octet extended community: {0}")]
    NonTransitiveFourOctetExtendedCommunityError(
        #[from] NonTransitiveFourOctetExtendedCommunityWritingError,
    ),

    #[error("in transitive opaque extended community: {0}")]
    TransitiveOpaqueExtendedCommunityError(#[from] TransitiveOpaqueExtendedCommunityWritingError),

    #[error("in non-transitive opaque extended community: {0}")]
    NonTransitiveOpaqueExtendedCommunityError(
        #[from] NonTransitiveOpaqueExtendedCommunityWritingError,
    ),

    #[error("in EVPN extended community: {0}")]
    EvpnExtendedCommunityError(#[from] EvpnExtendedCommunityWritingError),

    #[error("in experimental extended community: {0}")]
    ExperimentalExtendedCommunityError(#[from] ExperimentalExtendedCommunityWritingError),

    #[error("in unknown extended community: {0}")]
    UnknownExtendedCommunityError(#[from] UnknownExtendedCommunityWritingError),
}
impl_from_io_error!(ExtendedCommunityWritingError);

impl WritablePdu<ExtendedCommunityWritingError> for ExtendedCommunity {
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                ExtendedCommunity::TransitiveTwoOctet(value) => value.len(),
                ExtendedCommunity::NonTransitiveTwoOctet(value) => value.len(),
                ExtendedCommunity::TransitiveIpv4(value) => value.len(),
                ExtendedCommunity::NonTransitiveIpv4(value) => value.len(),
                ExtendedCommunity::TransitiveFourOctet(value) => value.len(),
                ExtendedCommunity::NonTransitiveFourOctet(value) => value.len(),
                ExtendedCommunity::TransitiveOpaque(value) => value.len(),
                ExtendedCommunity::NonTransitiveOpaque(value) => value.len(),
                ExtendedCommunity::Evpn(value) => value.len(),
                ExtendedCommunity::Experimental(value) => value.len(),
                ExtendedCommunity::Unknown(value) => value.len(),
            }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExtendedCommunityWritingError> {
        match self {
            ExtendedCommunity::TransitiveTwoOctet(value) => {
                writer.write_all(&[BgpExtendedCommunityType::TransitiveTwoOctet as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::NonTransitiveTwoOctet(value) => {
                writer.write_all(&[BgpExtendedCommunityType::NonTransitiveTwoOctet as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::TransitiveIpv4(value) => {
                writer.write_all(&[BgpExtendedCommunityType::TransitiveIpv4 as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::NonTransitiveIpv4(value) => {
                writer.write_all(&[BgpExtendedCommunityType::NonTransitiveIpv4 as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::TransitiveFourOctet(value) => {
                writer.write_all(&[BgpExtendedCommunityType::TransitiveFourOctet as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::NonTransitiveFourOctet(value) => {
                writer.write_all(&[BgpExtendedCommunityType::NonTransitiveFourOctet as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::TransitiveOpaque(value) => {
                writer.write_all(&[BgpExtendedCommunityType::TransitiveOpaque as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::NonTransitiveOpaque(value) => {
                writer.write_all(&[BgpExtendedCommunityType::NonTransitiveOpaque as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::Experimental(value) => {
                writer.write_all(&[value.code()])?;
                value.write(writer)?;
            }
            ExtendedCommunity::Evpn(value) => {
                writer.write_all(&[BgpExtendedCommunityType::Evpn as u8])?;
                value.write(writer)?;
            }
            ExtendedCommunity::Unknown(value) => {
                writer.write_all(&[value.code()])?;
                value.write(writer)?;
            }
        };
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum ExtendedCommunityIpv6WritingError {
    #[error("IO error while writing extended community IPv6: {0}")]
    StdIOError(Box<str>),

    #[error("in transitive IPv6 extended community: {0}")]
    TransitiveIpv6ExtendedCommunityError(#[from] TransitiveIpv6ExtendedCommunityWritingError),

    #[error("in non-transitive ip64 extended community: {0}")]
    NonTransitiveIp64ExtendedCommunityError(#[from] NonTransitiveIpv6ExtendedCommunityWritingError),

    #[error("in unknown extended community IPv6: {0}")]
    UnknownExtendedCommunityIpv6Error(#[from] UnknownExtendedCommunityIpv6WritingError),
}
impl_from_io_error!(ExtendedCommunityIpv6WritingError);

impl WritablePdu<ExtendedCommunityIpv6WritingError> for ExtendedCommunityIpv6 {
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::TransitiveIpv6(value) => value.len(),
                Self::NonTransitiveIpv6(value) => value.len(),
                Self::Unknown(value) => value.len(),
            }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExtendedCommunityIpv6WritingError> {
        match self {
            Self::TransitiveIpv6(value) => {
                writer.write_all(&[BgpExtendedCommunityIpv6Type::TransitiveIpv6 as u8])?;
                value.write(writer)?;
            }
            Self::NonTransitiveIpv6(value) => {
                writer.write_all(&[BgpExtendedCommunityIpv6Type::NonTransitiveIpv6 as u8])?;
                value.write(writer)?;
            }
            Self::Unknown(value) => {
                writer.write_all(&[value.code()])?;
                value.write(writer)?;
            }
        };
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum LargeCommunityWritingError {
    #[error("IO error while writing large community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(LargeCommunityWritingError);

impl WritablePdu<LargeCommunityWritingError> for LargeCommunity {
    /// 4-octet global admin + 4-octets local data part 1 + 4-octets local data
    /// part 1
    const BASE_LENGTH: usize = 12;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), LargeCommunityWritingError> {
        writer.write_all(&self.global_admin().to_be_bytes())?;
        writer.write_all(&self.local_data1().to_be_bytes())?;
        writer.write_all(&self.local_data2().to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveTwoOctetExtendedCommunityWritingError {
    #[error("IO error while writing transitive two-octet extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(TransitiveTwoOctetExtendedCommunityWritingError);

impl WritablePdu<TransitiveTwoOctetExtendedCommunityWritingError>
    for TransitiveTwoOctetExtendedCommunity
{
    // 1-octet subtype + 2-octets global admin + 4-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), TransitiveTwoOctetExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::RouteTarget {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::RouteTarget as u8,
                global_admin,
                local_admin,
            ),
            Self::RouteOrigin {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::RouteOrigin as u8,
                global_admin,
                local_admin,
            ),
            Self::OspfDomainIdentifier {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::OspfDomainIdentifier as u8,
                global_admin,
                local_admin,
            ),
            Self::BgpDataCollection {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::BgpDataCollection as u8,
                global_admin,
                local_admin,
            ),
            Self::SourceAs {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::RouteTarget as u8,
                global_admin,
                local_admin,
            ),
            Self::L2VpnIdentifier {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::L2VpnIdentifier as u8,
                global_admin,
                local_admin,
            ),
            Self::CiscoVpnDistinguisher {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::CiscoVpnDistinguisher as u8,
                global_admin,
                local_admin,
            ),
            Self::RouteTargetRecord {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::RouteTargetRecord as u8,
                global_admin,
                local_admin,
            ),
            Self::RtDerivedEc {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::RtDerivedEc as u8,
                global_admin,
                local_admin,
            ),
            Self::VirtualNetworkIdentifier {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::VirtualNetworkIdentifier as u8,
                global_admin,
                local_admin,
            ),
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&(*global_admin).to_be_bytes())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveTwoOctetExtendedCommunityWritingError {
    #[error("IO error while writing non-transitive two-octet extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(NonTransitiveTwoOctetExtendedCommunityWritingError);

impl WritablePdu<NonTransitiveTwoOctetExtendedCommunityWritingError>
    for NonTransitiveTwoOctetExtendedCommunity
{
    // 1-octet subtype + 2-octets global admin + 4-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), NonTransitiveTwoOctetExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::LinkBandwidth {
                global_admin,
                local_admin,
            } => (
                NonTransitiveTwoOctetExtendedCommunitySubType::LinkBandwidth as u8,
                global_admin,
                local_admin,
            ),
            Self::VirtualNetworkIdentifier {
                global_admin,
                local_admin,
            } => (
                NonTransitiveTwoOctetExtendedCommunitySubType::VirtualNetworkIdentifier as u8,
                global_admin,
                local_admin,
            ),
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&(*global_admin).to_be_bytes())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveIpv4ExtendedCommunityWritingError {
    #[error("IO error while writing transitive IPv4 extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(TransitiveIpv4ExtendedCommunityWritingError);

impl WritablePdu<TransitiveIpv4ExtendedCommunityWritingError> for TransitiveIpv4ExtendedCommunity {
    // 1-octet subtype + 4-octets global admin + 2-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), TransitiveIpv4ExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::RouteTarget {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::RouteTarget as u8,
                global_admin,
                local_admin,
            ),
            Self::RouteOrigin {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::RouteOrigin as u8,
                global_admin,
                local_admin,
            ),
            Self::Ipv4Ifit {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::Ipv4Ifit as u8,
                global_admin,
                local_admin,
            ),
            Self::OspfDomainIdentifier {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::OspfDomainIdentifier as u8,
                global_admin,
                local_admin,
            ),
            Self::OspfRouteID {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::OspfRouteID as u8,
                global_admin,
                local_admin,
            ),
            Self::NodeTarget {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::NodeTarget as u8,
                global_admin,
                local_admin,
            ),
            Self::L2VpnIdentifier {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::L2VpnIdentifier as u8,
                global_admin,
                local_admin,
            ),
            Self::VrfRouteImport {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::VrfRouteImport as u8,
                global_admin,
                local_admin,
            ),
            Self::FlowSpecRedirectToIpv4 {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::FlowSpecRedirectToIpv4 as u8,
                global_admin,
                local_admin,
            ),
            Self::CiscoVpnDistinguisher {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::CiscoVpnDistinguisher as u8,
                global_admin,
                local_admin,
            ),
            Self::InterAreaP2MpSegmentedNextHop {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::InterAreaP2MpSegmentedNextHop as u8,
                global_admin,
                local_admin,
            ),
            Self::RouteTargetRecord {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::RouteTargetRecord as u8,
                global_admin,
                local_admin,
            ),
            Self::VrfRecursiveNextHop {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::VrfRecursiveNextHop as u8,
                global_admin,
                local_admin,
            ),
            Self::RtDerivedEc {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::RtDerivedEc as u8,
                global_admin,
                local_admin,
            ),
            Self::MulticastVpnRpAddress {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::MulticastVpnRpAddress as u8,
                global_admin,
                local_admin,
            ),
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&global_admin.octets())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveIpv4ExtendedCommunityWritingError {
    #[error("IO error while writing non-transitive IPv4 extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(NonTransitiveIpv4ExtendedCommunityWritingError);

impl WritablePdu<NonTransitiveIpv4ExtendedCommunityWritingError>
    for NonTransitiveIpv4ExtendedCommunity
{
    // 1-octet subtype + 4-octets global admin + 2-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), NonTransitiveIpv4ExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&global_admin.octets())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveFourOctetExtendedCommunityWritingError {
    #[error("IO error while writing transitive four-octet extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(TransitiveFourOctetExtendedCommunityWritingError);

impl WritablePdu<TransitiveFourOctetExtendedCommunityWritingError>
    for TransitiveFourOctetExtendedCommunity
{
    // 1-octet subtype + 2-octets global admin + 4-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), TransitiveFourOctetExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::RouteTarget {
                global_admin,
                local_admin,
            } => (
                TransitiveFourOctetExtendedCommunitySubType::RouteTarget as u8,
                global_admin,
                local_admin,
            ),
            Self::RouteOrigin {
                global_admin,
                local_admin,
            } => (
                TransitiveFourOctetExtendedCommunitySubType::RouteOrigin as u8,
                global_admin,
                local_admin,
            ),
            Self::OspfDomainIdentifier {
                global_admin,
                local_admin,
            } => (
                TransitiveFourOctetExtendedCommunitySubType::OspfDomainIdentifier as u8,
                global_admin,
                local_admin,
            ),
            Self::BgpDataCollection {
                global_admin,
                local_admin,
            } => (
                TransitiveFourOctetExtendedCommunitySubType::BgpDataCollection as u8,
                global_admin,
                local_admin,
            ),
            Self::SourceAs {
                global_admin,
                local_admin,
            } => (
                TransitiveFourOctetExtendedCommunitySubType::RouteTarget as u8,
                global_admin,
                local_admin,
            ),
            Self::CiscoVpnDistinguisher {
                global_admin,
                local_admin,
            } => (
                TransitiveFourOctetExtendedCommunitySubType::CiscoVpnDistinguisher as u8,
                global_admin,
                local_admin,
            ),
            Self::RouteTargetRecord {
                global_admin,
                local_admin,
            } => (
                TransitiveFourOctetExtendedCommunitySubType::RouteTargetRecord as u8,
                global_admin,
                local_admin,
            ),
            Self::RtDerivedEc {
                global_admin,
                local_admin,
            } => (
                TransitiveTwoOctetExtendedCommunitySubType::RtDerivedEc as u8,
                global_admin,
                local_admin,
            ),
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&(*global_admin).to_be_bytes())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveFourOctetExtendedCommunityWritingError {
    #[error("IO error while writing non-transitive four-octet extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(NonTransitiveFourOctetExtendedCommunityWritingError);

impl WritablePdu<NonTransitiveFourOctetExtendedCommunityWritingError>
    for NonTransitiveFourOctetExtendedCommunity
{
    // 1-octet subtype + 2-octets global admin + 4-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), NonTransitiveFourOctetExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&(*global_admin).to_be_bytes())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveOpaqueExtendedCommunityWritingError {
    #[error("IO error while writing transitive opaque extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(TransitiveOpaqueExtendedCommunityWritingError);

impl WritablePdu<TransitiveOpaqueExtendedCommunityWritingError>
    for TransitiveOpaqueExtendedCommunity
{
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), TransitiveOpaqueExtendedCommunityWritingError> {
        match self {
            Self::Upa {
                drop,
                bgp_router_id,
            } => {
                writer.write_all(&[TransitiveOpaqueExtendedCommunitySubType::Upa as u8])?;
                // Flags: only the `D` bit is defined, the rest MUST be zero
                writer.write_all(&[if *drop { 0x80 } else { 0x00 }])?;
                // Reserved octet, MUST be zero on transmission
                writer.write_all(&[0x00])?;
                writer.write_all(&bgp_router_id.octets())?;
            }
            Self::DefaultGateway => {
                writer
                    .write_all(&[TransitiveOpaqueExtendedCommunitySubType::DefaultGateway as u8])?;
                writer.write_all(&0u16.to_be_bytes())?;
                writer.write_all(&0u32.to_be_bytes())?;
            }
            Self::Unassigned { sub_type, value } => {
                writer.write_all(&[*sub_type])?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveOpaqueExtendedCommunityWritingError {
    #[error("IO error while writing non-transitive opaque extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(NonTransitiveOpaqueExtendedCommunityWritingError);

impl WritablePdu<NonTransitiveOpaqueExtendedCommunityWritingError>
    for NonTransitiveOpaqueExtendedCommunity
{
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), NonTransitiveOpaqueExtendedCommunityWritingError> {
        match self {
            Self::Unassigned { sub_type, value } => {
                writer.write_all(&[*sub_type])?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum ExperimentalExtendedCommunityWritingError {
    #[error("IO error while writing experimental extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(ExperimentalExtendedCommunityWritingError);

impl WritablePdu<ExperimentalExtendedCommunityWritingError> for ExperimentalExtendedCommunity {
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExperimentalExtendedCommunityWritingError> {
        writer.write_all(&[self.sub_type()])?;
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum UnknownExtendedCommunityWritingError {
    #[error("IO error while writing unknown extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(UnknownExtendedCommunityWritingError);

impl WritablePdu<UnknownExtendedCommunityWritingError> for UnknownExtendedCommunity {
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), UnknownExtendedCommunityWritingError> {
        writer.write_all(&[self.sub_type()])?;
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveIpv6ExtendedCommunityWritingError {
    #[error("IO error while writing transitive IPv6 extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(TransitiveIpv6ExtendedCommunityWritingError);

impl WritablePdu<TransitiveIpv6ExtendedCommunityWritingError> for TransitiveIpv6ExtendedCommunity {
    // 1-octet subtype + 16-octets global admin + 2-octets local admin
    const BASE_LENGTH: usize = 19;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), TransitiveIpv6ExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::RouteTarget {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::RouteTarget as u8,
                global_admin,
                local_admin,
            ),
            Self::RouteOrigin {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::RouteOrigin as u8,
                global_admin,
                local_admin,
            ),
            Self::Ipv6Ifit {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::Ipv6Ifit as u8,
                global_admin,
                local_admin,
            ),
            Self::VrfRouteImport {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv4ExtendedCommunitySubType::VrfRouteImport as u8,
                global_admin,
                local_admin,
            ),
            Self::FlowSpecRedirectToIpv6 {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::FlowSpecRedirectToIpv6 as u8,
                global_admin,
                local_admin,
            ),
            Self::FlowSpecRtRedirectToIpv6 {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::FlowSpecRtRedirectToIpv6 as u8,
                global_admin,
                local_admin,
            ),
            Self::CiscoVpnDistinguisher {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::CiscoVpnDistinguisher as u8,
                global_admin,
                local_admin,
            ),
            Self::InterAreaP2MpSegmentedNextHop {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::InterAreaP2MpSegmentedNextHop as u8,
                global_admin,
                local_admin,
            ),
            Self::RtDerivedEc {
                global_admin,
                local_admin,
            } => (
                TransitiveIpv6ExtendedCommunitySubType::RtDerivedEc as u8,
                global_admin,
                local_admin,
            ),
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&global_admin.octets())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveIpv6ExtendedCommunityWritingError {
    #[error("IO error while writing non-transitive IPv6 extended community: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(NonTransitiveIpv6ExtendedCommunityWritingError);

impl WritablePdu<NonTransitiveIpv6ExtendedCommunityWritingError>
    for NonTransitiveIpv6ExtendedCommunity
{
    // 1-octet subtype + 16-octets global admin + 2-octets local admin
    const BASE_LENGTH: usize = 19;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), NonTransitiveIpv6ExtendedCommunityWritingError> {
        let (sub_type, global_admin, local_admin) = match self {
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_all(&[sub_type])?;
        writer.write_all(&global_admin.octets())?;
        writer.write_all(&(*local_admin).to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum UnknownExtendedCommunityIpv6WritingError {
    #[error("IO error while writing unknown extended community IPv6: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(UnknownExtendedCommunityIpv6WritingError);

impl WritablePdu<UnknownExtendedCommunityIpv6WritingError> for UnknownExtendedCommunityIpv6 {
    // 1-octet subtype + 18-octets value
    const BASE_LENGTH: usize = 19;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), UnknownExtendedCommunityIpv6WritingError> {
        writer.write_all(&[self.sub_type()])?;
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum EvpnExtendedCommunityWritingError {
    #[error("IO error while writing EVPN extended community: {0}")]
    StdIOError(Box<str>),

    #[error("in MAC address: {0}")]
    MacAddressError(#[from] MacAddressWritingError),
}
impl_from_io_error!(EvpnExtendedCommunityWritingError);

impl WritablePdu<EvpnExtendedCommunityWritingError> for EvpnExtendedCommunity {
    // 1-octet subtype + 2-octets global admin + 4-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), EvpnExtendedCommunityWritingError> {
        match self {
            Self::MacMobility { flags, seq_no } => {
                writer.write_all(&[EvpnExtendedCommunitySubType::MacMobility as u8])?;
                writer.write_all(&[*flags])?;
                // reserved
                writer.write_all(&[0])?;
                writer.write_all(&(*seq_no).to_be_bytes())?;
            }
            Self::EsiLabel { flags, esi_label } => {
                writer.write_all(&[EvpnExtendedCommunitySubType::EsiLabel as u8])?;
                writer.write_all(&[*flags])?;
                // reserved
                writer.write_all(&0u16.to_be_bytes())?;
                writer.write_all(esi_label)?;
            }
            Self::EsImportRouteTarget { route_target } => {
                writer.write_all(&[EvpnExtendedCommunitySubType::EsImportRouteTarget as u8])?;
                writer.write_all(route_target)?;
            }
            Self::EvpnRoutersMac { mac } => {
                writer.write_all(&[EvpnExtendedCommunitySubType::EvpnRoutersMac as u8])?;
                mac.write(writer)?;
            }
            Self::EvpnL2Attribute {
                control_flags,
                l2_mtu,
            } => {
                writer.write_all(&[EvpnExtendedCommunitySubType::EvpnL2Attribute as u8])?;
                writer.write_all(&(*control_flags).to_be_bytes())?;
                writer.write_all(&(*l2_mtu).to_be_bytes())?;
                // Reserved 2-octets
                writer.write_all(&0u16.to_be_bytes())?;
            }
            Self::Unassigned { sub_type, value } => {
                writer.write_all(&[*sub_type])?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}
