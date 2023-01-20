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
    community::*,
    iana::{
        NonTransitiveTwoOctetExtendedCommunitySubType, TransitiveFourOctetExtendedCommunitySubType,
        TransitiveIpv4ExtendedCommunitySubType, TransitiveIpv6ExtendedCommunitySubType,
        TransitiveTwoOctetExtendedCommunitySubType,
    },
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveTwoOctetExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<TransitiveTwoOctetExtendedCommunityWritingError>
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
    ) -> Result<(), TransitiveTwoOctetExtendedCommunityWritingError>
    where
        Self: Sized,
    {
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
        writer.write_u8(sub_type)?;
        writer.write_u16::<NetworkEndian>(*global_admin)?;
        writer.write_u32::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveTwoOctetExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<NonTransitiveTwoOctetExtendedCommunityWritingError>
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
    ) -> Result<(), NonTransitiveTwoOctetExtendedCommunityWritingError>
    where
        Self: Sized,
    {
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
        writer.write_u8(sub_type)?;
        writer.write_u16::<NetworkEndian>(*global_admin)?;
        writer.write_u32::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveIpv4ExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<TransitiveIpv4ExtendedCommunityWritingError> for TransitiveIpv4ExtendedCommunity {
    // 1-octet subtype + 4-octets global admin + 2-octets local admin
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), TransitiveIpv4ExtendedCommunityWritingError>
    where
        Self: Sized,
    {
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
        writer.write_u8(sub_type)?;
        writer.write_all(&global_admin.octets())?;
        writer.write_u16::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveIpv4ExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<NonTransitiveIpv4ExtendedCommunityWritingError>
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
    ) -> Result<(), NonTransitiveIpv4ExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        let (sub_type, global_admin, local_admin) = match self {
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_u8(sub_type)?;
        writer.write_all(&global_admin.octets())?;
        writer.write_u16::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveFourOctetExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<TransitiveFourOctetExtendedCommunityWritingError>
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
    ) -> Result<(), TransitiveFourOctetExtendedCommunityWritingError>
    where
        Self: Sized,
    {
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
        writer.write_u8(sub_type)?;
        writer.write_u32::<NetworkEndian>(*global_admin)?;
        writer.write_u16::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveFourOctetExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<NonTransitiveFourOctetExtendedCommunityWritingError>
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
    ) -> Result<(), NonTransitiveFourOctetExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        let (sub_type, global_admin, local_admin) = match self {
            Self::Unassigned {
                sub_type,
                global_admin,
                local_admin,
            } => (*sub_type, global_admin, local_admin),
        };
        writer.write_u8(sub_type)?;
        writer.write_u32::<NetworkEndian>(*global_admin)?;
        writer.write_u16::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveOpaqueExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<TransitiveOpaqueExtendedCommunityWritingError>
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
    ) -> Result<(), TransitiveOpaqueExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        match self {
            Self::Unassigned { sub_type, value } => {
                writer.write_u8(*sub_type)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveOpaqueExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<NonTransitiveOpaqueExtendedCommunityWritingError>
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
    ) -> Result<(), NonTransitiveOpaqueExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        match self {
            Self::Unassigned { sub_type, value } => {
                writer.write_u8(*sub_type)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ExperimentalExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<ExperimentalExtendedCommunityWritingError> for ExperimentalExtendedCommunity {
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExperimentalExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        writer.write_u8(self.sub_type())?;
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum UnknownExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<UnknownExtendedCommunityWritingError> for UnknownExtendedCommunity {
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), UnknownExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        writer.write_u8(self.sub_type())?;
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TransitiveIpv6ExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<TransitiveIpv6ExtendedCommunityWritingError> for TransitiveIpv6ExtendedCommunity {
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
        writer.write_u8(sub_type)?;
        writer.write_all(&global_admin.octets())?;
        writer.write_u16::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NonTransitiveIpv6ExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<NonTransitiveIpv6ExtendedCommunityWritingError>
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
        writer.write_u8(sub_type)?;
        writer.write_all(&global_admin.octets())?;
        writer.write_u16::<NetworkEndian>(*local_admin)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum UnknownExtendedCommunityIpv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<UnknownExtendedCommunityIpv6WritingError> for UnknownExtendedCommunityIpv6 {
    // 1-octet subtype + 18-octets value
    const BASE_LENGTH: usize = 19;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), UnknownExtendedCommunityIpv6WritingError> {
        writer.write_u8(self.sub_type())?;
        writer.write_all(self.value())?;
        Ok(())
    }
}
