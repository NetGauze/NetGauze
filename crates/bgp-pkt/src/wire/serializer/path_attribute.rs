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

//! Serializer for BGP Path Attributes

use crate::bgp_ls::{BgpLsNlri, BgpLsVpnNlri};
use crate::wire::serializer::bgp_ls::BgpLsWritingError;
use crate::{
    iana::{AigpAttributeType, PathAttributeType},
    nlri::*,
    path_attribute::*,
    wire::{
        serializer::{community::*, nlri::*, IpAddrWritingError},
        ACCUMULATED_IGP_METRIC,
    },
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_iana::address_family::AddressType;
use netgauze_iana::address_family::AddressType::{BgpLs, BgpLsVpn};
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;
use std::net::IpAddr;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum PathAttributeWritingError {
    StdIOError(#[from_std_io_error] String),
    OriginError(#[from] OriginWritingError),
    AsPathError(#[from] AsPathWritingError),
    NextHopError(#[from] NextHopWritingError),
    MultiExitDiscriminatorError(#[from] MultiExitDiscriminatorWritingError),
    LocalPreferenceError(#[from] LocalPreferenceWritingError),
    AtomicAggregateError(#[from] AtomicAggregateWritingError),
    AggregatorError(#[from] AggregatorWritingError),
    CommunitiesError(#[from] CommunitiesWritingError),
    ExtendedCommunitiesError(#[from] ExtendedCommunitiesWritingError),
    ExtendedCommunitiesIpv6Error(#[from] ExtendedCommunitiesIpv6WritingError),
    LargeCommunitiesError(#[from] LargeCommunitiesWritingError),
    OriginatorError(#[from] OriginatorWritingError),
    ClusterListError(#[from] ClusterListWritingError),
    MpReachError(#[from] MpReachWritingError),
    MpUnreachError(#[from] MpUnreachWritingError),
    BgpLsError(#[from] BgpLsWritingError),
    OnlyToCustomerError(#[from] OnlyToCustomerWritingError),
    AigpError(#[from] AigpWritingError),
    UnknownAttributeError(#[from] UnknownAttributeWritingError),
}

impl WritablePdu<PathAttributeWritingError> for PathAttribute {
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        let value_len = match self.value() {
            PathAttributeValue::Origin(value) => value.len(self.extended_length()),
            PathAttributeValue::AsPath(value) => value.len(self.extended_length()),
            PathAttributeValue::As4Path(value) => value.len(self.extended_length()),
            PathAttributeValue::NextHop(value) => value.len(self.extended_length()),
            PathAttributeValue::MultiExitDiscriminator(value) => value.len(self.extended_length()),
            PathAttributeValue::LocalPreference(value) => value.len(self.extended_length()),
            PathAttributeValue::AtomicAggregate(value) => value.len(self.extended_length()),
            PathAttributeValue::Aggregator(value) => value.len(self.extended_length()),
            PathAttributeValue::Communities(value) => value.len(self.extended_length()),
            PathAttributeValue::ExtendedCommunities(value) => value.len(self.extended_length()),
            PathAttributeValue::ExtendedCommunitiesIpv6(value) => value.len(self.extended_length()),
            PathAttributeValue::LargeCommunities(value) => value.len(self.extended_length()),
            PathAttributeValue::Originator(value) => value.len(self.extended_length()),
            PathAttributeValue::ClusterList(value) => value.len(self.extended_length()),
            PathAttributeValue::MpReach(value) => value.len(self.extended_length()),
            PathAttributeValue::MpUnreach(value) => value.len(self.extended_length()),
            PathAttributeValue::BgpLs(value) => value.len(self.extended_length()),
            PathAttributeValue::OnlyToCustomer(value) => value.len(self.extended_length()),
            PathAttributeValue::Aigp(value) => value.len(self.extended_length()),
            PathAttributeValue::UnknownAttribute(value) => value.len(self.extended_length()) - 1,
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), PathAttributeWritingError> {
        let mut attributes = 0x00u8;
        if self.optional() {
            attributes |= 0b10000000;
        }
        if self.transitive() {
            attributes |= 0b01000000;
        }
        if self.partial() {
            attributes |= 0b00100000;
        }
        if self.extended_length() {
            attributes |= 0b00010000;
        }
        writer.write_u8(attributes)?;
        match self.value() {
            PathAttributeValue::Origin(value) => {
                writer.write_u8(PathAttributeType::Origin.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::AsPath(value) => {
                writer.write_u8(PathAttributeType::AsPath.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::As4Path(value) => {
                writer.write_u8(PathAttributeType::As4Path.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::NextHop(value) => {
                writer.write_u8(PathAttributeType::NextHop.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::MultiExitDiscriminator(value) => {
                writer.write_u8(PathAttributeType::MultiExitDiscriminator.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::LocalPreference(value) => {
                writer.write_u8(PathAttributeType::LocalPreference.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::AtomicAggregate(value) => {
                writer.write_u8(PathAttributeType::AtomicAggregate.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::Aggregator(value) => {
                writer.write_u8(PathAttributeType::Aggregator.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::Communities(value) => {
                writer.write_u8(PathAttributeType::Communities.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::ExtendedCommunities(value) => {
                writer.write_u8(PathAttributeType::ExtendedCommunities.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::ExtendedCommunitiesIpv6(value) => {
                writer.write_u8(PathAttributeType::ExtendedCommunitiesIpv6.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::LargeCommunities(value) => {
                writer.write_u8(PathAttributeType::LargeCommunities.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::Originator(value) => {
                writer.write_u8(PathAttributeType::OriginatorId.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::ClusterList(value) => {
                writer.write_u8(PathAttributeType::ClusterList.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::MpReach(value) => {
                writer.write_u8(PathAttributeType::MpReachNlri.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::MpUnreach(value) => {
                writer.write_u8(PathAttributeType::MpUnreachNlri.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::BgpLs(value) => {
                writer.write_u8(PathAttributeType::BgpLsAttribute.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::OnlyToCustomer(value) => {
                writer.write_u8(PathAttributeType::OnlyToCustomer.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::Aigp(value) => {
                writer.write_u8(PathAttributeType::AccumulatedIgp.into())?;
                value.write(writer, self.extended_length())?;
            }
            PathAttributeValue::UnknownAttribute(value) => {
                value.write(writer, self.extended_length())?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum OriginWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, OriginWritingError> for Origin {
    // One octet length (if extended is not enabled) and second for the origin value
    const BASE_LENGTH: usize = 2;

    fn len(&self, extended_length: bool) -> usize {
        if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), OriginWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_u8((*self) as u8)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum AsPathWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<AsPathWritingError> for As2PathSegment {
    // one octet length + one more for segment type
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        // Multiply self.as_numbers().len() by 2 since each is two octets
        Self::BASE_LENGTH + (self.as_numbers().len() * 2)
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), AsPathWritingError> {
        writer.write_u8(self.segment_type() as u8)?;
        writer.write_u8(self.as_numbers().len() as u8)?;
        for as_num in self.as_numbers() {
            writer.write_u16::<NetworkEndian>(*as_num)?;
        }
        Ok(())
    }
}

impl WritablePdu<AsPathWritingError> for As4PathSegment {
    // one octet length + one more for segment type
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        // Multiply self.as_numbers().len() by 4 since each is four octets
        Self::BASE_LENGTH + (self.as_numbers().len() * 4)
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), AsPathWritingError> {
        writer.write_u8(self.segment_type() as u8)?;
        writer.write_u8(self.as_numbers().len() as u8)?;
        for as_num in self.as_numbers() {
            writer.write_u32::<NetworkEndian>(*as_num)?;
        }
        Ok(())
    }
}

impl WritablePduWithOneInput<bool, AsPathWritingError> for AsPath {
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + usize::from(extended_length);

        let segment_len = match self {
            Self::As2PathSegments(segments) => {
                segments.iter().map(|segment| segment.len()).sum::<usize>()
            }
            Self::As4PathSegments(segments) => {
                segments.iter().map(|segment| segment.len()).sum::<usize>()
            }
        };
        base + segment_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), AsPathWritingError> {
        write_length(self, extended_length, writer)?;
        match self {
            Self::As2PathSegments(segments) => {
                for segment in segments {
                    segment.write(writer)?;
                }
            }
            Self::As4PathSegments(segments) => {
                for segment in segments {
                    segment.write(writer)?;
                }
            }
        }
        Ok(())
    }
}

impl WritablePduWithOneInput<bool, AsPathWritingError> for As4Path {
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + usize::from(extended_length);
        let segment_len = self
            .segments()
            .iter()
            .map(|segment| segment.len())
            .sum::<usize>();
        base + segment_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), AsPathWritingError> {
        write_length(self, extended_length, writer)?;
        for segment in self.segments() {
            segment.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NextHopWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, NextHopWritingError> for NextHop {
    // One octet length (if extended is not enabled) and 4 for ipv4
    const BASE_LENGTH: usize = 5;

    fn len(&self, extended_length: bool) -> usize {
        if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), NextHopWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_all(&self.next_hop().octets())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MultiExitDiscriminatorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, MultiExitDiscriminatorWritingError> for MultiExitDiscriminator {
    // One octet length (if extended is not enabled) and 4 for u32 metric
    const BASE_LENGTH: usize = 5;

    fn len(&self, extended_length: bool) -> usize {
        if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), MultiExitDiscriminatorWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_u32::<NetworkEndian>(self.metric())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum LocalPreferenceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, LocalPreferenceWritingError> for LocalPreference {
    // One octet length (if extended is not enabled) and 4 for u32 local pref
    const BASE_LENGTH: usize = 5;

    fn len(&self, extended_length: bool) -> usize {
        if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), LocalPreferenceWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_u32::<NetworkEndian>(self.metric())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum AtomicAggregateWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, AtomicAggregateWritingError> for AtomicAggregate {
    // One octet length (if extended is not enabled)
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), AtomicAggregateWritingError> {
        write_length(self, extended_length, writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum AggregatorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, AggregatorWritingError> for As2Aggregator {
    // one length (not extended) + two octets as2 + 4 more for ipv4
    const BASE_LENGTH: usize = 7;

    fn len(&self, extended_length: bool) -> usize {
        Self::BASE_LENGTH + usize::from(extended_length)
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), AggregatorWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_u16::<NetworkEndian>(*self.asn())?;
        writer.write_all(&self.origin().octets())?;
        Ok(())
    }
}

impl WritablePduWithOneInput<bool, AggregatorWritingError> for As4Aggregator {
    // one length (not extended) + four octets as4 + 4 more for ipv4
    const BASE_LENGTH: usize = 9;

    fn len(&self, extended_length: bool) -> usize {
        Self::BASE_LENGTH + usize::from(extended_length)
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), AggregatorWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_u32::<NetworkEndian>(*self.asn())?;
        writer.write_all(&self.origin().octets())?;
        Ok(())
    }
}

impl WritablePduWithOneInput<bool, AggregatorWritingError> for Aggregator {
    const BASE_LENGTH: usize = 0;

    fn len(&self, extended_length: bool) -> usize {
        match self {
            Self::As2Aggregator(agg) => agg.len(extended_length),
            Self::As4Aggregator(agg) => agg.len(extended_length),
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), AggregatorWritingError> {
        match self {
            Self::As2Aggregator(agg) => agg.write(writer, extended_length),
            Self::As4Aggregator(agg) => agg.write(writer, extended_length),
        }
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum OriginatorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, OriginatorWritingError> for Originator {
    // 4-octet for BGP ID
    const BASE_LENGTH: usize = 5;

    fn len(&self, extended_length: bool) -> usize {
        if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), OriginatorWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_all(&self.id().octets())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ClusterIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<ClusterIdWritingError> for ClusterId {
    // 4-octet for BGP ID
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), ClusterIdWritingError> {
        writer.write_all(&self.id().octets())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ClusterListWritingError {
    StdIOError(#[from_std_io_error] String),
    ClusterIdError(#[from] ClusterIdWritingError),
}

impl WritablePduWithOneInput<bool, ClusterListWritingError> for ClusterList {
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let len = self.cluster_list().iter().map(|x| x.len()).sum::<usize>();
        len + if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), ClusterListWritingError> {
        write_length(self, extended_length, writer)?;
        for cluster_id in self.cluster_list() {
            cluster_id.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum UnknownAttributeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, UnknownAttributeWritingError> for UnknownAttribute {
    // One octet length (if extended is not enabled) and one octet for code
    const BASE_LENGTH: usize = 2;

    fn len(&self, extended_length: bool) -> usize {
        Self::BASE_LENGTH + self.value().len() + usize::from(extended_length)
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), UnknownAttributeWritingError> {
        writer.write_u8(self.code())?;
        let len = self.len(extended_length) - Self::BASE_LENGTH;
        if extended_length || len > u8::MAX.into() {
            writer.write_u16::<NetworkEndian>((len - 1) as u16)?;
        } else {
            writer.write_u8(len as u8)?;
        }
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum CommunitiesWritingError {
    StdIOError(#[from_std_io_error] String),
    CommunityError(#[from] CommunityWritingError),
}

impl WritablePduWithOneInput<bool, CommunitiesWritingError> for Communities {
    // One octet length (if extended is not enabled)
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + usize::from(extended_length);
        let value_len = self.communities().iter().map(|x| x.len()).sum::<usize>();
        base + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), CommunitiesWritingError> {
        write_length(self, extended_length, writer)?;
        for community in self.communities() {
            community.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ExtendedCommunitiesWritingError {
    StdIOError(#[from_std_io_error] String),
    ExtendedCommunityError(#[from] ExtendedCommunityWritingError),
}

impl WritablePduWithOneInput<bool, ExtendedCommunitiesWritingError> for ExtendedCommunities {
    // One octet length (if extended is not enabled)
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + usize::from(extended_length);
        let value_len = self.communities().iter().map(|x| x.len()).sum::<usize>();
        base + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), ExtendedCommunitiesWritingError> {
        write_length(self, extended_length, writer)?;
        for community in self.communities() {
            community.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ExtendedCommunitiesIpv6WritingError {
    StdIOError(#[from_std_io_error] String),
    ExtendedCommunityIpv6Error(#[from] ExtendedCommunityIpv6WritingError),
}

impl WritablePduWithOneInput<bool, ExtendedCommunitiesIpv6WritingError>
    for ExtendedCommunitiesIpv6
{
    // One octet length (if extended is not enabled)
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + usize::from(extended_length);
        let value_len = self.communities().iter().map(|x| x.len()).sum::<usize>();
        base + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), ExtendedCommunitiesIpv6WritingError> {
        write_length(self, extended_length, writer)?;
        for community in self.communities() {
            community.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum LargeCommunitiesWritingError {
    StdIOError(#[from_std_io_error] String),
    LargeCommunityError(#[from] LargeCommunityWritingError),
}

impl WritablePduWithOneInput<bool, LargeCommunitiesWritingError> for LargeCommunities {
    // One octet length (if extended is not enabled)
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + usize::from(extended_length);
        let value_len = self.communities().iter().map(|x| x.len()).sum::<usize>();
        base + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), LargeCommunitiesWritingError> {
        write_length(self, extended_length, writer)?;
        for community in self.communities() {
            community.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MpReachWritingError {
    StdIOError(#[from_std_io_error] String),
    IpAddrError(#[from] IpAddrWritingError),
    Ipv4UnicastAddressError(#[from] Ipv4UnicastAddressWritingError),
    Ipv4MulticastAddressError(#[from] Ipv4MulticastAddressWritingError),
    Ipv6UnicastAddressError(#[from] Ipv6UnicastAddressWritingError),
    Ipv6MulticastAddressError(#[from] Ipv6MulticastAddressWritingError),
    Ipv4MplsVpnUnicastAddressError(#[from] Ipv4MplsVpnUnicastAddressWritingError),
    Ipv6MplsVpnUnicastAddressError(#[from] Ipv6MplsVpnUnicastAddressWritingError),
    Ipv4NlriMplsLabelsAddressError(#[from] Ipv4NlriMplsLabelsAddressWritingError),
    Ipv6NlriMplsLabelsAddressError(#[from] Ipv6NlriMplsLabelsAddressWritingError),
    L2EvpnAddressError(#[from] L2EvpnAddressWritingError),
    LabeledNextHopError(#[from] LabeledNextHopWritingError),
    RouteTargetMembershipAddressError(#[from] RouteTargetMembershipAddressWritingError),
    BgpLsNlriWritingError(#[from] BgpLsWritingError),
    RouteDistinguisherWritingError(#[from] RouteDistinguisherWritingError),
}

impl WritablePduWithOneInput<bool, MpReachWritingError> for MpReach {
    // 2-octets AFI, 1-octet SAFI, and 1-octet reserved , 1-octet len
    const BASE_LENGTH: usize = 5;

    fn len(&self, extended_length: bool) -> usize {
        // Multiply self.as_numbers().len() by 2 since each is two octets
        let payload_len: usize = match self {
            Self::Ipv4Unicast {
                next_hop,
                next_hop_local,
                nlri,
            } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                let next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN as usize
                } else {
                    IPV6_LEN as usize
                };
                let local_len = if next_hop_local.is_some() {
                    IPV6_LEN as usize
                } else {
                    0
                };
                // One octet for the prefix length
                1 + next_hop_len + local_len + nlri_len
            }
            Self::Ipv4Multicast {
                next_hop,
                next_hop_local,
                nlri,
            } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                let mut next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN
                } else {
                    IPV6_LEN
                };
                if next_hop_local.is_some() {
                    next_hop_len += IPV6_LEN
                }
                next_hop_len as usize + 1 + nlri_len
            }
            Self::Ipv4NlriMplsLabels {
                next_hop,
                next_hop_local,
                nlri,
            } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                let next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN as usize
                } else {
                    IPV6_LEN as usize
                };
                let local_len = if next_hop_local.is_some() {
                    IPV6_LEN as usize
                } else {
                    0
                };
                // One octet for the prefix length
                1 + next_hop_len + local_len + nlri_len
            }
            Self::Ipv4MplsVpnUnicast { next_hop, nlri } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                next_hop.len() + nlri_len
            }
            Self::Ipv6Unicast {
                next_hop_global: _,
                next_hop_local,
                nlri,
            } => {
                let local_len: usize = next_hop_local.map(|_| IPV6_LEN as usize).unwrap_or(0);
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                IPV6_LEN as usize + 1 + local_len + nlri_len
            }
            Self::Ipv6Multicast {
                next_hop_global: _,
                next_hop_local,
                nlri,
            } => {
                let local_len: usize = next_hop_local.map(|_| IPV6_LEN as usize).unwrap_or(0);
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                IPV6_LEN as usize + 1 + local_len + nlri_len
            }
            Self::Ipv6NlriMplsLabels { next_hop: _, nlri } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                IPV6_LEN as usize + 1 + nlri_len
            }
            Self::Ipv6MplsVpnUnicast { next_hop, nlri } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                next_hop.len() + nlri_len
            }
            Self::L2Evpn { next_hop, nlri } => {
                let next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN as usize
                } else {
                    IPV6_LEN as usize
                };
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                next_hop_len + 1 + nlri_len
            }
            Self::RouteTargetMembership { next_hop, nlri } => {
                let next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN as usize
                } else {
                    IPV6_LEN as usize
                };
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                next_hop_len + 1 + nlri_len
            }
            Self::BgpLs { nlri, next_hop } => {
                let next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN as usize
                } else {
                    IPV6_LEN as usize
                };

                let ls_nlri_len: usize = nlri.iter().map(&BgpLsNlri::len).sum();

                next_hop_len + 1 /* next-hop prefix length */
                    + ls_nlri_len
            }
            Self::BgpLsVpn { nlri, next_hop } => {
                let next_hop_len = next_hop.len();

                let ls_nlri_len: usize = nlri.iter().map(&BgpLsVpnNlri::len).sum();

                next_hop_len + ls_nlri_len
            }
            Self::Unknown {
                afi: _,
                safi: _,
                value,
            } => value.len(),
        };
        Self::BASE_LENGTH + usize::from(extended_length) + payload_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), MpReachWritingError> {
        write_length(self, extended_length, writer)?;
        match self {
            Self::Ipv4Unicast {
                next_hop,
                next_hop_local,
                nlri,
            } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4UnicastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4UnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                let next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN
                } else {
                    IPV6_LEN
                };
                let local_len = if next_hop_local.is_some() {
                    IPV6_LEN
                } else {
                    0
                };
                writer.write_u8(next_hop_len + local_len)?;
                match next_hop {
                    IpAddr::V4(addr) => {
                        writer.write_all(&addr.octets())?;
                    }
                    IpAddr::V6(addr) => {
                        writer.write_all(&addr.octets())?;
                    }
                }
                if let Some(addr) = next_hop_local {
                    writer.write_all(&addr.octets())?;
                }
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4Multicast {
                next_hop,
                next_hop_local,
                nlri,
            } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4MulticastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4MulticastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                let mut next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN
                } else {
                    IPV6_LEN
                };
                if next_hop_local.is_some() {
                    next_hop_len += IPV6_LEN
                }
                writer.write_u8(next_hop_len)?;
                match next_hop {
                    IpAddr::V4(addr) => {
                        writer.write_all(&addr.octets())?;
                    }
                    IpAddr::V6(addr) => {
                        writer.write_all(&addr.octets())?;
                    }
                }
                if let Some(addr) = next_hop_local {
                    writer.write_all(&addr.octets())?;
                }
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4NlriMplsLabels {
                next_hop,
                next_hop_local,
                nlri,
            } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4NlriMplsLabelsAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv4NlriMplsLabelsAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                let next_hop_len = if next_hop.is_ipv4() {
                    IPV4_LEN
                } else {
                    IPV6_LEN
                };
                let local_len = if next_hop_local.is_some() {
                    IPV6_LEN
                } else {
                    0
                };
                writer.write_u8(next_hop_len + local_len)?;
                match next_hop {
                    IpAddr::V4(addr) => {
                        writer.write_all(&addr.octets())?;
                    }
                    IpAddr::V6(addr) => {
                        writer.write_all(&addr.octets())?;
                    }
                }
                if let Some(addr) = next_hop_local {
                    writer.write_all(&addr.octets())?;
                }
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4MplsVpnUnicast { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4MplsVpnUnicastAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv4MplsVpnUnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                next_hop.write(writer)?;
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6Unicast {
                next_hop_global,
                next_hop_local,
                nlri,
            } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6UnicastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6UnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                if let Some(local) = next_hop_local {
                    writer.write_u8(32)?;
                    writer.write_all(&next_hop_global.octets())?;
                    writer.write_all(&local.octets())?;
                } else {
                    writer.write_u8(16)?;
                    writer.write_all(&next_hop_global.octets())?;
                }
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6Multicast {
                next_hop_global,
                next_hop_local,
                nlri,
            } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6MulticastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6MulticastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                if let Some(local) = next_hop_local {
                    writer.write_u8(32)?;
                    writer.write_all(&next_hop_global.octets())?;
                    writer.write_all(&local.octets())?;
                } else {
                    writer.write_u8(16)?;
                    writer.write_all(&next_hop_global.octets())?;
                }
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6NlriMplsLabels { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6NlriMplsLabelsAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv6NlriMplsLabelsAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                next_hop.write(writer)?;
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6MplsVpnUnicast { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6MplsVpnUnicastAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv6MplsVpnUnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                next_hop.write(writer)?;
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::L2Evpn { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    L2EvpnAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    L2EvpnAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                next_hop.write(writer)?;
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::RouteTargetMembership { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    RouteTargetMembershipAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    RouteTargetMembershipAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                next_hop.write(writer)?;
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::BgpLs { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(AddressType::BgpLs.address_family().into())?;
                writer.write_u8(AddressType::BgpLs.subsequent_address_family().into())?;
                next_hop.write(writer)?;

                writer.write_u8(0)?;

                for nlri in nlri {
                    nlri.write(writer)?;
                }
            }
            Self::BgpLsVpn { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(AddressType::BgpLs.address_family().into())?;
                writer.write_u8(AddressType::BgpLsVpn.subsequent_address_family().into())?;

                // The RD of the next-hop is set to all zeros (https://www.rfc-editor.org/rfc/rfc7752#section-3.4)
                writer.write_u8((next_hop.len() - 1) as u8 /* len field */)?;
                writer.write_all(&[0u8; 8])?;
                match next_hop.next_hop() {
                    IpAddr::V4(ip) => writer.write(&ip.octets())?,
                    IpAddr::V6(ip) => writer.write(&ip.octets())?,
                };

                writer.write_u8(0)?;

                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Unknown { afi, safi, value } => {
                writer.write_u16::<NetworkEndian>(*afi as u16)?;
                writer.write_u8(*safi as u8)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MpUnreachWritingError {
    StdIOError(#[from_std_io_error] String),
    Ipv4UnicastAddressError(#[from] Ipv4UnicastAddressWritingError),
    Ipv4MulticastAddressError(#[from] Ipv4MulticastAddressWritingError),
    Ipv4NlriMplsLabelsAddressError(#[from] Ipv4NlriMplsLabelsAddressWritingError),
    Ipv4MplsVpnUnicastError(#[from] Ipv4MplsVpnUnicastAddressWritingError),
    Ipv6UnicastAddressError(#[from] Ipv6UnicastAddressWritingError),
    Ipv6MulticastAddressError(#[from] Ipv6MulticastAddressWritingError),
    Ipv6NlriMplsLabelsAddressError(#[from] Ipv6NlriMplsLabelsAddressWritingError),
    Ipv6MplsVpnUnicastAddressError(#[from] Ipv6MplsVpnUnicastAddressWritingError),
    L2EvpnAddressError(#[from] L2EvpnAddressWritingError),
    RouteTargetMembershipAddressError(#[from] RouteTargetMembershipAddressWritingError),
    BgpLsError(#[from] BgpLsWritingError),
}

impl WritablePduWithOneInput<bool, MpUnreachWritingError> for MpUnreach {
    // 1 len, 2-octets AFI, 1-octet SAFI
    const BASE_LENGTH: usize = 4;

    fn len(&self, extended_length: bool) -> usize {
        // Multiply self.as_numbers().len() by 2 since each is two octets
        let payload_len: usize = match self {
            Self::Ipv4Unicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv4Multicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv4NlriMplsLabels { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv4MplsVpnUnicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv6Unicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv6Multicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv6NlriMplsLabels { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv6MplsVpnUnicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::L2Evpn { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::RouteTargetMembership { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::BgpLs { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::BgpLsVpn { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Unknown {
                afi: _,
                safi: _,
                nlri,
            } => nlri.len(),
        };
        Self::BASE_LENGTH + usize::from(extended_length) + payload_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), MpUnreachWritingError> {
        write_length(self, extended_length, writer)?;
        match self {
            Self::Ipv4Unicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4UnicastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4UnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4Multicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4MulticastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4MulticastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4NlriMplsLabels { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4NlriMplsLabelsAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv4NlriMplsLabelsAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4MplsVpnUnicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4MplsVpnUnicastAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv4MplsVpnUnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6Unicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6UnicastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6UnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6Multicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6MulticastAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6MulticastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6NlriMplsLabels { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6NlriMplsLabelsAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv6NlriMplsLabelsAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6MplsVpnUnicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6MplsVpnUnicastAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    Ipv6MplsVpnUnicastAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::L2Evpn { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    L2EvpnAddress::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    L2EvpnAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::RouteTargetMembership { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    RouteTargetMembershipAddress::address_type()
                        .address_family()
                        .into(),
                )?;
                writer.write_u8(
                    RouteTargetMembershipAddress::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::BgpLs { nlri } => {
                writer.write_u16::<NetworkEndian>(BgpLs.address_family().into())?;
                writer.write_u8(BgpLs.subsequent_address_family().into())?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::BgpLsVpn { nlri } => {
                writer.write_u16::<NetworkEndian>(BgpLsVpn.address_family().into())?;
                writer.write_u8(BgpLsVpn.subsequent_address_family().into())?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Unknown { afi, safi, nlri } => {
                writer.write_u16::<NetworkEndian>(*afi as u16)?;
                writer.write_u8(*safi as u8)?;
                writer.write_all(nlri)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum OnlyToCustomerWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, OnlyToCustomerWritingError> for OnlyToCustomer {
    // 1-octet length + 4-octets for ASN
    const BASE_LENGTH: usize = 5;

    fn len(&self, extended_length: bool) -> usize {
        if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), OnlyToCustomerWritingError> {
        write_length(self, extended_length, writer)?;
        writer.write_u32::<NetworkEndian>(self.asn())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum AigpWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePduWithOneInput<bool, AigpWritingError> for Aigp {
    // 1-octet length + 1-octet for type + 2 octet for length
    const BASE_LENGTH: usize = 4;

    fn len(&self, extended_length: bool) -> usize {
        let base = if extended_length {
            Self::BASE_LENGTH + 1
        } else {
            Self::BASE_LENGTH
        };
        base + match self {
            Self::AccumulatedIgpMetric(_) => 8,
        }
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), AigpWritingError> {
        write_length(self, extended_length, writer)?;
        match self {
            Self::AccumulatedIgpMetric(metric) => {
                writer.write_u8(AigpAttributeType::AccumulatedIgpMetric as u8)?;
                writer.write_u16::<NetworkEndian>(ACCUMULATED_IGP_METRIC)?;
                writer.write_u64::<NetworkEndian>(*metric)?;
            }
        }
        Ok(())
    }
}

// TODO restore original visibility
#[inline]
pub(crate) fn write_length<T: Sized + WritablePduWithOneInput<bool, E>, E, W: std::io::Write>(
    attribute: &T,
    extended_length: bool,
    writer: &mut W,
) -> Result<(), E>
where
    E: From<std::io::Error>,
{
    let len = attribute.len(extended_length) - 1;
    if extended_length || len > u8::MAX.into() {
        writer.write_u16::<NetworkEndian>((len - 1) as u16)?;
    } else {
        writer.write_u8(len as u8)?;
    }
    Ok(())
}
