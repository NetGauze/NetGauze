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

use crate::{
    iana::PathAttributeType,
    nlri::*,
    path_attribute::*,
    wire::serializer::{community::*, nlri::*},
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePDU, WritablePDUWithOneInput};
use netgauze_serde_macros::WritingError;

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
    UnknownAttributeError(#[from] UnknownAttributeWritingError),
}

impl WritablePDU<PathAttributeWritingError> for PathAttribute {
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

impl WritablePDUWithOneInput<bool, OriginWritingError> for Origin {
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

impl WritablePDU<AsPathWritingError> for As2PathSegment {
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

impl WritablePDU<AsPathWritingError> for As4PathSegment {
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

impl WritablePDUWithOneInput<bool, AsPathWritingError> for AsPath {
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

impl WritablePDUWithOneInput<bool, AsPathWritingError> for As4Path {
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

impl WritablePDUWithOneInput<bool, NextHopWritingError> for NextHop {
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

impl WritablePDUWithOneInput<bool, MultiExitDiscriminatorWritingError> for MultiExitDiscriminator {
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

impl WritablePDUWithOneInput<bool, LocalPreferenceWritingError> for LocalPreference {
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

impl WritablePDUWithOneInput<bool, AtomicAggregateWritingError> for AtomicAggregate {
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

impl WritablePDUWithOneInput<bool, AggregatorWritingError> for As2Aggregator {
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

impl WritablePDUWithOneInput<bool, AggregatorWritingError> for As4Aggregator {
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

impl WritablePDUWithOneInput<bool, AggregatorWritingError> for Aggregator {
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

impl WritablePDUWithOneInput<bool, OriginatorWritingError> for Originator {
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

impl WritablePDU<ClusterIdWritingError> for ClusterId {
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

impl WritablePDUWithOneInput<bool, ClusterListWritingError> for ClusterList {
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

impl WritablePDUWithOneInput<bool, UnknownAttributeWritingError> for UnknownAttribute {
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

impl WritablePDUWithOneInput<bool, CommunitiesWritingError> for Communities {
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

impl WritablePDUWithOneInput<bool, ExtendedCommunitiesWritingError> for ExtendedCommunities {
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

impl WritablePDUWithOneInput<bool, ExtendedCommunitiesIpv6WritingError>
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

impl WritablePDUWithOneInput<bool, LargeCommunitiesWritingError> for LargeCommunities {
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
    Ipv4UnicastError(#[from] Ipv4UnicastWritingError),
    Ipv4MulticastError(#[from] Ipv4MulticastWritingError),
    Ipv6UnicastError(#[from] Ipv6UnicastWritingError),
    Ipv6MulticastError(#[from] Ipv6MulticastWritingError),
    Ipv4MplsVpnUnicastError(#[from] Ipv4MplsVpnUnicastWritingError),
    Ipv6MplsVpnUnicastError(#[from] Ipv6MplsVpnUnicastWritingError),
    LabeledNextHopError(#[from] LabeledNextHopWritingError),
}

impl WritablePDUWithOneInput<bool, MpReachWritingError> for MpReach {
    // 2-octets AFI, 1-octet SAFI, and 1-octet reserved , 1-octet len
    const BASE_LENGTH: usize = 5;

    fn len(&self, extended_length: bool) -> usize {
        // Multiply self.as_numbers().len() by 2 since each is two octets
        let payload_len: usize = match self {
            Self::Ipv4Unicast { next_hop: _, nlri } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                IPV4_LEN as usize + 1 + nlri_len
            }
            Self::Ipv4Multicast { next_hop: _, nlri } => {
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                IPV4_LEN as usize + 1 + nlri_len
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
            Self::Ipv6MplsVpnUnicast {
                next_hop_global,
                next_hop_local,
                nlri,
            } => {
                let local_len: usize = next_hop_local.map(|x| x.len()).unwrap_or(0);
                let nlri_len: usize = nlri.iter().map(|x| x.len()).sum();
                next_hop_global.len() + local_len + nlri_len
            }
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
            Self::Ipv4Unicast { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4Unicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4Unicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                writer.write_u8(IPV4_LEN)?;
                writer.write_all(&next_hop.octets())?;
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4Multicast { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4Multicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4Multicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                writer.write_u8(IPV4_LEN)?;
                writer.write_all(&next_hop.octets())?;
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4MplsVpnUnicast { next_hop, nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4MplsVpnUnicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4MplsVpnUnicast::address_type()
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
                    Ipv6Unicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6Unicast::address_type()
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
                    Ipv6Multicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6Multicast::address_type()
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
            Self::Ipv6MplsVpnUnicast {
                next_hop_global,
                next_hop_local,
                nlri,
            } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6MplsVpnUnicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6MplsVpnUnicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                if let Some(local) = next_hop_local {
                    next_hop_global.write(writer)?;
                    local.write(writer)?;
                } else {
                    next_hop_global.write(writer)?;
                }
                writer.write_u8(0)?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MpUnreachWritingError {
    StdIOError(#[from_std_io_error] String),
    Ipv4UnicastError(#[from] Ipv4UnicastWritingError),
    Ipv4MulticastError(#[from] Ipv4MulticastWritingError),
    Ipv4MplsVpnUnicastError(#[from] Ipv4MplsVpnUnicastWritingError),
    Ipv6UnicastError(#[from] Ipv6UnicastWritingError),
    Ipv6MulticastError(#[from] Ipv6MulticastWritingError),
    Ipv6MplsVpnUnicastError(#[from] Ipv6MplsVpnUnicastWritingError),
}

impl WritablePDUWithOneInput<bool, MpUnreachWritingError> for MpUnreach {
    // 1 len, 2-octets AFI, 1-octet SAFI
    const BASE_LENGTH: usize = 4;

    fn len(&self, extended_length: bool) -> usize {
        // Multiply self.as_numbers().len() by 2 since each is two octets
        let payload_len: usize = match self {
            Self::Ipv4Unicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv4Multicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv4MplsVpnUnicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv6Unicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv6Multicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
            Self::Ipv6MplsVpnUnicast { nlri } => nlri.iter().map(|x| x.len()).sum(),
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
                    Ipv4Unicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4Unicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4Multicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4Multicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4Multicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv4MplsVpnUnicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv4MplsVpnUnicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv4MplsVpnUnicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6Unicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6Unicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6Unicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6Multicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6Multicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6Multicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
            Self::Ipv6MplsVpnUnicast { nlri } => {
                writer.write_u16::<NetworkEndian>(
                    Ipv6MplsVpnUnicast::address_type().address_family().into(),
                )?;
                writer.write_u8(
                    Ipv6MplsVpnUnicast::address_type()
                        .subsequent_address_family()
                        .into(),
                )?;
                for nlri in nlri {
                    nlri.write(writer)?
                }
            }
        }
        Ok(())
    }
}

#[inline]
fn write_length<T: Sized + WritablePDUWithOneInput<bool, E>, E, W: std::io::Write>(
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
