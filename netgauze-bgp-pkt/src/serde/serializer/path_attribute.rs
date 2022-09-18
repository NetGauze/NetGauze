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
    path_attribute::{
        AS4Path, ASPath, Aggregator, As2Aggregator, As2PathSegment, As4Aggregator, As4PathSegment,
        AtomicAggregate, LocalPreference, MultiExitDiscriminator, NextHop, Origin, PathAttribute,
    },
    serde::serializer::update::BGPUpdateMessageWritingError,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePDU, WritablePDUWithOneInput};

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum PathAttributeWritingError {
    StdIOError(String),
    OriginError(OriginWritingError),
    AsPathError(AsPathWritingError),
    NextHopError(NextHopWritingError),
    MultiExitDiscriminatorError(MultiExitDiscriminatorWritingError),
    LocalPreferenceError(LocalPreferenceWritingError),
    AtomicAggregateError(AtomicAggregateWritingError),
    AggregatorError(AggregatorWritingError),
}

impl From<std::io::Error> for PathAttributeWritingError {
    fn from(err: std::io::Error) -> Self {
        PathAttributeWritingError::StdIOError(err.to_string())
    }
}

impl From<PathAttributeWritingError> for BGPUpdateMessageWritingError {
    fn from(value: PathAttributeWritingError) -> Self {
        BGPUpdateMessageWritingError::PathAttributeError(value)
    }
}

impl WritablePDU<PathAttributeWritingError> for PathAttribute {
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::Origin {
                extended_length,
                value,
            } => value.len(*extended_length),
            Self::ASPath {
                extended_length,
                value,
            } => value.len(*extended_length),
            Self::AS4Path {
                extended_length,
                value,
                ..
            } => value.len(*extended_length),
            Self::NextHop {
                extended_length,
                value,
            } => value.len(*extended_length),
            Self::MultiExitDiscriminator {
                extended_length,
                value,
            } => value.len(*extended_length),
            Self::LocalPreference {
                extended_length,
                value,
            } => value.len(*extended_length),
            Self::AtomicAggregate {
                extended_length,
                value,
            } => value.len(*extended_length),
            Self::Aggregator {
                extended_length,
                value,
                ..
            } => value.len(*extended_length),
            Self::UnknownAttribute { .. } => todo!(),
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
        match self {
            Self::Origin {
                extended_length,
                value,
            } => {
                writer.write_u8(PathAttributeType::Origin.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::ASPath {
                extended_length,
                value,
            } => {
                writer.write_u8(PathAttributeType::ASPath.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::AS4Path {
                extended_length,
                value,
                ..
            } => {
                writer.write_u8(PathAttributeType::AS4Path.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::NextHop {
                extended_length,
                value,
            } => {
                writer.write_u8(PathAttributeType::NextHop.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::MultiExitDiscriminator {
                extended_length,
                value,
            } => {
                writer.write_u8(PathAttributeType::MultiExitDiscriminator.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::LocalPreference {
                extended_length,
                value,
            } => {
                writer.write_u8(PathAttributeType::LocalPreference.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::AtomicAggregate {
                extended_length,
                value,
            } => {
                writer.write_u8(PathAttributeType::AtomicAggregate.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::Aggregator {
                extended_length,
                value,
                ..
            } => {
                writer.write_u8(PathAttributeType::Aggregator.into())?;
                value.write(writer, *extended_length)?;
            }
            Self::UnknownAttribute { .. } => todo!(),
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum OriginWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for OriginWritingError {
    fn from(err: std::io::Error) -> Self {
        OriginWritingError::StdIOError(err.to_string())
    }
}

impl From<OriginWritingError> for PathAttributeWritingError {
    fn from(value: OriginWritingError) -> Self {
        PathAttributeWritingError::OriginError(value)
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum AsPathWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for AsPathWritingError {
    fn from(err: std::io::Error) -> Self {
        AsPathWritingError::StdIOError(err.to_string())
    }
}

impl From<AsPathWritingError> for PathAttributeWritingError {
    fn from(value: AsPathWritingError) -> Self {
        PathAttributeWritingError::AsPathError(value)
    }
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

impl WritablePDUWithOneInput<bool, AsPathWritingError> for ASPath {
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + if extended_length { 1 } else { 0 };

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

impl WritablePDUWithOneInput<bool, AsPathWritingError> for AS4Path {
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let base = Self::BASE_LENGTH + if extended_length { 1 } else { 0 };
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum NextHopWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for NextHopWritingError {
    fn from(err: std::io::Error) -> Self {
        NextHopWritingError::StdIOError(err.to_string())
    }
}

impl From<NextHopWritingError> for PathAttributeWritingError {
    fn from(value: NextHopWritingError) -> Self {
        PathAttributeWritingError::NextHopError(value)
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MultiExitDiscriminatorWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for MultiExitDiscriminatorWritingError {
    fn from(err: std::io::Error) -> Self {
        MultiExitDiscriminatorWritingError::StdIOError(err.to_string())
    }
}

impl From<MultiExitDiscriminatorWritingError> for PathAttributeWritingError {
    fn from(value: MultiExitDiscriminatorWritingError) -> Self {
        PathAttributeWritingError::MultiExitDiscriminatorError(value)
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum LocalPreferenceWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for LocalPreferenceWritingError {
    fn from(err: std::io::Error) -> Self {
        LocalPreferenceWritingError::StdIOError(err.to_string())
    }
}

impl From<LocalPreferenceWritingError> for PathAttributeWritingError {
    fn from(value: LocalPreferenceWritingError) -> Self {
        PathAttributeWritingError::LocalPreferenceError(value)
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum AtomicAggregateWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for AtomicAggregateWritingError {
    fn from(err: std::io::Error) -> Self {
        AtomicAggregateWritingError::StdIOError(err.to_string())
    }
}

impl From<AtomicAggregateWritingError> for PathAttributeWritingError {
    fn from(value: AtomicAggregateWritingError) -> Self {
        PathAttributeWritingError::AtomicAggregateError(value)
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum AggregatorWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for AggregatorWritingError {
    fn from(err: std::io::Error) -> Self {
        AggregatorWritingError::StdIOError(err.to_string())
    }
}

impl From<AggregatorWritingError> for PathAttributeWritingError {
    fn from(value: AggregatorWritingError) -> Self {
        PathAttributeWritingError::AggregatorError(value)
    }
}

impl WritablePDUWithOneInput<bool, AggregatorWritingError> for As2Aggregator {
    // one length (not extended) + two octets as2 + 4 more for ipv4
    const BASE_LENGTH: usize = 7;

    fn len(&self, extended_length: bool) -> usize {
        Self::BASE_LENGTH + if extended_length { 1 } else { 0 }
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
        Self::BASE_LENGTH + if extended_length { 1 } else { 0 }
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
