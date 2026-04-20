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
// limitations under the License.Get the
// [netgauze_iana::address_family::AddressType] of a given NLRI

//! Deserializer for BGP Path Attributes

use crate::community::{Community, ExtendedCommunity, ExtendedCommunityIpv6, LargeCommunity};
use crate::iana::{AigpAttributeType, PathAttributeType, UndefinedPathAttributeType};
use crate::nlri::{
    BgpLsNlri, BgpLsVpnNlri, Ipv4MplsVpnUnicastAddress, Ipv4MulticastAddress,
    Ipv4NlriMplsLabelsAddress, Ipv4UnicastAddress, Ipv6MplsVpnUnicastAddress, Ipv6MulticastAddress,
    Ipv6NlriMplsLabelsAddress, Ipv6UnicastAddress, L2EvpnAddress, LabeledNextHop,
    RouteTargetMembershipAddress,
};
use crate::path_attribute::*;
use crate::wire::ACCUMULATED_IGP_METRIC;
use crate::wire::deserializer::BgpParsingContext;
use crate::wire::deserializer::community::*;
use crate::wire::deserializer::nlri::*;
use crate::wire::deserializer::path_attribute::{
    BgpLsAttributeParsingError, SegmentIdentifierParsingError,
};
use crate::wire::serializer::nlri::{IPV4_LEN, IPV6_LEN, IPV6_WITH_LINK_LOCAL_LEN};
use netgauze_iana::address_family::{AddressFamily, AddressType, SubsequentAddressFamily};
use netgauze_parse_utils::common::IpAddrParsingError;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::BytesReader;
use netgauze_parse_utils::traits::{
    ParseFrom, ParseFromWithOneInput, ParseFromWithThreeInputs, ParseFromWithTwoInputs,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const OPTIONAL_PATH_ATTRIBUTE_MASK: u8 = 0x80;
const TRANSITIVE_PATH_ATTRIBUTE_MASK: u8 = 0x40;
const PARTIAL_PATH_ATTRIBUTE_MASK: u8 = 0x20;
pub(crate) const EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK: u8 = 0x10;
pub(crate) const ORIGIN_LEN: u16 = 1;
pub(crate) const NEXT_HOP_LEN: u16 = 4;
pub(crate) const MULTI_EXIT_DISCRIMINATOR_LEN: u16 = 4;
pub(crate) const LOCAL_PREFERENCE_LEN: u16 = 4;
pub(crate) const ATOMIC_AGGREGATE_LEN: u16 = 0;
pub(crate) const AS2_AGGREGATOR_LEN: u16 = 6;
pub(crate) const AS4_AGGREGATOR_LEN: u16 = 8;

#[inline]
const fn check_length(attr_len: PathAttributeLength, expected: u16) -> bool {
    match attr_len {
        PathAttributeLength::U8(len) => len as u16 == expected,
        PathAttributeLength::U16(len) => len == expected,
    }
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum PathAttributeParsingError {
    #[error("Path attribute parsing error {0}")]
    Parse(#[from] ParseError),
    #[error("Path attribute error {0}")]
    OriginError(#[from] OriginParsingError),
    #[error("Path attribute error {0}")]
    AsPathError(#[from] AsPathParsingError),
    #[error("Path attribute error {0}")]
    NextHopError(#[from] NextHopParsingError),
    #[error("Path attribute error {0}")]
    MultiExitDiscriminatorError(#[from] MultiExitDiscriminatorParsingError),
    #[error("Path attribute error {0}")]
    LocalPreferenceError(#[from] LocalPreferenceParsingError),
    #[error("Path attribute error {0}")]
    AtomicAggregateError(#[from] AtomicAggregateParsingError),
    #[error("Path attribute error {0}")]
    AggregatorError(#[from] AggregatorParsingError),
    #[error("Path attribute error {0}")]
    CommunitiesError(#[from] CommunitiesParsingError),
    #[error("Path attribute error {0}")]
    ExtendedCommunitiesError(#[from] ExtendedCommunitiesParsingError),
    #[error("Path attribute error {0}")]
    ExtendedCommunitiesErrorIpv6(#[from] ExtendedCommunitiesIpv6ParsingError),
    #[error("Path attribute error {0}")]
    LargeCommunitiesError(#[from] LargeCommunitiesParsingError),
    #[error("Path attribute error {0}")]
    OriginatorError(#[from] OriginatorParsingError),
    #[error("Path attribute error {0}")]
    ClusterListError(#[from] ClusterListParsingError),
    #[error("Path attribute error {0}")]
    MpReachErrorError(#[from] MpReachParsingError),
    #[error("Path attribute error {0}")]
    MpUnreachErrorError(#[from] MpUnreachParsingError),
    #[error("Path attribute error {0}")]
    OnlyToCustomerError(#[from] OnlyToCustomerParsingError),
    #[error("Path attribute error {0}")]
    AigpError(#[from] AigpParsingError),
    #[error("Path attribute error {0}")]
    BgpLsError(#[from] BgpLsAttributeParsingError),
    #[error("Path attribute error {0}")]
    SegmentIdentifierParsingError(#[from] SegmentIdentifierParsingError),
    #[error("Path attribute error {0}")]
    UnknownAttributeError(#[from] UnknownAttributeParsingError),
    #[error("Path attribute {invalid_attribute} for path attribute {value:?} at offset {offset}")]
    InvalidPathAttribute {
        offset: usize,
        invalid_attribute: InvalidPathAttribute,
        value: Result<PathAttributeType, u8>,
    },
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for PathAttribute {
    type Error = PathAttributeParsingError;
    fn parse(cur: &mut BytesReader, ctx: &mut BgpParsingContext) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (asn4, multiple_labels, add_path_map) = (ctx.asn4, &ctx.multiple_labels, &ctx.add_path);
        let attributes = cur.read_u8()?;
        let code = cur.read_u8()?;
        let optional = attributes & OPTIONAL_PATH_ATTRIBUTE_MASK == OPTIONAL_PATH_ATTRIBUTE_MASK;
        let transitive =
            attributes & TRANSITIVE_PATH_ATTRIBUTE_MASK == TRANSITIVE_PATH_ATTRIBUTE_MASK;
        let partial = attributes & PARTIAL_PATH_ATTRIBUTE_MASK == PARTIAL_PATH_ATTRIBUTE_MASK;
        let extended_length =
            attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
        let value = match PathAttributeType::try_from(code) {
            Ok(PathAttributeType::Origin) => {
                let value = Origin::parse(cur, extended_length)?;
                PathAttributeValue::Origin(value)
            }
            Ok(PathAttributeType::AsPath) => {
                let value = AsPath::parse(cur, extended_length, asn4)?;
                PathAttributeValue::AsPath(value)
            }
            Ok(PathAttributeType::As4Path) => {
                let value = As4Path::parse(cur, extended_length)?;
                PathAttributeValue::As4Path(value)
            }
            Ok(PathAttributeType::NextHop) => {
                let value = NextHop::parse(cur, extended_length)?;
                PathAttributeValue::NextHop(value)
            }
            Ok(PathAttributeType::MultiExitDiscriminator) => {
                let value = MultiExitDiscriminator::parse(cur, extended_length)?;
                PathAttributeValue::MultiExitDiscriminator(value)
            }
            Ok(PathAttributeType::LocalPreference) => {
                let value = LocalPreference::parse(cur, extended_length)?;
                PathAttributeValue::LocalPreference(value)
            }
            Ok(PathAttributeType::AtomicAggregate) => {
                let value = AtomicAggregate::parse(cur, extended_length)?;
                PathAttributeValue::AtomicAggregate(value)
            }
            Ok(PathAttributeType::Aggregator) => {
                let value = Aggregator::parse(cur, extended_length, asn4)?;
                PathAttributeValue::Aggregator(value)
            }
            Ok(PathAttributeType::Communities) => {
                let value = Communities::parse(cur, extended_length)?;
                PathAttributeValue::Communities(value)
            }
            Ok(PathAttributeType::ExtendedCommunities) => {
                let value = ExtendedCommunities::parse(cur, extended_length)?;
                PathAttributeValue::ExtendedCommunities(value)
            }
            Ok(PathAttributeType::ExtendedCommunitiesIpv6) => {
                let value = ExtendedCommunitiesIpv6::parse(cur, extended_length)?;
                PathAttributeValue::ExtendedCommunitiesIpv6(value)
            }
            Ok(PathAttributeType::LargeCommunities) => {
                let value = LargeCommunities::parse(cur, extended_length)?;
                PathAttributeValue::LargeCommunities(value)
            }
            Ok(PathAttributeType::OriginatorId) => {
                let value = Originator::parse(cur, extended_length)?;
                PathAttributeValue::Originator(value)
            }
            Ok(PathAttributeType::ClusterList) => {
                let value = ClusterList::parse(cur, extended_length)?;
                PathAttributeValue::ClusterList(value)
            }
            Ok(PathAttributeType::MpReachNlri) => {
                let value = MpReach::parse(cur, extended_length, multiple_labels, add_path_map)?;
                PathAttributeValue::MpReach(value)
            }
            Ok(PathAttributeType::MpUnreachNlri) => {
                let value = MpUnreach::parse(cur, extended_length, multiple_labels, add_path_map)?;
                PathAttributeValue::MpUnreach(value)
            }
            Ok(PathAttributeType::OnlyToCustomer) => {
                let value = OnlyToCustomer::parse(cur, extended_length)?;
                PathAttributeValue::OnlyToCustomer(value)
            }
            Ok(PathAttributeType::AccumulatedIgp) => {
                let value = Aigp::parse(cur, extended_length)?;
                PathAttributeValue::Aigp(value)
            }
            Ok(PathAttributeType::BgpLsAttribute) => {
                let value = BgpLsAttribute::parse(cur, extended_length)?;
                PathAttributeValue::BgpLs(value)
            }
            Ok(PathAttributeType::BgpPrefixSid) => {
                let value = PrefixSegmentIdentifier::parse(cur, extended_length)?;
                PathAttributeValue::PrefixSegmentIdentifier(value)
            }
            Ok(_code) => {
                let value = UnknownAttribute::parse(cur, code, extended_length)?;
                PathAttributeValue::UnknownAttribute(value)
            }
            Err(UndefinedPathAttributeType(_code)) => {
                let value = UnknownAttribute::parse(cur, code, extended_length)?;
                PathAttributeValue::UnknownAttribute(value)
            }
        };
        let attr = match PathAttribute::from(optional, transitive, partial, extended_length, value)
        {
            Ok(attr) => attr,
            Err((value, err)) => {
                return Err(PathAttributeParsingError::InvalidPathAttribute {
                    offset,
                    invalid_attribute: err,
                    value: value.path_attribute_type(),
                });
            }
        };
        Ok(attr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum OriginParsingError {
    #[error("Origin parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Invalid origin length {length} at offset {offset}")]
    InvalidOriginLength {
        offset: usize,
        length: PathAttributeLength,
    },
    #[error("Undefined origin {code} at offset {offset}")]
    UndefinedOrigin { offset: usize, code: u8 },
}

impl<'a> ParseFromWithOneInput<'a, bool> for Origin {
    type Error = OriginParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let length = if extended_length {
            let raw = cur.read_u16_be()?;
            PathAttributeLength::U16(raw)
        } else {
            let raw = cur.read_u8()?;
            PathAttributeLength::U8(raw)
        };
        if !check_length(length, ORIGIN_LEN) {
            return Err(OriginParsingError::InvalidOriginLength { offset, length });
        }
        let offset = cur.offset();
        let code = cur.read_u8()?;
        let origin = Origin::try_from(code)
            .map_err(|_| OriginParsingError::UndefinedOrigin { offset, code })?;
        Ok(origin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum AsPathParsingError {
    #[error("AS Path parsing error: {0}")]
    Parse(#[from] ParseError),
    /// RFC 7606: An AS_PATH is considered malformed, if it has a Path Segment
    /// Length field of zero.
    #[error("AS Path zero segment length offset {offset}")]
    ZeroSegmentLength { offset: usize },
    /// Invalid Length
    #[error(
        "AS Path invalid path length found {found} while excepting {expecting} at offset {offset}"
    )]
    InvalidAsPathLength {
        offset: usize,
        expecting: usize,
        found: usize,
    },
    #[error("AS Path undefined segment type {code} at offset {offset}")]
    UndefinedAsPathSegmentType { offset: usize, code: u8 },
}

impl<'a> ParseFromWithTwoInputs<'a, bool, bool> for AsPath {
    type Error = AsPathParsingError;
    fn parse(
        cur: &mut BytesReader,
        extended_length: bool,
        asn4: bool,
    ) -> Result<Self, Self::Error> {
        let mut segments_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        if asn4 {
            let mut segments = Vec::new();
            while !segments_buf.is_empty() {
                let segment = As4PathSegment::parse(&mut segments_buf)?;
                segments.push(segment);
            }
            Ok(Self::As4PathSegments(segments))
        } else {
            let mut segments = Vec::new();
            while !segments_buf.is_empty() {
                let segment = As2PathSegment::parse(&mut segments_buf)?;
                segments.push(segment);
            }
            Ok(Self::As2PathSegments(segments))
        }
    }
}

impl<'a> ParseFrom<'a> for As2PathSegment {
    type Error = AsPathParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let code = cur.read_u8()?;
        let segment_type = AsPathSegmentType::try_from(code)
            .map_err(|_| AsPathParsingError::UndefinedAsPathSegmentType { offset, code })?;
        let offset = cur.offset();
        let count = cur.read_u8()?;
        if count == 0 {
            return Err(AsPathParsingError::ZeroSegmentLength { offset });
        }
        let count = count as usize;
        let expecting = count * 2;
        if cur.remaining() < expecting {
            return Err(AsPathParsingError::InvalidAsPathLength {
                offset,
                expecting,
                found: cur.remaining(),
            });
        }
        let mut as_numbers = Vec::new();
        for _ in 0..count {
            let asnum = cur.read_u16_be()?;
            as_numbers.push(asnum);
        }
        Ok(As2PathSegment::new(segment_type, as_numbers))
    }
}

impl<'a> ParseFrom<'a> for As4PathSegment {
    type Error = AsPathParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let code = cur.read_u8()?;
        let segment_type = AsPathSegmentType::try_from(code)
            .map_err(|_| AsPathParsingError::UndefinedAsPathSegmentType { offset, code })?;
        let offset = cur.offset();
        let count = cur.read_u8()?;
        if count == 0 {
            return Err(AsPathParsingError::ZeroSegmentLength { offset });
        }
        let count = count as usize;
        let expecting = count * 4;
        if cur.remaining() < expecting {
            return Err(AsPathParsingError::InvalidAsPathLength {
                offset,
                expecting,
                found: cur.remaining(),
            });
        }
        let mut as_numbers = Vec::new();
        for _ in 0..count {
            let asnum = cur.read_u32_be()?;
            as_numbers.push(asnum);
        }
        Ok(As4PathSegment::new(segment_type, as_numbers))
    }
}

impl<'a> ParseFromWithOneInput<'a, bool> for As4Path {
    type Error = AsPathParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut segments_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let mut segments = Vec::new();
        while !segments_buf.is_empty() {
            let segment = As4PathSegment::parse(&mut segments_buf)?;
            segments.push(segment);
        }
        Ok(Self::new(segments))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NextHopParsingError {
    #[error("Next Hop parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Next Hop invalid length {length} at offset {offset}")]
    InvalidNextHopLength {
        offset: usize,
        length: PathAttributeLength,
    },
}

impl<'a> ParseFromWithOneInput<'a, bool> for NextHop {
    type Error = NextHopParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let length = if extended_length {
            let raw = cur.read_u16_be()?;
            PathAttributeLength::U16(raw)
        } else {
            let raw = cur.read_u8()?;
            PathAttributeLength::U8(raw)
        };
        if !check_length(length, NEXT_HOP_LEN) {
            return Err(NextHopParsingError::InvalidNextHopLength { offset, length });
        }
        let address = cur.read_u32_be()?;
        let address = Ipv4Addr::from(address);
        Ok(NextHop::new(address))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MultiExitDiscriminatorParsingError {
    #[error("MultiExit discriminator parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("MultiExit discriminator invalid length {length} at offset {offset}")]
    InvalidLength {
        offset: usize,
        length: PathAttributeLength,
    },
}

impl<'a> ParseFromWithOneInput<'a, bool> for MultiExitDiscriminator {
    type Error = MultiExitDiscriminatorParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let length = if extended_length {
            let raw = cur.read_u16_be()?;
            PathAttributeLength::U16(raw)
        } else {
            let raw = cur.read_u8()?;
            PathAttributeLength::U8(raw)
        };
        if !check_length(length, MULTI_EXIT_DISCRIMINATOR_LEN) {
            return Err(MultiExitDiscriminatorParsingError::InvalidLength { offset, length });
        }

        let metric = cur.read_u32_be()?;
        Ok(MultiExitDiscriminator::new(metric))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LocalPreferenceParsingError {
    #[error("Local Preference parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Local Preference invalid length {length} at offset {offset}")]
    InvalidLength {
        offset: usize,
        length: PathAttributeLength,
    },
}

impl<'a> ParseFromWithOneInput<'a, bool> for LocalPreference {
    type Error = LocalPreferenceParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let length = if extended_length {
            let raw = cur.read_u16_be()?;
            PathAttributeLength::U16(raw)
        } else {
            let raw = cur.read_u8()?;
            PathAttributeLength::U8(raw)
        };
        if !check_length(length, LOCAL_PREFERENCE_LEN) {
            return Err(LocalPreferenceParsingError::InvalidLength { offset, length });
        }

        let pref = cur.read_u32_be()?;
        Ok(LocalPreference::new(pref))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum AtomicAggregateParsingError {
    #[error("Atomic Aggregate parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Atomic aggregate invalid length {length} at offset {offset}")]
    InvalidLength {
        offset: usize,
        length: PathAttributeLength,
    },
}

impl<'a> ParseFromWithOneInput<'a, bool> for AtomicAggregate {
    type Error = AtomicAggregateParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let length = if extended_length {
            let raw = cur.read_u16_be()?;
            PathAttributeLength::U16(raw)
        } else {
            let raw = cur.read_u8()?;
            PathAttributeLength::U8(raw)
        };
        if !check_length(length, ATOMIC_AGGREGATE_LEN) {
            return Err(AtomicAggregateParsingError::InvalidLength { offset, length });
        }
        Ok(AtomicAggregate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum AggregatorParsingError {
    #[error("Aggregator parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Aggregator aggregator invalid length {length} at offset {offset}")]
    InvalidLength {
        offset: usize,
        length: PathAttributeLength,
    },
}

impl<'a> ParseFromWithTwoInputs<'a, bool, bool> for Aggregator {
    type Error = AggregatorParsingError;
    fn parse(
        cur: &mut BytesReader,
        extended_length: bool,
        asn4: bool,
    ) -> Result<Self, Self::Error> {
        if asn4 {
            let as4_agg = As4Aggregator::parse(cur, extended_length)?;
            Ok(Aggregator::As4Aggregator(as4_agg))
        } else {
            let as2_agg = As2Aggregator::parse(cur, extended_length)?;
            Ok(Aggregator::As2Aggregator(as2_agg))
        }
    }
}

impl<'a> ParseFromWithOneInput<'a, bool> for As2Aggregator {
    type Error = AggregatorParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let length = if extended_length {
            let raw = cur.read_u16_be()?;
            PathAttributeLength::U16(raw)
        } else {
            let raw = cur.read_u8()?;
            PathAttributeLength::U8(raw)
        };
        if !check_length(length, AS2_AGGREGATOR_LEN) {
            return Err(AggregatorParsingError::InvalidLength { offset, length });
        }
        let asn = cur.read_u16_be()?;
        let origin = cur.read_u32_be()?;

        Ok(As2Aggregator::new(asn, Ipv4Addr::from(origin)))
    }
}

impl<'a> ParseFromWithOneInput<'a, bool> for As4Aggregator {
    type Error = AggregatorParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let length = if extended_length {
            let raw = cur.read_u16_be()?;
            PathAttributeLength::U16(raw)
        } else {
            let raw = cur.read_u8()?;
            PathAttributeLength::U8(raw)
        };
        if !check_length(length, AS4_AGGREGATOR_LEN) {
            return Err(AggregatorParsingError::InvalidLength { offset, length });
        }
        let asn = cur.read_u32_be()?;
        let origin = cur.read_u32_be()?;

        Ok(As4Aggregator::new(asn, Ipv4Addr::from(origin)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MpReachParsingError {
    #[error("BGP-MP reach parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("BGP-MP reach undefined address family (AFI) {afi} at offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },
    #[error("BGP-MP reach undefined subsequent address family (SAFI) {safi} at offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },
    #[error("BGP-MP reach IP address error for address type {address_type}: {error}")]
    IpAddrError {
        address_type: AddressType,
        error: IpAddrParsingError,
    },
    #[error("BGP-MP reach labeled next hop error for address type {address_type}: {error}")]
    LabeledNextHopError {
        address_type: AddressType,
        error: LabeledNextHopParsingError,
    },
    #[error("BGP-MP reach error: {0}")]
    Ipv4UnicastAddressError(#[from] Ipv4UnicastAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    Ipv4MulticastAddressError(#[from] Ipv4MulticastAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    Ipv4NlriMplsLabelsAddressError(#[from] Ipv4NlriMplsLabelsAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    Ipv4MplsVpnUnicastAddressError(#[from] Ipv4MplsVpnUnicastAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    Ipv6UnicastAddressError(#[from] Ipv6UnicastAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    Ipv6NlriMplsLabelsAddressError(#[from] Ipv6NlriMplsLabelsAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    Ipv6MulticastAddressError(#[from] Ipv6MulticastAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    Ipv6MplsVpnUnicastAddressError(#[from] Ipv6MplsVpnUnicastAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    L2EvpnAddressError(#[from] L2EvpnAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    RouteTargetMembershipAddressError(#[from] RouteTargetMembershipAddressParsingError),
    #[error("BGP-MP reach error: {0}")]
    BgpLsNlriParsingError(#[from] BgpLsNlriParsingError),
}

impl<'a> ParseFromWithThreeInputs<'a, bool, &HashMap<AddressType, u8>, &HashMap<AddressType, bool>>
    for MpReach
{
    type Error = MpReachParsingError;
    fn parse(
        cur: &mut BytesReader,
        extended_length: bool,
        multiple_labels: &HashMap<AddressType, u8>,
        add_path_map: &HashMap<AddressType, bool>,
    ) -> Result<Self, Self::Error> {
        let mut mp_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };

        let afi = AddressFamily::try_from(mp_buf.read_u16_be()?).map_err(|err| {
            MpReachParsingError::UndefinedAddressFamily {
                offset: mp_buf.offset() - 2,
                afi: err.0,
            }
        })?;
        let safi = SubsequentAddressFamily::try_from(mp_buf.read_u8()?).map_err(|err| {
            MpReachParsingError::UndefinedSubsequentAddressFamily {
                offset: mp_buf.offset() - 1,
                safi: err.0,
            }
        })?;
        match AddressType::from_afi_safi(afi, safi) {
            Ok(addr_type @ AddressType::Ipv4Unicast) => {
                let (next_hop, next_hop_local) =
                    parse_ip4_or_ipv6_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4UnicastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv4Unicast {
                    next_hop,
                    next_hop_local,
                    nlri,
                })
            }
            Ok(addr_type @ AddressType::Ipv4Multicast) => {
                let (next_hop, next_hop_local) =
                    parse_ip4_or_ipv6_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4MulticastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv4Multicast {
                    next_hop,
                    next_hop_local,
                    nlri,
                })
            }
            Ok(addr_type @ AddressType::Ipv4NlriMplsLabels) => {
                let (next_hop, next_hop_local) =
                    parse_ip4_or_ipv6_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4NlriMplsLabelsAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv4NlriMplsLabels {
                    next_hop,
                    next_hop_local,
                    nlri,
                })
            }
            Ok(addr_type @ AddressType::Ipv4MplsLabeledVpn) => {
                let next_hop = parse_labeled_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4MplsVpnUnicastAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv4MplsVpnUnicast { next_hop, nlri })
            }
            Ok(addr_type @ AddressType::Ipv6Unicast) => {
                let next_hop_len = mp_buf.read_u8()?;
                let global = mp_buf.read_u128_be()?;
                let next_hop_global = Ipv6Addr::from(global);
                let next_hop_local = if next_hop_len == 32 {
                    let local = mp_buf.read_u128_be()?;
                    Some(Ipv6Addr::from(local))
                } else {
                    None
                };
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6UnicastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv6Unicast {
                    next_hop_global,
                    next_hop_local,
                    nlri,
                })
            }
            Ok(addr_type @ AddressType::Ipv6Multicast) => {
                let next_hop_len = mp_buf.read_u8()?;
                let global = mp_buf.read_u128_be()?;
                let next_hop_global = Ipv6Addr::from(global);
                let next_hop_local = if next_hop_len == 32 {
                    let local = mp_buf.read_u128_be()?;
                    Some(Ipv6Addr::from(local))
                } else {
                    None
                };
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6MulticastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv6Multicast {
                    next_hop_global,
                    next_hop_local,
                    nlri,
                })
            }
            Ok(addr_type @ AddressType::Ipv6NlriMplsLabels) => {
                let (next_hop, next_hop_local) =
                    parse_ip4_or_ipv6_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6NlriMplsLabelsAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv6NlriMplsLabels {
                    next_hop,
                    next_hop_local,
                    nlri,
                })
            }
            Ok(addr_type @ AddressType::Ipv6MplsLabeledVpn) => {
                let next_hop = parse_labeled_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6MplsVpnUnicastAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpReach::Ipv6MplsVpnUnicast { next_hop, nlri })
            }
            Ok(addr_type @ AddressType::L2VpnBgpEvpn) => {
                let next_hop = parse_ip_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = L2EvpnAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::L2Evpn { next_hop, nlri })
            }
            Ok(addr_type @ AddressType::RouteTargetConstrains) => {
                let next_hop = parse_ip_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = RouteTargetMembershipAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::RouteTargetMembership { next_hop, nlri })
            }
            Ok(addr_type @ AddressType::BgpLs) => {
                let next_hop = parse_ip_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = BgpLsNlri::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::BgpLs { next_hop, nlri })
            }
            Ok(addr_type @ AddressType::BgpLsVpn) => {
                let next_hop = parse_labeled_next_hop(&mut mp_buf, addr_type)?;
                let _ = mp_buf.read_u8()?;
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = BgpLsVpnNlri::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpReach::BgpLsVpn { next_hop, nlri })
            }
            Ok(_) | Err(_) => Ok(MpReach::Unknown {
                afi,
                safi,
                value: mp_buf.read_bytes(mp_buf.remaining())?.to_vec(),
            }),
        }
    }
}

#[inline]
fn parse_ip_next_hop(
    mp_buf: &mut BytesReader,
    address_type: AddressType,
) -> Result<IpAddr, MpReachParsingError> {
    let next_hop = match IpAddr::parse(mp_buf) {
        Ok(next_hop) => next_hop,
        Err(error) => {
            return Err(MpReachParsingError::IpAddrError {
                address_type,
                error,
            });
        }
    };
    Ok(next_hop)
}

#[inline]
fn parse_ip4_or_ipv6_next_hop(
    mp_buf: &mut BytesReader,
    address_type: AddressType,
) -> Result<(IpAddr, Option<Ipv6Addr>), MpReachParsingError> {
    let offset = mp_buf.offset();
    let next_hop_len = mp_buf.read_u8()?;
    match next_hop_len {
        IPV4_LEN => {
            let next_hop = mp_buf.read_u32_be()?;
            let next_hop = Ipv4Addr::from(next_hop);
            Ok((IpAddr::V4(next_hop), None))
        }
        IPV6_LEN => {
            let next_hop = mp_buf.read_u128_be()?;
            let next_hop = Ipv6Addr::from(next_hop);
            Ok((IpAddr::V6(next_hop), None))
        }
        IPV6_WITH_LINK_LOCAL_LEN => {
            let next_hop = mp_buf.read_u128_be()?;
            let next_hop_local = mp_buf.read_u128_be()?;
            let next_hop = Ipv6Addr::from(next_hop);
            let next_hop_local = Ipv6Addr::from(next_hop_local);
            Ok((IpAddr::V6(next_hop), Some(next_hop_local)))
        }
        _ => Err(MpReachParsingError::IpAddrError {
            address_type,
            error: IpAddrParsingError::InvalidIpAddressLength {
                offset,
                length: next_hop_len,
            },
        }),
    }
}

#[inline]
fn parse_labeled_next_hop(
    mp_buf: &mut BytesReader,
    address_type: AddressType,
) -> Result<LabeledNextHop, MpReachParsingError> {
    let next_hop = match LabeledNextHop::parse(mp_buf) {
        Ok(next_hop) => next_hop,
        Err(error) => {
            return Err(MpReachParsingError::LabeledNextHopError {
                address_type,
                error,
            });
        }
    };
    Ok(next_hop)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MpUnreachParsingError {
    #[error("BGP-MP unreach parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("BGP-MP unreach undefined address family (AFI) {afi} at offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("BGP-MP unreach undefined subsequent address family (SAFI) {safi} at offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error("BGP-MP unreach error: {0}")]
    Ipv4UnicastAddressError(#[from] Ipv4UnicastAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    Ipv4MulticastAddressError(#[from] Ipv4MulticastAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    Ipv4NlriMplsLabelsAddressError(#[from] Ipv4NlriMplsLabelsAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    Ipv4MplsVpnUnicastAddressError(#[from] Ipv4MplsVpnUnicastAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    Ipv6UnicastAddressError(#[from] Ipv6UnicastAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    Ipv6MulticastAddressError(#[from] Ipv6MulticastAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    Ipv6NlriMplsLabelsAddressError(#[from] Ipv6NlriMplsLabelsAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    Ipv6MplsVpnUnicastAddressError(#[from] Ipv6MplsVpnUnicastAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    L2EvpnAddressError(#[from] L2EvpnAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    RouteTargetMembershipAddressError(#[from] RouteTargetMembershipAddressParsingError),

    #[error("BGP-MP unreach error: {0}")]
    BgpLsError(#[from] BgpLsNlriParsingError),
}

impl<'a> ParseFromWithThreeInputs<'a, bool, &HashMap<AddressType, u8>, &HashMap<AddressType, bool>>
    for MpUnreach
{
    type Error = MpUnreachParsingError;

    fn parse(
        cur: &mut BytesReader,
        extended_length: bool,
        multiple_labels: &HashMap<AddressType, u8>,
        add_path_map: &HashMap<AddressType, bool>,
    ) -> Result<Self, Self::Error> {
        let mut mp_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let offset = cur.offset();
        let afi = AddressFamily::try_from(mp_buf.read_u16_be()?)
            .map_err(|err| MpUnreachParsingError::UndefinedAddressFamily { offset, afi: err.0 })?;
        let safi = SubsequentAddressFamily::try_from(mp_buf.read_u8()?).map_err(|err| {
            MpUnreachParsingError::UndefinedSubsequentAddressFamily {
                offset,
                safi: err.0,
            }
        })?;
        match AddressType::from_afi_safi(afi, safi) {
            Ok(addr_type @ AddressType::Ipv4Unicast) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4UnicastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv4Unicast { nlri })
            }
            Ok(addr_type @ AddressType::Ipv4Multicast) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4MulticastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv4Multicast { nlri })
            }
            Ok(addr_type @ AddressType::Ipv4NlriMplsLabels) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4NlriMplsLabelsAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv4NlriMplsLabels { nlri })
            }
            Ok(addr_type @ AddressType::Ipv4MplsLabeledVpn) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv4MplsVpnUnicastAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv4MplsVpnUnicast { nlri })
            }
            Ok(addr_type @ AddressType::Ipv6Unicast) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6UnicastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv6Unicast { nlri })
            }
            Ok(addr_type @ AddressType::Ipv6Multicast) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6MulticastAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv6Multicast { nlri })
            }
            Ok(addr_type @ AddressType::Ipv6NlriMplsLabels) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6NlriMplsLabelsAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv6NlriMplsLabels { nlri })
            }
            Ok(addr_type @ AddressType::Ipv6MplsLabeledVpn) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = Ipv6MplsVpnUnicastAddress::parse(
                        &mut mp_buf,
                        add_path,
                        false,
                        *multiple_labels.get(&addr_type).unwrap_or(&1),
                    )?;
                    nlri.push(v);
                }
                Ok(MpUnreach::Ipv6MplsVpnUnicast { nlri })
            }
            Ok(addr_type @ AddressType::L2VpnBgpEvpn) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = L2EvpnAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::L2Evpn { nlri })
            }
            Ok(addr_type @ AddressType::RouteTargetConstrains) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = RouteTargetMembershipAddress::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::RouteTargetMembership { nlri })
            }
            Ok(addr_type @ AddressType::BgpLs) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = BgpLsNlri::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::BgpLs { nlri })
            }
            Ok(addr_type @ AddressType::BgpLsVpn) => {
                let add_path = add_path_map.get(&addr_type).is_some_and(|x| *x);
                let mut nlri = Vec::new();
                while !mp_buf.is_empty() {
                    let v = BgpLsVpnNlri::parse(&mut mp_buf, add_path)?;
                    nlri.push(v);
                }
                Ok(MpUnreach::BgpLsVpn { nlri })
            }
            Ok(_) | Err(_) => Ok(MpUnreach::Unknown {
                afi,
                safi,
                nlri: mp_buf.read_bytes(mp_buf.remaining())?.to_vec(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum UnknownAttributeParsingError {
    #[error("Unknown attribute parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error(
        "Unknown attribute unexpected length {actual} while expecting {expecting} at offset {offset}"
    )]
    InvalidLength {
        offset: usize,
        expecting: usize,
        actual: usize,
    },
}

impl<'a> ParseFromWithTwoInputs<'a, u8, bool> for UnknownAttribute {
    type Error = UnknownAttributeParsingError;
    fn parse(cur: &mut BytesReader, code: u8, extended_length: bool) -> Result<Self, Self::Error> {
        let length = if extended_length {
            cur.read_u16_be()? as usize
        } else {
            cur.read_u8()? as usize
        };

        if length > cur.remaining() {
            return Err(UnknownAttributeParsingError::InvalidLength {
                offset: cur.offset() - 2,
                expecting: length,
                actual: cur.remaining(),
            });
        }
        let value = cur.read_bytes(length)?;
        Ok(UnknownAttribute::new(code, value.to_vec()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum CommunitiesParsingError {
    #[error("Communities parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error(transparent)]
    CommunityError(#[from] CommunityParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for Communities {
    type Error = CommunitiesParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut communities_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let mut communities = Vec::new();
        while !communities_buf.is_empty() {
            let v = Community::parse(&mut communities_buf)?;
            communities.push(v);
        }
        Ok(Communities::new(communities))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ExtendedCommunitiesParsingError {
    #[error("Extended communities parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error(transparent)]
    ExtendedCommunityError(#[from] ExtendedCommunityParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for ExtendedCommunities {
    type Error = ExtendedCommunitiesParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut communities_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let mut communities = Vec::new();
        while !communities_buf.is_empty() {
            let v = ExtendedCommunity::parse(&mut communities_buf)?;
            communities.push(v);
        }
        Ok(ExtendedCommunities::new(communities))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ExtendedCommunitiesIpv6ParsingError {
    #[error("Extended communities ipv6 parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error(transparent)]
    ExtendedCommunityIpv6Error(#[from] ExtendedCommunityIpv6ParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for ExtendedCommunitiesIpv6 {
    type Error = ExtendedCommunitiesIpv6ParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut communities_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let mut communities = Vec::new();
        while !communities_buf.is_empty() {
            let v = ExtendedCommunityIpv6::parse(&mut communities_buf)?;
            communities.push(v);
        }
        Ok(ExtendedCommunitiesIpv6::new(communities))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LargeCommunitiesParsingError {
    #[error("Large communities parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error(transparent)]
    LargeCommunityError(#[from] LargeCommunityParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for LargeCommunities {
    type Error = LargeCommunitiesParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut communities_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let mut communities = Vec::new();
        while !communities_buf.is_empty() {
            let v = LargeCommunity::parse(&mut communities_buf)?;
            communities.push(v);
        }
        Ok(LargeCommunities::new(communities))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum OriginatorParsingError {
    #[error("Originator parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for Originator {
    type Error = OriginatorParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut data_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let id = data_buf.read_u32_be()?;
        Ok(Originator::new(Ipv4Addr::from(id)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ClusterIdParsingError {
    #[error("Cluster id parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for ClusterId {
    type Error = ClusterIdParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let id = cur.read_u32_be()?;
        Ok(ClusterId::new(Ipv4Addr::from(id)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ClusterListParsingError {
    #[error("Cluster list parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error(transparent)]
    ClusterIdError(#[from] ClusterIdParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for ClusterList {
    type Error = ClusterListParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut data_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let mut cluster_ids = Vec::new();
        while !data_buf.is_empty() {
            let v = ClusterId::parse(&mut data_buf)?;
            cluster_ids.push(v);
        }
        Ok(ClusterList::new(cluster_ids))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum AigpParsingError {
    #[error("AIGP parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("AIGP attribute type {aigp_attribute_type} is undefined at offset {offset}")]
    UndefinedAigpAttributeType {
        offset: usize,
        aigp_attribute_type: u8,
    },

    #[error("AIGP attribute with invalid length {length} at offset {offset}")]
    InvalidLength { offset: usize, length: u16 },
}

impl<'a> ParseFromWithOneInput<'a, bool> for Aigp {
    type Error = AigpParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut data_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };

        let aigp_type = AigpAttributeType::try_from(data_buf.read_u8()?).map_err(|error| {
            AigpParsingError::UndefinedAigpAttributeType {
                offset: data_buf.offset() - 1,
                aigp_attribute_type: error.0,
            }
        })?;
        match aigp_type {
            AigpAttributeType::AccumulatedIgpMetric => {
                let length = data_buf.read_u16_be()?;
                if length != ACCUMULATED_IGP_METRIC {
                    return Err(AigpParsingError::InvalidLength {
                        offset: data_buf.offset() - 2,
                        length,
                    });
                }
                let metric = data_buf.read_u64_be()?;
                Ok(Aigp::AccumulatedIgpMetric(metric))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum OnlyToCustomerParsingError {
    #[error("Only to customer parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for OnlyToCustomer {
    type Error = OnlyToCustomerParsingError;
    fn parse(cur: &mut BytesReader, extended_length: bool) -> Result<Self, Self::Error> {
        let mut data_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };
        let asn = data_buf.read_u32_be()?;
        Ok(OnlyToCustomer::new(asn))
    }
}
