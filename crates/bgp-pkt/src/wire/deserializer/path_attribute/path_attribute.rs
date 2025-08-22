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

use crate::{
    iana::{
        AigpAttributeType, PathAttributeType, UndefinedAigpAttributeType,
        UndefinedPathAttributeType,
    },
    nlri::LabeledNextHop,
    path_attribute::*,
    wire::{
        deserializer::{
            community::*,
            nlri::*,
            path_attribute::{BgpLsAttributeParsingError, SegmentIdentifierParsingError},
            BgpParsingContext, IpAddrParsingError,
        },
        serializer::nlri::{IPV4_LEN, IPV6_LEN, IPV6_WITH_LINK_LOCAL_LEN},
        ACCUMULATED_IGP_METRIC,
    },
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, SubsequentAddressFamily, UndefinedAddressFamily,
    UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{
    parse_into_located_one_input, parse_into_located_three_inputs, parse_into_located_two_inputs,
    parse_till_empty, parse_till_empty_into_located, parse_till_empty_into_with_one_input_located,
    parse_till_empty_into_with_three_inputs_located, ErrorKindSerdeDeref, LocatedParsingError,
    ReadablePdu, ReadablePduWithOneInput, ReadablePduWithThreeInputs, ReadablePduWithTwoInputs,
    Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u64, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const OPTIONAL_PATH_ATTRIBUTE_MASK: u8 = 0x80;
const TRANSITIVE_PATH_ATTRIBUTE_MASK: u8 = 0x40;
const PARTIAL_PATH_ATTRIBUTE_MASK: u8 = 0x20;
pub(crate) const EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK: u8 = 0x10;
const ORIGIN_LEN: u16 = 1;
const NEXT_HOP_LEN: u16 = 4;
const MULTI_EXIT_DISCRIMINATOR_LEN: u16 = 4;
const LOCAL_PREFERENCE_LEN: u16 = 4;
const ATOMIC_AGGREGATE_LEN: u16 = 0;
const AS2_AGGREGATOR_LEN: u16 = 6;
const AS4_AGGREGATOR_LEN: u16 = 8;

#[inline]
const fn check_length(attr_len: PathAttributeLength, expected: u16) -> bool {
    match attr_len {
        PathAttributeLength::U8(len) => len as u16 == expected,
        PathAttributeLength::U16(len) => len == expected,
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum PathAttributeParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    OriginError(#[from_located(module = "self")] OriginParsingError),
    AsPathError(#[from_located(module = "self")] AsPathParsingError),
    NextHopError(#[from_located(module = "self")] NextHopParsingError),
    MultiExitDiscriminatorError(
        #[from_located(module = "self")] MultiExitDiscriminatorParsingError,
    ),
    LocalPreferenceError(#[from_located(module = "self")] LocalPreferenceParsingError),
    AtomicAggregateError(#[from_located(module = "self")] AtomicAggregateParsingError),
    AggregatorError(#[from_located(module = "self")] AggregatorParsingError),
    CommunitiesError(#[from_located(module = "self")] CommunitiesParsingError),
    ExtendedCommunitiesError(#[from_located(module = "self")] ExtendedCommunitiesParsingError),
    ExtendedCommunitiesErrorIpv6(
        #[from_located(module = "self")] ExtendedCommunitiesIpv6ParsingError,
    ),
    LargeCommunitiesError(#[from_located(module = "self")] LargeCommunitiesParsingError),
    OriginatorError(#[from_located(module = "self")] OriginatorParsingError),
    ClusterListError(#[from_located(module = "self")] ClusterListParsingError),
    MpReachErrorError(#[from_located(module = "self")] MpReachParsingError),
    MpUnreachErrorError(#[from_located(module = "self")] MpUnreachParsingError),
    OnlyToCustomerError(#[from_located(module = "self")] OnlyToCustomerParsingError),
    AigpError(#[from_located(module = "self")] AigpParsingError),
    BgpLsError(
        #[from_located(module = "crate::wire::deserializer::path_attribute")]
        BgpLsAttributeParsingError,
    ),
    SegmentIdentifierParsingError(
        #[from_located(module = "crate::wire::deserializer::path_attribute")]
        SegmentIdentifierParsingError,
    ),
    UnknownAttributeError(#[from_located(module = "self")] UnknownAttributeParsingError),
    InvalidPathAttribute(InvalidPathAttribute, PathAttributeValue),
}

pub trait IntoLocatedPathAttributeParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a>;
}

impl<'a> ReadablePduWithOneInput<'a, &mut BgpParsingContext, LocatedPathAttributeParsingError<'a>>
    for PathAttribute
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedPathAttributeParsingError<'a>> {
        let (asn4, multiple_labels, add_path_map) = (ctx.asn4, &ctx.multiple_labels, &ctx.add_path);
        let (buf, attributes) = be_u8(buf)?;
        let buf_before_code = buf;
        let (buf, code) = be_u8(buf)?;
        let optional = attributes & OPTIONAL_PATH_ATTRIBUTE_MASK == OPTIONAL_PATH_ATTRIBUTE_MASK;
        let transitive =
            attributes & TRANSITIVE_PATH_ATTRIBUTE_MASK == TRANSITIVE_PATH_ATTRIBUTE_MASK;
        let partial = attributes & PARTIAL_PATH_ATTRIBUTE_MASK == PARTIAL_PATH_ATTRIBUTE_MASK;
        let extended_length =
            attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
        let (buf, value) = match PathAttributeType::try_from(code) {
            Ok(PathAttributeType::Origin) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::Origin(value);
                (buf, value)
            }
            Ok(PathAttributeType::AsPath) => {
                let (buf, value) = parse_into_located_two_inputs(buf, extended_length, asn4)?;
                let value = PathAttributeValue::AsPath(value);
                (buf, value)
            }
            Ok(PathAttributeType::As4Path) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::As4Path(value);
                (buf, value)
            }
            Ok(PathAttributeType::NextHop) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::NextHop(value);
                (buf, value)
            }
            Ok(PathAttributeType::MultiExitDiscriminator) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::MultiExitDiscriminator(value);
                (buf, value)
            }
            Ok(PathAttributeType::LocalPreference) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::LocalPreference(value);
                (buf, value)
            }
            Ok(PathAttributeType::AtomicAggregate) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::AtomicAggregate(value);
                (buf, value)
            }
            Ok(PathAttributeType::Aggregator) => {
                let (buf, value) = parse_into_located_two_inputs(buf, extended_length, asn4)?;
                let value = PathAttributeValue::Aggregator(value);
                (buf, value)
            }
            Ok(PathAttributeType::Communities) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::Communities(value);
                (buf, value)
            }
            Ok(PathAttributeType::ExtendedCommunities) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::ExtendedCommunities(value);
                (buf, value)
            }
            Ok(PathAttributeType::ExtendedCommunitiesIpv6) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::ExtendedCommunitiesIpv6(value);
                (buf, value)
            }
            Ok(PathAttributeType::LargeCommunities) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::LargeCommunities(value);
                (buf, value)
            }
            Ok(PathAttributeType::OriginatorId) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::Originator(value);
                (buf, value)
            }
            Ok(PathAttributeType::ClusterList) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::ClusterList(value);
                (buf, value)
            }
            Ok(PathAttributeType::MpReachNlri) => {
                let (buf, value) = parse_into_located_three_inputs(
                    buf,
                    extended_length,
                    multiple_labels,
                    add_path_map,
                )?;
                let value = PathAttributeValue::MpReach(value);
                (buf, value)
            }
            Ok(PathAttributeType::MpUnreachNlri) => {
                let (buf, value) = parse_into_located_three_inputs(
                    buf,
                    extended_length,
                    multiple_labels,
                    add_path_map,
                )?;
                let value = PathAttributeValue::MpUnreach(value);
                (buf, value)
            }
            Ok(PathAttributeType::OnlyToCustomer) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::OnlyToCustomer(value);
                (buf, value)
            }
            Ok(PathAttributeType::AccumulatedIgp) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::Aigp(value);
                (buf, value)
            }
            Ok(PathAttributeType::BgpLsAttribute) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::BgpLs(value);
                (buf, value)
            }
            Ok(PathAttributeType::BgpPrefixSid) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::PrefixSegmentIdentifier(value);
                (buf, value)
            }
            Ok(_code) => {
                let (buf, value) = parse_into_located_one_input(buf_before_code, extended_length)?;
                let value = PathAttributeValue::UnknownAttribute(value);
                (buf, value)
            }
            Err(UndefinedPathAttributeType(_code)) => {
                let (buf, value) = parse_into_located_one_input(buf_before_code, extended_length)?;
                let value = PathAttributeValue::UnknownAttribute(value);
                (buf, value)
            }
        };
        let attr = match PathAttribute::from(optional, transitive, partial, extended_length, value)
        {
            Ok(attr) => attr,
            Err((value, err)) => {
                return Err(nom::Err::Error(LocatedPathAttributeParsingError::new(
                    buf,
                    PathAttributeParsingError::InvalidPathAttribute(err, value),
                )));
            }
        };
        Ok((buf, attr))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OriginParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidOriginLength(#[from_external] PathAttributeLength),
    UndefinedOrigin(#[from_external] UndefinedOrigin),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedOriginParsingError<'a>> for Origin {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedOriginParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, ORIGIN_LEN) {
            return Err(nom::Err::Error(LocatedOriginParsingError::new(
                input,
                OriginParsingError::InvalidOriginLength(length),
            )));
        }
        let (buf, origin) = nom::combinator::map_res(be_u8, Origin::try_from)(buf)?;
        Ok((buf, origin))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AsPathParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    /// RFC 7606: An AS_PATH is considered malformed, if it has a Path Segment
    /// Length field of zero.
    ZeroSegmentLength,
    /// Invalid Length
    InvalidAsPathLength {
        expecting: usize,
        found: usize,
    },
    UndefinedAsPathSegmentType(#[from_external] UndefinedAsPathSegmentType),
}

impl<'a> ReadablePduWithTwoInputs<'a, bool, bool, LocatedAsPathParsingError<'a>> for AsPath {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
        asn4: bool,
    ) -> IResult<Span<'a>, Self, LocatedAsPathParsingError<'a>> {
        let (buf, segments_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        if asn4 {
            let (_, segments) = parse_till_empty(segments_buf)?;
            Ok((buf, Self::As4PathSegments(segments)))
        } else {
            let (_, segments) = parse_till_empty(segments_buf)?;
            Ok((buf, Self::As2PathSegments(segments)))
        }
    }
}

impl<'a> ReadablePdu<'a, LocatedAsPathParsingError<'a>> for As2PathSegment {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedAsPathParsingError<'a>> {
        let (buf, segment_type) =
            nom::combinator::map_res(be_u8, AsPathSegmentType::try_from)(buf)?;
        let before = buf;
        let (buf, count) = be_u8(buf)?;
        if count == 0 {
            return Err(nom::Err::Error(LocatedAsPathParsingError::new(
                before,
                AsPathParsingError::ZeroSegmentLength,
            )));
        }
        let count = count as usize;
        let expecting = count * 2;
        if buf.len() < expecting {
            return Err(nom::Err::Error(LocatedAsPathParsingError::new(
                buf,
                AsPathParsingError::InvalidAsPathLength {
                    expecting,
                    found: buf.len(),
                },
            )));
        }
        let (buf, as_numbers) = nom::multi::many_m_n(count, count, be_u16)(buf)?;
        Ok((buf, As2PathSegment::new(segment_type, as_numbers)))
    }
}

impl<'a> ReadablePdu<'a, LocatedAsPathParsingError<'a>> for As4PathSegment {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedAsPathParsingError<'a>> {
        let (buf, segment_type) =
            nom::combinator::map_res(be_u8, AsPathSegmentType::try_from)(buf)?;
        let before = buf;
        let (buf, count) = be_u8(buf)?;
        if count == 0 {
            return Err(nom::Err::Error(LocatedAsPathParsingError::new(
                before,
                AsPathParsingError::ZeroSegmentLength,
            )));
        }
        let count = count as usize;
        let expecting = count * 4;
        if buf.len() < expecting {
            return Err(nom::Err::Error(LocatedAsPathParsingError::new(
                buf,
                AsPathParsingError::InvalidAsPathLength {
                    expecting,
                    found: buf.len(),
                },
            )));
        }
        let (buf, as_numbers) = nom::multi::many_m_n(count, count, be_u32)(buf)?;
        Ok((buf, As4PathSegment::new(segment_type, as_numbers)))
    }
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedAsPathParsingError<'a>> for As4Path {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedAsPathParsingError<'a>> {
        let (buf, segments_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_, segments) = parse_till_empty(segments_buf)?;
        Ok((buf, Self::new(segments)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NextHopParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidNextHopLength(PathAttributeLength),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedNextHopParsingError<'a>> for NextHop {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedNextHopParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, NEXT_HOP_LEN) {
            return Err(nom::Err::Error(LocatedNextHopParsingError::new(
                input,
                NextHopParsingError::InvalidNextHopLength(length),
            )));
        }
        let (buf, address) = be_u32(buf)?;
        let address = Ipv4Addr::from(address);

        Ok((buf, NextHop::new(address)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MultiExitDiscriminatorParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedMultiExitDiscriminatorParsingError<'a>>
    for MultiExitDiscriminator
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedMultiExitDiscriminatorParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, MULTI_EXIT_DISCRIMINATOR_LEN) {
            return Err(nom::Err::Error(
                LocatedMultiExitDiscriminatorParsingError::new(
                    input,
                    MultiExitDiscriminatorParsingError::InvalidLength(length),
                ),
            ));
        }

        let (buf, metric) = be_u32(buf)?;
        Ok((buf, MultiExitDiscriminator::new(metric)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LocalPreferenceParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedLocalPreferenceParsingError<'a>>
    for LocalPreference
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedLocalPreferenceParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, LOCAL_PREFERENCE_LEN) {
            return Err(nom::Err::Error(LocatedLocalPreferenceParsingError::new(
                input,
                LocalPreferenceParsingError::InvalidLength(length),
            )));
        }

        let (buf, pref) = be_u32(buf)?;
        Ok((buf, LocalPreference::new(pref)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AtomicAggregateParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedAtomicAggregateParsingError<'a>>
    for AtomicAggregate
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedAtomicAggregateParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, ATOMIC_AGGREGATE_LEN) {
            return Err(nom::Err::Error(LocatedAtomicAggregateParsingError::new(
                input,
                AtomicAggregateParsingError::InvalidLength(length),
            )));
        }
        Ok((buf, AtomicAggregate))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AggregatorParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePduWithTwoInputs<'a, bool, bool, LocatedAggregatorParsingError<'a>>
    for Aggregator
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
        asn4: bool,
    ) -> IResult<Span<'a>, Self, LocatedAggregatorParsingError<'a>> {
        if asn4 {
            let (buf, as4_agg) = As4Aggregator::from_wire(buf, extended_length)?;
            Ok((buf, Aggregator::As4Aggregator(as4_agg)))
        } else {
            let (buf, as2_agg) = As2Aggregator::from_wire(buf, extended_length)?;
            Ok((buf, Aggregator::As2Aggregator(as2_agg)))
        }
    }
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedAggregatorParsingError<'a>> for As2Aggregator {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedAggregatorParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, AS2_AGGREGATOR_LEN) {
            return Err(nom::Err::Error(LocatedAggregatorParsingError::new(
                input,
                AggregatorParsingError::InvalidLength(length),
            )));
        }
        let (buf, asn) = be_u16(buf)?;
        let (buf, origin) = be_u32(buf)?;

        Ok((buf, As2Aggregator::new(asn, Ipv4Addr::from(origin))))
    }
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedAggregatorParsingError<'a>> for As4Aggregator {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedAggregatorParsingError<'a>> {
        let input = buf;
        let (buf, length) = if extended_length {
            let (buf, raw) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(raw))
        } else {
            let (buf, raw) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(raw))
        };
        if !check_length(length, AS4_AGGREGATOR_LEN) {
            return Err(nom::Err::Error(LocatedAggregatorParsingError::new(
                input,
                AggregatorParsingError::InvalidLength(length),
            )));
        }
        let (buf, asn) = be_u32(buf)?;
        let (buf, origin) = be_u32(buf)?;

        Ok((buf, As4Aggregator::new(asn, Ipv4Addr::from(origin))))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MpReachParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    IpAddrError(AddressType, IpAddrParsingError),
    LabeledNextHopError(AddressType, LabeledNextHopParsingError),
    Ipv4UnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4UnicastAddressParsingError,
    ),
    Ipv4MulticastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv4MulticastAddressParsingError,
    ),
    Ipv4NlriMplsLabelsAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv4NlriMplsLabelsAddressParsingError,
    ),
    Ipv4MplsVpnUnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv4MplsVpnUnicastAddressParsingError,
    ),
    Ipv6UnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6UnicastAddressParsingError,
    ),
    Ipv6NlriMplsLabelsAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv6NlriMplsLabelsAddressParsingError,
    ),
    Ipv6MulticastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv6MulticastAddressParsingError,
    ),
    Ipv6MplsVpnUnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv6MplsVpnUnicastAddressParsingError,
    ),
    L2EvpnAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] L2EvpnAddressParsingError,
    ),
    RouteTargetMembershipAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        RouteTargetMembershipAddressParsingError,
    ),
    BgpLsNlriParsingError(
        #[from_located(module = "crate::wire::deserializer::nlri")] BgpLsNlriParsingError,
    ),
}

impl<'a>
    ReadablePduWithThreeInputs<
        'a,
        bool,
        &HashMap<AddressType, u8>,
        &HashMap<AddressType, bool>,
        LocatedMpReachParsingError<'a>,
    > for MpReach
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
        multiple_labels: &HashMap<AddressType, u8>,
        add_path_map: &HashMap<AddressType, bool>,
    ) -> IResult<Span<'a>, Self, LocatedMpReachParsingError<'a>> {
        let (buf, mp_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (mp_buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(mp_buf)?;
        let (mp_buf, safi) =
            nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(mp_buf)?;
        match AddressType::from_afi_safi(afi, safi) {
            Ok(AddressType::Ipv4Unicast) => {
                let (mp_buf, (next_hop, next_hop_local)) =
                    parse_ip4_or_ipv6_next_hop(mp_buf, AddressType::Ipv4Unicast)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv4Unicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((
                    buf,
                    MpReach::Ipv4Unicast {
                        next_hop,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            Ok(AddressType::Ipv4Multicast) => {
                let (mp_buf, (next_hop, next_hop_local)) =
                    parse_ip4_or_ipv6_next_hop(mp_buf, AddressType::Ipv4Unicast)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv4Multicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((
                    buf,
                    MpReach::Ipv4Multicast {
                        next_hop,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            Ok(AddressType::Ipv4NlriMplsLabels) => {
                let (mp_buf, (next_hop, next_hop_local)) =
                    parse_ip4_or_ipv6_next_hop(mp_buf, AddressType::Ipv4NlriMplsLabels)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv4NlriMplsLabels)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    false,
                    *multiple_labels
                        .get(&AddressType::Ipv4NlriMplsLabels)
                        .unwrap_or(&1),
                )?;
                Ok((
                    buf,
                    MpReach::Ipv4NlriMplsLabels {
                        next_hop,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            Ok(AddressType::Ipv4MplsLabeledVpn) => {
                let (mp_buf, next_hop) =
                    parse_labeled_next_hop(mp_buf, AddressType::Ipv4MplsLabeledVpn)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv4MplsLabeledVpn)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    false,
                    *multiple_labels
                        .get(&AddressType::Ipv4MplsLabeledVpn)
                        .unwrap_or(&1),
                )?;
                Ok((buf, MpReach::Ipv4MplsVpnUnicast { next_hop, nlri }))
            }
            Ok(AddressType::Ipv6Unicast) => {
                let (mp_buf, next_hop_len) = be_u8(mp_buf)?;
                let (mp_buf, global) = be_u128(mp_buf)?;
                let next_hop_global = Ipv6Addr::from(global);
                let (mp_buf, next_hop_local) = if next_hop_len == 32 {
                    let (mp_buf, local) = be_u128(mp_buf)?;
                    (mp_buf, Some(Ipv6Addr::from(local)))
                } else {
                    (mp_buf, None)
                };
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv6Unicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((
                    buf,
                    MpReach::Ipv6Unicast {
                        next_hop_global,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            Ok(AddressType::Ipv6Multicast) => {
                let (mp_buf, next_hop_len) = be_u8(mp_buf)?;
                let (mp_buf, global) = be_u128(mp_buf)?;
                let next_hop_global = Ipv6Addr::from(global);
                let (mp_buf, next_hop_local) = if next_hop_len == 32 {
                    let (mp_buf, local) = be_u128(mp_buf)?;
                    (mp_buf, Some(Ipv6Addr::from(local)))
                } else {
                    (mp_buf, None)
                };
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv6Multicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((
                    buf,
                    MpReach::Ipv6Multicast {
                        next_hop_global,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            Ok(AddressType::Ipv6NlriMplsLabels) => {
                let (mp_buf, (next_hop, next_hop_local)) =
                    parse_ip4_or_ipv6_next_hop(mp_buf, AddressType::Ipv4NlriMplsLabels)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv6NlriMplsLabels)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    false,
                    *multiple_labels
                        .get(&AddressType::Ipv6NlriMplsLabels)
                        .unwrap_or(&1),
                )?;
                Ok((
                    buf,
                    MpReach::Ipv6NlriMplsLabels {
                        next_hop,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            Ok(AddressType::Ipv6MplsLabeledVpn) => {
                let (mp_buf, next_hop) =
                    parse_labeled_next_hop(mp_buf, AddressType::Ipv6MplsLabeledVpn)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::Ipv6MplsLabeledVpn)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    false,
                    *multiple_labels
                        .get(&AddressType::Ipv6MplsLabeledVpn)
                        .unwrap_or(&1),
                )?;
                Ok((buf, MpReach::Ipv6MplsVpnUnicast { next_hop, nlri }))
            }
            Ok(AddressType::L2VpnBgpEvpn) => {
                let (mp_buf, next_hop) = parse_ip_next_hop(mp_buf, AddressType::L2VpnBgpEvpn)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::L2VpnBgpEvpn)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpReach::L2Evpn { next_hop, nlri }))
            }
            Ok(AddressType::RouteTargetConstrains) => {
                let (mp_buf, next_hop) =
                    parse_ip_next_hop(mp_buf, AddressType::RouteTargetConstrains)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map
                    .get(&AddressType::L2VpnBgpEvpn)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpReach::RouteTargetMembership { next_hop, nlri }))
            }
            Ok(AddressType::BgpLs) => {
                let (mp_buf, next_hop) = parse_ip_next_hop(mp_buf, AddressType::BgpLs)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map.get(&AddressType::BgpLs).is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpReach::BgpLs { next_hop, nlri }))
            }
            Ok(AddressType::BgpLsVpn) => {
                let (mp_buf, next_hop) = parse_labeled_next_hop(mp_buf, AddressType::BgpLsVpn)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let add_path = add_path_map.get(&AddressType::BgpLsVpn).is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpReach::BgpLsVpn { next_hop, nlri }))
            }
            Ok(_) | Err(_) => Ok((
                buf,
                MpReach::Unknown {
                    afi,
                    safi,
                    value: mp_buf.to_vec(),
                },
            )),
        }
    }
}

#[inline]
fn parse_ip_next_hop(
    mp_buf: Span<'_>,
    address_type: AddressType,
) -> IResult<Span<'_>, IpAddr, LocatedMpReachParsingError<'_>> {
    let (mp_buf, next_hop) = match IpAddr::from_wire(mp_buf) {
        Ok((mp_buf, next_hop)) => (mp_buf, next_hop),
        Err(err) => {
            return Err(match err {
                nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
                nom::Err::Error(error) => {
                    let (e, s) = (error.error, error.span);
                    nom::Err::Error(LocatedMpReachParsingError::new(
                        s,
                        MpReachParsingError::IpAddrError(address_type, e),
                    ))
                }
                nom::Err::Failure(failure) => {
                    let (e, s) = (failure.error, failure.span);
                    nom::Err::Failure(LocatedMpReachParsingError::new(
                        s,
                        MpReachParsingError::IpAddrError(address_type, e),
                    ))
                }
            });
        }
    };
    Ok((mp_buf, next_hop))
}

#[inline]
fn parse_ip4_or_ipv6_next_hop(
    mp_buf: Span<'_>,
    address_type: AddressType,
) -> IResult<Span<'_>, (IpAddr, Option<Ipv6Addr>), LocatedMpReachParsingError<'_>> {
    let begin_buf = mp_buf;
    let (mp_buf, next_hop_len) = be_u8(mp_buf)?;
    match next_hop_len {
        IPV4_LEN => {
            let (mp_buf, next_hop) = be_u32(mp_buf)?;
            let next_hop = Ipv4Addr::from(next_hop);
            Ok((mp_buf, (IpAddr::V4(next_hop), None)))
        }
        IPV6_LEN => {
            let (mp_buf, next_hop) = be_u128(mp_buf)?;
            let next_hop = Ipv6Addr::from(next_hop);
            Ok((mp_buf, (IpAddr::V6(next_hop), None)))
        }
        IPV6_WITH_LINK_LOCAL_LEN => {
            let (mp_buf, next_hop) = be_u128(mp_buf)?;
            let (mp_buf, next_hop_local) = be_u128(mp_buf)?;
            let next_hop = Ipv6Addr::from(next_hop);
            let next_hop_local = Ipv6Addr::from(next_hop_local);
            Ok((mp_buf, (IpAddr::V6(next_hop), Some(next_hop_local))))
        }
        _ => Err(nom::Err::Error(LocatedMpReachParsingError::new(
            begin_buf,
            MpReachParsingError::IpAddrError(
                address_type,
                IpAddrParsingError::InvalidIpAddressLength(next_hop_len),
            ),
        ))),
    }
}

#[inline]
fn parse_labeled_next_hop(
    mp_buf: Span<'_>,
    address_type: AddressType,
) -> IResult<Span<'_>, LabeledNextHop, LocatedMpReachParsingError<'_>> {
    let (mp_buf, next_hop) = match LabeledNextHop::from_wire(mp_buf) {
        Ok((mp_buf, next_hop)) => (mp_buf, next_hop),
        Err(err) => {
            return Err(match err {
                nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
                nom::Err::Error(error) => {
                    let (e, s) = (error.error().clone(), *error.span());
                    nom::Err::Error(LocatedMpReachParsingError::new(
                        s,
                        MpReachParsingError::LabeledNextHopError(address_type, e),
                    ))
                }
                nom::Err::Failure(failure) => {
                    let (e, s) = (failure.error().clone(), *failure.span());
                    nom::Err::Failure(LocatedMpReachParsingError::new(
                        s,
                        MpReachParsingError::LabeledNextHopError(address_type, e),
                    ))
                }
            });
        }
    };
    Ok((mp_buf, next_hop))
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MpUnreachParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    Ipv4UnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4UnicastAddressParsingError,
    ),
    Ipv4MulticastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv4MulticastAddressParsingError,
    ),
    Ipv4NlriMplsLabelsAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv4NlriMplsLabelsAddressParsingError,
    ),
    Ipv4MplsVpnUnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv4MplsVpnUnicastAddressParsingError,
    ),
    Ipv6UnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6UnicastAddressParsingError,
    ),
    Ipv6MulticastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv6MulticastAddressParsingError,
    ),
    Ipv6NlriMplsLabelsAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv6NlriMplsLabelsAddressParsingError,
    ),
    Ipv6MplsVpnUnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        Ipv6MplsVpnUnicastAddressParsingError,
    ),
    L2EvpnAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] L2EvpnAddressParsingError,
    ),
    RouteTargetMembershipAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")]
        RouteTargetMembershipAddressParsingError,
    ),
    BgpLsError(#[from_located(module = "crate::wire::deserializer::nlri")] BgpLsNlriParsingError),
}

impl<'a>
    ReadablePduWithThreeInputs<
        'a,
        bool,
        &HashMap<AddressType, u8>,
        &HashMap<AddressType, bool>,
        LocatedMpUnreachParsingError<'a>,
    > for MpUnreach
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
        multiple_labels: &HashMap<AddressType, u8>,
        add_path_map: &HashMap<AddressType, bool>,
    ) -> IResult<Span<'a>, Self, LocatedMpUnreachParsingError<'a>> {
        let (buf, mp_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (mp_buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(mp_buf)?;
        let (mp_buf, safi) =
            nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(mp_buf)?;
        match AddressType::from_afi_safi(afi, safi) {
            Ok(AddressType::Ipv4Unicast) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv4Unicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::Ipv4Unicast { nlri }))
            }
            Ok(AddressType::Ipv4Multicast) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv4Multicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::Ipv4Multicast { nlri }))
            }
            Ok(AddressType::Ipv4NlriMplsLabels) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv4NlriMplsLabels)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    true,
                    *multiple_labels
                        .get(&AddressType::Ipv4NlriMplsLabels)
                        .unwrap_or(&1),
                )?;
                Ok((buf, MpUnreach::Ipv4NlriMplsLabels { nlri }))
            }
            Ok(AddressType::Ipv4MplsLabeledVpn) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv4Multicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    true,
                    *multiple_labels
                        .get(&AddressType::Ipv4MplsLabeledVpn)
                        .unwrap_or(&1),
                )?;
                Ok((buf, MpUnreach::Ipv4MplsVpnUnicast { nlri }))
            }
            Ok(AddressType::Ipv6Unicast) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv6Unicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::Ipv6Unicast { nlri }))
            }
            Ok(AddressType::Ipv6Multicast) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv6Multicast)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::Ipv6Multicast { nlri }))
            }
            Ok(AddressType::Ipv6NlriMplsLabels) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv6NlriMplsLabels)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    true,
                    *multiple_labels
                        .get(&AddressType::Ipv6NlriMplsLabels)
                        .unwrap_or(&1),
                )?;
                Ok((buf, MpUnreach::Ipv6NlriMplsLabels { nlri }))
            }
            Ok(AddressType::Ipv6MplsLabeledVpn) => {
                let add_path = add_path_map
                    .get(&AddressType::Ipv6MplsLabeledVpn)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_three_inputs_located(
                    mp_buf,
                    add_path,
                    true,
                    *multiple_labels
                        .get(&AddressType::Ipv6MplsLabeledVpn)
                        .unwrap_or(&1),
                )?;
                Ok((buf, MpUnreach::Ipv6MplsVpnUnicast { nlri }))
            }
            Ok(AddressType::L2VpnBgpEvpn) => {
                let add_path = add_path_map
                    .get(&AddressType::L2VpnBgpEvpn)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::L2Evpn { nlri }))
            }
            Ok(AddressType::RouteTargetConstrains) => {
                let add_path = add_path_map
                    .get(&AddressType::RouteTargetConstrains)
                    .is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::L2Evpn { nlri }))
            }
            Ok(AddressType::BgpLs) => {
                let add_path = add_path_map.get(&AddressType::BgpLs).is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::BgpLs { nlri }))
            }
            Ok(AddressType::BgpLsVpn) => {
                let add_path = add_path_map.get(&AddressType::BgpLsVpn).is_some_and(|x| *x);
                let (_, nlri) = parse_till_empty_into_with_one_input_located(mp_buf, add_path)?;
                Ok((buf, MpUnreach::BgpLsVpn { nlri }))
            }
            Ok(_) | Err(_) => Ok((
                buf,
                MpUnreach::Unknown {
                    afi,
                    safi,
                    nlri: mp_buf.to_vec(),
                },
            )),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UnknownAttributeParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength {
        expecting: usize,
        actual: usize,
    },
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedUnknownAttributeParsingError<'a>>
    for UnknownAttribute
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedUnknownAttributeParsingError<'a>> {
        let (buf, code) = be_u8(buf)?;
        let input = buf;
        let (buf, len) = if extended_length {
            let (buf, len) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(len))
        } else {
            let (buf, len) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(len))
        };
        let length: u16 = len.into();
        if length as usize > buf.len() {
            return Err(nom::Err::Error(LocatedUnknownAttributeParsingError::new(
                input,
                UnknownAttributeParsingError::InvalidLength {
                    expecting: length as usize,
                    actual: buf.len(),
                },
            )));
        }
        let (buf, value) = nom::bytes::complete::take(length)(buf)?;

        Ok((buf, UnknownAttribute::new(code, (*value.fragment()).into())))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum CommunitiesParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    CommunityError(
        #[from_located(module = "crate::wire::deserializer::community")] CommunityParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedCommunitiesParsingError<'a>> for Communities {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedCommunitiesParsingError<'a>> {
        let (buf, communities_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_, communities) = parse_till_empty_into_located(communities_buf)?;
        Ok((buf, Communities::new(communities)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunitiesParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    ExtendedCommunityError(
        #[from_located(module = "crate::wire::deserializer::community")]
        ExtendedCommunityParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedExtendedCommunitiesParsingError<'a>>
    for ExtendedCommunities
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedExtendedCommunitiesParsingError<'a>> {
        let (buf, communities_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_, communities) = parse_till_empty_into_located(communities_buf)?;
        Ok((buf, ExtendedCommunities::new(communities)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunitiesIpv6ParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    ExtendedCommunityIpv6Error(
        #[from_located(module = "crate::wire::deserializer::community")]
        ExtendedCommunityIpv6ParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedExtendedCommunitiesIpv6ParsingError<'a>>
    for ExtendedCommunitiesIpv6
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedExtendedCommunitiesIpv6ParsingError<'a>> {
        let (buf, communities_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_, communities) = parse_till_empty_into_located(communities_buf)?;
        Ok((buf, ExtendedCommunitiesIpv6::new(communities)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LargeCommunitiesParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    LargeCommunityError(
        #[from_located(module = "crate::wire::deserializer::community")] LargeCommunityParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedLargeCommunitiesParsingError<'a>>
    for LargeCommunities
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedLargeCommunitiesParsingError<'a>> {
        let (buf, communities_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_, communities) = parse_till_empty_into_located(communities_buf)?;
        Ok((buf, LargeCommunities::new(communities)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OriginatorParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedOriginatorParsingError<'a>> for Originator {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedOriginatorParsingError<'a>> {
        let (buf, data_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_buf, id) = be_u32(data_buf)?;
        Ok((buf, Originator::new(Ipv4Addr::from(id))))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ClusterIdParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedClusterIdParsingError<'a>> for ClusterId {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedClusterIdParsingError<'a>> {
        let (buf, id) = be_u32(buf)?;
        Ok((buf, ClusterId::new(Ipv4Addr::from(id))))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ClusterListParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    ClusterIdError(#[from_located(module = "self")] ClusterIdParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedClusterListParsingError<'a>> for ClusterList {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedClusterListParsingError<'a>> {
        let (buf, data_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_, cluster_ids) = parse_till_empty_into_located(data_buf)?;
        Ok((buf, ClusterList::new(cluster_ids)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AigpParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedAigpAttributeType(#[from_external] UndefinedAigpAttributeType),
    InvalidLength(u16),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedAigpParsingError<'a>> for Aigp {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedAigpParsingError<'a>> {
        let (buf, data_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (data_buf, aigp_type) =
            nom::combinator::map_res(be_u8, AigpAttributeType::try_from)(data_buf)?;
        match aigp_type {
            AigpAttributeType::AccumulatedIgpMetric => {
                let input = data_buf;
                let (data_buf, length) = be_u16(data_buf)?;
                if length != ACCUMULATED_IGP_METRIC {
                    return Err(nom::Err::Error(LocatedAigpParsingError::new(
                        input,
                        AigpParsingError::InvalidLength(length),
                    )));
                }
                let (_buf, metric) = be_u64(data_buf)?;
                Ok((buf, Aigp::AccumulatedIgpMetric(metric)))
            }
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OnlyToCustomerParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedOnlyToCustomerParsingError<'a>>
    for OnlyToCustomer
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedOnlyToCustomerParsingError<'a>> {
        let (buf, data_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let (_buf, asn) = be_u32(data_buf)?;
        Ok((buf, OnlyToCustomer::new(asn)))
    }
}
