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

//! Deserializer for BGP Path Attributes

use crate::{
    iana::{PathAttributeType, UndefinedPathAttributeType},
    path_attribute::*,
    wire::deserializer::{community::*, nlri::*},
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
    UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_into_located_two_inputs,
    parse_till_empty, parse_till_empty_into_located, ErrorKindSerdeDeref, ReadablePDU,
    ReadablePDUWithOneInput, ReadablePDUWithTwoInputs, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

const OPTIONAL_PATH_ATTRIBUTE_MASK: u8 = 0x80;
const TRANSITIVE_PATH_ATTRIBUTE_MASK: u8 = 0x40;
const PARTIAL_PATH_ATTRIBUTE_MASK: u8 = 0x20;
const EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK: u8 = 0x10;
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum PathAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
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
    MpReachErrorError(#[from_located(module = "self")] MpReachParsingError),
    MpUnreachErrorError(#[from_located(module = "self")] MpUnreachParsingError),
    UnknownAttributeError(#[from_located(module = "self")] UnknownAttributeParsingError),
    InvalidPathAttribute(InvalidPathAttribute),
}

pub trait IntoLocatedPathAttributeParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a>;
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedPathAttributeParsingError<'a>> for PathAttribute {
    fn from_wire(
        buf: Span<'a>,
        asn4: bool,
    ) -> IResult<Span<'a>, Self, LocatedPathAttributeParsingError<'a>> {
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
            Ok(PathAttributeType::ASPath) => {
                let (buf, value) = parse_into_located_two_inputs(buf, extended_length, asn4)?;
                let value = PathAttributeValue::ASPath(value);
                (buf, value)
            }
            Ok(PathAttributeType::AS4Path) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::AS4Path(value);
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
            Ok(PathAttributeType::MPReachNLRI) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::MpReach(value);
                (buf, value)
            }
            Ok(PathAttributeType::MPUnreachNLRI) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let value = PathAttributeValue::MpUnreach(value);
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
            Err(err) => {
                return Err(nom::Err::Error(LocatedPathAttributeParsingError::new(
                    buf,
                    PathAttributeParsingError::InvalidPathAttribute(err),
                )))
            }
        };
        Ok((buf, attr))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OriginParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidOriginLength(#[from_external] PathAttributeLength),
    UndefinedOrigin(#[from_external] UndefinedOrigin),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedOriginParsingError<'a>> for Origin {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AsPathParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedAsPathSegmentType(#[from_external] UndefinedAsPathSegmentType),
}

impl<'a> ReadablePDUWithTwoInputs<'a, bool, bool, LocatedAsPathParsingError<'a>> for ASPath {
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

impl<'a> ReadablePDU<'a, LocatedAsPathParsingError<'a>> for As2PathSegment {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedAsPathParsingError<'a>> {
        let (buf, segment_type) =
            nom::combinator::map_res(be_u8, AsPathSegmentType::try_from)(buf)?;
        let (buf, as_numbers) = nom::multi::length_count(be_u8, be_u16)(buf)?;
        Ok((buf, As2PathSegment::new(segment_type, as_numbers)))
    }
}

impl<'a> ReadablePDU<'a, LocatedAsPathParsingError<'a>> for As4PathSegment {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedAsPathParsingError<'a>> {
        let (buf, segment_type) =
            nom::combinator::map_res(be_u8, AsPathSegmentType::try_from)(buf)?;
        let (buf, as_numbers) = nom::multi::length_count(be_u8, be_u32)(buf)?;
        Ok((buf, As4PathSegment::new(segment_type, as_numbers)))
    }
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedAsPathParsingError<'a>> for AS4Path {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NextHopParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidNextHopLength(PathAttributeLength),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedNextHopParsingError<'a>> for NextHop {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MultiExitDiscriminatorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedMultiExitDiscriminatorParsingError<'a>>
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LocalPreferenceParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedLocalPreferenceParsingError<'a>>
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AtomicAggregateParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedAtomicAggregateParsingError<'a>>
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AggregatorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(PathAttributeLength),
}

impl<'a> ReadablePDUWithTwoInputs<'a, bool, bool, LocatedAggregatorParsingError<'a>>
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

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedAggregatorParsingError<'a>> for As2Aggregator {
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

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedAggregatorParsingError<'a>> for As4Aggregator {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MpReachParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
    /// MP-BGP is not yet implemented for the given address type
    UnknownAddressType(AddressType),
    Ipv4UnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4UnicastParsingError,
    ),
    Ipv4MulticastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4MulticastParsingError,
    ),
    Ipv4MplsVpnUnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4MplsVpnUnicastParsingError,
    ),
    Ipv6UnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6UnicastParsingError,
    ),
    Ipv6MulticastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6MulticastParsingError,
    ),
    Ipv6MplsVpnUnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6MplsVpnUnicastParsingError,
    ),
    LabeledNextHopError(
        #[from_located(module = "crate::wire::deserializer::nlri")] LabeledNextHopParsingError,
    ),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedMpReachParsingError<'a>> for MpReach {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedMpReachParsingError<'a>> {
        let (buf, mp_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let mp_buf_begin = mp_buf;
        let (mp_buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(mp_buf)?;
        let (mp_buf, safi) =
            nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(mp_buf)?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(val) => val,
            Err(err) => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::InvalidAddressType(err),
                )))
            }
        };
        match address_type {
            AddressType::Ipv4Unicast => {
                let (mp_buf, _next_hop_len) = be_u8(mp_buf)?;
                let (mp_buf, next_hop) = be_u32(mp_buf)?;
                let next_hop = Ipv4Addr::from(next_hop);
                let (mp_buf, _) = be_u8(mp_buf)?;
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpReach::Ipv4Unicast { next_hop, nlri }))
            }
            AddressType::Ipv4Multicast => {
                let (mp_buf, _next_hop_len) = be_u8(mp_buf)?;
                let (mp_buf, next_hop) = be_u32(mp_buf)?;
                let next_hop = Ipv4Addr::from(next_hop);
                let (mp_buf, _) = be_u8(mp_buf)?;
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpReach::Ipv4Multicast { next_hop, nlri }))
            }
            AddressType::Ipv4MplsLabeledVpn => {
                let (mp_buf, next_hop) = parse_into_located(mp_buf)?;
                let (mp_buf, _) = be_u8(mp_buf)?;
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpReach::Ipv4MplsVpnUnicast { next_hop, nlri }))
            }
            AddressType::Ipv4MulticastBgpMplsVpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv4MulticastBgpMplsVpn),
                )))
            }
            AddressType::Ipv4Bgp4over6 => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv4Bgp4over6),
                )))
            }
            AddressType::Ipv4FlowSpec => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv4FlowSpec),
                )))
            }
            AddressType::Ipv4FlowSpecL3Vpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv4FlowSpecL3Vpn),
                )))
            }
            AddressType::Ipv4NlriMplsLabels => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv4NlriMplsLabels),
                )))
            }
            AddressType::Ipv6Unicast => {
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
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((
                    buf,
                    MpReach::Ipv6Unicast {
                        next_hop_global,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            AddressType::Ipv6Multicast => {
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
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((
                    buf,
                    MpReach::Ipv6Multicast {
                        next_hop_global,
                        next_hop_local,
                        nlri,
                    },
                ))
            }
            AddressType::Ipv6MplsLabeledVpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv6MplsLabeledVpn),
                )))
            }
            AddressType::Ipv6MulticastBgpMplsVpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv6MulticastBgpMplsVpn),
                )))
            }
            AddressType::Ipv6Bgp6over4 => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv6Bgp6over4),
                )))
            }
            AddressType::Ipv6FlowSpec => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv6FlowSpec),
                )))
            }
            AddressType::Ipv6FlowSpecL3Vpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv6FlowSpecL3Vpn),
                )))
            }
            AddressType::Ipv6NlriMplsLabels => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv6NlriMplsLabels),
                )))
            }
            AddressType::L2VpnBgpEvpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::L2VpnBgpEvpn),
                )))
            }
            AddressType::BgpLs => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::BgpLs),
                )))
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MpUnreachParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedAddressFamily(#[from_external] UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(#[from_external] UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
    /// MP-BGP is not yet implemented for the given address type
    UnknownAddressType(AddressType),
    Ipv4UnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4UnicastParsingError,
    ),
    Ipv4MulticastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4MulticastParsingError,
    ),
    Ipv4MplsVpnUnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4MplsVpnUnicastParsingError,
    ),
    Ipv6UnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6UnicastParsingError,
    ),
    Ipv6MulticastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6MulticastParsingError,
    ),
    Ipv6MplsVpnUnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv6MplsVpnUnicastParsingError,
    ),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedMpUnreachParsingError<'a>> for MpUnreach {
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedMpUnreachParsingError<'a>> {
        let (buf, mp_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };
        let mp_buf_begin = mp_buf;
        let (mp_buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(mp_buf)?;
        let (mp_buf, safi) =
            nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(mp_buf)?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(val) => val,
            Err(err) => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::InvalidAddressType(err),
                )))
            }
        };
        match address_type {
            AddressType::Ipv4Unicast => {
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpUnreach::Ipv4Unicast { nlri }))
            }
            AddressType::Ipv4Multicast => {
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpUnreach::Ipv4Multicast { nlri }))
            }
            AddressType::Ipv4MplsLabeledVpn => {
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpUnreach::Ipv4MplsVpnUnicast { nlri }))
            }
            AddressType::Ipv4MulticastBgpMplsVpn => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv4MulticastBgpMplsVpn),
                )))
            }
            AddressType::Ipv4Bgp4over6 => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv4Bgp4over6),
                )))
            }
            AddressType::Ipv4FlowSpec => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv4FlowSpec),
                )))
            }
            AddressType::Ipv4FlowSpecL3Vpn => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv4FlowSpecL3Vpn),
                )))
            }
            AddressType::Ipv4NlriMplsLabels => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv4NlriMplsLabels),
                )))
            }
            AddressType::Ipv6Unicast => {
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpUnreach::Ipv6Unicast { nlri }))
            }
            AddressType::Ipv6Multicast => {
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpUnreach::Ipv6Multicast { nlri }))
            }
            AddressType::Ipv6MplsLabeledVpn => {
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpUnreach::Ipv6MplsVpnUnicast { nlri }))
            }
            AddressType::Ipv6MulticastBgpMplsVpn => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv6MulticastBgpMplsVpn),
                )))
            }
            AddressType::Ipv6Bgp6over4 => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv6Bgp6over4),
                )))
            }
            AddressType::Ipv6FlowSpec => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv6FlowSpec),
                )))
            }
            AddressType::Ipv6FlowSpecL3Vpn => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv6FlowSpecL3Vpn),
                )))
            }
            AddressType::Ipv6NlriMplsLabels => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv6NlriMplsLabels),
                )))
            }
            AddressType::L2VpnBgpEvpn => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::L2VpnBgpEvpn),
                )))
            }
            AddressType::BgpLs => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::BgpLs),
                )))
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UnknownAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedUnknownAttributeParsingError<'a>>
    for UnknownAttribute
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedUnknownAttributeParsingError<'a>> {
        let (buf, code) = be_u8(buf)?;
        let (buf, len) = if extended_length {
            let (buf, len) = be_u16(buf)?;
            (buf, PathAttributeLength::U16(len))
        } else {
            let (buf, len) = be_u8(buf)?;
            (buf, PathAttributeLength::U8(len))
        };
        let length: u16 = len.into();
        let (buf, value) = nom::bytes::complete::take(length)(buf)?;

        Ok((buf, UnknownAttribute::new(code, (*value.fragment()).into())))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum CommunitiesParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    CommunityError(
        #[from_located(module = "crate::wire::deserializer::community")] CommunityParsingError,
    ),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedCommunitiesParsingError<'a>> for Communities {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunitiesParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    ExtendedCommunityError(
        #[from_located(module = "crate::wire::deserializer::community")]
        ExtendedCommunityParsingError,
    ),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedExtendedCommunitiesParsingError<'a>>
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunitiesIpv6ParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    ExtendedCommunityIpv6Error(
        #[from_located(module = "crate::wire::deserializer::community")]
        ExtendedCommunityIpv6ParsingError,
    ),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedExtendedCommunitiesIpv6ParsingError<'a>>
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LargeCommunitiesParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    LargeCommunityError(
        #[from_located(module = "crate::wire::deserializer::community")] LargeCommunityParsingError,
    ),
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedLargeCommunitiesParsingError<'a>>
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
