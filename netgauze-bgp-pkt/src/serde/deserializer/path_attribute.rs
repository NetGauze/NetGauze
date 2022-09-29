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
    path_attribute::{
        AS4Path, ASPath, Aggregator, As2Aggregator, As2PathSegment, As4Aggregator, As4PathSegment,
        AsPathSegmentType, AtomicAggregate, Communities, Community, LocalPreference, MpReach,
        MpUnreach, MultiExitDiscriminator, NextHop, Origin, PathAttribute, PathAttributeLength,
        UndefinedAsPathSegmentType, UndefinedOrigin, UnknownAttribute,
    },
    serde::deserializer::{
        nlri::{
            Ipv4MulticastParsingError, Ipv4UnicastParsingError, Ipv6MulticastParsingError,
            Ipv6UnicastParsingError,
        },
        update::LocatedBGPUpdateMessageParsingError,
        BGPUpdateMessageParsingError,
    },
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
    UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{
    parse_into_located_one_input, parse_into_located_three_inputs, parse_into_located_two_inputs,
    parse_till_empty, parse_till_empty_into_located, IntoLocatedError, LocatedParsingError,
    ReadablePDU, ReadablePDUWithOneInput, ReadablePDUWithThreeInputs, ReadablePDUWithTwoInputs,
    Span,
};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u128, be_u16, be_u32, be_u8},
    IResult,
};
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum PathAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    OriginError(OriginParsingError),
    AsPathError(AsPathParsingError),
    NextHopError(NextHopParsingError),
    MultiExitDiscriminatorError(MultiExitDiscriminatorParsingError),
    LocalPreferenceError(LocalPreferenceParsingError),
    AtomicAggregateError(AtomicAggregateParsingError),
    AggregatorError(AggregatorParsingError),
    CommunitiesError(CommunitiesParsingError),
    MpReachErrorError(MpReachParsingError),
    MpUnreachErrorError(MpUnreachParsingError),
    UnknownAttributeError(UnknownAttributeParsingError),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedPathAttributeParsingError<'a> {
    span: Span<'a>,
    error: PathAttributeParsingError,
}

impl<'a> LocatedPathAttributeParsingError<'a> {
    pub const fn new(span: Span<'a>, error: PathAttributeParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedPathAttributeParsingError<'a> {
    type Span = Span<'a>;
    type Error = PathAttributeParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedBGPUpdateMessageParsingError<'a>>
    for LocatedPathAttributeParsingError<'a>
{
    fn into_located(self) -> LocatedBGPUpdateMessageParsingError<'a> {
        LocatedBGPUpdateMessageParsingError::new(
            self.span,
            BGPUpdateMessageParsingError::PathAttributeError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, PathAttributeParsingError>
    for LocatedPathAttributeParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: PathAttributeParsingError,
    ) -> Self {
        LocatedPathAttributeParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedPathAttributeParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedPathAttributeParsingError::new(input, PathAttributeParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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
        match PathAttributeType::try_from(code) {
            Ok(PathAttributeType::Origin) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::Origin {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::ASPath) => {
                let (buf, value) = parse_into_located_two_inputs(buf, extended_length, asn4)?;
                let path_attr = PathAttribute::ASPath {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::AS4Path) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::AS4Path {
                    partial,
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::NextHop) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::NextHop {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::MultiExitDiscriminator) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::MultiExitDiscriminator {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::LocalPreference) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::LocalPreference {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::AtomicAggregate) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::AtomicAggregate {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::Aggregator) => {
                let (buf, value) = parse_into_located_two_inputs(buf, extended_length, asn4)?;
                let path_attr = PathAttribute::Aggregator {
                    partial,
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::Communities) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::Communities {
                    partial,
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::MPReachNLRI) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::MpReach {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::MPUnreachNLRI) => {
                let (buf, value) = parse_into_located_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::MpUnreach {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(_code) => {
                let (buf, value) = parse_into_located_three_inputs(
                    buf_before_code,
                    optional,
                    transitive,
                    extended_length,
                )?;
                let path_attr = PathAttribute::UnknownAttribute { partial, value };
                Ok((buf, path_attr))
            }
            Err(UndefinedPathAttributeType(_code)) => {
                let (buf, value) = parse_into_located_three_inputs(
                    buf_before_code,
                    optional,
                    transitive,
                    extended_length,
                )?;
                let path_attr = PathAttribute::UnknownAttribute { partial, value };
                Ok((buf, path_attr))
            }
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum OriginParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidOriginLength(PathAttributeLength),
    UndefinedOrigin(UndefinedOrigin),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedOriginParsingError<'a> {
    span: Span<'a>,
    error: OriginParsingError,
}

impl<'a> LocatedOriginParsingError<'a> {
    pub const fn new(span: Span<'a>, error: OriginParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedOriginParsingError<'a> {
    type Span = Span<'a>;
    type Error = OriginParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>> for LocatedOriginParsingError<'a> {
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::OriginError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, OriginParsingError> for LocatedOriginParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: OriginParsingError) -> Self {
        LocatedOriginParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedOrigin> for LocatedOriginParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: UndefinedOrigin) -> Self {
        LocatedOriginParsingError::new(input, OriginParsingError::UndefinedOrigin(error))
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedOriginParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedOriginParsingError::new(input, OriginParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum AsPathParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedAsPathSegmentType(UndefinedAsPathSegmentType),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedAsPathParsingError<'a> {
    span: Span<'a>,
    error: AsPathParsingError,
}

impl<'a> LocatedAsPathParsingError<'a> {
    pub const fn new(span: Span<'a>, error: AsPathParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedAsPathParsingError<'a> {
    type Span = Span<'a>;
    type Error = AsPathParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>> for LocatedAsPathParsingError<'a> {
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::AsPathError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, AsPathParsingError> for LocatedAsPathParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: AsPathParsingError) -> Self {
        LocatedAsPathParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedAsPathParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedAsPathParsingError::new(input, AsPathParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedAsPathSegmentType> for LocatedAsPathParsingError<'a> {
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedAsPathSegmentType,
    ) -> Self {
        LocatedAsPathParsingError::new(input, AsPathParsingError::UndefinedAsPathSegmentType(error))
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum NextHopParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidNextHopLength(PathAttributeLength),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedNextHopParsingError<'a> {
    span: Span<'a>,
    error: NextHopParsingError,
}

impl<'a> LocatedNextHopParsingError<'a> {
    pub const fn new(span: Span<'a>, error: NextHopParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedNextHopParsingError<'a> {
    type Span = Span<'a>;
    type Error = NextHopParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>> for LocatedNextHopParsingError<'a> {
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::NextHopError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, NextHopParsingError> for LocatedNextHopParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: NextHopParsingError) -> Self {
        LocatedNextHopParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedNextHopParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedNextHopParsingError::new(input, NextHopParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MultiExitDiscriminatorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidLength(PathAttributeLength),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedMultiExitDiscriminatorParsingError<'a> {
    span: Span<'a>,
    error: MultiExitDiscriminatorParsingError,
}

impl<'a> LocatedMultiExitDiscriminatorParsingError<'a> {
    pub const fn new(span: Span<'a>, error: MultiExitDiscriminatorParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedMultiExitDiscriminatorParsingError<'a> {
    type Span = Span<'a>;
    type Error = MultiExitDiscriminatorParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>>
    for LocatedMultiExitDiscriminatorParsingError<'a>
{
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::MultiExitDiscriminatorError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, MultiExitDiscriminatorParsingError>
    for LocatedMultiExitDiscriminatorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: MultiExitDiscriminatorParsingError,
    ) -> Self {
        LocatedMultiExitDiscriminatorParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedMultiExitDiscriminatorParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedMultiExitDiscriminatorParsingError::new(
            input,
            MultiExitDiscriminatorParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum LocalPreferenceParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidLength(PathAttributeLength),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedLocalPreferenceParsingError<'a> {
    span: Span<'a>,
    error: LocalPreferenceParsingError,
}

impl<'a> LocatedLocalPreferenceParsingError<'a> {
    pub const fn new(span: Span<'a>, error: LocalPreferenceParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedLocalPreferenceParsingError<'a> {
    type Span = Span<'a>;
    type Error = LocalPreferenceParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>>
    for LocatedLocalPreferenceParsingError<'a>
{
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::LocalPreferenceError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, LocalPreferenceParsingError>
    for LocatedLocalPreferenceParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: LocalPreferenceParsingError,
    ) -> Self {
        LocatedLocalPreferenceParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedLocalPreferenceParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedLocalPreferenceParsingError::new(input, LocalPreferenceParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum AtomicAggregateParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidLength(PathAttributeLength),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedAtomicAggregateParsingError<'a> {
    span: Span<'a>,
    error: AtomicAggregateParsingError,
}

impl<'a> LocatedAtomicAggregateParsingError<'a> {
    pub const fn new(span: Span<'a>, error: AtomicAggregateParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedAtomicAggregateParsingError<'a> {
    type Span = Span<'a>;
    type Error = AtomicAggregateParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>>
    for LocatedAtomicAggregateParsingError<'a>
{
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::AtomicAggregateError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, AtomicAggregateParsingError>
    for LocatedAtomicAggregateParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: AtomicAggregateParsingError,
    ) -> Self {
        LocatedAtomicAggregateParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedAtomicAggregateParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedAtomicAggregateParsingError::new(input, AtomicAggregateParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum AggregatorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidLength(PathAttributeLength),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedAggregatorParsingError<'a> {
    span: Span<'a>,
    error: AggregatorParsingError,
}

impl<'a> LocatedAggregatorParsingError<'a> {
    pub const fn new(span: Span<'a>, error: AggregatorParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedAggregatorParsingError<'a> {
    type Span = Span<'a>;
    type Error = AggregatorParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>>
    for LocatedAggregatorParsingError<'a>
{
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::AggregatorError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, AggregatorParsingError> for LocatedAggregatorParsingError<'a> {
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: AggregatorParsingError,
    ) -> Self {
        LocatedAggregatorParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedAggregatorParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedAggregatorParsingError::new(input, AggregatorParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MpReachParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedAddressFamily(UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
    /// MP-BGP is not yet implemented for the given address type
    UnknownAddressType(AddressType),
    Ipv4UnicastError(Ipv4UnicastParsingError),
    Ipv4MulticastError(Ipv4MulticastParsingError),
    Ipv6UnicastError(Ipv6UnicastParsingError),
    Ipv6MulticastError(Ipv6MulticastParsingError),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedMpReachParsingError<'a> {
    span: Span<'a>,
    error: MpReachParsingError,
}

impl<'a> LocatedMpReachParsingError<'a> {
    pub const fn new(span: Span<'a>, error: MpReachParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedMpReachParsingError<'a> {
    type Span = Span<'a>;
    type Error = MpReachParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>> for LocatedMpReachParsingError<'a> {
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::MpReachErrorError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, MpReachParsingError> for LocatedMpReachParsingError<'a> {
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: MpReachParsingError) -> Self {
        LocatedMpReachParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedMpReachParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedMpReachParsingError::new(input, MpReachParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedAddressFamily> for LocatedMpReachParsingError<'a> {
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedAddressFamily,
    ) -> Self {
        LocatedMpReachParsingError::new(input, MpReachParsingError::UndefinedAddressFamily(error))
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedSubsequentAddressFamily>
    for LocatedMpReachParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedSubsequentAddressFamily,
    ) -> Self {
        LocatedMpReachParsingError::new(
            input,
            MpReachParsingError::UndefinedSubsequentAddressFamily(error),
        )
    }
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
        let (mp_buf, next_hop_len) = be_u8(mp_buf)?;
        match address_type {
            AddressType::Ipv4Unicast => {
                let (mp_buf, next_hop) = be_u32(mp_buf)?;
                let next_hop = Ipv4Addr::from(next_hop);
                let (mp_buf, _) = be_u8(mp_buf)?;
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpReach::Ipv4Unicast { next_hop, nlri }))
            }
            AddressType::Ipv4Multicast => {
                let (mp_buf, next_hop) = be_u32(mp_buf)?;
                let next_hop = Ipv4Addr::from(next_hop);
                let (mp_buf, _) = be_u8(mp_buf)?;
                let (_, nlri) = parse_till_empty_into_located(mp_buf)?;
                Ok((buf, MpReach::Ipv4Multicast { next_hop, nlri }))
            }
            AddressType::IpPv4MplsLabeledVpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::IpPv4MplsLabeledVpn),
                )))
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
            AddressType::Ipv6MPLSLabeledVpn => {
                return Err(nom::Err::Error(LocatedMpReachParsingError::new(
                    mp_buf_begin,
                    MpReachParsingError::UnknownAddressType(AddressType::Ipv6MPLSLabeledVpn),
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MpUnreachParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedAddressFamily(UndefinedAddressFamily),
    UndefinedSubsequentAddressFamily(UndefinedSubsequentAddressFamily),
    InvalidAddressType(InvalidAddressType),
    /// MP-BGP is not yet implemented for the given address type
    UnknownAddressType(AddressType),
    Ipv4UnicastError(Ipv4UnicastParsingError),
    Ipv4MulticastError(Ipv4MulticastParsingError),
    Ipv6UnicastError(Ipv6UnicastParsingError),
    Ipv6MulticastError(Ipv6MulticastParsingError),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedMpUnreachParsingError<'a> {
    span: Span<'a>,
    error: MpUnreachParsingError,
}

impl<'a> LocatedMpUnreachParsingError<'a> {
    pub const fn new(span: Span<'a>, error: MpUnreachParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedMpUnreachParsingError<'a> {
    type Span = Span<'a>;
    type Error = MpUnreachParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>>
    for LocatedMpUnreachParsingError<'a>
{
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::MpUnreachErrorError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, MpUnreachParsingError> for LocatedMpUnreachParsingError<'a> {
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: MpUnreachParsingError,
    ) -> Self {
        LocatedMpUnreachParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedMpUnreachParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedMpUnreachParsingError::new(input, MpUnreachParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedAddressFamily> for LocatedMpUnreachParsingError<'a> {
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedAddressFamily,
    ) -> Self {
        LocatedMpUnreachParsingError::new(
            input,
            MpUnreachParsingError::UndefinedAddressFamily(error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedSubsequentAddressFamily>
    for LocatedMpUnreachParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedSubsequentAddressFamily,
    ) -> Self {
        LocatedMpUnreachParsingError::new(
            input,
            MpUnreachParsingError::UndefinedSubsequentAddressFamily(error),
        )
    }
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
            AddressType::IpPv4MplsLabeledVpn => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::IpPv4MplsLabeledVpn),
                )))
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
            AddressType::Ipv6MPLSLabeledVpn => {
                return Err(nom::Err::Error(LocatedMpUnreachParsingError::new(
                    mp_buf_begin,
                    MpUnreachParsingError::UnknownAddressType(AddressType::Ipv6MPLSLabeledVpn),
                )))
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum UnknownAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedUnknownAttributeParsingError<'a> {
    span: Span<'a>,
    error: UnknownAttributeParsingError,
}

impl<'a> LocatedUnknownAttributeParsingError<'a> {
    pub const fn new(span: Span<'a>, error: UnknownAttributeParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedUnknownAttributeParsingError<'a> {
    type Span = Span<'a>;
    type Error = UnknownAttributeParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>>
    for LocatedUnknownAttributeParsingError<'a>
{
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::UnknownAttributeError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, UnknownAttributeParsingError>
    for LocatedUnknownAttributeParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UnknownAttributeParsingError,
    ) -> Self {
        LocatedUnknownAttributeParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedUnknownAttributeParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedUnknownAttributeParsingError::new(
            input,
            UnknownAttributeParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> ReadablePDUWithThreeInputs<'a, bool, bool, bool, LocatedUnknownAttributeParsingError<'a>>
    for UnknownAttribute
{
    fn from_wire(
        buf: Span<'a>,
        optional: bool,
        transitive: bool,
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

        Ok((
            buf,
            UnknownAttribute::new(optional, transitive, code, len, (*value.fragment()).into()),
        ))
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum CommunitiesParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedCommunitiesParsingError<'a> {
    span: Span<'a>,
    error: CommunitiesParsingError,
}

impl<'a> LocatedCommunitiesParsingError<'a> {
    pub const fn new(span: Span<'a>, error: CommunitiesParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedCommunitiesParsingError<'a> {
    type Span = Span<'a>;
    type Error = CommunitiesParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedPathAttributeParsingError<'a>>
    for LocatedCommunitiesParsingError<'a>
{
    fn into_located(self) -> LocatedPathAttributeParsingError<'a> {
        LocatedPathAttributeParsingError::new(
            self.span,
            PathAttributeParsingError::CommunitiesError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, CommunitiesParsingError>
    for LocatedCommunitiesParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: CommunitiesParsingError,
    ) -> Self {
        LocatedCommunitiesParsingError::new(input, error)
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedCommunitiesParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedCommunitiesParsingError::new(input, CommunitiesParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
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
        let (_, communities) = parse_till_empty(communities_buf)?;
        Ok((buf, Communities::new(communities)))
    }
}

impl<'a> ReadablePDU<'a, LocatedCommunitiesParsingError<'a>> for Community {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedCommunitiesParsingError<'a>> {
        let (buf, value) = be_u32(buf)?;
        Ok((buf, Community::new(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_parse_utils::Span;
    use nom::error::ErrorKind;

    #[test]
    fn test_located_path_attribute_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = PathAttributeParsingError::NomError(ErrorKind::Eof);

        let located = LocatedPathAttributeParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }

    #[test]
    fn test_located_origin_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = OriginParsingError::NomError(ErrorKind::Eof);

        let located = LocatedOriginParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }

    #[test]
    fn test_located_as_path_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = AsPathParsingError::NomError(ErrorKind::Eof);

        let located = LocatedAsPathParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }

    #[test]
    fn test_located_next_hop_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = NextHopParsingError::NomError(ErrorKind::Eof);

        let located = LocatedNextHopParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }

    #[test]
    fn test_located_med_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = MultiExitDiscriminatorParsingError::NomError(ErrorKind::Eof);

        let located = LocatedMultiExitDiscriminatorParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }

    #[test]
    fn test_located_atomic_aggregate_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = AtomicAggregateParsingError::NomError(ErrorKind::Eof);

        let located = LocatedAtomicAggregateParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }

    #[test]
    fn test_located_aggregate_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = AggregatorParsingError::NomError(ErrorKind::Eof);

        let located = LocatedAggregatorParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }

    #[test]
    fn test_located_unknown_attr_parsing_error() {
        let span = Span::new(&[1, 1, 3]);
        let error = UnknownAttributeParsingError::NomError(ErrorKind::Eof);

        let located = LocatedUnknownAttributeParsingError::new(span, error.clone());

        assert_eq!(located.span().location_offset(), span.location_offset());
        assert_eq!(located.span().fragment(), span.fragment());
        assert_eq!(located.error(), &error);
    }
}
