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
        AsPathSegmentType, AtomicAggregate, LocalPreference, MultiExitDiscriminator, NextHop,
        Origin, PathAttribute, PathAttributeLength, UndefinedAsPathSegmentType, UndefinedOrigin,
        UnknownAttribute,
    },
    serde::deserializer::{
        update::LocatedBGPUpdateMessageParsingError, BGPUpdateMessageParsingError,
    },
};
use netgauze_parse_utils::{
    parse_till_empty, ReadablePDU, ReadablePDUWithOneInput, ReadablePDUWithThreeInputs,
    ReadablePDUWithTwoInputs, Span,
};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use std::net::Ipv4Addr;

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

#[inline]
fn parse_path_attribute_with_one_input<
    'a,
    I,
    E: IntoLocatedPathAttributeParsingError<'a>,
    T: ReadablePDUWithOneInput<'a, I, E>,
>(
    buf: Span<'a>,
    input: I,
) -> IResult<Span<'a>, T, LocatedPathAttributeParsingError<'a>> {
    match T::from_wire(buf, input) {
        Ok((buf, value)) => Ok((buf, value)),
        Err(err) => {
            return match err {
                nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                nom::Err::Error(error) => Err(nom::Err::Error(
                    error.into_located_attribute_parsing_error(),
                )),
                nom::Err::Failure(failure) => Err(nom::Err::Failure(
                    failure.into_located_attribute_parsing_error(),
                )),
            }
        }
    }
}

#[inline]
fn parse_path_attribute_with_two_inputs<
    'a,
    I1,
    I2,
    E: IntoLocatedPathAttributeParsingError<'a>,
    T: ReadablePDUWithTwoInputs<'a, I1, I2, E>,
>(
    buf: Span<'a>,
    input1: I1,
    input2: I2,
) -> IResult<Span<'a>, T, LocatedPathAttributeParsingError<'a>> {
    match T::from_wire(buf, input1, input2) {
        Ok((buf, value)) => Ok((buf, value)),
        Err(err) => {
            return match err {
                nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                nom::Err::Error(error) => Err(nom::Err::Error(
                    error.into_located_attribute_parsing_error(),
                )),
                nom::Err::Failure(failure) => Err(nom::Err::Failure(
                    failure.into_located_attribute_parsing_error(),
                )),
            }
        }
    }
}

#[inline]
fn parse_path_attribute_with_three_inputs<
    'a,
    I1,
    I2,
    I3,
    E: IntoLocatedPathAttributeParsingError<'a>,
    T: ReadablePDUWithThreeInputs<'a, I1, I2, I3, E>,
>(
    buf: Span<'a>,
    input1: I1,
    input2: I2,
    input3: I3,
) -> IResult<Span<'a>, T, LocatedPathAttributeParsingError<'a>> {
    match T::from_wire(buf, input1, input2, input3) {
        Ok((buf, value)) => Ok((buf, value)),
        Err(err) => {
            return match err {
                nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                nom::Err::Error(error) => Err(nom::Err::Error(
                    error.into_located_attribute_parsing_error(),
                )),
                nom::Err::Failure(failure) => Err(nom::Err::Failure(
                    failure.into_located_attribute_parsing_error(),
                )),
            }
        }
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &PathAttributeParsingError {
        &self.error
    }

    pub const fn into_located_bgp_update_message_error(
        self,
    ) -> LocatedBGPUpdateMessageParsingError<'a> {
        let span = self.span;
        let error = self.error;
        LocatedBGPUpdateMessageParsingError::new(
            span,
            BGPUpdateMessageParsingError::PathAttributeError(error),
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
                let (buf, value) = parse_path_attribute_with_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::Origin {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::ASPath) => {
                let (buf, value) =
                    parse_path_attribute_with_two_inputs(buf, extended_length, asn4)?;
                let path_attr = PathAttribute::ASPath {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::AS4Path) => {
                let (buf, value) = parse_path_attribute_with_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::AS4Path {
                    partial,
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::NextHop) => {
                let (buf, value) = parse_path_attribute_with_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::NextHop {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::MultiExitDiscriminator) => {
                let (buf, value) = parse_path_attribute_with_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::MultiExitDiscriminator {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::LocalPreference) => {
                let (buf, value) = parse_path_attribute_with_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::LocalPreference {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::AtomicAggregate) => {
                let (buf, value) = parse_path_attribute_with_one_input(buf, extended_length)?;
                let path_attr = PathAttribute::AtomicAggregate {
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(PathAttributeType::Aggregator) => {
                let (buf, value) =
                    parse_path_attribute_with_two_inputs(buf, extended_length, asn4)?;
                let path_attr = PathAttribute::Aggregator {
                    partial,
                    extended_length,
                    value,
                };
                Ok((buf, path_attr))
            }
            Ok(_code) => {
                let (buf, value) = parse_path_attribute_with_three_inputs(
                    buf_before_code,
                    optional,
                    transitive,
                    extended_length,
                )?;
                let path_attr = PathAttribute::UnknownAttribute { partial, value };
                Ok((buf, path_attr))
            }
            Err(UndefinedPathAttributeType(_code)) => {
                let (buf, value) = parse_path_attribute_with_three_inputs(
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &OriginParsingError {
        &self.error
    }
}
impl<'a> IntoLocatedPathAttributeParsingError<'a> for LocatedOriginParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &AsPathParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedPathAttributeParsingError<'a> for LocatedAsPathParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &NextHopParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedPathAttributeParsingError<'a> for LocatedNextHopParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &MultiExitDiscriminatorParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedPathAttributeParsingError<'a>
    for LocatedMultiExitDiscriminatorParsingError<'a>
{
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &LocalPreferenceParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedPathAttributeParsingError<'a> for LocatedLocalPreferenceParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &AtomicAggregateParsingError {
        &self.error
    }
}
impl<'a> IntoLocatedPathAttributeParsingError<'a> for LocatedAtomicAggregateParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &AggregatorParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedPathAttributeParsingError<'a> for LocatedAggregatorParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &UnknownAttributeParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedPathAttributeParsingError<'a> for LocatedUnknownAttributeParsingError<'a> {
    fn into_located_attribute_parsing_error(self) -> LocatedPathAttributeParsingError<'a> {
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
