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

//! Traits for Ser/Deser wire protocols

#[cfg(feature = "test-helpers")]
pub mod test_helpers;

use netgauze_locate::BinarySpan;
use nom::IResult;
use std::fmt::Debug;

pub type Span<'a> = BinarySpan<&'a [u8]>;

/// Generic trait for Readable Protocol Data Unit that doesn't need any external
/// input while parsing the packet.
pub trait ReadablePdu<'a, Error: Debug> {
    fn from_wire(buf: Span<'a>) -> nom::IResult<Span<'a>, Self, Error>
    where
        Self: Sized;
}

/// Generic trait Readable Protocol Data Unit that does need a single external
/// input
pub trait ReadablePduWithOneInput<'a, T, ErrorType> {
    fn from_wire(buf: Span<'a>, input: T) -> nom::IResult<Span<'a>, Self, ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Readable Protocol Data Unit that does need two external
/// inputs
pub trait ReadablePduWithTwoInputs<'a, T, U, ErrorType> {
    fn from_wire(buf: Span<'a>, input1: T, input2: U) -> nom::IResult<Span<'a>, Self, ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Readable Protocol Data Unit that does need three external
/// inputs
pub trait ReadablePduWithThreeInputs<'a, I1, I2, I3, ErrorType> {
    fn from_wire(
        buf: Span<'a>,
        input1: I1,
        input2: I2,
        input3: I3,
    ) -> nom::IResult<Span<'a>, Self, ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Writable Protocol Data Unit that doesn't need any external
/// input while writing the packet.
#[allow(clippy::len_without_is_empty)]
pub trait WritablePdu<ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [`Self::len`] might be less than the length value written in
    /// the PDU, since most PDUs don't include the length of their 'length'
    /// field in the calculation
    fn len(&self) -> usize;

    fn write<T: std::io::Write>(&self, _writer: &mut T) -> Result<(), ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Writable Protocol Data Unit that doesn't need any external
/// input while writing the packet.
#[allow(clippy::len_without_is_empty)]
pub trait WritablePduWithOneInput<I, ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [`Self::len`] might be less than the length value written in
    /// the PDU, since most PDUs don't include the length of their 'length'
    /// field in the calculation
    fn len(&self, input: I) -> usize;

    fn write<T: std::io::Write>(&self, _writer: &mut T, input: I) -> Result<(), ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Writable Protocol Data Unit that doesn't need any external
/// input while writing the packet.
#[allow(clippy::len_without_is_empty)]
pub trait WritablePduWithTwoInputs<I1, I2, ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [`Self::len`] might be less than the length value written in
    /// the PDU, since most PDUs don't include the length of their 'length'
    /// field in the calculation
    fn len(&self, input1: I1, input2: I2) -> usize;

    fn write<T: std::io::Write>(
        &self,
        _writer: &mut T,
        input1: I1,
        input2: I2,
    ) -> Result<(), ErrorType>
    where
        Self: Sized;
}

/// Located Parsing error is the error raised by parsing a given buffer and a
/// reference to the location where it occurred. The offset of the buffer in the
/// [`Span`] should refer (as much as possible) to the first byte where the
/// error started
pub trait LocatedParsingError {
    type Span;
    type Error;

    fn span(&self) -> &Self::Span;
    fn error(&self) -> &Self::Error;
}

#[inline]
pub fn parse_into_located<'a, Lin: Debug, L: From<Lin>, T: ReadablePdu<'a, Lin>>(
    buf: Span<'a>,
) -> IResult<Span<'a>, T, L> {
    match T::from_wire(buf) {
        Ok((buf, value)) => Ok((buf, value)),
        Err(err) => match err {
            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
            nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
            nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
        },
    }
}

#[inline]
pub fn parse_into_located_one_input<
    'a,
    I,
    Lin: Debug,
    L: From<Lin>,
    T: ReadablePduWithOneInput<'a, I, Lin>,
>(
    buf: Span<'a>,
    input: I,
) -> IResult<Span<'a>, T, L> {
    match T::from_wire(buf, input) {
        Ok((buf, value)) => Ok((buf, value)),
        Err(err) => match err {
            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
            nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
            nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
        },
    }
}

#[inline]
pub fn parse_into_located_two_inputs<
    'a,
    I1,
    I2,
    Lin: Debug,
    L: From<Lin>,
    T: ReadablePduWithTwoInputs<'a, I1, I2, Lin>,
>(
    buf: Span<'a>,
    input1: I1,
    input2: I2,
) -> IResult<Span<'a>, T, L> {
    match T::from_wire(buf, input1, input2) {
        Ok((buf, value)) => Ok((buf, value)),
        Err(err) => match err {
            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
            nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
            nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
        },
    }
}

#[inline]
pub fn parse_into_located_three_inputs<
    'a,
    I1,
    I2,
    I3,
    Lin: Debug,
    L: From<Lin>,
    T: ReadablePduWithThreeInputs<'a, I1, I2, I3, Lin>,
>(
    buf: Span<'a>,
    input1: I1,
    input2: I2,
    input3: I3,
) -> IResult<Span<'a>, T, L> {
    match T::from_wire(buf, input1, input2, input3) {
        Ok((buf, value)) => Ok((buf, value)),
        Err(err) => match err {
            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
            nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
            nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
        },
    }
}

/// Keep repeating the parser till the buf is empty
#[inline]
pub fn parse_till_empty<'a, T: ReadablePdu<'a, E>, E: Debug>(
    buf: Span<'a>,
) -> IResult<Span<'a>, Vec<T>, E> {
    let mut buf = buf;
    let mut ret = Vec::new();
    while !buf.is_empty() {
        let (tmp, element) = T::from_wire(buf)?;
        ret.push(element);
        buf = tmp;
    }
    Ok((buf, ret))
}

/// Keep repeating the parser till the buf is empty
#[inline]
pub fn parse_till_empty_into_located<'a, Lin: Debug, L: From<Lin>, T: ReadablePdu<'a, Lin>>(
    buf: Span<'a>,
) -> IResult<Span<'a>, Vec<T>, L> {
    let mut buf = buf;
    let mut ret = Vec::new();
    while !buf.is_empty() {
        let (tmp, element) = parse_into_located(buf)?;
        ret.push(element);
        buf = tmp;
    }
    Ok((buf, ret))
}

/// Keep repeating the parser till the buf is empty
#[inline]
pub fn parse_till_empty_with_one_input<
    'a,
    I: Clone,
    T: ReadablePduWithOneInput<'a, I, E>,
    E: Debug,
>(
    buf: Span<'a>,
    input: I,
) -> IResult<Span<'a>, Vec<T>, E> {
    let mut buf = buf;
    let mut ret = Vec::new();
    while !buf.is_empty() {
        let (tmp, element) = T::from_wire(buf, input.clone())?;
        ret.push(element);
        buf = tmp;
    }
    Ok((buf, ret))
}

/// Keep repeating the parser till the buf is empty
#[inline]
pub fn parse_till_empty_into_with_one_input_located<
    'a,
    I: Clone,
    Lin: Debug,
    L: From<Lin>,
    T: ReadablePduWithOneInput<'a, I, Lin>,
>(
    buf: Span<'a>,
    input: I,
) -> IResult<Span<'a>, Vec<T>, L> {
    let mut buf = buf;
    let mut ret = Vec::new();
    while !buf.is_empty() {
        let (tmp, element) = parse_into_located_one_input(buf, input.clone())?;
        ret.push(element);
        buf = tmp;
    }
    Ok((buf, ret))
}

/// Keep repeating the parser till the buf is empty
#[inline]
pub fn parse_till_empty_into_with_two_inputs_located<
    'a,
    I1: Clone,
    I2: Clone,
    Lin: Debug,
    L: From<Lin>,
    T: ReadablePduWithTwoInputs<'a, I1, I2, Lin>,
>(
    buf: Span<'a>,
    input1: I1,
    input2: I2,
) -> IResult<Span<'a>, Vec<T>, L> {
    let mut buf = buf;
    let mut ret = Vec::new();
    while !buf.is_empty() {
        let (tmp, element) = parse_into_located_two_inputs(buf, input1.clone(), input2.clone())?;
        ret.push(element);
        buf = tmp;
    }
    Ok((buf, ret))
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(remote = "nom::error::ErrorKind")]
pub enum ErrorKindSerdeDeref {
    Tag,
    MapRes,
    MapOpt,
    Alt,
    IsNot,
    IsA,
    SeparatedList,
    SeparatedNonEmptyList,
    Many0,
    Many1,
    ManyTill,
    Count,
    TakeUntil,
    LengthValue,
    TagClosure,
    Alpha,
    Digit,
    HexDigit,
    OctDigit,
    AlphaNumeric,
    Space,
    MultiSpace,
    LengthValueFn,
    Eof,
    Switch,
    TagBits,
    OneOf,
    NoneOf,
    Char,
    CrLf,
    RegexpMatch,
    RegexpMatches,
    RegexpFind,
    RegexpCapture,
    RegexpCaptures,
    TakeWhile1,
    Complete,
    Fix,
    Escaped,
    EscapedTransform,
    NonEmpty,
    ManyMN,
    Not,
    Permutation,
    Verify,
    TakeTill1,
    TakeWhileMN,
    TooLarge,
    Many0Count,
    Many1Count,
    Float,
    Satisfy,
    Fail,
}
