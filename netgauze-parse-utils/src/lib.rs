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
use std::fmt::Debug;

pub type Span<'a> = BinarySpan<&'a [u8]>;

/// Generic trait for Readable Protocol Data Unit that doesn't need any external
/// input while parsing the packet.
pub trait ReadablePDU<'a, Error: Debug> {
    fn from_wire(buf: Span<'a>) -> nom::IResult<Span<'a>, Self, Error>
    where
        Self: Sized;
}

/// Generic trait Readable Protocol Data Unit that does need a single external
/// input
pub trait ReadablePDUWithOneInput<'a, T, ErrorType> {
    fn from_wire(buf: Span<'a>, input: T) -> nom::IResult<Span<'a>, Self, ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Readable Protocol Data Unit that does need two external
/// inputs
pub trait ReadablePDUWithTwoInputs<'a, T, U, ErrorType> {
    fn from_wire(buf: Span<'a>, input1: T, input2: U) -> nom::IResult<Span<'a>, Self, ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Readable Protocol Data Unit that does need three external
/// inputs
pub trait ReadablePDUWithThreeInputs<'a, I1, I2, I3, ErrorType> {
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
pub trait WritablePDU<ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [Self::len] might be less than the length value written in
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
pub trait WritablePDUWithOneInput<I, ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [Self::len] might be less than the length value written in
    /// the PDU, since most PDUs don't include the length of their 'length'
    /// field in the calculation
    fn len(&self, input: I) -> usize;

    fn write<T: std::io::Write>(&self, _writer: &mut T, input: I) -> Result<(), ErrorType>
    where
        Self: Sized;
}

/// Keep repeating the parser till the buf is empty
#[inline]
pub fn parse_till_empty<'a, T: ReadablePDU<'a, E>, E: Debug>(
    buf: Span<'a>,
) -> nom::IResult<Span<'a>, Vec<T>, E> {
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
pub fn parse_till_empty_with_one_input<
    'a,
    I: Copy,
    T: ReadablePDUWithOneInput<'a, I, E>,
    E: Debug,
>(
    buf: Span<'a>,
    input: I,
) -> nom::IResult<Span<'a>, Vec<T>, E> {
    let mut buf = buf;
    let mut ret = Vec::new();
    while !buf.is_empty() {
        let (tmp, element) = T::from_wire(buf, input)?;
        ret.push(element);
        buf = tmp;
    }
    Ok((buf, ret))
}
