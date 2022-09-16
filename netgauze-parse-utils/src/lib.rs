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
pub trait ReadablePDUWithTwoInput<'a, T, U, ErrorType> {
    fn from_wire(buf: Span<'a>, input1: T, input2: U) -> nom::IResult<Span<'a>, Self, ErrorType>
    where
        Self: Sized;
}
