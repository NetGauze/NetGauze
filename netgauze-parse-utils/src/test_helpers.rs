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

//! Various functions used in testing the correctness or
//! serializing/deserializing wire protocols

use crate::{
    ReadablePDU, ReadablePDUWithOneInput, ReadablePDUWithThreeInputs, ReadablePDUWithTwoInputs,
    Span, WritablePDU, WritablePDUWithOneInput,
};
use netgauze_locate::BinarySpan;
use nom::IResult;
use std::{fmt::Debug, io::Cursor};

/// Helper method to combine multiple vectors into one
pub fn combine(v: Vec<&[u8]>) -> Vec<u8> {
    v.iter()
        .flat_map(|x| x.iter())
        .cloned()
        .collect::<Vec<u8>>()
}

/// Fancier assert to for more meaningful error messages
pub fn test_parsed_completely<'a, T, E>(input: &'a [u8], expected: &T) -> T
where
    T: ReadablePDU<'a, E> + PartialEq + Debug,
    E: Debug,
{
    let parsed = <T as ReadablePDU<E>>::from_wire(Span::new(input));
    assert!(parsed.is_ok(), "Message failed parsing, while expecting it to pass.\n\tExpected : {expected:?}\n\tParsed msg: {parsed:?}");
    let (span, value) = parsed.unwrap();
    assert_eq!(&value, expected);
    assert_eq!(
        span.fragment().len(),
        0,
        "Not all the input is consumed by the parser, didn't consume: {span:?}",
    );
    value
}

/// Fancier assert to for more meaningful error messages
pub fn test_parsed_completely_with_one_input<'a, T, I, E>(
    input: &'a [u8],
    parser_input: I,
    expected: &T,
) -> T
where
    T: ReadablePDUWithOneInput<'a, I, E> + PartialEq + Debug,
    E: Debug,
{
    let parsed = <T as ReadablePDUWithOneInput<I, E>>::from_wire(Span::new(input), parser_input);
    assert!(parsed.is_ok(), "Message failed parsing, while expecting it to pass.\n\tExpected : {expected:?}\n\tParsed msg: {parsed:?}");
    let (span, value) = parsed.unwrap();
    assert_eq!(&value, expected);
    assert_eq!(
        span.fragment().len(),
        0,
        "Not all the input is consumed by the parser, didn't consume: {span:?}",
    );
    value
}

/// Fancier assert to for more meaningful error messages
pub fn test_parsed_completely_with_two_inputs<'a, T, I, K, E>(
    input: &'a [u8],
    parser_input1: I,
    parser_input2: K,
    expected: &T,
) -> T
where
    T: ReadablePDUWithTwoInputs<'a, I, K, E> + PartialEq + Debug,
    E: Debug,
{
    let parsed = <T as ReadablePDUWithTwoInputs<I, K, E>>::from_wire(
        Span::new(input),
        parser_input1,
        parser_input2,
    );
    assert!(parsed.is_ok(), "Message failed parsing, while expecting it to pass.\n\tExpected : {expected:?}\n\tParsed msg: {parsed:?}");
    let (span, value) = parsed.unwrap();
    assert_eq!(&value, expected);
    assert_eq!(
        span.fragment().len(),
        0,
        "Not all the input is consumed by the parser, didn't consume: {span:?}",
    );
    value
}

/// Fancier assert to for more meaningful error messages
pub fn test_parsed_completely_with_three_inputs<'a, T, I1, I2, I3, E>(
    input: &'a [u8],
    parser_input1: I1,
    parser_input2: I2,
    parser_input3: I3,
    expected: &T,
) -> T
where
    T: ReadablePDUWithThreeInputs<'a, I1, I2, I3, E> + PartialEq + Debug,
    E: Debug,
{
    let parsed = <T as ReadablePDUWithThreeInputs<I1, I2, I3, E>>::from_wire(
        Span::new(input),
        parser_input1,
        parser_input2,
        parser_input3,
    );
    assert!(parsed.is_ok(), "Message failed parsing, while expecting it to pass.\n\tExpected : {expected:?}\n\tParsed msg: {parsed:?}");
    let (span, value) = parsed.unwrap();
    assert_eq!(&value, expected);
    assert_eq!(
        span.fragment().len(),
        0,
        "Not all the input is consumed by the parser, didn't consume: {span:?}",
    );
    value
}

/// Fancier assert to for more meaningful error messages
pub fn test_parse_error<'a, T, E>(input: &'a [u8], expected_err: &E)
where
    T: ReadablePDU<'a, E> + Debug,
    E: Debug + Eq,
{
    let parsed: IResult<BinarySpan<&[u8]>, T, E> =
        <T as ReadablePDU<E>>::from_wire(Span::new(input));
    assert!(
        parsed.is_err(),
        "Message was parsed, while expecting it to fail.\n\tExpected : {expected_err:?}\n\tParsed msg: {parsed:?}"
    );

    if let Err(nom::Err::Error(parsed_error)) = parsed {
        assert_eq!(&parsed_error, expected_err);
    } else {
        panic!(
            "Expected the test to fail with Err(nom::Err:Err(x)) but it didn't. Got {parsed:?} instead"
        );
    }
}

/// Fancier assert to for more meaningful error messages
pub fn test_parse_error_with_one_input<'a, T, I, E>(
    input: &'a [u8],
    parser_input: I,
    expected_err: &'a E,
) where
    T: ReadablePDUWithOneInput<'a, I, E> + Debug,
    E: Debug + Eq,
{
    let parsed: IResult<BinarySpan<&[u8]>, T, E> =
        <T as ReadablePDUWithOneInput<I, E>>::from_wire(Span::new(input), parser_input);
    assert!(
        parsed.is_err(),
        "Message was parsed, while expecting it to fail.\n\tExpected : {expected_err:?}\n\tParsed msg: {parsed:?}"
    );

    if let Err(nom::Err::Error(parsed_error)) = parsed {
        assert_eq!(&parsed_error, expected_err);
    } else {
        panic!(
            "Expected the test to fail with Err(nom::Err:Err(x)) but it didn't. Got {parsed:?} instead"
        );
    }
}

/// Fancier assert to for more meaningful error messages
pub fn test_parse_error_with_two_inputs<'a, T, I, K, E>(
    input: &'a [u8],
    parser_input1: I,
    parser_input2: K,
    expected_err: nom::Err<E>,
) where
    T: ReadablePDUWithTwoInputs<'a, I, K, E> + Debug,
    E: Debug + Eq,
{
    let parsed: IResult<BinarySpan<&[u8]>, T, E> =
        <T as ReadablePDUWithTwoInputs<I, K, E>>::from_wire(
            Span::new(input),
            parser_input1,
            parser_input2,
        );
    assert!(
        parsed.is_err(),
        "Message was parsed, while expecting it to fail.\n\tExpected : {expected_err:?}\n\tParsed msg: {parsed:?}"
    );

    assert_eq!(parsed.err().unwrap(), expected_err);
}

pub fn test_write<T: WritablePDU<E>, E: Eq>(input: &T, expected: &[u8]) -> Result<(), E> {
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    input.write(&mut cursor)?;
    assert_eq!(
        buf, expected,
        "Serialized buffer is different the the expected one"
    );
    assert_eq!(
        input.len(),
        expected.len(),
        "Packet::len() is different the serialized buffer length"
    );
    Ok(())
}

pub fn test_write_with_one_input<I: Copy, T: WritablePDUWithOneInput<I, E>, E: Eq>(
    input: &T,
    parser_input: I,
    expected: &[u8],
) -> Result<(), E> {
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    input.write(&mut cursor, parser_input)?;
    assert_eq!(
        buf, expected,
        "Serialized buffer is different the the expected one"
    );
    assert_eq!(
        input.len(parser_input),
        expected.len(),
        "Packet::len() is different the serialized buffer length"
    );
    Ok(())
}
