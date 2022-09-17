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

use crate::{
    capabilities::BGPCapability,
    iana::{BGPOpenMessageParameterType, UndefinedBGPOpenMessageParameterType},
    open::BGPOpenMessageParameter,
    serde::deserializer::{
        capabilities::{BGPCapabilityParsingError, LocatedBGPCapabilityParsingError},
        BGPMessageParsingError, LocatedBGPMessageParsingError,
    },
    BGPOpenMessage,
};
use netgauze_parse_utils::{parse_till_empty, ReadablePDU, Span};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use std::net::Ipv4Addr;

/// BGP Open Message Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPOpenMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UnsupportedVersionNumber(u8),
    ParameterError(BGPParameterParsingError),
}

/// BGP Open Message Parsing errors  with the input location of where it
/// occurred in the input byte stream being parsed
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPOpenMessageParsingError<'a> {
    span: Span<'a>,
    error: BGPOpenMessageParsingError,
}

impl<'a> LocatedBGPOpenMessageParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPOpenMessageParsingError) -> Self {
        Self { span, error }
    }

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &BGPOpenMessageParsingError {
        &self.error
    }

    pub const fn into_located_bgp_message_parsing_error(self) -> LocatedBGPMessageParsingError<'a> {
        let span = self.span;
        let error = self.error;
        LocatedBGPMessageParsingError::new(
            span,
            BGPMessageParsingError::BGPOpenMessageParsingError(error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedBGPOpenMessageParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedBGPOpenMessageParsingError::new(input, BGPOpenMessageParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, BGPOpenMessageParsingError>
    for LocatedBGPOpenMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPOpenMessageParsingError,
    ) -> Self {
        LocatedBGPOpenMessageParsingError::new(input, error)
    }
}

/// BGP Open Message Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPParameterParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedParameterType(UndefinedBGPOpenMessageParameterType),
    CapabilityError(BGPCapabilityParsingError),
}

/// BGP Open Parameter Message Parsing errors  with the input location of where
/// it occurred in the input byte stream being parsed
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPParameterParsingError<'a> {
    span: Span<'a>,
    error: BGPParameterParsingError,
}

impl<'a> LocatedBGPParameterParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPParameterParsingError) -> Self {
        Self { span, error }
    }

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &BGPParameterParsingError {
        &self.error
    }

    pub const fn into_located_bgp_open_message_parsing_error(
        self,
    ) -> LocatedBGPOpenMessageParsingError<'a> {
        let span = self.span;
        let error = self.error;
        LocatedBGPOpenMessageParsingError::new(
            span,
            BGPOpenMessageParsingError::ParameterError(error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedBGPParameterParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedBGPParameterParsingError::new(input, BGPParameterParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, BGPParameterParsingError>
    for LocatedBGPParameterParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPParameterParsingError,
    ) -> Self {
        LocatedBGPParameterParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedBGPOpenMessageParameterType>
    for LocatedBGPParameterParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedBGPOpenMessageParameterType,
    ) -> Self {
        LocatedBGPParameterParsingError::new(
            input,
            BGPParameterParsingError::UndefinedParameterType(error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedBGPOpenMessageParsingError<'a>> for BGPOpenMessage {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBGPOpenMessageParsingError<'a>> {
        let (buf, _) = nom::combinator::map_res(be_u8, |x| {
            if x == 4 {
                Ok(x)
            } else {
                Err(BGPOpenMessageParsingError::UnsupportedVersionNumber(x))
            }
        })(buf)?;
        let (buf, my_as) = be_u16(buf)?;
        let (buf, hold_time) = be_u16(buf)?;
        let (buf, bgp_id) = be_u32(buf)?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        let (buf, params_buf) = nom::multi::length_data(be_u8)(buf)?;
        let (_, params) = match parse_till_empty::<
            '_,
            BGPOpenMessageParameter,
            LocatedBGPParameterParsingError<'_>,
        >(params_buf)
        {
            Ok((buf, params)) => (buf, params),
            Err(err) => {
                return match err {
                    nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                    nom::Err::Error(err) => Err(nom::Err::Error(
                        err.into_located_bgp_open_message_parsing_error(),
                    )),
                    nom::Err::Failure(err) => Err(nom::Err::Failure(
                        err.into_located_bgp_open_message_parsing_error(),
                    )),
                }
            }
        };
        Ok((buf, BGPOpenMessage::new(my_as, hold_time, bgp_id, params)))
    }
}

impl<'a> ReadablePDU<'a, LocatedBGPParameterParsingError<'a>> for BGPOpenMessageParameter {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBGPParameterParsingError<'a>> {
        let begin_buf = buf;
        let (buf, param_type) =
            nom::combinator::map_res(be_u8, BGPOpenMessageParameterType::try_from)(buf)?;
        match param_type {
            BGPOpenMessageParameterType::Capability => {
                let (buf, capabilities_buf) = nom::multi::length_data(be_u8)(buf)?;
                let (_, capabilities) = match parse_till_empty::<
                    '_,
                    BGPCapability,
                    LocatedBGPCapabilityParsingError<'_>,
                >(capabilities_buf)
                {
                    Ok((buf, capabilities)) => (buf, capabilities),
                    Err(err) => {
                        return match err {
                            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                            nom::Err::Error(error) => {
                                Err(nom::Err::Error(error.into_located_parameter_error()))
                            }
                            nom::Err::Failure(error) => {
                                Err(nom::Err::Failure(error.into_located_parameter_error()))
                            }
                        }
                    }
                };
                Ok((buf, BGPOpenMessageParameter::Capabilities(capabilities)))
            }
            BGPOpenMessageParameterType::ExtendedLength => {
                return Err(nom::Err::Error(LocatedBGPParameterParsingError::new(
                    begin_buf,
                    BGPParameterParsingError::UndefinedParameterType(
                        UndefinedBGPOpenMessageParameterType(
                            BGPOpenMessageParameterType::ExtendedLength.into(),
                        ),
                    ),
                )))
            }
        }
    }
}
