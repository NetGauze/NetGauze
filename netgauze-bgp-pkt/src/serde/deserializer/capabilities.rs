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
    capabilities::{
        BGPCapability, ExperimentalCapability, ExperimentalCapabilityCode, UnrecognizedCapability,
        ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH, ROUTE_REFRESH_CAPABILITY_LENGTH,
    },
    iana::{BGPCapabilityCode, UndefinedBGPCapabilityCode},
    serde::deserializer::open::{BGPParameterParsingError, LocatedBGPParameterParsingError},
};
use netgauze_parse_utils::{IntoLocatedError, LocatedParsingError, ReadablePDU, Span};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::be_u8,
    IResult,
};

/// BGP Capability Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPCapabilityParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedCapabilityCode(UndefinedBGPCapabilityCode),
    InvalidRouteRefreshLength(u8),
    InvalidEnhancedRouteRefreshLength(u8),
}

/// BGP Open Message Parsing errors  with the input location of where it
/// occurred in the input byte stream being parsed
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPCapabilityParsingError<'a> {
    span: Span<'a>,
    error: BGPCapabilityParsingError,
}

impl<'a> LocatedBGPCapabilityParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPCapabilityParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedBGPCapabilityParsingError<'a> {
    type Span = Span<'a>;
    type Error = BGPCapabilityParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedBGPParameterParsingError<'a>>
    for LocatedBGPCapabilityParsingError<'a>
{
    fn into_located(self) -> LocatedBGPParameterParsingError<'a> {
        LocatedBGPParameterParsingError::new(
            self.span,
            BGPParameterParsingError::CapabilityError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedBGPCapabilityParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedBGPCapabilityParsingError::new(input, BGPCapabilityParsingError::NomError(kind))
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, BGPCapabilityParsingError>
    for LocatedBGPCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPCapabilityParsingError,
    ) -> Self {
        LocatedBGPCapabilityParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedBGPCapabilityCode>
    for LocatedBGPCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedBGPCapabilityCode,
    ) -> Self {
        LocatedBGPCapabilityParsingError::new(
            input,
            BGPCapabilityParsingError::UndefinedCapabilityCode(error),
        )
    }
}

fn parse_experimental_capability(
    code: ExperimentalCapabilityCode,
    buf: Span<'_>,
) -> IResult<Span<'_>, BGPCapability, LocatedBGPCapabilityParsingError<'_>> {
    let (buf, value) = nom::multi::length_value(be_u8, nom::multi::many0(be_u8))(buf)?;
    Ok((
        buf,
        BGPCapability::Experimental(ExperimentalCapability::new(code, value)),
    ))
}

fn parse_unrecognized_capability(
    code: u8,
    buf: Span<'_>,
) -> IResult<Span<'_>, BGPCapability, LocatedBGPCapabilityParsingError<'_>> {
    let (buf, value) = nom::multi::length_value(be_u8, nom::multi::many0(be_u8))(buf)?;
    Ok((
        buf,
        BGPCapability::Unrecognized(UnrecognizedCapability::new(code, value)),
    ))
}

fn parse_route_refresh_capability(
    buf: Span<'_>,
) -> IResult<Span<'_>, BGPCapability, LocatedBGPCapabilityParsingError<'_>> {
    let (buf, _) = nom::combinator::map_res(be_u8, |length| {
        if length != ROUTE_REFRESH_CAPABILITY_LENGTH {
            Err(BGPCapabilityParsingError::InvalidRouteRefreshLength(length))
        } else {
            Ok(length)
        }
    })(buf)?;
    Ok((buf, BGPCapability::RouteRefresh))
}

fn parse_enhanced_route_refresh_capability(
    buf: Span<'_>,
) -> IResult<Span<'_>, BGPCapability, LocatedBGPCapabilityParsingError<'_>> {
    let (buf, _) = nom::combinator::map_res(be_u8, |length| {
        if length != ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH {
            Err(BGPCapabilityParsingError::InvalidEnhancedRouteRefreshLength(length))
        } else {
            Ok(length)
        }
    })(buf)?;
    Ok((buf, BGPCapability::EnhancedRouteRefresh))
}

impl<'a> ReadablePDU<'a, LocatedBGPCapabilityParsingError<'a>> for BGPCapability {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBGPCapabilityParsingError<'a>> {
        let parsed: IResult<Span<'_>, BGPCapabilityCode, LocatedBGPCapabilityParsingError<'_>> =
            nom::combinator::map_res(be_u8, BGPCapabilityCode::try_from)(buf);
        match parsed {
            Ok((buf, code)) => match code {
                BGPCapabilityCode::MultiProtocolExtensions => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::RouteRefreshCapability => parse_route_refresh_capability(buf),
                BGPCapabilityCode::OutboundRouteFilteringCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::ExtendedNextHopEncoding => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::BGPExtendedMessage => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::BGPSecCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::MultipleLabelsCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::BGPRole => parse_unrecognized_capability(code.into(), buf),
                BGPCapabilityCode::GracefulRestartCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::FourOctetAS => parse_unrecognized_capability(code.into(), buf),
                BGPCapabilityCode::SupportForDynamicCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::MultiSessionBGPCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::ADDPathCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::EnhancedRouteRefresh => {
                    parse_enhanced_route_refresh_capability(buf)
                }
                BGPCapabilityCode::LongLivedGracefulRestartLLGRCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::RoutingPolicyDistribution => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::FQDN => parse_unrecognized_capability(code.into(), buf),
                BGPCapabilityCode::Experimental239 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental239, buf)
                }
                BGPCapabilityCode::Experimental240 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental240, buf)
                }
                BGPCapabilityCode::Experimental241 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental241, buf)
                }
                BGPCapabilityCode::Experimental242 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental242, buf)
                }
                BGPCapabilityCode::Experimental243 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental243, buf)
                }
                BGPCapabilityCode::Experimental244 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental244, buf)
                }
                BGPCapabilityCode::Experimental245 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental245, buf)
                }
                BGPCapabilityCode::Experimental246 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental246, buf)
                }
                BGPCapabilityCode::Experimental247 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental247, buf)
                }
                BGPCapabilityCode::Experimental248 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental248, buf)
                }
                BGPCapabilityCode::Experimental249 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental249, buf)
                }
                BGPCapabilityCode::Experimental250 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental250, buf)
                }
                BGPCapabilityCode::Experimental251 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental251, buf)
                }
                BGPCapabilityCode::Experimental252 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental252, buf)
                }
                BGPCapabilityCode::Experimental253 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental253, buf)
                }
                BGPCapabilityCode::Experimental254 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental254, buf)
                }
            },
            Err(nom::Err::Error(LocatedBGPCapabilityParsingError {
                span: buf,
                error:
                    BGPCapabilityParsingError::UndefinedCapabilityCode(UndefinedBGPCapabilityCode(_)),
            })) => {
                // Parse code again, since nom won't advance the buffer on map_res error
                let (buf, code) = be_u8(buf)?;
                parse_unrecognized_capability(code, buf)
            }
            Err(err) => Err(err),
        }
    }
}
