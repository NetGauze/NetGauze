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
        AddPathCapability, AddPathCapabilityAddressFamily, BGPCapability, ExperimentalCapability,
        ExperimentalCapabilityCode, ExtendedNextHopEncoding, ExtendedNextHopEncodingCapability,
        FourOctetASCapability, MultiProtocolExtensionsCapability, UnrecognizedCapability,
        ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH, EXTENDED_MESSAGE_CAPABILITY_LENGTH,
        EXTENDED_NEXT_HOP_ENCODING_LENGTH, FOUR_OCTET_AS_CAPABILITY_LENGTH,
        MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH, ROUTE_REFRESH_CAPABILITY_LENGTH,
    },
    iana::{BGPCapabilityCode, UndefinedBGPCapabilityCode},
    serde::deserializer::open::{BGPParameterParsingError, LocatedBGPParameterParsingError},
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
    UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{
    parse_into_located, parse_till_empty, IntoLocatedError, LocatedParsingError, ReadablePDU, Span,
};
use nom::{
    error::{ErrorKind, FromExternalError, ParseError},
    number::complete::{be_u16, be_u32, be_u8},
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
    InvalidExtendedMessageLength(u8),
    FourOctetASCapabilityError(FourOctetASCapabilityParsingError),
    MultiProtocolExtensionsCapabilityError(MultiProtocolExtensionsCapabilityParsingError),
    AddPathCapabilityError(AddPathCapabilityParsingError),
    ExtendedNextHopEncodingCapabilityError(ExtendedNextHopEncodingCapabilityParsingError),
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

impl<'a> ParseError<Span<'a>> for LocatedBGPCapabilityParsingError<'a> {
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
    let (buf, value) = nom::multi::length_count(be_u8, be_u8)(buf)?;
    Ok((
        buf,
        BGPCapability::Experimental(ExperimentalCapability::new(code, value)),
    ))
}

fn parse_unrecognized_capability(
    code: u8,
    buf: Span<'_>,
) -> IResult<Span<'_>, BGPCapability, LocatedBGPCapabilityParsingError<'_>> {
    let (buf, value) = nom::multi::length_count(be_u8, be_u8)(buf)?;
    Ok((
        buf,
        BGPCapability::Unrecognized(UnrecognizedCapability::new(code, value)),
    ))
}

/// Helper function to read and check the capability exact length
#[inline]
fn check_capability_length<'a, E, L: FromExternalError<Span<'a>, E> + ParseError<Span<'a>>>(
    buf: Span<'a>,
    expected: u8,
    err: fn(u8) -> E,
) -> IResult<Span<'a>, u8, L> {
    let (buf, length) = nom::combinator::map_res(be_u8, |length| {
        if length != expected {
            Err(err(length))
        } else {
            Ok(length)
        }
    })(buf)?;
    Ok((buf, length))
}

fn parse_route_refresh_capability(
    buf: Span<'_>,
) -> IResult<Span<'_>, BGPCapability, LocatedBGPCapabilityParsingError<'_>> {
    let (buf, _) = check_capability_length(buf, ROUTE_REFRESH_CAPABILITY_LENGTH, |x| {
        BGPCapabilityParsingError::InvalidRouteRefreshLength(x)
    })?;
    Ok((buf, BGPCapability::RouteRefresh))
}

fn parse_enhanced_route_refresh_capability(
    buf: Span<'_>,
) -> IResult<Span<'_>, BGPCapability, LocatedBGPCapabilityParsingError<'_>> {
    let (buf, _) = check_capability_length(buf, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH, |x| {
        BGPCapabilityParsingError::InvalidEnhancedRouteRefreshLength(x)
    })?;
    Ok((buf, BGPCapability::EnhancedRouteRefresh))
}

impl<'a> ReadablePDU<'a, LocatedBGPCapabilityParsingError<'a>> for BGPCapability {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBGPCapabilityParsingError<'a>> {
        let parsed: IResult<Span<'_>, BGPCapabilityCode, LocatedBGPCapabilityParsingError<'_>> =
            nom::combinator::map_res(be_u8, BGPCapabilityCode::try_from)(buf);
        match parsed {
            Ok((buf, code)) => match code {
                BGPCapabilityCode::MultiProtocolExtensions => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BGPCapability::MultiProtocolExtensions(cap)))
                }
                BGPCapabilityCode::RouteRefreshCapability => parse_route_refresh_capability(buf),
                BGPCapabilityCode::OutboundRouteFilteringCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::ExtendedNextHopEncoding => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BGPCapability::ExtendedNextHopEncoding(cap)))
                }
                BGPCapabilityCode::BGPExtendedMessage => {
                    let (buf, _) =
                        check_capability_length(buf, EXTENDED_MESSAGE_CAPABILITY_LENGTH, |x| {
                            BGPCapabilityParsingError::InvalidExtendedMessageLength(x)
                        })?;
                    Ok((buf, BGPCapability::ExtendedMessage))
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
                BGPCapabilityCode::FourOctetAS => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BGPCapability::FourOctetAS(cap)))
                }
                BGPCapabilityCode::SupportForDynamicCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::MultiSessionBGPCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BGPCapabilityCode::ADDPathCapability => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BGPCapability::AddPath(cap)))
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum FourOctetASCapabilityParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidLength(u8),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedFourOctetASCapabilityParsingError<'a> {
    span: Span<'a>,
    error: FourOctetASCapabilityParsingError,
}

impl<'a> LocatedFourOctetASCapabilityParsingError<'a> {
    pub const fn new(span: Span<'a>, error: FourOctetASCapabilityParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedFourOctetASCapabilityParsingError<'a> {
    type Span = Span<'a>;
    type Error = FourOctetASCapabilityParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedBGPCapabilityParsingError<'a>>
    for LocatedFourOctetASCapabilityParsingError<'a>
{
    fn into_located(self) -> LocatedBGPCapabilityParsingError<'a> {
        LocatedBGPCapabilityParsingError::new(
            self.span,
            BGPCapabilityParsingError::FourOctetASCapabilityError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, FourOctetASCapabilityParsingError>
    for LocatedFourOctetASCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: FourOctetASCapabilityParsingError,
    ) -> Self {
        LocatedFourOctetASCapabilityParsingError::new(input, error)
    }
}

impl<'a> ParseError<Span<'a>> for LocatedFourOctetASCapabilityParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedFourOctetASCapabilityParsingError::new(
            input,
            FourOctetASCapabilityParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> ReadablePDU<'a, LocatedFourOctetASCapabilityParsingError<'a>> for FourOctetASCapability {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedFourOctetASCapabilityParsingError<'a>> {
        let (buf, _) = check_capability_length(buf, FOUR_OCTET_AS_CAPABILITY_LENGTH, |x| {
            FourOctetASCapabilityParsingError::InvalidLength(x)
        })?;
        let (buf, asn4) = be_u32(buf)?;
        Ok((buf, FourOctetASCapability::new(asn4)))
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MultiProtocolExtensionsCapabilityParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    InvalidLength(u8),
    AddressFamilyError(UndefinedAddressFamily),
    SubsequentAddressFamilyError(UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedMultiProtocolExtensionsCapabilityParsingError<'a> {
    span: Span<'a>,
    error: MultiProtocolExtensionsCapabilityParsingError,
}

impl<'a> LocatedMultiProtocolExtensionsCapabilityParsingError<'a> {
    pub const fn new(span: Span<'a>, error: MultiProtocolExtensionsCapabilityParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedMultiProtocolExtensionsCapabilityParsingError<'a> {
    type Span = Span<'a>;
    type Error = MultiProtocolExtensionsCapabilityParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedBGPCapabilityParsingError<'a>>
    for LocatedMultiProtocolExtensionsCapabilityParsingError<'a>
{
    fn into_located(self) -> LocatedBGPCapabilityParsingError<'a> {
        LocatedBGPCapabilityParsingError::new(
            self.span,
            BGPCapabilityParsingError::MultiProtocolExtensionsCapabilityError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, MultiProtocolExtensionsCapabilityParsingError>
    for LocatedMultiProtocolExtensionsCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: MultiProtocolExtensionsCapabilityParsingError,
    ) -> Self {
        LocatedMultiProtocolExtensionsCapabilityParsingError::new(input, error)
    }
}

impl<'a> ParseError<Span<'a>> for LocatedMultiProtocolExtensionsCapabilityParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedMultiProtocolExtensionsCapabilityParsingError::new(
            input,
            MultiProtocolExtensionsCapabilityParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedAddressFamily>
    for LocatedMultiProtocolExtensionsCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedAddressFamily,
    ) -> Self {
        LocatedMultiProtocolExtensionsCapabilityParsingError::new(
            input,
            MultiProtocolExtensionsCapabilityParsingError::AddressFamilyError(error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedSubsequentAddressFamily>
    for LocatedMultiProtocolExtensionsCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedSubsequentAddressFamily,
    ) -> Self {
        LocatedMultiProtocolExtensionsCapabilityParsingError::new(
            input,
            MultiProtocolExtensionsCapabilityParsingError::SubsequentAddressFamilyError(error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedMultiProtocolExtensionsCapabilityParsingError<'a>>
    for MultiProtocolExtensionsCapability
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedMultiProtocolExtensionsCapabilityParsingError<'a>> {
        let (buf, _) =
            check_capability_length(buf, MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH, |x| {
                MultiProtocolExtensionsCapabilityParsingError::InvalidLength(x)
            })?;
        let input = buf;
        let (buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(buf)?;
        let (buf, _) = be_u8(buf)?;
        let (buf, safi) = nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(buf)?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedMultiProtocolExtensionsCapabilityParsingError::new(
                        input,
                        MultiProtocolExtensionsCapabilityParsingError::AddressTypeError(err),
                    ),
                ))
            }
        };
        Ok((buf, MultiProtocolExtensionsCapability::new(address_type)))
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum AddPathCapabilityParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    AddressFamilyError(UndefinedAddressFamily),
    SubsequentAddressFamilyError(UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
    InvalidAddPathSendReceiveValue(u8),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedAddPathCapabilityParsingError<'a> {
    span: Span<'a>,
    error: AddPathCapabilityParsingError,
}

impl<'a> LocatedAddPathCapabilityParsingError<'a> {
    pub const fn new(span: Span<'a>, error: AddPathCapabilityParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedAddPathCapabilityParsingError<'a> {
    type Span = Span<'a>;
    type Error = AddPathCapabilityParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedBGPCapabilityParsingError<'a>>
    for LocatedAddPathCapabilityParsingError<'a>
{
    fn into_located(self) -> LocatedBGPCapabilityParsingError<'a> {
        LocatedBGPCapabilityParsingError::new(
            self.span,
            BGPCapabilityParsingError::AddPathCapabilityError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, AddPathCapabilityParsingError>
    for LocatedAddPathCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: AddPathCapabilityParsingError,
    ) -> Self {
        LocatedAddPathCapabilityParsingError::new(input, error)
    }
}

impl<'a> ParseError<Span<'a>> for LocatedAddPathCapabilityParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedAddPathCapabilityParsingError::new(
            input,
            AddPathCapabilityParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedAddressFamily>
    for LocatedAddPathCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedAddressFamily,
    ) -> Self {
        LocatedAddPathCapabilityParsingError::new(
            input,
            AddPathCapabilityParsingError::AddressFamilyError(error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedSubsequentAddressFamily>
    for LocatedAddPathCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedSubsequentAddressFamily,
    ) -> Self {
        LocatedAddPathCapabilityParsingError::new(
            input,
            AddPathCapabilityParsingError::SubsequentAddressFamilyError(error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedAddPathCapabilityParsingError<'a>> for AddPathCapability {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedAddPathCapabilityParsingError<'a>> {
        let (buf, params_buf) = nom::multi::length_data(be_u8)(buf)?;
        let (_, address_families) = parse_till_empty(params_buf)?;

        Ok((buf, AddPathCapability::new(address_families)))
    }
}

impl<'a> ReadablePDU<'a, LocatedAddPathCapabilityParsingError<'a>>
    for AddPathCapabilityAddressFamily
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedAddPathCapabilityParsingError<'a>> {
        let input = buf;
        let (buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(buf)?;
        let (buf, safi) = nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(buf)?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(nom::Err::Error(LocatedAddPathCapabilityParsingError::new(
                    input,
                    AddPathCapabilityParsingError::AddressTypeError(err),
                )))
            }
        };
        let (buf, (receive, send)) = nom::combinator::map_res(be_u8, |send_receive| {
            if send_receive > 0x03u8 {
                Err(AddPathCapabilityParsingError::InvalidAddPathSendReceiveValue(send_receive))
            } else {
                Ok((
                    send_receive & 0x01u8 == 0x01u8,
                    send_receive & 0x02u8 == 0x02u8,
                ))
            }
        })(buf)?;

        Ok((
            buf,
            AddPathCapabilityAddressFamily::new(address_type, send, receive),
        ))
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ExtendedNextHopEncodingCapabilityParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    AddressFamilyError(UndefinedAddressFamily),
    SubsequentAddressFamilyError(UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedExtendedNextHopEncodingCapabilityParsingError<'a> {
    span: Span<'a>,
    error: ExtendedNextHopEncodingCapabilityParsingError,
}

impl<'a> LocatedExtendedNextHopEncodingCapabilityParsingError<'a> {
    pub const fn new(span: Span<'a>, error: ExtendedNextHopEncodingCapabilityParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedExtendedNextHopEncodingCapabilityParsingError<'a> {
    type Span = Span<'a>;
    type Error = ExtendedNextHopEncodingCapabilityParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> IntoLocatedError<LocatedBGPCapabilityParsingError<'a>>
    for LocatedExtendedNextHopEncodingCapabilityParsingError<'a>
{
    fn into_located(self) -> LocatedBGPCapabilityParsingError<'a> {
        LocatedBGPCapabilityParsingError::new(
            self.span,
            BGPCapabilityParsingError::ExtendedNextHopEncodingCapabilityError(self.error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, ExtendedNextHopEncodingCapabilityParsingError>
    for LocatedExtendedNextHopEncodingCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: ExtendedNextHopEncodingCapabilityParsingError,
    ) -> Self {
        LocatedExtendedNextHopEncodingCapabilityParsingError::new(input, error)
    }
}

impl<'a> ParseError<Span<'a>> for LocatedExtendedNextHopEncodingCapabilityParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedExtendedNextHopEncodingCapabilityParsingError::new(
            input,
            ExtendedNextHopEncodingCapabilityParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedAddressFamily>
    for LocatedExtendedNextHopEncodingCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedAddressFamily,
    ) -> Self {
        LocatedExtendedNextHopEncodingCapabilityParsingError::new(
            input,
            ExtendedNextHopEncodingCapabilityParsingError::AddressFamilyError(error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedSubsequentAddressFamily>
    for LocatedExtendedNextHopEncodingCapabilityParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UndefinedSubsequentAddressFamily,
    ) -> Self {
        LocatedExtendedNextHopEncodingCapabilityParsingError::new(
            input,
            ExtendedNextHopEncodingCapabilityParsingError::SubsequentAddressFamilyError(error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedExtendedNextHopEncodingCapabilityParsingError<'a>>
    for ExtendedNextHopEncodingCapability
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedExtendedNextHopEncodingCapabilityParsingError<'a>> {
        let (buf, encodings_buf) = nom::multi::length_data(be_u8)(buf)?;
        let (_, encodings) = parse_till_empty(encodings_buf)?;

        Ok((buf, ExtendedNextHopEncodingCapability::new(encodings)))
    }
}

impl<'a> ReadablePDU<'a, LocatedExtendedNextHopEncodingCapabilityParsingError<'a>>
    for ExtendedNextHopEncoding
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedExtendedNextHopEncodingCapabilityParsingError<'a>> {
        let input = buf;
        let (buf, ehe_buf) =
            nom::bytes::complete::take(EXTENDED_NEXT_HOP_ENCODING_LENGTH as usize)(buf)?;
        let (ehe_buf, nlri_afi) =
            nom::combinator::map_res(be_u16, AddressFamily::try_from)(ehe_buf)?;
        let (ehe_buf, nlri_safi) =
            nom::combinator::map_res(be_u16, |x| SubsequentAddressFamily::try_from(x as u8))(
                ehe_buf,
            )?;
        let address_type = match AddressType::from_afi_safi(nlri_afi, nlri_safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedExtendedNextHopEncodingCapabilityParsingError::new(
                        input,
                        ExtendedNextHopEncodingCapabilityParsingError::AddressTypeError(err),
                    ),
                ))
            }
        };

        let (_, next_hop_afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(ehe_buf)?;

        Ok((
            buf,
            ExtendedNextHopEncoding::new(address_type, next_hop_afi),
        ))
    }
}
