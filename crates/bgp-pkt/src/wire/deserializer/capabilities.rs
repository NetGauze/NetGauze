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
    capabilities::*,
    iana::{BgpCapabilityCode, UndefinedBgpCapabilityCode},
};
use netgauze_iana::address_family::{
    AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
    UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{
    parse_into_located, parse_till_empty, parse_till_empty_into_located, ErrorKindSerdeDeref,
    ReadablePdu, Span,
};
use nom::{
    error::{ErrorKind, FromExternalError, ParseError},
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

use crate::{
    iana::{BgpRoleValue, UndefinedBgpRoleValue},
    wire::{
        BGP_ROLE_CAPABILITY_LENGTH, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH,
        EXTENDED_MESSAGE_CAPABILITY_LENGTH, EXTENDED_NEXT_HOP_ENCODING_LENGTH,
        FOUR_OCTET_AS_CAPABILITY_LENGTH, GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH,
        MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH, ROUTE_REFRESH_CAPABILITY_LENGTH,
    },
};
use netgauze_serde_macros::LocatedError;

/// BGP Capability Parsing errors
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpCapabilityParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedCapabilityCode(#[from_external] UndefinedBgpCapabilityCode),
    InvalidRouteRefreshLength(u8),
    InvalidEnhancedRouteRefreshLength(u8),
    InvalidExtendedMessageLength(u8),
    FourOctetAsCapabilityError(#[from_located(module = "self")] FourOctetAsCapabilityParsingError),
    MultiProtocolExtensionsCapabilityError(
        #[from_located(module = "self")] MultiProtocolExtensionsCapabilityParsingError,
    ),
    GracefulRestartCapabilityError(
        #[from_located(module = "self")] GracefulRestartCapabilityParsingError,
    ),
    AddPathCapabilityError(#[from_located(module = "self")] AddPathCapabilityParsingError),
    ExtendedNextHopEncodingCapabilityError(
        #[from_located(module = "self")] ExtendedNextHopEncodingCapabilityParsingError,
    ),
    MultipleLabelError(#[from_located(module = "self")] MultipleLabelParsingError),
    BgpRoleCapabilityError(#[from_located(module = "self")] BgpRoleCapabilityParsingError),
}

fn parse_experimental_capability(
    code: ExperimentalCapabilityCode,
    buf: Span<'_>,
) -> IResult<Span<'_>, BgpCapability, LocatedBgpCapabilityParsingError<'_>> {
    let (buf, value) = nom::multi::length_count(be_u8, be_u8)(buf)?;
    Ok((
        buf,
        BgpCapability::Experimental(ExperimentalCapability::new(code, value)),
    ))
}

fn parse_unrecognized_capability(
    code: u8,
    buf: Span<'_>,
) -> IResult<Span<'_>, BgpCapability, LocatedBgpCapabilityParsingError<'_>> {
    let (buf, value) = nom::multi::length_count(be_u8, be_u8)(buf)?;
    Ok((
        buf,
        BgpCapability::Unrecognized(UnrecognizedCapability::new(code, value)),
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
) -> IResult<Span<'_>, BgpCapability, LocatedBgpCapabilityParsingError<'_>> {
    let (buf, _) = check_capability_length(buf, ROUTE_REFRESH_CAPABILITY_LENGTH, |x| {
        BgpCapabilityParsingError::InvalidRouteRefreshLength(x)
    })?;
    Ok((buf, BgpCapability::RouteRefresh))
}

fn parse_enhanced_route_refresh_capability(
    buf: Span<'_>,
) -> IResult<Span<'_>, BgpCapability, LocatedBgpCapabilityParsingError<'_>> {
    let (buf, _) = check_capability_length(buf, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH, |x| {
        BgpCapabilityParsingError::InvalidEnhancedRouteRefreshLength(x)
    })?;
    Ok((buf, BgpCapability::EnhancedRouteRefresh))
}

impl<'a> ReadablePdu<'a, LocatedBgpCapabilityParsingError<'a>> for BgpCapability {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpCapabilityParsingError<'a>> {
        let parsed: IResult<Span<'_>, BgpCapabilityCode, LocatedBgpCapabilityParsingError<'_>> =
            nom::combinator::map_res(be_u8, BgpCapabilityCode::try_from)(buf);
        match parsed {
            Ok((buf, code)) => match code {
                BgpCapabilityCode::MultiProtocolExtensions => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BgpCapability::MultiProtocolExtensions(cap)))
                }
                BgpCapabilityCode::RouteRefreshCapability => parse_route_refresh_capability(buf),
                BgpCapabilityCode::OutboundRouteFilteringCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BgpCapabilityCode::ExtendedNextHopEncoding => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BgpCapability::ExtendedNextHopEncoding(cap)))
                }
                BgpCapabilityCode::CiscoRouteRefresh => {
                    let (buf, _) =
                        check_capability_length(buf, ROUTE_REFRESH_CAPABILITY_LENGTH, |x| {
                            BgpCapabilityParsingError::InvalidRouteRefreshLength(x)
                        })?;
                    Ok((buf, BgpCapability::CiscoRouteRefresh))
                }
                BgpCapabilityCode::BgpExtendedMessage => {
                    let (buf, _) =
                        check_capability_length(buf, EXTENDED_MESSAGE_CAPABILITY_LENGTH, |x| {
                            BgpCapabilityParsingError::InvalidExtendedMessageLength(x)
                        })?;
                    Ok((buf, BgpCapability::ExtendedMessage))
                }
                BgpCapabilityCode::BgpSecCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BgpCapabilityCode::MultipleLabelsCapability => {
                    let (buf, cap) = parse_till_empty_into_located(buf)?;
                    Ok((buf, BgpCapability::MultipleLabels(cap)))
                }
                BgpCapabilityCode::BgpRole => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BgpCapability::BgpRole(cap)))
                }
                BgpCapabilityCode::GracefulRestartCapability => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BgpCapability::GracefulRestartCapability(cap)))
                }
                BgpCapabilityCode::FourOctetAs => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BgpCapability::FourOctetAs(cap)))
                }
                BgpCapabilityCode::SupportForDynamicCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BgpCapabilityCode::MultiSessionBgpCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BgpCapabilityCode::AddPathCapability => {
                    let (buf, cap) = parse_into_located(buf)?;
                    Ok((buf, BgpCapability::AddPath(cap)))
                }
                BgpCapabilityCode::EnhancedRouteRefresh => {
                    parse_enhanced_route_refresh_capability(buf)
                }
                BgpCapabilityCode::LongLivedGracefulRestartLLGRCapability => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BgpCapabilityCode::RoutingPolicyDistribution => {
                    parse_unrecognized_capability(code.into(), buf)
                }
                BgpCapabilityCode::FQDN => parse_unrecognized_capability(code.into(), buf),
                BgpCapabilityCode::Experimental239 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental239, buf)
                }
                BgpCapabilityCode::Experimental240 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental240, buf)
                }
                BgpCapabilityCode::Experimental241 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental241, buf)
                }
                BgpCapabilityCode::Experimental242 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental242, buf)
                }
                BgpCapabilityCode::Experimental243 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental243, buf)
                }
                BgpCapabilityCode::Experimental244 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental244, buf)
                }
                BgpCapabilityCode::Experimental245 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental245, buf)
                }
                BgpCapabilityCode::Experimental246 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental246, buf)
                }
                BgpCapabilityCode::Experimental247 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental247, buf)
                }
                BgpCapabilityCode::Experimental248 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental248, buf)
                }
                BgpCapabilityCode::Experimental249 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental249, buf)
                }
                BgpCapabilityCode::Experimental250 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental250, buf)
                }
                BgpCapabilityCode::Experimental251 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental251, buf)
                }
                BgpCapabilityCode::Experimental252 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental252, buf)
                }
                BgpCapabilityCode::Experimental253 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental253, buf)
                }
                BgpCapabilityCode::Experimental254 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental254, buf)
                }
            },
            Err(nom::Err::Error(LocatedBgpCapabilityParsingError {
                span: buf,
                error:
                    BgpCapabilityParsingError::UndefinedCapabilityCode(UndefinedBgpCapabilityCode(_)),
            })) => {
                // Parse code again, since nom won't advance the buffer on map_res error
                let (buf, code) = be_u8(buf)?;
                parse_unrecognized_capability(code, buf)
            }
            Err(err) => Err(err),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FourOctetAsCapabilityParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(u8),
}

impl<'a> ReadablePdu<'a, LocatedFourOctetAsCapabilityParsingError<'a>> for FourOctetAsCapability {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedFourOctetAsCapabilityParsingError<'a>> {
        let (buf, _) = check_capability_length(buf, FOUR_OCTET_AS_CAPABILITY_LENGTH, |x| {
            FourOctetAsCapabilityParsingError::InvalidLength(x)
        })?;
        let (buf, asn4) = be_u32(buf)?;
        Ok((buf, FourOctetAsCapability::new(asn4)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MultiProtocolExtensionsCapabilityParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(u8),
    AddressFamilyError(#[from_external] UndefinedAddressFamily),
    SubsequentAddressFamilyError(#[from_external] UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
}

impl<'a> ReadablePdu<'a, LocatedMultiProtocolExtensionsCapabilityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum GracefulRestartCapabilityParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    AddressFamilyError(#[from_external] UndefinedAddressFamily),
    SubsequentAddressFamilyError(#[from_external] UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
}

impl<'a> ReadablePdu<'a, LocatedGracefulRestartCapabilityParsingError<'a>>
    for GracefulRestartCapability
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedGracefulRestartCapabilityParsingError<'a>> {
        let (buf, params_buf) = nom::multi::length_data(be_u8)(buf)?;
        let (params_buf, header) = be_u16(params_buf)?;
        let restart = header & 0x8000 == 0x8000;
        let graceful_notification = header & 0x4000 == 0x4000;
        let time = header & 0x0fff;
        let (_, address_families) = parse_till_empty(params_buf)?;
        Ok((
            buf,
            GracefulRestartCapability::new(restart, graceful_notification, time, address_families),
        ))
    }
}

impl<'a> ReadablePdu<'a, LocatedGracefulRestartCapabilityParsingError<'a>>
    for GracefulRestartAddressFamily
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedGracefulRestartCapabilityParsingError<'a>> {
        let input = buf;
        let (buf, ehe_buf) =
            nom::bytes::complete::take(GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH as usize)(buf)?;
        let (ehe_buf, nlri_afi) =
            nom::combinator::map_res(be_u16, AddressFamily::try_from)(ehe_buf)?;
        let (ehe_buf, nlri_safi) =
            nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(ehe_buf)?;
        let address_type = match AddressType::from_afi_safi(nlri_afi, nlri_safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(nom::Err::Error(
                    LocatedGracefulRestartCapabilityParsingError::new(
                        input,
                        GracefulRestartCapabilityParsingError::AddressTypeError(err),
                    ),
                ))
            }
        };
        let (_, flags) = be_u8(ehe_buf)?;
        let forwarding_state = flags & 0x80 == 0x80;

        Ok((
            buf,
            GracefulRestartAddressFamily::new(forwarding_state, address_type),
        ))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum AddPathCapabilityParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    AddressFamilyError(#[from_external] UndefinedAddressFamily),
    SubsequentAddressFamilyError(#[from_external] UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
    InvalidAddPathSendReceiveValue(u8),
}

impl<'a> ReadablePdu<'a, LocatedAddPathCapabilityParsingError<'a>> for AddPathCapability {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedAddPathCapabilityParsingError<'a>> {
        let (buf, params_buf) = nom::multi::length_data(be_u8)(buf)?;
        let (_, address_families) = parse_till_empty(params_buf)?;

        Ok((buf, AddPathCapability::new(address_families)))
    }
}

impl<'a> ReadablePdu<'a, LocatedAddPathCapabilityParsingError<'a>> for AddPathAddressFamily {
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

        Ok((buf, AddPathAddressFamily::new(address_type, send, receive)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ExtendedNextHopEncodingCapabilityParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    AddressFamilyError(#[from_external] UndefinedAddressFamily),
    SubsequentAddressFamilyError(#[from_external] UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
}

impl<'a> ReadablePdu<'a, LocatedExtendedNextHopEncodingCapabilityParsingError<'a>>
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

impl<'a> ReadablePdu<'a, LocatedExtendedNextHopEncodingCapabilityParsingError<'a>>
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

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MultipleLabelParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    AddressFamilyError(#[from_external] UndefinedAddressFamily),
    SubsequentAddressFamilyError(#[from_external] UndefinedSubsequentAddressFamily),
    AddressTypeError(InvalidAddressType),
}

impl<'a> ReadablePdu<'a, LocatedMultipleLabelParsingError<'a>> for MultipleLabel {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedMultipleLabelParsingError<'a>> {
        let input = buf;
        let (buf, afi) = nom::combinator::map_res(be_u16, AddressFamily::try_from)(buf)?;
        let (buf, safi) = nom::combinator::map_res(be_u8, SubsequentAddressFamily::try_from)(buf)?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(nom::Err::Error(LocatedMultipleLabelParsingError::new(
                    input,
                    MultipleLabelParsingError::AddressTypeError(err),
                )))
            }
        };
        let (buf, count) = be_u8(buf)?;
        Ok((buf, MultipleLabel::new(address_type, count)))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpRoleCapabilityParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(u8),
    UndefinedBgpRoleValue(#[from_external] UndefinedBgpRoleValue),
}

impl<'a> ReadablePdu<'a, LocatedBgpRoleCapabilityParsingError<'a>> for BgpRoleCapability {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBgpRoleCapabilityParsingError<'a>> {
        let (buf, _) = check_capability_length(buf, BGP_ROLE_CAPABILITY_LENGTH, |x| {
            BgpRoleCapabilityParsingError::InvalidLength(x)
        })?;
        let (buf, role) = nom::combinator::map_res(be_u8, BgpRoleValue::try_from)(buf)?;
        Ok((buf, BgpRoleCapability::new(role)))
    }
}
