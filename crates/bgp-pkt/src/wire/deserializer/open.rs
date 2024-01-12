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
    capabilities::BgpCapability,
    iana::{BgpOpenMessageParameterType, UndefinedBgpOpenMessageParameterType},
    notification::OpenMessageError,
    open::{BgpOpenMessageParameter, BGP_VERSION},
    wire::deserializer::{capabilities::BgpCapabilityParsingError, BgpParsingContext},
    BgpOpenMessage,
};
use netgauze_parse_utils::{
    parse_into_located_one_input, ErrorKindSerdeDeref, LocatedParsingError, ReadablePdu,
    ReadablePduWithOneInput, Span,
};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// BGP Open Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpOpenMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UnsupportedVersionNumber(u8),
    UnacceptableHoldTime(u16),
    /// RFC 4271 specifies that BGP ID must be a valid unicast IP host address.
    InvalidBgpId(u32),
    ParameterError(#[from_located(module = "self")] BgpParameterParsingError),
}

/// BGP Open Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpParameterParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedParameterType(#[from_external] UndefinedBgpOpenMessageParameterType),
    CapabilityError(
        #[from_located(module = "crate::wire::deserializer::capabilities")]
        BgpCapabilityParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, &mut BgpParsingContext, LocatedBgpOpenMessageParsingError<'a>>
    for BgpOpenMessage
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBgpOpenMessageParsingError<'a>> {
        let (buf, _) = nom::combinator::map_res(be_u8, |x| {
            if x == 4 {
                Ok(x)
            } else {
                Err(BgpOpenMessageParsingError::UnsupportedVersionNumber(x))
            }
        })(buf)?;
        let (buf, my_as) = be_u16(buf)?;
        let begin_buf = buf;
        let (buf, hold_time) = be_u16(buf)?;
        // RFC 4271: If the Hold Time field of the OPEN message is unacceptable, then
        // the Error Subcode MUST be set to Unacceptable Hold Time. An implementation
        // MUST reject Hold Time values of one or two seconds. An implementation MAY
        // reject any proposed Hold Time.
        if hold_time == 1 || hold_time == 2 {
            return Err(nom::Err::Error(LocatedBgpOpenMessageParsingError::new(
                begin_buf,
                BgpOpenMessageParsingError::UnacceptableHoldTime(hold_time),
            )));
        }
        let (buf, bgp_id) = be_u32(buf)?;
        let begin_buf = buf;
        let bgp_id = Ipv4Addr::from(bgp_id);
        // RFC 4271: If the BGP Identifier field of the OPEN message is syntactically
        // incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
        // Syntactic correctness means that the BGP Identifier field represents
        // a valid unicast IP host address. NOTE: not all BGP implementation
        // check for syntactic correctness
        if bgp_id.is_broadcast() || bgp_id.is_multicast() || bgp_id.is_unspecified() {
            return Err(nom::Err::Error(LocatedBgpOpenMessageParsingError::new(
                begin_buf,
                BgpOpenMessageParsingError::InvalidBgpId(bgp_id.into()),
            )));
        }
        let (buf, mut params_buf) = nom::multi::length_data(be_u8)(buf)?;
        let mut params = Vec::new();
        while !params_buf.is_empty() {
            let (tmp, element) = parse_into_located_one_input(params_buf, &mut *ctx)?;
            params.push(element);
            params_buf = tmp;
        }
        Ok((buf, BgpOpenMessage::new(my_as, hold_time, bgp_id, params)))
    }
}

impl<'a> ReadablePduWithOneInput<'a, &mut BgpParsingContext, LocatedBgpParameterParsingError<'a>>
    for BgpOpenMessageParameter
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBgpParameterParsingError<'a>> {
        let begin_buf = buf;
        let (buf, param_type) =
            nom::combinator::map_res(be_u8, BgpOpenMessageParameterType::try_from)(buf)?;
        match param_type {
            BgpOpenMessageParameterType::Capability => parse_capability_param(buf, ctx),
            BgpOpenMessageParameterType::ExtendedLength => {
                return Err(nom::Err::Error(LocatedBgpParameterParsingError::new(
                    begin_buf,
                    BgpParameterParsingError::UndefinedParameterType(
                        UndefinedBgpOpenMessageParameterType(
                            BgpOpenMessageParameterType::ExtendedLength.into(),
                        ),
                    ),
                )))
            }
        }
    }
}

#[inline]
fn parse_capability_param<'a>(
    buf: Span<'a>,
    ctx: &mut BgpParsingContext,
) -> IResult<Span<'a>, BgpOpenMessageParameter, LocatedBgpParameterParsingError<'a>> {
    let (buf, mut capabilities_buf) = nom::multi::length_data(be_u8)(buf)?;
    let mut capabilities = Vec::new();
    while !capabilities_buf.is_empty() {
        match BgpCapability::from_wire(capabilities_buf) {
            Ok((tmp, capability)) => {
                capabilities.push(capability);
                capabilities_buf = tmp;
            }
            Err(err) => {
                match err {
                    nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed))?,
                    nom::Err::Error(err) => {
                        if !ctx.fail_on_capability_error {
                            // Advance the parser and ignore malformed capability
                            // RFC 5492 defines that a BGP speaker should ignore capabilities it
                            // does not understand and not report any error.
                            // It will only report a notification if the capability is
                            // understood but not supported by the speaker
                            let (tmp, _code) = be_u8(capabilities_buf)?;
                            let (tmp, _value) = nom::multi::length_count(be_u8, be_u8)(tmp)?;
                            capabilities_buf = tmp;
                            ctx.parsing_errors
                                .capability_errors
                                .push(err.error().clone());
                        } else {
                            Err(nom::Err::Error(err.into()))?
                        }
                    }
                    nom::Err::Failure(failure) => {
                        if !ctx.fail_on_capability_error {
                            // Advance the parser and ignore malformed capability
                            // RFC 5492 defines that a BGP speaker should ignore capabilities it
                            // does not understand and not report any error.
                            // It will only report a notification if the capability is
                            // understood but not supported by the speaker
                            let (tmp, _code) = be_u8(capabilities_buf)?;
                            let (tmp, _value) = nom::multi::length_count(be_u8, be_u8)(tmp)?;
                            capabilities_buf = tmp;
                            ctx.parsing_errors
                                .capability_errors
                                .push(failure.error().clone());
                        } else {
                            Err(nom::Err::Failure(failure.into()))?
                        }
                    }
                }
            }
        }
    }
    Ok((buf, BgpOpenMessageParameter::Capabilities(capabilities)))
}

impl From<BgpParameterParsingError> for OpenMessageError {
    fn from(param_err: BgpParameterParsingError) -> Self {
        match param_err {
            // RFC 4271: If one of the Optional Parameters in the OPEN message is recognized, but is
            // malformed, then the Error Subcode MUST be set to 0 (Unspecific)
            BgpParameterParsingError::NomError(_) => OpenMessageError::Unspecific { value: vec![] },
            // RFC 4271: If one of the Optional Parameters in the OPEN message is not recognized,
            // then the Error Subcode MUST be set to Unsupported Optional Parameters.
            BgpParameterParsingError::UndefinedParameterType(param_type) => {
                OpenMessageError::UnsupportedOptionalParameter {
                    value: vec![param_type.0],
                }
            }
            // RFC 5492 defines that a BGP speaker should ignore capabilities it
            // does not understand and not report any error.
            // It will only report a notification if the capability is
            // understood but not supported by the speaker. If an error is reported anyways by the
            // parser we set the notif to Unspecific
            BgpParameterParsingError::CapabilityError(_) => {
                OpenMessageError::Unspecific { value: vec![] }
            }
        }
    }
}

impl From<BgpOpenMessageParsingError> for OpenMessageError {
    fn from(error: BgpOpenMessageParsingError) -> Self {
        match error {
            BgpOpenMessageParsingError::NomError(_) => {
                OpenMessageError::Unspecific { value: vec![] }
            }
            // RFC 4271: If the version number in the Version field of the received OPEN message is
            // not supported, then the Error Subcode MUST be set to Unsupported Version Number.
            // The Data field is a 2-octet unsigned integer, which indicates the largest,
            // locally-supported version number less than the version the remote BGP peer bid (as
            // indicated in the received OPEN message), or if the smallest, locally-supported
            // version number is greater than the version the remote BGP peer bid, then the
            // smallest, locally-supported version number.
            BgpOpenMessageParsingError::UnsupportedVersionNumber(_) => {
                OpenMessageError::UnsupportedVersionNumber {
                    value: (BGP_VERSION as u16).to_be_bytes().to_vec(),
                }
            }
            BgpOpenMessageParsingError::UnacceptableHoldTime(hold_time) => {
                OpenMessageError::UnacceptableHoldTime {
                    value: hold_time.to_be_bytes().to_vec(),
                }
            }
            // RFC 4271: If the BGP Identifier field of the OPEN message is syntactically incorrect,
            // then the Error Subcode MUST be set to Bad BGP Identifier. Syntactic correctness means
            // that the BGP Identifier field represents a valid unicast IP host address.
            // NOTE: not all BGP implementation check for syntactic correctness
            BgpOpenMessageParsingError::InvalidBgpId(bgp_id) => {
                OpenMessageError::BadBgpIdentifier {
                    value: bgp_id.to_be_bytes().to_vec(),
                }
            }
            BgpOpenMessageParsingError::ParameterError(param_error) => param_error.into(),
        }
    }
}
