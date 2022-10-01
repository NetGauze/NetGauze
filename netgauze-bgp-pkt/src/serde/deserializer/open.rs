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
    iana::{BGPOpenMessageParameterType, UndefinedBGPOpenMessageParameterType},
    open::BGPOpenMessageParameter,
    serde::deserializer::capabilities::BGPCapabilityParsingError,
    BGPOpenMessage,
};
use netgauze_parse_utils::{parse_till_empty_into_located, ReadablePDU, Span};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use std::net::Ipv4Addr;

/// BGP Open Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BGPOpenMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    UnsupportedVersionNumber(u8),
    ParameterError(#[from_located(module = "self")] BGPParameterParsingError),
}

/// BGP Open Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BGPParameterParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    UndefinedParameterType(#[from_external] UndefinedBGPOpenMessageParameterType),
    CapabilityError(
        #[from_located(module = "crate::serde::deserializer::capabilities")]
        BGPCapabilityParsingError,
    ),
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
        let (_, params) = parse_till_empty_into_located(params_buf)?;
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
                let (_, capabilities) = parse_till_empty_into_located(capabilities_buf)?;
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
