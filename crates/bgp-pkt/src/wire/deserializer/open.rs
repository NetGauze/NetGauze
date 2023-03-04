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
    iana::{BgpOpenMessageParameterType, UndefinedBgpOpenMessageParameterType},
    open::BgpOpenMessageParameter,
    wire::deserializer::capabilities::BgpCapabilityParsingError,
    BgpOpenMessage,
};
use netgauze_parse_utils::{parse_till_empty_into_located, ErrorKindSerdeDeref, ReadablePdu, Span};
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

impl<'a> ReadablePdu<'a, LocatedBgpOpenMessageParsingError<'a>> for BgpOpenMessage {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpOpenMessageParsingError<'a>> {
        let (buf, _) = nom::combinator::map_res(be_u8, |x| {
            if x == 4 {
                Ok(x)
            } else {
                Err(BgpOpenMessageParsingError::UnsupportedVersionNumber(x))
            }
        })(buf)?;
        let (buf, my_as) = be_u16(buf)?;
        let (buf, hold_time) = be_u16(buf)?;
        let (buf, bgp_id) = be_u32(buf)?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        let (buf, params_buf) = nom::multi::length_data(be_u8)(buf)?;
        let (_, params) = parse_till_empty_into_located(params_buf)?;
        Ok((buf, BgpOpenMessage::new(my_as, hold_time, bgp_id, params)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpParameterParsingError<'a>> for BgpOpenMessageParameter {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpParameterParsingError<'a>> {
        let begin_buf = buf;
        let (buf, param_type) =
            nom::combinator::map_res(be_u8, BgpOpenMessageParameterType::try_from)(buf)?;
        match param_type {
            BgpOpenMessageParameterType::Capability => {
                let (buf, capabilities_buf) = nom::multi::length_data(be_u8)(buf)?;
                let (_, capabilities) = parse_till_empty_into_located(capabilities_buf)?;
                Ok((buf, BgpOpenMessageParameter::Capabilities(capabilities)))
            }
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
