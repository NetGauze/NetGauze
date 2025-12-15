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

use nom::IResult;
use nom::error::ErrorKind;
use nom::number::complete::{be_u16, be_u32};
use serde::{Deserialize, Serialize};

use crate::{FieldSpecifier, FieldSpecifierError};
use netgauze_parse_utils::{ErrorKindSerdeDeref, ReadablePdu, Span};
use netgauze_serde_macros::LocatedError;

use crate::ie::{IE, IEError};

pub mod ie;
pub mod ipfix;
pub mod netflow;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FlowParsingError {
    IpfixParsingError(ipfix::IpfixPacketParsingError),
    NetFlowV9ParsingError(netflow::NetFlowV9PacketParsingError),
}

impl std::fmt::Display for FlowParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowParsingError::IpfixParsingError(err) => {
                write!(f, "Flow parsing error parsing IPFIX packet: {err}")
            }
            FlowParsingError::NetFlowV9ParsingError(err) => {
                write!(f, "Flow parsing error parsing Netflow V9 packet: {err}")
            }
        }
    }
}

impl std::error::Error for FlowParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FlowParsingError::IpfixParsingError(err) => Some(err),
            FlowParsingError::NetFlowV9ParsingError(err) => Some(err),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FieldSpecifierParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    FieldSpecifierError(FieldSpecifierError),
    IEError(IEError),
}

impl std::fmt::Display for FieldSpecifierParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(e) => write!(f, "{}", nom::Err::Error(e)),
            Self::FieldSpecifierError(e) => write!(f, "{e}"),
            Self::IEError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FieldSpecifierParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NomError(_err) => None,
            Self::FieldSpecifierError(err) => Some(err),
            Self::IEError(err) => Some(err),
        }
    }
}

impl<'a> ReadablePdu<'a, LocatedFieldSpecifierParsingError<'a>> for FieldSpecifier {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedFieldSpecifierParsingError<'a>> {
        let input = buf;
        let (buf, code) = be_u16(buf)?;
        let is_enterprise = code & 0x8000u16 != 0;
        let (buf, length) = be_u16(buf)?;
        let (buf, (pen, code)) = if is_enterprise {
            let (buf, pen) = be_u32(buf)?;
            // remove the enterprise bit from the IE number
            (buf, (pen, code & 0x7FFF))
        } else {
            (buf, (0, code))
        };
        let ie = match IE::try_from((pen, code)) {
            Ok(ie) => ie,
            Err(err) => {
                return Err(nom::Err::Error(LocatedFieldSpecifierParsingError::new(
                    input,
                    FieldSpecifierParsingError::IEError(err),
                )));
            }
        };
        let spec = match FieldSpecifier::new(ie, length) {
            Ok(spec) => spec,
            Err(err) => {
                return Err(nom::Err::Error(LocatedFieldSpecifierParsingError::new(
                    input,
                    FieldSpecifierParsingError::FieldSpecifierError(err),
                )));
            }
        };
        Ok((buf, spec))
    }
}
