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

use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u32},
    IResult,
};
use serde::{Deserialize, Serialize};

use crate::{FieldSpecifier, FieldSpecifierError};
use netgauze_parse_utils::{ErrorKindSerdeDeref, ReadablePDU, Span};
use netgauze_serde_macros::LocatedError;

use crate::ie::{IEError, IE};

pub mod ie;
pub mod ipfix;
pub mod netflow;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FlowParsingError {
    IpfixParsingError(ipfix::IpfixPacketParsingError),
    NetFlowV9ParsingError(netflow::NetFlowV9PacketParsingError),
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FieldSpecifierParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    FieldSpecifierError(FieldSpecifierError),
    IEError(IEError),
}

impl<'a> ReadablePDU<'a, LocatedFieldSpecifierParsingError<'a>> for FieldSpecifier {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedFieldSpecifierParsingError<'a>> {
        let input = buf;
        let (buf, code) = be_u16(buf)?;
        let is_enterprise = code & 0x8000u16 != 0;
        let (buf, length) = be_u16(buf)?;
        let (buf, pen) = if is_enterprise {
            be_u32(buf)?
        } else {
            (buf, 0)
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
                )))
            }
        };
        Ok((buf, spec))
    }
}
