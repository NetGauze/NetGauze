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

use serde::{Deserialize, Serialize};

use crate::{FieldSpecifier, FieldSpecifierError};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFrom;

use crate::ie::{IE, IEError};

pub mod ie;
pub mod ipfix;
pub mod netflow;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FlowParsingError {
    #[error("Flow parsing error parsing IPFIX packet: {0}")]
    IpfixParsingError(ipfix::IpfixPacketParsingError),

    #[error("Flow parsing error parsing NetFlow V9 packet: {0}")]
    NetFlowV9ParsingError(netflow::NetFlowV9PacketParsingError),
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FieldSpecifierParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("in field specifier: {0}")]
    FieldSpecifierError(#[from] FieldSpecifierError),

    #[error("in field specifier: {0}")]
    IEError(#[from] IEError),
}

impl<'a> ParseFrom<'a> for FieldSpecifier {
    type Error = FieldSpecifierParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let code = cur.read_u16_be()?;
        let is_enterprise = code & 0x8000u16 != 0;
        let length = cur.read_u16_be()?;
        let (pen, code) = if is_enterprise {
            let pen = cur.read_u32_be()?;
            // remove the enterprise bit from the IE number
            (pen, code & 0x7FFF)
        } else {
            (0, code)
        };
        let ie = IE::try_from((pen, code))?;
        Ok(FieldSpecifier::new(ie, length)?)
    }
}
