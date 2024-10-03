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

pub mod ie;
pub mod ipfix;
pub mod netflow;

use crate::{ie::InformationElementTemplate, FieldSpecifier};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FlowWritingError {
    StdIOError(#[from_std_io_error] String),
    IpfixWritingError(#[from] ipfix::IpfixPacketWritingError),
    NetFlowV9WritingError(#[from] netflow::NetFlowV9WritingError),
}

impl std::fmt::Display for FlowWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(e) => write!(f, "StdIO error: {e}"),
            Self::IpfixWritingError(e) => write!(f, "IPFIX writing error: {e}"),
            Self::NetFlowV9WritingError(e) => write!(f, "NetFlow V9 writing error: {e}"),
        }
    }
}

impl std::error::Error for FlowWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::IpfixWritingError(e) => Some(e),
            Self::NetFlowV9WritingError(e) => Some(e),
        }
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FieldSpecifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl std::fmt::Display for FieldSpecifierWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(e) => write!(f, "StdIO error: {e}"),
        }
    }
}

impl std::error::Error for FieldSpecifierWritingError {}

impl WritablePdu<FieldSpecifierWritingError> for FieldSpecifier {
    /// 2-octets field id, 2-octets length
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + if self.element_id.pen() == 0 { 0 } else { 4 }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), FieldSpecifierWritingError> {
        let element_id = self.element_id.id();
        let pen = self.element_id.pen();

        if pen == 0 {
            writer.write_u16::<NetworkEndian>(element_id)?;
        } else {
            // Set Enterprise bit
            writer.write_u16::<NetworkEndian>(element_id | 0x8000)?;
        }

        writer.write_u16::<NetworkEndian>(self.length)?;

        if pen != 0 {
            writer.write_u32::<NetworkEndian>(pen)?;
        }
        Ok(())
    }
}
