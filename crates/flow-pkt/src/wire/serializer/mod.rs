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

use crate::FieldSpecifier;
use crate::ie::InformationElementTemplate;
use netgauze_parse_utils::{WritablePdu, impl_from_io_error};
use std::io::Write;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum FlowWritingError {
    #[error("IO error while writing flow packet: {0}")]
    StdIOError(Box<str>),

    #[error("in IPFIX packet: {0}")]
    IpfixWritingError(#[from] ipfix::IpfixPacketWritingError),

    #[error("in NetFlow V9 packet: {0}")]
    NetFlowV9WritingError(#[from] netflow::NetFlowV9WritingError),
}
impl_from_io_error!(FlowWritingError);

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum FieldSpecifierWritingError {
    #[error("IO error while writing field specifier: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(FieldSpecifierWritingError);

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
            writer.write_all(&element_id.to_be_bytes())?;
        } else {
            // Set Enterprise bit
            writer.write_all(&(element_id | 0x8000).to_be_bytes())?;
        }

        writer.write_all(&self.length.to_be_bytes())?;

        if pen != 0 {
            writer.write_all(&pen.to_be_bytes())?;
        }
        Ok(())
    }
}
