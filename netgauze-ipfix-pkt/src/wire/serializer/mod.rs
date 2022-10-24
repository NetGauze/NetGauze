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

use crate::IpfixHeader;
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum IpfixHeaderWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<IpfixHeaderWritingError> for IpfixHeader {
    /// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
    /// observation domain id)
    const BASE_LENGTH: usize = 16;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), IpfixHeaderWritingError> {
        writer.write_u16::<NetworkEndian>(self.version)?;
        writer.write_u16::<NetworkEndian>(self.len() as u16)?;
        writer.write_u32::<NetworkEndian>(self.export_time.timestamp() as u32)?;
        writer.write_u32::<NetworkEndian>(self.sequence_number)?;
        writer.write_u32::<NetworkEndian>(self.observation_domain_id)?;
        Ok(())
    }
}
