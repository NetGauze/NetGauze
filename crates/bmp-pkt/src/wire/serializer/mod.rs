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

//! Serializer library for BMP's wire protocol

pub mod v3;
pub mod v4;

use crate::{
    wire::serializer::{v3::BmpMessageValueWritingError, v4::BmpV4MessageValueWritingError},
    *,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    BmpMessageValueError(#[from] BmpMessageValueWritingError),
    BmpV4MessageValueError(#[from] BmpV4MessageValueWritingError),
}

impl WritablePdu<BmpMessageWritingError> for BmpMessage {
    /// 1-octet version, 4-octets msg length
    const BASE_LENGTH: usize = 5;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::V3(value) => value.len(),
                Self::V4(value) => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BmpMessageWritingError> {
        writer.write_u8(self.get_version().into())?;
        writer.write_u32::<NetworkEndian>(self.len() as u32)?;

        match self {
            Self::V3(value) => {
                value.write(writer)?;
            }
            Self::V4(value) => {
                value.write(writer)?;
            }
        }
        Ok(())
    }
}
