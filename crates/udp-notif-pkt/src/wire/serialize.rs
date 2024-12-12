// Copyright (C) 2024-present The NetGauze Authors.
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

use crate::{MediaTypeNames, UdpNotifOption, UdpNotifPacket};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum UdpNotifOptionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<UdpNotifOptionWritingError> for UdpNotifOption {
    // One octet for type and another for length
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        match self {
            UdpNotifOption::Segment { .. } => {
                // base length + two octets for segment length of which the last bit is a `last
                // segment` flag
                Self::BASE_LENGTH + 2
            }
            UdpNotifOption::PrivateEncoding(value) => Self::BASE_LENGTH + value.len(),
            UdpNotifOption::Unknown { value, .. } => Self::BASE_LENGTH + value.len(),
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), UdpNotifOptionWritingError> {
        match self {
            UdpNotifOption::Segment { number, last } => {
                writer.write_u8(1)?;
                writer.write_u8(4)?;
                writer.write_u16::<NetworkEndian>(number << 1 | if *last { 1u16 } else { 0 })?;
            }
            UdpNotifOption::PrivateEncoding(value) => {
                writer.write_u8(2)?;
                writer.write_u8(value.len() as u8 + 2)?;
                writer.write_all(value)?;
            }
            UdpNotifOption::Unknown { typ, value } => {
                writer.write_u8(*typ)?;
                writer.write_u8(value.len() as u8 + 2)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum UdpNotifPacketWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidHeaderLength(usize),
    InvalidMessageLength(usize),
    OptionError(#[from] UdpNotifOptionWritingError),
}

impl WritablePdu<UdpNotifPacketWritingError> for UdpNotifPacket {
    const BASE_LENGTH: usize = 12;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self
                .options
                .values()
                .map(UdpNotifOption::len)
                .sum::<usize>()
            + self.payload.len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), UdpNotifPacketWritingError> {
        let version: u8 = 0x01;
        let mut first_byte: u8 = version << 5;
        if MediaTypeNames::from(self.media_type) == MediaTypeNames::Unknown {
            first_byte |= 0x10;
        }
        let mt: u8 = self.media_type.into();
        first_byte |= mt;
        writer.write_u8(first_byte)?;
        let header_len = 12
            + self
                .options
                .values()
                .map(UdpNotifOption::len)
                .sum::<usize>();
        if header_len > u8::MAX as usize {
            return Err(UdpNotifPacketWritingError::InvalidHeaderLength(header_len));
        }
        writer.write_u8(header_len as u8)?;
        let message_len = header_len + self.payload().len();
        if message_len > u16::MAX as usize {
            return Err(UdpNotifPacketWritingError::InvalidMessageLength(
                message_len,
            ));
        }
        writer.write_u16::<NetworkEndian>(message_len as u16)?;
        writer.write_u32::<NetworkEndian>(self.publisher_id())?;
        writer.write_u32::<NetworkEndian>(self.message_id())?;
        for option in self.options() {
            option.1.write(writer)?;
        }
        writer.write_all(self.payload())?;
        Ok(())
    }
}
