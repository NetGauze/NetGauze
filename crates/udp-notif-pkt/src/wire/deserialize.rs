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

use crate::raw::{MediaType, MediaTypeNames, UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket};
use bytes::Bytes;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFrom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UdpNotifOptionParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("UDP-Notif option with invalid length {0}")]
    InvalidOptionLength(u8),
}

impl<'a> ParseFrom<'a> for UdpNotifOption {
    type Error = UdpNotifOptionParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let typ = cur.read_u8()?;
        let option_len = cur.read_u8()?;
        if option_len < 2 {
            return Err(UdpNotifOptionParsingError::InvalidOptionLength(option_len));
        }
        let value_buf = cur.read_bytes(option_len as usize - 2)?;
        match typ {
            1 => {
                let mut value = SliceReader::new(value_buf);
                let high = value.read_u8()?;
                let low = value.read_u8()?;
                let number = ((high as u16) << 7) | ((low as u16) >> 1);
                // Extract the L flag (the least significant bit of the last byte)
                let last = (low & 0x01) != 0;
                Ok(UdpNotifOption::Segment { number, last })
            }
            2 => Ok(UdpNotifOption::PrivateEncoding(value_buf.to_vec())),
            typ => Ok(UdpNotifOption::Unknown {
                typ,
                value: value_buf.to_vec(),
            }),
        }
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UdpNotifPacketParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("Invalid UDP-Notif version {0}")]
    InvalidVersion(u8),

    #[error("UDP-Notif with invalid S-Flag")]
    InvalidSFlag,

    #[error("Invalid options: {0}")]
    UdpNotifOptionError(#[from] UdpNotifOptionParsingError),

    #[error("UDP-Notif with invalid headers length {0}")]
    InvalidHeaderLength(u8),

    #[error("UDP-Notif with invalid message length {0}")]
    InvalidMessageLength(u16),

    #[error("S Flag is set without private encoding option")]
    PrivateEncodingOptionIsNotPresent,
}

impl<'a> ParseFrom<'a> for UdpNotifPacket {
    type Error = UdpNotifPacketParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        if cur.remaining() < 12 {
            return Err(ParseError::eof(cur.offset(), 12, cur.remaining()).into());
        }
        let first_word = cur.peek_u32_be()?;
        let message_len = (first_word & 0x0000ffff) as u16;
        let header_len = ((first_word & 0x00ff0000) >> 16) as u8;
        if header_len as u16 > message_len {
            return Err(UdpNotifPacketParsingError::InvalidHeaderLength(header_len));
        }
        let payload_len = message_len as usize - header_len as usize;

        let first_octet = cur.read_u8()?;
        let version = (first_octet >> 5) & 0b111;
        if version != 1 {
            return Err(UdpNotifPacketParsingError::InvalidVersion(version));
        }
        let s_flag = (first_octet & 0b00010000) != 0;
        let media_type: MediaType = (first_octet & 0b00001111).into();
        if s_flag && MediaTypeNames::from(media_type) != MediaTypeNames::Unknown {
            return Err(UdpNotifPacketParsingError::InvalidSFlag);
        }

        let header_len = cur.read_u8()?;
        if header_len < 2 {
            return Err(UdpNotifPacketParsingError::InvalidHeaderLength(header_len));
        }
        if cur.remaining() < header_len as usize - 2 {
            return Err(UdpNotifPacketParsingError::InvalidHeaderLength(header_len));
        }
        // The header carries the (redundant) message length, publisher id,
        // message id, then the variable-length options.
        let mut header_buf = cur.take_slice(header_len as usize - 2)?;
        let _message_length = header_buf.read_u16_be()?;
        let publisher_id = header_buf.read_u32_be()?;
        let message_id = header_buf.read_u32_be()?;

        let mut options = HashMap::new();
        // As per UDP-Notif RFC: When S is set, MT represents a private space to be
        // freely used for non standard encodings. When S is set, the Private
        // Encoding Option SHOULD be present in the UDP-Notif message header.
        let mut private_is_correct = !s_flag;
        while !header_buf.is_empty() {
            let option = UdpNotifOption::parse(&mut header_buf)?;
            if s_flag && option.code() == UdpNotifOptionCode::PrivateEncoding {
                private_is_correct = true;
            }
            options.insert(option.code(), option);
        }
        if !private_is_correct {
            return Err(UdpNotifPacketParsingError::PrivateEncodingOptionIsNotPresent);
        }

        // TODO: find more efficient way without need to do a memory copy
        let payload = Bytes::from(cur.read_bytes(payload_len)?.to_vec());
        Ok(UdpNotifPacket::new(
            media_type,
            publisher_id,
            message_id,
            options,
            payload,
        ))
    }
}
