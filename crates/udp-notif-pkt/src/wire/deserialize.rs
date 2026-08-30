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

use crate::raw::{MediaType, UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket};
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
                // Extract the L flag (the least significant bit of the last
                // byte)
                let last = (low & 0x01) != 0;
                Ok(UdpNotifOption::Segment { number, last })
            }
            2 => Ok(UdpNotifOption::PrivateEncoding(value_buf.into())),
            typ => Ok(UdpNotifOption::Unknown {
                typ,
                value: value_buf.into(),
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

    /// No longer produced: when the S-flag is set every MT value is valid,
    /// because the whole field is private space. Retained so that previously
    /// serialized errors still deserialize.
    #[error("UDP-Notif with invalid S-Flag")]
    InvalidSFlag,

    #[error("Invalid options: {0}")]
    UdpNotifOptionError(#[from] UdpNotifOptionParsingError),

    #[error("UDP-Notif with invalid headers length {0}")]
    InvalidHeaderLength(u8),

    #[error("UDP-Notif with invalid message length {0}")]
    InvalidMessageLength(u16),

    /// No longer produced: the "Private Encoding Option" this checked for was
    /// removed from the draft, private encoding being signalled by the S-flag
    /// alone. Retained so that previously serialized errors still deserialize.
    #[error("S Flag is set without private encoding option")]
    PrivateEncodingOptionIsNotPresent,
}

/// Everything a UDP-Notif message carries except its payload. Parsing the
/// fixed header + options is shared between the borrowing [`ParseFrom`]
/// path (which must copy the payload out of the borrowed slice) and the
/// owned-[`Bytes`] implementation (which slices the payload zero-copy).
struct UdpNotifHeader {
    media_type: MediaType,
    publisher_id: u32,
    message_id: u32,
    options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
    /// Number of payload bytes that follow the header at the reader's
    /// current position.
    payload_len: usize,
}

impl<'a> ParseFrom<'a> for UdpNotifHeader {
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
        // The S-flag selects which space the MT field is read against: when
        // set, all 16 values are private and their meaning is agreed
        // out-of-band, so no value is invalid here.
        let s_flag = (first_octet & 0b00010000) != 0;
        let media_type = MediaType::from_wire(first_octet & 0b00001111, s_flag);

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

        // Private encoding is signalled by the S-flag alone; there is no
        // option to look for. Earlier revisions of the draft defined a
        // "Private Encoding Option", but it was removed and the IANA
        // UDP-Notif Option Types registry now assigns only 0 (Reserved) and
        // 1 (Segmentation). Type 2 is still parsed, as an unknown option, for
        // compatibility with senders built against those revisions.
        let mut options = HashMap::new();
        while !header_buf.is_empty() {
            let option = UdpNotifOption::parse(&mut header_buf)?;
            options.insert(option.code(), option);
        }

        Ok(UdpNotifHeader {
            media_type,
            publisher_id,
            message_id,
            options,
            payload_len,
        })
    }
}

impl<'a> ParseFrom<'a> for UdpNotifPacket {
    type Error = UdpNotifPacketParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let header = UdpNotifHeader::parse(cur)?;
        // No owning buffer here (the reader only borrows a `&[u8]`), so the
        // payload must be copied out. Callers with an owned `Bytes` should use
        // [`UdpNotifPacket::from_bytes`] to slice it zero-copy instead.
        let payload = Bytes::copy_from_slice(cur.read_bytes(header.payload_len)?);
        Ok(UdpNotifPacket::new(
            header.media_type,
            header.publisher_id,
            header.message_id,
            header.options,
            payload,
        ))
    }
}

impl UdpNotifPacket {
    /// Parse a complete UDP-Notif packet out of an owned [`Bytes`] buffer,
    /// slicing the payload zero-copy (a refcount bump on the shared
    /// allocation) instead of copying it. `buf` must start at the packet
    /// header; any bytes beyond the declared message length are ignored.
    pub fn from_bytes(buf: Bytes) -> Result<Self, UdpNotifPacketParsingError> {
        // Parse the header off a borrow, then release the borrow (offsets are
        // `Copy`) so the payload can be sliced out of the owning `buf`.
        let (header, payload_start) = {
            let mut cur = SliceReader::new(&buf);
            let header = UdpNotifHeader::parse(&mut cur)?;
            (header, cur.offset())
        };
        let payload = buf.slice(payload_start..payload_start + header.payload_len);
        Ok(UdpNotifPacket::new(
            header.media_type,
            header.publisher_id,
            header.message_id,
            header.options,
            payload,
        ))
    }
}
