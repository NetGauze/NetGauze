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
use netgauze_parse_utils::{ReadablePdu, Span, parse_into_located};
use netgauze_serde_macros::LocatedError;
use nom::IResult;
use nom::error::ErrorKind;
use nom::number::complete::{be_u16, be_u32};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(
    LocatedError, strum_macros::Display, Eq, PartialEq, Clone, Debug, Serialize, Deserialize,
)]
pub enum UdpNotifOptionParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidOptionLength(u8),
}

impl std::error::Error for UdpNotifOptionParsingError {}

impl<'a> ReadablePdu<'a, LocatedUdpNotifOptionParsingError<'a>> for UdpNotifOption {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedUdpNotifOptionParsingError<'a>> {
        let (buf, typ) = nom::number::complete::u8(buf)?;
        let input = buf;
        let (buf, option_len) = nom::number::complete::u8(buf)?;
        if option_len < 2 {
            return Err(nom::Err::Error(LocatedUdpNotifOptionParsingError::new(
                input,
                UdpNotifOptionParsingError::InvalidOptionLength(option_len),
            )));
        }
        let (buf, value_buf) = nom::bytes::complete::take(option_len - 2)(buf)?;
        match typ {
            1 => {
                let (value_buf, high) = nom::number::complete::u8(value_buf)?;
                let (_value_buf, low) = nom::number::complete::u8(value_buf)?;
                let number = ((high as u16) << 7) | ((low as u16) >> 1);
                // Extract the L flag (the least significant bit of the last byte)
                let last = (low & 0x01) != 0;

                Ok((buf, UdpNotifOption::Segment { number, last }))
            }
            2 => Ok((buf, UdpNotifOption::PrivateEncoding(value_buf.to_vec()))),
            typ => Ok((
                buf,
                UdpNotifOption::Unknown {
                    typ,
                    value: value_buf.to_vec(),
                },
            )),
        }
    }
}

#[derive(
    LocatedError, strum_macros::Display, Eq, PartialEq, Clone, Debug, Serialize, Deserialize,
)]
pub enum UdpNotifPacketParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),

    #[strum(to_string = "Invalid UDP-Notif version {0}")]
    InvalidVersion(u8),

    #[strum(to_string = "UDP-Notif with invalid S-Flag")]
    InvalidSFlag,

    #[strum(to_string = "Invalid options: {0}")]
    UdpNotifOptionError(#[from_located(module = "self")] UdpNotifOptionParsingError),

    #[strum(to_string = "UDP-Notif with invalid headers length {0}")]
    InvalidHeaderLength(u8),

    #[strum(to_string = "UDP-Notif with invalid message length {0}")]
    InvalidMessageLength(u16),

    #[strum(to_string = "S Flag is set without private encoding option")]
    PrivateEncodingOptionIsNotPresent,
}

impl std::error::Error for UdpNotifPacketParsingError {}

impl<'a> ReadablePdu<'a, LocatedUdpNotifPacketParsingError<'a>> for UdpNotifPacket {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedUdpNotifPacketParsingError<'a>> {
        if buf.len() < 12 {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                buf,
                UdpNotifPacketParsingError::NomError(ErrorKind::Eof),
            )));
        }
        let (_, first_word) = nom::combinator::peek(be_u32)(buf)?;
        let message_len = (first_word & 0x0000ffff) as u16;
        let header_len = ((first_word & 0x00ff0000) >> 16) as u8;
        if header_len as u16 > message_len {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                buf,
                UdpNotifPacketParsingError::InvalidHeaderLength(header_len),
            )));
        }
        let payload_len = message_len as usize - header_len as usize;
        let input = buf;
        let (buf, first_octet) = nom::number::complete::u8(buf)?;
        let version = (first_octet >> 5) & 0b111;
        if version != 1 {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                input,
                UdpNotifPacketParsingError::InvalidVersion(version),
            )));
        }
        let s_flag = (first_octet & 0b00010000) != 0;
        let media_type: MediaType = (first_octet & 0b00001111).into();
        if s_flag && MediaTypeNames::from(media_type) != MediaTypeNames::Unknown {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                input,
                UdpNotifPacketParsingError::InvalidSFlag,
            )));
        }
        let (buf, header_len) = nom::number::complete::u8(buf)?;
        if header_len < 2 {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                input,
                UdpNotifPacketParsingError::InvalidHeaderLength(header_len),
            )));
        }
        if buf.len() < (header_len - 2) as usize {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                input,
                UdpNotifPacketParsingError::InvalidHeaderLength(header_len),
            )));
        }
        let header_buf_input = buf;
        let (buf, header_buf) = nom::bytes::complete::take(header_len - 2)(buf)?;
        let (header_buf, _message_length) = be_u16(header_buf)?;
        let (header_buf, publisher_id) = be_u32(header_buf)?;
        let (mut header_buf, message_id) = be_u32(header_buf)?;
        let mut options = HashMap::new();
        // AS per UDP NOTIF RFC: When S is set, MT represents a private space to be
        // freely used for non standard encodings. When S is set, the Private
        // Encoding Option SHOULD be present in the UDP-Notif message header.
        let mut private_is_correct = !s_flag;
        while !header_buf.is_empty() {
            let (t, option) = parse_into_located::<
                LocatedUdpNotifOptionParsingError<'_>,
                LocatedUdpNotifPacketParsingError<'_>,
                UdpNotifOption,
            >(header_buf)?;
            if s_flag && option.code() == UdpNotifOptionCode::PrivateEncoding {
                private_is_correct = true;
            }
            options.insert(option.code(), option);
            header_buf = t;
        }
        if !private_is_correct {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                header_buf_input,
                UdpNotifPacketParsingError::PrivateEncodingOptionIsNotPresent,
            )));
        }
        let (buf, payload) = nom::bytes::complete::take(payload_len)(buf)?;
        // TODO: find more efficient way without need to do a memory copy
        let payload = Bytes::from(payload.to_vec());
        Ok((
            buf,
            UdpNotifPacket::new(media_type, publisher_id, message_id, options, payload),
        ))
    }
}
