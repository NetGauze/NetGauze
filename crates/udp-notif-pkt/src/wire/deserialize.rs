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

use crate::{UdpNotifHeader, UdpNotifOption, UdpNotifPacket};
use bytes::Bytes;
use netgauze_parse_utils::{parse_into_located, ReadablePdu, ReadablePduWithOneInput, Span};
use netgauze_serde_macros::LocatedError;
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u32},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UdpNotifOptionParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidOptionLength(u8),
}

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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UdpNotifHeaderParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidVersion(u8),
    UdpNotifOptionError(#[from_located(module = "self")] UdpNotifOptionParsingError),
    InvalidHeaderLength(u8),
    InvalidMessageLength(u16),
}

impl<'a> ReadablePdu<'a, LocatedUdpNotifHeaderParsingError<'a>> for UdpNotifHeader {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedUdpNotifHeaderParsingError<'a>> {
        let input = buf;
        let (buf, first_octet) = nom::number::complete::u8(buf)?;
        let version = (first_octet >> 5) & 0b111;
        if version != 1 {
            return Err(nom::Err::Error(LocatedUdpNotifHeaderParsingError::new(
                input,
                UdpNotifHeaderParsingError::InvalidVersion(version),
            )));
        }
        let s_flag = (first_octet & 0b00010000) != 0;
        let media_type = (first_octet & 0b00001111).into();
        let (buf, header_len) = nom::number::complete::u8(buf)?;
        if header_len < 2 {
            return Err(nom::Err::Error(LocatedUdpNotifHeaderParsingError::new(
                input,
                UdpNotifHeaderParsingError::InvalidHeaderLength(header_len),
            )));
        }
        if buf.len() < (header_len - 2) as usize {
            return Err(nom::Err::Error(LocatedUdpNotifHeaderParsingError::new(
                input,
                UdpNotifHeaderParsingError::InvalidHeaderLength(header_len),
            )));
        }
        let (buf, header_buf) = nom::bytes::complete::take(header_len - 2)(buf)?;
        let (header_buf, _message_length) = be_u16(header_buf)?;
        let (header_buf, publisher_id) = be_u32(header_buf)?;
        let (mut header_buf, message_id) = be_u32(header_buf)?;
        let mut options = HashMap::new();
        while !header_buf.is_empty() {
            let (t, option) = parse_into_located::<
                LocatedUdpNotifOptionParsingError<'_>,
                LocatedUdpNotifHeaderParsingError<'_>,
                UdpNotifOption,
            >(header_buf)?;

            options.insert(option.code(), option);
            header_buf = t;
        }
        Ok((
            buf,
            UdpNotifHeader {
                s_flag,
                media_type,
                publisher_id,
                message_id,
                options,
            },
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UdpNotifPacketParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UdpNotifHeaderError(#[from_located(module = "self")] UdpNotifHeaderParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, Bytes, LocatedUdpNotifPacketParsingError<'a>>
    for UdpNotifPacket
{
    fn from_wire(
        buf: Span<'a>,
        bytes_buf: Bytes,
    ) -> IResult<Span<'a>, Self, LocatedUdpNotifPacketParsingError<'a>> {
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
                UdpNotifPacketParsingError::UdpNotifHeaderError(
                    UdpNotifHeaderParsingError::InvalidHeaderLength(header_len),
                ),
            )));
        }
        let payload_len = message_len as usize - header_len as usize;
        let (buf, header) = parse_into_located(buf)?; // this is inefficient copying bytes around
        if bytes_buf.len() < buf.location_offset() + payload_len {
            return Err(nom::Err::Error(LocatedUdpNotifPacketParsingError::new(
                buf,
                UdpNotifPacketParsingError::UdpNotifHeaderError(
                    UdpNotifHeaderParsingError::InvalidMessageLength(message_len),
                ),
            )));
        }
        let payload = bytes_buf.slice(buf.location_offset()..buf.location_offset() + payload_len);
        let (buf, _payload) = nom::bytes::complete::take(payload_len)(buf)?;
        Ok((buf, UdpNotifPacket::new(header, payload)))
    }
}
