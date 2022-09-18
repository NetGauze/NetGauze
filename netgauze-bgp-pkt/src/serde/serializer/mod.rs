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

//! Serializer library for BGP's wire protocol

pub mod capabilities;
pub mod open;
pub mod path_attribute;
pub mod update;

use byteorder::{NetworkEndian, WriteBytesExt};

use netgauze_parse_utils::WritablePDU;

use crate::{
    iana::BGPMessageType,
    serde::{
        deserializer::{BGP_MAX_MESSAGE_LENGTH, BGP_MIN_MESSAGE_LENGTH},
        serializer::{open::BGPOpenMessageWritingError, update::BGPUpdateMessageWritingError},
    },
    BGPMessage,
};

/// Helper method to round up the number of bytes based on a given length
#[inline]
fn round_len(len: u8) -> u8 {
    (len as f32 / 8.0).ceil() as u8
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPMessageWritingError {
    /// The size of written message is larger than allowed size: 4,096 for open
    /// and keepalive and 2^16 for the rest
    BGPMessageLengthOverflow(usize),

    StdIOError(String),

    /// Error encountered during parsing a [crate::open::BGPOpenMessage]
    OpenError(BGPOpenMessageWritingError),

    /// Error encountered during parsing a [crate::update::BGPUpdateMessage]
    UpdateError(BGPUpdateMessageWritingError),
}

impl From<std::io::Error> for BGPMessageWritingError {
    fn from(err: std::io::Error) -> Self {
        BGPMessageWritingError::StdIOError(err.to_string())
    }
}

impl WritablePDU<BGPMessageWritingError> for BGPMessage {
    const BASE_LENGTH: usize = BGP_MIN_MESSAGE_LENGTH as usize;
    fn len(&self) -> usize {
        let body_len = match self {
            Self::Open(open) => open.len(),
            Self::Update(update) => update.len(),
            Self::Notification(_notification) => todo!(),
            Self::KeepAlive => 0,
        };
        Self::BASE_LENGTH as usize + body_len
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), BGPMessageWritingError> {
        let len = self.len();
        match self {
            BGPMessage::Open(_) | BGPMessage::KeepAlive => {
                if len > BGP_MAX_MESSAGE_LENGTH as usize {
                    return Err(BGPMessageWritingError::BGPMessageLengthOverflow(len));
                }
            }
            BGPMessage::Update(_) | BGPMessage::Notification(_) => {}
        }
        writer.write_all(&u128::MAX.to_be_bytes())?;
        writer.write_u16::<NetworkEndian>(len as u16)?;
        match self {
            BGPMessage::Open(open) => {
                writer.write_u8(BGPMessageType::Open.into())?;
                open.write(writer)?;
            }
            BGPMessage::Update(update) => {
                writer.write_u8(BGPMessageType::Update.into())?;
                update.write(writer)?;
            }
            Self::Notification(_notification) => todo!(),
            BGPMessage::KeepAlive => {
                writer.write_u8(BGPMessageType::KeepAlive.into())?;
            }
        }
        Ok(())
    }
}
