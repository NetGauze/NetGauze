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
pub mod nlri;
pub mod notification;
pub mod open;
pub mod path_attribute;
pub mod route_refresh;
pub mod update;

use byteorder::{NetworkEndian, WriteBytesExt};

use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;

use crate::{
    wire::{
        deserializer::{BGP_MAX_MESSAGE_LENGTH, BGP_MIN_MESSAGE_LENGTH},
        serializer::{
            notification::BGPNotificationMessageWritingError, open::BGPOpenMessageWritingError,
            route_refresh::BGPRouteRefreshMessageWritingError,
            update::BGPUpdateMessageWritingError,
        },
    },
    BGPMessage,
};

/// Helper method to round up the number of bytes based on a given length
#[inline]
pub(crate) fn round_len(len: u8) -> u8 {
    (len as f32 / 8.0).ceil() as u8
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BGPMessageWritingError {
    /// The size of written message is larger than allowed size: 4,096 for open
    /// and keepalive and 2^16 for the rest
    BGPMessageLengthOverflow(usize),

    StdIOError(#[from_std_io_error] String),

    /// Error encountered during parsing a [crate::open::BGPOpenMessage]
    OpenError(#[from] BGPOpenMessageWritingError),

    /// Error encountered during parsing a [crate::update::BGPUpdateMessage]
    UpdateError(#[from] BGPUpdateMessageWritingError),

    NotificationError(#[from] BGPNotificationMessageWritingError),

    RouteRefreshError(#[from] BGPRouteRefreshMessageWritingError),
}

impl WritablePDU<BGPMessageWritingError> for BGPMessage {
    const BASE_LENGTH: usize = BGP_MIN_MESSAGE_LENGTH as usize;
    fn len(&self) -> usize {
        let body_len = match self {
            Self::Open(open) => open.len(),
            Self::Update(update) => update.len(),
            Self::Notification(notification) => notification.len(),
            Self::KeepAlive => 0,
            Self::RouteRefresh(route_refresh) => route_refresh.len(),
        };
        Self::BASE_LENGTH as usize + body_len
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), BGPMessageWritingError> {
        let len = self.len();
        match self {
            Self::Open(_) | Self::KeepAlive => {
                if len > BGP_MAX_MESSAGE_LENGTH as usize {
                    return Err(BGPMessageWritingError::BGPMessageLengthOverflow(len));
                }
            }
            Self::Update(_) | Self::Notification(_) | Self::RouteRefresh(_) => {}
        }
        writer.write_all(&u128::MAX.to_be_bytes())?;
        writer.write_u16::<NetworkEndian>(len as u16)?;
        match self {
            Self::Open(open) => {
                writer.write_u8(self.get_type().into())?;
                open.write(writer)?;
            }
            Self::Update(update) => {
                writer.write_u8(self.get_type().into())?;
                update.write(writer)?;
            }
            Self::Notification(notification) => {
                writer.write_u8(self.get_type().into())?;
                notification.write(writer)?;
            }
            Self::KeepAlive => {
                writer.write_u8(self.get_type().into())?;
            }
            Self::RouteRefresh(route_refresh) => {
                writer.write_u8(self.get_type().into())?;
                route_refresh.write(writer)?;
            }
        }
        Ok(())
    }
}
