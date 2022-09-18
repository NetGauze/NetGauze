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

use crate::{
    iana::{BGPErrorNotificationCode, MessageHeaderErrorSubCode},
    notification::MessageHeaderError,
    serde::serializer::BGPMessageWritingError,
    BGPNotificationMessage,
};
use byteorder::WriteBytesExt;
use netgauze_parse_utils::WritablePDU;

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPNotificationMessageWritingError {
    StdIOError(String),
    MessageHeaderError(MessageHeaderErrorWritingError),
}

impl From<std::io::Error> for BGPNotificationMessageWritingError {
    fn from(err: std::io::Error) -> Self {
        BGPNotificationMessageWritingError::StdIOError(err.to_string())
    }
}

impl From<BGPNotificationMessageWritingError> for BGPMessageWritingError {
    fn from(value: BGPNotificationMessageWritingError) -> Self {
        BGPMessageWritingError::NotificationError(value)
    }
}

impl WritablePDU<BGPNotificationMessageWritingError> for BGPNotificationMessage {
    // One octet for the code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::MessageHeaderError(value) => value.len(),
            Self::OpenMessageError(_) => todo!(),
            Self::UpdateMessageError(_) => todo!(),
            Self::HoldTimerExpiredError(_) => todo!(),
            Self::FiniteStateMachineError(_) => todo!(),
            Self::CeaseError(_) => todo!(),
            Self::RouteRefreshError(_) => todo!(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), BGPNotificationMessageWritingError> {
        match self {
            Self::MessageHeaderError(value) => {
                writer.write_u8(BGPErrorNotificationCode::MessageHeaderError.into())?;
                value.write(writer)?;
            }
            Self::OpenMessageError(_) => todo!(),
            Self::UpdateMessageError(_) => todo!(),
            Self::HoldTimerExpiredError(_) => todo!(),
            Self::FiniteStateMachineError(_) => todo!(),
            Self::CeaseError(_) => todo!(),
            Self::RouteRefreshError(_) => todo!(),
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MessageHeaderErrorWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for MessageHeaderErrorWritingError {
    fn from(err: std::io::Error) -> Self {
        MessageHeaderErrorWritingError::StdIOError(err.to_string())
    }
}

impl From<MessageHeaderErrorWritingError> for BGPNotificationMessageWritingError {
    fn from(value: MessageHeaderErrorWritingError) -> Self {
        BGPNotificationMessageWritingError::MessageHeaderError(value)
    }
}

impl WritablePDU<MessageHeaderErrorWritingError> for MessageHeaderError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::Unspecific { value } => value.len(),
            Self::ConnectionNotSynchronized { value } => value.len(),
            Self::BadMessageLength { value } => value.len(),
            Self::BadMessageType { value } => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), MessageHeaderErrorWritingError> {
        match self {
            Self::Unspecific { value } => {
                writer.write_u8(MessageHeaderErrorSubCode::Unspecific.into())?;
                writer.write_all(value)?;
            }
            Self::ConnectionNotSynchronized { value } => {
                writer.write_u8(MessageHeaderErrorSubCode::ConnectionNotSynchronized.into())?;
                writer.write_all(value)?;
            }
            Self::BadMessageLength { value } => {
                writer.write_u8(MessageHeaderErrorSubCode::BadMessageLength.into())?;
                writer.write_all(value)?;
            }
            Self::BadMessageType { value } => {
                writer.write_u8(MessageHeaderErrorSubCode::BadMessageType.into())?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}
