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
    iana::{
        BGPErrorNotificationCode, MessageHeaderErrorSubCode, OpenMessageErrorSubCode,
        UpdateMessageErrorSubCode,
    },
    notification::{MessageHeaderError, OpenMessageError, UpdateMessageError},
    serde::serializer::BGPMessageWritingError,
    BGPNotificationMessage,
};
use byteorder::WriteBytesExt;
use netgauze_parse_utils::WritablePDU;

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPNotificationMessageWritingError {
    StdIOError(String),
    MessageHeaderError(MessageHeaderErrorWritingError),
    OpenMessageError(OpenMessageErrorWritingError),
    UpdateMessageError(UpdateMessageErrorWritingError),
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
            Self::OpenMessageError(value) => value.len(),
            Self::UpdateMessageError(value) => value.len(),
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
            Self::OpenMessageError(value) => {
                writer.write_u8(BGPErrorNotificationCode::OpenMessageError.into())?;
                value.write(writer)?;
            }
            Self::UpdateMessageError(value) => {
                writer.write_u8(BGPErrorNotificationCode::UpdateMessageError.into())?;
                value.write(writer)?;
            }
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum OpenMessageErrorWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for OpenMessageErrorWritingError {
    fn from(err: std::io::Error) -> Self {
        OpenMessageErrorWritingError::StdIOError(err.to_string())
    }
}

impl From<OpenMessageErrorWritingError> for BGPNotificationMessageWritingError {
    fn from(value: OpenMessageErrorWritingError) -> Self {
        BGPNotificationMessageWritingError::OpenMessageError(value)
    }
}

impl WritablePDU<OpenMessageErrorWritingError> for OpenMessageError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::Unspecific { value } => value.len(),
            Self::UnsupportedVersionNumber { value } => value.len(),
            Self::BadPeerAS { value } => value.len(),
            Self::BadBGPIdentifier { value } => value.len(),
            Self::UnsupportedOptionalParameter { value } => value.len(),
            Self::UnacceptableHoldTime { value } => value.len(),
            Self::UnsupportedCapability { value } => value.len(),
            Self::RoleMismatch { value } => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), OpenMessageErrorWritingError> {
        match self {
            OpenMessageError::Unspecific { value } => {
                writer.write_u8(OpenMessageErrorSubCode::Unspecific.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::UnsupportedVersionNumber { value } => {
                writer.write_u8(OpenMessageErrorSubCode::UnsupportedVersionNumber.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::BadPeerAS { value } => {
                writer.write_u8(OpenMessageErrorSubCode::BadPeerAS.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::BadBGPIdentifier { value } => {
                writer.write_u8(OpenMessageErrorSubCode::BadBGPIdentifier.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::UnsupportedOptionalParameter { value } => {
                writer.write_u8(OpenMessageErrorSubCode::UnsupportedOptionalParameter.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::UnacceptableHoldTime { value } => {
                writer.write_u8(OpenMessageErrorSubCode::UnacceptableHoldTime.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::UnsupportedCapability { value } => {
                writer.write_u8(OpenMessageErrorSubCode::UnsupportedCapability.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::RoleMismatch { value } => {
                writer.write_u8(OpenMessageErrorSubCode::RoleMismatch.into())?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum UpdateMessageErrorWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for UpdateMessageErrorWritingError {
    fn from(err: std::io::Error) -> Self {
        UpdateMessageErrorWritingError::StdIOError(err.to_string())
    }
}

impl From<UpdateMessageErrorWritingError> for BGPNotificationMessageWritingError {
    fn from(value: UpdateMessageErrorWritingError) -> Self {
        BGPNotificationMessageWritingError::UpdateMessageError(value)
    }
}

impl WritablePDU<UpdateMessageErrorWritingError> for UpdateMessageError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::Unspecific { value } => value.len(),
            Self::MalformedAttributeList { value } => value.len(),
            Self::UnrecognizedWellKnownAttribute { value } => value.len(),
            Self::MissingWellKnownAttribute { value } => value.len(),
            Self::AttributeFlagsError { value } => value.len(),
            Self::AttributeLengthError { value } => value.len(),
            Self::InvalidOriginAttribute { value } => value.len(),
            Self::InvalidNextHopAttribute { value } => value.len(),
            Self::OptionalAttributeError { value } => value.len(),
            Self::InvalidNetworkField { value } => value.len(),
            Self::MalformedASPath { value } => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), UpdateMessageErrorWritingError> {
        match self {
            Self::Unspecific { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::Unspecific.into())?;
                writer.write_all(value)?;
            }
            Self::MalformedAttributeList { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::MalformedAttributeList.into())?;
                writer.write_all(value)?;
            }
            Self::UnrecognizedWellKnownAttribute { value } => {
                writer
                    .write_u8(UpdateMessageErrorSubCode::UnrecognizedWellKnownAttribute.into())?;
                writer.write_all(value)?;
            }
            Self::MissingWellKnownAttribute { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::MissingWellKnownAttribute.into())?;
                writer.write_all(value)?;
            }
            Self::AttributeFlagsError { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::AttributeFlagsError.into())?;
                writer.write_all(value)?;
            }
            Self::AttributeLengthError { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::AttributeLengthError.into())?;
                writer.write_all(value)?;
            }
            Self::InvalidOriginAttribute { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::InvalidOriginAttribute.into())?;
                writer.write_all(value)?;
            }
            Self::InvalidNextHopAttribute { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::InvalidNextHopAttribute.into())?;
                writer.write_all(value)?;
            }
            Self::OptionalAttributeError { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::OptionalAttributeError.into())?;
                writer.write_all(value)?;
            }
            Self::InvalidNetworkField { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::InvalidNetworkField.into())?;
                writer.write_all(value)?;
            }
            Self::MalformedASPath { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::MalformedASPath.into())?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}
