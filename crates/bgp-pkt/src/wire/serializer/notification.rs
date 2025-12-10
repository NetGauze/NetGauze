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
    BgpNotificationMessage,
    iana::{
        BgpErrorNotificationCode, CeaseErrorSubCode, FiniteStateMachineErrorSubCode,
        MessageHeaderErrorSubCode, OpenMessageErrorSubCode, RouteRefreshMessageErrorSubCode,
        UpdateMessageErrorSubCode,
    },
    notification::{
        CeaseError, FiniteStateMachineError, HoldTimerExpiredError, MessageHeaderError,
        OpenMessageError, RouteRefreshError, UpdateMessageError,
    },
};
use byteorder::WriteBytesExt;
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpNotificationMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    MessageHeaderError(#[from] MessageHeaderErrorWritingError),
    OpenMessageError(#[from] OpenMessageErrorWritingError),
    UpdateMessageError(#[from] UpdateMessageErrorWritingError),
    HoldTimerExpiredError(#[from] HoldTimerExpiredErrorWritingError),
    FiniteStateMachineError(#[from] FiniteStateMachineErrorWritingError),
    CeaseError(#[from] CeaseErrorWritingError),
    RouteRefreshError(#[from] RouteRefreshErrorWritingError),
}

impl WritablePdu<BgpNotificationMessageWritingError> for BgpNotificationMessage {
    // One octet for the code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::MessageHeaderError(value) => value.len(),
            Self::OpenMessageError(value) => value.len(),
            Self::UpdateMessageError(value) => value.len(),
            Self::HoldTimerExpiredError(value) => value.len(),
            Self::FiniteStateMachineError(value) => value.len(),
            Self::CeaseError(value) => value.len(),
            Self::RouteRefreshError(value) => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), BgpNotificationMessageWritingError> {
        match self {
            Self::MessageHeaderError(value) => {
                writer.write_u8(BgpErrorNotificationCode::MessageHeaderError.into())?;
                value.write(writer)?;
            }
            Self::OpenMessageError(value) => {
                writer.write_u8(BgpErrorNotificationCode::OpenMessageError.into())?;
                value.write(writer)?;
            }
            Self::UpdateMessageError(value) => {
                writer.write_u8(BgpErrorNotificationCode::UpdateMessageError.into())?;
                value.write(writer)?;
            }
            Self::HoldTimerExpiredError(value) => {
                writer.write_u8(BgpErrorNotificationCode::HoldTimerExpired.into())?;
                value.write(writer)?;
            }
            Self::FiniteStateMachineError(value) => {
                writer.write_u8(BgpErrorNotificationCode::FiniteStateMachineError.into())?;
                value.write(writer)?;
            }
            Self::CeaseError(value) => {
                writer.write_u8(BgpErrorNotificationCode::Cease.into())?;
                value.write(writer)?;
            }
            Self::RouteRefreshError(value) => {
                writer.write_u8(BgpErrorNotificationCode::RouteRefreshMessageError.into())?;
                value.write(writer)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MessageHeaderErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<MessageHeaderErrorWritingError> for MessageHeaderError {
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

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum OpenMessageErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<OpenMessageErrorWritingError> for OpenMessageError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::Unspecific { value } => value.len(),
            Self::UnsupportedVersionNumber { value } => value.len(),
            Self::BadPeerAs { value } => value.len(),
            Self::BadBgpIdentifier { value } => value.len(),
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
            OpenMessageError::BadPeerAs { value } => {
                writer.write_u8(OpenMessageErrorSubCode::BadPeerAs.into())?;
                writer.write_all(value)?;
            }
            OpenMessageError::BadBgpIdentifier { value } => {
                writer.write_u8(OpenMessageErrorSubCode::BadBgpIdentifier.into())?;
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

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum UpdateMessageErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<UpdateMessageErrorWritingError> for UpdateMessageError {
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
            Self::MalformedAsPath { value } => value.len(),
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
            Self::MalformedAsPath { value } => {
                writer.write_u8(UpdateMessageErrorSubCode::MalformedAsPath.into())?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum HoldTimerExpiredErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<HoldTimerExpiredErrorWritingError> for HoldTimerExpiredError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::Unspecific { sub_code: _, value } => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), HoldTimerExpiredErrorWritingError> {
        match self {
            Self::Unspecific { sub_code, value } => {
                writer.write_u8(*sub_code)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FiniteStateMachineErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<FiniteStateMachineErrorWritingError> for FiniteStateMachineError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::Unspecific { value } => value.len(),
            Self::ReceiveUnexpectedMessageInOpenSentState { value } => value.len(),
            Self::ReceiveUnexpectedMessageInOpenConfirmState { value } => value.len(),
            Self::ReceiveUnexpectedMessageInEstablishedState { value } => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), FiniteStateMachineErrorWritingError> {
        match self {
            Self::Unspecific { value } => {
                writer.write_u8(FiniteStateMachineErrorSubCode::UnspecifiedError.into())?;
                writer.write_all(value)?;
            }
            Self::ReceiveUnexpectedMessageInOpenSentState { value } => {
                writer.write_u8(
                    FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenSentState.into(),
                )?;
                writer.write_all(value)?;
            }
            Self::ReceiveUnexpectedMessageInOpenConfirmState { value } => {
                writer.write_u8(
                    FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenConfirmState
                        .into(),
                )?;
                writer.write_all(value)?;
            }
            Self::ReceiveUnexpectedMessageInEstablishedState { value } => {
                writer.write_u8(
                    FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInEstablishedState
                        .into(),
                )?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum CeaseErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<CeaseErrorWritingError> for CeaseError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::MaximumNumberOfPrefixesReached { value } => value.len(),
            Self::AdministrativeShutdown { value } => value.len(),
            Self::PeerDeConfigured { value } => value.len(),
            Self::AdministrativeReset { value } => value.len(),
            Self::ConnectionRejected { value } => value.len(),
            Self::OtherConfigurationChange { value } => value.len(),
            Self::ConnectionCollisionResolution { value } => value.len(),
            Self::OutOfResources { value } => value.len(),
            Self::HardReset { value } => value.len(),
            Self::BfdDown { value } => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), CeaseErrorWritingError> {
        match self {
            Self::MaximumNumberOfPrefixesReached { value } => {
                writer.write_u8(CeaseErrorSubCode::MaximumNumberOfPrefixesReached.into())?;
                writer.write_all(value)?;
            }
            Self::AdministrativeShutdown { value } => {
                writer.write_u8(CeaseErrorSubCode::AdministrativeShutdown.into())?;
                writer.write_all(value)?;
            }
            Self::PeerDeConfigured { value } => {
                writer.write_u8(CeaseErrorSubCode::PeerDeConfigured.into())?;
                writer.write_all(value)?;
            }
            Self::AdministrativeReset { value } => {
                writer.write_u8(CeaseErrorSubCode::AdministrativeReset.into())?;
                writer.write_all(value)?;
            }
            Self::ConnectionRejected { value } => {
                writer.write_u8(CeaseErrorSubCode::ConnectionRejected.into())?;
                writer.write_all(value)?;
            }
            Self::OtherConfigurationChange { value } => {
                writer.write_u8(CeaseErrorSubCode::OtherConfigurationChange.into())?;
                writer.write_all(value)?;
            }
            Self::ConnectionCollisionResolution { value } => {
                writer.write_u8(CeaseErrorSubCode::ConnectionCollisionResolution.into())?;
                writer.write_all(value)?;
            }
            Self::OutOfResources { value } => {
                writer.write_u8(CeaseErrorSubCode::OutOfResources.into())?;
                writer.write_all(value)?;
            }
            Self::HardReset { value } => {
                writer.write_u8(CeaseErrorSubCode::HardReset.into())?;
                writer.write_all(value)?;
            }
            Self::BfdDown { value } => {
                writer.write_u8(CeaseErrorSubCode::BfdDown.into())?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteRefreshErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<RouteRefreshErrorWritingError> for RouteRefreshError {
    // One octet sub-code
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::InvalidMessageLength { value } => value.len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), RouteRefreshErrorWritingError> {
        match self {
            Self::InvalidMessageLength { value } => {
                writer.write_u8(RouteRefreshMessageErrorSubCode::InvalidMessageLength.into())?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}
