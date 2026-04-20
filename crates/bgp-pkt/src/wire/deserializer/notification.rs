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

//! Deserializer for BGP Notification message

use crate::BgpNotificationMessage;
use crate::iana::{
    BgpErrorNotificationCode, CeaseErrorSubCode, FiniteStateMachineErrorSubCode,
    MessageHeaderErrorSubCode, OpenMessageErrorSubCode, RouteRefreshMessageErrorSubCode,
    UpdateMessageErrorSubCode,
};
use crate::notification::{
    CeaseError, FiniteStateMachineError, HoldTimerExpiredError, MessageHeaderError,
    OpenMessageError, RouteRefreshError, UpdateMessageError,
};

use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFrom;
use serde::{Deserialize, Serialize};

/// BGP Notification Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpNotificationMessageParsingError {
    #[error("BGP notification message parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Undefined BGP error notification code: {code} at offset {offset}")]
    UndefinedBgpErrorNotificationCode { offset: usize, code: u8 },

    #[error("BGP notification message error: {0}")]
    MessageHeaderError(#[from] MessageHeaderErrorParsingError),

    #[error("BGP notification message error: {0}")]
    OpenMessageError(#[from] OpenMessageErrorParsingError),

    #[error("BGP notification message error: {0}")]
    UpdateMessageError(#[from] UpdateMessageErrorParsingError),

    #[error("BGP notification message error: {0}")]
    HoldTimerExpiredError(#[from] HoldTimerExpiredErrorParsingError),

    #[error("BGP notification message error: {0}")]
    FiniteStateMachineError(#[from] FiniteStateMachineErrorParsingError),

    #[error("BGP notification message error: {0}")]
    CeaseError(#[from] CeaseErrorParsingError),

    #[error("BGP notification message error: {0}")]
    RouteRefreshError(#[from] RouteRefreshErrorParsingError),
}

impl<'a> ParseFrom<'a> for BgpNotificationMessage {
    type Error = BgpNotificationMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let notification_type =
            BgpErrorNotificationCode::try_from(cur.read_u8()?).map_err(|err| {
                BgpNotificationMessageParsingError::UndefinedBgpErrorNotificationCode {
                    offset: cur.offset() - 1,
                    code: err.0,
                }
            })?;
        match notification_type {
            BgpErrorNotificationCode::MessageHeaderError => {
                let value = MessageHeaderError::parse(cur)?;
                Ok(BgpNotificationMessage::MessageHeaderError(value))
            }
            BgpErrorNotificationCode::OpenMessageError => {
                let value = OpenMessageError::parse(cur)?;
                Ok(BgpNotificationMessage::OpenMessageError(value))
            }
            BgpErrorNotificationCode::UpdateMessageError => {
                let value = UpdateMessageError::parse(cur)?;
                Ok(BgpNotificationMessage::UpdateMessageError(value))
            }
            BgpErrorNotificationCode::HoldTimerExpired => {
                let value = HoldTimerExpiredError::parse(cur)?;
                Ok(BgpNotificationMessage::HoldTimerExpiredError(value))
            }
            BgpErrorNotificationCode::FiniteStateMachineError => {
                let value = FiniteStateMachineError::parse(cur)?;
                Ok(BgpNotificationMessage::FiniteStateMachineError(value))
            }
            BgpErrorNotificationCode::Cease => {
                let value = CeaseError::parse(cur)?;
                Ok(BgpNotificationMessage::CeaseError(value))
            }
            BgpErrorNotificationCode::RouteRefreshMessageError => {
                let value = RouteRefreshError::parse(cur)?;
                Ok(BgpNotificationMessage::RouteRefreshError(value))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MessageHeaderErrorParsingError {
    #[error("Message header error parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Undefined message header error type: {code} at offset {offset}")]
    UndefinedMessageHeaderErrorType { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for MessageHeaderError {
    type Error = MessageHeaderErrorParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let sub_code = MessageHeaderErrorSubCode::try_from(cur.read_u8()?).map_err(|err| {
            MessageHeaderErrorParsingError::UndefinedMessageHeaderErrorType {
                offset: cur.offset() - 1,
                code: err.0,
            }
        })?;
        let value = cur.read_bytes(cur.remaining())?.to_vec();

        match sub_code {
            MessageHeaderErrorSubCode::Unspecific => Ok(MessageHeaderError::Unspecific { value }),
            MessageHeaderErrorSubCode::ConnectionNotSynchronized => {
                Ok(MessageHeaderError::ConnectionNotSynchronized { value })
            }
            MessageHeaderErrorSubCode::BadMessageLength => {
                Ok(MessageHeaderError::BadMessageLength { value })
            }
            MessageHeaderErrorSubCode::BadMessageType => {
                Ok(MessageHeaderError::BadMessageType { value })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum OpenMessageErrorParsingError {
    #[error("Open message error parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Undefined open message error sub code {code} at offset {offset}")]
    UndefinedOpenMessageErrorSubCode { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for OpenMessageError {
    type Error = OpenMessageErrorParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let sub_code = OpenMessageErrorSubCode::try_from(cur.read_u8()?).map_err(|err| {
            OpenMessageErrorParsingError::UndefinedOpenMessageErrorSubCode {
                offset: cur.offset() - 1,
                code: err.0,
            }
        })?;
        let value = cur.read_bytes(cur.remaining())?.to_vec();

        match sub_code {
            OpenMessageErrorSubCode::Unspecific => Ok(OpenMessageError::Unspecific { value }),
            OpenMessageErrorSubCode::UnsupportedVersionNumber => {
                Ok(OpenMessageError::UnsupportedVersionNumber { value })
            }
            OpenMessageErrorSubCode::BadPeerAs => Ok(OpenMessageError::BadPeerAs { value }),
            OpenMessageErrorSubCode::BadBgpIdentifier => {
                Ok(OpenMessageError::BadBgpIdentifier { value })
            }
            OpenMessageErrorSubCode::UnsupportedOptionalParameter => {
                Ok(OpenMessageError::UnsupportedOptionalParameter { value })
            }
            OpenMessageErrorSubCode::UnacceptableHoldTime => {
                Ok(OpenMessageError::UnacceptableHoldTime { value })
            }
            OpenMessageErrorSubCode::UnsupportedCapability => {
                Ok(OpenMessageError::UnsupportedCapability { value })
            }
            OpenMessageErrorSubCode::RoleMismatch => Ok(OpenMessageError::RoleMismatch { value }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum UpdateMessageErrorParsingError {
    #[error("Update message error parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Undefined update message error sub code {code} at offset {offset}")]
    UndefinedUpdateMessageErrorSubCode { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for UpdateMessageError {
    type Error = UpdateMessageErrorParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let sub_code = UpdateMessageErrorSubCode::try_from(cur.read_u8()?).map_err(|err| {
            UpdateMessageErrorParsingError::UndefinedUpdateMessageErrorSubCode {
                offset: cur.offset() - 1,
                code: err.0,
            }
        })?;
        let value = cur.read_bytes(cur.remaining())?.to_vec();

        match sub_code {
            UpdateMessageErrorSubCode::Unspecific => Ok(Self::Unspecific { value }),
            UpdateMessageErrorSubCode::MalformedAttributeList => {
                Ok(Self::MalformedAttributeList { value })
            }
            UpdateMessageErrorSubCode::UnrecognizedWellKnownAttribute => {
                Ok(Self::UnrecognizedWellKnownAttribute { value })
            }
            UpdateMessageErrorSubCode::MissingWellKnownAttribute => {
                Ok(Self::MissingWellKnownAttribute { value })
            }
            UpdateMessageErrorSubCode::AttributeFlagsError => {
                Ok(Self::AttributeFlagsError { value })
            }
            UpdateMessageErrorSubCode::AttributeLengthError => {
                Ok(Self::AttributeLengthError { value })
            }
            UpdateMessageErrorSubCode::InvalidOriginAttribute => {
                Ok(Self::InvalidOriginAttribute { value })
            }
            UpdateMessageErrorSubCode::InvalidNextHopAttribute => {
                Ok(Self::InvalidNextHopAttribute { value })
            }
            UpdateMessageErrorSubCode::OptionalAttributeError => {
                Ok(Self::OptionalAttributeError { value })
            }
            UpdateMessageErrorSubCode::InvalidNetworkField => {
                Ok(Self::InvalidNetworkField { value })
            }
            UpdateMessageErrorSubCode::MalformedAsPath => Ok(Self::MalformedAsPath { value }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum HoldTimerExpiredErrorParsingError {
    #[error("Hold timer expired error parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for HoldTimerExpiredError {
    type Error = HoldTimerExpiredErrorParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let sub_code = cur.read_u8()?;
        let value = cur.read_bytes(cur.remaining())?.to_vec();

        Ok(HoldTimerExpiredError::Unspecific { sub_code, value })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum FiniteStateMachineErrorParsingError {
    #[error("Finite state machine error parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Undefined finite state machine error: {code} at offset {offset}")]
    Undefined { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for FiniteStateMachineError {
    type Error = FiniteStateMachineErrorParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let sub_code = FiniteStateMachineErrorSubCode::try_from(cur.read_u8()?).map_err(|err| {
            FiniteStateMachineErrorParsingError::Undefined {
                offset: cur.offset() - 1,
                code: err.0,
            }
        })?;
        let value = cur.read_bytes(cur.remaining())?.to_vec();

        match sub_code {
            FiniteStateMachineErrorSubCode::UnspecifiedError => {
                Ok(FiniteStateMachineError::Unspecific { value })
            }
            FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenSentState => {
                Ok(FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { value })
            }
            FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenConfirmState => {
                Ok(FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState { value })
            }
            FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInEstablishedState => {
                Ok(FiniteStateMachineError::ReceiveUnexpectedMessageInEstablishedState { value })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum CeaseErrorParsingError {
    #[error("Cease error parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Undefined cease error: {code} at offset {offset}")]
    Undefined { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for CeaseError {
    type Error = CeaseErrorParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let sub_code = CeaseErrorSubCode::try_from(cur.read_u8()?).map_err(|err| {
            CeaseErrorParsingError::Undefined {
                offset: cur.offset() - 1,
                code: err.0,
            }
        })?;
        let value = cur.read_bytes(cur.remaining())?.to_vec();
        match sub_code {
            CeaseErrorSubCode::MaximumNumberOfPrefixesReached => {
                Ok(CeaseError::MaximumNumberOfPrefixesReached { value })
            }
            CeaseErrorSubCode::AdministrativeShutdown => {
                Ok(CeaseError::AdministrativeShutdown { value })
            }
            CeaseErrorSubCode::PeerDeConfigured => Ok(CeaseError::PeerDeConfigured { value }),
            CeaseErrorSubCode::AdministrativeReset => Ok(CeaseError::AdministrativeReset { value }),
            CeaseErrorSubCode::ConnectionRejected => Ok(CeaseError::ConnectionRejected { value }),
            CeaseErrorSubCode::OtherConfigurationChange => {
                Ok(CeaseError::OtherConfigurationChange { value })
            }
            CeaseErrorSubCode::ConnectionCollisionResolution => {
                Ok(CeaseError::ConnectionCollisionResolution { value })
            }
            CeaseErrorSubCode::OutOfResources => Ok(CeaseError::OutOfResources { value }),
            CeaseErrorSubCode::HardReset => Ok(CeaseError::HardReset { value }),
            CeaseErrorSubCode::BfdDown => Ok(CeaseError::BfdDown { value }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteRefreshErrorParsingError {
    #[error("Route refresh error parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Undefined route refresh error: {code} at offset {offset}")]
    Undefined { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for RouteRefreshError {
    type Error = RouteRefreshErrorParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let sub_code =
            RouteRefreshMessageErrorSubCode::try_from(cur.read_u8()?).map_err(|err| {
                RouteRefreshErrorParsingError::Undefined {
                    offset: cur.offset() - 1,
                    code: err.0,
                }
            })?;
        let value = cur.read_bytes(cur.remaining())?;
        match sub_code {
            RouteRefreshMessageErrorSubCode::InvalidMessageLength => {
                Ok(RouteRefreshError::InvalidMessageLength {
                    value: value.to_vec(),
                })
            }
        }
    }
}
