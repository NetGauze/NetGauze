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

use crate::{
    iana::{
        BGPErrorNotificationCode, CeaseErrorSubCode, FiniteStateMachineErrorSubCode,
        MessageHeaderErrorSubCode, OpenMessageErrorSubCode, RouteRefreshMessageErrorSubCode,
        UndefinedBGPErrorNotificationCode, UndefinedCeaseErrorSubCode,
        UndefinedFiniteStateMachineErrorSubCode, UndefinedMessageHeaderErrorSubCode,
        UndefinedOpenMessageErrorSubCode, UndefinedRouteRefreshMessageError,
        UndefinedUpdateMessageErrorSubCode, UpdateMessageErrorSubCode,
    },
    notification::{
        CeaseError, FiniteStateMachineError, HoldTimerExpiredError, MessageHeaderError,
        OpenMessageError, RouteRefreshError, UpdateMessageError,
    },
    BGPNotificationMessage,
};
use netgauze_parse_utils::{parse_into_located, ReadablePDU, Span};
use netgauze_serde_macros::LocatedError;
use nom::{error::ErrorKind, number::complete::be_u8, IResult};

/// BGP Notification Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BGPNotificationMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    UndefinedBGPErrorNotificationCode(#[from_external] UndefinedBGPErrorNotificationCode),
    MessageHeaderError(#[from_located(module = "self")] MessageHeaderErrorParsingError),
    OpenMessageError(#[from_located(module = "self")] OpenMessageErrorParsingError),
    UpdateMessageError(#[from_located(module = "self")] UpdateMessageErrorParsingError),
    HoldTimerExpiredError(#[from_located(module = "self")] HoldTimerExpiredErrorParsingError),
    FiniteStateMachineError(#[from_located(module = "self")] FiniteStateMachineErrorParsingError),
    CeaseError(#[from_located(module = "self")] CeaseErrorParsingError),
    RouteRefreshError(#[from_located(module = "self")] RouteRefreshErrorParsingError),
}

impl<'a> ReadablePDU<'a, LocatedBGPNotificationMessageParsingError<'a>> for BGPNotificationMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBGPNotificationMessageParsingError<'a>> {
        let (buf, notification_type) =
            nom::combinator::map_res(be_u8, BGPErrorNotificationCode::try_from)(buf)?;
        match notification_type {
            BGPErrorNotificationCode::MessageHeaderError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::MessageHeaderError(value)))
            }
            BGPErrorNotificationCode::OpenMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::OpenMessageError(value)))
            }
            BGPErrorNotificationCode::UpdateMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::UpdateMessageError(value)))
            }
            BGPErrorNotificationCode::HoldTimerExpired => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::HoldTimerExpiredError(value)))
            }
            BGPErrorNotificationCode::FiniteStateMachineError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::FiniteStateMachineError(value)))
            }
            BGPErrorNotificationCode::Cease => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::CeaseError(value)))
            }
            BGPErrorNotificationCode::RouteRefreshMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::RouteRefreshError(value)))
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum MessageHeaderErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    UndefinedMessageHeaderErrorType(#[from_external] UndefinedMessageHeaderErrorSubCode),
}

impl<'a> ReadablePDU<'a, LocatedMessageHeaderErrorParsingError<'a>> for MessageHeaderError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedMessageHeaderErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, MessageHeaderErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            MessageHeaderErrorSubCode::Unspecific => Ok((
                buf,
                MessageHeaderError::Unspecific {
                    value: (*value.fragment()).into(),
                },
            )),
            MessageHeaderErrorSubCode::ConnectionNotSynchronized => Ok((
                buf,
                MessageHeaderError::ConnectionNotSynchronized {
                    value: (*value.fragment()).into(),
                },
            )),
            MessageHeaderErrorSubCode::BadMessageLength => Ok((
                buf,
                MessageHeaderError::BadMessageLength {
                    value: (*value.fragment()).into(),
                },
            )),
            MessageHeaderErrorSubCode::BadMessageType => Ok((
                buf,
                MessageHeaderError::BadMessageType {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum OpenMessageErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    UndefinedOpenMessageErrorSubCode(#[from_external] UndefinedOpenMessageErrorSubCode),
}

impl<'a> ReadablePDU<'a, LocatedOpenMessageErrorParsingError<'a>> for OpenMessageError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedOpenMessageErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, OpenMessageErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            OpenMessageErrorSubCode::Unspecific => Ok((
                buf,
                OpenMessageError::Unspecific {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnsupportedVersionNumber => Ok((
                buf,
                OpenMessageError::UnsupportedVersionNumber {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::BadPeerAS => Ok((
                buf,
                OpenMessageError::BadPeerAS {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::BadBGPIdentifier => Ok((
                buf,
                OpenMessageError::BadBGPIdentifier {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnsupportedOptionalParameter => Ok((
                buf,
                OpenMessageError::UnsupportedOptionalParameter {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnacceptableHoldTime => Ok((
                buf,
                OpenMessageError::UnacceptableHoldTime {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnsupportedCapability => Ok((
                buf,
                OpenMessageError::UnsupportedCapability {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::RoleMismatch => Ok((
                buf,
                OpenMessageError::RoleMismatch {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum UpdateMessageErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    UndefinedUpdateMessageErrorSubCode(#[from_external] UndefinedUpdateMessageErrorSubCode),
}

impl<'a> ReadablePDU<'a, LocatedUpdateMessageErrorParsingError<'a>> for UpdateMessageError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedUpdateMessageErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, UpdateMessageErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            UpdateMessageErrorSubCode::Unspecific => Ok((
                buf,
                Self::Unspecific {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::MalformedAttributeList => Ok((
                buf,
                Self::MalformedAttributeList {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::UnrecognizedWellKnownAttribute => Ok((
                buf,
                Self::UnrecognizedWellKnownAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::MissingWellKnownAttribute => Ok((
                buf,
                Self::MissingWellKnownAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::AttributeFlagsError => Ok((
                buf,
                Self::AttributeFlagsError {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::AttributeLengthError => Ok((
                buf,
                Self::AttributeLengthError {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::InvalidOriginAttribute => Ok((
                buf,
                Self::InvalidOriginAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::InvalidNextHopAttribute => Ok((
                buf,
                Self::InvalidNextHopAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::OptionalAttributeError => Ok((
                buf,
                Self::OptionalAttributeError {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::InvalidNetworkField => Ok((
                buf,
                Self::InvalidNetworkField {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::MalformedASPath => Ok((
                buf,
                Self::MalformedASPath {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum HoldTimerExpiredErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePDU<'a, LocatedHoldTimerExpiredErrorParsingError<'a>> for HoldTimerExpiredError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedHoldTimerExpiredErrorParsingError<'a>> {
        let (buf, sub_code) = be_u8(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;
        Ok((
            buf,
            HoldTimerExpiredError::Unspecific {
                sub_code,
                value: (*value.fragment()).into(),
            },
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum FiniteStateMachineErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    Undefined(#[from_external] UndefinedFiniteStateMachineErrorSubCode),
}

impl<'a> ReadablePDU<'a, LocatedFiniteStateMachineErrorParsingError<'a>>
    for FiniteStateMachineError
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedFiniteStateMachineErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, FiniteStateMachineErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            FiniteStateMachineErrorSubCode::UnspecifiedError => Ok((
                buf,
                FiniteStateMachineError::Unspecific {
                    value: (*value.fragment()).into(),
                },
            )),
            FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenSentState => Ok((
                buf,
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState {
                    value: (*value.fragment()).into(),
                },
            )),
            FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenConfirmState => Ok((
                buf,
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
                    value: (*value.fragment()).into(),
                },
            )),
            FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInEstablishedState => Ok((
                buf,
                FiniteStateMachineError::ReceiveUnexpectedMessageInEstablishedState {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum CeaseErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    Undefined(#[from_external] UndefinedCeaseErrorSubCode),
}

impl<'a> ReadablePDU<'a, LocatedCeaseErrorParsingError<'a>> for CeaseError {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedCeaseErrorParsingError<'a>> {
        let (buf, sub_code) = nom::combinator::map_res(be_u8, CeaseErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            CeaseErrorSubCode::MaximumNumberOfPrefixesReached => Ok((
                buf,
                CeaseError::MaximumNumberOfPrefixesReached {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::AdministrativeShutdown => Ok((
                buf,
                CeaseError::AdministrativeShutdown {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::PeerDeConfigured => Ok((
                buf,
                CeaseError::PeerDeConfigured {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::AdministrativeReset => Ok((
                buf,
                CeaseError::AdministrativeReset {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::ConnectionRejected => Ok((
                buf,
                CeaseError::ConnectionRejected {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::OtherConfigurationChange => Ok((
                buf,
                CeaseError::OtherConfigurationChange {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::ConnectionCollisionResolution => Ok((
                buf,
                CeaseError::ConnectionCollisionResolution {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::OutOfResources => Ok((
                buf,
                CeaseError::OutOfResources {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::HardReset => Ok((
                buf,
                CeaseError::HardReset {
                    value: (*value.fragment()).into(),
                },
            )),
            CeaseErrorSubCode::BfdDown => Ok((
                buf,
                CeaseError::BfdDown {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum RouteRefreshErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(#[from_nom] ErrorKind),
    Undefined(#[from_external] UndefinedRouteRefreshMessageError),
}

impl<'a> ReadablePDU<'a, LocatedRouteRefreshErrorParsingError<'a>> for RouteRefreshError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedRouteRefreshErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, RouteRefreshMessageErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            RouteRefreshMessageErrorSubCode::InvalidMessageLength => Ok((
                buf,
                RouteRefreshError::InvalidMessageLength {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}
