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
        BgpErrorNotificationCode, CeaseErrorSubCode, FiniteStateMachineErrorSubCode,
        MessageHeaderErrorSubCode, OpenMessageErrorSubCode, RouteRefreshMessageErrorSubCode,
        UndefinedBgpErrorNotificationCode, UndefinedCeaseErrorSubCode,
        UndefinedFiniteStateMachineErrorSubCode, UndefinedMessageHeaderErrorSubCode,
        UndefinedOpenMessageErrorSubCode, UndefinedRouteRefreshMessageError,
        UndefinedUpdateMessageErrorSubCode, UpdateMessageErrorSubCode,
    },
    notification::{
        CeaseError, FiniteStateMachineError, HoldTimerExpiredError, MessageHeaderError,
        OpenMessageError, RouteRefreshError, UpdateMessageError,
    },
    BgpNotificationMessage,
};
use netgauze_parse_utils::{parse_into_located, ErrorKindSerdeDeref, ReadablePdu, Span};
use netgauze_serde_macros::LocatedError;
use nom::{error::ErrorKind, number::complete::be_u8, IResult};
use serde::{Deserialize, Serialize};

/// BGP Notification Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpNotificationMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedBgpErrorNotificationCode(#[from_external] UndefinedBgpErrorNotificationCode),
    MessageHeaderError(#[from_located(module = "self")] MessageHeaderErrorParsingError),
    OpenMessageError(#[from_located(module = "self")] OpenMessageErrorParsingError),
    UpdateMessageError(#[from_located(module = "self")] UpdateMessageErrorParsingError),
    HoldTimerExpiredError(#[from_located(module = "self")] HoldTimerExpiredErrorParsingError),
    FiniteStateMachineError(#[from_located(module = "self")] FiniteStateMachineErrorParsingError),
    CeaseError(#[from_located(module = "self")] CeaseErrorParsingError),
    RouteRefreshError(#[from_located(module = "self")] RouteRefreshErrorParsingError),
}

impl<'a> ReadablePdu<'a, LocatedBgpNotificationMessageParsingError<'a>> for BgpNotificationMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBgpNotificationMessageParsingError<'a>> {
        let (buf, notification_type) =
            nom::combinator::map_res(be_u8, BgpErrorNotificationCode::try_from)(buf)?;
        match notification_type {
            BgpErrorNotificationCode::MessageHeaderError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BgpNotificationMessage::MessageHeaderError(value)))
            }
            BgpErrorNotificationCode::OpenMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BgpNotificationMessage::OpenMessageError(value)))
            }
            BgpErrorNotificationCode::UpdateMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BgpNotificationMessage::UpdateMessageError(value)))
            }
            BgpErrorNotificationCode::HoldTimerExpired => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BgpNotificationMessage::HoldTimerExpiredError(value)))
            }
            BgpErrorNotificationCode::FiniteStateMachineError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BgpNotificationMessage::FiniteStateMachineError(value)))
            }
            BgpErrorNotificationCode::Cease => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BgpNotificationMessage::CeaseError(value)))
            }
            BgpErrorNotificationCode::RouteRefreshMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BgpNotificationMessage::RouteRefreshError(value)))
            }
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum MessageHeaderErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedMessageHeaderErrorType(#[from_external] UndefinedMessageHeaderErrorSubCode),
}

impl<'a> ReadablePdu<'a, LocatedMessageHeaderErrorParsingError<'a>> for MessageHeaderError {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OpenMessageErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedOpenMessageErrorSubCode(#[from_external] UndefinedOpenMessageErrorSubCode),
}

impl<'a> ReadablePdu<'a, LocatedOpenMessageErrorParsingError<'a>> for OpenMessageError {
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
            OpenMessageErrorSubCode::BadPeerAs => Ok((
                buf,
                OpenMessageError::BadPeerAs {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::BadBgpIdentifier => Ok((
                buf,
                OpenMessageError::BadBgpIdentifier {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum UpdateMessageErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UndefinedUpdateMessageErrorSubCode(#[from_external] UndefinedUpdateMessageErrorSubCode),
}

impl<'a> ReadablePdu<'a, LocatedUpdateMessageErrorParsingError<'a>> for UpdateMessageError {
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
            UpdateMessageErrorSubCode::MalformedAsPath => Ok((
                buf,
                Self::MalformedAsPath {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum HoldTimerExpiredErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
}

impl<'a> ReadablePdu<'a, LocatedHoldTimerExpiredErrorParsingError<'a>> for HoldTimerExpiredError {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FiniteStateMachineErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Undefined(#[from_external] UndefinedFiniteStateMachineErrorSubCode),
}

impl<'a> ReadablePdu<'a, LocatedFiniteStateMachineErrorParsingError<'a>>
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum CeaseErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Undefined(#[from_external] UndefinedCeaseErrorSubCode),
}

impl<'a> ReadablePdu<'a, LocatedCeaseErrorParsingError<'a>> for CeaseError {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum RouteRefreshErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Undefined(#[from_external] UndefinedRouteRefreshMessageError),
}

impl<'a> ReadablePdu<'a, LocatedRouteRefreshErrorParsingError<'a>> for RouteRefreshError {
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
