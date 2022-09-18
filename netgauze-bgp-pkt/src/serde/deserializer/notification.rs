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
        BGPErrorNotificationCode, MessageHeaderErrorSubCode, UndefinedBGPErrorNotificationCode,
        UndefinedMessageHeaderErrorSubCode,
    },
    notification::MessageHeaderError,
    serde::deserializer::{BGPMessageParsingError, LocatedBGPMessageParsingError},
    BGPNotificationMessage,
};
use netgauze_parse_utils::{
    parse_into_located, IntoLocatedError, LocatedParsingError, ReadablePDU, Span,
};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::be_u8,
    IResult,
};

/// BGP Notification Message Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPNotificationMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedBGPErrorNotificationCode(UndefinedBGPErrorNotificationCode),
    MessageHeaderError(MessageHeaderErrorParsingError),
}

/// BGP Notification Message Parsing errors  with the input location of where it
/// occurred in the input byte stream being parsed
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPNotificationMessageParsingError<'a> {
    span: Span<'a>,
    error: BGPNotificationMessageParsingError,
}

impl<'a> LocatedBGPNotificationMessageParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPNotificationMessageParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError<'a, BGPNotificationMessageParsingError>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn span(&self) -> &Span<'a> {
        &self.span
    }

    fn error(&self) -> &BGPNotificationMessageParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedError<'a, BGPMessageParsingError, LocatedBGPMessageParsingError<'a>>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn into_located(self) -> LocatedBGPMessageParsingError<'a> {
        LocatedBGPMessageParsingError::new(
            self.span,
            BGPMessageParsingError::BGPNotificationMessageParsingError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedBGPNotificationMessageParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedBGPNotificationMessageParsingError::new(
            input,
            BGPNotificationMessageParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, BGPNotificationMessageParsingError>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPNotificationMessageParsingError,
    ) -> Self {
        LocatedBGPNotificationMessageParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedBGPErrorNotificationCode>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedBGPErrorNotificationCode,
    ) -> Self {
        LocatedBGPNotificationMessageParsingError::new(
            input,
            BGPNotificationMessageParsingError::UndefinedBGPErrorNotificationCode(e),
        )
    }
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
            BGPErrorNotificationCode::OpenMessageError => todo!(),
            BGPErrorNotificationCode::UpdateMessageError => todo!(),
            BGPErrorNotificationCode::HoldTimerExpired => todo!(),
            BGPErrorNotificationCode::FiniteStateMachineError => todo!(),
            BGPErrorNotificationCode::Cease => todo!(),
            BGPErrorNotificationCode::RouteRefreshMessageError => todo!(),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MessageHeaderErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedMessageHeaderErrorType(UndefinedMessageHeaderErrorSubCode),
}

/// BGP Notification Message Parsing errors  with the input location of where it
/// occurred in the input byte stream being parsed
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedMessageHeaderErrorParsingError<'a> {
    span: Span<'a>,
    error: MessageHeaderErrorParsingError,
}

impl<'a> LocatedMessageHeaderErrorParsingError<'a> {
    pub const fn new(span: Span<'a>, error: MessageHeaderErrorParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError<'a, MessageHeaderErrorParsingError>
    for LocatedMessageHeaderErrorParsingError<'a>
{
    fn span(&self) -> &Span<'a> {
        &self.span
    }

    fn error(&self) -> &MessageHeaderErrorParsingError {
        &self.error
    }
}

impl<'a>
    IntoLocatedError<
        'a,
        BGPNotificationMessageParsingError,
        LocatedBGPNotificationMessageParsingError<'a>,
    > for LocatedMessageHeaderErrorParsingError<'a>
{
    fn into_located(self) -> LocatedBGPNotificationMessageParsingError<'a> {
        LocatedBGPNotificationMessageParsingError::new(
            self.span,
            BGPNotificationMessageParsingError::MessageHeaderError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedMessageHeaderErrorParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedMessageHeaderErrorParsingError::new(
            input,
            MessageHeaderErrorParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, MessageHeaderErrorParsingError>
    for LocatedMessageHeaderErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: MessageHeaderErrorParsingError,
    ) -> Self {
        LocatedMessageHeaderErrorParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedMessageHeaderErrorSubCode>
    for LocatedMessageHeaderErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedMessageHeaderErrorSubCode,
    ) -> Self {
        LocatedMessageHeaderErrorParsingError::new(
            input,
            MessageHeaderErrorParsingError::UndefinedMessageHeaderErrorType(e),
        )
    }
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
