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
    serde::deserializer::{BGPMessageParsingError, LocatedBGPMessageParsingError},
    BGPNotificationMessage,
};
use netgauze_parse_utils::{IntoLocatedError, LocatedParsingError, ReadablePDU, Span};
use nom::{
    error::{ErrorKind, FromExternalError},
    IResult,
};

/// BGP Notification Message Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPNotificationMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
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

impl<'a> ReadablePDU<'a, LocatedBGPNotificationMessageParsingError<'a>> for BGPNotificationMessage {
    fn from_wire(
        _buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBGPNotificationMessageParsingError<'a>> {
        todo!()
    }
}
