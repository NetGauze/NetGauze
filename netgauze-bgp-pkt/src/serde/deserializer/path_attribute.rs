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

//! Deserializer for BGP Path Attributes

use crate::{
    path_attribute::PathAttribute,
    serde::deserializer::{
        update::LocatedBGPUpdateMessageParsingError, BGPUpdateMessageParsingError,
    },
};
use netgauze_parse_utils::{ReadablePDU, Span};
use nom::{
    error::{ErrorKind, FromExternalError},
    IResult,
};

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPPathAttributeParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPPathAttributeParsingError<'a> {
    span: Span<'a>,
    error: BGPPathAttributeParsingError,
}

impl<'a> LocatedBGPPathAttributeParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPPathAttributeParsingError) -> Self {
        Self { span, error }
    }

    pub const fn span(&self) -> &Span<'a> {
        &self.span
    }

    pub const fn error(&self) -> &BGPPathAttributeParsingError {
        &self.error
    }

    pub const fn into_located_bgp_update_message_error(
        self,
    ) -> LocatedBGPUpdateMessageParsingError<'a> {
        let span = self.span;
        let error = self.error;
        LocatedBGPUpdateMessageParsingError::new(
            span,
            BGPUpdateMessageParsingError::PathAttributeError(error),
        )
    }
}

impl<'a> FromExternalError<Span<'a>, BGPPathAttributeParsingError>
    for LocatedBGPPathAttributeParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPPathAttributeParsingError,
    ) -> Self {
        LocatedBGPPathAttributeParsingError::new(input, error)
    }
}

impl<'a> ReadablePDU<'a, LocatedBGPPathAttributeParsingError<'a>> for PathAttribute {
    fn from_wire(
        _buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBGPPathAttributeParsingError<'a>> {
        todo!()
    }
}
