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
    nlri::{
        InvalidIpv4MulticastNetwork, InvalidIpv4UnicastNetwork, InvalidIpv6MulticastNetwork,
        InvalidIpv6UnicastNetwork, Ipv4Multicast, Ipv4Unicast, Ipv6Multicast, Ipv6Unicast,
    },
    serde::deserializer::{
        ipv4_network_from_wire, ipv6_network_from_wire,
        path_attribute::{LocatedMpReachParsingError, MpReachParsingError},
        Ipv4PrefixParsingError, Ipv6PrefixParsingError, LocatedIpv4PrefixParsingError,
        LocatedIpv6PrefixParsingError,
    },
};
use netgauze_parse_utils::{IntoLocatedError, LocatedParsingError, ReadablePDU, Span};
use nom::{
    error::{ErrorKind, FromExternalError},
    IResult,
};

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Ipv6UnicastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    Ipv6PrefixError(Ipv6PrefixParsingError),
    InvalidUnicastNetwork(InvalidIpv6UnicastNetwork),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedIpv6UnicastParsingError<'a> {
    span: Span<'a>,
    error: Ipv6UnicastParsingError,
}

impl<'a> LocatedIpv6UnicastParsingError<'a> {
    pub const fn new(span: Span<'a>, error: Ipv6UnicastParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedIpv6UnicastParsingError<'a> {
    type Span = Span<'a>;
    type Error = Ipv6UnicastParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> FromExternalError<Span<'a>, Ipv6PrefixParsingError>
    for LocatedIpv6UnicastParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, e: Ipv6PrefixParsingError) -> Self {
        LocatedIpv6UnicastParsingError::new(input, Ipv6UnicastParsingError::Ipv6PrefixError(e))
    }
}

impl<'a> IntoLocatedError<LocatedIpv6UnicastParsingError<'a>>
    for LocatedIpv6PrefixParsingError<'a>
{
    fn into_located(self) -> LocatedIpv6UnicastParsingError<'a> {
        LocatedIpv6UnicastParsingError::new(
            self.span,
            Ipv6UnicastParsingError::Ipv6PrefixError(self.error),
        )
    }
}

impl<'a> IntoLocatedError<LocatedMpReachParsingError<'a>> for LocatedIpv6UnicastParsingError<'a> {
    fn into_located(self) -> LocatedMpReachParsingError<'a> {
        LocatedMpReachParsingError::new(
            self.span,
            MpReachParsingError::Ipv6UnicastError(self.error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedIpv6UnicastParsingError<'a>> for Ipv6Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6UnicastParsingError<'a>> {
        let input = buf;
        let (buf, net) = match ipv6_network_from_wire(buf) {
            Ok((buf, net)) => (buf, net),
            Err(err) => {
                return Err(match err {
                    nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
                    nom::Err::Error(error) => nom::Err::Error(error.into_located()),
                    nom::Err::Failure(error) => nom::Err::Failure(error.into_located()),
                })
            }
        };
        let net = match Ipv6Unicast::from_net(net) {
            Ok(net) => net,
            Err(err) => {
                return Err(nom::Err::Error(LocatedIpv6UnicastParsingError::new(
                    input,
                    Ipv6UnicastParsingError::InvalidUnicastNetwork(err),
                )));
            }
        };
        Ok((buf, net))
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Ipv6MulticastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    Ipv6PrefixError(Ipv6PrefixParsingError),
    InvalidMulticastNetwork(InvalidIpv6MulticastNetwork),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedIpv6MulticastParsingError<'a> {
    span: Span<'a>,
    error: Ipv6MulticastParsingError,
}

impl<'a> LocatedIpv6MulticastParsingError<'a> {
    pub const fn new(span: Span<'a>, error: Ipv6MulticastParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedIpv6MulticastParsingError<'a> {
    type Span = Span<'a>;
    type Error = Ipv6MulticastParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> FromExternalError<Span<'a>, Ipv6PrefixParsingError>
    for LocatedIpv6MulticastParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, e: Ipv6PrefixParsingError) -> Self {
        LocatedIpv6MulticastParsingError::new(input, Ipv6MulticastParsingError::Ipv6PrefixError(e))
    }
}

impl<'a> IntoLocatedError<LocatedIpv6MulticastParsingError<'a>>
    for LocatedIpv6PrefixParsingError<'a>
{
    fn into_located(self) -> LocatedIpv6MulticastParsingError<'a> {
        LocatedIpv6MulticastParsingError::new(
            self.span,
            Ipv6MulticastParsingError::Ipv6PrefixError(self.error),
        )
    }
}

impl<'a> IntoLocatedError<LocatedMpReachParsingError<'a>> for LocatedIpv6MulticastParsingError<'a> {
    fn into_located(self) -> LocatedMpReachParsingError<'a> {
        LocatedMpReachParsingError::new(
            self.span,
            MpReachParsingError::Ipv6MulticastError(self.error),
        )
    }
}

impl<'a> IntoLocatedError<LocatedMpReachParsingError<'a>> for LocatedIpv4MulticastParsingError<'a> {
    fn into_located(self) -> LocatedMpReachParsingError<'a> {
        LocatedMpReachParsingError::new(
            self.span,
            MpReachParsingError::Ipv4MulticastError(self.error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedIpv6MulticastParsingError<'a>> for Ipv6Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6MulticastParsingError<'a>> {
        let input = buf;
        let (buf, net) = match ipv6_network_from_wire(buf) {
            Ok((buf, net)) => (buf, net),
            Err(err) => {
                return Err(match err {
                    nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
                    nom::Err::Error(error) => nom::Err::Error(error.into_located()),
                    nom::Err::Failure(error) => nom::Err::Failure(error.into_located()),
                })
            }
        };
        let net = match Ipv6Multicast::from_net(net) {
            Ok(net) => net,
            Err(err) => {
                return Err(nom::Err::Error(LocatedIpv6MulticastParsingError::new(
                    input,
                    Ipv6MulticastParsingError::InvalidMulticastNetwork(err),
                )));
            }
        };
        Ok((buf, net))
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Ipv4UnicastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    Ipv4PrefixError(Ipv4PrefixParsingError),
    InvalidUnicastNetwork(InvalidIpv4UnicastNetwork),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedIpv4UnicastParsingError<'a> {
    span: Span<'a>,
    error: Ipv4UnicastParsingError,
}

impl<'a> LocatedIpv4UnicastParsingError<'a> {
    pub const fn new(span: Span<'a>, error: Ipv4UnicastParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedIpv4UnicastParsingError<'a> {
    type Span = Span<'a>;
    type Error = Ipv4UnicastParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> FromExternalError<Span<'a>, Ipv4PrefixParsingError>
    for LocatedIpv4UnicastParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, e: Ipv4PrefixParsingError) -> Self {
        LocatedIpv4UnicastParsingError::new(input, Ipv4UnicastParsingError::Ipv4PrefixError(e))
    }
}

impl<'a> IntoLocatedError<LocatedIpv4UnicastParsingError<'a>>
    for LocatedIpv4PrefixParsingError<'a>
{
    fn into_located(self) -> LocatedIpv4UnicastParsingError<'a> {
        LocatedIpv4UnicastParsingError::new(
            self.span,
            Ipv4UnicastParsingError::Ipv4PrefixError(self.error),
        )
    }
}

impl<'a> IntoLocatedError<LocatedMpReachParsingError<'a>> for LocatedIpv4UnicastParsingError<'a> {
    fn into_located(self) -> LocatedMpReachParsingError<'a> {
        LocatedMpReachParsingError::new(
            self.span,
            MpReachParsingError::Ipv4UnicastError(self.error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedIpv4UnicastParsingError<'a>> for Ipv4Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4UnicastParsingError<'a>> {
        let input = buf;
        let (buf, net) = match ipv4_network_from_wire(buf) {
            Ok((buf, net)) => (buf, net),
            Err(err) => {
                return Err(match err {
                    nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
                    nom::Err::Error(error) => nom::Err::Error(error.into_located()),
                    nom::Err::Failure(error) => nom::Err::Failure(error.into_located()),
                })
            }
        };
        let net = match Ipv4Unicast::from_net(net) {
            Ok(net) => net,
            Err(err) => {
                return Err(nom::Err::Error(LocatedIpv4UnicastParsingError::new(
                    input,
                    Ipv4UnicastParsingError::InvalidUnicastNetwork(err),
                )));
            }
        };
        Ok((buf, net))
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Ipv4MulticastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    Ipv4PrefixError(Ipv4PrefixParsingError),
    InvalidMulticastNetwork(InvalidIpv4MulticastNetwork),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedIpv4MulticastParsingError<'a> {
    span: Span<'a>,
    error: Ipv4MulticastParsingError,
}

impl<'a> LocatedIpv4MulticastParsingError<'a> {
    pub const fn new(span: Span<'a>, error: Ipv4MulticastParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError for LocatedIpv4MulticastParsingError<'a> {
    type Span = Span<'a>;
    type Error = Ipv4MulticastParsingError;

    fn span(&self) -> &Self::Span {
        &self.span
    }

    fn error(&self) -> &Self::Error {
        &self.error
    }
}

impl<'a> FromExternalError<Span<'a>, Ipv4PrefixParsingError>
    for LocatedIpv4MulticastParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, e: Ipv4PrefixParsingError) -> Self {
        LocatedIpv4MulticastParsingError::new(input, Ipv4MulticastParsingError::Ipv4PrefixError(e))
    }
}

impl<'a> IntoLocatedError<LocatedIpv4MulticastParsingError<'a>>
    for LocatedIpv4PrefixParsingError<'a>
{
    fn into_located(self) -> LocatedIpv4MulticastParsingError<'a> {
        LocatedIpv4MulticastParsingError::new(
            self.span,
            Ipv4MulticastParsingError::Ipv4PrefixError(self.error),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedIpv4MulticastParsingError<'a>> for Ipv4Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4MulticastParsingError<'a>> {
        let input = buf;
        let (buf, net) = match ipv4_network_from_wire(buf) {
            Ok((buf, net)) => (buf, net),
            Err(err) => {
                return Err(match err {
                    nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
                    nom::Err::Error(error) => nom::Err::Error(error.into_located()),
                    nom::Err::Failure(error) => nom::Err::Failure(error.into_located()),
                })
            }
        };
        let net = match Ipv4Multicast::from_net(net) {
            Ok(net) => net,
            Err(err) => {
                return Err(nom::Err::Error(LocatedIpv4MulticastParsingError::new(
                    input,
                    Ipv4MulticastParsingError::InvalidMulticastNetwork(err),
                )));
            }
        };
        Ok((buf, net))
    }
}
