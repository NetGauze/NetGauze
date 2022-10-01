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
    serde::deserializer::{Ipv4PrefixParsingError, Ipv6PrefixParsingError},
};
use netgauze_parse_utils::{parse_into_located, ReadablePDU, Span};
use netgauze_serde_macros::LocatedError;
use nom::{error::ErrorKind, IResult};

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv6UnicastParsingError {
    Ipv6PrefixError(
        #[from_external]
        #[from_located(module = "crate::serde::deserializer")]
        Ipv6PrefixParsingError,
    ),
    InvalidUnicastNetwork(#[from_external] InvalidIpv6UnicastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv6UnicastParsingError<'a>> for Ipv6Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv6MulticastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    Ipv6PrefixError(
        #[from_external]
        #[from_located(module = "crate::serde::deserializer")]
        Ipv6PrefixParsingError,
    ),
    InvalidMulticastNetwork(#[from_external] InvalidIpv6MulticastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv6MulticastParsingError<'a>> for Ipv6Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6MulticastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4UnicastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    Ipv4PrefixError(
        #[from_external]
        #[from_located(module = "crate::serde::deserializer")]
        Ipv4PrefixParsingError,
    ),
    InvalidUnicastNetwork(#[from_external] InvalidIpv4UnicastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv4UnicastParsingError<'a>> for Ipv4Unicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4UnicastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4MulticastParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    Ipv4PrefixError(
        #[from_external]
        #[from_located(module = "crate::serde::deserializer")]
        Ipv4PrefixParsingError,
    ),
    InvalidMulticastNetwork(#[from_external] InvalidIpv4MulticastNetwork),
}

impl<'a> ReadablePDU<'a, LocatedIpv4MulticastParsingError<'a>> for Ipv4Multicast {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4MulticastParsingError<'a>> {
        let (buf, net) = nom::combinator::map_res(parse_into_located, Self::from_net)(buf)?;
        Ok((buf, net))
    }
}
