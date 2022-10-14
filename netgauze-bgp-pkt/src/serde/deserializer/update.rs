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

//! Deserializer for BGP Update message

use crate::{
    serde::deserializer::{path_attribute::PathAttributeParsingError, Ipv4PrefixParsingError},
    update::{NetworkLayerReachabilityInformation, WithdrawRoute},
    BGPUpdateMessage,
};
use ipnet::Ipv4Net;
use netgauze_parse_utils::{
    parse_into_located, parse_till_empty_into_located,
    parse_till_empty_into_with_one_input_located, ReadablePDU, ReadablePDUWithOneInput, Span,
};
use nom::{error::ErrorKind, number::complete::be_u16, IResult};
use serde::{Deserialize, Serialize};

use crate::serde::deserializer::ErrorKindSerdeDeref;
use netgauze_serde_macros::LocatedError;

/// BGP Open Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BGPUpdateMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    WithdrawRouteError(#[from_located(module = "self")] WithdrawRouteParsingError),
    PathAttributeError(
        #[from_located(module = "crate::serde::deserializer::path_attribute")]
        PathAttributeParsingError,
    ),
    NetworkLayerReachabilityInformationError(
        #[from_located(module = "self")] NetworkLayerReachabilityInformationParsingError,
    ),
}

/// Helper function to parse the withdraw routes buffer in an update message
#[inline]
fn parse_withdraw_routes(
    buf: Span<'_>,
) -> IResult<Span<'_>, Vec<WithdrawRoute>, LocatedBGPUpdateMessageParsingError<'_>> {
    let (buf, routes) = parse_till_empty_into_located(buf)?;
    Ok((buf, routes))
}

impl<'a> ReadablePDUWithOneInput<'a, bool, LocatedBGPUpdateMessageParsingError<'a>>
    for BGPUpdateMessage
{
    fn from_wire(
        buf: Span<'a>,
        asn4: bool,
    ) -> IResult<Span<'a>, Self, LocatedBGPUpdateMessageParsingError<'a>> {
        let (buf, withdrawn_buf) = nom::multi::length_data(be_u16)(buf)?;
        let (_, withdrawn_routes) = parse_withdraw_routes(withdrawn_buf)?;
        let (buf, path_attributes_buf) = nom::multi::length_data(be_u16)(buf)?;
        let (_, path_attributes) =
            parse_till_empty_into_with_one_input_located(path_attributes_buf, asn4)?;
        let (buf, nlri_vec) = parse_till_empty_into_located(buf)?;
        Ok((
            buf,
            BGPUpdateMessage::new(withdrawn_routes, path_attributes, nlri_vec),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum WithdrawRouteParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Ipv4PrefixParsingError(
        #[from_located(module = "crate::serde::deserializer")] Ipv4PrefixParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedWithdrawRouteParsingError<'a>> for WithdrawRoute {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedWithdrawRouteParsingError<'a>> {
        let (buf, net) = parse_into_located(buf)?;
        Ok((buf, WithdrawRoute::new(net)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NetworkLayerReachabilityInformationParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    Ipv4PrefixParsingError(
        #[from_located(module = "crate::serde::deserializer")] Ipv4PrefixParsingError,
    ),
}

fn parse_nlri_ipv4(
    buf: Span<'_>,
) -> IResult<Span<'_>, Ipv4Net, LocatedNetworkLayerReachabilityInformationParsingError<'_>> {
    let (buf, net) = parse_into_located(buf)?;
    Ok((buf, net))
}

impl<'a> ReadablePDU<'a, LocatedNetworkLayerReachabilityInformationParsingError<'a>>
    for NetworkLayerReachabilityInformation
{
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedNetworkLayerReachabilityInformationParsingError<'a>> {
        let mut buf = buf;
        let mut nets = vec![];
        while !buf.is_empty() {
            let (t, net) = parse_nlri_ipv4(buf)?;
            nets.push(net);
            buf = t;
        }
        Ok((buf, NetworkLayerReachabilityInformation::new(nets)))
    }
}
