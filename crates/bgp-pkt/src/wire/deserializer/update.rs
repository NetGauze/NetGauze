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

use crate::BgpUpdateMessage;
use crate::wire::deserializer::path_attribute::{
    LocatedPathAttributeParsingError, PathAttributeParsingError,
};
use ipnet::Ipv4Net;
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{
    LocatedParsingError, ReadablePduWithOneInput, Span, parse_into_located,
};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u32};
use serde::{Deserialize, Serialize};

use crate::nlri::{InvalidIpv4UnicastNetwork, Ipv4Unicast, Ipv4UnicastAddress};
use crate::notification::UpdateMessageError;
use crate::path_attribute::PathAttribute;
use crate::wire::deserializer::path_attribute::{
    EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK, OriginParsingError,
};
use crate::wire::deserializer::{BgpParsingContext, Ipv4PrefixParsingError};
use netgauze_parse_utils::ErrorKindSerdeDeref;
use netgauze_serde_macros::LocatedError;

/// BGP Open Message Parsing errors
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpUpdateMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    PathAttributeError(
        #[from_located(module = "crate::wire::deserializer::path_attribute")]
        PathAttributeParsingError,
    ),
    Ipv4PrefixError(#[from_located(module = "crate::wire::deserializer")] Ipv4PrefixParsingError),
    InvalidIpv4UnicastNetwork(InvalidIpv4UnicastNetwork),
}

#[inline]
fn parse_nlri<'a>(
    buf: Span<'a>,
    add_path: bool,
    is_update: bool,
    ctx: &mut BgpParsingContext,
) -> IResult<Span<'a>, Vec<Ipv4UnicastAddress>, LocatedBgpUpdateMessageParsingError<'a>> {
    let mut buf = buf;
    let mut nlri_vec = Vec::new();
    while !buf.is_empty() {
        let (tmp, path_id) = if add_path {
            let (tmp, add_path) = be_u32(buf)?;
            (tmp, Some(add_path))
        } else {
            (buf, None)
        };
        let buf_begin = tmp;
        let (tmp, ipv4_net): (Span<'a>, Ipv4Net) = parse_into_located(tmp)?;
        match Ipv4Unicast::from_net(ipv4_net) {
            Ok(unicast) => {
                let address = Ipv4UnicastAddress::new(path_id, unicast);
                nlri_vec.push(address);
            }
            Err(err) => {
                // RFC 4271: If a prefix in the NLRI field is semantically incorrect (e.g., an
                // unexpected multicast IP address), an error SHOULD be logged locally, and the
                // prefix SHOULD be ignored.
                if is_update && ctx.fail_on_non_unicast_update_nlri {
                    ctx.parsing_errors.non_unicast_update_nlri.push(ipv4_net);
                }
                if !is_update && !ctx.fail_on_non_unicast_withdraw_nlri {
                    ctx.parsing_errors.non_unicast_withdraw_nlri.push(ipv4_net);
                } else if is_update && !ctx.fail_on_non_unicast_update_nlri {
                    ctx.parsing_errors.non_unicast_update_nlri.push(ipv4_net);
                } else {
                    return Err(nom::Err::Error(LocatedBgpUpdateMessageParsingError::new(
                        buf_begin,
                        BgpUpdateMessageParsingError::InvalidIpv4UnicastNetwork(err),
                    )));
                }
            }
        };
        buf = tmp;
    }
    Ok((buf, nlri_vec))
}

#[inline]
fn advance_attr_buffer(
    path_attributes_buf: Span<'_>,
) -> IResult<Span<'_>, Span<'_>, LocatedBgpUpdateMessageParsingError<'_>> {
    let (buf, attributes) = be_u8(path_attributes_buf)?;
    let (buf, _code) = be_u8(buf)?;
    let extended_length =
        attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
    let (buf, length) = if extended_length {
        let (buf, length) = be_u16(buf)?;
        (buf, length as usize)
    } else {
        let (buf, length) = be_u8(buf)?;
        (buf, length as usize)
    };
    nom::bytes::complete::take(length)(buf)
}

/// Length is for value length only (not counting attribute type and extra byte
/// for extended length)
#[inline]
fn advance_attr_buffer_fixed(
    length: usize,
    path_attributes_buf: Span<'_>,
) -> IResult<Span<'_>, Span<'_>, LocatedBgpUpdateMessageParsingError<'_>> {
    let (buf, attributes) = be_u8(path_attributes_buf)?;
    let extended_length =
        attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
    if extended_length {
        // extra one for path attribute type
        // extra two for extended length
        nom::bytes::complete::take(length + 3)(buf)
    } else {
        // extra one for path attribute type
        // extra one for length
        nom::bytes::complete::take(length + 2)(buf)
    }
}

impl<'a>
    ReadablePduWithOneInput<'a, &mut BgpParsingContext, LocatedBgpUpdateMessageParsingError<'a>>
    for BgpUpdateMessage
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBgpUpdateMessageParsingError<'a>> {
        let add_path = ctx
            .add_path
            .get(&AddressType::Ipv4Unicast)
            .is_some_and(|x| *x);
        let (buf, withdrawn_buf) = nom::multi::length_data(be_u16)(buf)?;
        let (_, withdrawn_routes) = parse_nlri(withdrawn_buf, add_path, false, ctx)?;
        let (buf, mut path_attributes_buf) = nom::multi::length_data(be_u16)(buf)?;
        let mut path_attributes = Vec::new();
        while !path_attributes_buf.is_empty() {
            match PathAttribute::from_wire(path_attributes_buf, &mut *ctx) {
                Ok((tmp, element)) => {
                    path_attributes.push(element);
                    path_attributes_buf = tmp;
                }
                Err(nom_err) => match nom_err {
                    nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed))?,
                    nom::Err::Error(located_path_attr_error) => {
                        if ctx.fail_on_malformed_path_attr {
                            return Err(nom::Err::Error(located_path_attr_error.into()));
                        }
                        let (tmp, _) =
                            handle_path_error(path_attributes_buf, ctx, &located_path_attr_error)?;
                        path_attributes_buf = tmp;
                        ctx.parsing_errors
                            .path_attr_errors
                            .push(located_path_attr_error.error().clone());
                    }
                    nom::Err::Failure(located_path_attr_error) => {
                        if ctx.fail_on_malformed_path_attr {
                            return Err(nom::Err::Error(located_path_attr_error.into()));
                        }
                        let (tmp, _) =
                            handle_path_error(path_attributes_buf, ctx, &located_path_attr_error)?;
                        path_attributes_buf = tmp;
                        ctx.parsing_errors
                            .path_attr_errors
                            .push(located_path_attr_error.error().clone());
                    }
                },
            };
        }
        let (buf, nlri_vec) = parse_nlri(buf, add_path, true, ctx)?;
        Ok((
            buf,
            BgpUpdateMessage::new(withdrawn_routes, path_attributes, nlri_vec),
        ))
    }
}

fn handle_path_error<'a>(
    path_attributes_buf: Span<'a>,
    ctx: &mut BgpParsingContext,
    located_path_attr_error: &LocatedPathAttributeParsingError<'a>,
) -> IResult<Span<'a>, (), LocatedBgpUpdateMessageParsingError<'a>> {
    let buf = match located_path_attr_error.error() {
        PathAttributeParsingError::NomError(_) => {
            return Err(nom::Err::Error(located_path_attr_error.clone().into()));
        }
        PathAttributeParsingError::OriginError(_) => {
            let (buf, _) = advance_attr_buffer_fixed(1usize, path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::AsPathError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::NextHopError(_) => {
            let (buf, _) = advance_attr_buffer_fixed(4usize, path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::MultiExitDiscriminatorError(_) => {
            let (buf, _) = advance_attr_buffer_fixed(4usize, path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::LocalPreferenceError(_) => {
            let (buf, _) = advance_attr_buffer_fixed(4usize, path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::AtomicAggregateError(_) => {
            let (buf, _) = advance_attr_buffer_fixed(0usize, path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::AggregatorError(_) => {
            let size = if ctx.asn4 { 8usize } else { 6usize };
            let (buf, _) = advance_attr_buffer_fixed(size, path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::CommunitiesError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::ExtendedCommunitiesError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::LargeCommunitiesError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::OriginatorError(_) => {
            let (buf, _) = advance_attr_buffer_fixed(4usize, path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::ClusterListError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::MpReachErrorError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::MpUnreachErrorError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::OnlyToCustomerError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::AigpError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::UnknownAttributeError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::InvalidPathAttribute(_, _) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::BgpLsError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
        PathAttributeParsingError::SegmentIdentifierParsingError(_) => {
            let (buf, _) = advance_attr_buffer(path_attributes_buf)?;
            buf
        }
    };
    Ok((buf, ()))
}

impl From<BgpUpdateMessageParsingError> for UpdateMessageError {
    fn from(value: BgpUpdateMessageParsingError) -> Self {
        // For EoF errors we follow: RFC 4271 Error checking of an UPDATE message begins
        // by examining the path attributes. If the Withdrawn Routes Length or
        // Total Attribute Length is too large (i.e., if Withdrawn Routes Length
        // + Total Attribute Length + 23 exceeds the message Length), then the
        // Error Subcode MUST be set to Malformed Attribute List.
        match value {
            BgpUpdateMessageParsingError::NomError(err) => {
                if err == nom::error::ErrorKind::Eof {
                    UpdateMessageError::MalformedAttributeList { value: vec![] }
                } else {
                    UpdateMessageError::Unspecific { value: vec![] }
                }
            }
            BgpUpdateMessageParsingError::PathAttributeError(attr_err) => {
                // TODO need to be refined in accordance with RFC 7606
                match attr_err {
                    PathAttributeParsingError::NomError(_) => {
                        UpdateMessageError::MalformedAttributeList { value: vec![] }
                    }
                    PathAttributeParsingError::OriginError(err) => match err {
                        OriginParsingError::NomError(_) => {
                            UpdateMessageError::InvalidOriginAttribute { value: vec![] }
                        }
                        OriginParsingError::InvalidOriginLength(_) => {
                            UpdateMessageError::InvalidOriginAttribute { value: vec![] }
                        }
                        OriginParsingError::UndefinedOrigin(_) => {
                            UpdateMessageError::InvalidOriginAttribute { value: vec![] }
                        }
                    },
                    PathAttributeParsingError::AsPathError(_) => {
                        UpdateMessageError::MalformedAsPath { value: vec![] }
                    }
                    PathAttributeParsingError::NextHopError(_) => {
                        UpdateMessageError::InvalidNextHopAttribute { value: vec![] }
                    }
                    PathAttributeParsingError::MultiExitDiscriminatorError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::LocalPreferenceError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::AtomicAggregateError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::AggregatorError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::CommunitiesError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::ExtendedCommunitiesError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::LargeCommunitiesError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::OriginatorError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::ClusterListError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::MpReachErrorError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::MpUnreachErrorError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::OnlyToCustomerError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::AigpError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                    PathAttributeParsingError::UnknownAttributeError(_) => {
                        UpdateMessageError::Unspecific { value: vec![] }
                    }
                    PathAttributeParsingError::InvalidPathAttribute(_, _) => {
                        UpdateMessageError::AttributeFlagsError { value: vec![] }
                    }
                    PathAttributeParsingError::BgpLsError(_) => {
                        // TODO what to do here ?
                        UpdateMessageError::Unspecific { value: vec![] }
                    }
                    PathAttributeParsingError::SegmentIdentifierParsingError(_) => {
                        UpdateMessageError::OptionalAttributeError { value: vec![] }
                    }
                }
            }
            BgpUpdateMessageParsingError::Ipv4PrefixError(prefix_err) => {
                if Ipv4PrefixParsingError::NomError(nom::error::ErrorKind::Eof) == prefix_err {
                    return UpdateMessageError::MalformedAttributeList { value: vec![] };
                }
                UpdateMessageError::InvalidNetworkField { value: vec![] }
            }
            BgpUpdateMessageParsingError::InvalidIpv4UnicastNetwork(_) => {
                // RFC 4271: If a prefix in the NLRI field is semantically incorrect (e.g., an
                // unexpected multicast IP address), an error SHOULD be logged locally, and the
                // prefix SHOULD be ignored.
                // If parser is configured to be strict and this error triggered, then report
                // Unspecific error
                UpdateMessageError::Unspecific { value: vec![] }
            }
        }
    }
}
