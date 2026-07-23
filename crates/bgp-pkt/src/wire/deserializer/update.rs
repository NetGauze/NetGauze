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
use crate::nlri::{Ipv4Unicast, Ipv4UnicastAddress};
use crate::notification::UpdateMessageError;
use crate::path_attribute::PathAttribute;
use crate::wire::deserializer::BgpParsingContext;
use crate::wire::deserializer::community::{
    CommunityParsingError, ExtendedCommunityIpv6ParsingError, ExtendedCommunityParsingError,
};
use crate::wire::deserializer::path_attribute::{
    AS2_AGGREGATOR_LEN, AS4_AGGREGATOR_LEN, ATOMIC_AGGREGATE_LEN, AggregatorParsingError,
    AsPathParsingError, AtomicAggregateParsingError, CommunitiesParsingError,
    EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK, ExtendedCommunitiesIpv6ParsingError,
    ExtendedCommunitiesParsingError, LOCAL_PREFERENCE_LEN, LocalPreferenceParsingError,
    MULTI_EXIT_DISCRIMINATOR_LEN, MultiExitDiscriminatorParsingError, NEXT_HOP_LEN,
    NextHopParsingError, OriginParsingError, PathAttributeParsingError,
};
use ipnet::Ipv4Net;
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::common::Ipv4PrefixParsingError;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};
use serde::{Deserialize, Serialize};

/// BGP Open Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpUpdateMessageParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("in path attribute: {0}")]
    PathAttributeError(#[from] PathAttributeParsingError),

    #[error("in IPv4 prefix: {0}")]
    Ipv4PrefixError(#[from] Ipv4PrefixParsingError),

    #[error("{network} is not a valid IPv4 unicast network in NLRI at byte offset {offset}")]
    InvalidIpv4UnicastNetwork { offset: usize, network: Ipv4Net },
}

/// Counts entries in a withdrawn-routes/NLRI buffer without materializing
/// them, mirroring [`Ipv4Net`]'s own prefix-length-to-byte-count logic, so
/// `parse_nlri` can size its `Vec::with_capacity` exactly instead of
/// guessing from a flat minimum-size heuristic.
///
/// Purely advisory: a malformed buffer stops the count early rather than
/// returning an error, so it never changes what error the real parsing
/// loop reports (or its type) — it only ever affects the capacity hint.
#[inline]
fn count_nlri(mut cur: SliceReader<'_>, add_path: bool) -> usize {
    let mut count = 0usize;
    loop {
        if cur.is_empty() {
            return count;
        }
        if add_path && cur.read_u32_be().is_err() {
            return count;
        }
        let Ok(prefix_len) = cur.read_u8() else {
            return count;
        };
        let prefix_size = if prefix_len >= u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        if cur.read_bytes(prefix_size.min(4) as usize).is_err() {
            return count;
        }
        count += 1;
    }
}

#[inline]
fn parse_nlri<'a>(
    cur: &mut SliceReader<'a>,
    add_path: bool,
    is_update: bool,
    ctx: &mut BgpParsingContext,
) -> Result<Box<[Ipv4UnicastAddress]>, BgpUpdateMessageParsingError> {
    let mut nlri_vec = Vec::with_capacity(count_nlri(*cur, add_path));
    while !cur.is_empty() {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let offset = cur.offset();
        let ipv4_net = Ipv4Net::parse(cur)?;
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
                    return Err(BgpUpdateMessageParsingError::InvalidIpv4UnicastNetwork {
                        offset,
                        network: err.0,
                    });
                }
            }
        };
    }
    Ok(nlri_vec.into_boxed_slice())
}

/// Counts path attributes in a buffer without parsing their values,
/// mirroring [`advance_attr_buffer`]'s header framing, so the real parsing
/// loop can size its `Vec::with_capacity` exactly instead of guessing from
/// a flat minimum-size heuristic.
///
/// Purely advisory: a malformed buffer stops the count early rather than
/// returning an error, so it never changes what error the real parsing
/// loop reports (or its type) — it only ever affects the capacity hint.
#[inline(always)]
fn count_path_attributes(mut cur: SliceReader<'_>) -> usize {
    let mut count = 0usize;
    loop {
        if cur.is_empty() {
            return count;
        }
        let Ok(attributes) = cur.read_u8() else {
            return count;
        };
        let Ok(_code) = cur.read_u8() else {
            return count;
        };
        let extended_length =
            attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
        let len = if extended_length {
            let Ok(len) = cur.read_u16_be() else {
                return count;
            };
            len as usize
        } else {
            let Ok(len) = cur.read_u8() else {
                return count;
            };
            len as usize
        };
        if cur.take_slice(len).is_err() {
            return count;
        }
        count += 1;
    }
}

#[inline]
fn advance_attr_buffer<'a>(
    path_attributes_buf: &mut SliceReader<'a>,
) -> Result<SliceReader<'a>, BgpUpdateMessageParsingError> {
    let attributes = path_attributes_buf.read_u8()?;
    let _code = path_attributes_buf.read_u8()?;
    let extended_length =
        attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
    let buf = if extended_length {
        let len = path_attributes_buf.read_u16_be()?;
        path_attributes_buf.take_slice(len as usize)?
    } else {
        let len = path_attributes_buf.read_u8()?;
        path_attributes_buf.take_slice(len as usize)?
    };
    Ok(buf)
}

/// Length is for value length only (not counting attribute type and extra byte
/// for extended length)
#[inline]
fn advance_attr_buffer_fixed<'a>(
    length: usize,
    path_attributes_buf: &mut SliceReader<'a>,
) -> Result<SliceReader<'a>, BgpUpdateMessageParsingError> {
    let attributes = path_attributes_buf.read_u8()?;
    let extended_length =
        attributes & EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK == EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK;
    if extended_length {
        // extra one for path attribute type
        // extra two for extended length
        let buf = path_attributes_buf.take_slice(length + 3)?;
        Ok(buf)
    } else {
        // extra one for path attribute type
        // extra one for length
        let buf = path_attributes_buf.take_slice(length + 2)?;
        Ok(buf)
    }
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for BgpUpdateMessage {
    type Error = BgpUpdateMessageParsingError;
    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BgpParsingContext) -> Result<Self, Self::Error> {
        let add_path = ctx
            .add_path
            .get(&AddressType::Ipv4Unicast)
            .is_some_and(|x| *x);
        let len = cur.read_u16_be()?;
        let mut withdrawn_buf = cur.take_slice(len as usize)?;
        let withdrawn_routes = parse_nlri(&mut withdrawn_buf, add_path, false, ctx)?;
        let len = cur.read_u16_be()?;
        let mut path_attributes_buf = cur.take_slice(len as usize)?;
        let mut path_attributes = Vec::with_capacity(count_path_attributes(path_attributes_buf));
        while !path_attributes_buf.is_empty() {
            match PathAttribute::parse(&mut path_attributes_buf, &mut *ctx) {
                Ok(element) => {
                    path_attributes.push(element);
                }
                Err(error) => match error {
                    PathAttributeParsingError::Parse(parse_error) => {
                        return Err(BgpUpdateMessageParsingError::Parse(parse_error));
                    }
                    err => {
                        if ctx.fail_on_malformed_path_attr {
                            return Err(BgpUpdateMessageParsingError::PathAttributeError(err));
                        } else {
                            handle_path_error(&mut path_attributes_buf, ctx, &err)?;
                            ctx.parsing_errors.path_attr_errors.push(err);
                        }
                    }
                },
            };
        }
        let nlri_vec = parse_nlri(cur, add_path, true, ctx)?;
        Ok(BgpUpdateMessage::new(
            withdrawn_routes,
            path_attributes.into_boxed_slice(),
            nlri_vec,
        ))
    }
}

fn handle_path_error<'a>(
    path_attributes_buf: &mut SliceReader<'a>,
    ctx: &mut BgpParsingContext,
    path_attr_error: &PathAttributeParsingError,
) -> Result<SliceReader<'a>, BgpUpdateMessageParsingError> {
    let buf = match path_attr_error {
        PathAttributeParsingError::Parse(error)
        | PathAttributeParsingError::OriginError(OriginParsingError::Parse(error))
        | PathAttributeParsingError::AsPathError(AsPathParsingError::Parse(error))
        | PathAttributeParsingError::NextHopError(NextHopParsingError::Parse(error))
        | PathAttributeParsingError::MultiExitDiscriminatorError(
            MultiExitDiscriminatorParsingError::Parse(error),
        )
        | PathAttributeParsingError::LocalPreferenceError(LocalPreferenceParsingError::Parse(
            error,
        ))
        | PathAttributeParsingError::AtomicAggregateError(AtomicAggregateParsingError::Parse(
            error,
        ))
        | PathAttributeParsingError::AggregatorError(AggregatorParsingError::Parse(error))
        | PathAttributeParsingError::CommunitiesError(CommunitiesParsingError::Parse(error))
        | PathAttributeParsingError::CommunitiesError(CommunitiesParsingError::CommunityError(
            CommunityParsingError::Parse(error),
        ))
        | PathAttributeParsingError::ExtendedCommunitiesError(
            ExtendedCommunitiesParsingError::Parse(error),
        )
        | PathAttributeParsingError::ExtendedCommunitiesError(
            ExtendedCommunitiesParsingError::ExtendedCommunityError(
                ExtendedCommunityParsingError::Parse(error),
            ),
        )
        | PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(
            ExtendedCommunitiesIpv6ParsingError::Parse(error),
        )
        | PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(
            ExtendedCommunitiesIpv6ParsingError::ExtendedCommunityIpv6Error(
                ExtendedCommunityIpv6ParsingError::Parse(error),
            ),
        ) => {
            return Err(BgpUpdateMessageParsingError::Parse(*error));
        }
        PathAttributeParsingError::OriginError(_) => path_attributes_buf.take_slice(0)?,
        PathAttributeParsingError::AsPathError(_) => path_attributes_buf.take_slice(0)?,
        PathAttributeParsingError::NextHopError(NextHopParsingError::InvalidNextHopLength {
            ..
        }) => path_attributes_buf.take_slice(NEXT_HOP_LEN as usize)?,
        PathAttributeParsingError::MultiExitDiscriminatorError(
            MultiExitDiscriminatorParsingError::InvalidLength { .. },
        ) => path_attributes_buf.take_slice(MULTI_EXIT_DISCRIMINATOR_LEN as usize)?,
        PathAttributeParsingError::LocalPreferenceError(
            LocalPreferenceParsingError::InvalidLength { .. },
        ) => path_attributes_buf.take_slice(LOCAL_PREFERENCE_LEN as usize)?,
        PathAttributeParsingError::AtomicAggregateError(
            AtomicAggregateParsingError::InvalidLength { .. },
        ) => path_attributes_buf.take_slice(ATOMIC_AGGREGATE_LEN as usize)?,
        PathAttributeParsingError::AggregatorError(AggregatorParsingError::InvalidLength {
            ..
        }) => {
            let size = if ctx.asn4 {
                AS4_AGGREGATOR_LEN
            } else {
                AS2_AGGREGATOR_LEN
            };
            path_attributes_buf.take_slice(size as usize)?
        }
        // we cannot skip communities parsing errors
        // PathAttributeParsingError::CommunitiesError(_) => {
        // }
        PathAttributeParsingError::ExtendedCommunitiesError(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::LargeCommunitiesError(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::OriginatorError(_) => {
            advance_attr_buffer_fixed(4usize, path_attributes_buf)?
        }
        PathAttributeParsingError::ClusterListError(_) => advance_attr_buffer(path_attributes_buf)?,
        PathAttributeParsingError::MpReachErrorError(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::MpUnreachErrorError(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::OnlyToCustomerError(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::AigpError(_) => advance_attr_buffer(path_attributes_buf)?,
        PathAttributeParsingError::UnknownAttributeError(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::InvalidPathAttribute { .. } => {
            advance_attr_buffer(path_attributes_buf)?
        }
        PathAttributeParsingError::BgpLsError(_) => advance_attr_buffer(path_attributes_buf)?,
        PathAttributeParsingError::SegmentIdentifierParsingError(_) => {
            advance_attr_buffer(path_attributes_buf)?
        }
    };
    Ok(buf)
}

impl From<BgpUpdateMessageParsingError> for UpdateMessageError {
    fn from(value: BgpUpdateMessageParsingError) -> Self {
        // For EoF errors we follow: RFC 4271 Error checking of an UPDATE message begins
        // by examining the path attributes. If the Withdrawn Routes Length or
        // Total Attribute Length is too large (i.e., if Withdrawn Routes Length
        // + Total Attribute Length + 23 exceeds the message Length), then the
        // Error Subcode MUST be set to Malformed Attribute List.
        match value {
            BgpUpdateMessageParsingError::Parse(err) => match err {
                ParseError::UnexpectedEof { .. } => UpdateMessageError::MalformedAttributeList {
                    value: vec![].into(),
                },
                ParseError::InvalidPaddingLength { .. } => UpdateMessageError::Unspecific {
                    value: vec![].into(),
                },
            },
            BgpUpdateMessageParsingError::PathAttributeError(attr_err) => {
                // TODO need to be refined in accordance with RFC 7606
                match attr_err {
                    PathAttributeParsingError::Parse(_) => {
                        UpdateMessageError::MalformedAttributeList {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::OriginError(err) => match err {
                        OriginParsingError::Parse(_) => {
                            UpdateMessageError::InvalidOriginAttribute {
                                value: vec![].into(),
                            }
                        }
                        OriginParsingError::InvalidOriginLength { .. } => {
                            UpdateMessageError::InvalidOriginAttribute {
                                value: vec![].into(),
                            }
                        }
                        OriginParsingError::UndefinedOrigin { .. } => {
                            UpdateMessageError::InvalidOriginAttribute {
                                value: vec![].into(),
                            }
                        }
                    },
                    PathAttributeParsingError::AsPathError(_) => {
                        UpdateMessageError::MalformedAsPath {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::NextHopError(_) => {
                        UpdateMessageError::InvalidNextHopAttribute {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::MultiExitDiscriminatorError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::LocalPreferenceError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::AtomicAggregateError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::AggregatorError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::CommunitiesError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::ExtendedCommunitiesError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::LargeCommunitiesError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::OriginatorError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::ClusterListError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::MpReachErrorError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::MpUnreachErrorError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::OnlyToCustomerError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::AigpError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::UnknownAttributeError(_) => {
                        UpdateMessageError::Unspecific {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::InvalidPathAttribute { .. } => {
                        UpdateMessageError::AttributeFlagsError {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::BgpLsError(_) => {
                        // TODO what to do here ?
                        UpdateMessageError::Unspecific {
                            value: vec![].into(),
                        }
                    }
                    PathAttributeParsingError::SegmentIdentifierParsingError(_) => {
                        UpdateMessageError::OptionalAttributeError {
                            value: vec![].into(),
                        }
                    }
                }
            }
            BgpUpdateMessageParsingError::Ipv4PrefixError(prefix_err) => {
                if matches!(prefix_err, Ipv4PrefixParsingError::Parse(_)) {
                    return UpdateMessageError::MalformedAttributeList {
                        value: vec![].into(),
                    };
                }
                UpdateMessageError::InvalidNetworkField {
                    value: vec![].into(),
                }
            }
            BgpUpdateMessageParsingError::InvalidIpv4UnicastNetwork { .. } => {
                // RFC 4271: If a prefix in the NLRI field is semantically incorrect (e.g., an
                // unexpected multicast IP address), an error SHOULD be logged locally, and the
                // prefix SHOULD be ignored.
                // If parser is configured to be strict and this error triggered, then report
                // Unspecific error
                UpdateMessageError::Unspecific {
                    value: vec![].into(),
                }
            }
        }
    }
}
