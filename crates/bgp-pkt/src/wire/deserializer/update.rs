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
    AS2_AGGREGATOR_LEN, AS4_AGGREGATOR_LEN, ATOMIC_AGGREGATE_LEN, AggregatorParsingError,
    AsPathParsingError, AtomicAggregateParsingError, CommunitiesParsingError,
    ExtendedCommunitiesIpv6ParsingError, ExtendedCommunitiesParsingError, LOCAL_PREFERENCE_LEN,
    LocalPreferenceParsingError, MULTI_EXIT_DISCRIMINATOR_LEN, MultiExitDiscriminatorParsingError,
    NEXT_HOP_LEN, NextHopParsingError, PathAttributeParsingError,
};
use ipnet::Ipv4Net;
use netgauze_iana::address_family::AddressType;

use crate::nlri::{Ipv4Unicast, Ipv4UnicastAddress};
use crate::notification::UpdateMessageError;
use crate::path_attribute::PathAttribute;
use crate::wire::deserializer::BgpParsingContext;
use crate::wire::deserializer::community::{
    CommunityParsingError, ExtendedCommunityIpv6ParsingError, ExtendedCommunityParsingError,
};
use crate::wire::deserializer::path_attribute::{
    EXTENDED_LENGTH_PATH_ATTRIBUTE_MASK, OriginParsingError,
};
use netgauze_parse_utils::common::Ipv4PrefixParsingError;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};
use serde::{Deserialize, Serialize};

/// BGP Open Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpUpdateMessageParsingError {
    #[error("BGP update message Parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("BGP update message error: {0}")]
    PathAttributeError(#[from] PathAttributeParsingError),

    #[error("BGP update message error: {0}")]
    Ipv4PrefixError(#[from] Ipv4PrefixParsingError),

    #[error(
        "BGP update message invalid IPv4 unicast network in NLRI at offset {offset}: {network}"
    )]
    InvalidIpv4UnicastNetwork { offset: usize, network: Ipv4Net },
}

#[inline]
fn parse_nlri<'a>(
    cur: &mut SliceReader<'a>,
    add_path: bool,
    is_update: bool,
    ctx: &mut BgpParsingContext,
) -> Result<Vec<Ipv4UnicastAddress>, BgpUpdateMessageParsingError> {
    let mut nlri_vec = Vec::new();
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
    Ok(nlri_vec)
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
        let mut path_attributes = Vec::new();
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
            path_attributes,
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
            return Err(BgpUpdateMessageParsingError::Parse(error.clone()));
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
                ParseError::UnexpectedEof { .. } => {
                    UpdateMessageError::MalformedAttributeList { value: vec![] }
                }
                ParseError::InvalidValue { .. } => UpdateMessageError::Unspecific { value: vec![] },
            },
            BgpUpdateMessageParsingError::PathAttributeError(attr_err) => {
                // TODO need to be refined in accordance with RFC 7606
                match attr_err {
                    PathAttributeParsingError::Parse(_) => {
                        UpdateMessageError::MalformedAttributeList { value: vec![] }
                    }
                    PathAttributeParsingError::OriginError(err) => match err {
                        OriginParsingError::Parse(_) => {
                            UpdateMessageError::InvalidOriginAttribute { value: vec![] }
                        }
                        OriginParsingError::InvalidOriginLength { .. } => {
                            UpdateMessageError::InvalidOriginAttribute { value: vec![] }
                        }
                        OriginParsingError::UndefinedOrigin { .. } => {
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
                    PathAttributeParsingError::InvalidPathAttribute { .. } => {
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
                if matches!(prefix_err, Ipv4PrefixParsingError::Parse(_)) {
                    return UpdateMessageError::MalformedAttributeList { value: vec![] };
                }
                UpdateMessageError::InvalidNetworkField { value: vec![] }
            }
            BgpUpdateMessageParsingError::InvalidIpv4UnicastNetwork { .. } => {
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
