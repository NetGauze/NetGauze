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

use crate::BgpOpenMessage;
use crate::capabilities::BgpCapability;
use crate::iana::BgpOpenMessageParameterType;
use crate::notification::OpenMessageError;
use crate::open::{BGP_VERSION, BgpOpenMessageParameter};
use crate::wire::deserializer;
use crate::wire::deserializer::BgpParsingContext;
use crate::wire::deserializer::capabilities::BgpCapabilityParsingError;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// BGP Open Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpOpenMessageParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "unsupported BGP version {version} at byte offset {offset} (expected {})",
        BGP_VERSION
    )]
    UnsupportedVersionNumber { offset: usize, version: u8 },

    #[error("unacceptable hold time {time} at byte offset {offset} (must be 0 or >= 3 seconds)")]
    UnacceptableHoldTime { offset: usize, time: u16 },

    /// RFC 4271 specifies that BGP ID must be a valid unicast IP host address.
    #[error("invalid BGP identifier {bgp_id} at byte offset {offset} (must be a unicast address)")]
    InvalidBgpId { offset: usize, bgp_id: Ipv4Addr },

    #[error("in open parameter: {0}")]
    ParameterError(#[from] BgpParameterParsingError),
}

/// BGP Open Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpParameterParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown parameter type {code} at byte offset {offset}")]
    UndefinedParameterType { offset: usize, code: u8 },

    #[error("in capability: {0}")]
    CapabilityError(#[from] BgpCapabilityParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for BgpOpenMessage {
    type Error = BgpOpenMessageParsingError;

    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BgpParsingContext) -> Result<Self, Self::Error> {
        // Check the version if valid without updating the offset
        let version = cur.peek_u8()?;
        if version != BGP_VERSION {
            return Err(BgpOpenMessageParsingError::UnsupportedVersionNumber {
                offset: cur.offset(),
                version,
            });
        }
        // read the version since it's now validated to be correct
        let _ = cur.read_u8()?;

        let my_as = cur.read_u16_be()?;
        let hold_time = cur.peek_u16_be()?;
        // RFC 4271: If the Hold Time field of the OPEN message is unacceptable, then
        // the Error Subcode MUST be set to Unacceptable Hold Time. An implementation
        // MUST reject Hold Time values of one or two seconds. An implementation MAY
        // reject any proposed Hold Time.
        if hold_time == 1 || hold_time == 2 {
            return Err(BgpOpenMessageParsingError::UnacceptableHoldTime {
                offset: cur.offset() - 2,
                time: hold_time,
            });
        }
        // read hold_time
        let _ = cur.read_u16_be()?;

        let bgp_id = cur.peek_u32_be()?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        // RFC 4271: If the BGP Identifier field of the OPEN message is syntactically
        // incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
        // Syntactic correctness means that the BGP Identifier field represents
        // a valid unicast IP host address. NOTE: not all BGP implementation
        // check for syntactic correctness
        if bgp_id.is_broadcast() || bgp_id.is_multicast() || bgp_id.is_unspecified() {
            return Err(BgpOpenMessageParsingError::InvalidBgpId {
                offset: cur.offset(),
                bgp_id,
            });
        }
        // read the BGP ID after checked to valid
        let _ = cur.read_u32_be()?;
        let len = cur.read_u8()?;
        // shortcut for speed when there are no parameters
        if len == 0 {
            return Ok(BgpOpenMessage::new(my_as, hold_time, bgp_id, vec![]));
        }
        let mut params_buf = cur.take_slice(len as usize)?;
        let mut params = Vec::with_capacity(deserializer::count_t8_l8_tlvs(params_buf));
        while !params_buf.is_empty() {
            let element = BgpOpenMessageParameter::parse(&mut params_buf, ctx)?;
            params.push(element);
        }
        Ok(BgpOpenMessage::new(
            my_as,
            hold_time,
            bgp_id,
            params.into_boxed_slice(),
        ))
    }
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for BgpOpenMessageParameter {
    type Error = BgpParameterParsingError;
    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BgpParsingContext) -> Result<Self, Self::Error> {
        let code = cur.peek_u8()?;
        let param_type = BgpOpenMessageParameterType::try_from(code).map_err(|err| {
            BgpParameterParsingError::UndefinedParameterType {
                offset: cur.offset(),
                code: err.0,
            }
        })?;

        match param_type {
            BgpOpenMessageParameterType::Capability => {
                let _ = cur.read_u8()?;
                parse_capability_param(cur, ctx)
            }
            BgpOpenMessageParameterType::ExtendedLength => {
                Err(BgpParameterParsingError::UndefinedParameterType {
                    offset: cur.offset(),
                    code: param_type.into(),
                })
            }
        }
    }
}

#[inline]
fn parse_capability_param<'a>(
    cur: &mut SliceReader<'a>,
    ctx: &mut BgpParsingContext,
) -> Result<BgpOpenMessageParameter, BgpParameterParsingError> {
    let len = cur.read_u8()?;
    let mut capabilities_buf = cur.take_slice(len as usize)?;
    let mut capabilities = Vec::with_capacity(deserializer::count_t8_l8_tlvs(capabilities_buf));
    while !capabilities_buf.is_empty() {
        match BgpCapability::parse(&mut capabilities_buf) {
            Ok(capability) => {
                capabilities.push(capability);
            }
            Err(err) => {
                if !ctx.fail_on_capability_error {
                    // RFC 5492 defines that a BGP speaker should ignore capabilities it
                    // does not understand and not report any error.
                    // It will only report a notification if the capability is
                    // understood but not supported by the speaker
                    ctx.parsing_errors.capability_errors.push(err);
                } else {
                    return Err(BgpParameterParsingError::CapabilityError(err));
                }
            }
        }
    }
    Ok(BgpOpenMessageParameter::Capabilities(
        capabilities.into_boxed_slice(),
    ))
}

impl From<BgpParameterParsingError> for OpenMessageError {
    fn from(param_err: BgpParameterParsingError) -> Self {
        match param_err {
            // RFC 4271: If one of the Optional Parameters in the OPEN message is recognized, but is
            // malformed, then the Error Subcode MUST be set to 0 (Unspecific)
            BgpParameterParsingError::Parse(_) => OpenMessageError::Unspecific {
                value: vec![].into(),
            },
            // RFC 4271: If one of the Optional Parameters in the OPEN message is not recognized,
            // then the Error Subcode MUST be set to Unsupported Optional Parameters.
            BgpParameterParsingError::UndefinedParameterType { offset: _, code } => {
                OpenMessageError::UnsupportedOptionalParameter {
                    value: vec![code].into(),
                }
            }
            // RFC 5492 defines that a BGP speaker should ignore capabilities it
            // does not understand and not report any error.
            // It will only report a notification if the capability is
            // understood but not supported by the speaker. If an error is reported anyways by the
            // parser we set the notif to Unspecific
            BgpParameterParsingError::CapabilityError(_) => OpenMessageError::Unspecific {
                value: vec![].into(),
            },
        }
    }
}

impl From<BgpOpenMessageParsingError> for OpenMessageError {
    fn from(error: BgpOpenMessageParsingError) -> Self {
        match error {
            BgpOpenMessageParsingError::Parse(_) => OpenMessageError::Unspecific {
                value: vec![].into(),
            },
            // RFC 4271: If the version number in the Version field of the received OPEN message is
            // not supported, then the Error Subcode MUST be set to Unsupported Version Number.
            // The Data field is a 2-octet unsigned integer, which indicates the largest,
            // locally-supported version number less than the version the remote BGP peer bid (as
            // indicated in the received OPEN message), or if the smallest, locally-supported
            // version number is greater than the version the remote BGP peer bid, then the
            // smallest, locally-supported version number.
            BgpOpenMessageParsingError::UnsupportedVersionNumber { .. } => {
                OpenMessageError::UnsupportedVersionNumber {
                    value: (BGP_VERSION as u16).to_be_bytes().into(),
                }
            }
            BgpOpenMessageParsingError::UnacceptableHoldTime { offset: _, time } => {
                OpenMessageError::UnacceptableHoldTime {
                    value: time.to_be_bytes().into(),
                }
            }
            // RFC 4271: If the BGP Identifier field of the OPEN message is syntactically incorrect,
            // then the Error Subcode MUST be set to Bad BGP Identifier. Syntactic correctness means
            // that the BGP Identifier field represents a valid unicast IP host address.
            // NOTE: not all BGP implementation check for syntactic correctness
            BgpOpenMessageParsingError::InvalidBgpId { bgp_id, .. } => {
                OpenMessageError::BadBgpIdentifier {
                    value: bgp_id.to_bits().to_be_bytes().into(),
                }
            }
            BgpOpenMessageParsingError::ParameterError(param_error) => param_error.into(),
        }
    }
}
