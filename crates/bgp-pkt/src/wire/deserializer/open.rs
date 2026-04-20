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
    #[error("BGP open message parsing Error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("BGP open unsupported BGP version number at offset {offset} with version {version}")]
    UnsupportedVersionNumber { offset: usize, version: u8 },

    #[error("BGP open unacceptable hold time at offset {offset} with hold time {time}")]
    UnacceptableHoldTime { offset: usize, time: u16 },

    /// RFC 4271 specifies that BGP ID must be a valid unicast IP host address.
    #[error("BGP open invalid BGP ID at offset {offset} with BGP ID {bgp_id}")]
    InvalidBgpId { offset: usize, bgp_id: u32 },

    #[error("BGP open error: {0}")]
    ParameterError(#[from] BgpParameterParsingError),
}

/// BGP Open Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpParameterParsingError {
    #[error("BGP open parameter parsing Error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("BGP open undefined parameter type at offset {offset} with code {code}")]
    UndefinedParameterType { offset: usize, code: u8 },

    #[error("BGP open parameter error: {0}")]
    CapabilityError(#[from] BgpCapabilityParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for BgpOpenMessage {
    type Error = BgpOpenMessageParsingError;
    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BgpParsingContext) -> Result<Self, Self::Error> {
        let version = cur.read_u8()?;
        if version != BGP_VERSION {
            return Err(BgpOpenMessageParsingError::UnsupportedVersionNumber {
                offset: cur.offset() - 1,
                version,
            });
        }
        let my_as = cur.read_u16_be()?;
        let hold_time = cur.read_u16_be()?;
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
        let bgp_id = cur.read_u32_be()?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        // RFC 4271: If the BGP Identifier field of the OPEN message is syntactically
        // incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
        // Syntactic correctness means that the BGP Identifier field represents
        // a valid unicast IP host address. NOTE: not all BGP implementation
        // check for syntactic correctness
        if bgp_id.is_broadcast() || bgp_id.is_multicast() || bgp_id.is_unspecified() {
            return Err(BgpOpenMessageParsingError::InvalidBgpId {
                offset: cur.offset() - 4,
                bgp_id: bgp_id.into(),
            });
        }
        let len = cur.read_u8()?;
        let mut params_buf = cur.take_slice(len as usize)?;
        let mut params = Vec::new();
        while !params_buf.is_empty() {
            let element = BgpOpenMessageParameter::parse(&mut params_buf, ctx)?;
            params.push(element);
        }
        Ok(BgpOpenMessage::new(my_as, hold_time, bgp_id, params))
    }
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for BgpOpenMessageParameter {
    type Error = BgpParameterParsingError;
    fn parse(cur: &mut SliceReader<'a>, ctx: &mut BgpParsingContext) -> Result<Self, Self::Error> {
        let param_type = BgpOpenMessageParameterType::try_from(cur.read_u8()?).map_err(|err| {
            BgpParameterParsingError::UndefinedParameterType {
                offset: cur.offset() - 1,
                code: err.0,
            }
        })?;
        match param_type {
            BgpOpenMessageParameterType::Capability => parse_capability_param(cur, ctx),
            BgpOpenMessageParameterType::ExtendedLength => {
                Err(BgpParameterParsingError::UndefinedParameterType {
                    offset: cur.offset() - 1,
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
    let mut capabilities = Vec::new();
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
    Ok(BgpOpenMessageParameter::Capabilities(capabilities))
}

impl From<BgpParameterParsingError> for OpenMessageError {
    fn from(param_err: BgpParameterParsingError) -> Self {
        match param_err {
            // RFC 4271: If one of the Optional Parameters in the OPEN message is recognized, but is
            // malformed, then the Error Subcode MUST be set to 0 (Unspecific)
            BgpParameterParsingError::Parse(_) => OpenMessageError::Unspecific { value: vec![] },
            // RFC 4271: If one of the Optional Parameters in the OPEN message is not recognized,
            // then the Error Subcode MUST be set to Unsupported Optional Parameters.
            BgpParameterParsingError::UndefinedParameterType { offset: _, code } => {
                OpenMessageError::UnsupportedOptionalParameter { value: vec![code] }
            }
            // RFC 5492 defines that a BGP speaker should ignore capabilities it
            // does not understand and not report any error.
            // It will only report a notification if the capability is
            // understood but not supported by the speaker. If an error is reported anyways by the
            // parser we set the notif to Unspecific
            BgpParameterParsingError::CapabilityError(_) => {
                OpenMessageError::Unspecific { value: vec![] }
            }
        }
    }
}

impl From<BgpOpenMessageParsingError> for OpenMessageError {
    fn from(error: BgpOpenMessageParsingError) -> Self {
        match error {
            BgpOpenMessageParsingError::Parse(_) => OpenMessageError::Unspecific { value: vec![] },
            // RFC 4271: If the version number in the Version field of the received OPEN message is
            // not supported, then the Error Subcode MUST be set to Unsupported Version Number.
            // The Data field is a 2-octet unsigned integer, which indicates the largest,
            // locally-supported version number less than the version the remote BGP peer bid (as
            // indicated in the received OPEN message), or if the smallest, locally-supported
            // version number is greater than the version the remote BGP peer bid, then the
            // smallest, locally-supported version number.
            BgpOpenMessageParsingError::UnsupportedVersionNumber { .. } => {
                OpenMessageError::UnsupportedVersionNumber {
                    value: (BGP_VERSION as u16).to_be_bytes().to_vec(),
                }
            }
            BgpOpenMessageParsingError::UnacceptableHoldTime { offset: _, time } => {
                OpenMessageError::UnacceptableHoldTime {
                    value: time.to_be_bytes().to_vec(),
                }
            }
            // RFC 4271: If the BGP Identifier field of the OPEN message is syntactically incorrect,
            // then the Error Subcode MUST be set to Bad BGP Identifier. Syntactic correctness means
            // that the BGP Identifier field represents a valid unicast IP host address.
            // NOTE: not all BGP implementation check for syntactic correctness
            BgpOpenMessageParsingError::InvalidBgpId { bgp_id, .. } => {
                OpenMessageError::BadBgpIdentifier {
                    value: bgp_id.to_be_bytes().to_vec(),
                }
            }
            BgpOpenMessageParsingError::ParameterError(param_error) => param_error.into(),
        }
    }
}
