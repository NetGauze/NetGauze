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

use crate::capabilities::*;
use crate::iana::{BgpCapabilityCode, BgpRoleValue};
use crate::wire::{
    BGP_ROLE_CAPABILITY_LENGTH, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH,
    EXTENDED_MESSAGE_CAPABILITY_LENGTH, EXTENDED_NEXT_HOP_ENCODING_LENGTH,
    FOUR_OCTET_AS_CAPABILITY_LENGTH, GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH,
    LONG_LIVED_GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH, MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH,
    ROUTE_REFRESH_CAPABILITY_LENGTH,
};
use netgauze_iana::address_family::{AddressFamily, AddressType, SubsequentAddressFamily};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFrom;
use serde::{Deserialize, Serialize};

/// BGP Capability Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpCapabilityParsingError {
    #[error("in BGP capability: {0}")]
    Parse(#[from] ParseError),

    #[error("unknown capability code {code} at byte offset {offset}")]
    UndefinedCapabilityCode { offset: usize, code: u8 },

    #[error(
        "invalid route refresh capability length {length} at byte offset {offset} (expected {})",
        ROUTE_REFRESH_CAPABILITY_LENGTH
    )]
    InvalidRouteRefreshLength { offset: usize, length: u8 },

    #[error(
        "invalid enhanced route refresh capability length {length} at byte offset {offset} (expected {})",
        ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH
    )]
    InvalidEnhancedRouteRefreshLength { offset: usize, length: u8 },

    #[error(
        "invalid extended message capability length {length} at byte offset {offset} (expected {})",
        EXTENDED_MESSAGE_CAPABILITY_LENGTH
    )]
    InvalidExtendedMessageLength { offset: usize, length: u8 },

    #[error("in four-octet AS capability: {0}")]
    FourOctetAsCapabilityError(#[from] FourOctetAsCapabilityParsingError),

    #[error("in multi-protocol extensions capability: {0}")]
    MultiProtocolExtensionsCapabilityError(#[from] MultiProtocolExtensionsCapabilityParsingError),

    #[error("in graceful restart capability: {0}")]
    GracefulRestartCapabilityError(#[from] GracefulRestartCapabilityParsingError),

    #[error("in long-lived graceful restart capability: {0}")]
    LongLivedGracefulRestartCapabilityError(#[from] LongLivedGracefulRestartCapabilityParsingError),

    #[error("in FQDN capability: {0}")]
    FqdnCapabilityError(#[from] FqdnCapabilityParsingError),

    #[error("in add-path capability: {0}")]
    AddPathCapabilityError(#[from] AddPathCapabilityParsingError),

    #[error("in extended next hop encoding capability: {0}")]
    ExtendedNextHopEncodingCapabilityError(#[from] ExtendedNextHopEncodingCapabilityParsingError),

    #[error("in multiple labels capability: {0}")]
    MultipleLabelError(#[from] MultipleLabelParsingError),

    #[error("in BGP role capability: {0}")]
    BgpRoleCapabilityError(#[from] BgpRoleCapabilityParsingError),
}

fn parse_experimental_capability(
    code: ExperimentalCapabilityCode,
    cur: &mut SliceReader<'_>,
) -> Result<BgpCapability, BgpCapabilityParsingError> {
    let len = cur.read_u8()?;
    let value = cur.read_bytes(len as usize)?;
    Ok(BgpCapability::Experimental(ExperimentalCapability::new(
        code,
        value.to_vec(),
    )))
}

fn parse_unrecognized_capability(
    code: u8,
    cur: &mut SliceReader<'_>,
) -> Result<BgpCapability, BgpCapabilityParsingError> {
    let len = cur.read_u8()?;
    let value = cur.read_bytes(len as usize)?;
    Ok(BgpCapability::Unrecognized(UnrecognizedCapability::new(
        code,
        value.to_vec(),
    )))
}

/// Helper function to read and check the capability exact length
#[inline(always)]
fn check_capability_length(cur: &mut SliceReader<'_>, expected: u8) -> Result<u8, u8> {
    let length = cur.peek_u8().map_err(|_| 0)?;
    if length == expected {
        cur.read_u8().map_err(|_| 0)?;
        Ok(length)
    } else {
        Err(length)
    }
}

fn parse_route_refresh_capability(
    cur: &mut SliceReader<'_>,
) -> Result<BgpCapability, BgpCapabilityParsingError> {
    check_capability_length(cur, ROUTE_REFRESH_CAPABILITY_LENGTH).map_err(|length| {
        BgpCapabilityParsingError::InvalidRouteRefreshLength {
            offset: cur.offset(),
            length,
        }
    })?;
    Ok(BgpCapability::RouteRefresh)
}

fn parse_enhanced_route_refresh_capability(
    cur: &mut SliceReader<'_>,
) -> Result<BgpCapability, BgpCapabilityParsingError> {
    check_capability_length(cur, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH).map_err(|length| {
        BgpCapabilityParsingError::InvalidEnhancedRouteRefreshLength {
            offset: cur.offset(),
            length,
        }
    })?;
    Ok(BgpCapability::EnhancedRouteRefresh)
}

impl<'a> ParseFrom<'a> for BgpCapability {
    type Error = BgpCapabilityParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let parsed = BgpCapabilityCode::try_from(cur.read_u8()?);
        match parsed {
            Ok(code) => match code {
                BgpCapabilityCode::MultiProtocolExtensions => {
                    let cap = MultiProtocolExtensionsCapability::parse(cur)?;
                    Ok(BgpCapability::MultiProtocolExtensions(cap))
                }
                BgpCapabilityCode::RouteRefreshCapability => parse_route_refresh_capability(cur),
                BgpCapabilityCode::OutboundRouteFilteringCapability => {
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::ExtendedNextHopEncoding => {
                    let cap = ExtendedNextHopEncodingCapability::parse(cur)?;
                    Ok(BgpCapability::ExtendedNextHopEncoding(cap))
                }
                BgpCapabilityCode::CiscoRouteRefresh => {
                    check_capability_length(cur, ROUTE_REFRESH_CAPABILITY_LENGTH).map_err(
                        |length| BgpCapabilityParsingError::InvalidRouteRefreshLength {
                            offset: cur.offset(),
                            length,
                        },
                    )?;
                    Ok(BgpCapability::CiscoRouteRefresh)
                }
                BgpCapabilityCode::BgpExtendedMessage => {
                    check_capability_length(cur, EXTENDED_MESSAGE_CAPABILITY_LENGTH).map_err(
                        |length| BgpCapabilityParsingError::InvalidExtendedMessageLength {
                            offset: cur.offset(),
                            length,
                        },
                    )?;
                    Ok(BgpCapability::ExtendedMessage)
                }
                BgpCapabilityCode::BgpSecCapability => {
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::MultipleLabelsCapability => {
                    let mut cap = Vec::with_capacity(cur.remaining() / 4);
                    while !cur.is_empty() {
                        let v = MultipleLabel::parse(cur)?;
                        cap.push(v);
                    }
                    Ok(BgpCapability::MultipleLabels(cap.into()))
                }
                BgpCapabilityCode::BgpRole => {
                    let cap = BgpRoleCapability::parse(cur)?;
                    Ok(BgpCapability::BgpRole(cap))
                }
                BgpCapabilityCode::GracefulRestartCapability => {
                    let cap = GracefulRestartCapability::parse(cur)?;
                    Ok(BgpCapability::GracefulRestartCapability(cap))
                }
                BgpCapabilityCode::FourOctetAs => {
                    let cap = FourOctetAsCapability::parse(cur)?;
                    Ok(BgpCapability::FourOctetAs(cap))
                }
                BgpCapabilityCode::SupportForDynamicCapability => {
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::MultiSessionBgpCapability => {
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::AddPathCapability => {
                    let cap = AddPathCapability::parse(cur)?;
                    Ok(BgpCapability::AddPath(cap))
                }
                BgpCapabilityCode::EnhancedRouteRefresh => {
                    parse_enhanced_route_refresh_capability(cur)
                }
                BgpCapabilityCode::LongLivedGracefulRestartLLGRCapability => {
                    let cap = LongLivedGracefulRestartCapability::parse(cur)?;
                    Ok(BgpCapability::LongLivedGracefulRestart(cap))
                }
                BgpCapabilityCode::RoutingPolicyDistribution => {
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::FQDN => {
                    let cap = FqdnCapability::parse(cur)?;
                    Ok(BgpCapability::Fqdn(cap))
                }
                BgpCapabilityCode::Experimental239 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental239, cur)
                }
                BgpCapabilityCode::Experimental240 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental240, cur)
                }
                BgpCapabilityCode::Experimental241 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental241, cur)
                }
                BgpCapabilityCode::Experimental242 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental242, cur)
                }
                BgpCapabilityCode::Experimental243 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental243, cur)
                }
                BgpCapabilityCode::Experimental244 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental244, cur)
                }
                BgpCapabilityCode::Experimental245 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental245, cur)
                }
                BgpCapabilityCode::Experimental246 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental246, cur)
                }
                BgpCapabilityCode::Experimental247 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental247, cur)
                }
                BgpCapabilityCode::Experimental248 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental248, cur)
                }
                BgpCapabilityCode::Experimental249 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental249, cur)
                }
                BgpCapabilityCode::Experimental250 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental250, cur)
                }
                BgpCapabilityCode::Experimental251 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental251, cur)
                }
                BgpCapabilityCode::Experimental252 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental252, cur)
                }
                BgpCapabilityCode::Experimental253 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental253, cur)
                }
                BgpCapabilityCode::Experimental254 => {
                    parse_experimental_capability(ExperimentalCapabilityCode::Experimental254, cur)
                }
            },
            Err(err) => parse_unrecognized_capability(err.0, cur),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum FourOctetAsCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "invalid length {length} at byte offset {offset} (expected {})",
        FOUR_OCTET_AS_CAPABILITY_LENGTH
    )]
    InvalidLength { offset: usize, length: u8 },
}

impl<'a> ParseFrom<'a> for FourOctetAsCapability {
    type Error = FourOctetAsCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        check_capability_length(cur, FOUR_OCTET_AS_CAPABILITY_LENGTH).map_err(|length| {
            FourOctetAsCapabilityParsingError::InvalidLength {
                offset: cur.offset(),
                length,
            }
        })?;
        let asn4 = cur.read_u32_be()?;
        Ok(FourOctetAsCapability::new(asn4))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MultiProtocolExtensionsCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "invalid length {length} at byte offset {offset} (expected {})",
        MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH
    )]
    InvalidLength { offset: usize, length: u8 },

    #[error("unknown address family {afi} at byte offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("unknown subsequent address family {safi} at byte offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error("unsupported address family pair (afi {afi}, safi {safi}) at byte offset {offset}")]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

impl<'a> ParseFrom<'a> for MultiProtocolExtensionsCapability {
    type Error = MultiProtocolExtensionsCapabilityParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        check_capability_length(cur, MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH).map_err(
            |length| MultiProtocolExtensionsCapabilityParsingError::InvalidLength {
                offset: cur.offset(),
                length,
            },
        )?;
        let afi = AddressFamily::try_from(cur.read_u16_be()?).map_err(|err| {
            MultiProtocolExtensionsCapabilityParsingError::UndefinedAddressFamily {
                offset: cur.offset() - 2,
                afi: err.0,
            }
        })?;
        let _ = cur.read_u8()?;
        let safi = SubsequentAddressFamily::try_from(cur.read_u8()?).map_err(|err| {
            MultiProtocolExtensionsCapabilityParsingError::UndefinedSubsequentAddressFamily {
                offset: cur.offset() - 1,
                safi: err.0,
            }
        })?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(
                    MultiProtocolExtensionsCapabilityParsingError::AddressTypeError {
                        // AFI (2 bytes), reserved (1 byte), and SAFI (1 byte) are the last 4 read
                        offset: cur.offset() - 4,
                        afi: err.address_family().into(),
                        safi: err.subsequent_address_family().into(),
                    },
                );
            }
        };

        Ok(MultiProtocolExtensionsCapability::new(address_type))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum GracefulRestartCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown address family {afi} at byte offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("unknown subsequent address family {safi} at byte offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error("unsupported address family pair (afi {afi}, safi {safi}) at byte offset {offset}")]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

impl<'a> ParseFrom<'a> for GracefulRestartCapability {
    type Error = GracefulRestartCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let len = cur.read_u8()?;
        let mut params_buf = cur.take_slice(len as usize)?;
        let header = params_buf.read_u16_be()?;
        let restart = header & 0x8000 == 0x8000;
        let graceful_notification = header & 0x4000 == 0x4000;
        let time = header & 0x0fff;
        let mut address_families = Vec::with_capacity(params_buf.remaining() / 4);
        while !params_buf.is_empty() {
            let v = GracefulRestartAddressFamily::parse(&mut params_buf)?;
            address_families.push(v);
        }

        Ok(GracefulRestartCapability::new(
            restart,
            graceful_notification,
            time,
            address_families,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LongLivedGracefulRestartCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "invalid long-lived graceful restart capability length {length} at byte offset {offset} (must be a multiple of {})",
        LONG_LIVED_GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH
    )]
    InvalidLength { offset: usize, length: u8 },

    #[error("unknown address family {afi} at byte offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("unknown subsequent address family {safi} at byte offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error("unsupported address family pair (afi {afi}, safi {safi}) at byte offset {offset}")]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum FqdnCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid UTF-8 in FQDN {field} at byte offset {offset}: {error}")]
    InvalidUtf8 {
        offset: usize,
        field: Box<str>,
        error: Box<str>,
    },
}

impl<'a> ParseFrom<'a> for FqdnCapability {
    type Error = FqdnCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let len = cur.read_u8()?;
        let mut value_buf = cur.take_slice(len as usize)?;

        let mut read_name = |field: &str| -> Result<Box<str>, FqdnCapabilityParsingError> {
            let name_len = value_buf.read_u8()?;
            let offset = value_buf.offset();
            let bytes = value_buf.read_bytes(name_len as usize)?;
            String::from_utf8(bytes.to_vec())
                .map_err(|error| FqdnCapabilityParsingError::InvalidUtf8 {
                    offset,
                    field: field.to_string().into_boxed_str(),
                    error: error.to_string().into_boxed_str(),
                })
                .map(|x| x.into_boxed_str())
        };

        let hostname = read_name("hostname")?;
        // Speakers with no domain configured still send the length field, as a
        // zero-length name, so this read is not conditional.
        let domain_name = read_name("domain name")?;

        Ok(FqdnCapability::new(hostname, domain_name))
    }
}

impl<'a> ParseFrom<'a> for LongLivedGracefulRestartCapability {
    type Error = LongLivedGracefulRestartCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let len = cur.read_u8()?;
        // The value is a whole number of <AFI, SAFI, Flags, Stale Time> tuples;
        // anything else means the capability is malformed rather than merely
        // carrying a family we do not know about.
        if len % LONG_LIVED_GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH != 0 {
            return Err(
                LongLivedGracefulRestartCapabilityParsingError::InvalidLength {
                    offset,
                    length: len,
                },
            );
        }
        let mut params_buf = cur.take_slice(len as usize)?;
        let mut address_families = Vec::with_capacity(
            params_buf.remaining() / LONG_LIVED_GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH as usize,
        );
        while !params_buf.is_empty() {
            let v = LongLivedGracefulRestartAddressFamily::parse(&mut params_buf)?;
            address_families.push(v);
        }
        Ok(LongLivedGracefulRestartCapability::new(address_families))
    }
}

impl<'a> ParseFrom<'a> for LongLivedGracefulRestartAddressFamily {
    type Error = LongLivedGracefulRestartCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let mut buf = cur.take_slice(LONG_LIVED_GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH as usize)?;

        let afi = AddressFamily::try_from(buf.read_u16_be()?).map_err(|err| {
            LongLivedGracefulRestartCapabilityParsingError::UndefinedAddressFamily {
                offset: buf.offset() - 2,
                afi: err.0,
            }
        })?;
        let safi = SubsequentAddressFamily::try_from(buf.read_u8()?).map_err(|err| {
            LongLivedGracefulRestartCapabilityParsingError::UndefinedSubsequentAddressFamily {
                offset: buf.offset() - 1,
                safi: err.0,
            }
        })?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(
                    LongLivedGracefulRestartCapabilityParsingError::AddressTypeError {
                        // AFI (2 bytes) and SAFI (1 byte) are the last 3 read
                        offset: buf.offset() - 3,
                        afi: err.address_family().into(),
                        safi: err.subsequent_address_family().into(),
                    },
                );
            }
        };

        let flags = buf.read_u8()?;
        // Only the most significant `F` bit is defined; the remaining bits are
        // reserved and MUST be ignored by the receiver (RFC 9494).
        let forwarding_state = flags & 0x80 == 0x80;

        // Long-lived Stale Time is 24 bits
        let stale_time_bytes: [u8; 3] = buf.read_array()?;
        let stale_time = u32::from_be_bytes([
            0,
            stale_time_bytes[0],
            stale_time_bytes[1],
            stale_time_bytes[2],
        ]);

        Ok(LongLivedGracefulRestartAddressFamily::new(
            forwarding_state,
            address_type,
            stale_time,
        ))
    }
}

impl<'a> ParseFrom<'a> for GracefulRestartAddressFamily {
    type Error = GracefulRestartCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let mut ehe_buf = cur.take_slice(GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH as usize)?;

        let afi = AddressFamily::try_from(ehe_buf.read_u16_be()?).map_err(|err| {
            GracefulRestartCapabilityParsingError::UndefinedAddressFamily {
                offset: ehe_buf.offset() - 2,
                afi: err.0,
            }
        })?;
        let safi = SubsequentAddressFamily::try_from(ehe_buf.read_u8()?).map_err(|err| {
            GracefulRestartCapabilityParsingError::UndefinedSubsequentAddressFamily {
                offset: ehe_buf.offset() - 1,
                safi: err.0,
            }
        })?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(GracefulRestartCapabilityParsingError::AddressTypeError {
                    offset: ehe_buf.offset() - 3,
                    afi: err.address_family().into(),
                    safi: err.subsequent_address_family().into(),
                });
            }
        };

        let flags = ehe_buf.read_u8()?;
        let forwarding_state = flags & 0x80 == 0x80;

        Ok(GracefulRestartAddressFamily::new(
            forwarding_state,
            address_type,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum AddPathCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown address family {afi} at byte offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("unknown subsequent address family {safi} at byte offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error("unsupported address family pair (afi {afi}, safi {safi}) at byte offset {offset}")]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },

    #[error("invalid send/receive value {value} at byte offset {offset} (must be 0–3)")]
    InvalidAddPathSendReceiveValue { offset: usize, value: u8 },
}

impl<'a> ParseFrom<'a> for AddPathCapability {
    type Error = AddPathCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let length = cur.read_u8()?;
        let mut params_buf = cur.take_slice(length as usize)?;
        let mut address_families = Vec::with_capacity(params_buf.remaining() / 4);
        while !params_buf.is_empty() {
            let address_family = AddPathAddressFamily::parse(&mut params_buf)?;
            address_families.push(address_family);
        }
        Ok(AddPathCapability::new(address_families))
    }
}

impl<'a> ParseFrom<'a> for AddPathAddressFamily {
    type Error = AddPathCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let afi = AddressFamily::try_from(cur.read_u16_be()?).map_err(|err| {
            AddPathCapabilityParsingError::UndefinedAddressFamily {
                offset: cur.offset() - 2, // AFI is the last 2 bytes read
                afi: err.0,
            }
        })?;
        let safi = SubsequentAddressFamily::try_from(cur.read_u8()?).map_err(|err| {
            AddPathCapabilityParsingError::UndefinedSubsequentAddressFamily {
                offset: cur.offset() - 1, // SAFI is the last byte read
                safi: err.0,
            }
        })?;

        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(AddPathCapabilityParsingError::AddressTypeError {
                    offset: cur.offset() - 3,
                    afi: err.address_family().into(),
                    safi: err.subsequent_address_family().into(),
                });
            }
        };

        let send_receive = cur.read_u8()?;
        let (receive, send) = if send_receive > 0x03u8 {
            return Err(
                AddPathCapabilityParsingError::InvalidAddPathSendReceiveValue {
                    offset: cur.offset() - 1,
                    value: send_receive,
                },
            );
        } else {
            (
                send_receive & 0x01u8 == 0x01u8,
                send_receive & 0x02u8 == 0x02u8,
            )
        };

        Ok(AddPathAddressFamily::new(address_type, send, receive))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ExtendedNextHopEncodingCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown address family {afi} at byte offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("unknown subsequent address family {safi} at byte offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error("unsupported address family pair (afi {afi}, safi {safi}) at byte offset {offset}")]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

impl<'a> ParseFrom<'a> for ExtendedNextHopEncodingCapability {
    type Error = ExtendedNextHopEncodingCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let len = cur.read_u8()?;
        let mut encoding_buf = cur.take_slice(len as usize)?;
        let mut encodings = Vec::with_capacity(encoding_buf.remaining() / 6);
        while !encoding_buf.is_empty() {
            let encoding = ExtendedNextHopEncoding::parse(&mut encoding_buf)?;
            encodings.push(encoding);
        }
        Ok(ExtendedNextHopEncodingCapability::new(encodings))
    }
}

impl<'a> ParseFrom<'a> for ExtendedNextHopEncoding {
    type Error = ExtendedNextHopEncodingCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let mut ehe_buf = cur.take_slice(EXTENDED_NEXT_HOP_ENCODING_LENGTH as usize)?;
        let nlri_afi = AddressFamily::try_from(ehe_buf.read_u16_be()?).map_err(|err| {
            ExtendedNextHopEncodingCapabilityParsingError::UndefinedAddressFamily {
                offset: ehe_buf.offset() - 2,
                afi: err.0,
            }
        })?;
        let nlri_safi =
            SubsequentAddressFamily::try_from(ehe_buf.read_u16_be()? as u8).map_err(|err| {
                ExtendedNextHopEncodingCapabilityParsingError::UndefinedSubsequentAddressFamily {
                    // SAFI is carried in the last 2 bytes read in this encoding
                    offset: ehe_buf.offset() - 2,
                    safi: err.0,
                }
            })?;
        let address_type = match AddressType::from_afi_safi(nlri_afi, nlri_safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(
                    ExtendedNextHopEncodingCapabilityParsingError::AddressTypeError {
                        // AFI (2 bytes) and SAFI (2 bytes) are the last 4 bytes read
                        offset: ehe_buf.offset() - 4,
                        afi: err.address_family().into(),
                        safi: err.subsequent_address_family().into(),
                    },
                );
            }
        };

        let next_hop_afi = AddressFamily::try_from(ehe_buf.read_u16_be()?).map_err(|err| {
            ExtendedNextHopEncodingCapabilityParsingError::UndefinedAddressFamily {
                offset: ehe_buf.offset() - 2, // AFI is the last 2 bytes read
                afi: err.0,
            }
        })?;

        Ok(ExtendedNextHopEncoding::new(address_type, next_hop_afi))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MultipleLabelParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("unknown address family {afi} at byte offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("unknown subsequent address family {safi} at byte offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error("unsupported address family pair (afi {afi}, safi {safi}) at byte offset {offset}")]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

impl<'a> ParseFrom<'a> for MultipleLabel {
    type Error = MultipleLabelParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let afi = AddressFamily::try_from(cur.read_u16_be()?).map_err(|err| {
            MultipleLabelParsingError::UndefinedAddressFamily { offset, afi: err.0 }
        })?;
        let safi = SubsequentAddressFamily::try_from(cur.read_u8()?).map_err(|err| {
            MultipleLabelParsingError::UndefinedSubsequentAddressFamily {
                offset: cur.offset() - 1,
                safi: err.0,
            }
        })?;
        let address_type = match AddressType::from_afi_safi(afi, safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(MultipleLabelParsingError::AddressTypeError {
                    offset,
                    afi: err.address_family().into(),
                    safi: err.subsequent_address_family().into(),
                });
            }
        };
        let count = cur.read_u8()?;
        Ok(MultipleLabel::new(address_type, count))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpRoleCapabilityParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "invalid length {length} at byte offset {offset} (expected {})",
        BGP_ROLE_CAPABILITY_LENGTH
    )]
    InvalidLength { offset: usize, length: u8 },

    #[error("unknown BGP role value {code} at byte offset {offset}")]
    UndefinedBgpRoleValue { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for BgpRoleCapability {
    type Error = BgpRoleCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        check_capability_length(cur, BGP_ROLE_CAPABILITY_LENGTH).map_err(|length| {
            BgpRoleCapabilityParsingError::InvalidLength {
                offset: cur.offset(),
                length,
            }
        })?;
        let code = cur.peek_u8()?;
        let role = BgpRoleValue::try_from(code).map_err(|_| {
            BgpRoleCapabilityParsingError::UndefinedBgpRoleValue {
                offset: cur.offset(),
                code,
            }
        })?;
        let _code = cur.read_u8()?;
        Ok(BgpRoleCapability::new(role))
    }
}
