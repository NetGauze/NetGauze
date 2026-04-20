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
    MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH, ROUTE_REFRESH_CAPABILITY_LENGTH,
};
use netgauze_iana::address_family::{AddressFamily, AddressType, SubsequentAddressFamily};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFrom;
use serde::{Deserialize, Serialize};

/// BGP Capability Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpCapabilityParsingError {
    #[error("BGP capability parsing Error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("BGP capability undefined capability code at offset {offset} with code {code}")]
    UndefinedCapabilityCode { offset: usize, code: u8 },

    #[error(
        "BGP capability invalid route refresh capability length at offset {offset} with length {length}"
    )]
    InvalidRouteRefreshLength { offset: usize, length: u8 },

    #[error(
        "BGP capability invalid enhanced route refresh capability length at offset {offset} with length {length}"
    )]
    InvalidEnhancedRouteRefreshLength { offset: usize, length: u8 },

    #[error(
        "BGP capability invalid extended message capability length at offset {offset} with length {length}"
    )]
    InvalidExtendedMessageLength { offset: usize, length: u8 },

    #[error("BGP capability error: {0}")]
    FourOctetAsCapabilityError(#[from] FourOctetAsCapabilityParsingError),

    #[error("BGP capability error: {0}")]
    MultiProtocolExtensionsCapabilityError(#[from] MultiProtocolExtensionsCapabilityParsingError),

    #[error("BGP capability error: {0}")]
    GracefulRestartCapabilityError(#[from] GracefulRestartCapabilityParsingError),

    #[error("BGP capability error: {0}")]
    AddPathCapabilityError(#[from] AddPathCapabilityParsingError),

    #[error("BGP capability error: {0}")]
    ExtendedNextHopEncodingCapabilityError(#[from] ExtendedNextHopEncodingCapabilityParsingError),

    #[error("BGP capability error: {0}")]
    MultipleLabelError(#[from] MultipleLabelParsingError),

    #[error("BGP capability error: {0}")]
    BgpRoleCapabilityError(#[from] BgpRoleCapabilityParsingError),
}

fn parse_experimental_capability<'a>(
    code: ExperimentalCapabilityCode,
    cur: &mut SliceReader<'a>,
) -> Result<BgpCapability, BgpCapabilityParsingError> {
    let len = cur.read_u8()?;
    let value = cur.read_bytes(len as usize)?;
    Ok(BgpCapability::Experimental(ExperimentalCapability::new(
        code,
        value.to_vec(),
    )))
}

fn parse_unrecognized_capability<'a>(
    code: u8,
    cur: &mut SliceReader<'a>,
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
    let length = cur.read_u8().map_err(|_| 0)?;
    if length == expected {
        Ok(length)
    } else {
        Err(length)
    }
}

fn parse_route_refresh_capability<'a>(
    cur: &mut SliceReader<'a>,
) -> Result<BgpCapability, BgpCapabilityParsingError> {
    check_capability_length(cur, ROUTE_REFRESH_CAPABILITY_LENGTH).map_err(|length| {
        BgpCapabilityParsingError::InvalidRouteRefreshLength {
            offset: cur.offset() - 1,
            length,
        }
    })?;
    Ok(BgpCapability::RouteRefresh)
}

fn parse_enhanced_route_refresh_capability<'a>(
    cur: &mut SliceReader<'a>,
) -> Result<BgpCapability, BgpCapabilityParsingError> {
    check_capability_length(cur, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH).map_err(|length| {
        BgpCapabilityParsingError::InvalidEnhancedRouteRefreshLength {
            offset: cur.offset() - 1,
            length,
        }
    })?;
    Ok(BgpCapability::EnhancedRouteRefresh)
}

impl<'a> ParseFrom<'a> for BgpCapability {
    type Error = BgpCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let code = BgpCapabilityCode::try_from(cur.read_u8()?);
        //.map_err(|err| BgpCapabilityParsingError::UndefinedCapabilityCode{offset:
        //.map_err(|err| cur.offset() - 1, code: err.0})?;
        match code {
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
                            offset: cur.offset() - 1,
                            length,
                        },
                    )?;
                    Ok(BgpCapability::CiscoRouteRefresh)
                }
                BgpCapabilityCode::BgpExtendedMessage => {
                    check_capability_length(cur, EXTENDED_MESSAGE_CAPABILITY_LENGTH).map_err(
                        |length| BgpCapabilityParsingError::InvalidExtendedMessageLength {
                            offset: cur.offset() - 1,
                            length,
                        },
                    )?;
                    Ok(BgpCapability::ExtendedMessage)
                }
                BgpCapabilityCode::BgpSecCapability => {
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::MultipleLabelsCapability => {
                    let mut cap = Vec::new();
                    while !cur.is_empty() {
                        let v = MultipleLabel::parse(cur)?;
                        cap.push(v);
                    }
                    Ok(BgpCapability::MultipleLabels(cap))
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
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::RoutingPolicyDistribution => {
                    parse_unrecognized_capability(code.into(), cur)
                }
                BgpCapabilityCode::FQDN => parse_unrecognized_capability(code.into(), cur),
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
    #[error("Four-octet AS capability parsing error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("Four-octet AS capability invalid length at offset {offset} with length {length}")]
    InvalidLength { offset: usize, length: u8 },
}

impl<'a> ParseFrom<'a> for FourOctetAsCapability {
    type Error = FourOctetAsCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        check_capability_length(cur, FOUR_OCTET_AS_CAPABILITY_LENGTH).map_err(|length| {
            FourOctetAsCapabilityParsingError::InvalidLength {
                offset: cur.offset() - 1,
                length,
            }
        })?;
        let asn4 = cur.read_u32_be()?;
        Ok(FourOctetAsCapability::new(asn4))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MultiProtocolExtensionsCapabilityParsingError {
    #[error("Multi-protocol extensions capability parsing error: {0:?}")]
    Parse(#[from] ParseError),

    #[error(
        "Multi-protocol extensions capability invalid length at offset {offset} with length {length}"
    )]
    InvalidLength { offset: usize, length: u8 },

    #[error(
        "Multi-protocol extensions capability undefined address family {afi} at offset {offset}"
    )]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error(
        "Multi-protocol extensions capability undefined subsequent address family {safi} at offset {offset}"
    )]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error(
        "Multi-protocol extensions capability address type error at offset {offset} for address family {afi} and subsequent address family {safi}"
    )]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

impl<'a> ParseFrom<'a> for MultiProtocolExtensionsCapability {
    type Error = MultiProtocolExtensionsCapabilityParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        check_capability_length(cur, MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH).map_err(
            |length| MultiProtocolExtensionsCapabilityParsingError::InvalidLength {
                offset: cur.offset() - 1,
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
                        offset: cur.offset() - 3,
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
    #[error("Graceful restart capability parsing error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("Multiple Label undefined address family {afi} at offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("Multiple Label undefined subsequent address family {safi} at offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error(
        "Multiple Label address type error at offset {offset} for address family {afi} and subsequent address family {safi}"
    )]
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
        let mut address_families = Vec::new();
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
    #[error("Add path capability parsing error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("Add path capability undefined address family {afi} at offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("Add path capability undefined subsequent address family {safi} at offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error(
        "Add path capability address type error at offset {offset} for address family {afi} and subsequent address family {safi}"
    )]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },

    #[error("Add path capability invalid send receive value at offset {offset} with value {value}")]
    InvalidAddPathSendReceiveValue { offset: usize, value: u8 },
}

impl<'a> ParseFrom<'a> for AddPathCapability {
    type Error = AddPathCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let length = cur.read_u8()?;
        let mut params_buf = cur.take_slice(length as usize)?;
        let mut address_families = Vec::new();
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
    #[error("Extended next hop capability parsing error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("Extended next hop capability undefined address family {afi} at offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error(
        "Extended next hop capability undefined subsequent address family {safi} at offset {offset}"
    )]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error(
        "Extended next hop capability address type error at offset {offset} for address family {afi} and subsequent address family {safi}"
    )]
    AddressTypeError { offset: usize, afi: u16, safi: u8 },
}

impl<'a> ParseFrom<'a> for ExtendedNextHopEncodingCapability {
    type Error = ExtendedNextHopEncodingCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let len = cur.read_u8()?;
        let mut encoding_buf = cur.take_slice(len as usize)?;
        let mut encodings = Vec::new();
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
                    offset: ehe_buf.offset() - 1, // SAFI is the last byte read
                    safi: err.0,
                }
            })?;
        let address_type = match AddressType::from_afi_safi(nlri_afi, nlri_safi) {
            Ok(address_type) => address_type,
            Err(err) => {
                return Err(
                    ExtendedNextHopEncodingCapabilityParsingError::AddressTypeError {
                        offset: ehe_buf.offset() - 3, // AFI and SAFI are the last 3 bytes read
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
    #[error("Multiple Label parsing error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("Multiple Label undefined address family {afi} at offset {offset}")]
    UndefinedAddressFamily { offset: usize, afi: u16 },

    #[error("Multiple Label undefined subsequent address family {safi} at offset {offset}")]
    UndefinedSubsequentAddressFamily { offset: usize, safi: u8 },

    #[error(
        "Multiple Label address type error at offset {offset} for address family {afi} and subsequent address family {safi}"
    )]
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
    #[error("BGP Role Capability parsing error: {0:?}")]
    Parse(#[from] ParseError),

    #[error("BGP role capability length {length}  is invalid at offset {offset}")]
    InvalidLength { offset: usize, length: u8 },

    #[error("BGP role capability code {code:?} is unrecognizable at offset {offset}")]
    UndefinedBgpRoleValue { offset: usize, code: u8 },
}

impl<'a> ParseFrom<'a> for BgpRoleCapability {
    type Error = BgpRoleCapabilityParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        check_capability_length(cur, BGP_ROLE_CAPABILITY_LENGTH).map_err(|length| {
            BgpRoleCapabilityParsingError::InvalidLength {
                offset: cur.offset() - 1,
                length,
            }
        })?;
        let code = cur.read_u8()?;
        let role = BgpRoleValue::try_from(code).map_err(|_| {
            BgpRoleCapabilityParsingError::UndefinedBgpRoleValue {
                offset: cur.offset() - 1, // code is the last byte read
                code,
            }
        })?;
        Ok(BgpRoleCapability::new(role))
    }
}
