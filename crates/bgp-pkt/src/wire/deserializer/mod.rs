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

//! Deserializer library for BGP's wire protocol

pub mod capabilities;
pub mod community;
pub mod nlri;
pub mod notification;
pub mod open;
pub mod path_attribute;
pub mod route_refresh;
pub mod update;

use ipnet::Ipv4Net;
use std::collections::HashMap;

use netgauze_iana::address_family::AddressType;
use serde::{Deserialize, Serialize};

use crate::BgpMessage;
use crate::capabilities::BgpCapability;
use crate::iana::BgpMessageType;
use crate::notification::{BgpNotificationMessage, FiniteStateMachineError, MessageHeaderError};
use crate::open::BgpOpenMessage;
use crate::route_refresh::BgpRouteRefreshMessage;
use crate::update::BgpUpdateMessage;
use crate::wire::deserializer::capabilities::BgpCapabilityParsingError;
use crate::wire::deserializer::notification::BgpNotificationMessageParsingError;
use crate::wire::deserializer::open::BgpOpenMessageParsingError;
use crate::wire::deserializer::path_attribute::PathAttributeParsingError;
use crate::wire::deserializer::route_refresh::BgpRouteRefreshMessageParsingError;
use crate::wire::deserializer::update::BgpUpdateMessageParsingError;
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::BytesReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};

/// Min message size in BGP is 19 octets. They're counted from
/// 16-octets synchronization header, 2-octets length, and 1 octet for type.
pub const BGP_MIN_MESSAGE_LENGTH: u16 = 19;

/// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271) defined max length as 4096.
/// *Note*, this only applies to [`BgpMessage::Open`] and
/// [`BgpMessage::KeepAlive`] according to the updated
/// [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654)
pub const BGP_MAX_MESSAGE_LENGTH: u16 = 4096;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct BgpParsingIgnoredErrors {
    non_unicast_withdraw_nlri: Vec<Ipv4Net>,
    non_unicast_update_nlri: Vec<Ipv4Net>,
    capability_errors: Vec<BgpCapabilityParsingError>,
    path_attr_errors: Vec<PathAttributeParsingError>,
}

impl BgpParsingIgnoredErrors {
    pub const fn non_unicast_withdraw_nlri(&self) -> &Vec<Ipv4Net> {
        &self.non_unicast_withdraw_nlri
    }

    pub const fn non_unicast_update_nlri(&self) -> &Vec<Ipv4Net> {
        &self.non_unicast_update_nlri
    }

    pub const fn capability_errors(&self) -> &Vec<BgpCapabilityParsingError> {
        &self.capability_errors
    }

    pub const fn path_attr_errors(&self) -> &Vec<PathAttributeParsingError> {
        &self.path_attr_errors
    }
}

#[derive(Debug, Clone)]
pub struct BgpParsingContext {
    asn4: bool,
    multiple_labels: HashMap<AddressType, u8>,
    add_path: HashMap<AddressType, bool>,
    fail_on_non_unicast_withdraw_nlri: bool,
    fail_on_non_unicast_update_nlri: bool,
    fail_on_capability_error: bool,
    fail_on_malformed_path_attr: bool,
    parsing_errors: BgpParsingIgnoredErrors,
}

impl BgpParsingContext {
    pub fn new(
        asn4: bool,
        multiple_labels: HashMap<AddressType, u8>,
        add_path: HashMap<AddressType, bool>,
        fail_on_non_unicast_withdraw_nlri: bool,
        fail_on_non_unicast_update_nlri: bool,
        fail_on_capability_error: bool,
        fail_on_malformed_path_attr: bool,
    ) -> Self {
        Self {
            asn4,
            multiple_labels,
            add_path,
            fail_on_non_unicast_withdraw_nlri,
            fail_on_non_unicast_update_nlri,
            fail_on_capability_error,
            fail_on_malformed_path_attr,
            parsing_errors: BgpParsingIgnoredErrors::default(),
        }
    }

    pub fn asn2_default() -> Self {
        Self::new(
            false,
            HashMap::new(),
            HashMap::new(),
            true,
            true,
            true,
            true,
        )
    }

    pub const fn asn4(&self) -> bool {
        self.asn4
    }

    pub fn set_asn4(&mut self, value: bool) {
        self.asn4 = value
    }

    pub const fn multiple_labels(&self) -> &HashMap<AddressType, u8> {
        &self.multiple_labels
    }

    pub fn multiple_labels_mut(&mut self) -> &mut HashMap<AddressType, u8> {
        &mut self.multiple_labels
    }

    pub const fn add_path(&self) -> &HashMap<AddressType, bool> {
        &self.add_path
    }

    pub fn add_path_mut(&mut self) -> &mut HashMap<AddressType, bool> {
        &mut self.add_path
    }

    #[inline]
    pub fn update_capabilities(&mut self, capability: &BgpCapability, adj_rib_out: bool) {
        match capability {
            BgpCapability::AddPath(add_path) => {
                for address_family in add_path.address_families() {
                    let add_path_support = if adj_rib_out {
                        address_family.send()
                    } else {
                        address_family.receive()
                    };
                    self.add_path_mut()
                        .insert(address_family.address_type(), add_path_support);
                }
            }
            BgpCapability::MultipleLabels(multiple_labels) => {
                for multiple_label in multiple_labels {
                    self.multiple_labels_mut()
                        .insert(multiple_label.address_type(), multiple_label.count());
                }
            }
            _ => {}
        }
    }

    pub const fn fail_on_non_unicast_withdraw_nlri(&self) -> bool {
        self.fail_on_non_unicast_withdraw_nlri
    }

    pub const fn fail_on_non_unicast_update_nlri(&self) -> bool {
        self.fail_on_non_unicast_update_nlri
    }

    pub const fn fail_on_capability_error(&self) -> bool {
        self.fail_on_capability_error
    }

    pub const fn fail_on_malformed_path_attr(&self) -> bool {
        self.fail_on_malformed_path_attr
    }

    pub const fn parsing_errors(&self) -> &BgpParsingIgnoredErrors {
        &self.parsing_errors
    }

    // Move out existing parsing errors and replace it with a new empty instant
    pub fn reset_parsing_errors(&mut self) -> BgpParsingIgnoredErrors {
        std::mem::take(&mut self.parsing_errors)
    }
}

impl Default for BgpParsingContext {
    fn default() -> Self {
        Self::new(true, HashMap::new(), HashMap::new(), true, true, true, true)
    }
}

/// BGP Message Parsing errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpMessageParsingError {
    #[error("BGP Message Parsing Error: {0:?}")]
    Parse(#[from] ParseError),

    /// The first 16-bytes of a BGP message is NOT all set to `1`
    /// For simplicity, we carry the equivalent [`u128`] value that was invalid
    /// instead of the whole buffer
    #[error(
        "The first 16-bytes of a BGP message is NOT all set to `1`: {header:x?} at offset {offset}"
    )]
    ConnectionNotSynchronized { offset: usize, header: u128 },

    /// Couldn't recognize the type octet in the BGPMessage, see
    /// [UndefinedBgpMessageType]
    #[error("Couldn't recognize the type octet in the BGP Message: {code:x?} at offset {offset}")]
    UndefinedBgpMessageType { offset: usize, code: u8 },

    /// BGP Message length is not in the defined \[min, max\] range for the
    /// given message type
    #[error("BGP Message bad length {length} at offset {offset}")]
    BadMessageLength { offset: usize, length: u16 },

    #[error(
        "BGP Message bad length {length} at offset {offset} with unparsed bytes {unparsed_bytes}"
    )]
    UnparseableBytes {
        offset: usize,
        length: u16,
        unparsed_bytes: usize,
    },

    #[error("BGP Message error: {0}")]
    BgpOpenMessageParsingError(#[from] BgpOpenMessageParsingError),

    #[error("BGP Message error: {0}")]
    BgpUpdateMessageParsingError(#[from] BgpUpdateMessageParsingError),

    #[error("BGP Message error: {0}")]
    BgpNotificationMessageParsingError(#[from] BgpNotificationMessageParsingError),

    #[error("BGP Message error: {0}")]
    BgpRouteRefreshMessageParsingError(#[from] BgpRouteRefreshMessageParsingError),
}

/// Smaller error variant of BgpMessageParsingError for small stack allocations
/// in parse_bgp_message_length_and_type
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpMessageOpenAndLengthParsingError {
    #[error("BGP Message Parsing Error: {0:?}")]
    Parse(#[from] ParseError),

    /// Couldn't recognize the type octet in the BGPMessage, see
    /// [UndefinedBgpMessageType]
    #[error("Couldn't recognize the type octet in the BGP Message: {code:x?} at offset {offset}")]
    UndefinedBgpMessageType { offset: usize, code: u8 },

    /// BGP Message length is not in the defined \[min, max\] range for the
    /// given message type
    #[error("BGP Message bad length {length} at offset {offset}")]
    BadMessageLength { offset: usize, length: u16 },
}

/// Parse [`BgpMessage`] length and type, then check that the length of a BGP
/// message is valid according to it's type. Takes into consideration both rules at [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
/// and [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654).
///
/// Returns the length, message type, and BytesReader limited to the BGP message
/// as specified in the length (everything after the length and type octets)
#[inline]
fn parse_bgp_message_length_and_type(
    cur: &mut BytesReader,
) -> Result<(u16, BgpMessageType, BytesReader), BgpMessageOpenAndLengthParsingError> {
    let length = cur.read_u16_be()?;

    // Fail early if the message length is not valid
    if length < BGP_MIN_MESSAGE_LENGTH {
        return Err(BgpMessageOpenAndLengthParsingError::BadMessageLength {
            offset: cur.offset() - 2,
            length,
        });
    }

    // Only read the subset that is defined by the length
    // Check the message size before doing any math on it
    let mut bgp_message_buf = cur.take_slice(length as usize - 18).map_err(|_| {
        BgpMessageOpenAndLengthParsingError::BadMessageLength {
            offset: cur.offset() - 2,
            length,
        }
    })?;

    let message_type = BgpMessageType::try_from(bgp_message_buf.read_u8()?).map_err(|error| {
        BgpMessageOpenAndLengthParsingError::UndefinedBgpMessageType {
            offset: bgp_message_buf.offset() - 1,
            code: error.0,
        }
    })?;

    match message_type {
        BgpMessageType::Open | BgpMessageType::KeepAlive => {
            if !(BGP_MIN_MESSAGE_LENGTH..=BGP_MAX_MESSAGE_LENGTH).contains(&length) {
                return Err(BgpMessageOpenAndLengthParsingError::BadMessageLength {
                    offset: bgp_message_buf.offset() - 3,
                    length,
                });
            }
        }
        BgpMessageType::Update | BgpMessageType::Notification | BgpMessageType::RouteRefresh => {}
    }
    Ok((length, message_type, bgp_message_buf))
}

impl<'a> ParseFromWithOneInput<'a, &mut BgpParsingContext> for BgpMessage {
    type Error = BgpMessageParsingError;
    fn parse(cur: &mut BytesReader, ctx: &mut BgpParsingContext) -> Result<Self, Self::Error> {
        let header = cur.read_u128_be()?;
        if header != u128::MAX {
            return Err(BgpMessageParsingError::ConnectionNotSynchronized {
                offset: cur.offset() - 16,
                header,
            });
        }

        // Parse both length and type together, since we need to do input validation on
        // the length based on the type of the message
        let (length, message_type, mut bgp_message_buf) =
            match parse_bgp_message_length_and_type(cur) {
                Ok(value) => value,
                Err(err) => {
                    let e = match err {
                        BgpMessageOpenAndLengthParsingError::Parse(parse) => {
                            BgpMessageParsingError::Parse(parse)
                        }
                        BgpMessageOpenAndLengthParsingError::UndefinedBgpMessageType {
                            offset,
                            code,
                        } => BgpMessageParsingError::UndefinedBgpMessageType { offset, code },
                        BgpMessageOpenAndLengthParsingError::BadMessageLength {
                            offset,
                            length,
                        } => BgpMessageParsingError::BadMessageLength { offset, length },
                    };
                    return Err(e);
                }
            };
        let msg = match message_type {
            BgpMessageType::Open => {
                let open = BgpOpenMessage::parse(&mut bgp_message_buf, ctx)?;
                BgpMessage::Open(open)
            }
            BgpMessageType::Update => {
                let update = BgpUpdateMessage::parse(&mut bgp_message_buf, ctx)?;
                BgpMessage::Update(update)
            }
            BgpMessageType::Notification => {
                let notification = BgpNotificationMessage::parse(&mut bgp_message_buf)?;
                BgpMessage::Notification(notification)
            }
            BgpMessageType::KeepAlive => BgpMessage::KeepAlive,
            BgpMessageType::RouteRefresh => {
                let route_refresh = BgpRouteRefreshMessage::parse(&mut bgp_message_buf)?;
                BgpMessage::RouteRefresh(route_refresh)
            }
        };

        // Make sure we consumed the full BGP message as specified by its length
        if !bgp_message_buf.is_empty() {
            return Err(BgpMessageParsingError::UnparseableBytes {
                offset: bgp_message_buf.offset(),
                length,
                unparsed_bytes: bgp_message_buf.remaining(),
            });
        }
        Ok(msg)
    }
}

impl From<BgpMessageParsingError> for BgpNotificationMessage {
    fn from(value: BgpMessageParsingError) -> Self {
        match value {
            BgpMessageParsingError::Parse(_) => {
                // TODO: more detailed error
                BgpNotificationMessage::MessageHeaderError(MessageHeaderError::Unspecific {
                    value: vec![],
                })
            }
            BgpMessageParsingError::ConnectionNotSynchronized { header, .. } => {
                BgpNotificationMessage::MessageHeaderError(
                    MessageHeaderError::ConnectionNotSynchronized {
                        value: header.to_be_bytes().to_vec(),
                    },
                )
            }
            BgpMessageParsingError::UndefinedBgpMessageType { code: msg_type, .. } => {
                BgpNotificationMessage::MessageHeaderError(MessageHeaderError::BadMessageType {
                    value: msg_type.to_be_bytes().to_vec(),
                })
            }
            BgpMessageParsingError::BadMessageLength {
                length: bad_length, ..
            } => BgpNotificationMessage::MessageHeaderError(MessageHeaderError::BadMessageLength {
                value: bad_length.to_be_bytes().to_vec(),
            }),
            BgpMessageParsingError::UnparseableBytes {
                length: bad_length, ..
            } => BgpNotificationMessage::MessageHeaderError(MessageHeaderError::BadMessageLength {
                value: bad_length.to_be_bytes().to_vec(),
            }),
            BgpMessageParsingError::BgpOpenMessageParsingError(open_err) => {
                BgpNotificationMessage::OpenMessageError(open_err.into())
            }
            BgpMessageParsingError::BgpUpdateMessageParsingError(update_err) => {
                BgpNotificationMessage::UpdateMessageError(update_err.into())
            }
            BgpMessageParsingError::BgpNotificationMessageParsingError(_notification) => {
                // Notification messages parsing should be ignored and consider a session
                // closed.
                BgpNotificationMessage::FiniteStateMachineError(
                    FiniteStateMachineError::Unspecific { value: vec![] },
                )
            }
            BgpMessageParsingError::BgpRouteRefreshMessageParsingError(route_refresh_error) => {
                BgpNotificationMessage::RouteRefreshError(route_refresh_error.into())
            }
        }
    }
}

#[inline]
pub fn read_tlv_header_t16_l16<E>(cur: &mut BytesReader) -> Result<(u16, u16, BytesReader), E>
where
    E: std::error::Error + From<ParseError>,
{
    let tlv_type = cur.read_u16_be()?;
    let tlv_length = cur.read_u16_be()?;
    let data = cur.take_slice(tlv_length as usize)?;
    Ok((tlv_type, tlv_length, data))
}

#[inline]
pub fn read_tlv_header_t8_l16<E>(cur: &mut BytesReader) -> Result<(u8, u16, BytesReader), E>
where
    E: std::error::Error + From<ParseError>,
{
    let tlv_type = cur.read_u8()?;
    let tlv_length = cur.read_u16_be()?;
    let data = cur.take_slice(tlv_length as usize)?;

    Ok((tlv_type, tlv_length, data))
}
