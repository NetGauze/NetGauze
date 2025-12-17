// Copyright (C) 2025-present The NetGauze Authors.
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

//! UDP-Notif packet decoding and payload handling.
//!
//! This module provides types and functionality for decoding [crate::raw]
//! UDP-Notif packets into structured Rust types. It supports both the current
//! IETF YANG Push notification envelope format and the legacy notification
//! format.
//!
//! # Main Types
//!
//! - [`UdpNotifPacketDecoded`]: A fully decoded UDP-Notif packet with parsed
//!   payload
//! - [`UdpNotifPayload`]: Enum representing the two supported notification
//!   formats
//! - [`UdpNotifPayloadConversionError`]: Error type for payload conversion
//!   failures
//!
//! # Supported Media Types (all other media types will result in an error)
//!
//! - `YangDataJson`: JSON-encoded YANG data
//! - `YangDataCbor`: CBOR-encoded YANG data
//!
//! # Example
//!
//! ```ignore
//! use crate::UdpNotifPacket;
//! use crate::dp_notif::UdpNotifPacketDecoded;
//!
//! let packet: UdpNotifPacket = /* ... */;
//! let decoded: UdpNotifPacketDecoded = (&packet).try_into()?;
//!
//! match decoded.payload() {
//!     UdpNotifPayload::NotificationEnvelope(envelope) => {
//!         // Handle modern envelope format
//!     }
//!     UdpNotifPayload::NotificationLegacy(legacy) => {
//!         // Handle legacy notification format
//!     }
//! }
//! ```

use crate::notification::{NotificationEnvelope, NotificationLegacy};
use crate::raw::{MediaType, UDP_NOTIF_V1, UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum UdpNotifPayload {
    #[serde(rename = "ietf-yp-notification:envelope")]
    NotificationEnvelope(NotificationEnvelope),

    #[serde(rename = "ietf-notification:notification")]
    NotificationLegacy(NotificationLegacy), // deprecated
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UdpNotifPacketDecoded {
    media_type: MediaType,
    publisher_id: u32,
    message_id: u32,
    options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
    payload: UdpNotifPayload,
}

impl UdpNotifPacketDecoded {
    pub const fn new(
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
        payload: UdpNotifPayload,
    ) -> Self {
        Self {
            media_type,
            publisher_id,
            message_id,
            options,
            payload,
        }
    }
    pub const fn version(&self) -> u8 {
        UDP_NOTIF_V1
    }
    pub const fn media_type(&self) -> MediaType {
        self.media_type
    }
    pub const fn publisher_id(&self) -> u32 {
        self.publisher_id
    }
    pub const fn message_id(&self) -> u32 {
        self.message_id
    }
    pub const fn options(&self) -> &HashMap<UdpNotifOptionCode, UdpNotifOption> {
        &self.options
    }
    pub const fn payload(&self) -> &UdpNotifPayload {
        &self.payload
    }
}

#[derive(Debug)]
pub enum UdpNotifPayloadConversionError {
    UnsupportedMediaType(MediaType),
    JsonError(serde_json::Error),
    CborError(ciborium::de::Error<std::io::Error>),
}

impl From<serde_json::Error> for UdpNotifPayloadConversionError {
    fn from(err: serde_json::Error) -> Self {
        UdpNotifPayloadConversionError::JsonError(err)
    }
}

impl From<ciborium::de::Error<std::io::Error>> for UdpNotifPayloadConversionError {
    fn from(err: ciborium::de::Error<std::io::Error>) -> Self {
        UdpNotifPayloadConversionError::CborError(err)
    }
}

impl fmt::Display for UdpNotifPayloadConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpNotifPayloadConversionError::UnsupportedMediaType(media_type) => {
                write!(f, "Unsupported media type: {media_type}")
            }
            UdpNotifPayloadConversionError::JsonError(err) => {
                write!(f, "JSON error: {err}")
            }
            UdpNotifPayloadConversionError::CborError(err) => {
                write!(f, "CBOR error: {err}")
            }
        }
    }
}

impl TryFrom<&UdpNotifPacket> for UdpNotifPacketDecoded {
    type Error = UdpNotifPayloadConversionError;

    fn try_from(pkt: &UdpNotifPacket) -> Result<Self, UdpNotifPayloadConversionError> {
        let payload = match pkt.media_type() {
            MediaType::YangDataJson => serde_json::from_slice(&pkt.payload())?,
            MediaType::YangDataCbor => {
                let val: Value = ciborium::de::from_reader(std::io::Cursor::new(pkt.payload()))?;
                serde_json::from_value(val)?
            }
            media_type => {
                return Err(UdpNotifPayloadConversionError::UnsupportedMediaType(
                    media_type,
                ));
            }
        };

        Ok(UdpNotifPacketDecoded {
            media_type: pkt.media_type(),
            publisher_id: pkt.publisher_id(),
            message_id: pkt.message_id(),
            options: pkt.options().clone(),
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::{
        Encoding, NotificationEnvelope, NotificationLegacy, NotificationVariant,
        SubscriptionStartedModified, Target, UpdateTrigger, YangPushModuleVersion,
    };
    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_udp_notif_packet_decoded_envelope_sub_started() {
        let payload = json!({
            "ietf-yp-notification:envelope": {
                "contents": {
                    "ietf-subscribed-notifications:subscription-started": {
                        "encoding": "encode-json",
                        "id": 30,
                        "ietf-yang-push-revision:module-version": [
                            { "module-name": "openconfig-interfaces", "revision": "2025-06-10" }
                        ],
                        "ietf-yang-push:datastore": "ietf-datastores:operational",
                        "ietf-yang-push:datastore-xpath-filter": "openconfig-interfaces:interfaces",
                        "ietf-yang-push:on-change": { "sync-on-start": true },
                    }
                },
                "event-time": "2025-04-17T15:20:14.840Z",
                "another-time": "2025-01-01T15:20:14.840Z",
                "hostname": "ipf-zbl1327-r-daisy-91",
                "sequence-number": 0
            }
        })
        .to_string()
        .into_bytes();

        let packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1234,
            5678,
            HashMap::new(),
            Bytes::from(payload),
        );

        let decoded: UdpNotifPacketDecoded = (&packet).try_into().unwrap();

        // Test UdpNotifPacketDecoded getters
        assert_eq!(decoded.media_type(), MediaType::YangDataJson);
        assert_eq!(decoded.publisher_id(), 1234);
        assert_eq!(decoded.message_id(), 5678);

        // Create the expected NotificationEnvelope
        let sub_started = SubscriptionStartedModified::new(
            30,
            Target::new(
                None,
                None,
                None,
                None,
                Some("ietf-datastores:operational".to_string()),
                None,
                Some("openconfig-interfaces:interfaces".to_string()),
            ),
            None,
            None,
            Some(Encoding::Json),
            None,
            Some(UpdateTrigger::OnChange {
                dampening_period: None,
                sync_on_start: Some(true),
                excluded_change: None,
            }),
            Some(vec![YangPushModuleVersion::new(
                "openconfig-interfaces".to_string(),
                Some("2025-06-10".to_string()),
                None,
            )]),
            None,
            json!({}),
        );
        let expected = NotificationEnvelope::new(
            DateTime::parse_from_rfc3339("2025-04-17T15:20:14.840Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("ipf-zbl1327-r-daisy-91".to_string()),
            Some(0),
            Some(NotificationVariant::SubscriptionStarted(sub_started)),
            json!({"another-time": "2025-01-01T15:20:14.840Z"}),
        );

        // Compare the decoded payload with the expected NotificationEnvelope
        assert_eq!(
            decoded.payload(),
            &UdpNotifPayload::NotificationEnvelope(expected)
        );
    }

    #[test]
    fn test_udp_notif_packet_decoded_legacy_sub_started() {
        let payload = json!({
            "ietf-notification:notification": {
                "eventTime": "2025-05-12T12:00:00Z",
                "additional_stuff": "example",
                "ietf-subscribed-notifications:subscription-started": {
                  "encoding": "encode-json",
                  "id": 1,
                  "ietf-distributed-notif:message-publisher-ids": [
                    16974839, 16973828, 16974828
                  ],
                  "ietf-yang-push:datastore": "ietf-datastores:running",
                  "additional_stuff": [ { "key1": "a" }, { "key2": "b" } ],
                }
            }
        })
        .to_string()
        .into_bytes();

        let packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1234,
            5678,
            HashMap::new(),
            Bytes::from(payload),
        );

        let decoded: UdpNotifPacketDecoded = (&packet).try_into().unwrap();

        // Create the expected NotificationLegacy
        let sub_started = SubscriptionStartedModified::new(
            1,
            Target::new(
                None,
                None,
                None,
                None,
                Some("ietf-datastores:running".to_string()),
                None,
                None,
            ),
            None,
            None,
            Some(Encoding::Json),
            None,
            None,
            None,
            None,
            json!({"ietf-distributed-notif:message-publisher-ids": [
                    16974839, 16973828, 16974828
                  ],
                  "additional_stuff": [ { "key1": "a" }, { "key2": "b" } ]}),
        );
        let expected = NotificationLegacy::new(
            DateTime::parse_from_rfc3339("2025-05-12T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            Some(NotificationVariant::SubscriptionStarted(sub_started)),
            json!({
              "additional_stuff": "example"}),
        );

        // Compare the decoded payload with expected NotificationLegacy
        assert_eq!(
            decoded.payload(),
            &UdpNotifPayload::NotificationLegacy(expected)
        );
    }

    #[test]
    fn test_udp_notif_packet_decoded_unknown_media_type() {
        let payload = Bytes::from(vec![0x01, 0x02, 0x03]);

        let packet =
            UdpNotifPacket::new(MediaType::Unknown(99), 1234, 5678, HashMap::new(), payload);

        // Attempt to decode the packet (will throw an error since the media type is
        // unknown)
        let result = UdpNotifPacketDecoded::try_from(&packet);
        assert!(matches!(
            result,
            Err(UdpNotifPayloadConversionError::UnsupportedMediaType(_))
        ));
    }

    #[test]
    fn test_udp_notif_packet_decoded_invalid_json_payload() {
        let payload = Bytes::from(b"invalid json".to_vec());

        let packet =
            UdpNotifPacket::new(MediaType::YangDataJson, 1234, 5678, HashMap::new(), payload);

        // Attempt to decode the packet (will throw an error since the payload is not
        // valid JSON)
        let result = UdpNotifPacketDecoded::try_from(&packet);

        assert!(
            matches!(result, Err(UdpNotifPayloadConversionError::JsonError(_))),
            "Unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_udp_notif_packet_decoded_unknown_notification_variant() {
        let payload = json!({
                    "ietf-yp-notification:envelope": {
                        "event-time": "2025-03-04T07:11:33.252679191+00:00",
                        "hostname": "some-router",
                        "sequence-number": 5,
                        "contents": {
                            "unknown-notification-variant": {
                                "id": 12345678,
                                "encoding": "encode-json",
                                "transport": "ietf-udp-notif-transport:udp-notif",
                            }
                        },
                      }
        })
        .to_string()
        .into_bytes();

        let packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1,
            1,
            HashMap::new(),
            Bytes::from(payload),
        );

        // Attempt to decode the packet (will throw an error since the
        // NotificationVariant is unknown)
        let result = UdpNotifPacketDecoded::try_from(&packet);

        assert!(
            matches!(result, Err(UdpNotifPayloadConversionError::JsonError(_))),
            "Unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_udp_notif_packet_decoded_empty_content() {
        let payload = json!({
                    "ietf-yp-notification:envelope": {
                        "event-time": "2025-03-04T07:11:33.252679191+00:00",
                        "hostname": "some-router",
                        "sequence-number": 5,
                        "contents": {},
                      }
        })
        .to_string()
        .into_bytes();

        let packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1,
            1,
            HashMap::new(),
            Bytes::from(payload),
        );

        // Attempt to decode the packet (will throw an error since there
        // isn't any of the defined NotificationVariant)
        let result = UdpNotifPacketDecoded::try_from(&packet);

        assert!(
            matches!(result, Err(UdpNotifPayloadConversionError::JsonError(_))),
            "Unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_udp_notif_packet_decoded_no_content() {
        let payload = json!({
                    "ietf-yp-notification:envelope": {
                        "event-time": "2025-03-04T07:11:33.252679191+00:00",
                        "hostname": "some-router",
                        "sequence-number": 5,
                      }
        })
        .to_string()
        .into_bytes();

        let packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1,
            1,
            HashMap::new(),
            Bytes::from(payload),
        );

        // Attempt to decode the packet (should succeed)
        let decoded: UdpNotifPacketDecoded = (&packet).try_into().unwrap();

        // Create the expected NotificationEnvelope
        let expected = NotificationEnvelope::new(
            DateTime::parse_from_rfc3339("2025-03-04T07:11:33.252679191+00:00")
                .unwrap()
                .with_timezone(&Utc),
            Some("some-router".to_string()),
            Some(5),
            None,
            json!({}),
        );

        // Check the hostname and sequence number
        assert_eq!(
            decoded.payload(),
            &UdpNotifPayload::NotificationEnvelope(expected)
        );
    }
}
