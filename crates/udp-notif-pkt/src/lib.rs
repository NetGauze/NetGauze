// Copyright (C) 2024-present The NetGauze Authors.
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

#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "serde")]
pub mod wire;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, convert::TryFrom, fmt};
use strum_macros::Display;

use netgauze_yang_push::model::notification::{NotificationEnvelope, NotificationLegacy};

const UDP_NOTIF_VERSION: u8 = 1;

#[derive(
    Display,
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    Hash,
    strum_macros::EnumDiscriminants,
)]
#[strum_discriminants(name(MediaTypeNames))]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum MediaType {
    Reserved,
    YangDataJson,
    YangDataXml,
    YangDataCbor,
    Unknown(u8),
}

impl From<u8> for MediaType {
    fn from(value: u8) -> Self {
        match value {
            0 => MediaType::Reserved,
            1 => MediaType::YangDataJson,
            2 => MediaType::YangDataXml,
            3 => MediaType::YangDataCbor,
            value => MediaType::Unknown(value),
        }
    }
}

impl From<MediaType> for u8 {
    fn from(value: MediaType) -> Self {
        match value {
            MediaType::Reserved => 0,
            MediaType::YangDataJson => 1,
            MediaType::YangDataXml => 2,
            MediaType::YangDataCbor => 3,
            MediaType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum UdpNotifOptionCode {
    Segment = 1,
    PrivateEncoding = 2,
    Unknown(u8),
}

impl From<u8> for UdpNotifOptionCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Segment,
            2 => Self::PrivateEncoding,
            v => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum UdpNotifOption {
    Segment { number: u16, last: bool },
    PrivateEncoding(Vec<u8>),
    Unknown { typ: u8, value: Vec<u8> },
}

impl UdpNotifOption {
    pub const fn code(&self) -> UdpNotifOptionCode {
        match self {
            Self::Segment { .. } => UdpNotifOptionCode::Segment,
            Self::PrivateEncoding(_) => UdpNotifOptionCode::PrivateEncoding,
            Self::Unknown { typ, .. } => UdpNotifOptionCode::Unknown(*typ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UdpNotifPacket {
    media_type: MediaType,
    publisher_id: u32,
    message_id: u32,
    options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_bytes))]
    payload: Bytes,
}

impl UdpNotifPacket {
    pub const fn new(
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
        payload: Bytes,
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
        UDP_NOTIF_VERSION
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

    pub const fn payload(&self) -> &Bytes {
        &self.payload
    }
}

#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Bytes> {
    let value: Vec<u8> = u.arbitrary()?;
    Ok(Bytes::from(value))
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
        UDP_NOTIF_VERSION
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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum UdpNotifPayload {
    #[serde(rename = "ietf-yp-notification:envelope")]
    NotificationEnvelope(NotificationEnvelope),

    #[serde(rename = "ietf-notification:notification")]
    NotificationLegacy(NotificationLegacy), // deprecated
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
            MediaType::YangDataJson => serde_json::from_slice(pkt.payload())?,
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
            media_type: pkt.media_type,
            publisher_id: pkt.publisher_id,
            message_id: pkt.message_id,
            options: pkt.options.clone(),
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use core::panic;
    use netgauze_yang_push::model::notification::{
        Encoding, NotificationVariant, SubscriptionStartedModified, Target, UpdateTrigger,
        YangPushModuleVersion,
    };
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

        // Create expected NotificationEnvelope
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
            serde_json::json!({}),
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

        // Compare the decoded payload with expected NotificationEnvelope
        match decoded.payload() {
            UdpNotifPayload::NotificationEnvelope(decoded) => {
                assert_eq!(decoded, &expected);
            }
            _ => {
                panic!("Expected UdpNotifPayload::NotificationEnvelope");
            }
        }
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

        // Create expected NotificationLegacy
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
            serde_json::json!({
              "additional_stuff": "example"}),
        );

        // Compare the decoded payload with expected NotificationLegacy
        match decoded.payload() {
            UdpNotifPayload::NotificationLegacy(decoded) => {
                assert_eq!(decoded, &expected);
            }
            _ => {
                panic!("Expected UdpNotifPayload::NotificationLegacy");
            }
        }
    }

    #[test]
    fn test_udp_notif_packet_decoded_unknown_mediatype() {
        let payload = Bytes::from(vec![0x01, 0x02, 0x03]);

        let packet =
            UdpNotifPacket::new(MediaType::Unknown(99), 1234, 5678, HashMap::new(), payload);

        // Attempt to decode the packet (will throw an error since the media type is
        // unknown)
        let result = UdpNotifPacketDecoded::try_from(&packet);

        assert!(result.is_err());
        if let Err(UdpNotifPayloadConversionError::UnsupportedMediaType(media_type)) = result {
            assert_eq!(media_type, MediaType::Unknown(99));
        } else {
            panic!("Expected UnsupportedMediaType error");
        }
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

        // Create expected NotificationEnvelope
        let expected = NotificationEnvelope::new(
            DateTime::parse_from_rfc3339("2025-03-04T07:11:33.252679191+00:00")
                .unwrap()
                .with_timezone(&Utc),
            Some("some-router".to_string()),
            Some(5),
            None,
            json!({}),
        );

        // Check hostname and sequence number
        match decoded.payload() {
            UdpNotifPayload::NotificationEnvelope(decoded) => {
                assert_eq!(decoded, &expected);
            }
            _ => {
                panic!("Expected UdpNotifPayload::NotificationEnvelope");
            }
        }
    }
}
