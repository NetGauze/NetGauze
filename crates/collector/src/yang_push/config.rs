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

//! # Yang Telemetry Configuration Module
//!
//! This module provides configuration and conversion capabilities for telemetry
//! data to be published to Kafka using YANG schemas. It implements the
//! `YangConverter` trait to transform telemetry messages into YANG-compliant
//! JSON format.

use crate::publishers::kafka_yang::YangConverter;
use netgauze_yang_push::ContentId;
use netgauze_yang_push::cache::storage::{SubscriptionInfo, YangLibraryReference};
use netgauze_yang_push::model::telemetry::TelemetryMessageWrapper;
use serde::{Deserialize, Serialize};

#[derive(Debug, strum_macros::Display)]
pub enum TelemetryYangConverterError {
    #[strum(to_string = "Failed to read from file: {0}")]
    IoError(std::io::Error),

    #[strum(to_string = "Failed to parse schema JSON: {0}")]
    JsonError(serde_json::Error),

    #[strum(to_string = "Failed to serialize telemetry message: {0}")]
    SerializationError(crate::UdpNotifSerializationError),
}

impl From<std::io::Error> for TelemetryYangConverterError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<serde_json::Error> for TelemetryYangConverterError {
    fn from(value: serde_json::Error) -> Self {
        Self::JsonError(value)
    }
}

impl std::error::Error for TelemetryYangConverterError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryYangConverter {
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub subject_prefix: Option<String>,

    pub root_schema_name: String,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub default_yang_lib_ref: Option<YangLibraryReference>,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub extension_yang_lib_ref: Option<YangLibraryReference>,
}

impl TelemetryYangConverter {
    pub fn new(
        root_schema_name: String,
        default_yang_lib_ref: Option<YangLibraryReference>,
        extension_yang_lib_ref: Option<YangLibraryReference>,
    ) -> Self {
        Self {
            subject_prefix: None,
            root_schema_name,
            default_yang_lib_ref,
            extension_yang_lib_ref,
        }
    }
}

impl
    YangConverter<
        (Option<ContentId>, SubscriptionInfo, TelemetryMessageWrapper),
        TelemetryYangConverterError,
    > for TelemetryYangConverter
{
    fn subject_prefix(&self) -> Option<&str> {
        self.subject_prefix.as_deref()
    }

    fn root_schema_name(&self) -> &str {
        &self.root_schema_name
    }

    fn default_yang_lib(&self) -> Option<&YangLibraryReference> {
        self.default_yang_lib_ref.as_ref()
    }

    fn extension_yang_lib_ref(&self) -> Option<&YangLibraryReference> {
        self.extension_yang_lib_ref.as_ref()
    }

    fn content_id(
        &self,
        input: &(Option<ContentId>, SubscriptionInfo, TelemetryMessageWrapper),
    ) -> Option<ContentId> {
        input.0.clone()
    }

    fn get_key(
        &self,
        input: &(Option<ContentId>, SubscriptionInfo, TelemetryMessageWrapper),
    ) -> Option<serde_json::Value> {
        let (_, subscription_info, _) = input;
        let ip = subscription_info.peer().ip();
        Some(serde_json::Value::String(ip.to_string()))
    }

    fn serialize_json(
        &self,
        input: (Option<ContentId>, SubscriptionInfo, TelemetryMessageWrapper),
    ) -> Result<Vec<u8>, TelemetryYangConverterError> {
        let telemetry_message_wrapper = input.2;
        serde_json::to_vec(&telemetry_message_wrapper).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use netgauze_yang_push::model::telemetry::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn create_test_subscription_info(ip: IpAddr) -> SubscriptionInfo {
        SubscriptionInfo::new(
            SocketAddr::new(ip, 8080),
            1,
            "test-content-id".to_string(),
            netgauze_udp_notif_pkt::notification::Target::new_datastore(
                "ietf-datastores:operational".to_string(),
                either::Right("/test-path".to_string()),
            ),
            vec!["test-module".to_string()],
        )
    }

    fn create_test_telemetry_message_wrapper() -> TelemetryMessageWrapper {
        use chrono::Utc;
        TelemetryMessageWrapper::new(TelemetryMessage::new(
            None,
            TelemetryMessageMetadata::new(
                None,
                Utc.timestamp_millis_opt(0).unwrap(),
                EventType::Update,
                None,
                SessionProtocol::YangPush,
                "127.0.0.1".parse().unwrap(),
                None,
                None,
                None,
                None,
            ),
            None,
            None,
            None,
        ))
    }

    #[test]
    fn test_new_converter() {
        let root_name = "ietf-telemetry-message".to_string();
        let converter = TelemetryYangConverter::new(root_name.clone(), None, None);

        assert_eq!(converter.root_schema_name, root_name);
        assert!(converter.subject_prefix.is_none());
        assert!(converter.default_yang_lib_ref.is_none());
    }

    #[test]
    fn test_trait_getters() {
        let root_name = "test-root".to_string();
        let mut converter = TelemetryYangConverter::new(root_name.clone(), None, None);
        converter.subject_prefix = Some("prefix".to_string());

        assert_eq!(converter.root_schema_name(), root_name);
        assert_eq!(converter.subject_prefix(), Some("prefix"));
    }

    #[test]
    fn test_content_id_extraction() {
        let converter = TelemetryYangConverter::new("test".to_string(), None, None);
        let content_id = Some("cid-123".to_string());
        let sub_info = create_test_subscription_info(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let msg = create_test_telemetry_message_wrapper();

        let input = (content_id.clone(), sub_info, msg);
        assert_eq!(converter.content_id(&input), content_id);
    }

    #[test]
    fn test_get_key_ipv4() {
        let converter = TelemetryYangConverter::new("test".to_string(), None, None);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sub_info = create_test_subscription_info(ip);
        let msg = create_test_telemetry_message_wrapper();

        let input = (None, sub_info, msg);
        let key = converter.get_key(&input).unwrap();
        assert_eq!(key, serde_json::Value::String("192.168.1.1".to_string()));
    }

    #[test]
    fn test_get_key_ipv6() {
        let converter = TelemetryYangConverter::new("test".to_string(), None, None);
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let sub_info = create_test_subscription_info(ip);
        let msg = create_test_telemetry_message_wrapper();

        let input = (None, sub_info, msg);
        let key = converter.get_key(&input).unwrap();
        assert_eq!(key, serde_json::Value::String("2001:db8::1".to_string()));
    }

    #[test]
    fn test_serialize_json_success() {
        let converter = TelemetryYangConverter::new("test".to_string(), None, None);
        let sub_info = create_test_subscription_info(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let msg = create_test_telemetry_message_wrapper();
        let expected = serde_json::to_value(&msg).unwrap();

        // Call serialize_json to serialize into bytes
        let input = (None, sub_info, msg);
        let result = converter.serialize_json(input);
        assert!(result.is_ok());

        // Deserialize back into json_value and check
        let json_value: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(json_value, expected);
    }
}
