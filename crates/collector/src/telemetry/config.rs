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
use netgauze_yang_push::{
    model::telemetry::TelemetryMessageWrapper, validation::SubscriptionInfo, ContentId,
};
use schema_registry_converter::schema_registry_common::SuppliedSchema;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use tracing::error;

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
    pub root_schema: PathBuf,
}

impl TelemetryYangConverter {
    pub fn new(root_schema: PathBuf) -> Self {
        Self { root_schema }
    }

    fn load_schema(schema_path: &PathBuf) -> Result<SuppliedSchema, TelemetryYangConverterError> {
        let schema_content = fs::read_to_string(schema_path)?;
        let supplied_schema: SuppliedSchema = serde_json::from_str(&schema_content)?;
        Ok(supplied_schema)
    }
}

impl YangConverter<(SubscriptionInfo, TelemetryMessageWrapper), TelemetryYangConverterError>
    for TelemetryYangConverter
{
    fn get_root_schema(&self) -> Result<SuppliedSchema, TelemetryYangConverterError> {
        let schema = match Self::load_schema(&self.root_schema) {
            Ok(schema) => schema,
            Err(err) => {
                error!(
                    "Failed to load Telemetry Message root schema from {:?}: {}",
                    self.root_schema, err
                );
                return Err(err);
            }
        };

        Ok(schema)
    }

    fn get_content_id(
        &self,
        input: &(SubscriptionInfo, TelemetryMessageWrapper),
    ) -> Option<ContentId> {
        input.0.content_id().cloned()
    }

    fn get_key(
        &self,
        input: &(SubscriptionInfo, TelemetryMessageWrapper),
    ) -> Option<serde_json::Value> {
        let ip = input.0.peer_addr().ip();
        Some(serde_json::Value::String(ip.to_string()))
    }

    fn serialize_json(
        &self,
        input: (SubscriptionInfo, TelemetryMessageWrapper),
    ) -> Result<serde_json::Value, TelemetryYangConverterError> {
        let telemetry_message_wrapper = input.1;
        serde_json::to_value(telemetry_message_wrapper).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::{
        io::Write,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };
    use tempfile::NamedTempFile;

    fn create_test_schema_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        let schema_content = r#"{
            "name": "test-telemetry-message",
            "schema_type": {
                "Other": "YANG"
            },
            "schema": "module test-telemetry-message { namespace \"urn:test\"; prefix tm; }",
            "references": [],
            "properties": null,
            "tags": null
        }"#;
        file.write_all(schema_content.as_bytes())
            .expect("Failed to write test schema");
        file
    }

    fn create_test_subscription_info() -> SubscriptionInfo {
        SubscriptionInfo::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            8080,
        ))
        .with_subscription_id(1)
        .with_content_id("test-subscription".to_string())
    }

    fn create_test_telemetry_message_wrapper() -> TelemetryMessageWrapper {
        use chrono::Utc;
        use netgauze_yang_push::model::telemetry::*;

        TelemetryMessageWrapper::new(TelemetryMessage::new(
            None,
            TelemetryMessageMetadata::new(
                None,
                Utc.timestamp_millis_opt(0).unwrap(),
                SessionProtocol::YangPush,
                "127.0.0.1".parse().unwrap(),
                None,
                None,
                None,
                None,
            ),
            None,
            NetworkOperatorMetadata::new(Vec::new()),
            None,
        ))
    }

    #[test]
    fn test_new_converter() {
        let schema_path = PathBuf::from("root-schema.json");
        let converter = TelemetryYangConverter::new(schema_path.clone());

        assert_eq!(converter.root_schema, schema_path);
    }

    #[test]
    fn test_get_root_schema_success() {
        let schema_file = create_test_schema_file();
        let converter = TelemetryYangConverter::new(schema_file.path().to_path_buf());

        let result = converter.get_root_schema();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_root_schema_file_not_found() {
        let converter = TelemetryYangConverter::new(PathBuf::from("nonexistent.json"));

        let result = converter.get_root_schema();
        assert!(result.is_err());

        match result.unwrap_err() {
            TelemetryYangConverterError::IoError(_) => {}
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_get_root_schema_invalid_json() {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        file.write_all(b"invalid json")
            .expect("Failed to write invalid JSON");

        let converter = TelemetryYangConverter::new(file.path().to_path_buf());

        let result = converter.get_root_schema();
        assert!(result.is_err());

        match result.unwrap_err() {
            TelemetryYangConverterError::JsonError(_) => {}
            _ => panic!("Expected JsonError"),
        }
    }

    #[test]
    fn test_get_key_extracts_ip_address() {
        let schema_file = create_test_schema_file();
        let converter = TelemetryYangConverter::new(schema_file.path().to_path_buf());

        let subscription_info = create_test_subscription_info();
        let message_wrapper = create_test_telemetry_message_wrapper();
        let input = (subscription_info, message_wrapper);

        let key = converter.get_key(&input);
        assert_eq!(
            key.unwrap(),
            serde_json::Value::String("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_get_key_with_ipv6() {
        let schema_file = create_test_schema_file();
        let converter = TelemetryYangConverter::new(schema_file.path().to_path_buf());

        let ipv6_addr = "2001:db8::1".parse().unwrap();
        let subscription_info = SubscriptionInfo::new(SocketAddr::new(ipv6_addr, 8080))
            .with_subscription_id(1)
            .with_content_id("test-subscription".to_string());
        let message_wrapper = create_test_telemetry_message_wrapper();
        let input = (subscription_info, message_wrapper);

        let key = converter.get_key(&input);
        assert_eq!(
            key.unwrap(),
            serde_json::Value::String("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_serialize_json_success() {
        let schema_file = create_test_schema_file();
        let converter = TelemetryYangConverter::new(schema_file.path().to_path_buf());

        let subscription_info = create_test_subscription_info();
        let message_wrapper = create_test_telemetry_message_wrapper();
        let input = (subscription_info, message_wrapper);

        let result = converter.serialize_json(input);

        assert!(result.is_ok());
        let json_value = result.unwrap();

        println!("{}", serde_json::to_string(&json_value).unwrap());

        let expected_json_str = r#"{
    "ietf-telemetry-message:message": {
        "telemetry-message-metadata": {
            "collection-timestamp": "1970-01-01T00:00:00Z",
            "session-protocol": "yp-push",
            "export-address": "127.0.0.1"
        },
        "network-operator-metadata": {
            "labels": []
        }
    }
}"#;

        let expected_json: serde_json::Value =
            serde_json::from_str(expected_json_str).expect("Expected JSON should be valid");

        assert_eq!(json_value, expected_json);
    }
}
