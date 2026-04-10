// Copyright (C) 2026-present The NetGauze Authors.
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

//! BMP Avro Serialization Configuration
//!
//! This module defines configuration structures and enums for controlling
//! how BMP messages are serialized to Avro for publishing (e.g., to Kafka).
//! It allows selecting the Avro schema strategy and provides integration
//! with the AvroConverter trait for flexible serialization and publishing
//! workflows.

use crate::bmp::pmacct_schema::{
    EventType, PmacctBmpConversionError, PmacctBmpMessage, PmacctConversionContext,
};
use crate::publishers::kafka_avro::{AvroConverter, KafkaAvroPublisherActorError};
use apache_avro::AvroSchema;
use apache_avro::types::Value as AvroValue;
use netgauze_bmp_service::BmpRequest;
use schema_registry_converter::avro_common::get_supplied_schema;
use schema_registry_converter::schema_registry_common::SubjectNameStrategy;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use smallvec::SmallVec;
use std::sync::Arc;

#[derive(Debug, strum_macros::Display)]
pub enum BmpAvroConverterError {
    ConversionError(PmacctBmpConversionError),
    AvroError(apache_avro::Error),
    #[strum(to_string = "Serialization error: {0}")]
    SerializationError(serde_json::Error),
}

impl std::error::Error for BmpAvroConverterError {}

impl From<PmacctBmpConversionError> for BmpAvroConverterError {
    fn from(e: PmacctBmpConversionError) -> Self {
        Self::ConversionError(e)
    }
}

impl From<apache_avro::Error> for BmpAvroConverterError {
    fn from(e: apache_avro::Error) -> Self {
        Self::AvroError(e)
    }
}

impl From<BmpAvroConverterError> for KafkaAvroPublisherActorError {
    fn from(e: BmpAvroConverterError) -> Self {
        Self::TransformationError(e.to_string())
    }
}

impl From<serde_json::Error> for BmpAvroConverterError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e)
    }
}
/// Specifies the Avro schema type for BMP messages. Supported:
///
/// - `Union`: All BMP message types are represented as a single Avro union
///   schema.
///
/// Future variants may include separate schemas per BMP message type.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BmpAvroSchemaType {
    #[default]
    Union,
}

/// Configuration for BMP Avro serialization and publishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmpAvroConfig {
    #[serde(default)]
    pub schema_type: BmpAvroSchemaType,

    #[serde(skip)]
    pub writer_id: String,
}
impl AvroConverter<Arc<BmpRequest>, BmpAvroConverterError> for BmpAvroConfig {
    fn get_avro_schema(&self) -> Result<String, BmpAvroConverterError> {
        serde_json::to_string(&PmacctBmpMessage::get_schema()).map_err(BmpAvroConverterError::from)
    }

    fn get_subject_name_strategy(
        &self,
        topic: &str,
    ) -> Result<SubjectNameStrategy, BmpAvroConverterError> {
        let schema = apache_avro::Schema::parse_str(&self.get_avro_schema()?)
            .map_err(BmpAvroConverterError::from)?;
        Ok(SubjectNameStrategy::TopicNameStrategyWithSchema(
            topic.to_string(),
            false, // is_key = false (this is for the value, not the key)
            get_supplied_schema(&schema),
        ))
    }

    fn get_key(&self, input: &Arc<BmpRequest>) -> Option<JsonValue> {
        let (addr_info, _) = input.as_ref();
        Some(JsonValue::String(
            addr_info.remote_socket().ip().to_string(),
        ))
    }

    type AvroValues = SmallVec<[AvroValue; 16]>;
    fn get_avro_values(
        &self,
        input: Arc<BmpRequest>,
    ) -> Result<Self::AvroValues, BmpAvroConverterError> {
        let current_time = chrono::Utc::now();
        let timestamp_arrival = format!(
            "{}.{:06}",
            current_time.timestamp(),
            current_time.timestamp_subsec_micros()
        );

        let ctx = PmacctConversionContext {
            writer_id: self.writer_id.clone(),
            event_type: EventType::Log,
            timestamp_arrival,
            label: None,
            tag: None,
        };

        // Convert into PmacctBmpMessages
        let msgs = PmacctBmpMessage::try_from_bmp_request(input.as_ref(), &ctx)?;

        msgs.into_iter()
            .map(|msg| msg.get_avro_value().map_err(BmpAvroConverterError::from))
            .collect()
    }
}
