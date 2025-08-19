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

pub mod aggregation;
pub mod config;
pub mod enrichment;
pub mod sonata;
pub mod sonata_enrichment;
pub mod types;

use apache_avro::types::{Value as AvroValue, ValueKind as AvroValueKind};
use netgauze_flow_pkt::{
    ie,
    ie::{HasIE, InformationElementDataType, InformationElementTemplate},
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// The supported subset of AVRO values
///
/// RawValue is needed because:
/// 1. [apache_avro::types::Value] is not serializable, thus not suitable to use
///    in a config.
/// 2. We support only a subset of [apache_avro::types::Value].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, strum_macros::EnumDiscriminants)]
#[strum_discriminants(name(ValueKind))]
pub enum RawValue {
    Bytes(Vec<u8>),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Boolean(bool),
    String(String),
    TimestampMillis(i64),
    StringArray(Vec<String>),
    StringMap(HashMap<String, String>),
}

impl RawValue {
    pub const fn avro_type(&self) -> AvroValueKind {
        match self {
            Self::Bytes(_) => AvroValueKind::Bytes,
            Self::U8(_) => AvroValueKind::Int,
            Self::U16(_) => AvroValueKind::Int,
            Self::U32(_) => AvroValueKind::Long,
            Self::U64(_) => AvroValueKind::Long,
            Self::I8(_) => AvroValueKind::Int,
            Self::I16(_) => AvroValueKind::Int,
            Self::I32(_) => AvroValueKind::Int,
            Self::I64(_) => AvroValueKind::Long,
            Self::F32(_) => AvroValueKind::Float,
            Self::F64(_) => AvroValueKind::Double,
            Self::Boolean(_) => AvroValueKind::Boolean,
            Self::String(_) => AvroValueKind::String,
            Self::TimestampMillis(_) => AvroValueKind::TimestampMillis,
            Self::StringArray(_) => AvroValueKind::Array,
            Self::StringMap(_) => AvroValueKind::Map,
        }
    }

    pub fn into_avro_value(self) -> AvroValue {
        match self {
            Self::Bytes(bytes) => AvroValue::Bytes(bytes),
            Self::U8(v) => AvroValue::Int(v.into()),
            Self::U16(v) => AvroValue::Int(v.into()),
            Self::U32(v) => AvroValue::Long(v.into()),
            Self::U64(v) => AvroValue::Long(v as i64),
            Self::I8(v) => AvroValue::Int(v.into()),
            Self::I16(v) => AvroValue::Int(v.into()),
            Self::I32(v) => AvroValue::Int(v),
            Self::I64(v) => AvroValue::Long(v),
            Self::F32(v) => AvroValue::Float(v),
            Self::F64(v) => AvroValue::Double(v),
            Self::Boolean(v) => AvroValue::Boolean(v),
            Self::String(v) => AvroValue::String(v),
            Self::TimestampMillis(v) => AvroValue::TimestampMillis(v),
            Self::StringArray(v) => {
                AvroValue::Array(v.into_iter().map(AvroValue::String).collect())
            }
            Self::StringMap(v) => AvroValue::Map(
                v.into_iter()
                    .map(|(k, v)| (k, AvroValue::String(v)))
                    .collect(),
            ),
        }
    }

    pub fn into_json_value(self) -> JsonValue {
        match self {
            Self::Bytes(v) => JsonValue::from(v),
            Self::U8(v) => JsonValue::from(v),
            Self::U16(v) => JsonValue::from(v),
            Self::U32(v) => JsonValue::from(v),
            Self::U64(v) => JsonValue::from(v),
            Self::I8(v) => JsonValue::from(v),
            Self::I16(v) => JsonValue::from(v),
            Self::I32(v) => JsonValue::from(v),
            Self::I64(v) => JsonValue::from(v),
            Self::F32(v) => JsonValue::from(v),
            Self::F64(v) => JsonValue::from(v),
            Self::Boolean(v) => JsonValue::from(v),
            Self::String(v) => JsonValue::from(v),
            Self::TimestampMillis(v) => JsonValue::from(v),
            Self::StringArray(v) => {
                JsonValue::Array(v.into_iter().map(JsonValue::String).collect())
            }
            Self::StringMap(v) => JsonValue::Object(
                v.into_iter()
                    .map(|(k, v)| (k, JsonValue::String(v)))
                    .collect(),
            ),
        }
    }
}

impl From<ie::Field> for RawValue {
    fn from(val: ie::Field) -> Self {
        let cloned = val.clone();
        let converted = match val.ie().data_type() {
            InformationElementDataType::octetArray => val
                .try_into()
                .map(|x: Box<[u8]>| RawValue::Bytes(x.to_vec())),
            InformationElementDataType::unsigned8 => val.try_into().map(RawValue::U8),
            InformationElementDataType::unsigned16 => val.try_into().map(RawValue::U16),
            InformationElementDataType::unsigned32 => val.try_into().map(RawValue::U32),
            InformationElementDataType::unsigned64 => val.try_into().map(RawValue::U64),
            InformationElementDataType::signed8 => val.try_into().map(RawValue::I8),
            InformationElementDataType::signed16 => val.try_into().map(RawValue::I16),
            InformationElementDataType::signed32 => val.try_into().map(RawValue::I32),
            InformationElementDataType::signed64 => val.try_into().map(RawValue::I64),
            InformationElementDataType::float32 => val
                .try_into()
                .map(|x: ordered_float::OrderedFloat<f32>| RawValue::F32(x.0)),
            InformationElementDataType::float64 => val
                .try_into()
                .map(|x: ordered_float::OrderedFloat<f64>| RawValue::F64(x.0)),
            InformationElementDataType::boolean => val.try_into().map(RawValue::Boolean),
            InformationElementDataType::macAddress => val.try_into().map(RawValue::String),
            InformationElementDataType::string => val.try_into().map(RawValue::String),
            // TODO: support the various timestamps in AVRO: timestamp-millis and timestamp-micro
            InformationElementDataType::dateTimeSeconds
            | InformationElementDataType::dateTimeMilliseconds
            | InformationElementDataType::dateTimeMicroseconds
            | InformationElementDataType::dateTimeNanoseconds => {
                val.try_into().map(RawValue::TimestampMillis)
            }
            InformationElementDataType::ipv4Address => val.try_into().map(RawValue::String),
            InformationElementDataType::ipv6Address => val.try_into().map(RawValue::String),
            InformationElementDataType::basicList => val
                .try_into()
                .map(|x: Box<[u8]>| RawValue::Bytes(x.to_vec())),
            InformationElementDataType::subTemplateList => val
                .try_into()
                .map(|x: Box<[u8]>| RawValue::Bytes(x.to_vec())),
            InformationElementDataType::subTemplateMultiList => val
                .try_into()
                .map(|x: Box<[u8]>| RawValue::Bytes(x.to_vec())),
            InformationElementDataType::unsigned256 => val
                .try_into()
                .map(|x: Box<[u8; 32]>| RawValue::Bytes(x.to_vec())),
        };
        match converted {
            Ok(v) => v,
            Err(_) => cloned.try_into().map(RawValue::String).unwrap(),
        }
    }
}
