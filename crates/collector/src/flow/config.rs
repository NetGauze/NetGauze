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

//! NetGauze Module for Flow Record Configuration and Transformation
//!
//! This module provides functionality for configuring and transforming flow
//! records from NetFlow and IPFIX formats. The main components are:
//!
//! - `FlowOutputConfig`: Defines the output schema and field configurations
//! - `FieldConfig`: Configures field selection and transformations
//! - `FieldSelectFunction`: Methods for selecting fields from flow records
//! - `FieldTransformFunction`: Functions to transform selected field values
//!
//! Flow records can be transformed into AVRO or JSON formats with customizable
//! field selection, renaming, and type conversions.

use crate::flow::RawValue;
use crate::flow::types::FieldRef;
use crate::publishers::kafka_avro::{AvroConverter, KafkaAvroPublisherActorError};
use apache_avro::types::{Value as AvroValue, ValueKind as AvroValueKind};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use netgauze_flow_pkt::FlowInfo;
use netgauze_flow_pkt::ie::{
    self, Field, FieldConversionError, HasIE, IE, InformationElementDataType,
    InformationElementTemplate,
};
use netgauze_flow_pkt::ipfix::{DataRecord, Set};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, strum_macros::Display)]
pub enum FlowOutputConfigValidationError {
    #[strum(to_string = "Invalid FieldConfig for {0}, reason: {1}")]
    InvalidFieldConfig(String, String),
}

impl std::error::Error for FlowOutputConfigValidationError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowOutputConfig {
    pub fields: IndexMap<String, FieldConfig>,
}

impl FlowOutputConfig {
    pub fn validate(&self) -> Result<(), FlowOutputConfigValidationError> {
        for (name, field_config) in &self.fields {
            field_config.validate().map_err(|e| {
                FlowOutputConfigValidationError::InvalidFieldConfig(name.to_string(), e.to_string())
            })?;
        }
        Ok(())
    }

    fn get_fields_schema(&self, indent: usize) -> Vec<String> {
        let mut fields_schema = vec![];
        let mut custom_primitives = false;
        for (field, config) in &self.fields {
            if field.contains("custom_primitives.") {
                custom_primitives = true;
            } else {
                fields_schema.push(format!(
                    "{:indent$}{}",
                    "",
                    config.get_record_schema(
                        field,
                        if matches!(
                            config.transform,
                            FieldTransformFunction::StringArray
                                | FieldTransformFunction::StringArrayAgg
                                | FieldTransformFunction::StringMapAgg(_)
                                | FieldTransformFunction::MplsIndex
                        ) {
                            Some(AvroValueKind::String)
                        } else {
                            None
                        }
                    )
                ));
            }
        }
        if custom_primitives {
            fields_schema.push(format!("{:indent$}{{ \"name\": \"custom_primitives\", \"type\": {{\"type\": \"map\", \"values\": \"string\"}} }}", ""));
        }
        fields_schema
    }

    fn get_avro_value(&self, record: &DataRecord) -> Result<AvroValue, FunctionError> {
        let mut fields = Vec::<(String, AvroValue)>::with_capacity(self.fields.len());
        let mut custom_primitives = IndexMap::new();

        // Store fields indexed by FieldRef (IE, index)
        let fields_map = FieldRef::map_fields_into_fxhashmap(record.fields());

        // Collect required fields to construct avro record
        for (name, field_config) in &self.fields {
            let value = field_config.avro_value(&fields_map)?;

            if let Some(stripped_name) = name.strip_prefix("custom_primitives.") {
                if let Some(value) = value {
                    custom_primitives.insert(stripped_name.to_string(), value);
                }
            } else {
                let value = if field_config.is_nullable() {
                    value
                        .map(|x| AvroValue::Union(1, Box::new(x)))
                        .unwrap_or(AvroValue::Null)
                } else if let Some(value) = value {
                    value
                } else {
                    return Err(FunctionError::FieldIsNull(name.to_string()));
                };
                fields.push((name.clone(), value));
            }
        }

        if !custom_primitives.is_empty() {
            fields.push((
                "custom_primitives".to_string(),
                AvroValue::Map(custom_primitives.into_iter().collect()),
            ));
        }

        Ok(AvroValue::Record(fields))
    }
}

impl AvroConverter<(IpAddr, FlowInfo), FunctionError> for FlowOutputConfig {
    fn get_avro_schema(&self) -> String {
        let indent = 2usize;

        // Initialize schema
        let mut schema = "{\n".to_string();
        schema.push_str(format!("{:indent$}\"type\": \"record\",\n", "", indent = indent).as_str());
        schema.push_str(
            format!("{:indent$}\"name\": \"acct_data\",\n", "", indent = indent).as_str(),
        );
        schema.push_str(format!("{:indent$}\"fields\": [\n", "", indent = indent).as_str());

        // Push custom fields to the schema
        let mut fields_schema = vec![];
        fields_schema.extend(self.get_fields_schema(4));

        // Finalize schema
        schema.push_str(format!("{}\n", fields_schema.join(",\n")).as_str());
        schema.push_str(format!("{:indent$}]\n", "").as_str());
        schema.push('}');
        schema
    }

    fn get_key(&self, input: &(IpAddr, FlowInfo)) -> Option<JsonValue> {
        Some(JsonValue::String(input.0.to_string()))
    }

    // At the moment we only have a single record per FlowInfo -> pre-allocate 1
    type AvroValues = SmallVec<[AvroValue; 1]>;
    fn get_avro_values(
        &self,
        input: (IpAddr, FlowInfo),
    ) -> Result<Self::AvroValues, FunctionError> {
        match input.1 {
            FlowInfo::IPFIX(pkt) => pkt
                .sets()
                .iter()
                .filter_map(|set| match set {
                    Set::Data { id: _, records } => Some(records),
                    _ => None,
                })
                .flatten()
                .map(|record| self.get_avro_value(record))
                .collect::<Result<SmallVec<_>, _>>(),
            FlowInfo::NetFlowV9(_) => {
                Err(FunctionError::UnsupportedFlowType("NetFlowV9".to_string()))
            }
        }
    }
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum FieldConfigValidationError {
    #[strum(to_string = "Coalesce list cannot be empty")]
    EmptyCoalesceList,

    #[strum(to_string = "Multi-select list cannot be empty")]
    EmptyMultiList,

    #[strum(to_string = "Invalid transform: {0}")]
    InvalidTransform(String),

    #[strum(to_string = "Incompatible default: {0}")]
    IncompatibleDefault(String),
}

impl std::error::Error for FieldConfigValidationError {}

/// Configure how fields are selected and what transformations are applied for
/// each IE in the [FlowInfo]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConfig {
    /// Select one more [IE] fields from [FlowInfo]
    select: FieldSelectFunction,

    /// Set a default value if the selected field is null
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    default: Option<RawValue>,

    /// Apply a transformation on the selected fields
    #[serde(default, skip_serializing_if = "FieldTransformFunction::is_identity")]
    transform: FieldTransformFunction,
}

impl FieldConfig {
    /// Validate that the transform and default are compatible with the selected
    /// IE(s)
    pub fn validate(&self) -> Result<(), FieldConfigValidationError> {
        let ies = match &self.select {
            FieldSelectFunction::Single(s) => vec![s.ie()],
            FieldSelectFunction::Coalesce(c) => c.ies.iter().map(|s| s.ie()).collect(),
            FieldSelectFunction::Multi(m) => m.ies.iter().map(|s| s.ie()).collect(),
            FieldSelectFunction::Layer2SegmentId(l2) => vec![l2.single_select.ie()],
        };

        if ies.is_empty() {
            return Err(match &self.select {
                FieldSelectFunction::Coalesce(_) => FieldConfigValidationError::EmptyCoalesceList,
                FieldSelectFunction::Multi(_) => FieldConfigValidationError::EmptyMultiList,
                _ => unreachable!(), // will fail at struct serde due to missing ie field
            });
        }

        self.validate_select_transform_compatibility(&ies)?;

        for ie in &ies {
            self.validate_ie_compatibility(*ie)?;
        }

        if let Some(default) = &self.default {
            self.validate_default(default)?;
        }

        Ok(())
    }

    fn validate_select_transform_compatibility(
        &self,
        ies: &[IE],
    ) -> Result<(), FieldConfigValidationError> {
        use {FieldSelectFunction as SF, FieldTransformFunction as TF};

        match (&self.select, &self.transform) {
            (SF::Multi(_), TF::StringArrayAgg | TF::StringMapAgg(_) | TF::MplsIndex) => {
                // Validate StringMapAgg rename keys match selected IEs
                if let TF::StringMapAgg(Some(rename_map)) = &self.transform {
                    let ie_set: HashSet<_> = ies.iter().copied().collect();
                    for ie in rename_map.keys() {
                        if !ie_set.contains(ie) {
                            return Err(FieldConfigValidationError::InvalidTransform(format!(
                                "StringMapAgg rename references {ie} not in Multi select"
                            )));
                        }
                    }
                }
                Ok(())
            }

            // Multi selection requires an aggregating transform
            (SF::Multi(_), other) => Err(FieldConfigValidationError::InvalidTransform(format!(
                "Transform {:?} cannot be used with Multi selection. Use an aggregating \
                 transform ('StringArrayAgg', 'StringMapAgg', or 'MplsIndex'). IEs: {}",
                other,
                ies.iter()
                    .map(|ie| format!("{} ({:?})", ie, ie.data_type()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),

            // Single or Coalesce selection cannot be used with aggregating transforms
            (
                SF::Single(_) | SF::Coalesce(_) | SF::Layer2SegmentId(_),
                TF::StringArrayAgg | TF::StringMapAgg(_) | TF::MplsIndex,
            ) => Err(FieldConfigValidationError::InvalidTransform(format!(
                "Transform {:?} requires Multi selection. IEs: {}",
                self.transform,
                ies.iter()
                    .map(|ie| format!("{} ({:?})", ie, ie.data_type()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),

            // Coalesce selection with mixed types requires explicit transform
            (SF::Coalesce(_), TF::Identity) => {
                let first_type = ie_avro_type(ies[0]);
                if ies.iter().any(|ie| ie_avro_type(*ie) != first_type) {
                    return Err(FieldConfigValidationError::InvalidTransform(format!(
                        "Coalesce selection with mixed types require explicit \
                        transform ('String', 'TrimmedString', 'LowercaseString', \
                       'TimestampMillisString', 'Rename'). IEs: {}",
                        ies.iter()
                            .map(|ie| format!("{} ({:?})", ie, ie.data_type()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                Ok(())
            }

            // Layer2SegmentId must use correct IE
            (SF::Layer2SegmentId(_), _) if ies.len() != 1 || ies[0] != IE::layer2SegmentId => {
                Err(FieldConfigValidationError::InvalidTransform(
                    "Layer2SegmentId requires layer2SegmentId IE".to_string(),
                ))
            }

            // All other combinations are valid
            _ => Ok(()),
        }
    }

    fn validate_ie_compatibility(&self, ie: IE) -> Result<(), FieldConfigValidationError> {
        use FieldTransformFunction as TF;

        match &self.transform {
            TF::TimestampMillisString => {
                if !matches!(
                    ie.data_type(),
                    InformationElementDataType::dateTimeSeconds
                        | InformationElementDataType::dateTimeMilliseconds
                        | InformationElementDataType::dateTimeMicroseconds
                        | InformationElementDataType::dateTimeNanoseconds
                ) {
                    return Err(FieldConfigValidationError::InvalidTransform(format!(
                        "TimestampMillisString requires timestamp IE, got {} ({:?})",
                        ie,
                        ie.data_type()
                    )));
                }
            }

            TF::StringArray => {
                if ie != IE::tcpControlBits {
                    return Err(FieldConfigValidationError::InvalidTransform(format!(
                        "StringArray currently only works with tcpControlBits, got {ie}"
                    )));
                }
            }

            TF::MplsIndex => {
                if !matches!(
                    ie,
                    IE::mplsLabelStackSection
                        | IE::mplsLabelStackSection2
                        | IE::mplsLabelStackSection3
                        | IE::mplsLabelStackSection4
                        | IE::mplsLabelStackSection5
                        | IE::mplsLabelStackSection6
                        | IE::mplsLabelStackSection7
                        | IE::mplsLabelStackSection8
                        | IE::mplsLabelStackSection9
                        | IE::mplsLabelStackSection10
                ) {
                    return Err(FieldConfigValidationError::InvalidTransform(format!(
                        "MplsIndex requires MPLS label stack fields, got {ie}"
                    )));
                }
            }

            // String transforms require TryInto<String> (implemented for all types except Bytes)
            TF::String
            | TF::TrimmedString
            | TF::LowercaseString
            | TF::Rename(_)
            | TF::StringArrayAgg
            | TF::StringMapAgg(_) => {
                if ie_avro_type(ie) == AvroValueKind::Bytes {
                    return Err(FieldConfigValidationError::InvalidTransform(format!(
                        "{:?} requires String conversion, but {} is Bytes type ({:?})",
                        self.transform,
                        ie,
                        ie.data_type()
                    )));
                }
            }

            TF::Identity => {}
        }

        Ok(())
    }

    fn validate_default(&self, default: &RawValue) -> Result<(), FieldConfigValidationError> {
        let expected = self.avro_type();
        let actual = default.avro_type();

        if expected != actual {
            Err(FieldConfigValidationError::IncompatibleDefault(format!(
                "Default type mismatch: expected {expected:?}, {actual:?}"
            )))
        } else {
            Ok(())
        }
    }

    pub fn get_record_schema(&self, name: &str, inner_val: Option<AvroValueKind>) -> String {
        let mut schema = "{ ".to_string();
        schema.push_str(format!("\"name\": \"{name}\", ").as_str());
        if self.is_nullable() {
            if self.avro_type() == AvroValueKind::Array {
                if let Some(inner_val) = inner_val {
                    schema.push_str(
                        format!(
                            "\"type\": [\"null\", {{\"type\": \"{:?}\", \"items\": \"{:?}\"}}] ",
                            self.avro_type(),
                            inner_val
                        )
                        .to_lowercase()
                        .as_str(),
                    );
                }
            } else if self.avro_type() == AvroValueKind::Map {
                if let Some(inner_val) = inner_val {
                    schema.push_str(
                        format!(
                            "\"type\": [\"null\", {{\"type\": \"{:?}\", \"values\": \"{:?}\"}}] ",
                            self.avro_type(),
                            inner_val
                        )
                        .to_lowercase()
                        .as_str(),
                    );
                }
            } else {
                schema.push_str(
                    format!("\"type\": [\"null\", \"{:?}\"] ", self.avro_type())
                        .to_lowercase()
                        .as_str(),
                );
            }
        } else if self.avro_type() == AvroValueKind::Array {
            if let Some(inner_val) = inner_val {
                schema.push_str(
                    format!(
                        "\"type\": {{\"type\": \"{:?}\", \"items\": \"{:?}\"}} ",
                        self.avro_type(),
                        inner_val
                    )
                    .to_lowercase()
                    .as_str(),
                );
            }
        } else if self.avro_type() == AvroValueKind::Map {
            if let Some(inner_val) = inner_val {
                schema.push_str(
                    format!(
                        "\"type\": {{\"type\": \"{:?}\", \"values\": \"{:?}\"}} ",
                        self.avro_type(),
                        inner_val
                    )
                    .to_lowercase()
                    .as_str(),
                );
            }
        } else {
            schema.push_str(
                format!("\"type\": \"{:?}\" ", self.avro_type())
                    .to_lowercase()
                    .as_str(),
            );
        }
        schema.push('}');
        schema
    }

    pub fn is_nullable(&self) -> bool {
        self.select.is_nullable() && self.default.is_none()
    }

    pub fn avro_type(&self) -> AvroValueKind {
        self.transform.avro_type(self.select.avro_type())
    }

    pub fn avro_value(
        &self,
        flow: &FxHashMap<SingleFieldSelect, &Field>,
    ) -> Result<Option<AvroValue>, FunctionError> {
        let selected = self.select.apply(flow);
        let transformed = self.transform.apply(selected)?;
        let value = match transformed {
            Some(value) => Some(value),
            None => self.default.clone(),
        };
        Ok(value.map(|x| x.into_avro_value()))
    }

    pub fn json_value(
        &self,
        flow: &FxHashMap<SingleFieldSelect, &Field>,
    ) -> Result<Option<JsonValue>, FunctionError> {
        let selected = self.select.apply(flow);
        let transformed = self.transform.apply(selected)?;
        let value = match transformed {
            Some(value) => Some(value),
            None => self.default.clone(),
        };
        Ok(value.map(|x| x.into_json_value()))
    }
}

/// Select field(s) from [FlowInfo]
pub trait FieldSelect {
    /// Return true if a field can be a null value
    fn is_nullable(&self) -> bool;

    /// Returns the appropriate primitive avro type for the given field.
    ///
    /// Note: if field is nullable, still the basic type is returned
    /// not a union of null and type as defined by AVRO.
    fn avro_type(&self) -> AvroValueKind;

    /// Select a value from the given flow
    fn apply(&self, flow: &FxHashMap<SingleFieldSelect, &Field>) -> Option<Vec<Field>>;
}

/// An enum for all supported Field selection functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldSelectFunction {
    Single(SingleFieldSelect),
    Coalesce(CoalesceFieldSelect),
    Multi(MultiSelect),
    Layer2SegmentId(Layer2SegmentIdFieldSelect),
}

impl FieldSelect for FieldSelectFunction {
    fn is_nullable(&self) -> bool {
        match self {
            FieldSelectFunction::Single(f) => f.is_nullable(),
            FieldSelectFunction::Coalesce(f) => f.is_nullable(),
            FieldSelectFunction::Multi(f) => f.is_nullable(),
            FieldSelectFunction::Layer2SegmentId(f) => f.is_nullable(),
        }
    }

    fn avro_type(&self) -> AvroValueKind {
        match self {
            FieldSelectFunction::Single(f) => f.avro_type(),
            FieldSelectFunction::Coalesce(f) => f.avro_type(),
            FieldSelectFunction::Multi(f) => f.avro_type(),
            FieldSelectFunction::Layer2SegmentId(f) => f.avro_type(),
        }
    }
    fn apply(&self, flow: &FxHashMap<SingleFieldSelect, &Field>) -> Option<Vec<Field>> {
        match self {
            FieldSelectFunction::Single(single) => single.apply(flow),
            FieldSelectFunction::Coalesce(coalesce) => coalesce.apply(flow),
            FieldSelectFunction::Multi(coalesce) => coalesce.apply(flow),
            FieldSelectFunction::Layer2SegmentId(single) => single.apply(flow),
        }
    }
}

/// Selects a single field from [FlowInfo]
pub type SingleFieldSelect = FieldRef;

impl FieldSelect for SingleFieldSelect {
    fn is_nullable(&self) -> bool {
        true
    }

    fn avro_type(&self) -> AvroValueKind {
        ie_avro_type(self.ie())
    }

    fn apply(&self, flow: &FxHashMap<SingleFieldSelect, &Field>) -> Option<Vec<Field>> {
        flow.get(self).map(|&field| vec![field.clone()])
    }
}

/// Given multiple IEs, select the first field that is not null.
///
/// Notes:
/// - If no field exists then a [None] is returned.
/// - If the fields have different types, the selected value is converted to a
///   string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoalesceFieldSelect {
    pub ies: Vec<SingleFieldSelect>,
}

impl FieldSelect for CoalesceFieldSelect {
    fn is_nullable(&self) -> bool {
        true
    }

    fn avro_type(&self) -> AvroValueKind {
        if self.ies.is_empty() {
            return AvroValueKind::String;
        }

        let first_type = ie_avro_type(self.ies[0].ie());

        // return string if we find a different type
        for ie in &self.ies[1..] {
            if ie_avro_type(ie.ie()) != first_type {
                return AvroValueKind::String;
            }
        }

        first_type
    }

    fn apply(&self, flow: &FxHashMap<SingleFieldSelect, &Field>) -> Option<Vec<Field>> {
        self.ies
            .iter()
            .find_map(|single_select| single_select.apply(flow))
    }
}

/// Select multiple Fields into one array
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSelect {
    pub ies: Vec<SingleFieldSelect>,
}

impl FieldSelect for MultiSelect {
    fn is_nullable(&self) -> bool {
        true
    }

    fn avro_type(&self) -> AvroValueKind {
        AvroValueKind::Array
    }

    fn apply(&self, flow: &FxHashMap<SingleFieldSelect, &Field>) -> Option<Vec<Field>> {
        let ret: Vec<Field> = self
            .ies
            .iter()
            .filter_map(|single_select| single_select.apply(flow))
            .flatten()
            .collect();

        if ret.is_empty() { None } else { Some(ret) }
    }
}

// Layer 2 Segment ID (IE351) Encapsulation Types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum Layer2SegmentId {
    VxLAN = 0x01,
    NVGRE = 0x02,
    Unassigned(u8),
}
impl From<&Layer2SegmentId> for u8 {
    fn from(segment_id: &Layer2SegmentId) -> Self {
        match segment_id {
            Layer2SegmentId::VxLAN => 0x01,
            Layer2SegmentId::NVGRE => 0x02,
            Layer2SegmentId::Unassigned(value) => *value,
        }
    }
}
impl Layer2SegmentId {
    pub fn get_mask(&self) -> u64 {
        match self {
            // VxLAN Network Identifier (VNI) is a 24-bit identifier
            //
            // Reference: [RFC 7348](https://www.iana.org/go/rfc7348)
            Layer2SegmentId::VxLAN => 0x0000_00FF_FFFF,
            // NVGRE Tenant Network Identifier (TNI) is a 24-bit identifier
            //
            // Reference: [RFC 7637](https://www.iana.org/go/rfc7637)
            Layer2SegmentId::NVGRE => 0x0000_00FF_FFFF,
            Layer2SegmentId::Unassigned(_) => 0x00FF_FFFF_FFFF,
        }
    }
}

// Special select for Layer 2 Segment ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer2SegmentIdFieldSelect {
    #[serde(flatten)]
    pub single_select: SingleFieldSelect,

    pub encap_type: Layer2SegmentId,
}

impl FieldSelect for Layer2SegmentIdFieldSelect {
    fn is_nullable(&self) -> bool {
        true
    }

    fn avro_type(&self) -> AvroValueKind {
        AvroValueKind::Long
    }

    fn apply(&self, flow: &FxHashMap<SingleFieldSelect, &Field>) -> Option<Vec<Field>> {
        flow.get(&self.single_select).and_then(|&field| {
            // Check if it's a layer2SegmentId field
            if let ie::Field::layer2SegmentId(id) = field {
                // Check if the first byte matches the provided encap_type
                if (id >> 56) as u8 == u8::from(&self.encap_type) {
                    Some(vec![ie::Field::layer2SegmentId(
                        id & self.encap_type.get_mask(),
                    )])
                } else {
                    None
                }
            } else {
                None
            }
        })
    }
}

/// Maps IE to a primitive AVRO type
fn ie_avro_type(ie: IE) -> AvroValueKind {
    match ie.data_type() {
        InformationElementDataType::octetArray => AvroValueKind::Bytes,
        InformationElementDataType::unsigned8 => AvroValueKind::Int,
        InformationElementDataType::unsigned16 => AvroValueKind::Int,
        InformationElementDataType::unsigned32 => AvroValueKind::Long,
        InformationElementDataType::unsigned64 => AvroValueKind::Long,
        InformationElementDataType::signed8 => AvroValueKind::Int,
        InformationElementDataType::signed16 => AvroValueKind::Int,
        InformationElementDataType::signed32 => AvroValueKind::Int,
        InformationElementDataType::signed64 => AvroValueKind::Long,
        InformationElementDataType::float32 => AvroValueKind::Float,
        InformationElementDataType::float64 => AvroValueKind::Double,
        InformationElementDataType::boolean => AvroValueKind::Boolean,
        InformationElementDataType::macAddress => AvroValueKind::String,
        InformationElementDataType::string => AvroValueKind::String,
        InformationElementDataType::dateTimeSeconds => AvroValueKind::TimestampMillis,
        InformationElementDataType::dateTimeMilliseconds => AvroValueKind::TimestampMillis,
        InformationElementDataType::dateTimeMicroseconds => AvroValueKind::TimestampMicros,
        InformationElementDataType::dateTimeNanoseconds => AvroValueKind::TimestampNanos,
        InformationElementDataType::ipv4Address => AvroValueKind::String,
        InformationElementDataType::ipv6Address => AvroValueKind::String,
        InformationElementDataType::basicList => AvroValueKind::Bytes,
        InformationElementDataType::subTemplateList => AvroValueKind::Bytes,
        InformationElementDataType::subTemplateMultiList => AvroValueKind::Bytes,
        InformationElementDataType::unsigned256 => AvroValueKind::Bytes,
    }
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum FunctionError {
    #[strum(to_string = "Field conversion error: {0}")]
    FieldConversionError(FieldConversionError),
    #[strum(to_string = "Field index not found: {0}")]
    FieldIndexNotFound(usize),
    #[strum(to_string = "Unexpected field: {0}")]
    UnexpectedField(ie::Field),
    #[strum(to_string = "Field is null: {0}")]
    FieldIsNull(String),
    #[strum(to_string = "Unsupported flow type: {0}")]
    UnsupportedFlowType(String),
}

impl From<FieldConversionError> for FunctionError {
    fn from(value: FieldConversionError) -> Self {
        Self::FieldConversionError(value)
    }
}

impl std::error::Error for FunctionError {}

impl From<FunctionError> for KafkaAvroPublisherActorError {
    fn from(value: FunctionError) -> Self {
        Self::TransformationError(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct KeyValueRename {
    key_rename: String,
    #[serde(default)]
    val_rename: Option<IndexMap<String, String>>,
}

/// Field transformation functions
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub enum FieldTransformFunction {
    /// No transformation is applied
    #[default]
    Identity,

    /// Convert single value into a string
    String,

    /// Convert single value into a string and trim trailing null characters
    TrimmedString,

    /// Convert single value into lowercase string
    LowercaseString,

    /// Convert single value to TimestampMillis then to String
    TimestampMillisString,

    /// Convert single value to string and rename.
    /// If no key is given for the rename, then the name is passed as is
    Rename(IndexMap<String, String>),

    /// Convert single value to a StringArray
    StringArray,

    /// Collect multiple MPLS labels into a StringArray
    MplsIndex,

    /// Transform values to String and group in String Array
    StringArrayAgg,

    /// Transform values to String and group in Map with key = IE name
    StringMapAgg(#[serde(default)] Option<IndexMap<IE, KeyValueRename>>),
}

impl FieldTransformFunction {
    pub const fn is_identity(&self) -> bool {
        matches!(self, FieldTransformFunction::Identity)
    }

    pub fn avro_type(&self, identity_type: AvroValueKind) -> AvroValueKind {
        match self {
            Self::Identity => identity_type,
            Self::String => AvroValueKind::String,
            Self::TrimmedString => AvroValueKind::String,
            Self::LowercaseString => AvroValueKind::String,
            Self::TimestampMillisString => AvroValueKind::String,
            Self::Rename(_) => AvroValueKind::String,
            Self::StringArray => AvroValueKind::Array,
            Self::MplsIndex => AvroValueKind::Array,
            Self::StringArrayAgg => AvroValueKind::Array,
            Self::StringMapAgg(_) => AvroValueKind::Map,
        }
    }

    pub fn apply(&self, fields: Option<Vec<Field>>) -> Result<Option<RawValue>, FunctionError> {
        let fields = match fields {
            Some(fields) => fields,
            None => return Ok(None),
        };

        tracing::trace!(
            "Transform apply: transform={:?}, num_fields={}, first_field={:?}",
            self,
            fields.len(),
            fields.first().map(|f| f.ie())
        );

        match self {
            Self::Identity => Ok(fields.into_iter().last().map(|x| x.into())),

            Self::String => {
                if let Some(field) = fields.into_iter().last() {
                    Ok(Some(RawValue::String(field.try_into()?)))
                } else {
                    Ok(None)
                }
            }

            Self::TrimmedString => {
                if let Some(field) = fields.into_iter().last() {
                    let original: String = field.try_into()?;
                    let trimmed = original.trim_end_matches(char::from(0)).to_string();
                    Ok(Some(RawValue::String(trimmed)))
                } else {
                    Ok(None)
                }
            }

            Self::LowercaseString => {
                if let Some(field) = fields.into_iter().last() {
                    let original: String = field.try_into()?;
                    Ok(Some(RawValue::String(original.to_lowercase())))
                } else {
                    Ok(None)
                }
            }

            Self::TimestampMillisString => {
                if let Some(field) = fields.into_iter().last() {
                    let ts: DateTime<Utc> = field.try_into()?;
                    Ok(Some(RawValue::String(ts.timestamp().to_string())))
                } else {
                    Ok(None)
                }
            }

            Self::Rename(rename_fields) => {
                if let Some(field) = fields.into_iter().last() {
                    let string_value: String = field.try_into()?;
                    let renamed = rename_fields
                        .get(&string_value)
                        .cloned()
                        .unwrap_or(string_value);
                    Ok(Some(RawValue::String(renamed)))
                } else {
                    Ok(None)
                }
            }

            Self::StringArray => {
                if let Some(field) = fields.into_iter().last() {
                    Ok(Some(RawValue::StringArray(field.try_into()?)))
                } else {
                    Ok(None)
                }
            }

            Self::MplsIndex => {
                if fields.is_empty() {
                    return Ok(None);
                }
                let mut ret = Vec::with_capacity(fields.len());
                for field in fields {
                    fn format_mpls(num: u8, v: &[u8]) -> String {
                        format!(
                            "{num}-{}",
                            u32::from_be_bytes([
                                0,
                                *v.first().unwrap(),
                                *v.get(1).unwrap(),
                                *v.get(2).unwrap()
                            ])
                        )
                    }
                    match field {
                        ie::Field::mplsLabelStackSection(v) => ret.push(format_mpls(1, &v)),
                        ie::Field::mplsLabelStackSection2(v) => ret.push(format_mpls(2, &v)),
                        ie::Field::mplsLabelStackSection3(v) => ret.push(format_mpls(3, &v)),
                        ie::Field::mplsLabelStackSection4(v) => ret.push(format_mpls(4, &v)),
                        ie::Field::mplsLabelStackSection5(v) => ret.push(format_mpls(5, &v)),
                        ie::Field::mplsLabelStackSection6(v) => ret.push(format_mpls(6, &v)),
                        ie::Field::mplsLabelStackSection7(v) => ret.push(format_mpls(7, &v)),
                        ie::Field::mplsLabelStackSection8(v) => ret.push(format_mpls(8, &v)),
                        ie::Field::mplsLabelStackSection9(v) => ret.push(format_mpls(9, &v)),
                        ie::Field::mplsLabelStackSection10(v) => ret.push(format_mpls(10, &v)),
                        _ => return Err(FunctionError::UnexpectedField(field)),
                    }
                }
                Ok(Some(RawValue::StringArray(ret)))
            }

            Self::StringArrayAgg => {
                if fields.is_empty() {
                    Ok(None)
                } else {
                    let ret: Result<Vec<String>, _> =
                        fields.into_iter().map(|field| field.try_into()).collect();
                    Ok(Some(RawValue::StringArray(ret?)))
                }
            }

            Self::StringMapAgg(rename) => {
                if fields.is_empty() {
                    Ok(None)
                } else {
                    let mut ret = HashMap::with_capacity(fields.len());
                    for field in fields {
                        let field_ie = field.ie();
                        let field_value: String = field.try_into()?;

                        // Look for rename config for this IE
                        if let Some(rename_config) = rename.as_ref().and_then(|r| r.get(&field_ie))
                        {
                            let key = if rename_config.key_rename.is_empty() {
                                field_ie.to_string()
                            } else {
                                rename_config.key_rename.clone()
                            };

                            // Apply value rename if existing
                            let value = rename_config
                                .val_rename
                                .as_ref()
                                .and_then(|val_rename| val_rename.get(&field_value))
                                .cloned()
                                .unwrap_or(field_value);

                            ret.insert(key, value);
                        } else {
                            ret.insert(field_ie.to_string(), field_value);
                        }
                    }
                    Ok(Some(RawValue::StringMap(ret)))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
