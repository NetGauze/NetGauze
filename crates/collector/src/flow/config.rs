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

use crate::flow::{EnrichedFlow, RawValue};
use apache_avro::types::ValueKind as AvroValueKind;
use netgauze_flow_pkt::{
    ie,
    ie::{FieldConversionError, InformationElementDataType, InformationElementTemplate, IE},
    ipfix, netflow, FlatFlowInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowOutputConfig {
    pub fields: indexmap::IndexMap<String, FieldConfig>,
}

impl FlowOutputConfig {
    fn get_fields(fields: &indexmap::IndexMap<String, FieldConfig>, indent: usize) -> Vec<String> {
        let mut fields_schema = vec![];
        let mut custom_primitives = false;
        for (field, config) in fields {
            if field.contains("custom_primitives.") {
                custom_primitives = true;
            } else {
                fields_schema.push(format!("{:indent$}{}", "", config.get_record_schema(field)));
            }
        }
        if custom_primitives {
            fields_schema.push(format!("{:indent$}{{\"name\": \"custom_primitives\", \"type\": {{\"type\": \"map\", \"values\": \"string\"}} }}", ""));
        }
        fields_schema
    }

    pub fn get_avro_schema(&self) -> String {
        let indent = 2usize;
        let mut schema = "{\n".to_string();
        schema.push_str(format!("{:indent$}\"type\": \"record\",\n", "", indent = indent).as_str());
        schema.push_str(
            format!("{:indent$}\"name\": \"acct_data\",\n", "", indent = indent).as_str(),
        );
        // TODO: add fields extracted from the Enriched metadata
        schema.push_str(format!("{:indent$}\"fields\": [\n", "", indent = indent).as_str());
        let fields_schema = Self::get_fields(&self.fields, 4);
        schema.push_str(format!("{}\n", fields_schema.join(",\n")).as_str());
        schema.push_str(format!("{:indent$}]\n", "").as_str());
        schema.push('}');
        schema
    }

    pub fn get_avro_value(
        &self,
        enriched_flow: EnrichedFlow,
    ) -> Result<apache_avro::types::Value, FunctionError> {
        let mut fields = vec![];
        let mut custom_primitives = indexmap::IndexMap::new();
        for (name, field_config) in &self.fields {
            let value = field_config.avro_value(&enriched_flow.flow)?;
            if name.starts_with("custom_primitives.") {
                let name = name.trim_start_matches("custom_primitives.").to_string();
                custom_primitives.insert(name, value.unwrap());
            } else {
                let value = if field_config.is_nullable() {
                    value
                        .map(|x| apache_avro::types::Value::Union(1, Box::new(x)))
                        .unwrap_or(apache_avro::types::Value::Null)
                } else {
                    value.unwrap()
                };
                fields.push((name.clone(), value));
            }
        }
        fields.push((
            "custom_primitives".to_string(),
            apache_avro::types::Value::Map(custom_primitives.into_iter().collect()),
        ));
        Ok(apache_avro::types::Value::Record(fields))
    }
}

/// Configure how fields are selected and what transformations are applied for
/// each IE in the [FlatFlowInfo]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConfig {
    /// Select one more [IE] fields from [FlatFlowInfo]
    select: FieldSelectFunction,

    /// Set a default value if the selected field is null
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    default: Option<RawValue>,

    /// Apply a transformation on the selected fields
    #[serde(default, skip_serializing_if = "FieldTransformFunction::is_identity")]
    transform: FieldTransformFunction,
}

impl FieldConfig {
    pub fn get_record_schema(&self, name: &str) -> String {
        let mut schema = "{ ".to_string();
        schema.push_str(format!("\"name\": \"{name}\", ").as_str());
        if self.is_nullable() {
            schema.push_str(
                format!("\"type\": [\"null\", \"{:?}\"] ", self.avro_type())
                    .to_lowercase()
                    .as_str(),
            );
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

    pub fn avro_type(&self) -> apache_avro::types::ValueKind {
        self.transform.avro_type(self.select.avro_type())
    }

    pub fn avro_value(
        &self,
        flow: &FlatFlowInfo,
    ) -> Result<Option<apache_avro::types::Value>, FunctionError> {
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
        flow: &FlatFlowInfo,
    ) -> Result<Option<serde_json::Value>, FunctionError> {
        let selected = self.select.apply(flow);
        let transformed = self.transform.apply(selected)?;
        let value = match transformed {
            Some(value) => Some(value),
            None => self.default.clone(),
        };
        Ok(value.map(|x| x.into_json_value()))
    }
}

/// Select a field from [FlatFlowInfo]
pub trait FieldSelect {
    /// Return true if a field can be a null value
    fn is_nullable(&self) -> bool;

    /// Returns the appropriate primitive avro type for the given field.
    ///
    /// Note: if field is nullable, still the basic type is returned
    /// not a union of null and type as defined by AVRO.
    fn avro_type(&self) -> AvroValueKind;

    /// Select a value from the given flow
    fn apply(&self, flow: &FlatFlowInfo) -> Option<Vec<ie::Field>>;
}

/// An enum for all supported Field selection functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldSelectFunction {
    Single(SingleFieldSelect),
    Coalesce(CoalesceFieldSelect),
    Mpls(MultiSelect),
}

impl FieldSelect for FieldSelectFunction {
    fn is_nullable(&self) -> bool {
        match self {
            FieldSelectFunction::Single(f) => f.is_nullable(),
            FieldSelectFunction::Coalesce(f) => f.is_nullable(),
            FieldSelectFunction::Mpls(f) => f.is_nullable(),
        }
    }

    fn avro_type(&self) -> AvroValueKind {
        match self {
            FieldSelectFunction::Single(f) => f.avro_type(),
            FieldSelectFunction::Coalesce(f) => f.avro_type(),
            FieldSelectFunction::Mpls(f) => f.avro_type(),
        }
    }
    fn apply(&self, flow: &FlatFlowInfo) -> Option<Vec<ie::Field>> {
        match self {
            FieldSelectFunction::Single(single) => single.apply(flow),
            FieldSelectFunction::Coalesce(coalesce) => coalesce.apply(flow),
            FieldSelectFunction::Mpls(coalesce) => coalesce.apply(flow),
        }
    }
}

/// When a [SingleFieldSelect] doesn't define an index, then assume this
/// value as default index.
const fn default_field_index() -> usize {
    0
}

/// Selects a single field from [FlatFlowInfo]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleFieldSelect {
    pub ie: IE,
    #[serde(default = "default_field_index")]
    pub index: usize,
}

impl FieldSelect for SingleFieldSelect {
    fn is_nullable(&self) -> bool {
        true
    }

    fn avro_type(&self) -> AvroValueKind {
        ie_avro_type(self.ie)
    }

    fn apply(&self, flow: &FlatFlowInfo) -> Option<Vec<ie::Field>> {
        match flow {
            FlatFlowInfo::NetFlowV9(packet) => match packet.set() {
                netflow::FlatSet::Template(_) => None,
                netflow::FlatSet::OptionsTemplate(_) => None,
                netflow::FlatSet::Data { id: _id, record } => record
                    .fields()
                    .get(self.ie)
                    .get(self.index)
                    .cloned()
                    .map(|x| vec![x]),
            },
            FlatFlowInfo::IPFIX(packet) => match packet.set() {
                ipfix::FlatSet::Template(_) => None,
                ipfix::FlatSet::OptionsTemplate(_) => None,
                ipfix::FlatSet::Data { id: _id, record } => record
                    .fields()
                    .get(self.ie)
                    .get(self.index)
                    .cloned()
                    .map(|x| vec![x]),
            },
        }
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
        let avro_type = self.ies.iter().map(|x| x.ie).collect::<HashSet<_>>();
        if avro_type.len() == 1 {
            self.ies[0].avro_type()
        } else {
            AvroValueKind::String
        }
    }

    fn apply(&self, flow: &FlatFlowInfo) -> Option<Vec<ie::Field>> {
        match flow {
            FlatFlowInfo::NetFlowV9(packet) => match packet.set() {
                netflow::FlatSet::Template(_) => None,
                netflow::FlatSet::OptionsTemplate(_) => None,
                netflow::FlatSet::Data { id: _id, record: _ } => {
                    for single in &self.ies {
                        if let Some(field) = single.apply(flow) {
                            return Some(field.clone());
                        }
                    }
                    None
                }
            },
            FlatFlowInfo::IPFIX(packet) => match packet.set() {
                ipfix::FlatSet::Template(_) => None,
                ipfix::FlatSet::OptionsTemplate(_) => None,
                ipfix::FlatSet::Data { id: _id, record: _ } => {
                    for single in &self.ies {
                        if let Some(field) = single.apply(flow) {
                            return Some(field.clone());
                        }
                    }
                    None
                }
            },
        }
    }
}

/// Special select for all MPLS labels into one array
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

    fn apply(&self, flow: &FlatFlowInfo) -> Option<Vec<ie::Field>> {
        match flow {
            FlatFlowInfo::NetFlowV9(packet) => match packet.set() {
                netflow::FlatSet::Template(_) => None,
                netflow::FlatSet::OptionsTemplate(_) => None,
                netflow::FlatSet::Data { id: _id, record: _ } => {
                    let mut ret = vec![];
                    for single in &self.ies {
                        if let Some(field) = single.apply(flow) {
                            for f in field {
                                ret.push(f);
                            }
                        }
                    }
                    Some(ret)
                }
            },
            FlatFlowInfo::IPFIX(packet) => match packet.set() {
                ipfix::FlatSet::Template(_) => None,
                ipfix::FlatSet::OptionsTemplate(_) => None,
                ipfix::FlatSet::Data { id: _id, record: _ } => {
                    let mut ret = vec![];
                    for single in &self.ies {
                        if let Some(field) = single.apply(flow) {
                            for f in field {
                                ret.push(f);
                            }
                        }
                    }
                    Some(ret)
                }
            },
        }
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

#[derive(Debug, Clone)]
pub enum FunctionError {
    FieldConversionError(FieldConversionError),
    FieldIndexNotFound(usize),
    UnexpectedField(ie::Field),
}

impl From<FieldConversionError> for FunctionError {
    fn from(value: FieldConversionError) -> Self {
        Self::FieldConversionError(value)
    }
}

impl std::fmt::Display for FunctionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldConversionError(err) => write!(f, "Field Conversion Error: {err}"),
            Self::FieldIndexNotFound(index) => write!(f, "Field Index Not Found: {index}"),
            Self::UnexpectedField(field) => write!(f, "Unexpected field: {field}"),
        }
    }
}

impl std::error::Error for FunctionError {}

/// Field transformation functions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum FieldTransformFunction {
    /// No transformation is applied
    #[default]
    Identity,

    /// Convert the value into a string
    String,

    /// Convert the value to string and rename.
    /// If no key is given for the rename, then the name is passed as is
    Rename(indexmap::IndexMap<String, String>),

    /// Index MPLS labels
    MplsIndex,
}

impl FieldTransformFunction {
    pub const fn is_identity(&self) -> bool {
        matches!(self, FieldTransformFunction::Identity)
    }

    pub fn avro_type(&self, identity_type: AvroValueKind) -> AvroValueKind {
        match self {
            Self::Identity => identity_type,
            Self::String => AvroValueKind::String,
            Self::Rename(_) => AvroValueKind::String,
            Self::MplsIndex => AvroValueKind::Array,
        }
    }

    pub fn apply(&self, field: Option<Vec<ie::Field>>) -> Result<Option<RawValue>, FunctionError> {
        let mut field = if let Some(field) = field {
            field
        } else {
            return Ok(None);
        };
        match self {
            Self::Identity => Ok(field.pop().map(|x| x.into())),
            Self::String => {
                if let Some(field) = field.pop() {
                    Ok(Some(RawValue::String(field.try_into()?)))
                } else {
                    Ok(None)
                }
            }
            Self::Rename(rename_fields) => {
                if let Some(field) = field.pop() {
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
            Self::MplsIndex => {
                let mut ret = vec![];
                for field in field {
                    fn format_mpls(num: u8, v: Vec<u8>) -> String {
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
                        ie::Field::mplsLabelStackSection(v) => ret.push(format_mpls(1, v)),
                        ie::Field::mplsLabelStackSection2(v) => ret.push(format_mpls(2, v)),
                        ie::Field::mplsLabelStackSection3(v) => ret.push(format_mpls(3, v)),
                        ie::Field::mplsLabelStackSection4(v) => ret.push(format_mpls(4, v)),
                        ie::Field::mplsLabelStackSection5(v) => ret.push(format_mpls(5, v)),
                        ie::Field::mplsLabelStackSection6(v) => ret.push(format_mpls(6, v)),
                        ie::Field::mplsLabelStackSection7(v) => ret.push(format_mpls(7, v)),
                        ie::Field::mplsLabelStackSection8(v) => ret.push(format_mpls(8, v)),
                        ie::Field::mplsLabelStackSection9(v) => ret.push(format_mpls(9, v)),
                        ie::Field::mplsLabelStackSection10(v) => ret.push(format_mpls(10, v)),
                        _ => return Err(FunctionError::UnexpectedField(field)),
                    }
                }
                Ok(Some(RawValue::StringArray(ret)))
            }
        }
    }
}
