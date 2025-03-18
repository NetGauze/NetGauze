// Copyright (C) 2023-present The NetGauze Authors.
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

use crate::{
    ie::{
        Field, Fields, InformationElementDataType, InformationElementSemantics,
        InformationElementTemplate, InformationElementUnits,
    },
    DataSetId, FieldSpecifier,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::Range};

pub const NETFLOW_V9_VERSION: u16 = 9;

/// A value of 0 is reserved for Template Sets
pub(crate) const NETFLOW_TEMPLATE_SET_ID: u16 = 0;

/// A value of 3 is reserved for Options Template Sets
pub(crate) const NETFLOW_OPTIONS_TEMPLATE_SET_ID: u16 = 1;

/// Simpler template that is used to decode data records
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct DecodingTemplate {
    pub scope_fields_specs: Box<[ScopeFieldSpecifier]>,
    pub fields_specs: Box<[FieldSpecifier]>,
}

/// Cache to store templates needed for decoding data packets
pub type TemplatesMap = HashMap<u16, DecodingTemplate>;

///
/// ```text
/// +--------+-------------------------------------------+
/// |        | +----------+ +---------+ +----------+     |
/// | Packet | | Template | | Data    | | Options  |     |
/// | Header | | FlowSet  | | FlowSet | | Template | ... |
/// |        | |          | |         | | FlowSet  |     |
/// |        | +----------+ +---------+ +----------+     |
/// +--------+-------------------------------------------+
/// ```
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Version Number          |            Count              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           sysUpTime                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           UNIX Secs                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Sequence Number                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Source ID                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct NetFlowV9Packet {
    version: u16,
    sys_up_time: u32,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))]
    unix_time: DateTime<Utc>,
    sequence_number: u32,
    source_id: u32,
    sets: Box<[Set]>,
}

impl NetFlowV9Packet {
    pub fn new(
        sys_up_time: u32,
        unix_time: DateTime<Utc>,
        sequence_number: u32,
        source_id: u32,
        sets: Box<[Set]>,
    ) -> Self {
        Self {
            version: NETFLOW_V9_VERSION,
            sys_up_time,
            unix_time,
            sequence_number,
            source_id,
            sets,
        }
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn sys_up_time(&self) -> u32 {
        self.sys_up_time
    }

    pub const fn unix_time(&self) -> DateTime<Utc> {
        self.unix_time
    }

    pub const fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub const fn source_id(&self) -> u32 {
        self.source_id
    }

    pub const fn sets(&self) -> &[Set] {
        &self.sets
    }

    pub fn flatten(self) -> Vec<FlatNetFlowV9Packet> {
        let sys_up_time = self.sys_up_time;
        let unix_time = self.unix_time;
        let sequence_number = self.sequence_number;
        let source_id = self.source_id;
        IntoIterator::into_iter(self.sets)
            .flat_map(|set| set.flatten())
            .map(|set| FlatNetFlowV9Packet {
                sys_up_time,
                unix_time,
                sequence_number,
                source_id,
                set,
            })
            .collect()
    }

    pub fn flatten_data(self) -> Vec<FlatNetFlowV9DataPacket> {
        let sys_up_time = self.sys_up_time;
        let unix_time = self.unix_time;
        let sequence_number = self.sequence_number;
        let source_id = self.source_id;
        IntoIterator::into_iter(self.sets)
            .flat_map(|set| set.flatten_data())
            .map(|set| FlatNetFlowV9DataPacket {
                sys_up_time,
                unix_time,
                sequence_number,
                source_id,
                set,
            })
            .collect()
    }
}

/// Flattened version of [NetFlowV9Packet]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatNetFlowV9Packet {
    sys_up_time: u32,
    unix_time: DateTime<Utc>,
    sequence_number: u32,
    source_id: u32,
    set: FlatSet,
}

impl FlatNetFlowV9Packet {
    pub fn new(
        sys_up_time: u32,
        unix_time: DateTime<Utc>,
        sequence_number: u32,
        source_id: u32,
        set: FlatSet,
    ) -> Self {
        Self {
            sys_up_time,
            unix_time,
            sequence_number,
            source_id,
            set,
        }
    }

    pub const fn sys_up_time(&self) -> u32 {
        self.sys_up_time
    }

    pub const fn unix_time(&self) -> DateTime<Utc> {
        self.unix_time
    }

    pub const fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub const fn source_id(&self) -> u32 {
        self.source_id
    }

    pub const fn set(&self) -> &FlatSet {
        &self.set
    }
}

/// Flattened data only version of [NetFlowV9Packet]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatNetFlowV9DataPacket {
    sys_up_time: u32,
    unix_time: DateTime<Utc>,
    sequence_number: u32,
    source_id: u32,
    set: FlatDataSet,
}

impl FlatNetFlowV9DataPacket {
    pub fn new(
        sys_up_time: u32,
        unix_time: DateTime<Utc>,
        sequence_number: u32,
        source_id: u32,
        set: FlatDataSet,
    ) -> Self {
        Self {
            sys_up_time,
            unix_time,
            sequence_number,
            source_id,
            set,
        }
    }

    pub const fn sys_up_time(&self) -> u32 {
        self.sys_up_time
    }

    pub const fn unix_time(&self) -> DateTime<Utc> {
        self.unix_time
    }

    pub const fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub const fn source_id(&self) -> u32 {
        self.source_id
    }

    pub const fn set(&self) -> &FlatDataSet {
        &self.set
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Set {
    Template(Box<[TemplateRecord]>),
    OptionsTemplate(Box<[OptionsTemplateRecord]>),
    Data {
        id: DataSetId,
        records: Box<[DataRecord]>,
    },
}

impl Set {
    pub const fn id(&self) -> u16 {
        match self {
            Self::Template(_) => NETFLOW_TEMPLATE_SET_ID,
            Self::OptionsTemplate(_) => NETFLOW_OPTIONS_TEMPLATE_SET_ID,
            Self::Data { id, records: _ } => id.0,
        }
    }

    pub fn flatten(self) -> Vec<FlatSet> {
        match self {
            Self::Template(values) => IntoIterator::into_iter(values)
                .map(FlatSet::Template)
                .collect(),
            Self::OptionsTemplate(values) => IntoIterator::into_iter(values)
                .map(FlatSet::OptionsTemplate)
                .collect(),
            Self::Data { id, records } => IntoIterator::into_iter(records)
                .map(|record| FlatSet::Data {
                    id,
                    record: Box::new(FlatDataRecord::new(
                        record.scope_fields.to_vec().into(),
                        record.fields.to_vec().into(),
                    )),
                })
                .collect(),
        }
    }

    pub fn flatten_data(self) -> Vec<FlatDataSet> {
        match self {
            Self::Template(_) => vec![],
            Self::OptionsTemplate(_) => {
                vec![]
            }
            Self::Data { id, records } => IntoIterator::into_iter(records)
                .map(|record| {
                    FlatDataSet::new(
                        id,
                        FlatDataRecord::new(
                            record.scope_fields.to_vec().into(),
                            record.fields.to_vec().into(),
                        ),
                    )
                })
                .collect(),
        }
    }
}

/// Flattened version of [Set]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlatSet {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data {
        id: DataSetId,
        record: Box<FlatDataRecord>,
    },
}

impl FlatSet {
    pub const fn id(&self) -> u16 {
        match self {
            Self::Template(_) => NETFLOW_TEMPLATE_SET_ID,
            Self::OptionsTemplate(_) => NETFLOW_OPTIONS_TEMPLATE_SET_ID,
            Self::Data { id, record: _ } => id.0,
        }
    }
}

/// Flattened Data only version of [Set] without any templates or options
/// template
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatDataSet {
    id: DataSetId,
    record: FlatDataRecord,
}

impl FlatDataSet {
    pub const fn new(id: DataSetId, record: FlatDataRecord) -> Self {
        Self { id, record }
    }
    pub const fn id(&self) -> u16 {
        self.id.0
    }

    pub const fn record(&self) -> &FlatDataRecord {
        &self.record
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct TemplateRecord {
    id: u16,
    field_specifiers: Box<[FieldSpecifier]>,
}

impl TemplateRecord {
    pub const fn new(id: u16, field_specifiers: Box<[FieldSpecifier]>) -> Self {
        Self {
            id,
            field_specifiers,
        }
    }

    /// Each Template Record is given a unique Template ID in the range 256 to
    /// 65535.
    ///
    /// TODO (AH): do we need to check for template IDs < 256,
    /// see [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1)
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// List of [`FieldSpecifier`] defined in the template.
    pub const fn field_specifiers(&self) -> &[FieldSpecifier] {
        &self.field_specifiers
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct OptionsTemplateRecord {
    id: u16,
    scope_field_specifiers: Box<[ScopeFieldSpecifier]>,
    field_specifiers: Box<[FieldSpecifier]>,
}

impl OptionsTemplateRecord {
    pub const fn new(
        id: u16,
        scope_field_specifiers: Box<[ScopeFieldSpecifier]>,
        field_specifiers: Box<[FieldSpecifier]>,
    ) -> Self {
        Self {
            id,
            scope_field_specifiers,
            field_specifiers,
        }
    }

    pub const fn id(&self) -> u16 {
        self.id
    }

    pub const fn scope_field_specifiers(&self) -> &[ScopeFieldSpecifier] {
        &self.scope_field_specifiers
    }

    pub const fn field_specifiers(&self) -> &[FieldSpecifier] {
        &self.field_specifiers
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct DataRecord {
    scope_fields: Box<[ScopeField]>,
    fields: Box<[Field]>,
}

impl DataRecord {
    pub const fn new(scope_fields: Box<[ScopeField]>, fields: Box<[Field]>) -> Self {
        Self {
            scope_fields,
            fields,
        }
    }

    pub const fn scope_fields(&self) -> &[ScopeField] {
        &self.scope_fields
    }

    pub const fn fields(&self) -> &[Field] {
        &self.fields
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatDataRecord {
    scope_fields: ScopeFields,
    fields: Fields,
}

impl FlatDataRecord {
    pub const fn new(scope_fields: ScopeFields, fields: Fields) -> Self {
        Self {
            scope_fields,
            fields,
        }
    }

    pub const fn scope_fields(&self) -> &ScopeFields {
        &self.scope_fields
    }

    pub const fn fields(&self) -> &Fields {
        &self.fields
    }
}

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum ScopeField {
    Unknown { pen: u32, id: u16, value: Box<[u8]> },
    System(System),
    Interface(Interface),
    LineCard(LineCard),
    Cache(Cache),
    Template(Template),
}

impl ScopeField {
    pub const fn ie(&self) -> ScopeIE {
        match self {
            Self::Unknown { pen, id, value: _ } => ScopeIE::Unknown { pen: *pen, id: *id },
            Self::System(_) => ScopeIE::System,
            Self::Interface(_) => ScopeIE::Interface,
            Self::LineCard(_) => ScopeIE::LineCard,
            Self::Cache(_) => ScopeIE::Cache,
            Self::Template(_) => ScopeIE::Template,
        }
    }
}

#[derive(Default, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ScopeFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<Vec<System>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<Vec<Interface>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_card: Option<Vec<LineCard>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<Vec<Cache>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<Vec<Template>>,
}

impl From<Vec<ScopeField>> for ScopeFields {
    fn from(fields: Vec<ScopeField>) -> Self {
        let mut out = ScopeFields::default();
        for field in fields {
            match field {
                ScopeField::Unknown { .. } => {}
                ScopeField::System(system) => {
                    if out.system.is_none() {
                        out.system = Some(Vec::with_capacity(1));
                    }
                    if let Some(inner) = out.system.as_mut() {
                        inner.push(system)
                    }
                }
                ScopeField::Interface(interface) => {
                    if out.interface.is_none() {
                        out.interface = Some(Vec::with_capacity(1));
                    }
                    if let Some(inner) = out.interface.as_mut() {
                        inner.push(interface)
                    }
                }
                ScopeField::LineCard(line_card) => {
                    if out.line_card.is_none() {
                        out.line_card = Some(Vec::with_capacity(1));
                    }
                    if let Some(inner) = out.line_card.as_mut() {
                        inner.push(line_card)
                    }
                }
                ScopeField::Cache(cache) => {
                    if out.cache.is_none() {
                        out.cache = Some(Vec::with_capacity(1));
                    }
                    if let Some(inner) = out.cache.as_mut() {
                        inner.push(cache)
                    }
                }
                ScopeField::Template(template) => {
                    if out.template.is_none() {
                        out.template = Some(Vec::with_capacity(1));
                    }
                    if let Some(inner) = out.template.as_mut() {
                        inner.push(template)
                    }
                }
            }
        }
        out
    }
}

#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct System(pub u32);

#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Interface(pub u32);

#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct LineCard(pub u32);

#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Cache(pub Box<[u8]>);

#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Template(pub Box<[u8]>);

#[derive(Copy, Eq, Clone, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum ScopeIE {
    Unknown { pen: u32, id: u16 },
    System,
    Interface,
    LineCard,
    Cache,
    Template,
}

impl From<(u32, u16)> for ScopeIE {
    fn from(value: (u32, u16)) -> Self {
        let (pen, id) = value;
        match value {
            (0, 1) => ScopeIE::System,
            (0, 2) => ScopeIE::Interface,
            (0, 3) => ScopeIE::LineCard,
            (0, 4) => ScopeIE::Cache,
            (0, 5) => ScopeIE::Template,
            _ => ScopeIE::Unknown { pen, id },
        }
    }
}

impl InformationElementTemplate for ScopeIE {
    fn semantics(&self) -> Option<InformationElementSemantics> {
        match self {
            Self::System => Some(InformationElementSemantics::identifier),
            Self::Interface => Some(InformationElementSemantics::identifier),
            Self::LineCard => Some(InformationElementSemantics::identifier),
            _ => None,
        }
    }

    fn data_type(&self) -> InformationElementDataType {
        match self {
            Self::System => InformationElementDataType::octetArray,
            Self::Interface => InformationElementDataType::unsigned32,
            Self::LineCard => InformationElementDataType::unsigned32,
            Self::Cache => InformationElementDataType::octetArray,
            Self::Template => InformationElementDataType::octetArray,
            Self::Unknown { .. } => InformationElementDataType::octetArray,
        }
    }

    fn value_range(&self) -> Option<Range<u64>> {
        None
    }

    fn units(&self) -> Option<InformationElementUnits> {
        None
    }

    fn id(&self) -> u16 {
        match self {
            Self::Unknown { id, .. } => *id,
            Self::System => 1,
            Self::Interface => 2,
            Self::LineCard => 3,
            Self::Cache => 4,
            Self::Template => 5,
        }
    }

    fn pen(&self) -> u32 {
        match self {
            Self::Unknown { pen, .. } => *pen,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ScopeFieldSpecifier {
    element_id: ScopeIE,
    length: u16,
}

impl ScopeFieldSpecifier {
    pub const fn new(element_id: ScopeIE, length: u16) -> Self {
        Self { element_id, length }
    }

    pub const fn element_id(&self) -> ScopeIE {
        self.element_id
    }

    pub const fn length(&self) -> u16 {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_scope_fields_from() {
        let fields = vec![
            ScopeField::System(System(1)),
            ScopeField::Interface(Interface(2)),
            ScopeField::LineCard(LineCard(3)),
            ScopeField::Cache(Cache(Box::new([1, 2, 3]))),
            ScopeField::Template(Template(Box::new([1, 2, 3]))),
        ];
        let scope_fields = ScopeFields::from(fields);
        assert_eq!(scope_fields.system.unwrap().len(), 1);
        assert_eq!(scope_fields.interface.unwrap().len(), 1);
        assert_eq!(scope_fields.line_card.unwrap().len(), 1);
        assert_eq!(scope_fields.cache.unwrap().len(), 1);
        assert_eq!(scope_fields.template.unwrap().len(), 1);
    }

    #[test]
    fn test_scope_ie_from() {
        let ie = ScopeIE::from((0, 1));
        assert_eq!(ie, ScopeIE::System);
        let ie = ScopeIE::from((0, 2));
        assert_eq!(ie, ScopeIE::Interface);
        let ie = ScopeIE::from((0, 3));
        assert_eq!(ie, ScopeIE::LineCard);
        let ie = ScopeIE::from((0, 4));
        assert_eq!(ie, ScopeIE::Cache);
        let ie = ScopeIE::from((0, 5));
        assert_eq!(ie, ScopeIE::Template);
        let ie = ScopeIE::from((1, 1));
        assert_eq!(ie, ScopeIE::Unknown { pen: 1, id: 1 });
    }

    #[test]
    fn test_scope_ie_id() {
        let ie = ScopeIE::System;
        assert_eq!(ie.id(), 1);
        let ie = ScopeIE::Interface;
        assert_eq!(ie.id(), 2);
        let ie = ScopeIE::LineCard;
        assert_eq!(ie.id(), 3);
        let ie = ScopeIE::Cache;
        assert_eq!(ie.id(), 4);
        let ie = ScopeIE::Template;
        assert_eq!(ie.id(), 5);
        let ie = ScopeIE::Unknown { pen: 1, id: 1 };
        assert_eq!(ie.id(), 1);
    }

    #[test]
    fn test_scope_ie_pen() {
        let ie = ScopeIE::System;
        assert_eq!(ie.pen(), 0);
        let ie = ScopeIE::Interface;
        assert_eq!(ie.pen(), 0);
        let ie = ScopeIE::LineCard;
        assert_eq!(ie.pen(), 0);
        let ie = ScopeIE::Cache;
        assert_eq!(ie.pen(), 0);
        let ie = ScopeIE::Template;
        assert_eq!(ie.pen(), 0);
        let ie = ScopeIE::Unknown { pen: 1, id: 1 };
        assert_eq!(ie.pen(), 1);
    }

    #[test]
    fn test_scope_ie_data_type() {
        let ie = ScopeIE::System;
        assert_eq!(ie.data_type(), InformationElementDataType::octetArray);
        let ie = ScopeIE::Interface;
        assert_eq!(ie.data_type(), InformationElementDataType::unsigned32);
        let ie = ScopeIE::LineCard;
        assert_eq!(ie.data_type(), InformationElementDataType::unsigned32);
        let ie = ScopeIE::Cache;
        assert_eq!(ie.data_type(), InformationElementDataType::octetArray);
        let ie = ScopeIE::Template;
        assert_eq!(ie.data_type(), InformationElementDataType::octetArray);
        let ie = ScopeIE::Unknown { pen: 1, id: 1 };
        assert_eq!(ie.data_type(), InformationElementDataType::octetArray);
    }

    #[test]
    fn test_scope_ie_semantics() {
        let ie = ScopeIE::System;
        assert_eq!(
            ie.semantics(),
            Some(InformationElementSemantics::identifier)
        );
        let ie = ScopeIE::Interface;
        assert_eq!(
            ie.semantics(),
            Some(InformationElementSemantics::identifier)
        );
        let ie = ScopeIE::LineCard;
        assert_eq!(
            ie.semantics(),
            Some(InformationElementSemantics::identifier)
        );
        let ie = ScopeIE::Cache;
        assert_eq!(ie.semantics(), None);
        let ie = ScopeIE::Template;
        assert_eq!(ie.semantics(), None);
        let ie = ScopeIE::Unknown { pen: 1, id: 1 };
        assert_eq!(ie.semantics(), None);
    }

    #[test]
    fn test_scope_ie_value_range() {
        let ie = ScopeIE::System;
        assert_eq!(ie.value_range(), None);
        let ie = ScopeIE::Interface;
        assert_eq!(ie.value_range(), None);
        let ie = ScopeIE::LineCard;
        assert_eq!(ie.value_range(), None);
        let ie = ScopeIE::Cache;
        assert_eq!(ie.value_range(), None);
        let ie = ScopeIE::Template;
        assert_eq!(ie.value_range(), None);
        let ie = ScopeIE::Unknown { pen: 1, id: 1 };
        assert_eq!(ie.value_range(), None);
    }

    #[test]
    fn test_scope_ie_units() {
        let ie = ScopeIE::System;
        assert_eq!(ie.units(), None);
        let ie = ScopeIE::Interface;
        assert_eq!(ie.units(), None);
        let ie = ScopeIE::LineCard;
        assert_eq!(ie.units(), None);
        let ie = ScopeIE::Cache;
        assert_eq!(ie.units(), None);
        let ie = ScopeIE::Template;
        assert_eq!(ie.units(), None);
        let ie = ScopeIE::Unknown { pen: 1, id: 1 };
        assert_eq!(ie.units(), None);
    }

    #[test]
    fn test_scope_field_specifier_new() {
        let ie = ScopeIE::System;
        let length = 1;
        let field_specifier = ScopeFieldSpecifier::new(ie, length);
        assert_eq!(field_specifier.element_id(), ie);
        assert_eq!(field_specifier.length(), length);
    }

    #[test]
    fn test_flatten_netflow() {
        let sys_up_time = 0;
        let unix_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
        let sequence_number = 0;
        let source_id = 0;
        let set = Set::Data {
            id: DataSetId(0),
            records: Box::new([DataRecord::new(
                Box::new([ScopeField::System(System(1))]),
                Box::new([Field::octetDeltaCount(1000)]),
            )]),
        };
        let packet = NetFlowV9Packet::new(
            sys_up_time,
            unix_time,
            sequence_number,
            source_id,
            Box::new([set]),
        );
        let flat_packets = packet.flatten();
        assert_eq!(flat_packets.len(), 1);
        let flat_packet = &flat_packets[0];
        assert_eq!(flat_packet.sys_up_time(), sys_up_time);
        assert_eq!(flat_packet.unix_time(), unix_time);
        assert_eq!(flat_packet.sequence_number(), sequence_number);
        assert_eq!(flat_packet.source_id(), source_id);
        let flat_set = flat_packet.set();
        assert_eq!(flat_set.id(), NETFLOW_TEMPLATE_SET_ID);
        let expected = FlatSet::Data {
            id: DataSetId(0),
            record: Box::new(FlatDataRecord::new(
                ScopeFields {
                    system: Some(vec![System(1)]),
                    ..Default::default()
                },
                Fields {
                    octetDeltaCount: Some(vec![1000]),
                    ..Default::default()
                },
            )),
        };
        assert_eq!(flat_set, &expected);
    }
}
