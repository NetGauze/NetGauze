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
        Field, InformationElementDataType, InformationElementSemantics, InformationElementTemplate,
        InformationElementUnits,
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
pub type DecodingTemplate = (Vec<ScopeFieldSpecifier>, Vec<FieldSpecifier>);

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
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct NetFlowV9Packet {
    version: u16,
    sys_up_time: u32,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))]
    unix_time: DateTime<Utc>,
    sequence_number: u32,
    source_id: u32,
    sets: Vec<Set>,
}

impl NetFlowV9Packet {
    pub fn new(
        sys_up_time: u32,
        unix_time: DateTime<Utc>,
        sequence_number: u32,
        source_id: u32,
        sets: Vec<Set>,
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

    pub const fn sets(&self) -> &Vec<Set> {
        &self.sets
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Set {
    Template(Vec<TemplateRecord>),
    OptionsTemplate(Vec<OptionsTemplateRecord>),
    Data {
        id: DataSetId,
        records: Vec<DataRecord>,
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
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct TemplateRecord {
    id: u16,
    field_specifiers: Vec<FieldSpecifier>,
}

impl TemplateRecord {
    pub const fn new(id: u16, field_specifiers: Vec<FieldSpecifier>) -> Self {
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
    pub const fn field_specifiers(&self) -> &Vec<FieldSpecifier> {
        &self.field_specifiers
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct OptionsTemplateRecord {
    id: u16,
    scope_field_specifiers: Vec<ScopeFieldSpecifier>,
    field_specifiers: Vec<FieldSpecifier>,
}

impl OptionsTemplateRecord {
    pub const fn new(
        id: u16,
        scope_field_specifiers: Vec<ScopeFieldSpecifier>,
        field_specifiers: Vec<FieldSpecifier>,
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

    pub const fn scope_field_specifiers(&self) -> &Vec<ScopeFieldSpecifier> {
        &self.scope_field_specifiers
    }

    pub const fn field_specifiers(&self) -> &Vec<FieldSpecifier> {
        &self.field_specifiers
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct DataRecord {
    scope_fields: Vec<ScopeField>,
    fields: Vec<Field>,
}

impl DataRecord {
    pub const fn new(scope_fields: Vec<ScopeField>, fields: Vec<Field>) -> Self {
        Self {
            scope_fields,
            fields,
        }
    }

    pub const fn scope_fields(&self) -> &Vec<ScopeField> {
        &self.scope_fields
    }

    pub const fn fields(&self) -> &Vec<Field> {
        &self.fields
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum ScopeField {
    Unknown { pen: u32, id: u16, value: Vec<u8> },
    System(System),
    Interface(Interface),
    LineCard(LineCard),
    Cache(Cache),
    Template(Template),
}

#[derive(Eq, Clone, PartialEq, Ord, PartialOrd, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct System(pub u32);

#[derive(Eq, Clone, PartialEq, Ord, PartialOrd, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Interface(pub u32);

#[derive(Eq, Clone, PartialEq, Ord, PartialOrd, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct LineCard(pub u32);

#[derive(Eq, Clone, PartialEq, Ord, PartialOrd, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Cache(pub Vec<u8>);

#[derive(Eq, Clone, PartialEq, Ord, PartialOrd, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Template(pub Vec<u8>);

#[derive(
    Copy, Eq, Clone, PartialEq, Ord, PartialOrd, Debug, serde::Serialize, serde::Deserialize,
)]
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

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
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
