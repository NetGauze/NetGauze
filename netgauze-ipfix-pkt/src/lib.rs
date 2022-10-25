// Copyright (C) 2022-present The NetGauze Authors.
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

pub mod ie;
#[cfg(feature = "serde")]
pub mod wire;

use crate::ie::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub(crate) const IPFIX_VERSION: u16 = 10;

///
/// ```text
///  +--------+--------------------------------------------------------+
///  |        | +----------+ +---------+     +-----------+ +---------+ |
///  |Message | | Template | | Data    |     | Options   | | Data    | |
///  | Header | | Set      | | Set     | ... | Template  | | Set     | |
///  |        | |          | |         |     | Set       | |         | |
///  |        | +----------+ +---------+     +-----------+ +---------+ |
///  +--------+--------------------------------------------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpfixPacket {
    header: IpfixHeader,
    payload: Vec<Set>,
}

impl IpfixPacket {
    pub const fn new(header: IpfixHeader, payload: Vec<Set>) -> Self {
        Self { header, payload }
    }

    pub const fn header(&self) -> &IpfixHeader {
        &self.header
    }

    pub const fn payload(&self) -> &Vec<Set> {
        &self.payload
    }
}

///
/// ```text
/// 0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Version Number          |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Export Time                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Sequence Number                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Observation Domain ID                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpfixHeader {
    version: u16,
    export_time: DateTime<Utc>,
    sequence_number: u32,
    observation_domain_id: u32,
}

impl IpfixHeader {
    pub const fn new(
        export_time: DateTime<Utc>,
        sequence_number: u32,
        observation_domain_id: u32,
    ) -> Self {
        Self {
            version: IPFIX_VERSION,
            export_time,
            sequence_number,
            observation_domain_id,
        }
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn export_time(&self) -> DateTime<Utc> {
        self.export_time
    }

    pub const fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub const fn observation_domain_id(&self) -> u32 {
        self.observation_domain_id
    }
}

/// Every Set contains a common header. The Sets can be any of these three
/// possible types: Data Set, Template Set, or Options Template Set.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Set ID               |          Length               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Set {
    id: u16,
    payload: SetPayload,
}

impl Set {
    pub const fn new(id: u16, payload: SetPayload) -> Self {
        Self { id, payload }
    }

    pub const fn id(&self) -> u16 {
        self.id
    }

    pub const fn payload(&self) -> &SetPayload {
        &self.payload
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SetPayload {
    Data(Vec<DataRecord>),
    Template(Vec<TemplateRecord>),
    OptionsTemplate(Vec<OptionsTemplateRecord>),
}

/// Template Records allow the Collecting Process to process
/// IPFIX Messages without necessarily knowing the interpretation of all
/// Data Records. A Template Record contains any combination of IANA-
/// assigned and/or enterprise-specific Information Element identifiers.
///
/// ```text
/// +--------------------------------------------------+
/// | Template Record Header                           |
/// +--------------------------------------------------+
/// | Field Specifier                                  |
/// +--------------------------------------------------+
/// | Field Specifier                                  |
/// +--------------------------------------------------+
///  ...
/// +--------------------------------------------------+
/// | Field Specifier                                  |
/// +--------------------------------------------------+
/// ```
///
/// The format of the Template Record Header is
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Template ID (> 255)      |         Field Count           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

    pub const fn id(&self) -> u16 {
        self.id
    }

    pub const fn field_specifiers(&self) -> &Vec<FieldSpecifier> {
        &self.field_specifiers
    }
}

/// Field Specifier
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |E|  Information Element ident. |        Field Length           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Enterprise Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldSpecifier {
    element_id: InformationElementId,
    length: u16,
}

impl FieldSpecifier {
    pub const fn new(element_id: InformationElementId, length: u16) -> Self {
        Self { element_id, length }
    }

    pub const fn element_id(&self) -> InformationElementId {
        self.element_id
    }

    pub const fn length(&self) -> u16 {
        self.length
    }
}

/// An Options Template Record contains any combination of IANA-assigned
/// and/or enterprise-specific Information Element identifiers.
/// ```text
/// +--------------------------------------------------+
/// | Options Template Record Header                   |
/// +--------------------------------------------------+
/// | Field Specifier                                  |
/// +--------------------------------------------------+
/// | Field Specifier                                  |
/// +--------------------------------------------------+
///  ...
/// +--------------------------------------------------+
/// | Field Specifier                                  |
/// +--------------------------------------------------+
/// ```
///
///
/// The format of the Options Template Record Header:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Template ID (> 255)   |         Field Count           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Scope Field Count        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// An The example in Figure shows an Options Template Set with mixed
/// IANA-assigned and enterprise-specific Information Elements.
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Set ID = 3           |          Length               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Template ID = 258     |         Field Count = N + M   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Scope Field Count = N     |0|  Scope 1 Infor. Element id. |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Scope 1 Field Length      |0|  Scope 2 Infor. Element id. |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Scope 2 Field Length      |             ...               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            ...                |1|  Scope N Infor. Element id. |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Scope N Field Length      |   Scope N Enterprise Number  ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ..  Scope N Enterprise Number   |1| Option 1 Infor. Element id. |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Option 1 Field Length      |  Option 1 Enterprise Number  ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .. Option 1 Enterprise Number   |              ...              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             ...               |0| Option M Infor. Element id. |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Option M Field Length     |      Padding (optional)       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OptionsTemplateRecord {
    id: u16,
    scope_field_specifiers: Vec<FieldSpecifier>,
    field_specifiers: Vec<FieldSpecifier>,
}

impl OptionsTemplateRecord {
    pub const fn new(
        id: u16,
        scope_field_specifiers: Vec<FieldSpecifier>,
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

    pub const fn scope_field_specifiers(&self) -> &Vec<FieldSpecifier> {
        &self.scope_field_specifiers
    }

    pub const fn field_specifiers(&self) -> &Vec<FieldSpecifier> {
        &self.field_specifiers
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataRecord {
    flows: Vec<Flow>,
}

impl DataRecord {
    pub const fn new(flows: Vec<Flow>) -> Self {
        Self { flows }
    }

    pub const fn flows(&self) -> &Vec<Flow> {
        &self.flows
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    records: Vec<ie::Record>,
}

impl Flow {
    pub const fn new(records: Vec<ie::Record>) -> Self {
        Self { records }
    }

    pub const fn records(&self) -> &Vec<ie::Record> {
        &self.records
    }
}
