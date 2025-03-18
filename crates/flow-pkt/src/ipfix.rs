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

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    ie::{Field, Fields},
    DataSetId, FieldSpecifier, IE,
};
use netgauze_analytics::flow::{AggrOp, AggregationError};

pub const IPFIX_VERSION: u16 = 10;

/// A value of 2 is reserved for Template Sets
pub(crate) const IPFIX_TEMPLATE_SET_ID: u16 = 2;

/// A value of 3 is reserved for Options Template Sets
pub(crate) const IPFIX_OPTIONS_TEMPLATE_SET_ID: u16 = 3;

/// Simpler template that is used to decode data records
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct DecodingTemplate {
    pub scope_fields_specs: Box<[FieldSpecifier]>,
    pub fields_specs: Box<[FieldSpecifier]>,
}

/// Cache to store templates needed for decoding data packets
pub type TemplatesMap = HashMap<u16, DecodingTemplate>;

/// IP Flow Information Export (IPFIX) v10 Packet.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct IpfixPacket {
    version: u16,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))]
    export_time: DateTime<Utc>,
    sequence_number: u32,
    observation_domain_id: u32,
    sets: Box<[Set]>,
}

impl IpfixPacket {
    pub const fn new(
        export_time: DateTime<Utc>,
        sequence_number: u32,
        observation_domain_id: u32,
        sets: Box<[Set]>,
    ) -> Self {
        Self {
            version: IPFIX_VERSION,
            export_time,
            sequence_number,
            observation_domain_id,
            sets,
        }
    }

    /// IPFIX Protocol version
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Time at which the IPFIX Message Header leaves the Exporter.
    ///
    /// Note: The exporter is sending this value at a seconds granularity as
    /// UNIX epoch.
    pub const fn export_time(&self) -> DateTime<Utc> {
        self.export_time
    }

    /// Incremental sequence counter modulo 2^32 of all IPFIX Data Records sent
    /// in the current stream from the current Observation Domain by the
    /// Exporting Process.
    ///
    /// Note: Template and Options Template Records do not increase the Sequence
    /// Number.
    pub const fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// A 32-bit identifier of the Observation Domain that is locally unique to
    /// the Exporting Process.
    pub const fn observation_domain_id(&self) -> u32 {
        self.observation_domain_id
    }

    /// The IPFIX payload is a vector of [Set].
    pub const fn sets(&self) -> &[Set] {
        &self.sets
    }

    pub fn flatten(self) -> Vec<FlatIpfixPacket> {
        let export_time = self.export_time;
        let sequence_number = self.sequence_number;
        let observation_domain_id = self.observation_domain_id;
        IntoIterator::into_iter(self.sets)
            .flat_map(|set| set.flatten())
            .map(|set| FlatIpfixPacket {
                export_time,
                sequence_number,
                observation_domain_id,
                set,
            })
            .collect()
    }

    pub fn flatten_data(self) -> Vec<FlatIpfixDataPacket> {
        let export_time = self.export_time;
        let sequence_number = self.sequence_number;
        let observation_domain_id = self.observation_domain_id;
        IntoIterator::into_iter(self.sets)
            .flat_map(|set| set.flatten_data())
            .map(|set| FlatIpfixDataPacket {
                export_time,
                sequence_number,
                observation_domain_id,
                set,
            })
            .collect()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatIpfixPacket {
    export_time: DateTime<Utc>,
    sequence_number: u32,
    observation_domain_id: u32,
    set: FlatSet,
}

impl FlatIpfixPacket {
    pub const fn new(
        export_time: DateTime<Utc>,
        sequence_number: u32,
        observation_domain_id: u32,
        set: FlatSet,
    ) -> Self {
        Self {
            export_time,
            sequence_number,
            observation_domain_id,
            set,
        }
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

    pub const fn set(&self) -> &FlatSet {
        &self.set
    }

    pub fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        self.set.extract_as_key_str(ie, indices)
    }

    pub fn reduce(
        &mut self,
        incoming: &FlatIpfixPacket,
        transform: &IndexMap<IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        self.set.reduce(&incoming.set, transform)
    }
}

/// Data only IPFIX packet, without any templates or options template
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatIpfixDataPacket {
    export_time: DateTime<Utc>,
    sequence_number: u32,
    observation_domain_id: u32,
    set: FlatDataSet,
}

impl FlatIpfixDataPacket {
    pub const fn new(
        export_time: DateTime<Utc>,
        sequence_number: u32,
        observation_domain_id: u32,
        set: FlatDataSet,
    ) -> Self {
        Self {
            export_time,
            sequence_number,
            observation_domain_id,
            set,
        }
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

    pub const fn set(&self) -> &FlatDataSet {
        &self.set
    }

    pub fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        self.set.extract_as_key_str(ie, indices)
    }

    pub fn reduce(
        &mut self,
        incoming: &FlatIpfixDataPacket,
        transform: &IndexMap<IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        self.set.reduce(&incoming.set, transform)
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
            Self::Template(_) => IPFIX_TEMPLATE_SET_ID,
            Self::OptionsTemplate(_) => IPFIX_OPTIONS_TEMPLATE_SET_ID,
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
                    record: Box::new(record.flatten()),
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
                .map(|record| FlatDataSet::new(id, record.flatten()))
                .collect(),
        }
    }
}

/// A version of [Set] that contain only one record
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlatSet {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data {
        id: DataSetId,
        record: Box<FlatDataRecord>,
    },
}

impl Default for FlatSet {
    fn default() -> Self {
        FlatSet::Data {
            id: DataSetId(0),
            record: Box::new(FlatDataRecord::default()),
        }
    }
}

impl FlatSet {
    pub const fn id(&self) -> u16 {
        match self {
            Self::Template(_) => IPFIX_TEMPLATE_SET_ID,
            Self::OptionsTemplate(_) => IPFIX_OPTIONS_TEMPLATE_SET_ID,
            Self::Data { id, record: _ } => id.0,
        }
    }

    fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        match self {
            FlatSet::Data { record, .. } => record.extract_as_key_str(ie, indices),
            _ => Err(AggregationError::FlatSetIsNotData),
        }
    }

    fn reduce(
        &mut self,
        incoming: &FlatSet,
        transform: &IndexMap<IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        match self {
            FlatSet::Data { record, .. } => {
                if let FlatSet::Data {
                    record: incoming_record,
                    ..
                } = incoming
                {
                    record.reduce(incoming_record, transform)
                } else {
                    Err(AggregationError::FlatSetIsNotData)
                }
            }
            _ => Err(AggregationError::FlatSetIsNotData),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatDataSet {
    id: DataSetId,
    record: FlatDataRecord,
}

impl Default for FlatDataSet {
    fn default() -> Self {
        Self {
            id: DataSetId(0),
            record: FlatDataRecord::default(),
        }
    }
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

    fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        self.record.extract_as_key_str(ie, indices)
    }

    fn reduce(
        &mut self,
        incoming: &FlatDataSet,
        transform: &IndexMap<IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        self.record.reduce(&incoming.record, transform)
    }
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
    /// 65535. TODO (AH): do we need to check for template IDs < 256,
    /// see [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1)
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// List of [`FieldSpecifier`] defined in the template.
    pub const fn field_specifiers(&self) -> &[FieldSpecifier] {
        &self.field_specifiers
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct OptionsTemplateRecord {
    id: u16,
    scope_field_specifiers: Box<[FieldSpecifier]>,
    field_specifiers: Box<[FieldSpecifier]>,
}

impl OptionsTemplateRecord {
    pub const fn new(
        id: u16,
        scope_field_specifiers: Box<[FieldSpecifier]>,
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

    pub const fn scope_field_specifiers(&self) -> &[FieldSpecifier] {
        &self.scope_field_specifiers
    }

    pub const fn field_specifiers(&self) -> &[FieldSpecifier] {
        &self.field_specifiers
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct DataRecord {
    scope_fields: Box<[Field]>,
    fields: Box<[Field]>,
}

impl DataRecord {
    pub const fn new(scope_fields: Box<[Field]>, fields: Box<[Field]>) -> Self {
        Self {
            scope_fields,
            fields,
        }
    }

    pub const fn scope_fields(&self) -> &[Field] {
        &self.scope_fields
    }

    pub const fn fields(&self) -> &[Field] {
        &self.fields
    }

    pub fn flatten(self) -> FlatDataRecord {
        FlatDataRecord::new(self.scope_fields.into(), self.fields.into())
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatDataRecord {
    scope_fields: Fields,
    fields: Fields,
}

impl FlatDataRecord {
    pub const fn new(scope_fields: Fields, fields: Fields) -> Self {
        Self {
            scope_fields,
            fields,
        }
    }

    pub const fn scope_fields(&self) -> &Fields {
        &self.scope_fields
    }

    pub const fn fields(&self) -> &Fields {
        &self.fields
    }

    fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        self.fields.extract_as_key_str(ie, indices)
    }

    fn reduce(
        &mut self,
        incoming: &FlatDataRecord,
        transform: &IndexMap<IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        self.fields.reduce(&incoming.fields, transform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie;
    use chrono::TimeZone;
    use netgauze_iana::tcp::TCPHeaderFlags;

    #[test]
    fn test_ipfix_packet() {
        let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
        let sequence_number = 0;
        let observation_domain_id = 0;
        let sets = [
            Set::Template(Box::new([TemplateRecord::new(
                256,
                Box::new([
                    FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                    FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
                ]),
            )])),
            Set::OptionsTemplate(Box::new([OptionsTemplateRecord::new(
                258,
                Box::new([FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()]),
                Box::new([FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()]),
            )])),
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([Field::octetDeltaCount(189)]),
                    Box::new([Field::tcpDestinationPort(8080)]),
                )]),
            },
        ];
        let packet = IpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            Box::new(sets.clone()),
        );
        assert_eq!(packet.version(), IPFIX_VERSION);
        assert_eq!(packet.export_time(), export_time);
        assert_eq!(packet.sequence_number(), sequence_number);
        assert_eq!(packet.observation_domain_id(), observation_domain_id);
        assert_eq!(packet.sets(), &sets);
    }

    #[test]
    fn test_ipfix_packet_flatten() {
        let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
        let sequence_number = 0;
        let observation_domain_id = 0;
        let sets = Box::new([
            Set::Template(Box::new([TemplateRecord::new(
                256,
                Box::new([
                    FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                    FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
                ]),
            )])),
            Set::OptionsTemplate(Box::new([OptionsTemplateRecord::new(
                258,
                Box::new([FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()]),
                Box::new([FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()]),
            )])),
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([Field::octetDeltaCount(189)]),
                    Box::new([Field::tcpDestinationPort(8080)]),
                )]),
            },
        ]);
        let packet = IpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            sets.clone(),
        );
        let flat_packets = packet.flatten();
        assert_eq!(flat_packets.len(), 3);
        assert_eq!(flat_packets[0].export_time(), export_time);
        assert_eq!(flat_packets[0].sequence_number(), sequence_number);
        assert_eq!(
            flat_packets[0].observation_domain_id(),
            observation_domain_id
        );
        assert_eq!(flat_packets[0].set().id(), IPFIX_TEMPLATE_SET_ID);
        assert_eq!(flat_packets[1].set().id(), IPFIX_OPTIONS_TEMPLATE_SET_ID);
        assert_eq!(flat_packets[2].set().id(), 256);
    }

    #[test]
    fn test_template_record() {
        let template = TemplateRecord::new(
            256,
            Box::new([
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ]),
        );
        assert_eq!(template.id(), 256);
        assert_eq!(
            template.field_specifiers(),
            &[
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ]
        );
    }

    #[test]
    fn test_options_template_record() {
        let template = OptionsTemplateRecord::new(
            258,
            Box::new([FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()]),
            Box::new([FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()]),
        );
        assert_eq!(template.id(), 258);
        assert_eq!(
            template.scope_field_specifiers(),
            &[FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()]
        );
        assert_eq!(
            template.field_specifiers(),
            &[FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()]
        );
    }

    #[test]
    fn test_data_record() {
        let record = DataRecord::new(
            Box::new([Field::octetDeltaCount(189)]),
            Box::new([Field::tcpDestinationPort(8080)]),
        );
        assert_eq!(record.scope_fields(), &[Field::octetDeltaCount(189)]);
        assert_eq!(record.fields(), &[Field::tcpDestinationPort(8080)]);
    }

    #[test]
    fn test_flat_data_record() {
        let record = FlatDataRecord::new(
            Fields {
                interfaceName: Some(vec!["eth0".into()]),
                ..Default::default()
            },
            Fields {
                octetDeltaCount: Some(vec![189]),
                tcpDestinationPort: Some(vec![8080]),
                ..Default::default()
            },
        );
        assert_eq!(
            record.scope_fields(),
            &Fields {
                interfaceName: Some(vec!["eth0".into()]),
                ..Default::default()
            }
        );
        assert_eq!(
            record.fields(),
            &Fields {
                octetDeltaCount: Some(vec![189]),
                tcpDestinationPort: Some(vec![8080]),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_set() {
        let template = TemplateRecord::new(
            256,
            Box::new([
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ]),
        );
        let options_template = OptionsTemplateRecord::new(
            258,
            Box::new([FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()]),
            Box::new([FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()]),
        );
        let data = DataRecord::new(
            Box::new([Field::octetDeltaCount(189)]),
            Box::new([Field::tcpDestinationPort(8080)]),
        );
        let sets = [
            Set::Template(Box::new([template.clone()])),
            Set::OptionsTemplate(Box::new([options_template.clone()])),
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([data.clone()]),
            },
        ];
        assert_eq!(sets[0].id(), IPFIX_TEMPLATE_SET_ID);
        assert_eq!(sets[1].id(), IPFIX_OPTIONS_TEMPLATE_SET_ID);
        assert_eq!(sets[2].id(), 256);
    }

    #[test]
    fn test_flat_set() {
        let template = TemplateRecord::new(
            256,
            Box::new([
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ]),
        );
        let options_template = OptionsTemplateRecord::new(
            258,
            Box::new([FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()]),
            Box::new([FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()]),
        );
        let data = DataRecord::new(
            Box::new([Field::octetDeltaCount(189)]),
            Box::new([Field::tcpDestinationPort(8080)]),
        );
        let flat_data = data.clone().flatten();
        let sets = [
            FlatSet::Template(template.clone()),
            FlatSet::OptionsTemplate(options_template.clone()),
            FlatSet::Data {
                id: DataSetId::new(256).unwrap(),
                record: Box::new(flat_data),
            },
        ];
        assert_eq!(sets[0].id(), IPFIX_TEMPLATE_SET_ID);
        assert_eq!(sets[1].id(), IPFIX_OPTIONS_TEMPLATE_SET_ID);
        assert_eq!(sets[2].id(), 256);
    }

    #[test]
    fn test_flat_ipfix_packet_reduce() {
        let export_time = Utc.with_ymd_and_hms(2025, 2, 28, 10, 0, 0).unwrap();
        let sequence_number = 0;
        let observation_domain_id = 0;

        let mut packet1 = FlatIpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            FlatSet::Data {
                id: DataSetId::new(256).unwrap(),
                record: Box::new(FlatDataRecord::new(
                    Fields::default(),
                    Fields {
                        octetDeltaCount: Some(vec![100]),
                        minimumTTL: Some(vec![64]),
                        maximumTTL: Some(vec![128]),
                        tcpControlBits: Some(vec![TCPHeaderFlags::new(
                            true, false, false, true, false, false, false, false,
                        )]),
                        ..Default::default()
                    },
                )),
            },
        );

        let packet2 = FlatIpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            FlatSet::Data {
                id: DataSetId::new(256).unwrap(),
                record: Box::new(FlatDataRecord::new(
                    Fields::default(),
                    Fields {
                        octetDeltaCount: Some(vec![200]),
                        minimumTTL: Some(vec![100]),
                        maximumTTL: Some(vec![230]),
                        tcpControlBits: Some(vec![TCPHeaderFlags::new(
                            false, false, false, false, true, false, false, true,
                        )]),
                        ..Default::default()
                    },
                )),
            },
        );

        let mut transform = IndexMap::new();
        transform.insert(ie::IE::octetDeltaCount, AggrOp::Add);
        transform.insert(ie::IE::minimumTTL, AggrOp::Min);
        transform.insert(ie::IE::maximumTTL, AggrOp::Max);
        transform.insert(ie::IE::tcpControlBits, AggrOp::BoolMapOr);

        packet1.reduce(&packet2, &transform).unwrap();

        if let FlatSet::Data { record, .. } = packet1.set() {
            assert_eq!(record.fields().octetDeltaCount, Some(vec![300]));
            assert_eq!(record.fields().minimumTTL, Some(vec![64]));
            assert_eq!(record.fields().maximumTTL, Some(vec![230]));
            assert_eq!(
                record.fields().tcpControlBits,
                Some(vec![TCPHeaderFlags::new(
                    true, false, false, true, true, false, false, true
                )])
            );
        } else {
            panic!("Expected FlatSet::Data");
        }
    }

    #[test]
    fn test_extract_as_key_str() {
        let export_time = Utc.with_ymd_and_hms(2025, 2, 28, 10, 0, 0).unwrap();
        let sequence_number = 0;
        let observation_domain_id = 0;

        let packet = FlatIpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            FlatSet::Data {
                id: DataSetId::new(256).unwrap(),
                record: Box::new(FlatDataRecord::new(
                    Fields::default(),
                    Fields {
                        exporterIPv6Address: Some(vec![
                            std::net::Ipv6Addr::new(0xcafe, 0, 0, 0, 0, 0, 0, 1),
                            std::net::Ipv6Addr::new(0xcafe, 0, 0, 0, 0, 0, 0, 2),
                            std::net::Ipv6Addr::new(0xcafe, 0, 0, 0, 0, 0, 0, 3),
                        ]),
                        ..Default::default()
                    },
                )),
            },
        );

        let key_str = packet
            .extract_as_key_str(&ie::IE::exporterIPv6Address, &Some(vec![0, 2, 3]))
            .unwrap();
        assert_eq!(key_str, "cafe::1,cafe::3,None");

        let non_data_packet = FlatIpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            FlatSet::Template(TemplateRecord::new(256, Box::new([]))),
        );

        let result = non_data_packet.extract_as_key_str(&ie::IE::exporterIPv6Address, &None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AggregationError::FlatSetIsNotData
        ));
    }
}
