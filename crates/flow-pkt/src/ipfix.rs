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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{ie::Field, DataSetId, FieldSpecifier};

pub const IPFIX_VERSION: u16 = 10;

/// A value of 2 is reserved for Template Sets
pub(crate) const IPFIX_TEMPLATE_SET_ID: u16 = 2;

/// A value of 3 is reserved for Options Template Sets
pub(crate) const IPFIX_OPTIONS_TEMPLATE_SET_ID: u16 = 3;

/// Simpler template that is used to decode data records
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct DecodingTemplate {
    pub scope_fields_specs: Box<[FieldSpecifier]>,
    pub fields_specs: Box<[FieldSpecifier]>,

    /// Number of Data Records processed using this template
    pub processed_count: u64,
}

impl DecodingTemplate {
    pub const fn new(
        scope_fields_specs: Box<[FieldSpecifier]>,
        fields_specs: Box<[FieldSpecifier]>,
    ) -> Self {
        Self {
            scope_fields_specs,
            fields_specs,
            processed_count: 0,
        }
    }

    /// Increment Data Record count by one
    pub const fn increment_processed_count(&mut self) {
        self.processed_count = self.processed_count.wrapping_add(1);
    }

    /// Get the current processed Data Record count
    pub const fn processed_count(&self) -> u64 {
        self.processed_count
    }

    /// Get the current processed Data Record count and reset the value to zero
    pub const fn reset_processed_count(&mut self) -> u64 {
        let prev = self.processed_count;
        self.processed_count = 0;
        prev
    }
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

    /// Consume the packet and return the owned sets
    pub fn into_sets(self) -> Box<[Set]> {
        self.sets
    }

    /// Add fields to all data records in the packet
    pub fn with_fields_added(self, add_fields: &[Field]) -> Self {
        let sets = self
            .sets
            .into_vec()
            .into_iter()
            .map(|set| set.with_fields_added(add_fields))
            .collect::<Box<[_]>>();

        Self {
            version: self.version,
            export_time: self.export_time,
            sequence_number: self.sequence_number,
            observation_domain_id: self.observation_domain_id,
            sets,
        }
    }

    /// Add scope fields to all data records in the packet
    pub fn with_scope_fields_added(self, add_scope_fields: &[Field]) -> Self {
        let sets = self
            .sets
            .into_vec()
            .into_iter()
            .map(|set| set.with_scope_fields_added(add_scope_fields))
            .collect::<Box<[_]>>();

        Self {
            version: self.version,
            export_time: self.export_time,
            sequence_number: self.sequence_number,
            observation_domain_id: self.observation_domain_id,
            sets,
        }
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

    /// Add fields to all data records in this set
    pub fn with_fields_added(self, add_fields: &[Field]) -> Self {
        match self {
            Set::Data { id, records } => {
                let modified_records = records
                    .into_vec()
                    .into_iter()
                    .map(|record| record.with_fields_added(add_fields))
                    .collect::<Box<[_]>>();

                Set::Data {
                    id,
                    records: modified_records,
                }
            }
            other => other,
        }
    }

    /// Add scope fields to all data records in this set
    pub fn with_scope_fields_added(self, add_scope_fields: &[Field]) -> Self {
        match self {
            Set::Data { id, records } => {
                let modified_records = records
                    .into_vec()
                    .into_iter()
                    .map(|record| record.with_scope_fields_added(add_scope_fields))
                    .collect::<Box<[_]>>();

                Set::Data {
                    id,
                    records: modified_records,
                }
            }
            other => other,
        }
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

    /// Add multiple fields
    pub fn with_fields_added(self, add_fields: &[Field]) -> Self {
        let mut fields = self.fields.into_vec();
        fields.extend_from_slice(add_fields);

        Self {
            scope_fields: self.scope_fields,
            fields: fields.into_boxed_slice(),
        }
    }

    /// Add multiple scope fields
    pub fn with_scope_fields_added(self, add_scope_fields: &[Field]) -> Self {
        let mut scope_fields = self.scope_fields.into_vec();
        scope_fields.extend_from_slice(add_scope_fields);

        Self {
            scope_fields: scope_fields.into_boxed_slice(),
            fields: self.fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie;
    use chrono::TimeZone;

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
    fn test_data_record_with_fields_added() {
        let original_record = DataRecord::new(
            Box::new([Field::octetDeltaCount(189)]),
            Box::new([Field::tcpDestinationPort(8080)]),
        );

        let modified_record = original_record.with_fields_added(&[
            Field::packetDeltaCount(10),
            Field::sourceIPv4Address([192, 168, 1, 1].into()),
        ]);

        let expected_record = DataRecord::new(
            Box::new([Field::octetDeltaCount(189)]),
            Box::new([
                Field::tcpDestinationPort(8080),
                Field::packetDeltaCount(10),
                Field::sourceIPv4Address([192, 168, 1, 1].into()),
            ]),
        );

        assert_eq!(modified_record, expected_record);
    }

    #[test]
    fn test_data_record_with_scope_fields_added() {
        let original_record = DataRecord::new(
            Box::new([Field::octetDeltaCount(189)]),
            Box::new([Field::tcpDestinationPort(8080)]),
        );

        let modified_record = original_record
            .with_scope_fields_added(&[Field::egressVRFID(42), Field::ingressVRFID(24)]);

        let expected_record = DataRecord::new(
            Box::new([
                Field::octetDeltaCount(189),
                Field::egressVRFID(42),
                Field::ingressVRFID(24),
            ]),
            Box::new([Field::tcpDestinationPort(8080)]),
        );

        assert_eq!(modified_record, expected_record);
    }

    #[test]
    fn test_set_with_fields_added() {
        let data_record1 = DataRecord::new(
            Box::new([Field::octetDeltaCount(100)]),
            Box::new([Field::tcpDestinationPort(80)]),
        );
        let data_record2 = DataRecord::new(
            Box::new([Field::octetDeltaCount(200)]),
            Box::new([Field::tcpDestinationPort(443)]),
        );

        let data_set = Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([data_record1, data_record2]),
        };

        let modified_set = data_set.with_fields_added(&[Field::packetDeltaCount(5)]);

        let expected_set = Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([
                DataRecord::new(
                    Box::new([Field::octetDeltaCount(100)]),
                    Box::new([Field::tcpDestinationPort(80), Field::packetDeltaCount(5)]),
                ),
                DataRecord::new(
                    Box::new([Field::octetDeltaCount(200)]),
                    Box::new([Field::tcpDestinationPort(443), Field::packetDeltaCount(5)]),
                ),
            ]),
        };

        assert_eq!(modified_set, expected_set);
    }

    #[test]
    fn test_set_with_scope_fields_added() {
        let data_record1 = DataRecord::new(
            Box::new([Field::octetDeltaCount(100)]),
            Box::new([Field::tcpDestinationPort(80)]),
        );
        let data_record2 = DataRecord::new(
            Box::new([Field::octetDeltaCount(200)]),
            Box::new([Field::tcpDestinationPort(443)]),
        );

        let data_set = Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([data_record1, data_record2]),
        };

        let modified_set = data_set.with_scope_fields_added(&[Field::egressVRFID(42)]);

        let expected_set = Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([
                DataRecord::new(
                    Box::new([Field::octetDeltaCount(100), Field::egressVRFID(42)]),
                    Box::new([Field::tcpDestinationPort(80)]),
                ),
                DataRecord::new(
                    Box::new([Field::octetDeltaCount(200), Field::egressVRFID(42)]),
                    Box::new([Field::tcpDestinationPort(443)]),
                ),
            ]),
        };

        assert_eq!(modified_set, expected_set);
    }

    #[test]
    fn test_ipfix_packet_with_fields_added() {
        let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();

        let original_packet = IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([
                Set::Data {
                    id: DataSetId::new(256).unwrap(),
                    records: Box::new([DataRecord::new(
                        Box::new([Field::octetDeltaCount(100)]),
                        Box::new([Field::tcpDestinationPort(80)]),
                    )]),
                },
                Set::Template(Box::new([TemplateRecord::new(
                    256,
                    Box::new([
                        FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                        FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
                    ]),
                )])),
            ]),
        );

        let modified_packet = original_packet.with_fields_added(&[Field::packetDeltaCount(5)]);

        let expected_packet = IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([
                Set::Data {
                    id: DataSetId::new(256).unwrap(),
                    records: Box::new([DataRecord::new(
                        Box::new([Field::octetDeltaCount(100)]),
                        Box::new([Field::tcpDestinationPort(80), Field::packetDeltaCount(5)]),
                    )]),
                },
                Set::Template(Box::new([TemplateRecord::new(
                    256,
                    Box::new([
                        FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                        FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
                    ]),
                )])),
            ]),
        );

        assert_eq!(modified_packet, expected_packet);
    }

    #[test]
    fn test_ipfix_packet_with_scope_fields_added() {
        let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
        let data_record = DataRecord::new(
            Box::new([Field::octetDeltaCount(100)]),
            Box::new([Field::tcpDestinationPort(80)]),
        );

        let original_packet = IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([data_record]),
            }]),
        );

        let modified_packet = original_packet.with_scope_fields_added(&[Field::egressVRFID(42)]);

        let expected_packet = IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([Field::octetDeltaCount(100), Field::egressVRFID(42)]),
                    Box::new([Field::tcpDestinationPort(80)]),
                )]),
            }]),
        );

        assert_eq!(modified_packet, expected_packet);
    }
}
