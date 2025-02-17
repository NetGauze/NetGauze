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

use crate::{
    ie::{Field, Fields},
    DataSetId, FieldSpecifier,
};

pub const IPFIX_VERSION: u16 = 10;

/// A value of 2 is reserved for Template Sets
pub(crate) const IPFIX_TEMPLATE_SET_ID: u16 = 2;

/// A value of 3 is reserved for Options Template Sets
pub(crate) const IPFIX_OPTIONS_TEMPLATE_SET_ID: u16 = 3;

/// Simpler template that is used to decode data records
pub type DecodingTemplate = (Vec<FieldSpecifier>, Vec<FieldSpecifier>);

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
    sets: Vec<Set>,
}

impl IpfixPacket {
    pub const fn new(
        export_time: DateTime<Utc>,
        sequence_number: u32,
        observation_domain_id: u32,
        sets: Vec<Set>,
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
    pub const fn sets(&self) -> &Vec<Set> {
        &self.sets
    }

    pub fn flatten(self) -> Vec<FlatIpfixPacket> {
        let export_time = self.export_time;
        let sequence_number = self.sequence_number;
        let observation_domain_id = self.observation_domain_id;
        self.sets
            .into_iter()
            .flat_map(|set| set.flatten())
            .map(|set| FlatIpfixPacket {
                export_time,
                sequence_number,
                observation_domain_id,
                set,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
            Self::Template(_) => IPFIX_TEMPLATE_SET_ID,
            Self::OptionsTemplate(_) => IPFIX_OPTIONS_TEMPLATE_SET_ID,
            Self::Data { id, records: _ } => id.0,
        }
    }

    pub fn flatten(self) -> Vec<FlatSet> {
        match self {
            Self::Template(values) => values
                .into_iter()
                .map(|x| FlatSet::new(Some(x), None, None))
                .collect(),
            Self::OptionsTemplate(values) => values
                .into_iter()
                .map(|x| FlatSet::new(None, Some(x), None))
                .collect(),
            Self::Data { id, records } => records
                .into_iter()
                .map(|record| {
                    FlatSet::new(None, None, Some(FlatDataSet::new(id, record.flatten())))
                })
                .collect(),
        }
    }
}

/// A version of [Set] that contain only one record
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatSet {
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    template: Option<TemplateRecord>,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    options_template: Option<OptionsTemplateRecord>,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    data: Option<FlatDataSet>,
}

impl FlatSet {
    pub const fn new(
        template: Option<TemplateRecord>,
        options_template: Option<OptionsTemplateRecord>,
        data: Option<FlatDataSet>,
    ) -> Self {
        Self {
            template,
            options_template,
            data,
        }
    }

    pub const fn template(&self) -> Option<&TemplateRecord> {
        self.template.as_ref()
    }

    pub const fn options_template(&self) -> Option<&OptionsTemplateRecord> {
        self.options_template.as_ref()
    }

    pub const fn data(&self) -> Option<&FlatDataSet> {
        self.data.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatDataSet {
    id: DataSetId,
    record: FlatDataRecord,
}

impl FlatDataSet {
    pub const fn new(id: DataSetId, record: FlatDataRecord) -> Self {
        Self { id, record }
    }

    pub const fn id(&self) -> DataSetId {
        self.id
    }

    pub const fn record(&self) -> &FlatDataRecord {
        &self.record
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
    /// 65535. TODO (AH): do we need to check for template IDs < 256,
    /// see [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1)
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// List of [`FieldSpecifier`] defined in the template.
    pub const fn field_specifiers(&self) -> &Vec<FieldSpecifier> {
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct DataRecord {
    scope_fields: Vec<Field>,
    fields: Vec<Field>,
}

impl DataRecord {
    pub const fn new(scope_fields: Vec<Field>, fields: Vec<Field>) -> Self {
        Self {
            scope_fields,
            fields,
        }
    }

    pub const fn scope_fields(&self) -> &Vec<Field> {
        &self.scope_fields
    }

    pub const fn fields(&self) -> &Vec<Field> {
        &self.fields
    }

    pub fn flatten(self) -> FlatDataRecord {
        FlatDataRecord::new(self.scope_fields.into(), self.fields.into())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        let sets = vec![
            Set::Template(vec![TemplateRecord::new(
                256,
                vec![
                    FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                    FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
                ],
            )]),
            Set::OptionsTemplate(vec![OptionsTemplateRecord::new(
                258,
                vec![FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()],
                vec![FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()],
            )]),
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: vec![DataRecord::new(
                    vec![Field::octetDeltaCount(189)],
                    vec![Field::tcpDestinationPort(8080)],
                )],
            },
        ];
        let packet = IpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            sets.clone(),
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
        let sets = vec![
            Set::Template(vec![TemplateRecord::new(
                256,
                vec![
                    FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                    FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
                ],
            )]),
            Set::OptionsTemplate(vec![OptionsTemplateRecord::new(
                258,
                vec![FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()],
                vec![FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()],
            )]),
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: vec![DataRecord::new(
                    vec![Field::octetDeltaCount(189)],
                    vec![Field::tcpDestinationPort(8080)],
                )],
            },
        ];
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
        assert!(flat_packets[0].set.template().is_some());
        assert!(flat_packets[1].set.options_template().is_some());
        assert!(flat_packets[2].set.data().is_some());
    }

    #[test]
    fn test_template_record() {
        let template = TemplateRecord::new(
            256,
            vec![
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ],
        );
        assert_eq!(template.id(), 256);
        assert_eq!(
            template.field_specifiers(),
            &vec![
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ]
        );
    }

    #[test]
    fn test_options_template_record() {
        let template = OptionsTemplateRecord::new(
            258,
            vec![FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()],
            vec![FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()],
        );
        assert_eq!(template.id(), 258);
        assert_eq!(
            template.scope_field_specifiers(),
            &vec![FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()]
        );
        assert_eq!(
            template.field_specifiers(),
            &vec![FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()]
        );
    }

    #[test]
    fn test_data_record() {
        let record = DataRecord::new(
            vec![Field::octetDeltaCount(189)],
            vec![Field::tcpDestinationPort(8080)],
        );
        assert_eq!(record.scope_fields(), &vec![Field::octetDeltaCount(189)]);
        assert_eq!(record.fields(), &vec![Field::tcpDestinationPort(8080)]);
    }

    #[test]
    fn test_flat_data_record() {
        let record = FlatDataRecord::new(
            Fields {
                interfaceName: Some(vec!["eth0".to_string()]),
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
                interfaceName: Some(vec!["eth0".to_string()]),
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
            vec![
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ],
        );
        let options_template = OptionsTemplateRecord::new(
            258,
            vec![FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()],
            vec![FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()],
        );
        let data = DataRecord::new(
            vec![Field::octetDeltaCount(189)],
            vec![Field::tcpDestinationPort(8080)],
        );
        let sets = [
            Set::Template(vec![template.clone()]),
            Set::OptionsTemplate(vec![options_template.clone()]),
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: vec![data.clone()],
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
            vec![
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::tcpDestinationPort, 2).unwrap(),
            ],
        );
        let options_template = OptionsTemplateRecord::new(
            258,
            vec![FieldSpecifier::new(ie::IE::egressVRFID, 4).unwrap()],
            vec![FieldSpecifier::new(ie::IE::interfaceName, 255).unwrap()],
        );
        let data = DataRecord::new(
            vec![Field::octetDeltaCount(189)],
            vec![Field::tcpDestinationPort(8080)],
        );
        let flat_data = data.clone().flatten();
        let sets = [
            FlatSet::new(Some(template.clone()), None, None),
            FlatSet::new(None, Some(options_template.clone()), None),
            FlatSet::new(
                None,
                None,
                Some(FlatDataSet::new(DataSetId::new(256).unwrap(), flat_data)),
            ),
        ];
        assert!(sets[0].template().is_some());
        assert!(sets[1].options_template().is_some());
        assert!(sets[2].data().is_some());
    }
}
