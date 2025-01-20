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

#[cfg(feature = "codec")]
pub mod codec;
pub mod ie;
pub mod ipfix;
pub mod netflow;
#[cfg(feature = "serde")]
pub mod wire;

use crate::ie::*;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlowInfo {
    NetFlowV9(netflow::NetFlowV9Packet),
    IPFIX(ipfix::IpfixPacket),
}

impl FlowInfo {
    pub fn flatten(self) -> Vec<FlatFlowInfo> {
        match self {
            FlowInfo::NetFlowV9(pkt) => pkt
                .flatten()
                .into_iter()
                .map(FlatFlowInfo::NetFlowV9)
                .collect(),
            FlowInfo::IPFIX(pkt) => pkt.flatten().into_iter().map(FlatFlowInfo::IPFIX).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlatFlowInfo {
    NetFlowV9(netflow::FlatNetFlowV9Packet),
    IPFIX(ipfix::FlatIpfixPacket),
}

/// Errors when crafting a new Set
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FieldSpecifierError {
    /// Specified field length was out of the range defined by the registry
    InvalidLength(u16, IE),
}

impl std::fmt::Display for FieldSpecifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldSpecifierError::InvalidLength(len, ie) => {
                write!(f, "Invalid length specified {len} for IE: {ie:?}")
            }
        }
    }
}

impl std::error::Error for FieldSpecifierError {}

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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct FieldSpecifier {
    element_id: IE,
    length: u16,
}

impl FieldSpecifier {
    pub fn new(element_id: IE, length: u16) -> Result<Self, FieldSpecifierError> {
        if let Some(range) = element_id.length_range() {
            if !range.contains(&length) {
                return Err(FieldSpecifierError::InvalidLength(length, element_id));
            }
        };
        Ok(Self { element_id, length })
    }

    pub const fn element_id(&self) -> IE {
        self.element_id
    }

    pub const fn length(&self) -> u16 {
        self.length
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum DataSetIdError {
    InvalidId(u16),
}

impl std::fmt::Display for DataSetIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId(id) => {
                write!(f, "Invalid data set id specified {id}")
            }
        }
    }
}

impl std::error::Error for DataSetIdError {}

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct DataSetId(u16);

/// Values 256 and above are used for Data Sets
pub(crate) const DATA_SET_MIN_ID: u16 = 256;

impl DataSetId {
    pub const fn new(id: u16) -> Result<Self, DataSetIdError> {
        if id < DATA_SET_MIN_ID {
            Err(DataSetIdError::InvalidId(id))
        } else {
            Ok(Self(id))
        }
    }

    #[inline]
    pub const fn id(&self) -> u16 {
        self.0
    }
}

impl Deref for DataSetId {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "fuzz")]
fn arbitrary_datetime(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    loop {
        let seconds = u.int_in_range(0..=i64::MAX)?;
        if let chrono::LocalResult::Single(tt) = chrono::Utc.timestamp_opt(seconds, 0) {
            return Ok(tt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ipfix::{FlatIpfixPacket, IpfixPacket},
        netflow::{FlatNetFlowV9Packet, NetFlowV9Packet},
    };
    use chrono::{TimeZone, Utc};
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipfix_data_flatten() {
        let ipfix_data = IpfixPacket::new(
            Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
            0,
            0,
            vec![ipfix::Set::Data {
                id: DataSetId::new(400).unwrap(),
                records: vec![
                    ipfix::DataRecord::new(
                        vec![Field::egressVRFID(10)],
                        vec![
                            Field::destinationIPv4Address(Ipv4Addr::new(10, 100, 0, 1)),
                            Field::octetDeltaCount(1200),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::ingress,
                            )),
                        ],
                    ),
                    ipfix::DataRecord::new(
                        vec![
                            Field::egressVRFID(30),
                            Field::interfaceName("eth0".to_string()),
                        ],
                        vec![
                            Field::sourceIPv4Address(Ipv4Addr::new(10, 100, 0, 2)),
                            Field::packetDeltaCount(1),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::egress,
                            )),
                        ],
                    ),
                ],
            }],
        );
        let flow = FlowInfo::IPFIX(ipfix_data);
        let flattened = flow.flatten();
        let scope_fields1 = Fields {
            egressVRFID: Some(vec![10]),
            ..Default::default()
        };
        let scope_fields2 = Fields {
            egressVRFID: Some(vec![30]),
            interfaceName: Some(vec!["eth0".into()]),
            ..Default::default()
        };
        let fields1 = Fields {
            destinationIPv4Address: Some(vec![Ipv4Addr::new(10, 100, 0, 1)]),
            octetDeltaCount: Some(vec![1200]),
            vmware: Some(vmware::Fields {
                flowDirection: Some(vec![vmware::flowDirection::ingress]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let fields2 = Fields {
            sourceIPv4Address: Some(vec![Ipv4Addr::new(10, 100, 0, 2)]),
            packetDeltaCount: Some(vec![1]),
            vmware: Some(vmware::Fields {
                flowDirection: Some(vec![vmware::flowDirection::egress]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let expected = vec![
            FlatFlowInfo::IPFIX(FlatIpfixPacket::new(
                Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
                0,
                0,
                ipfix::FlatSet::Data {
                    id: DataSetId::new(400).unwrap(),
                    record: Box::new(ipfix::FlatDataRecord::new(scope_fields1, fields1)),
                },
            )),
            FlatFlowInfo::IPFIX(FlatIpfixPacket::new(
                Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
                0,
                0,
                ipfix::FlatSet::Data {
                    id: DataSetId::new(400).unwrap(),
                    record: Box::new(ipfix::FlatDataRecord::new(scope_fields2, fields2)),
                },
            )),
        ];
        assert_eq!(expected, flattened);
    }

    #[test]
    fn test_netflow_data_flatten() {
        let data = NetFlowV9Packet::new(
            1000,
            Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
            0,
            0,
            vec![netflow::Set::Data {
                id: DataSetId::new(400).unwrap(),
                records: vec![
                    netflow::DataRecord::new(
                        vec![netflow::ScopeField::Interface(netflow::Interface(100))],
                        vec![
                            Field::destinationIPv4Address(Ipv4Addr::new(10, 100, 0, 1)),
                            Field::octetDeltaCount(1200),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::ingress,
                            )),
                        ],
                    ),
                    netflow::DataRecord::new(
                        vec![
                            netflow::ScopeField::System(netflow::System(1)),
                            netflow::ScopeField::Interface(netflow::Interface(200)),
                        ],
                        vec![
                            Field::sourceIPv4Address(Ipv4Addr::new(10, 100, 0, 2)),
                            Field::packetDeltaCount(1),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::egress,
                            )),
                        ],
                    ),
                ],
            }],
        );
        let flow = FlowInfo::NetFlowV9(data);
        let flattened = flow.flatten();
        let scope_fields1 = netflow::ScopeFields {
            interface: Some(vec![netflow::Interface(100)]),
            ..Default::default()
        };
        let scope_fields2 = netflow::ScopeFields {
            system: Some(vec![netflow::System(1)]),
            interface: Some(vec![netflow::Interface(200)]),
            ..Default::default()
        };
        let fields1 = Fields {
            destinationIPv4Address: Some(vec![Ipv4Addr::new(10, 100, 0, 1)]),
            octetDeltaCount: Some(vec![1200]),
            vmware: Some(vmware::Fields {
                flowDirection: Some(vec![vmware::flowDirection::ingress]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let fields2 = Fields {
            sourceIPv4Address: Some(vec![Ipv4Addr::new(10, 100, 0, 2)]),
            packetDeltaCount: Some(vec![1]),
            vmware: Some(vmware::Fields {
                flowDirection: Some(vec![vmware::flowDirection::egress]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let expected1 = FlatFlowInfo::NetFlowV9(FlatNetFlowV9Packet::new(
            1000,
            Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
            0,
            0,
            netflow::FlatSet::Data {
                id: DataSetId::new(400).unwrap(),
                record: Box::new(netflow::FlatDataRecord::new(
                    scope_fields1.clone(),
                    fields1.clone(),
                )),
            },
        ));
        let expected2 = FlatFlowInfo::NetFlowV9(FlatNetFlowV9Packet::new(
            1000,
            Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
            0,
            0,
            netflow::FlatSet::Data {
                id: DataSetId::new(400).unwrap(),
                record: Box::new(netflow::FlatDataRecord::new(
                    scope_fields2.clone(),
                    fields2.clone(),
                )),
            },
        ));

        let expected = vec![expected1, expected2];
        assert_eq!(expected, flattened);
    }

    #[test]
    fn test_netflow_template() {
        let template_record1 = netflow::TemplateRecord::new(
            400,
            vec![
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ],
        );
        let template_record2 = netflow::TemplateRecord::new(
            401,
            vec![FieldSpecifier::new(IE::srhIPv6ActiveSegmentType, 1).unwrap()],
        );
        let options_template_record1 = netflow::OptionsTemplateRecord::new(
            1,
            vec![
                netflow::ScopeFieldSpecifier::new(netflow::ScopeIE::System, 4),
                netflow::ScopeFieldSpecifier::new(netflow::ScopeIE::Interface, 4),
            ],
            vec![
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ],
        );
        let netflow_template = NetFlowV9Packet::new(
            120,
            Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
            10,
            20,
            vec![
                netflow::Set::Template(vec![template_record1.clone(), template_record2.clone()]),
                netflow::Set::OptionsTemplate(vec![options_template_record1.clone()]),
            ],
        );
        let template = FlowInfo::NetFlowV9(netflow_template);

        let flattened = template.flatten();
        let expected = vec![
            FlatFlowInfo::NetFlowV9(FlatNetFlowV9Packet::new(
                120,
                Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
                10,
                20,
                netflow::FlatSet::Template(template_record1),
            )),
            FlatFlowInfo::NetFlowV9(FlatNetFlowV9Packet::new(
                120,
                Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
                10,
                20,
                netflow::FlatSet::Template(template_record2),
            )),
            FlatFlowInfo::NetFlowV9(FlatNetFlowV9Packet::new(
                120,
                Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
                10,
                20,
                netflow::FlatSet::OptionsTemplate(options_template_record1),
            )),
        ];
        assert_eq!(flattened, expected);
    }

    #[test]
    fn test_ipfix_template() {
        let template_record1 = ipfix::TemplateRecord::new(
            400,
            vec![
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ],
        );
        let template_record2 = ipfix::TemplateRecord::new(
            401,
            vec![FieldSpecifier::new(IE::srhIPv6ActiveSegmentType, 1).unwrap()],
        );
        let options_template_record1 = ipfix::OptionsTemplateRecord::new(
            1,
            vec![
                FieldSpecifier::new(IE::VRFname, 10).unwrap(),
                FieldSpecifier::new(IE::ipv4Options, 1).unwrap(),
            ],
            vec![
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ],
        );
        let ipfix_template = IpfixPacket::new(
            Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
            10,
            20,
            vec![
                ipfix::Set::Template(vec![template_record1.clone(), template_record2.clone()]),
                ipfix::Set::OptionsTemplate(vec![options_template_record1.clone()]),
            ],
        );
        let template = FlowInfo::IPFIX(ipfix_template);

        let flattened = template.flatten();
        let expected = vec![
            FlatFlowInfo::IPFIX(FlatIpfixPacket::new(
                Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
                10,
                20,
                ipfix::FlatSet::Template(template_record1),
            )),
            FlatFlowInfo::IPFIX(FlatIpfixPacket::new(
                Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
                10,
                20,
                ipfix::FlatSet::Template(template_record2),
            )),
            FlatFlowInfo::IPFIX(FlatIpfixPacket::new(
                Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
                10,
                20,
                ipfix::FlatSet::OptionsTemplate(options_template_record1),
            )),
        ];
        assert_eq!(flattened, expected);
    }
}
