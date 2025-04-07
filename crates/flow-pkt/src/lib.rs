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
use indexmap::IndexMap;
use netgauze_analytics::flow::{AggrOp, AggregationError};
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

    pub fn flatten_data(self) -> Vec<FlatFlowDataInfo> {
        match self {
            Self::NetFlowV9(pkt) => pkt
                .flatten_data()
                .into_iter()
                .map(|x| FlatFlowDataInfo::NetFlowV9(Box::new(x)))
                .collect(),
            Self::IPFIX(pkt) => pkt
                .flatten_data()
                .into_iter()
                .map(|x| FlatFlowDataInfo::IPFIX(Box::new(x)))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlatFlowInfo {
    NetFlowV9(netflow::FlatNetFlowV9Packet),
    IPFIX(ipfix::FlatIpfixPacket),
}

impl FlatFlowInfo {
    pub fn export_time(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::IPFIX(packet) => packet.export_time(),
            Self::NetFlowV9(packet) => packet.unix_time(),
        }
    }

    pub fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        match self {
            Self::IPFIX(packet) => packet.extract_as_key_str(ie, indices),
            Self::NetFlowV9(_) => Err(AggregationError::FlatFlowInfoNFv9NotSupported),
        }
    }

    pub fn reduce(
        &mut self,
        incoming: &FlatFlowInfo,
        transform: &IndexMap<IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        match self {
            Self::IPFIX(packet) => {
                if let Self::IPFIX(incoming_packet) = incoming {
                    packet.reduce(incoming_packet, transform)
                } else {
                    Err(AggregationError::FlatFlowInfoNFv9NotSupported)
                }
            }
            Self::NetFlowV9(_) => Err(AggregationError::FlatFlowInfoNFv9NotSupported),
        }
    }
}

/// A version of FlatFlowInfo with data only
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlatFlowDataInfo {
    NetFlowV9(Box<netflow::FlatNetFlowV9DataPacket>),
    IPFIX(Box<ipfix::FlatIpfixDataPacket>),
}

impl FlatFlowDataInfo {
    pub fn export_time(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::IPFIX(packet) => packet.export_time(),
            Self::NetFlowV9(packet) => packet.unix_time(),
        }
    }

    pub fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        match self {
            Self::IPFIX(packet) => packet.extract_as_key_str(ie, indices),
            Self::NetFlowV9(_) => Err(AggregationError::FlatFlowInfoNFv9NotSupported),
        }
    }

    pub fn reduce(
        &mut self,
        incoming: &FlatFlowDataInfo,
        transform: &IndexMap<IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        match self {
            Self::IPFIX(packet) => {
                if let Self::IPFIX(incoming_packet) = incoming {
                    packet.reduce(incoming_packet, transform)
                } else {
                    Err(AggregationError::FlatFlowInfoNFv9NotSupported)
                }
            }
            Self::NetFlowV9(_) => Err(AggregationError::FlatFlowInfoNFv9NotSupported),
        }
    }
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
        ie::protocolIdentifier,
        ipfix::{FlatIpfixPacket, IpfixPacket},
        netflow::{FlatNetFlowV9Packet, NetFlowV9Packet},
    };
    use chrono::{TimeZone, Utc};
    use netgauze_iana::tcp::TCPHeaderFlags;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipfix_data_flatten() {
        let ipfix_data = IpfixPacket::new(
            Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
            0,
            0,
            Box::new([ipfix::Set::Data {
                id: DataSetId::new(400).unwrap(),
                records: Box::new([
                    ipfix::DataRecord::new(
                        Box::new([Field::egressVRFID(10)]),
                        Box::new([
                            Field::destinationIPv4Address(Ipv4Addr::new(10, 100, 0, 1)),
                            Field::octetDeltaCount(1200),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::ingress,
                            )),
                        ]),
                    ),
                    ipfix::DataRecord::new(
                        Box::new([Field::egressVRFID(30), Field::interfaceName("eth0".into())]),
                        Box::new([
                            Field::sourceIPv4Address(Ipv4Addr::new(10, 100, 0, 2)),
                            Field::packetDeltaCount(1),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::egress,
                            )),
                        ]),
                    ),
                ]),
            }]),
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
            Box::new([netflow::Set::Data {
                id: DataSetId::new(400).unwrap(),
                records: Box::new([
                    netflow::DataRecord::new(
                        Box::new([netflow::ScopeField::Interface(netflow::Interface(100))]),
                        Box::new([
                            Field::destinationIPv4Address(Ipv4Addr::new(10, 100, 0, 1)),
                            Field::octetDeltaCount(1200),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::ingress,
                            )),
                        ]),
                    ),
                    netflow::DataRecord::new(
                        Box::new([
                            netflow::ScopeField::System(netflow::System(1)),
                            netflow::ScopeField::Interface(netflow::Interface(200)),
                        ]),
                        Box::new([
                            Field::sourceIPv4Address(Ipv4Addr::new(10, 100, 0, 2)),
                            Field::packetDeltaCount(1),
                            Field::VMWare(vmware::Field::flowDirection(
                                vmware::flowDirection::egress,
                            )),
                        ]),
                    ),
                ]),
            }]),
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
            Box::new([
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ]),
        );
        let template_record2 = netflow::TemplateRecord::new(
            401,
            Box::new([FieldSpecifier::new(IE::srhIPv6ActiveSegmentType, 1).unwrap()]),
        );
        let options_template_record1 = netflow::OptionsTemplateRecord::new(
            1,
            Box::new([
                netflow::ScopeFieldSpecifier::new(netflow::ScopeIE::System, 4),
                netflow::ScopeFieldSpecifier::new(netflow::ScopeIE::Interface, 4),
            ]),
            Box::new([
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ]),
        );
        let netflow_template = NetFlowV9Packet::new(
            120,
            Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
            10,
            20,
            Box::new([
                netflow::Set::Template(Box::new([
                    template_record1.clone(),
                    template_record2.clone(),
                ])),
                netflow::Set::OptionsTemplate(Box::new([options_template_record1.clone()])),
            ]),
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
            Box::new([
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ]),
        );
        let template_record2 = ipfix::TemplateRecord::new(
            401,
            Box::new([FieldSpecifier::new(IE::srhIPv6ActiveSegmentType, 1).unwrap()]),
        );
        let options_template_record1 = ipfix::OptionsTemplateRecord::new(
            1,
            Box::new([
                FieldSpecifier::new(IE::VRFname, 10).unwrap(),
                FieldSpecifier::new(IE::ipv4Options, 1).unwrap(),
            ]),
            Box::new([
                FieldSpecifier::new(IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(IE::destinationIPv4Address, 4).unwrap(),
            ]),
        );
        let ipfix_template = IpfixPacket::new(
            Utc.with_ymd_and_hms(2024, 7, 8, 13, 0, 0).unwrap(),
            10,
            20,
            Box::new([
                ipfix::Set::Template(Box::new([
                    template_record1.clone(),
                    template_record2.clone(),
                ])),
                ipfix::Set::OptionsTemplate(Box::new([options_template_record1.clone()])),
            ]),
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

    #[test]
    fn test_supports_arithmetic() {
        // octetArray doesn't support arithmetic operations
        assert!(!IE::mplsLabelStackSection.supports_arithmetic_ops());
        assert!(!IE::paddingOctets.supports_arithmetic_ops());
        // number types (except unsigned256) supports arithmetic ops,
        assert!(IE::destinationIPv4PrefixLength.supports_arithmetic_ops());
        assert!(IE::flowActiveTimeout.supports_arithmetic_ops());
        assert!(IE::distinctCountOfSourceIPv4Address.supports_arithmetic_ops());
        assert!(IE::postMCastPacketDeltaCount.supports_arithmetic_ops());
        assert!(!IE::ipv6ExtensionHeadersFull.supports_arithmetic_ops());
        assert!(IE::mibObjectValueInteger.supports_arithmetic_ops());
        assert!(IE::absoluteError.supports_arithmetic_ops());
        // numbers that are identifiers, flags, or have subregistries don't support
        // arithmetic ops
        assert!(!IE::ipClassOfService.supports_arithmetic_ops());
        assert!(!IE::egressInterface.supports_arithmetic_ops());
        assert!(!IE::forwardingStatus.supports_arithmetic_ops());
        // Bool doesn't support arithmetic ops
        assert!(!IE::dataRecordsReliability.supports_arithmetic_ops());
        // Time doesn't support arithmetic ops
        assert!(!IE::observationTimeSeconds.supports_arithmetic_ops());
        assert!(!IE::observationTimeMilliseconds.supports_arithmetic_ops());
        assert!(!IE::observationTimeNanoseconds.supports_arithmetic_ops());
        assert!(!IE::observationTimeMicroseconds.supports_arithmetic_ops());
        // IP addresses don't support arithmetic ops
        assert!(!IE::sourceIPv4Address.supports_arithmetic_ops());
        assert!(!IE::sourceIPv6Address.supports_arithmetic_ops());
        // List doesn't support arithmetic ops
        assert!(!IE::bgpSourceCommunityList.supports_arithmetic_ops());
        assert!(!IE::ipv6ExtensionHeaderTypeCountList.supports_arithmetic_ops());
        assert!(!IE::subTemplateMultiList.supports_arithmetic_ops());
    }

    #[test]
    fn test_supports_bitwise_ops() {
        // octetArray supports bitwise operations
        assert!(IE::mplsLabelStackSection.supports_bitwise_ops());
        assert!(IE::paddingOctets.supports_bitwise_ops());
        // number types (including unsigned256) supports bitwise ops,
        assert!(IE::destinationIPv4PrefixLength.supports_bitwise_ops());
        assert!(IE::flowActiveTimeout.supports_bitwise_ops());
        assert!(IE::distinctCountOfSourceIPv4Address.supports_bitwise_ops());
        assert!(IE::postMCastPacketDeltaCount.supports_bitwise_ops());
        assert!(IE::ipv6ExtensionHeadersFull.supports_bitwise_ops());
        assert!(IE::mibObjectValueInteger.supports_bitwise_ops());
        // numbers that are identifiers, flags, or have subregistries support bitwise
        // ops
        assert!(IE::ipClassOfService.supports_bitwise_ops());
        assert!(IE::egressInterface.supports_bitwise_ops());
        assert!(IE::forwardingStatus.supports_bitwise_ops());
        // Bool doesn't support bitwise ops
        assert!(IE::dataRecordsReliability.supports_bitwise_ops());
        // Time doesn't support bitwise ops
        assert!(!IE::observationTimeSeconds.supports_bitwise_ops());
        assert!(!IE::observationTimeMilliseconds.supports_bitwise_ops());
        assert!(!IE::observationTimeNanoseconds.supports_bitwise_ops());
        assert!(!IE::observationTimeMicroseconds.supports_bitwise_ops());
        // IP addresses support bitwise ops
        assert!(IE::sourceIPv4Address.supports_bitwise_ops());
        assert!(IE::sourceIPv6Address.supports_bitwise_ops());
    }

    #[test]
    fn test_supports_comparison_ops() {
        // octetArray doesn't support comparison operations
        assert!(!IE::mplsLabelStackSection.supports_comparison_ops());
        assert!(!IE::paddingOctets.supports_comparison_ops());
        // number types (excluding unsigned256) supports comparison ops,
        assert!(IE::destinationIPv4PrefixLength.supports_comparison_ops());
        assert!(IE::flowActiveTimeout.supports_comparison_ops());
        assert!(IE::distinctCountOfSourceIPv4Address.supports_comparison_ops());
        assert!(IE::postMCastPacketDeltaCount.supports_comparison_ops());
        assert!(!IE::ipv6ExtensionHeadersFull.supports_comparison_ops());
        assert!(IE::mibObjectValueInteger.supports_comparison_ops());
        // numbers that are identifiers, flags, or have subregistries support comparison
        // ops
        assert!(IE::ipClassOfService.supports_comparison_ops());
        assert!(IE::egressInterface.supports_comparison_ops());
        assert!(IE::forwardingStatus.supports_comparison_ops());
        // Bool doesn't support comparison ops
        assert!(!IE::dataRecordsReliability.supports_comparison_ops());
        // Time supports comparison ops
        assert!(IE::observationTimeSeconds.supports_comparison_ops());
        assert!(IE::observationTimeMilliseconds.supports_comparison_ops());
        assert!(IE::observationTimeNanoseconds.supports_comparison_ops());
        assert!(IE::observationTimeMicroseconds.supports_comparison_ops());
        // IP addresses support comparison ops
        assert!(IE::sourceIPv4Address.supports_comparison_ops());
        assert!(IE::sourceIPv6Address.supports_comparison_ops());
    }

    #[test]
    fn test_field_add() {
        let mut octet1 = Field::octetDeltaCount(100);
        let octet2 = Field::octetDeltaCount(200);
        let packet1 = Field::packetDeltaCount(300);

        let result_err1 = octet1.add_field(&packet1);
        let result_err2 = octet1.add_assign_field(&packet1);
        let result = octet1.add_field(&octet2).expect("add field");
        octet1
            .add_assign_field(&octet2)
            .expect("add field mut failed");
        let expected = Field::octetDeltaCount(300);
        let expected_err = Some(FieldOperationError::InapplicableAdd(
            IE::octetDeltaCount,
            IE::packetDeltaCount,
        ));

        assert_eq!(result, expected);
        assert_eq!(octet1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_field_min() {
        let mut field1 = Field::octetDeltaCount(100);
        let field2 = Field::octetDeltaCount(200);
        let packet1 = Field::packetDeltaCount(300);

        let result_err1 = field1.min_field(&packet1);
        let result_err2 = field1.min_assign_field(&packet1);
        let result = field1.min_field(&field2).expect("min field");
        field1
            .min_assign_field(&field2)
            .expect("min field mut failed");
        let expected = Field::octetDeltaCount(100);
        let expected_err = Some(FieldOperationError::InapplicableMin(
            IE::octetDeltaCount,
            IE::packetDeltaCount,
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_field_max() {
        let mut field1 = Field::octetDeltaCount(100);
        let field2 = Field::octetDeltaCount(200);
        let packet1 = Field::packetDeltaCount(300);

        let result_err1 = field1.max_field(&packet1);
        let result_err2 = field1.max_assign_field(&packet1);
        let result = field1.max_field(&field2).expect("max field");
        field1
            .max_assign_field(&field2)
            .expect("max field mut failed");
        let expected = Field::octetDeltaCount(200);
        let expected_err = Some(FieldOperationError::InapplicableMax(
            IE::octetDeltaCount,
            IE::packetDeltaCount,
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_field_bitwise_or() {
        let mut field1 = Field::octetDeltaCount(100);
        let field2 = Field::octetDeltaCount(200);
        let packet1 = Field::packetDeltaCount(300);

        let result_err1 = field1.bitwise_or_field(&packet1);
        let result_err2 = field1.bitwise_or_assign_field(&packet1);
        let result = field1.bitwise_or_field(&field2).expect("bitwise or field");
        field1
            .bitwise_or_assign_field(&field2)
            .expect("bitwise or field mut failed");
        let expected = Field::octetDeltaCount(236);
        let expected_err = Some(FieldOperationError::InapplicableBitwise(
            IE::octetDeltaCount,
            IE::packetDeltaCount,
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_field_bitwise_or_tcp_control_bits() {
        let mut field1 = Field::tcpControlBits(TCPHeaderFlags::from(0x01u8));
        let field2 = Field::tcpControlBits(TCPHeaderFlags::from(0x02u8));
        let packet1 = Field::packetDeltaCount(300);

        let result_err1 = field1.bitwise_or_field(&packet1);
        let result_err2 = field1.bitwise_or_assign_field(&packet1);
        let result = field1.bitwise_or_field(&field2).expect("bitwise or field");
        field1
            .bitwise_or_assign_field(&field2)
            .expect("bitwise or field mut failed");
        let expected = Field::tcpControlBits(TCPHeaderFlags::from(0x03u8));
        let expected_err = Some(FieldOperationError::InapplicableBitwise(
            IE::tcpControlBits,
            IE::packetDeltaCount,
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_field_bitwise_or_protocol_identifier() {
        let mut field1 = Field::protocolIdentifier(protocolIdentifier::ICMP);
        let field2 = Field::protocolIdentifier(protocolIdentifier::IGMP);
        let packet1 = Field::packetDeltaCount(300);

        let result_err1 = field1.bitwise_or_field(&packet1);
        let result_err2 = field1.bitwise_or_assign_field(&packet1);
        let result = field1.bitwise_or_field(&field2).expect("bitwise or field");
        field1
            .bitwise_or_assign_field(&field2)
            .expect("bitwise or field mut failed");
        let expected = Field::protocolIdentifier(protocolIdentifier::from(0x03u8));
        let expected_err = Some(FieldOperationError::InapplicableBitwise(
            IE::protocolIdentifier,
            IE::packetDeltaCount,
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_vmware_ops() {
        let mut vendor_field1 = vmware::Field::averageLatency(100);
        let vendor_field2 = vmware::Field::averageLatency(200);
        let vendor_other_field = vmware::Field::algControlFlowId(123);

        let result_err1 = vendor_field1.add_field(&vendor_other_field);
        let result_err2 = vendor_field1.add_assign_field(&vendor_other_field);
        let result = vendor_field1.add_field(&vendor_field2).expect("add field");
        vendor_field1
            .add_assign_field(&vendor_field2)
            .expect("add field");
        let expected = vmware::Field::averageLatency(300);
        let expected_err = Some(vmware::FieldOperationError::InapplicableAdd(
            vmware::IE::averageLatency,
            vmware::IE::algControlFlowId,
        ));

        assert_eq!(result, expected);
        assert_eq!(vendor_field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_vendor_field_add() {
        let mut field1 = Field::VMWare(vmware::Field::averageLatency(100));
        let field2 = Field::VMWare(vmware::Field::averageLatency(200));
        let other_field = Field::VMWare(vmware::Field::algControlFlowId(123));

        let result_err1 = field1.add_field(&other_field);
        let result_err2 = field1.add_assign_field(&other_field);
        let result = field1.add_field(&field2).expect("add field");
        field1.add_assign_field(&field2).expect("add field");
        let expected = Field::VMWare(vmware::Field::averageLatency(300));
        let expected_err = Some(FieldOperationError::InapplicableAdd(
            IE::VMWare(vmware::IE::averageLatency),
            IE::VMWare(vmware::IE::algControlFlowId),
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_vendor_field_min() {
        let mut field1 = Field::VMWare(vmware::Field::averageLatency(100));
        let field2 = Field::VMWare(vmware::Field::averageLatency(200));
        let other_field = Field::VMWare(vmware::Field::algControlFlowId(123));

        let result_err1 = field1.min_field(&other_field);
        let result_err2 = field1.min_assign_field(&other_field);
        let result = field1.min_field(&field2).expect("min field");
        field1.min_assign_field(&field2).expect("min field");
        let expected = Field::VMWare(vmware::Field::averageLatency(100));
        let expected_err = Some(FieldOperationError::InapplicableMin(
            IE::VMWare(vmware::IE::averageLatency),
            IE::VMWare(vmware::IE::algControlFlowId),
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_vendor_field_max() {
        let mut field1 = Field::VMWare(vmware::Field::averageLatency(100));
        let field2 = Field::VMWare(vmware::Field::averageLatency(200));
        let other_field = Field::VMWare(vmware::Field::algControlFlowId(123));

        let result_err1 = field1.max_field(&other_field);
        let result_err2 = field1.max_assign_field(&other_field);
        let result = field1.max_field(&field2).expect("max field");
        field1.max_assign_field(&field2).expect("max field");
        let expected = Field::VMWare(vmware::Field::averageLatency(200));
        let expected_err = Some(FieldOperationError::InapplicableMax(
            IE::VMWare(vmware::IE::averageLatency),
            IE::VMWare(vmware::IE::algControlFlowId),
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }

    #[test]
    fn test_vendor_field_bitwise_or() {
        let mut field1 = Field::VMWare(vmware::Field::algControlFlowId(100));
        let field2 = Field::VMWare(vmware::Field::algControlFlowId(200));
        let other_field = Field::VMWare(vmware::Field::averageLatency(123));

        let result_err1 = field1.bitwise_or_field(&other_field);
        let result_err2 = field1.bitwise_or_field(&other_field);
        let result = field1.bitwise_or_field(&field2).expect("bitwise or field");
        field1
            .bitwise_or_assign_field(&field2)
            .expect("bitwise or field");
        let expected = Field::VMWare(vmware::Field::algControlFlowId(236));
        let expected_err = Some(FieldOperationError::InapplicableBitwise(
            IE::VMWare(vmware::IE::algControlFlowId),
            IE::VMWare(vmware::IE::averageLatency),
        ));

        assert_eq!(result, expected);
        assert_eq!(field1, expected);
        assert_eq!(result_err1.err(), expected_err);
        assert_eq!(result_err2.err(), expected_err);
    }
}
