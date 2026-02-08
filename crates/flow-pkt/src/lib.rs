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

//! Flow packet types and utilities for IPFIX and NetFlow v9.
//!
//! This crate provides data models, information elements, and (optional)
//! codecs for working with IPFIX and NetFlow v9 packets. It includes helpers
//! to inspect packet metadata and to manipulate fields for IPFIX data records.
//!
//! # Example
//!
//! ```rust
//! use chrono::{TimeZone, Utc};
//! use netgauze_flow_pkt::ipfix::{IpfixPacket, Set};
//! use netgauze_flow_pkt::{DataSetId, FlowInfo};
//!
//! let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
//! let ipfix = IpfixPacket::new(
//!     export_time,
//!     1,
//!     42,
//!     Box::new([Set::Data {
//!         id: DataSetId::new(400).unwrap(),
//!         records: Box::new([]),
//!     }]),
//! );
//!
//! let flow = FlowInfo::IPFIX(ipfix);
//! assert_eq!(flow.observation_domain_id(), 42);
//! ```

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

/// Errors for FlowInfo operations
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, strum_macros::Display)]
pub enum FlowInfoError {
    /// NetFlow v9 is not supported for this operation
    #[strum(serialize = "NetFlow v9 is not supported for this operation")]
    NetFlowV9NotSupported,
}

impl std::error::Error for FlowInfoError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlowInfo {
    NetFlowV9(netflow::NetFlowV9Packet),
    IPFIX(ipfix::IpfixPacket),
}

impl FlowInfo {
    pub const fn export_time(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::IPFIX(packet) => packet.export_time(),
            Self::NetFlowV9(packet) => packet.unix_time(),
        }
    }

    pub const fn sequence_number(&self) -> u32 {
        match self {
            Self::IPFIX(packet) => packet.sequence_number(),
            Self::NetFlowV9(packet) => packet.sequence_number(),
        }
    }

    pub const fn observation_domain_id(&self) -> u32 {
        match self {
            Self::IPFIX(packet) => packet.observation_domain_id(),
            Self::NetFlowV9(packet) => packet.source_id(),
        }
    }

    /// Add fields to all data records in the flow packet
    pub fn with_fields_added(self, add_fields: &[Field]) -> Result<Self, FlowInfoError> {
        match self {
            Self::IPFIX(packet) => Ok(Self::IPFIX(packet.with_fields_added(add_fields))),
            Self::NetFlowV9(_) => Err(FlowInfoError::NetFlowV9NotSupported),
        }
    }

    /// Add scope fields to all data records in the flow packet
    pub fn with_scope_fields_added(
        self,
        add_scope_fields: &[Field],
    ) -> Result<Self, FlowInfoError> {
        match self {
            Self::IPFIX(packet) => Ok(Self::IPFIX(
                packet.with_scope_fields_added(add_scope_fields),
            )),
            Self::NetFlowV9(_) => Err(FlowInfoError::NetFlowV9NotSupported),
        }
    }
}

/// Errors when crafting a new Set
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, strum_macros::Display)]
pub enum FieldSpecifierError {
    /// Specified field length was out of the range defined by the registry
    #[strum(to_string = "Invalid length specified {0} for IE: {1:?}")]
    InvalidLength(u16, IE),
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
        if let Some(range) = element_id.length_range()
            && !range.contains(&length)
        {
            return Err(FieldSpecifierError::InvalidLength(length, element_id));
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

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize, strum_macros::Display)]
pub enum DataSetIdError {
    #[strum(serialize = "Invalid data set id specified: {0}")]
    InvalidId(u16),
}

impl std::error::Error for DataSetIdError {}

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
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
    use crate::ie::protocolIdentifier;
    use crate::ipfix::IpfixPacket;
    use crate::netflow::NetFlowV9Packet;
    use chrono::{TimeZone, Utc};
    use netgauze_iana::tcp::TCPHeaderFlags;

    #[test]
    fn test_flow_info_api() {
        let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
        let sequence_number = 2;
        let observation_domain = 100;
        let ipfix_data = IpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain,
            Box::new([ipfix::Set::Data {
                id: DataSetId::new(400).unwrap(),
                records: Box::new([]),
            }]),
        );
        let netflow_data = NetFlowV9Packet::new(
            45646,
            export_time,
            sequence_number,
            observation_domain,
            Box::new([netflow::Set::Data {
                id: DataSetId::new(400).unwrap(),
                records: Box::new([]),
            }]),
        );

        let flow_ipfix = FlowInfo::IPFIX(ipfix_data.clone());
        let flow_netflow = FlowInfo::NetFlowV9(netflow_data.clone());

        assert_eq!(ipfix_data.export_time(), export_time);
        assert_eq!(ipfix_data.sequence_number(), sequence_number);
        assert_eq!(ipfix_data.observation_domain_id(), observation_domain);
        assert_eq!(netflow_data.unix_time(), export_time);
        assert_eq!(netflow_data.sequence_number(), sequence_number);
        assert_eq!(netflow_data.source_id(), observation_domain);
        assert_eq!(flow_ipfix.export_time(), export_time);
        assert_eq!(flow_ipfix.sequence_number(), sequence_number);
        assert_eq!(flow_ipfix.observation_domain_id(), observation_domain);
        assert_eq!(flow_netflow.export_time(), export_time);
        assert_eq!(flow_netflow.sequence_number(), sequence_number);
        assert_eq!(flow_netflow.observation_domain_id(), observation_domain);
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
