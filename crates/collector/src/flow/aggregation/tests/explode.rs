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

#[cfg(test)]
mod tests {
    use crate::flow::aggregation::{aggregator::*, config::*};
    use chrono::{TimeZone, Utc};
    use netgauze_flow_pkt::{
        ie::{protocolIdentifier, Field, IE},
        ipfix::{DataRecord, IpfixPacket, Set},
        DataSetId, FlowInfo,
    };
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    };

    #[test]
    fn test_explode_simple_ipfix_packet() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9995);
        let collection_time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        // Create test fields
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
            Field::sourceTransportPort(80),
            Field::destinationTransportPort(443),
            Field::octetDeltaCount(1000),
            Field::packetDeltaCount(10),
        ];

        let record = DataRecord::new(Box::new([]), fields.into_boxed_slice());
        let set = Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([record]),
        };

        let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap();
        let ipfix_pkt = IpfixPacket::new(export_time, 1, 100, Box::new([set]));
        let flow_info = FlowInfo::IPFIX(ipfix_pkt);

        // Define key and aggregation selectors
        let key_select = vec![
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::destinationIPv4Address, 0),
            FieldRef::new(IE::sourceTransportPort, 0),
            FieldRef::new(IE::destinationTransportPort, 0),
        ];

        let agg_select = vec![
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add),
        ];

        // Create expected AggFlowInfo
        let expected = vec![AggFlowInfo::from((
            FlowCacheKey::new(
                peer.ip(),
                Box::new([
                    Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
                    Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
                    Some(Field::sourceTransportPort(80)),
                    Some(Field::destinationTransportPort(443)),
                ]),
            ),
            FlowCacheRecord::new(
                HashSet::from([9995]),
                HashSet::from([100]),
                HashSet::from([DataSetId::new(256).unwrap()]),
                export_time,
                export_time,
                collection_time,
                collection_time,
                Box::new([
                    Some(Field::octetDeltaCount(1000)),
                    Some(Field::packetDeltaCount(10)),
                ]),
                1,
            ),
        ))];

        // Call explode and compare
        let result = explode(&flow_info, peer, &key_select, &agg_select, collection_time);
        assert_eq!(result.collect::<Vec<AggFlowInfo>>(), expected);
    }

    #[test]
    fn test_explode_multiple_records() {
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            2055,
        );
        let collection_time = Utc.with_ymd_and_hms(2025, 1, 1, 11, 0, 0).unwrap();

        // Create multiple records with different flows
        let record1_fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
            Field::octetDeltaCount(500),
        ];

        let record2_fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 3)),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 4)),
            Field::octetDeltaCount(750),
        ];

        let record1 = DataRecord::new(Box::new([]), record1_fields.into_boxed_slice());
        let record2 = DataRecord::new(Box::new([]), record2_fields.into_boxed_slice());

        let set = Set::Data {
            id: DataSetId::new(300).unwrap(),
            records: Box::new([record1, record2]),
        };

        let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 14, 30, 0).unwrap();
        let ipfix_pkt = IpfixPacket::new(export_time, 5, 200, Box::new([set]));
        let flow_info = FlowInfo::IPFIX(ipfix_pkt);

        let key_select = vec![
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::destinationIPv4Address, 0),
        ];

        let agg_select = vec![AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add)];

        // Create expected AggFlowInfo structs
        let expected = vec![
            AggFlowInfo::from((
                FlowCacheKey::new(
                    peer.ip(),
                    Box::new([
                        Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
                        Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
                    ]),
                ),
                FlowCacheRecord::new(
                    HashSet::from([2055]),
                    HashSet::from([200]),
                    HashSet::from([DataSetId::new(300).unwrap()]),
                    export_time,
                    export_time,
                    collection_time,
                    collection_time,
                    Box::new([Some(Field::octetDeltaCount(500))]),
                    1,
                ),
            )),
            AggFlowInfo::from((
                FlowCacheKey::new(
                    peer.ip(),
                    Box::new([
                        Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 3))),
                        Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 4))),
                    ]),
                ),
                FlowCacheRecord::new(
                    HashSet::from([2055]),
                    HashSet::from([200]),
                    HashSet::from([DataSetId::new(300).unwrap()]),
                    export_time,
                    export_time,
                    collection_time,
                    collection_time,
                    Box::new([Some(Field::octetDeltaCount(750))]),
                    1,
                ),
            )),
        ];

        // Call explode and compare
        let result = explode(&flow_info, peer, &key_select, &agg_select, collection_time);

        assert_eq!(result.collect::<Vec<AggFlowInfo>>(), expected);
    }

    #[test]
    fn test_explode_repeating_ie_fields() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 4739);
        let collection_time = Utc.with_ymd_and_hms(2025, 1, 1, 13, 0, 0).unwrap();

        // Create record with some repeating IEs
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::sourceIPv4Address(Ipv4Addr::new(100, 100, 100, 1)),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
            Field::protocolIdentifier(protocolIdentifier::IPv6),
            Field::protocolIdentifier(protocolIdentifier::IPv4),
            Field::protocolIdentifier(protocolIdentifier::UDP),
            Field::octetDeltaCount(100),
            Field::octetDeltaCount(200),
        ];

        let record = DataRecord::new(Box::new([]), fields.into_boxed_slice());
        let set = Set::Data {
            id: DataSetId::new(400).unwrap(),
            records: Box::new([record]),
        };

        let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 16, 0, 0).unwrap();
        let ipfix_pkt = IpfixPacket::new(export_time, 10, 300, Box::new([set]));
        let flow_info = FlowInfo::IPFIX(ipfix_pkt);

        // Select only some of the fields
        let key_select = vec![
            FieldRef::new(IE::sourceIPv4Address, 1),
            FieldRef::new(IE::destinationIPv4Address, 0),
            FieldRef::new(IE::protocolIdentifier, 0),
            FieldRef::new(IE::protocolIdentifier, 2),
        ];

        let agg_select = vec![
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::octetDeltaCount, 1, AggOp::Add),
        ];

        // Create expected AggFlowInfo
        let expected = vec![AggFlowInfo::from((
            FlowCacheKey::new(
                peer.ip(),
                Box::new([
                    Some(Field::sourceIPv4Address(Ipv4Addr::new(100, 100, 100, 1))),
                    Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
                    Some(Field::protocolIdentifier(protocolIdentifier::IPv6)),
                    Some(Field::protocolIdentifier(protocolIdentifier::UDP)),
                ]),
            ),
            FlowCacheRecord::new(
                HashSet::from([4739]),
                HashSet::from([300]),
                HashSet::from([DataSetId::new(400).unwrap()]),
                export_time,
                export_time,
                collection_time,
                collection_time,
                Box::new([
                    Some(Field::octetDeltaCount(100)),
                    Some(Field::octetDeltaCount(200)),
                ]),
                1,
            ),
        ))];

        // Call explode and compare
        let result = explode(&flow_info, peer, &key_select, &agg_select, collection_time);

        assert_eq!(result.collect::<Vec<AggFlowInfo>>(), expected);
    }

    #[test]
    fn test_explode_missing_fields() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 9996);
        let collection_time = Utc.with_ymd_and_hms(2025, 1, 1, 15, 0, 0).unwrap();

        // Create record with only some of the expected fields
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::octetDeltaCount(500),
            Field::sourceIPv6Address(Ipv6Addr::new(0xc, 0xa, 0xf, 0xe, 0, 0, 0, 0)),
        ];

        let record = DataRecord::new(Box::new([]), fields.into_boxed_slice());
        let set = Set::Data {
            id: DataSetId::new(500).unwrap(),
            records: Box::new([record]),
        };

        let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 18, 0, 0).unwrap();
        let ipfix_pkt = IpfixPacket::new(export_time, 15, 400, Box::new([set]));
        let flow_info = FlowInfo::IPFIX(ipfix_pkt);

        let key_select = vec![
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::destinationIPv4Address, 0), // Missing
            FieldRef::new(IE::sourceIPv6Address, 0),
        ];

        let agg_select = vec![
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add), // Missing
        ];

        // Create expected AggFlowInfo
        let expected = vec![AggFlowInfo::from((
            FlowCacheKey::new(
                peer.ip(),
                Box::new([
                    Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
                    None,
                    Some(Field::sourceIPv6Address(Ipv6Addr::new(
                        0xc, 0xa, 0xf, 0xe, 0, 0, 0, 0,
                    ))),
                ]),
            ),
            FlowCacheRecord::new(
                HashSet::from([9996]),
                HashSet::from([400]),
                HashSet::from([DataSetId::new(500).unwrap()]),
                export_time,
                export_time,
                collection_time,
                collection_time,
                Box::new([Some(Field::octetDeltaCount(500)), None]),
                1,
            ),
        ))];

        // Call explode and compare
        let result = explode(&flow_info, peer, &key_select, &agg_select, collection_time);

        assert_eq!(result.collect::<Vec<AggFlowInfo>>(), expected);
    }

    #[test]
    fn test_explode_empty_selectors() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 2055);
        let collection_time = Utc.with_ymd_and_hms(2025, 1, 1, 16, 0, 0).unwrap();

        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::octetDeltaCount(300),
        ];

        let record = DataRecord::new(Box::new([]), fields.into_boxed_slice());
        let set = Set::Data {
            id: DataSetId::new(600).unwrap(),
            records: Box::new([record]),
        };

        let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 20, 0, 0).unwrap();
        let ipfix_pkt = IpfixPacket::new(export_time, 20, 500, Box::new([set]));
        let flow_info = FlowInfo::IPFIX(ipfix_pkt);

        // Empty selectors
        let key_select: Vec<FieldRef> = vec![];
        let agg_select: Vec<AggFieldRef> = vec![];

        // Create expected AggFlowInfo
        let expected = vec![AggFlowInfo::from((
            FlowCacheKey::new(peer.ip(), Box::new([])),
            FlowCacheRecord::new(
                HashSet::from([2055]),
                HashSet::from([500]),
                HashSet::from([DataSetId::new(600).unwrap()]),
                export_time,
                export_time,
                collection_time,
                collection_time,
                Box::new([]),
                1,
            ),
        ))];

        // Call explode and compare
        let result = explode(&flow_info, peer, &key_select, &agg_select, collection_time);

        assert_eq!(result.collect::<Vec<AggFlowInfo>>(), expected);
    }
}
