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

use crate::flow::aggregation::aggregator::*;
use chrono::{TimeZone, Utc};
use netgauze_analytics::aggregation::Aggregator;
use netgauze_flow_pkt::{
    ie::{protocolIdentifier, Field, IE},
    ipfix::{DataRecord, IpfixPacket, Set},
    DataSetId, FlowInfo,
};
use netgauze_iana::tcp::TCPHeaderFlags;
use rustc_hash::FxHashMap;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

fn create_test_config(
    key_select: Box<[FieldRef]>,
    agg_select: Box<[AggFieldRef]>,
) -> UnifiedConfig {
    UnifiedConfig::new(
        Duration::from_secs(60),
        Duration::from_secs(10),
        key_select,
        agg_select,
    )
}

fn create_test_agg_flow_info(
    peer_ip: IpAddr,
    key_fields: Box<[Option<Field>]>,
    agg_fields: Box<[Option<Field>]>,
    record_count: u64,
) -> AggFlowInfo {
    let time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

    AggFlowInfo::from((
        FlowCacheKey {
            peer_ip,
            key_fields,
        },
        FlowCacheRecord {
            peer_ports: HashSet::from([9995]),
            observation_domain_ids: HashSet::from([100]),
            template_ids: HashSet::from([DataSetId::new(256).unwrap()]),
            min_export_time: time,
            max_export_time: time,
            min_collection_time: time,
            max_collection_time: time,
            agg_fields,
            record_count,
        },
    ))
}

#[test]
fn test_aggregator_init() {
    let config = create_test_config(Box::new([]), Box::new([]));
    let aggregator = FlowAggregator::init(config.clone());

    assert_eq!(aggregator.config, config);

    // Test flush (empty)
    let flushed_cache = aggregator.flush();
    assert!(flushed_cache.is_empty());
}

#[test]
fn test_aggregator_push_new_flow() {
    let config = create_test_config(
        Box::new([
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::destinationIPv4Address, 0),
        ]),
        Box::new([
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::minimumTTL, 0, AggOp::Min),
            AggFieldRef::new(IE::maximumTTL, 0, AggOp::Max),
        ]),
    );
    let mut aggregator = FlowAggregator::init(config.clone());

    // Input AggFlowInfo
    let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let key_fields = Box::new([
        Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
        Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
    ]);
    let agg_fields = Box::new([
        Some(Field::octetDeltaCount(1000)),
        Some(Field::packetDeltaCount(10)),
        Some(Field::minimumTTL(64)),
        Some(Field::maximumTTL(128)),
    ]);
    let agg_flow_info = create_test_agg_flow_info(peer_ip, key_fields, agg_fields, 1);

    // Expected cache
    let expected_cache =
        FxHashMap::from_iter(vec![(agg_flow_info.key.clone(), agg_flow_info.rec.clone())]);

    // Push to aggregator
    aggregator.push(agg_flow_info);

    // Compare aggregator cache with expected cache
    assert_eq!(aggregator.cache, expected_cache);

    // Test flush
    let flushed_cache = aggregator.flush();
    assert_eq!(flushed_cache, expected_cache);
}

#[test]
fn test_aggregator_push_duplicate_flow_key() {
    let config = create_test_config(
        Box::new([
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::destinationIPv4Address, 0),
        ]),
        Box::new([
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::tcpControlBits, 0, AggOp::BoolMapOr),
        ]),
    );
    let mut aggregator = FlowAggregator::init(config.clone());

    // Create Input AggFlowInfos with same key
    let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let key_fields = Box::new([
        Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
        Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
    ]);

    let agg_fields_1 = Box::new([Some(Field::octetDeltaCount(1000)), None]);
    let agg_fields_2 = Box::new([
        Some(Field::octetDeltaCount(500)),
        Some(Field::tcpControlBits(TCPHeaderFlags::new(
            true, true, false, false, false, false, false, false,
        ))),
    ]);
    let agg_fields_3 = Box::new([
        None,
        Some(Field::tcpControlBits(TCPHeaderFlags::new(
            false, true, false, false, false, false, true, true,
        ))),
    ]);

    let agg_flow_info_1 = create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_1, 1);
    let agg_flow_info_2 = create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_2, 1);
    let agg_flow_info_3 = create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_3, 1);

    // Expected cache
    let agg_fields_result = Box::new([
        Some(Field::octetDeltaCount(1500)), // 1000 + 500
        Some(Field::tcpControlBits(TCPHeaderFlags::new(
            true, true, false, false, false, false, true, true,
        ))), // BoolMapOr aggregation
    ]);
    let agg_flow_info_result =
        create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_result, 3);

    let expected_cache = FxHashMap::from_iter(vec![(
        agg_flow_info_result.key.clone(),
        agg_flow_info_result.rec.clone(),
    )]);

    // Push to aggregator
    aggregator.push(agg_flow_info_1.clone());
    aggregator.push(agg_flow_info_2.clone());
    aggregator.push(agg_flow_info_3.clone());

    // Compare aggregator cache with expected cache
    assert_eq!(aggregator.cache, expected_cache);

    // Test flush
    let flushed_cache = aggregator.flush();
    assert_eq!(flushed_cache, expected_cache);
}

#[test]
fn test_aggregator_push_different_flow_keys() {
    let config = create_test_config(
        Box::new([
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::destinationIPv4Address, 0),
        ]),
        Box::new([
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::tcpControlBits, 0, AggOp::BoolMapOr),
        ]),
    );
    let mut aggregator = FlowAggregator::init(config.clone());

    // Create Input AggFlowInfos with same key
    let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let key_fields_1 = Box::new([
        Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
        Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
    ]);
    let key_fields_2 = Box::new([
        Some(Field::sourceIPv4Address(Ipv4Addr::new(20, 0, 0, 1))),
        Some(Field::destinationIPv4Address(Ipv4Addr::new(20, 0, 0, 2))),
    ]);

    let agg_fields = Box::new([Some(Field::octetDeltaCount(1000)), None]);

    let agg_flow_info_1 = create_test_agg_flow_info(peer_ip, key_fields_1, agg_fields.clone(), 1);
    let agg_flow_info_2 = create_test_agg_flow_info(peer_ip, key_fields_2, agg_fields.clone(), 1);

    let expected_cache = FxHashMap::from_iter(vec![
        (agg_flow_info_1.key.clone(), agg_flow_info_1.rec.clone()),
        (agg_flow_info_2.key.clone(), agg_flow_info_2.rec.clone()),
    ]);

    // Push to aggregator
    aggregator.push(agg_flow_info_1.clone());
    aggregator.push(agg_flow_info_2.clone());

    // Compare aggregator cache with expected cache
    assert_eq!(aggregator.cache, expected_cache);

    // Test flush
    let flushed_cache = aggregator.flush();
    assert_eq!(flushed_cache, expected_cache);
}

#[test]
fn test_reduce_add_operations() {
    let time1 = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
    let time2 = Utc.with_ymd_and_hms(2025, 1, 1, 11, 0, 0).unwrap();

    let agg_select = vec![
        AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
        AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add),
        AggFieldRef::new(IE::minimumTTL, 0, AggOp::Min),
        AggFieldRef::new(IE::maximumTTL, 0, AggOp::Max),
        AggFieldRef::new(IE::sourceTransportPort, 0, AggOp::Min),
        AggFieldRef::new(IE::destinationTransportPort, 0, AggOp::Max),
        AggFieldRef::new(IE::tcpControlBits, 0, AggOp::BoolMapOr),
        AggFieldRef::new(IE::fragmentFlags, 0, AggOp::BoolMapOr),
    ];

    let mut record1 = FlowCacheRecord {
        peer_ports: HashSet::from([9995, 1234]),
        observation_domain_ids: HashSet::from([100, 105]),
        template_ids: HashSet::from([DataSetId::new(256).unwrap()]),
        min_export_time: time1,
        max_export_time: time1,
        min_collection_time: time1,
        max_collection_time: time1,
        agg_fields: Box::new([
            Some(Field::octetDeltaCount(1000)),
            Some(Field::packetDeltaCount(10)),
            Some(Field::minimumTTL(64)),
            Some(Field::maximumTTL(128)),
            Some(Field::sourceTransportPort(80)),
            None,
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                true, true, false, false, false, false, false, false,
            ))),
            None,
        ]),
        record_count: 5,
    };

    let record2 = FlowCacheRecord {
        peer_ports: HashSet::from([9996]),
        observation_domain_ids: HashSet::from([101]),
        template_ids: HashSet::from([DataSetId::new(257).unwrap()]),
        min_export_time: time2,
        max_export_time: time2,
        min_collection_time: time2,
        max_collection_time: time2,
        agg_fields: Box::new([
            Some(Field::octetDeltaCount(2000)),
            Some(Field::packetDeltaCount(20)),
            Some(Field::minimumTTL(32)),
            Some(Field::maximumTTL(255)),
            None,
            Some(Field::destinationTransportPort(22)),
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                false, false, false, false, false, false, true, true,
            ))),
            None,
        ]),
        record_count: 1,
    };

    // Create expected reduce result
    let expected_record = FlowCacheRecord {
        peer_ports: HashSet::from([9995, 1234, 9996]),
        observation_domain_ids: HashSet::from([100, 105, 101]),
        template_ids: HashSet::from([DataSetId::new(256).unwrap(), DataSetId::new(257).unwrap()]),
        min_export_time: time1,
        max_export_time: time2,
        min_collection_time: time1,
        max_collection_time: time2,
        agg_fields: Box::new([
            Some(Field::octetDeltaCount(3000)),
            Some(Field::packetDeltaCount(30)),
            Some(Field::minimumTTL(32)),
            Some(Field::maximumTTL(255)),
            Some(Field::sourceTransportPort(80)),
            Some(Field::destinationTransportPort(22)),
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                true, true, false, false, false, false, true, true,
            ))),
            None,
        ]),
        record_count: 6,
    };

    // Perform the reduce operation
    record1.reduce(&record2, &agg_select);

    // Compare the result with expected
    assert_eq!(record1, expected_record);
}

#[test]
fn test_into_flowinfo_with_extra_fields() {
    // Create test data
    let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let shard_id = 5;
    let sequence_number = 42;
    let export_time = DateTime::parse_from_rfc3339("2025-07-02T10:00:00Z")
        .unwrap()
        .to_utc();
    let collection_time = DateTime::parse_from_rfc3339("2025-07-02T10:00:05Z")
        .unwrap()
        .to_utc();

    // Create key fields
    let key_fields = vec![
        Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
        Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
    ]
    .into_boxed_slice();

    // Create aggregated fields
    let agg_fields = vec![
        Some(Field::octetDeltaCount(1000)),
        Some(Field::packetDeltaCount(10)),
    ]
    .into_boxed_slice();

    // Create AggFlowInfo instance
    let agg_flow_info = AggFlowInfo::from((
        FlowCacheKey {
            peer_ip,
            key_fields: key_fields.clone(),
        },
        FlowCacheRecord {
            peer_ports: HashSet::from([9995, 9996]),
            observation_domain_ids: HashSet::from([1, 2]),
            template_ids: HashSet::from([
                DataSetId::new(256).unwrap(),
                DataSetId::new(257).unwrap(),
            ]),
            min_export_time: export_time,
            max_export_time: export_time,
            min_collection_time: collection_time,
            max_collection_time: collection_time,
            agg_fields: agg_fields.clone(),
            record_count: 3,
        },
    ));

    // Extra fields to add
    let extra_fields = vec![
        Field::NetGauze(netgauze::Field::windowStart(
            DateTime::parse_from_rfc3339("2025-07-02T10:00:00Z")
                .unwrap()
                .to_utc(),
        )),
        Field::NetGauze(netgauze::Field::windowEnd(
            DateTime::parse_from_rfc3339("2025-07-02T10:01:00Z")
                .unwrap()
                .to_utc(),
        )),
    ];

    // Call into_flowinfo
    let result = agg_flow_info.into_flowinfo_with_extra_fields(
        shard_id,
        sequence_number,
        extra_fields.clone(),
    );

    // Create expected record
    let mut expected_fields = Vec::new();
    expected_fields.extend(key_fields.iter().flatten().cloned());
    expected_fields.extend(agg_fields.iter().flatten().cloned());
    expected_fields.extend([
        Field::originalFlowsPresent(3),
        Field::minExportSeconds(export_time),
        Field::maxExportSeconds(export_time),
        Field::collectionTimeMilliseconds(collection_time),
    ]);
    expected_fields.extend(extra_fields);
    expected_fields.extend([
        Field::NetGauze(netgauze::Field::originalExporterTransportPort(9995)),
        Field::NetGauze(netgauze::Field::originalExporterTransportPort(9996)),
    ]);
    expected_fields.extend([
        Field::originalObservationDomainId(1),
        Field::originalObservationDomainId(2),
    ]);
    expected_fields.extend([
        Field::NetGauze(netgauze::Field::originalTemplateId(256)),
        Field::NetGauze(netgauze::Field::originalTemplateId(257)),
    ]);

    // Compare expected with result
    assert_eq!(result.sequence_number(), sequence_number);
    assert_eq!(result.observation_domain_id(), shard_id as u32);

    if let FlowInfo::IPFIX(pkt) = result {
        let sets = pkt.sets();
        assert_eq!(sets.len(), 1);

        if let Set::Data { records, .. } = &sets[0] {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].scope_fields().len(), 0);

            let mut resulting_fields = records[0].fields().to_vec();

            // Necessary sorting since HashSet does not guarantee ordering
            resulting_fields.sort();
            expected_fields.sort();

            assert_eq!(resulting_fields, expected_fields)
        } else {
            panic!("Expected an IPFIX Data Set")
        }
    } else {
        panic!("Expected FlowInfo::IPFIX")
    }
}

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
        FlowCacheKey {
            peer_ip: peer.ip(),
            key_fields: Box::new([
                Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
                Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
                Some(Field::sourceTransportPort(80)),
                Some(Field::destinationTransportPort(443)),
            ]),
        },
        FlowCacheRecord {
            peer_ports: HashSet::from([9995]),
            observation_domain_ids: HashSet::from([100]),
            template_ids: HashSet::from([DataSetId::new(256).unwrap()]),
            min_export_time: export_time,
            max_export_time: export_time,
            min_collection_time: collection_time,
            max_collection_time: collection_time,
            agg_fields: Box::new([
                Some(Field::octetDeltaCount(1000)),
                Some(Field::packetDeltaCount(10)),
            ]),
            record_count: 1,
        },
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
            FlowCacheKey {
                peer_ip: peer.ip(),
                key_fields: Box::new([
                    Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
                    Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
                ]),
            },
            FlowCacheRecord {
                peer_ports: HashSet::from([2055]),
                observation_domain_ids: HashSet::from([200]),
                template_ids: HashSet::from([DataSetId::new(300).unwrap()]),
                min_export_time: export_time,
                max_export_time: export_time,
                min_collection_time: collection_time,
                max_collection_time: collection_time,
                agg_fields: Box::new([Some(Field::octetDeltaCount(500))]),
                record_count: 1,
            },
        )),
        AggFlowInfo::from((
            FlowCacheKey {
                peer_ip: peer.ip(),
                key_fields: Box::new([
                    Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 3))),
                    Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 4))),
                ]),
            },
            FlowCacheRecord {
                peer_ports: HashSet::from([2055]),
                observation_domain_ids: HashSet::from([200]),
                template_ids: HashSet::from([DataSetId::new(300).unwrap()]),
                min_export_time: export_time,
                max_export_time: export_time,
                min_collection_time: collection_time,
                max_collection_time: collection_time,
                agg_fields: Box::new([Some(Field::octetDeltaCount(750))]),
                record_count: 1,
            },
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
        FlowCacheKey {
            peer_ip: peer.ip(),
            key_fields: Box::new([
                Some(Field::sourceIPv4Address(Ipv4Addr::new(100, 100, 100, 1))),
                Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
                Some(Field::protocolIdentifier(protocolIdentifier::IPv6)),
                Some(Field::protocolIdentifier(protocolIdentifier::UDP)),
            ]),
        },
        FlowCacheRecord {
            peer_ports: HashSet::from([4739]),
            observation_domain_ids: HashSet::from([300]),
            template_ids: HashSet::from([DataSetId::new(400).unwrap()]),
            min_export_time: export_time,
            max_export_time: export_time,
            min_collection_time: collection_time,
            max_collection_time: collection_time,
            agg_fields: Box::new([
                Some(Field::octetDeltaCount(100)),
                Some(Field::octetDeltaCount(200)),
            ]),
            record_count: 1,
        },
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
        FlowCacheKey {
            peer_ip: peer.ip(),
            key_fields: Box::new([
                Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
                None,
                Some(Field::sourceIPv6Address(Ipv6Addr::new(
                    0xc, 0xa, 0xf, 0xe, 0, 0, 0, 0,
                ))),
            ]),
        },
        FlowCacheRecord {
            peer_ports: HashSet::from([9996]),
            observation_domain_ids: HashSet::from([400]),
            template_ids: HashSet::from([DataSetId::new(500).unwrap()]),
            min_export_time: export_time,
            max_export_time: export_time,
            min_collection_time: collection_time,
            max_collection_time: collection_time,
            agg_fields: Box::new([Some(Field::octetDeltaCount(500)), None]),
            record_count: 1,
        },
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
        FlowCacheKey {
            peer_ip: peer.ip(),
            key_fields: Box::new([]),
        },
        FlowCacheRecord {
            peer_ports: HashSet::from([2055]),
            observation_domain_ids: HashSet::from([500]),
            template_ids: HashSet::from([DataSetId::new(600).unwrap()]),
            min_export_time: export_time,
            max_export_time: export_time,
            min_collection_time: collection_time,
            max_collection_time: collection_time,
            agg_fields: Box::new([]),
            record_count: 1,
        },
    ))];

    // Call explode and compare
    let result = explode(&flow_info, peer, &key_select, &agg_select, collection_time);

    assert_eq!(result.collect::<Vec<AggFlowInfo>>(), expected);
}
