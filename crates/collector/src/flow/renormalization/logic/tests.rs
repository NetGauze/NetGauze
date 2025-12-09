// Copyright (C) 2026-present The NetGauze Authors.
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

use super::*;
use chrono::{TimeZone, Utc};
use netgauze_flow_pkt::DataSetId;
use netgauze_flow_pkt::ie::{Field, netgauze, selectorAlgorithm};
use netgauze_flow_pkt::ipfix::{DataRecord, IpfixPacket, Set};
use ordered_float::OrderedFloat;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing_test::traced_test;

use crate::flow::renormalization::actor::RenormalizationStats;

fn create_stats() -> RenormalizationStats {
    let meter = opentelemetry::global::meter("test");
    RenormalizationStats::new(meter)
}

/// Creates a test context for use in unit tests
fn create_test_ctx() -> RenormalizationContext {
    RenormalizationContext {
        peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 12345),
        observation_domain_id: 0,
    }
}

/// Creates a test peer address for use in unit tests
fn create_test_peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 12345)
}

// Tests for renormalize_packet_sampling_ipfix_record() function
#[test]
fn test_no_renormalization() {
    let fields = vec![Field::octetDeltaCount(100), Field::packetDeltaCount(10)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();
    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_selector_algorithm_systematic_count_based() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::packetDeltaCount(10),
        Field::selectorAlgorithm(selectorAlgorithm::SystematiccountbasedSampling),
        Field::samplingPacketInterval(10),
        Field::samplingPacketSpace(90),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // sample 10 and then wait 90 before next sample
    // k = (10 + 90) / 10 = 10.0
    // new octets = 100 * 10 = 1000
    // new packets = 10 * 10 = 100

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::packetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::SystematiccountbasedSampling),
        Field::samplingPacketInterval(10),
        Field::samplingPacketSpace(90),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
#[traced_test]
fn test_selector_algorithm_systematiccount_based_zero_interval() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::SystematiccountbasedSampling),
        Field::samplingPacketInterval(0),
        Field::samplingPacketSpace(100),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("samplingPacketInterval IE field 305 is zero"));
}

#[test]
#[traced_test]
fn test_selector_algorithm_systematic_count_based_missing_params() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::SystematiccountbasedSampling),
        Field::samplingPacketInterval(10),
        // Missing PacketSpace
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain(
        "samplingPacketInterval IE field 305 and/or samplingPacketSpace IE field 306 missing"
    ));
}

#[test]
fn test_selector_algorithm_random_n_out_of_n() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::packetDeltaCount(10),
        Field::selectorAlgorithm(selectorAlgorithm::RandomnoutofNSampling),
        Field::samplingSize(10),
        Field::samplingPopulation(100),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 100 / 10 = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::packetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::RandomnoutofNSampling),
        Field::samplingSize(10),
        Field::samplingPopulation(100),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
#[traced_test]
fn test_selector_algorithm_random_n_out_of_n_zero_size() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::RandomnoutofNSampling),
        Field::samplingSize(0),
        Field::samplingPopulation(100),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("samplingSize IE field 309 is zero"));
}

#[test]
#[traced_test]
fn test_selector_algorithm_random_n_out_of_n_missing_params() {
    let fields = vec![
        Field::selectorAlgorithm(selectorAlgorithm::RandomnoutofNSampling),
        Field::samplingSize(10),
        // Missing Population
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain(
        "samplingSize IE field 309 and/or samplingPopulation IE field 310 missing"
    ));
}

#[test]
fn test_selector_algorithm_uniform_probabilistic() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::UniformprobabilisticSampling),
        Field::samplingProbability(OrderedFloat(0.1)),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 1.0 / 0.1 = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::selectorAlgorithm(selectorAlgorithm::UniformprobabilisticSampling),
        Field::samplingProbability(OrderedFloat(0.1)),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
#[traced_test]
fn test_selector_algorithm_uniform_probabilistic_zero() {
    let fields = vec![
        Field::selectorAlgorithm(selectorAlgorithm::UniformprobabilisticSampling),
        Field::samplingProbability(OrderedFloat(0.0)),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain(
        "samplingProbability IE field 311 is <= 0 or > 1"
    ));
}

#[test]
#[traced_test]
fn test_selector_algorithm_uniform_probabilistic_missing() {
    let fields = vec![Field::selectorAlgorithm(
        selectorAlgorithm::UniformprobabilisticSampling,
    )];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("samplingProbability IE field 311 missing"));
}

#[test]
#[traced_test]
fn test_selector_algorithm_unsupported() {
    // 2 = Systematic time-based Sampling (not currently implemented in renormalize)
    let fields = vec![Field::selectorAlgorithm(
        selectorAlgorithm::SystematictimebasedSampling,
    )];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("Unsupported selector algorithm IE field 304"));
}

#[test]
fn test_sampler_mode_deterministic() {
    // samplerMode 49 = 1 (Deterministic)
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::samplerMode(1),
        Field::samplerRandomInterval(10),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::samplerMode(1),
        Field::samplerRandomInterval(10),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
#[traced_test]
fn test_sampler_mode_missing_interval() {
    let fields = vec![Field::samplerMode(1)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("samplerRandomInterval IE field 50 missing"));
}

#[test]
#[traced_test]
fn test_sampler_mode_unsupported() {
    let fields = vec![Field::samplerMode(99), Field::samplerRandomInterval(10)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("Unsupported sampler mode IE field 49"));
}

#[test]
fn test_sampling_algorithm_deterministic() {
    // samplingAlgorithm 35 = 1 (Deterministic)
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::samplingAlgorithm(1),
        Field::samplingInterval(10),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::samplingAlgorithm(1),
        Field::samplingInterval(10),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
#[traced_test]
fn test_sampling_algorithm_missing_interval() {
    let fields = vec![Field::samplingAlgorithm(1)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("samplingInterval IE field 34 missing"));
}

#[test]
#[traced_test]
fn test_sampling_algorithm_unsupported() {
    let fields = vec![Field::samplingAlgorithm(99), Field::samplingInterval(10)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);

    assert_eq!(result, expected);
    assert!(logs_contain("Unsupported sampling algorithm IE field 35"));
}

#[test]
fn test_count_scaling() {
    // Test that all count fields are scaled
    let fields = vec![
        Field::samplingAlgorithm(1),
        Field::samplingInterval(2),
        Field::octetDeltaCount(100),
        Field::octetTotalCount(200),
        Field::packetDeltaCount(10),
        Field::packetTotalCount(20),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 2.0

    let expected_fields = vec![
        Field::samplingAlgorithm(1),
        Field::samplingInterval(2),
        Field::octetDeltaCount(200),
        Field::octetTotalCount(400),
        Field::packetDeltaCount(20),
        Field::packetTotalCount(40),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_inferred_sampling_packet_interval_and_space() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::samplingPacketInterval(10),
        Field::samplingPacketSpace(90),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = (10 + 90) / 10 = 10.0
    // new octets = 100 * 10 = 1000

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::samplingPacketInterval(10),
        Field::samplingPacketSpace(90),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_inferred_sampling_size_and_population() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::samplingSize(10),
        Field::samplingPopulation(100),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 100 / 10 = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::samplingSize(10),
        Field::samplingPopulation(100),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_inferred_sampling_probability() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::samplingProbability(OrderedFloat(0.1)),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 1.0 / 0.1 = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::samplingProbability(OrderedFloat(0.1)),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_inferred_sampler_random_interval() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::samplerRandomInterval(10),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::samplerRandomInterval(10),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_inferred_sampling_interval() {
    let fields = vec![Field::octetDeltaCount(100), Field::samplingInterval(10)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    // k = 10.0

    let expected_fields = vec![
        Field::octetDeltaCount(1000),
        Field::samplingInterval(10),
        Field::NetGauze(netgauze::Field::isRenormalized(true)),
    ];
    let expected = DataRecord::new(
        vec![].into_boxed_slice(),
        expected_fields.into_boxed_slice(),
    );

    let result =
        renormalize_packet_sampling_ipfix_record(record, &create_test_ctx(), &create_stats(), &[]);
    assert_eq!(result, expected);
}

// Tests for renormalize() function
#[test]
fn test_renormalize_empty_flow() {
    let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
    let flow_info = FlowInfo::IPFIX(IpfixPacket::new(export_time, 1, 100, Box::new([])));
    let expected = flow_info.clone();

    let result = renormalize(create_test_peer(), flow_info, &create_stats(), &[]);

    assert_eq!(result, expected);
}

#[test]
fn test_renormalize_data_set_with_sampling() {
    let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

    let input_records = vec![DataRecord::new(
        Box::new([]),
        Box::new([
            Field::octetDeltaCount(1000),
            Field::samplingAlgorithm(1),
            Field::samplingInterval(10),
        ]),
    )];

    let flow_info = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        1,
        100,
        Box::new([Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: input_records.into_boxed_slice(),
        }]),
    ));

    let expected_records = vec![DataRecord::new(
        Box::new([]),
        Box::new([
            Field::octetDeltaCount(10000),
            Field::samplingAlgorithm(1),
            Field::samplingInterval(10),
            Field::NetGauze(netgauze::Field::isRenormalized(true)),
        ]),
    )];

    let expected = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        1,
        100,
        Box::new([Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: expected_records.into_boxed_slice(),
        }]),
    ));

    let result = renormalize(create_test_peer(), flow_info, &create_stats(), &[]);

    assert_eq!(result, expected);
}

#[test]
#[traced_test]
fn test_renormalize_filters_templates_and_options() {
    let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

    let flow_info = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        1,
        100,
        Box::new([
            Set::Template(Box::new([])),
            Set::OptionsTemplate(Box::new([])),
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([]),
                    Box::new([Field::octetDeltaCount(500)]),
                )]),
            },
        ]),
    ));

    let expected = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        1,
        100,
        Box::new([
            // Templates and OptionsTemplates are filtered out
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([]),
                    Box::new([Field::octetDeltaCount(500)]),
                )]),
            },
        ]),
    ));

    let result = renormalize(create_test_peer(), flow_info, &create_stats(), &[]);

    assert_eq!(result, expected);

    // Check warning logs
    assert!(logs_contain(
        "Options Data Template Set received, filtering out"
    ));
    assert!(logs_contain("Data Template Set received, filtering out"));
}

#[test]
#[traced_test]
fn test_renormalize_handles_netflow_v9() {
    let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
    let flow_info = FlowInfo::NetFlowV9(netgauze_flow_pkt::netflow::NetFlowV9Packet::new(
        3600000,
        export_time,
        1,
        1,
        Box::new([]),
    ));
    let expected = flow_info.clone();

    let result = renormalize(create_test_peer(), flow_info, &create_stats(), &[]);

    // NetFlow V9 returns Ok but logs a warning
    assert_eq!(result, expected);
    assert!(logs_contain(
        "NetFlowV9 renormalization not implemented yet"
    ));
}
