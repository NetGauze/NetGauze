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
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

use crate::flow::renormalization::actor::RenormalizationStats;

fn create_stats() -> RenormalizationStats {
    let meter = opentelemetry::global::meter("test");
    RenormalizationStats::new(meter)
}

#[derive(Clone, Debug)]
struct TestWriter {
    logs: Arc<Mutex<Vec<u8>>>,
}

impl TestWriter {
    fn new() -> Self {
        Self {
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn output(&self) -> String {
        String::from_utf8(self.logs.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.logs.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for TestWriter {
    type Writer = TestWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn with_captured_logs<F: FnOnce() -> R, R>(f: F) -> (R, String) {
    let writer = TestWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        // Disable ensuring time/thread names to keep logs simpler for assertion,
        // although exact format depends on default config.
        .finish();

    let result = tracing::subscriber::with_default(subscriber, f);
    (result, writer.output())
}

// Tests for renormalize_packet_sampling_ipfix_record() function
#[test]
fn test_no_renormalization() {
    let fields = vec![Field::octetDeltaCount(100), Field::packetDeltaCount(10)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();
    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_selector_algorithm_systematiccount_based_zero_interval() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::SystematiccountbasedSampling),
        Field::samplingPacketInterval(0),
        Field::samplingPacketSpace(100),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[])
    });

    assert_eq!(result, expected);
    assert!(logs.contains("samplingPacketInterval IE field 305 is zero"));
}

#[test]
fn test_selector_algorithm_systematic_count_based_missing_params() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::SystematiccountbasedSampling),
        Field::samplingPacketInterval(10),
        // Missing PacketSpace
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[])
    });

    assert_eq!(result, expected);
    assert!(logs.contains(
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_selector_algorithm_random_n_out_of_n_zero_size() {
    let fields = vec![
        Field::octetDeltaCount(100),
        Field::selectorAlgorithm(selectorAlgorithm::RandomnoutofNSampling),
        Field::samplingSize(0),
        Field::samplingPopulation(100),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());
    let expected = record.clone();

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[])
    });

    assert_eq!(result, expected);
    assert!(logs.contains("samplingSize IE field 309 is zero"));
}

#[test]
fn test_selector_algorithm_random_n_out_of_n_missing_params() {
    let fields = vec![
        Field::selectorAlgorithm(selectorAlgorithm::RandomnoutofNSampling),
        Field::samplingSize(10),
        // Missing Population
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(
        logs.contains("samplingSize IE field 309 and/or samplingPopulation IE field 310 missing")
    );
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_selector_algorithm_uniform_probabilistic_zero() {
    let fields = vec![
        Field::selectorAlgorithm(selectorAlgorithm::UniformprobabilisticSampling),
        Field::samplingProbability(OrderedFloat(0.0)),
    ];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(logs.contains("samplingProbability IE field 311 is <= 0 or > 1"));
}

#[test]
fn test_selector_algorithm_uniform_probabilistic_missing() {
    let fields = vec![Field::selectorAlgorithm(
        selectorAlgorithm::UniformprobabilisticSampling,
    )];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(logs.contains("samplingProbability IE field 311 missing"));
}

#[test]
fn test_selector_algorithm_unsupported() {
    // 2 = Systematic time-based Sampling (not currently implemented in renormalize)
    let fields = vec![Field::selectorAlgorithm(
        selectorAlgorithm::SystematictimebasedSampling,
    )];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(logs.contains("Unsupported selector algorithm IE field 304"));
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_sampler_mode_missing_interval() {
    let fields = vec![Field::samplerMode(1)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(logs.contains("samplerRandomInterval IE field 50 missing"));
}

#[test]
fn test_sampler_mode_unsupported() {
    let fields = vec![Field::samplerMode(99), Field::samplerRandomInterval(10)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(logs.contains("Unsupported sampler mode IE field 49"));
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
    assert_eq!(result, expected);
}

#[test]
fn test_sampling_algorithm_missing_interval() {
    let fields = vec![Field::samplingAlgorithm(1)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(logs.contains("samplingInterval IE field 34 missing"));
}

#[test]
fn test_sampling_algorithm_unsupported() {
    let fields = vec![Field::samplingAlgorithm(99), Field::samplingInterval(10)];
    let record = DataRecord::new(vec![].into_boxed_slice(), fields.into_boxed_slice());

    let (result, logs) = with_captured_logs(|| {
        renormalize_packet_sampling_ipfix_record(record.clone(), &create_stats(), &[])
    });

    assert_eq!(result, record);
    assert!(logs.contains("Unsupported sampling algorithm IE filed 35"));
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
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

    let result = renormalize_packet_sampling_ipfix_record(record, &create_stats(), &[]);
    assert_eq!(result, expected);
}

// Tests for renormalize() function
#[test]
fn test_renormalize_empty_flow() {
    let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
    let flow_info = FlowInfo::IPFIX(IpfixPacket::new(export_time, 1, 100, Box::new([])));
    let expected = flow_info.clone();

    let result = renormalize(flow_info, &create_stats(), &[]);

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

    let result = renormalize(flow_info, &create_stats(), &[]);

    assert_eq!(result, expected);
}

#[test]
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

    let (result, logs) = with_captured_logs(|| renormalize(flow_info, &create_stats(), &[]));

    assert_eq!(result, expected);

    // Check warning logs
    assert!(logs.contains("Options Data Template Set received: filter out"));
    assert!(logs.contains("Data Template Set received: filter out"));
}

#[test]
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

    let (result, logs) = with_captured_logs(|| renormalize(flow_info, &create_stats(), &[]));

    // NetFlow V9 returns Ok but logs a warning
    assert_eq!(result, expected);
    assert!(logs.contains("NetFlowV9 renormalization not implemented yet"));
}
