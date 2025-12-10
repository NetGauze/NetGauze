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

use crate::flow::enrichment::{EnrichmentOperation, Scope, UpsertPayload, actor::*};
use chrono::{TimeZone, Utc};
use netgauze_flow_pkt::{
    DataSetId, FlowInfo,
    ie::{Field, netgauze},
    ipfix::{DataRecord, IpfixPacket, Set},
};
use std::net::SocketAddr;

#[test]
fn test_enrich_ipfix_with_cached_metadata() {
    let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
    let peer_addr: SocketAddr = "192.168.1.100:2055".parse().unwrap();
    let writer_id = "test-writer-id".to_string();

    // Create actor with dummy channels
    let meter = opentelemetry::global::meter("test");
    let stats = EnrichmentStats::new(meter);

    let mut actor = EnrichmentActor::new(
        None,                        // start with empty cache
        mpsc::channel(1).1,          // dummy cmd_recv
        async_channel::bounded(1).1, // dummy enrichment_rx
        async_channel::bounded(1).1, // dummy flow_rx
        async_channel::bounded(1).0, // dummy enriched_tx
        stats,
        0, // shard_id
        writer_id.clone(),
    );

    // Add enrichment data to cache
    let enrichment_op = EnrichmentOperation::Upsert(UpsertPayload {
        ip: peer_addr.ip(),
        scope: Scope::new(0, None), // Global scope
        weight: 100,
        fields: vec![
            Field::NetGauze(netgauze::Field::platformId("test-platform-ABC".into())),
            Field::NetGauze(netgauze::Field::nodeId("test-node-123".into())),
        ],
    });
    actor.enrichment_cache.apply_enrichment(enrichment_op);

    // Create original flow
    let original_flow = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        12345,
        0, // observation_domain_id
        Box::new([Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([DataRecord::new(
                Box::new([]), // scope fields
                Box::new([
                    Field::octetDeltaCount(5000),
                    Field::packetDeltaCount(5),
                    Field::tcpDestinationPort(80),
                ]),
            )]),
        }]),
    ));

    // Create expected enriched flow
    let expected_flow = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        12345,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([DataRecord::new(
                Box::new([]), // scope fields
                Box::new([
                    Field::octetDeltaCount(5000),
                    Field::packetDeltaCount(5),
                    Field::tcpDestinationPort(80),
                    Field::NetGauze(netgauze::Field::platformId("test-platform-ABC".into())),
                    Field::NetGauze(netgauze::Field::nodeId("test-node-123".into())),
                    Field::NetGauze(netgauze::Field::dataCollectionManifestName(
                        "test-writer-id".into(),
                    )),
                ]),
            )]),
        }]),
    ));

    // Enrich the flow
    let enriched_flow = actor.enrich(peer_addr.ip(), original_flow).unwrap();

    // Compare with expected
    assert_eq!(enriched_flow, expected_flow);
}

#[test]
fn test_enrich_filters_templates_sets_and_options_records() {
    let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
    let peer_addr: SocketAddr = "192.168.1.100:2055".parse().unwrap();
    let writer_id = "test-writer-id".to_string();

    let meter = opentelemetry::global::meter("test");
    let stats = EnrichmentStats::new(meter);

    let actor = EnrichmentActor::new(
        None,                        // start with empty cache
        mpsc::channel(1).1,          // dummy cmd_recv
        async_channel::bounded(1).1, // dummy enrichment_rx
        async_channel::bounded(1).1, // dummy flow_rx
        async_channel::bounded(1).0, // dummy enriched_tx
        stats,
        0,
        writer_id.clone(),
    );

    // Create original flow with template and data sets
    let original_flow = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        12345,
        0,
        Box::new([
            Set::Template(Box::new([])), // Should be filtered out
            Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([
                    DataRecord::new(Box::new([]), Box::new([Field::octetDeltaCount(1000)])),
                    DataRecord::new(
                        Box::new([Field::selectorId(42)]), /* scope field --> option record
                                                            * should be filtered out */
                        Box::new([Field::selectorName("SAMPLER".to_string().into())]),
                    ),
                ]),
            },
            Set::OptionsTemplate(Box::new([])), // Should be filtered out
        ]),
    ));

    // Create expected enriched flow (only data set remains)
    let expected_flow = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        12345,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([DataRecord::new(
                Box::new([]),
                Box::new([
                    Field::octetDeltaCount(1000),
                    Field::NetGauze(netgauze::Field::dataCollectionManifestName(
                        "test-writer-id".into(),
                    )),
                ]),
            )]),
        }]),
    ));

    // Enrich the flow
    let enriched_flow = actor.enrich(peer_addr.ip(), original_flow).unwrap();

    // Compare with expected
    assert_eq!(enriched_flow, expected_flow);
}

#[test]
fn test_enrich_multiple_records() {
    let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
    let peer_addr: SocketAddr = "192.168.1.100:2055".parse().unwrap();
    let writer_id = "test-writer-id".to_string();

    let meter = opentelemetry::global::meter("test");
    let stats = EnrichmentStats::new(meter);

    let mut actor = EnrichmentActor::new(
        None,                        // start with empty cache
        mpsc::channel(1).1,          // dummy cmd_recv
        async_channel::bounded(1).1, // dummy enrichment_rx
        async_channel::bounded(1).1, // dummy flow_rx
        async_channel::bounded(1).0, // dummy enriched_tx
        stats,
        0,
        writer_id.clone(),
    );

    // Add enrichment data to cache
    let enrichment_op = EnrichmentOperation::Upsert(UpsertPayload {
        ip: peer_addr.ip(),
        scope: Scope::new(0, None),
        weight: 100,
        fields: vec![Field::NetGauze(netgauze::Field::nodeId("router-01".into()))],
    });
    actor.enrichment_cache.apply_enrichment(enrichment_op);

    // Create original flow with multiple records
    let original_flow = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        12345,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([
                DataRecord::new(
                    Box::new([]),
                    Box::new([Field::octetDeltaCount(1000), Field::tcpSourcePort(80)]),
                ),
                DataRecord::new(
                    Box::new([]),
                    Box::new([Field::octetDeltaCount(2000), Field::tcpSourcePort(443)]),
                ),
            ]),
        }]),
    ));

    // Create expected enriched flow (both records enriched)
    let expected_flow = FlowInfo::IPFIX(IpfixPacket::new(
        export_time,
        12345,
        0,
        Box::new([Set::Data {
            id: DataSetId::new(256).unwrap(),
            records: Box::new([
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        Field::octetDeltaCount(1000),
                        Field::tcpSourcePort(80),
                        Field::NetGauze(netgauze::Field::nodeId("router-01".into())),
                        Field::NetGauze(netgauze::Field::dataCollectionManifestName(
                            "test-writer-id".into(),
                        )),
                    ]),
                ),
                DataRecord::new(
                    Box::new([]),
                    Box::new([
                        Field::octetDeltaCount(2000),
                        Field::tcpSourcePort(443),
                        Field::NetGauze(netgauze::Field::nodeId("router-01".into())),
                        Field::NetGauze(netgauze::Field::dataCollectionManifestName(
                            "test-writer-id".into(),
                        )),
                    ]),
                ),
            ]),
        }]),
    ));

    // Enrich the flow
    let enriched_flow = actor.enrich(peer_addr.ip(), original_flow).unwrap();

    // Compare with expected
    assert_eq!(enriched_flow, expected_flow);
}
