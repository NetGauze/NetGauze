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

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use netgauze_collector::flow::enrichment::{
    EnrichmentActor, EnrichmentCache, EnrichmentOperation, EnrichmentStats, Scope, UpsertPayload,
};
use netgauze_flow_pkt::{
    DataSetId,
    ie::{Field, netgauze},
    ipfix::{DataRecord, IpfixPacket, Set},
};
use std::{hint::black_box, net::IpAddr};
use tokio::sync::mpsc;

/// Helper to create data records with realistic field sets (10-15 fields each)
fn create_ipfix_packet_with_records(num_records: usize) -> IpfixPacket {
    let records = (0..num_records)
        .map(|i| {
            DataRecord::new(
                Box::new([]),
                Box::new([
                    Field::octetDeltaCount(1000 + i as u64),
                    Field::packetDeltaCount(10 + i as u64),
                    Field::sourceIPv4Address([192, 168, 1, (i % 255) as u8].into()),
                    Field::destinationIPv4Address([10, 0, 0, (i % 255) as u8].into()),
                    Field::tcpSourcePort((i % 65000) as u16),
                    Field::tcpDestinationPort(443),
                    Field::protocolIdentifier(((i % 255) as u8).into()),
                    Field::ipClassOfService(((i % 4) as u8).into()),
                    Field::flowStartMilliseconds(chrono::Utc::now()),
                    Field::flowEndMilliseconds(chrono::Utc::now()),
                    Field::tcpControlBits(((i % 255) as u8).into()),
                    Field::flowEndReason(((i % 255) as u8).into()),
                    Field::ingressInterface(100 + (i % 100) as u32),
                    Field::egressInterface(200 + (i % 100) as u32),
                ]),
            )
        })
        .collect::<Box<[_]>>();

    // Split records into multiple sets
    let num_sets = match num_records {
        1..=10 => 2,
        _ => 10,
    };
    let records_per_set = num_records / num_sets;

    let sets = (0..num_sets)
        .map(|set_idx| {
            let start = set_idx * records_per_set;
            let end = if set_idx == num_sets - 1 {
                records.len() // last set gets all remaining records
            } else {
                start + records_per_set
            };
            let set_records = records[start..end].to_vec().into_boxed_slice();

            Set::Data {
                id: DataSetId::new(256 + set_idx as u16).unwrap(),
                records: set_records,
            }
        })
        .collect::<Box<[_]>>();

    IpfixPacket::new(
        chrono::Utc::now(),
        12345,
        10, // obs-domain id
        sets,
    )
}

/// Helper to create enrichment cache with multiple scopes and fields
/// cache_scale: multiplier for the number of entries, example:
/// 1 -> 1x obs_domain_id, 10x in/out interface ids per obs_domain_id
/// 10 -> 10x obs_domain_id, 100x in/out interface ids per obs_domain_id
/// 100 -> 100x obs_domain_id, 1000x in/out interface ids per obs_domain_id
fn create_enrichment_cache(peer_ip: IpAddr, cache_scale: u32) -> EnrichmentCache {
    let mut cache = EnrichmentCache::new();

    // Global scope (obs_domain_id: 0, no scope fields)
    cache.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
        ip: peer_ip,
        scope: Scope::new(0, None),
        weight: 50,
        fields: vec![
            Field::NetGauze(netgauze::Field::platformId("global-platform-001".into())),
            Field::NetGauze(netgauze::Field::nodeId("global-node-001".into())),
            Field::applicationId([1, 2, 3].into()),
            Field::applicationName("NetGauze".into()),
            Field::applicationGroupName("Flow Collectors".into()),
            Field::applicationCategoryName("Network Telemetry Collectors".into()),
            Field::samplingSize(1),
            Field::samplingPopulation(4096),
            Field::NetGauze(netgauze::Field::ingressInterfaceName("unknown".into())),
            Field::NetGauze(netgauze::Field::egressInterfaceName("unknown".into())),
        ],
    }));

    let num_obs_domains = cache_scale;
    let num_ingress_interfaces = 10 * cache_scale;
    let num_egress_interfaces = 10 * cache_scale;

    // Domain-specific scopes for obs_domain_ids 1..=num_obs_domains
    for obs_domain_id in 1..=num_obs_domains {
        cache.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
            ip: peer_ip,
            scope: Scope::new(obs_domain_id, None),
            weight: 75,
            fields: vec![
                Field::selectorId(100 + obs_domain_id as u64),
                Field::selectorName(format!("random sampler {}", obs_domain_id).into()),
                Field::selectorAlgorithm(
                    netgauze_flow_pkt::ie::selectorAlgorithm::RandomnoutofNSampling,
                ),
                Field::samplingSize(1),
                Field::samplingPopulation(1024),
            ],
        }));
    }

    // Add interface-specific scopes for ingress interfaces
    for obs_domain_id in 1..=num_obs_domains {
        for ingress_if in 100..(100 + num_ingress_interfaces) {
            cache.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
                ip: peer_ip,
                scope: Scope::new(
                    obs_domain_id,
                    Some(vec![Field::ingressInterface(ingress_if)]),
                ),
                weight: 100,
                fields: vec![
                    Field::NetGauze(netgauze::Field::ingressInterfaceName(
                        format!("eth 0/{}", ingress_if).into(),
                    )),
                    Field::NetGauze(netgauze::Field::ingressInterfaceDescription(
                        format!("interface {} ingress desc", ingress_if).into(),
                    )),
                ],
            }));
        }
    }

    // Add interface-specific scopes for egress interfaces
    for obs_domain_id in 1..=num_obs_domains {
        for egress_if in 200..(200 + num_egress_interfaces) {
            cache.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
                ip: peer_ip,
                scope: Scope::new(obs_domain_id, Some(vec![Field::egressInterface(egress_if)])),
                weight: 100,
                fields: vec![
                    Field::NetGauze(netgauze::Field::egressInterfaceName(
                        format!("eth 0/{}", egress_if).into(),
                    )),
                    Field::NetGauze(netgauze::Field::egressInterfaceDescription(
                        format!("interface {} egress desc", egress_if).into(),
                    )),
                ],
            }));
        }
    }

    // Add combined ingress+egress scopes for a small subset (only for obs_domain_id
    // 10)
    for ingress_if in 100..(110) {
        for egress_if in 200..(210) {
            cache.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
                ip: peer_ip,
                scope: Scope::new(
                    10,
                    Some(vec![
                        Field::ingressInterface(ingress_if),
                        Field::egressInterface(egress_if),
                    ]),
                ),
                weight: 150,
                fields: vec![
                    Field::NetGauze(netgauze::Field::ingressInterfaceName(
                        format!("eth 0/{}", ingress_if).into(),
                    )),
                    Field::NetGauze(netgauze::Field::ingressInterfaceDescription(
                        format!("interface {} ingress combined desc", ingress_if).into(),
                    )),
                    Field::NetGauze(netgauze::Field::egressInterfaceName(
                        format!("eth 0/{}", egress_if).into(),
                    )),
                    Field::NetGauze(netgauze::Field::egressInterfaceDescription(
                        format!("interface {} egress combined desc", egress_if).into(),
                    )),
                ],
            }));
        }
    }
    cache
}

/// Helper to create an EnrichmentActor for benchmarking
fn create_enrichment_actor(cache: EnrichmentCache) -> EnrichmentActor {
    let meter = opentelemetry::global::meter("benchmark");
    let stats = EnrichmentStats::new(meter);

    // Create dummy channels that won't be used
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let (enrichment_tx, enrichment_rx) = async_channel::bounded(1);
    let (flow_tx, flow_rx) = async_channel::bounded(1);
    let (enriched_tx, _enriched_rx) = async_channel::bounded(1);

    // Close the senders so channels don't interfere
    drop(enrichment_tx);
    drop(flow_tx);

    EnrichmentActor::new(
        Some(cache),
        cmd_rx,
        enrichment_rx,
        flow_rx,
        enriched_tx,
        stats,
        0,
        "bench-writer".to_string(),
    )
}

/// Generic benchmark function
fn benchmark_enrich_packet(
    c: &mut Criterion,
    test_name: &str,
    num_records: usize,
    cache_scale: u32,
) {
    let peer_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let cache = create_enrichment_cache(peer_ip, cache_scale);
    let actor = create_enrichment_actor(cache);
    let pkt = create_ipfix_packet_with_records(num_records);

    c.bench_function(test_name, |b| {
        b.iter_batched(
            || pkt.clone(),                                                    // Setup (not timed)
            |pkt| black_box(actor.enrich_ipfix_packet(peer_ip, pkt).unwrap()), // Benchmark (timed)
            BatchSize::SmallInput,
        );
    });
}

// Benchmark with different combinations of packet sizes and cache sizes
fn benchmark_small_packet_small_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_4records_cache1x", 4, 1);
}
fn benchmark_small_packet_medium_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_4records_cache10x", 4, 10);
}
fn benchmark_small_packet_large_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_4records_cache100x", 4, 100);
}
fn benchmark_medium_packet_small_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_10records_cache1x", 10, 1);
}
fn benchmark_medium_packet_medium_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_10records_cache10x", 10, 10);
}
fn benchmark_medium_packet_large_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_10records_cache100x", 10, 100);
}
fn benchmark_large_packet_small_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_25records_cache1x", 25, 1);
}
fn benchmark_large_packet_medium_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_25records_cache10x", 25, 10);
}
fn benchmark_large_packet_large_cache(c: &mut Criterion) {
    benchmark_enrich_packet(c, "enrich_25records_cache100x", 25, 100);
}

criterion_group! {
    name = benches;
    // allow longer measurement time for the big-cache benches
    config = Criterion::default()
        .noise_threshold(0.05)
        .confidence_level(0.9)
        .sample_size(100)
        .measurement_time(std::time::Duration::from_secs(10));
    targets =
    benchmark_small_packet_small_cache,
    benchmark_small_packet_medium_cache,
    benchmark_small_packet_large_cache,
    benchmark_medium_packet_small_cache,
    benchmark_medium_packet_medium_cache,
    benchmark_medium_packet_large_cache,
    benchmark_large_packet_small_cache,
    benchmark_large_packet_medium_cache,
    benchmark_large_packet_large_cache,
}
criterion_main!(benches);
