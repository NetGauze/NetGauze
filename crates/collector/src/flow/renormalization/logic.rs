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

use crate::flow::renormalization::actor::RenormalizationStats;
use netgauze_flow_pkt::ie::{Field, netgauze, selectorAlgorithm};
use netgauze_flow_pkt::ipfix::DataRecord;
use netgauze_flow_pkt::{FlowInfo, ipfix};
use opentelemetry::KeyValue;
use tracing::{debug, warn};

fn calculate_count_based_k(
    interval: u32,
    space: u32,
    stats: &RenormalizationStats,
    stats_tags: &[KeyValue],
) -> Option<f64> {
    if interval == 0 {
        warn!("samplingPacketInterval IE field 305 is zero");
        stats.ie_missing_or_invalid.add(1, stats_tags);
        None
    } else {
        Some((space as f64 + interval as f64) / interval as f64)
    }
}

fn calculate_random_n_out_of_n_k(
    size: u32,
    population: u32,
    stats: &RenormalizationStats,
    stats_tags: &[KeyValue],
) -> Option<f64> {
    if size == 0 {
        warn!("samplingSize IE field 309 is zero");
        stats.ie_missing_or_invalid.add(1, stats_tags);
        None
    } else {
        Some(population as f64 / size as f64)
    }
}

fn calculate_probabilistic_k(
    probability: f64,
    stats: &RenormalizationStats,
    stats_tags: &[KeyValue],
) -> Option<f64> {
    if probability > 0.0 && probability <= 1.0 {
        Some(1.0 / probability)
    } else {
        warn!("samplingProbability IE field 311 is <= 0 or > 1");
        stats.ie_missing_or_invalid.add(1, stats_tags);
        None
    }
}

fn renormalize_packet_sampling_ipfix_record(
    record: DataRecord,
    stats: &RenormalizationStats,
    stats_tags: &[KeyValue],
) -> DataRecord {
    // Documentation at https://www.iana.org/assignments/ipfix/ipfix.xhtml

    // From RFC 3954, deprecated by RFC 7270:
    // +-----+----------------------------+-----+----------------------------+
    // |  ID | Name                       |  ID | Name                       |
    // +-----+----------------------------+-----+----------------------------+
    // | 34 | samplingInterval            | 35  | samplingAlgorithm          |
    // +-----+----------------------------+-----+----------------------------+
    let mut sampling_interval_34 = None;
    let mut sampling_algorithm_35 = None;

    // From RFC 3954, deprecated by RFC 7270:
    // +-----+----------------------------+-----+----------------------------+
    // |  ID | Name                       |  ID | Name                       |
    // +-----+----------------------------+-----+----------------------------+
    // | 49 | samplerMode                 | 50  | samplerRandomInterval      |
    // +-----+----------------------------+-----+----------------------------+
    let mut sampler_mode_49 = None;
    let mut sampler_random_interval_50 = None;

    // From RFC 5477:
    // +-----+----------------------------+-----+----------------------------+
    // |  ID | Name                       |  ID | Name                       |
    // +-----+----------------------------+-----+----------------------------+
    // | 304 | selectorAlgorithm          | 308 | samplingTimeSpace          |
    // | 305 | samplingPacketInterval     | 309 | samplingSize               |
    // | 306 | samplingPacketSpace        | 310 | samplingPopulation         |
    // | 307 | samplingTimeInterval       | 311 | samplingProbability        |
    // +-----+----------------------------+-----+----------------------------+
    // Algorithms and corresponding parameters
    // +----+------------------------+------------------------+
    // | ID |        Method          |      Parameters        |
    // +----+------------------------+------------------------+
    // | 1  | Systematic count-based | samplingPacketInterval |
    // |    | Sampling               | samplingPacketSpace    |
    // +----+------------------------+------------------------+
    // | 2  | Systematic time-based  | samplingTimeInterval   |
    // |    | Sampling               | samplingTimeSpace      |
    // +----+------------------------+------------------------+
    // | 3  | Random n-out-of-N      | samplingSize           |
    // |    | Sampling               | samplingPopulation     |
    // +----+------------------------+------------------------+
    // | 4  | Uniform probabilistic  | samplingProbability    |
    // |    | Sampling               |                        |
    // +----+------------------------+------------------------+
    // | 5  | Property Match         | no agreed parameters   |
    // |    | Filtering              |                        |
    // +----+------------------------+------------------------+
    // |   Hash-based Filtering      | hashInitialiserValue   |
    // +----+------------------------+ hashIPPayloadOffset    |
    // | 6  | using BOB              | hashIPPayloadSize      |
    // +----+------------------------+ hashSelectedRangeMin   |
    // | 7  | using IPSX             | hashSelectedRangeMax   |
    // +----+------------------------+ hashOutputRangeMin     |
    // | 8  | using CRC              | hashOutputRangeMax     |
    // +----+------------------------+------------------------+
    let mut selector_algorithm_304 = None;
    let mut sampling_packet_interval_305 = None;
    let mut sampling_packet_space_306 = None;
    let mut sampling_size_309 = None;
    let mut sampling_population_310 = None;
    let mut sampling_probability_311 = None;

    stats.processed_flows.add(1, stats_tags);

    // we expect records that have been already enriched with packet sampling IEs
    for field in record.fields() {
        match field {
            Field::samplingInterval(v) => sampling_interval_34 = Some(*v),
            Field::samplingAlgorithm(v) => sampling_algorithm_35 = Some(*v),
            Field::samplerMode(v) => sampler_mode_49 = Some(*v),
            Field::samplerRandomInterval(v) => sampler_random_interval_50 = Some(*v),
            Field::selectorAlgorithm(v) => selector_algorithm_304 = Some(*v),
            Field::samplingPacketInterval(v) => sampling_packet_interval_305 = Some(*v),
            Field::samplingPacketSpace(v) => sampling_packet_space_306 = Some(*v),
            Field::samplingSize(v) => sampling_size_309 = Some(*v),
            Field::samplingPopulation(v) => sampling_population_310 = Some(*v),
            Field::samplingProbability(v) => sampling_probability_311 = Some(*v),
            _ => {}
        }
    }

    // calculate renormalization factor k
    // 1. try to match based on the algorithms and the required parameters
    let k = if let Some(alg) = selector_algorithm_304 {
        match alg {
            selectorAlgorithm::SystematiccountbasedSampling => {
                // should have fields samplingPacketInterval and samplingPacketSpace
                if let (Some(interval), Some(space)) =
                    (sampling_packet_interval_305, sampling_packet_space_306)
                {
                    calculate_count_based_k(interval, space, stats, stats_tags)
                } else {
                    warn!(
                        "samplingPacketInterval IE field 305 and/or samplingPacketSpace IE field 306 missing for selectorAlgorithm {}",
                        alg
                    );
                    stats.ie_missing_or_invalid.add(1, stats_tags);
                    None
                }
            }
            selectorAlgorithm::RandomnoutofNSampling => {
                // should have fields samplingSize and samplingPopulation
                if let (Some(size), Some(population)) = (sampling_size_309, sampling_population_310)
                {
                    calculate_random_n_out_of_n_k(size, population, stats, stats_tags)
                } else {
                    warn!(
                        "samplingSize IE field 309 and/or samplingPopulation IE field 310 missing for selectorAlgorithm {}",
                        alg
                    );
                    stats.ie_missing_or_invalid.add(1, stats_tags);
                    None
                }
            }
            selectorAlgorithm::UniformprobabilisticSampling => {
                // should have field samplingProbability
                if let Some(probability) = sampling_probability_311 {
                    calculate_probabilistic_k(probability.0, stats, stats_tags)
                } else {
                    warn!(
                        "samplingProbability IE field 311 missing for selectorAlgorithm {}",
                        alg
                    );
                    stats.ie_missing_or_invalid.add(1, stats_tags);
                    None
                }
            }
            _ => {
                warn!("Unsupported selector algorithm IE field 304: {}", alg);
                stats.ie_missing_or_invalid.add(1, stats_tags);
                None
            }
        }
    } else if let Some(alg) = sampler_mode_49 {
        match alg {
            1 | 2 => {
                // should have field samplerRandomInterval
                if let Some(interval) = sampler_random_interval_50 {
                    Some(interval as f64)
                } else {
                    warn!(
                        "samplerRandomInterval IE field 50 missing for samplerMode {}",
                        alg
                    );
                    stats.ie_missing_or_invalid.add(1, stats_tags);
                    None
                }
            }
            _ => {
                warn!("Unsupported sampler mode IE field 49: {}", alg);
                stats.ie_missing_or_invalid.add(1, stats_tags);
                None
            }
        }
    } else if let Some(alg) = sampling_algorithm_35 {
        match alg {
            1 | 2 => {
                // should have field samplingInterval
                if let Some(interval) = sampling_interval_34 {
                    Some(interval as f64)
                } else {
                    warn!(
                        "samplingInterval IE field 34 missing for samplingAlgorithm {}",
                        alg
                    );
                    stats.ie_missing_or_invalid.add(1, stats_tags);
                    None
                }
            }
            _ => {
                warn!("Unsupported sampling algorithm IE filed 35: {}", alg);
                stats.ie_missing_or_invalid.add(1, stats_tags);
                None
            }
        }
    }
    // 2. if no algorithm matched, try to use the IEs directly
    // This infers the sampling method based on the presence of parameters
    else if let (Some(interval), Some(space)) =
        (sampling_packet_interval_305, sampling_packet_space_306)
    {
        stats.sampling_algorithm_inferred.add(1, stats_tags);
        calculate_count_based_k(interval, space, stats, stats_tags)
    } else if let (Some(size), Some(population)) = (sampling_size_309, sampling_population_310) {
        stats.sampling_algorithm_inferred.add(1, stats_tags);
        calculate_random_n_out_of_n_k(size, population, stats, stats_tags)
    } else if let Some(probability) = sampling_probability_311 {
        stats.sampling_algorithm_inferred.add(1, stats_tags);
        calculate_probabilistic_k(probability.0, stats, stats_tags)
    } else if let Some(interval) = sampler_random_interval_50 {
        stats.sampling_algorithm_inferred.add(1, stats_tags);
        Some(interval as f64)
    } else if let Some(interval) = sampling_interval_34 {
        stats.sampling_algorithm_inferred.add(1, stats_tags);
        Some(interval as f64)
    }
    // 3. else, no sampling information found hence we do not renormalize
    else {
        None
    };

    // apply renormalization factor k to packet and byte counts
    if let Some(k_val) = k {
        let (scope_fields, fields) = record.into_parts();
        let mut fields = fields.into_vec();
        fields.reserve(1);
        let mut is_something_renormalized = false;
        for field in &mut fields {
            match field {
                Field::octetDeltaCount(count) => {
                    *count = (*count as f64 * k_val) as u64;
                    is_something_renormalized = true;
                }
                Field::octetTotalCount(count) => {
                    *count = (*count as f64 * k_val) as u64;
                    is_something_renormalized = true;
                }
                Field::packetDeltaCount(count) => {
                    *count = (*count as f64 * k_val) as u64;
                    is_something_renormalized = true;
                }
                Field::packetTotalCount(count) => {
                    *count = (*count as f64 * k_val) as u64;
                    is_something_renormalized = true;
                }
                _ => {}
            }
        }
        if is_something_renormalized {
            fields.push(Field::NetGauze(netgauze::Field::isRenormalized(true)));
            stats.renormalized_flows.add(1, stats_tags);
        }
        return DataRecord::new(scope_fields, fields.into_boxed_slice());
    }

    record
}

pub(crate) fn renormalize(
    info: FlowInfo,
    stats: &RenormalizationStats,
    stats_tags: &[KeyValue],
) -> FlowInfo {
    // If there is any packet sampling information in the packet, then we adjsut the
    // flow packets and bytes and then add the isRenormalized boolean field to
    // true. Otherwise, we leave the flow as is.
    match info {
        FlowInfo::NetFlowV9(info) => {
            warn!("NetFlowV9 renormalization not implemented yet");
            stats.netflow_v9_not_supported.add(1, stats_tags);
            FlowInfo::NetFlowV9(info)
        }
        FlowInfo::IPFIX(pkt) => {
            let export_time = pkt.export_time();
            let sequence_number = pkt.sequence_number();
            let obs_id = pkt.observation_domain_id();

            let renormalized_sets = pkt
                .into_sets()
                .into_iter()
                .filter_map(|set| match set {
                    ipfix::Set::Data { id, records } => {
                        let enriched_records = records
                            .into_vec()
                            .into_iter()
                            .filter(|record| record.scope_fields().is_empty())
                            .map(|record| {
                                renormalize_packet_sampling_ipfix_record(record, stats, stats_tags)
                            })
                            .collect::<Box<[_]>>();

                        Some(ipfix::Set::Data {
                            id,
                            records: enriched_records,
                        })
                    }
                    ipfix::Set::OptionsTemplate(_) => {
                        debug!("Options Data Template Set received: filter out");
                        None
                    }
                    ipfix::Set::Template(_) => {
                        debug!("Data Template Set received: filter out");
                        None
                    }
                })
                .collect::<Box<[_]>>();

            FlowInfo::IPFIX(ipfix::IpfixPacket::new(
                export_time,
                sequence_number,
                obs_id,
                renormalized_sets,
            ))
        }
    }
}

#[cfg(test)]
#[path = "logic/tests.rs"]
mod tests;
