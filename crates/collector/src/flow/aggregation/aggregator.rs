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

//! Core aggregation engine and data structures for flow processing.
//!
//! This module implements the runtime aggregation engine that processes flow
//! records in time windows. The main components are:
//!
//! - `FlowAggregator` - Main aggregation engine implementing time-windowed flow
//!   aggregation with configurable operations
//! - `FlowCacheKey` & `FlowCacheRecord` - In-memory cache structures for
//!   maintaining aggregated flow state across time windows
//! - `AggFlowInfo` - Wrapper for aggregatable flow data with time-series
//!   metadata for windowed processing
//! - `explode()` - Flow explosion function that transforms FlowInfo records
//!   into multiple AggFlowInfo objects based on configuration selectors
//!
//! ## Aggregation Operations
//!
//! The aggregator supports these reduction operations on flow fields:
//! - **Add** - Sum numeric values across flows in the same window
//! - **Min** - Track minimum values across flows
//! - **Max** - Track maximum values across flows
//! - **BoolMapOr** - Bitwise OR operations for flag/bitmap fields
//!
//! ## Processing Flow
//!
//! 1. Incoming flows are exploded into `AggFlowInfo` records using field
//!    selectors
//! 2. Records are grouped by `FlowCacheKey` (peer IP + key fields)
//! 3. Aggregation operations are applied to combine records in the same group
//! 4. Time windows manage when aggregated records are flushed
//!
//! The aggregator maintains efficient in-memory state and handles reduction
//! operations for optimal performance across large flow volumes.

use crate::flow::{aggregation::config::*, types::FieldRef};
use chrono::{DateTime, Utc};
use netgauze_analytics::aggregation::*;
use netgauze_flow_pkt::{
    DataSetId, FlowInfo,
    ie::{Field, *},
    ipfix,
};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::{
    collections::{HashSet, hash_map::Entry},
    net::{IpAddr, SocketAddr},
};
use tracing::{error, info};

#[derive(Clone, Debug)]
pub struct FlowAggregator {
    cache: FxHashMap<FlowCacheKey, FlowCacheRecord>,
    config: UnifiedConfig,
}

impl Aggregator<UnifiedConfig, AggFlowInfo, FxHashMap<FlowCacheKey, FlowCacheRecord>>
    for FlowAggregator
{
    fn init(init: UnifiedConfig) -> Self {
        Self {
            cache: Default::default(),
            config: init,
        }
    }

    fn push(&mut self, incoming: AggFlowInfo) {
        // Update cache
        match self.cache.entry(incoming.key) {
            Entry::Occupied(mut rec) => {
                let rec = rec.get_mut();
                rec.reduce(&incoming.rec, self.config.agg_select());
            }
            Entry::Vacant(rec) => {
                // Push incoming message to cache
                rec.insert(incoming.rec);
            }
        }
    }

    fn flush(self) -> FxHashMap<FlowCacheKey, FlowCacheRecord> {
        self.cache
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct AggFlowInfo {
    key: FlowCacheKey,
    rec: FlowCacheRecord,
}

impl From<(FlowCacheKey, FlowCacheRecord)> for AggFlowInfo {
    fn from((key, rec): (FlowCacheKey, FlowCacheRecord)) -> Self {
        AggFlowInfo { key, rec }
    }
}

impl TimeSeriesData<IpAddr> for AggFlowInfo {
    fn get_key(&self) -> IpAddr {
        self.key.peer_ip
    }

    fn get_ts(&self) -> DateTime<Utc> {
        self.rec.max_export_time
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct FlowCacheKey {
    peer_ip: IpAddr,
    key_fields: Box<[Option<Field>]>,
}
impl FlowCacheKey {
    pub(crate) fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FlowCacheRecord {
    peer_ports: HashSet<u16>,
    observation_domain_ids: HashSet<u32>,
    template_ids: HashSet<DataSetId>,
    min_export_time: DateTime<Utc>,
    max_export_time: DateTime<Utc>,
    min_collection_time: DateTime<Utc>,
    max_collection_time: DateTime<Utc>,
    agg_fields: Box<[Option<Field>]>,
    record_count: u64,
}

#[allow(clippy::too_many_arguments)]
impl FlowCacheRecord {
    fn peer_ports(&self) -> &HashSet<u16> {
        &self.peer_ports
    }
    fn observation_domain_ids(&self) -> &HashSet<u32> {
        &self.observation_domain_ids
    }
    fn template_ids(&self) -> &HashSet<DataSetId> {
        &self.template_ids
    }
}

impl FlowCacheRecord {
    fn reduce(&mut self, rhs: &FlowCacheRecord, agg_select: &[AggFieldRef]) {
        // Hardcoded aggregations
        self.peer_ports.extend(rhs.peer_ports());
        self.observation_domain_ids
            .extend(rhs.observation_domain_ids());
        self.template_ids.extend(rhs.template_ids());
        self.min_export_time = std::cmp::min(self.min_export_time, rhs.min_export_time);
        self.max_export_time = std::cmp::max(self.max_export_time, rhs.max_export_time);
        self.min_collection_time = std::cmp::min(self.min_collection_time, rhs.min_collection_time);
        self.max_collection_time = std::cmp::max(self.max_collection_time, rhs.max_collection_time);
        self.record_count += rhs.record_count;

        // Custom aggregations
        for (idx, field_ref) in agg_select.iter().enumerate() {
            match (&mut self.agg_fields[idx], &rhs.agg_fields[idx]) {
                (Some(lhs_field), Some(rhs_field)) => {
                    let result = match field_ref.op() {
                        AggOp::Add => lhs_field.add_assign_field(rhs_field),
                        AggOp::Min => lhs_field.min_assign_field(rhs_field),
                        AggOp::Max => lhs_field.max_assign_field(rhs_field),
                        AggOp::BoolMapOr => lhs_field.bitwise_or_assign_field(rhs_field),
                    };

                    if let Err(e) = result {
                        error!(
                            "Failed to reduce flow record for op {:?} on IE {:?} at idx {}: {e}",
                            field_ref.op(),
                            field_ref.field_ref().ie(),
                            field_ref.field_ref().index()
                        )
                    }
                }
                (None, Some(rhs_field)) => {
                    self.agg_fields[idx] = Some(rhs_field.clone());
                }
                _ => {}
            }
        }
    }
}

impl AggFlowInfo {
    /// Convert AggFlowInfo into a FlowInfo IPFIX with a single DataRecord.
    pub(crate) fn into_flowinfo_with_extra_fields(
        self,
        shard_id: usize,
        sequence_number: u32,
        extra_fields: impl IntoIterator<Item = Field>,
    ) -> FlowInfo {
        let key = self.key;
        let rec = self.rec;
        let key_fields = key.key_fields;
        let agg_fields = rec.agg_fields;
        let peer_ports = rec.peer_ports;
        let observation_domain_ids = rec.observation_domain_ids;
        let template_ids = rec.template_ids;

        // As of rust 2024 we will be able to use `into_iter` directly on Box<[T]>.
        // (meaning we can remove the `into_vec()` calls)
        // https://doc.rust-lang.org/nightly/edition-guide/rust-2024/intoiterator-box-slice.html
        let fields: Box<[Field]> =
            key_fields
                .into_vec()
                .into_iter()
                .chain(agg_fields.into_vec())
                .flatten()
                .chain([
                    Field::originalFlowsPresent(rec.record_count),
                    Field::minExportSeconds(rec.min_export_time),
                    Field::maxExportSeconds(rec.max_export_time),
                    Field::collectionTimeMilliseconds(rec.max_collection_time),
                ])
                .chain(extra_fields)
                .chain(peer_ports.into_iter().map(|port| {
                    Field::NetGauze(netgauze::Field::originalExporterTransportPort(port))
                }))
                .chain(
                    observation_domain_ids
                        .into_iter()
                        .map(Field::originalObservationDomainId),
                )
                .chain(template_ids.into_iter().map(|template_id| {
                    Field::NetGauze(netgauze::Field::originalTemplateId(template_id.id()))
                }))
                .collect();

        let records = [ipfix::DataRecord::new(Box::new([]), fields)];

        let sets = [ipfix::Set::Data {
            id: DataSetId::new(u16::MAX).unwrap(),
            records: Box::new(records),
        }];

        let ipfix_pkt =
            ipfix::IpfixPacket::new(Utc::now(), sequence_number, shard_id as u32, Box::new(sets));

        FlowInfo::IPFIX(ipfix_pkt)
    }
}

/// Explode a FlowInfo into multiple AggFlowInfo records based on the provided
/// key and aggregation selectors.
pub(crate) fn explode(
    flow_info: &FlowInfo,
    peer: SocketAddr,
    key_select: &[FieldRef],
    agg_select: &[AggFieldRef],
    collection_time: DateTime<Utc>,
) -> (usize, impl Iterator<Item = AggFlowInfo> + use<>) {
    // FlowInfo are not expected to contain more than 16 records
    let mut exploded = SmallVec::<[AggFlowInfo; 16]>::new();

    let peer_ports = HashSet::from([peer.port()]);

    let key_len = key_select.len();
    let agg_len = agg_select.len();

    match flow_info {
        FlowInfo::IPFIX(pkt) => {
            let observation_domain_ids = HashSet::from([pkt.observation_domain_id()]);

            for set in pkt.sets() {
                let template_ids;
                let data_records = if let ipfix::Set::Data { id, records } = set {
                    template_ids = HashSet::from([*id]);
                    records
                } else {
                    continue;
                };

                for record in data_records {
                    // Store fields indexed by FieldRef (IE, index)
                    let fields_map = FieldRef::map_fields_into_fxhashmap(record.fields());

                    // Initialize output arrays
                    let mut key_fields = vec![None; key_len].into_boxed_slice();
                    let mut agg_fields = vec![None; agg_len].into_boxed_slice();

                    // Fill key fields
                    for (idx, field_ref) in key_select.iter().enumerate() {
                        if let Some(field) = fields_map.get(field_ref) {
                            key_fields[idx] = Some((*field).clone());
                        }
                    }

                    // Fill agg fields
                    for (idx, agg) in agg_select.iter().enumerate() {
                        if let Some(field) = fields_map.get(&agg.field_ref()) {
                            agg_fields[idx] = Some((*field).clone());
                        }
                    }

                    exploded.push(AggFlowInfo {
                        key: FlowCacheKey {
                            peer_ip: peer.ip(),
                            key_fields,
                        },
                        rec: FlowCacheRecord {
                            peer_ports: peer_ports.clone(),
                            observation_domain_ids: observation_domain_ids.clone(),
                            template_ids: template_ids.clone(),
                            min_export_time: pkt.export_time(),
                            max_export_time: pkt.export_time(),
                            min_collection_time: collection_time,
                            max_collection_time: collection_time,
                            agg_fields,
                            record_count: 1,
                        },
                    });
                }
            }
        }
        // TODO: handle NetFlowV9
        _ => {
            info!("Unsupported flow version for peer {}", peer);
        }
    }
    (exploded.len(), exploded.into_iter())
}

#[cfg(test)]
mod tests;
