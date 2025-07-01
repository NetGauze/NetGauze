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

//! A module for aggregating flow data based on configurable parameters.
//!
//! The main components are:
//! - `AggregationConfig` - Configuration for aggregation, including window
//!   duration, lateness, and transformation operations
//! - `FlowRequest` - Input message containing flow information and peer socket
//!   data
//! - `FlowAggregator` - Aggregates flow data based on the provided
//!   configuration and cache
//! - `AggregationActor` - Actor responsible for handling aggregation commands
//!   and processing flow requests using time-windowed aggregation
//! - `AggregationActorHandle` - Handle used to control the aggregation actor
//!
//! ## Aggregation Operations
//! - **Key** - Use field for grouping flows
//! - **Add** - Sum numeric values
//! - **Min/Max** - Track minimum/maximum values
//! - **BoolMapOr** - Bitwise OR operation for flags

use chrono::{DateTime, Utc};
use either::Either;
use futures::stream::{self, StreamExt};
use indexmap::IndexMap;
use netgauze_analytics::aggregation::*;
use netgauze_flow_pkt::{
    ie::{Field, HasIE, IE, *},
    ipfix::{DataRecord, IpfixPacket, Set},
    DataSetId, FlowInfo,
};
use netgauze_flow_service::FlowRequest;
use opentelemetry::metrics::{Counter, Meter};
use pin_utils::pin_mut;
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::{hash_map::Entry, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};
use strum_macros::Display;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, trace, warn};

// Global configuration knob for window waterline selection
static USE_COLLECTION_TIME: OnceLock<bool> = OnceLock::new();

fn set_timestamp_config(use_collection_time: bool) {
    USE_COLLECTION_TIME.set(use_collection_time).ok();
}
fn use_collection_time() -> bool {
    USE_COLLECTION_TIME.get().copied().unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct AggregationStats {
    pub received_messages: Counter<u64>,
    pub aggregated_messages: Counter<u64>,
    pub late_messages: Counter<u64>,
    pub sent_messages: Counter<u64>,
    pub send_timeout: Counter<u64>,
    pub send_error: Counter<u64>,
}

impl AggregationStats {
    pub fn new(meter: Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.flows.aggregation.received.messages")
            .with_description("Number of flow messages received for aggregation")
            .build();
        let aggregated_messages = meter
            .u64_counter("netgauze.collector.flows.aggregation.aggregated.messages")
            .with_description("Number of flat flow messages aggregated")
            .build();
        let late_messages = meter
            .u64_counter("netgauze.collector.flows.aggregation.late.messages")
            .with_description("Number of late messages discarded")
            .build();
        let sent_messages = meter
            .u64_counter("netgauze.collector.flows.aggregation.sent.messages")
            .with_description("Number of aggregated messages successfully sent upstream")
            .build();
        let send_timeout = meter
            .u64_counter("netgauze.collector.flows.aggregation.send.timeout")
            .with_description(
                "Number aggregated messages timed out and dropped while sending to upstream",
            )
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.aggregation.send.error")
            .with_description("Number aggregated messages sent upstream error")
            .build();
        Self {
            received_messages,
            aggregated_messages,
            late_messages,
            sent_messages,
            send_timeout,
            send_error,
        }
    }
}

impl std::error::Error for FlowAggregationActorError {}

#[derive(Debug, Clone)]
pub enum FlowAggregationActorError {
    AggregationChannelClosed,
    FlowReceiveError,
    InvalidOperation {
        ie: IE,
        op: Op,
        reason: String,
    },
    ConfigurationError {
        reason: String,
    },
    EmptyCache {
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    },
}

impl std::fmt::Display for FlowAggregationActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AggregationChannelClosed => write!(f, "aggregation channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
            Self::InvalidOperation { ie, op, reason } => {
                write!(f, "invalid operation \"{op}\" for \"{ie:?}\" [{reason}]")
            }
            Self::ConfigurationError { reason } => {
                write!(f, "configuration validation failed [{reason}]")
            }
            Self::EmptyCache {
                window_start,
                window_end,
            } => {
                write!(f, "empty cache for window ({window_start}, {window_end})")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    pub workers: usize,
    pub window_duration: Duration,
    pub lateness: Duration,
    pub transform: IndexMap<IE, Transform>,
    #[serde(default)]
    pub use_collection_time: Option<bool>,
}

impl AggregationConfig {
    pub fn workers(&self) -> usize {
        self.workers
    }
    pub fn window_duration(&self) -> Duration {
        self.window_duration
    }
    pub fn lateness(&self) -> Duration {
        self.lateness
    }
    pub fn transform(&self) -> &IndexMap<IE, Transform> {
        &self.transform
    }
}

impl Default for AggregationConfig {
    fn default() -> Self {
        AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform: IndexMap::new(),
            use_collection_time: None,
        }
    }
}

impl AggregationConfig {
    pub fn validate(&self) -> Result<(), FlowAggregationActorError> {
        if self.workers == 0 {
            return Err(FlowAggregationActorError::ConfigurationError {
                reason: "workers must be greater than 0".to_string(),
            });
        }

        if self.window_duration.is_zero() {
            return Err(FlowAggregationActorError::ConfigurationError {
                reason: "window_duration must be greater than 0".to_string(),
            });
        }

        if self.lateness > self.window_duration {
            return Err(FlowAggregationActorError::ConfigurationError {
                reason: "lateness cannot exceed window_duration".to_string(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Transform {
    Single(Op),
    Multi(IndexMap<usize, Op>),
}

#[derive(Display, Clone, Copy, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum Op {
    Key,
    Add,
    Min,
    Max,
    BoolMapOr,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
enum AggOp {
    Add,
    Min,
    Max,
    BoolMapOr,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
struct FieldRef {
    ie: IE,
    index: usize,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct AggFieldRef {
    field_ref: FieldRef,
    op: AggOp,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
struct UnifiedConfig {
    workers: usize,
    window_duration: Duration,
    lateness: Duration,
    key_select: Box<[FieldRef]>,
    agg_select: Box<[AggFieldRef]>,
    use_collection_time: bool,
}
impl UnifiedConfig {
    fn key_select(&self) -> &[FieldRef] {
        &self.key_select
    }
    fn agg_select(&self) -> &[AggFieldRef] {
        &self.agg_select
    }
}

/// Validates that the given aggregation operation is compatible with the IE
/// field's capabilities
fn validate_operation_compatibility(ie: &IE, op: &Op) -> Result<(), FlowAggregationActorError> {
    match op {
        Op::Key => Ok(()), // Key operations are allowed for all IEs
        Op::Add => {
            if ie.supports_arithmetic_ops() {
                Ok(())
            } else {
                Err(FlowAggregationActorError::InvalidOperation {
                    ie: *ie,
                    op: *op,
                    reason: "field does not support arithmetic operations".to_string(),
                })
            }
        }
        Op::Min | Op::Max => {
            if ie.supports_comparison_ops() {
                Ok(())
            } else {
                Err(FlowAggregationActorError::InvalidOperation {
                    ie: *ie,
                    op: *op,
                    reason: "field does not support comparison operations".to_string(),
                })
            }
        }
        Op::BoolMapOr => {
            if ie.supports_bitwise_ops() {
                Ok(())
            } else {
                Err(FlowAggregationActorError::InvalidOperation {
                    ie: *ie,
                    op: *op,
                    reason: "field does not support bitwise operations".to_string(),
                })
            }
        }
    }
}

impl TryInto<UnifiedConfig> for AggregationConfig {
    type Error = FlowAggregationActorError;

    fn try_into(self) -> Result<UnifiedConfig, Self::Error> {
        // Validate basic knobs
        self.validate()?;

        let mut key_select = Vec::new();
        let mut agg_select = Vec::new();

        for (ie, transform) in self.transform {
            match transform {
                Transform::Single(aggr_op) => {
                    validate_operation_compatibility(&ie, &aggr_op)?;

                    match aggr_op {
                        Op::Key => {
                            key_select.push(FieldRef { ie, index: 0 });
                        }
                        Op::Add => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::Add,
                            });
                        }
                        Op::Min => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::Min,
                            });
                        }
                        Op::Max => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::Max,
                            });
                        }
                        Op::BoolMapOr => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::BoolMapOr,
                            });
                        }
                    }
                }
                Transform::Multi(index_map) => {
                    for (index, aggr_op) in index_map {
                        validate_operation_compatibility(&ie, &aggr_op)?;

                        match aggr_op {
                            Op::Key => {
                                key_select.push(FieldRef { ie, index });
                            }
                            Op::Add => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::Add,
                                });
                            }
                            Op::Min => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::Min,
                                });
                            }
                            Op::Max => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::Max,
                                });
                            }
                            Op::BoolMapOr => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::BoolMapOr,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(UnifiedConfig {
            workers: self.workers,
            window_duration: self.window_duration,
            lateness: self.lateness,
            key_select: key_select.into_boxed_slice(),
            agg_select: agg_select.into_boxed_slice(),
            use_collection_time: self.use_collection_time.unwrap_or(false),
        })
    }
}

#[derive(Debug, Clone)]
struct AggFlowInfo {
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
        if use_collection_time() {
            self.rec.max_collection_time
        } else {
            // Default
            self.rec.max_export_time
        }
    }
}

impl AggFlowInfo {
    fn into_flowinfo_with_extra_fields(
        self,
        shard_id: usize,
        sequence_number: u32,
        extra_fields: impl IntoIterator<Item = Field>,
    ) -> FlowInfo {
        let key = self.key;
        let rec = self.rec;

        let mut additional_fields: SmallVec<[Field; 10]> = smallvec![
            Field::originalFlowsPresent(rec.record_count),
            Field::minExportSeconds(rec.min_export_time),
            Field::maxExportSeconds(rec.max_export_time),
            Field::collectionTimeMilliseconds(rec.max_collection_time),
        ];

        additional_fields.extend(extra_fields);

        additional_fields.extend(
            rec.peer_ports()
                .iter()
                .map(|port| Field::NetGauze(netgauze::Field::originalExporterTransportPort(*port))),
        );

        additional_fields.extend(
            rec.observation_domain_ids()
                .iter()
                .map(|obs_id| Field::originalObservationDomainId(*obs_id)),
        );
        additional_fields.extend(rec.template_ids().iter().map(|template_id| {
            Field::NetGauze(netgauze::Field::originalTemplateId(template_id.id()))
        }));

        let fields: Box<[Field]> = key
            .key_fields
            .into_vec()
            .into_iter()
            .chain(rec.agg_fields.into_vec())
            .flatten()
            .chain(additional_fields)
            .collect();

        let records = [DataRecord::new(Box::new([]), fields)];

        let sets = [Set::Data {
            id: DataSetId::new(u16::MAX).unwrap(),
            records: Box::new(records),
        }];

        let ipfix_pkt =
            IpfixPacket::new(Utc::now(), sequence_number, shard_id as u32, Box::new(sets));

        FlowInfo::IPFIX(ipfix_pkt)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct FlowCacheKey {
    peer_ip: IpAddr,
    key_fields: Box<[Option<Field>]>,
}

#[derive(Clone, Debug)]
struct FlowCacheRecord {
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
                    let result = match field_ref.op {
                        AggOp::Add => lhs_field.add_assign_field(rhs_field),
                        AggOp::Min => lhs_field.min_assign_field(rhs_field),
                        AggOp::Max => lhs_field.max_assign_field(rhs_field),
                        AggOp::BoolMapOr => lhs_field.bitwise_or_assign_field(rhs_field),
                    };

                    if let Err(e) = result {
                        error!(
                            "Failed to reduce flow record for op {:?} on IE {:?} at idx {}: {e}",
                            field_ref.op, field_ref.field_ref.ie, field_ref.field_ref.index
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

fn explode(
    flow_info: &FlowInfo,
    peer: SocketAddr,
    key_select: &[FieldRef],
    agg_select: &[AggFieldRef],
) -> SmallVec<[AggFlowInfo; 16]> {
    // TODO: check real average explosion factor and adjust SmallVec sizing
    let mut exploded = smallvec![];

    // TODO: consider recording this time at the flow_recv actor for correctness?
    let collection_time = Utc::now();
    let peer_ports = HashSet::from([peer.port()]);

    let key_len = key_select.len();
    let agg_len = agg_select.len();

    match flow_info {
        FlowInfo::IPFIX(pkt) => {
            let observation_domain_ids = HashSet::from([pkt.observation_domain_id()]);

            for set in pkt.sets() {
                let template_ids;
                let data_records = if let netgauze_flow_pkt::ipfix::Set::Data { id, records } = set
                {
                    template_ids = HashSet::from([*id]);
                    records
                } else {
                    continue;
                };

                for record in data_records {
                    // Store fields indexed by FieldRef (IE, index)
                    let fields_len = record.fields().len();
                    let mut fields_map: FxHashMap<FieldRef, &Field> =
                        FxHashMap::with_capacity_and_hasher(fields_len, FxBuildHasher);
                    let mut ie_counters: FxHashMap<IE, usize> =
                        FxHashMap::with_capacity_and_hasher(fields_len, FxBuildHasher);

                    for field in record.fields() {
                        let ie = field.ie();
                        let ie_count = ie_counters.entry(ie).or_insert(0);
                        fields_map.insert(
                            FieldRef {
                                ie,
                                index: *ie_count,
                            },
                            field,
                        );
                        *ie_count += 1;
                    }

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
                        if let Some(field) = fields_map.get(&agg.field_ref) {
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
        // TODO: handle NetFlowV9!
        _ => {
            info!("Unsupported flow version for peer {}", peer);
        }
    }
    exploded
}

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
#[derive(Debug, Clone, Copy)]
pub enum AggregationCommand {
    Shutdown,
}

#[derive(Debug)]
struct AggregationActor {
    cmd_recv: mpsc::Receiver<AggregationCommand>,
    rx: async_channel::Receiver<Arc<FlowRequest>>,
    tx: async_channel::Sender<(Window, (SocketAddr, FlowInfo))>,
    config: AggregationConfig,
    stats: AggregationStats,
    shard_id: usize,
    sequence_number: Arc<AtomicU32>,
}

impl AggregationActor {
    fn new(
        cmd_recv: mpsc::Receiver<AggregationCommand>,
        rx: async_channel::Receiver<Arc<FlowRequest>>,
        tx: async_channel::Sender<(Window, (SocketAddr, FlowInfo))>,
        config: AggregationConfig,
        stats: AggregationStats,
        shard_id: usize,
    ) -> Self {
        Self {
            cmd_recv,
            rx,
            tx,
            config,
            stats,
            shard_id,
            sequence_number: Arc::new(AtomicU32::new(0)),
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        let stats = self.stats.clone();

        let unified_config: UnifiedConfig = match self.config.try_into() {
            Ok(config) => config,
            Err(e) => {
                error!("FlowAggregationActorError ConfigurationError: {e}");
                Err(FlowAggregationActorError::ConfigurationError {
                    reason: e.to_string(),
                })?
            }
        };

        // Set the waterline time for windows
        set_timestamp_config(unified_config.use_collection_time);

        let key_select = unified_config.key_select();
        let agg_select = unified_config.agg_select();

        let agg = self
            .rx
            .flat_map(move |req| {
                let (peer, flow) = req.as_ref().clone();

                let tags = [
                    opentelemetry::KeyValue::new(
                        "shard_id",
                        opentelemetry::Value::I64(self.shard_id as i64),
                    ),
                    opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                    opentelemetry::KeyValue::new(
                        "network.peer.port",
                        opentelemetry::Value::I64(peer.port().into()),
                    ),
                ];
                stats.received_messages.add(1, &tags);

                stream::iter(explode(&flow, peer, key_select, agg_select))
            })
            .window_aggregate(
                unified_config.window_duration,
                unified_config.lateness,
                unified_config.clone(),
                FlowAggregator::init(unified_config.clone()),
            );
        pin_mut!(agg);

        loop {
            tokio::select! {
                biased;
                cmd_recv = self.cmd_recv.recv() => {
                    match cmd_recv {
                        Some(AggregationCommand::Shutdown) => {
                            info!("Received shutdown command, shutting down AggregationActor");
                        }
                        None => {
                            info!("Command channel closed, shutting down AggregationActor");
                        }
                    }
                    return Ok("Aggregation terminated successfully".to_string());
                }
                result = agg.next() => {
                    match result {
                        Some(Either::Left(((window_start, window_end), cache))) => {
                            let stats = self.stats.clone();
                            let tx = self.tx.clone();
                            let sequence_number = self.sequence_number.clone();
                            let shard_id = self.shard_id;

                            let peer_ip = match cache.keys().next() {
                                Some(key) => key.peer_ip,
                                None => {
                                    warn!("Empty aggregation cache for window ({:?}, {:?}), skipping", window_start, window_end);
                                    continue;
                                }
                            };

                            let exporter_ip = match peer_ip {
                                IpAddr::V4(ipv4) => Field::originalExporterIPv4Address(ipv4),
                                IpAddr::V6(ipv6) => Field::originalExporterIPv6Address(ipv6),
                            };
                            let window_start_fld = Field::NetGauze(netgauze::Field::windowStart(window_start));
                            let window_end_fld = Field::NetGauze(netgauze::Field::windowEnd(window_end));

                            tokio::spawn(async move {
                                for entry in cache.into_iter().map(AggFlowInfo::from) {
                                    let tags = [
                                        opentelemetry::KeyValue::new("shard_id", opentelemetry::Value::I64(self.shard_id as i64)),
                                        opentelemetry::KeyValue::new(
                                            "network.peer.address",
                                            format!("{peer_ip}"),
                                        ),
                                    ];
                                    stats.aggregated_messages.add(1, &tags);

                                    let message = entry.into_flowinfo_with_extra_fields(
                                      shard_id,
                                      sequence_number.fetch_add(1, Ordering::Relaxed),
                                      [
                                        window_start_fld.clone(),
                                        window_end_fld.clone(),
                                        exporter_ip.clone(),
                                    ]);

                                    let send_closure = tx.send(((window_start, window_end), (SocketAddr::new(peer_ip, 0), message)));
                                    match tokio::time::timeout(Duration::from_secs(1), send_closure).await {
                                        Ok(Ok(_)) => stats.sent_messages.add(1, &tags),
                                        Ok(Err(err)) => {
                                            error!("AggregationActor send error: {err}");
                                            stats.send_error.add(1, &tags);
                                        }
                                        Err(_) => {
                                            debug!("AggregationActor send timeout");
                                            stats.send_timeout.add(1, &tags)
                                        }
                                    }
                                }
                            });
                        }

                        Some(Either::Right(message)) => {
                            let tags = [
                                opentelemetry::KeyValue::new("shard_id", opentelemetry::Value::I64(self.shard_id as i64)),
                                opentelemetry::KeyValue::new(
                                    "network.peer.address",
                                    format!("{}", message.get_key()),
                                ),
                            ];

                            self.stats.late_messages.add(1, &tags);
                            trace!("Late messages: discarding");
                        }
                        None => {
                            info!("Aggregation channel closed, shutting down AggregationActor");
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum AggregationActorHandleError {
    SendError,
}

#[derive(Debug)]
pub struct AggregationActorHandle {
    cmd_send: mpsc::Sender<AggregationCommand>,
    rx: async_channel::Receiver<(Window, (SocketAddr, FlowInfo))>,
}

impl AggregationActorHandle {
    pub fn new(
        buffer_size: usize,
        config: AggregationConfig,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        stats: Either<opentelemetry::metrics::Meter, AggregationStats>,
        shard_id: usize,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (tx, rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            Either::Left(meter) => AggregationStats::new(meter),
            Either::Right(stats) => stats,
        };
        let actor = AggregationActor::new(cmd_recv, flow_rx, tx, config, stats, shard_id);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_send, rx };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), AggregationActorHandleError> {
        self.cmd_send
            .send(AggregationCommand::Shutdown)
            .await
            .map_err(|_| AggregationActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<(Window, (SocketAddr, FlowInfo))> {
        self.rx.clone()
    }
}
