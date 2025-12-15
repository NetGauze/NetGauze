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

//! Actor-based flow aggregation module for processing and aggregating network
//! flow data.
//!
//! This module provides the main actor implementation for flow aggregation:
//! - `AggregationActor` - Core actor that processes flow requests using
//!   time-windowed aggregation
//! - `AggregationActorHandle` - Handle for controlling and communicating with
//!   the actor
//! - `AggregationStats` - Metrics collection for aggregation operations
//!
//! The actor receives flow data, applies aggregation rules defined in the
//! configuration, and outputs aggregated results in time windows. It supports
//! parallel processing through multiple worker shards and provides
//! comprehensive telemetry.

use crate::flow::aggregation::aggregator::*;
use crate::flow::aggregation::config::*;
use chrono::Utc;
use either::Either;
use futures::stream::{self, StreamExt};
use netgauze_analytics::aggregation::{AggregationWindowStreamExt, Aggregator, TimeSeriesData};
use netgauze_flow_pkt::FlowInfo;
use netgauze_flow_pkt::ie::{Field, netgauze};
use opentelemetry::metrics::{Counter, Meter};
use pin_utils::pin_mut;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone)]
pub struct AggregationStats {
    pub received_messages: Counter<u64>,
    pub late_messages: Counter<u64>,
    pub exploded_records: Counter<u64>,
    pub aggregated_records: Counter<u64>,
    pub sent: Counter<u64>,
    pub send_timeout: Counter<u64>,
    pub send_error: Counter<u64>,
}

impl AggregationStats {
    pub fn new(meter: Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.flows.aggregation.received.messages")
            .with_description("Number of flow messages received for aggregation")
            .build();
        let late_messages = meter
            .u64_counter("netgauze.collector.flows.aggregation.late.messages")
            .with_description("Number of late flow messages discarded")
            .build();
        let exploded_records = meter
            .u64_counter("netgauze.collector.flows.aggregation.exploded.records")
            .with_description("Number of flat flow records exploded")
            .build();
        let aggregated_records = meter
            .u64_counter("netgauze.collector.flows.aggregation.aggregated.records")
            .with_description("Number of flat flow records aggregated")
            .build();
        let sent = meter
            .u64_counter("netgauze.collector.flows.aggregation.sent")
            .with_description("Number of aggregated records successfully sent upstream")
            .build();
        let send_timeout = meter
            .u64_counter("netgauze.collector.flows.aggregation.send.timeout")
            .with_description(
                "Number of aggregated records timed out and dropped while sending to upstream",
            )
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.aggregation.send.error")
            .with_description("Number of aggregated records sent upstream error")
            .build();
        Self {
            received_messages,
            late_messages,
            exploded_records,
            aggregated_records,
            sent,
            send_timeout,
            send_error,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AggregationCommand {
    Shutdown,
}

#[derive(Debug)]
struct AggregationActor {
    cmd_recv: mpsc::Receiver<AggregationCommand>,
    rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
    tx: async_channel::Sender<(IpAddr, FlowInfo)>,
    config: AggregationConfig,
    stats: AggregationStats,
    shard_id: usize,
    sequence_number: Arc<AtomicU32>,
}

impl AggregationActor {
    fn new(
        cmd_recv: mpsc::Receiver<AggregationCommand>,
        rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
        tx: async_channel::Sender<(IpAddr, FlowInfo)>,
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

        let unified_config: UnifiedConfig = self
            .config
            .try_into()
            .inspect_err(|e| error!("Flow Aggregation ConfigurationError: {e}"))?;

        let key_select = unified_config.key_select();
        let agg_select = unified_config.agg_select();

        let agg = self
            .rx
            .flat_map(move |input| {
                let (peer, flow) = input;

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

                // Explode the FlowInfo into single-record FlowInfos
                let (exploded_count, records) =
                    explode(&flow, peer, key_select, agg_select, Utc::now());
                stats.exploded_records.add(exploded_count as u64, &tags);

                stream::iter(records)
            })
            .window_aggregate(
                unified_config.window_duration(),
                unified_config.lateness(),
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
                        Some(Either::Left(((start, end), cache))) => {
                            let stats = self.stats.clone();
                            let tx = self.tx.clone();
                            let sequence_number = self.sequence_number.clone();
                            let shard_id = self.shard_id;

                            let peer_ip = match cache.keys().next() {
                                Some(key) => key.peer_ip(),
                                None => {
                                    warn!("Empty aggregation cache for window [{:?} - {:?}] (should not happen)", start, end);
                                    continue;
                                }
                            };

                            let tags = [
                                opentelemetry::KeyValue::new("shard_id", opentelemetry::Value::I64(self.shard_id as i64)),
                                opentelemetry::KeyValue::new(
                                    "network.peer.address",
                                    format!("{peer_ip}"),
                                ),
                            ];

                            let exporter_ip = match peer_ip {
                                IpAddr::V4(ipv4) => Field::originalExporterIPv4Address(ipv4),
                                IpAddr::V6(ipv6) => Field::originalExporterIPv6Address(ipv6),
                            };
                            let window_start = Field::NetGauze(netgauze::Field::windowStart(start));
                            let window_end = Field::NetGauze(netgauze::Field::windowEnd(end));

                            tokio::spawn(async move {
                                for entry in cache.into_iter().map(AggFlowInfo::from) {
                                    stats.aggregated_records.add(1, &tags);

                                    let flow = entry.into_flowinfo_with_extra_fields(
                                      shard_id,
                                      sequence_number.fetch_add(1, Ordering::Relaxed),
                                      [
                                        window_start.clone(),
                                        window_end.clone(),
                                        exporter_ip.clone(),
                                    ]);

                                    let send_closure = tx.send((peer_ip, flow));
                                    match tokio::time::timeout(Duration::from_secs(1), send_closure).await {
                                        Ok(Ok(_)) => stats.sent.add(1, &tags),
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
    rx: async_channel::Receiver<(IpAddr, FlowInfo)>,
}

impl AggregationActorHandle {
    pub fn new(
        buffer_size: usize,
        config: AggregationConfig,
        flow_rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
        stats: Either<Meter, AggregationStats>,
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

    pub fn subscribe(&self) -> async_channel::Receiver<(IpAddr, FlowInfo)> {
        self.rx.clone()
    }
}
