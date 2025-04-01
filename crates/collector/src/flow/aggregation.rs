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
//! - `InputMessage` - Represents an input message containing flow information
//!   and the peer socket data
//! - `FlowAggregator` - Aggregates flow data based on the provided
//!   configuration and cache
//! - `AggregationActor` - Actor responsible for handling aggregation commands
//!   and processing flow requests
//! - `AggregationActorHandle` - Handle used to control the aggregation actor

use either::Either;
use futures::stream::{self, StreamExt};
use indexmap::IndexMap;
use netgauze_analytics::{aggregation::*, flow::*};
use netgauze_flow_pkt::{ie, FlatFlowDataInfo};
use netgauze_flow_service::FlowRequest;
use opentelemetry::metrics::{Counter, Meter};
use pin_utils::pin_mut;
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, trace};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    pub workers: usize,
    pub window_duration: Duration,
    pub lateness: Duration,
    pub transform: IndexMap<ie::IE, AggrOp>,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform: IndexMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputMessage {
    pub peer: SocketAddr,
    pub flow: FlatFlowDataInfo,
}

impl TimeSeriesData<String> for InputMessage {
    fn get_key(&self) -> String {
        self.peer.ip().to_string()
    }
    fn get_ts(&self) -> chrono::DateTime<chrono::Utc> {
        self.flow.export_time()
    }
}

impl From<(SocketAddr, FlatFlowDataInfo)> for InputMessage {
    fn from((peer, flow): (SocketAddr, FlatFlowDataInfo)) -> Self {
        Self { peer, flow }
    }
}

impl InputMessage {
    pub fn extract_as_key_str(
        &self,
        ie: &ie::IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        self.flow.extract_as_key_str(ie, indices)
    }

    pub fn reduce(
        &mut self,
        incoming: &InputMessage,
        transform: &IndexMap<ie::IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        self.flow.reduce(&incoming.flow, transform)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FlowAggregator {
    pub cache: HashMap<String, InputMessage>,
    pub config: AggregationConfig,
}

impl
    Aggregator<
        (HashMap<String, InputMessage>, AggregationConfig),
        InputMessage,
        HashMap<String, InputMessage>,
    > for FlowAggregator
{
    fn init(init: (HashMap<String, InputMessage>, AggregationConfig)) -> Self {
        let (cache, config) = init;
        Self { cache, config }
    }

    // TODO: extend to return Result<>
    fn push(&mut self, incoming: InputMessage) {
        let mut key = incoming.get_key();

        // Extend key with the GROUP BY keys for IEs
        for (ie, op) in &self.config.transform {
            if let AggrOp::Key(indices) = op {
                key.push(',');
                match incoming.extract_as_key_str(ie, indices) {
                    Ok(extracted_key) => key.push_str(&extracted_key),
                    Err(e) => {
                        error!("Error extracting key as string: {e:?}");
                    }
                }
            }
        }
        // Update cache
        match self.cache.entry(key) {
            Entry::Occupied(mut accumulator) => {
                let accumulator = accumulator.get_mut();
                if let Err(e) = accumulator.reduce(&incoming, &self.config.transform) {
                    error!("Error reducing accumulator: {e:?}");
                }
            }
            Entry::Vacant(accumulator) => {
                // Push incoming message to cache
                accumulator.insert(incoming);
            }
        }
    }
    fn flush(self) -> HashMap<String, InputMessage> {
        self.cache
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AggregationCommand {
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
pub enum FlowAggregationActorError {
    AggregationChannelClosed,
    FlowReceiveError,
}

impl std::fmt::Display for FlowAggregationActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AggregationChannelClosed => write!(f, "aggregation channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
        }
    }
}

#[derive(Debug)]
struct AggregationActor {
    cmd_recv: mpsc::Receiver<AggregationCommand>,
    rx: async_channel::Receiver<Arc<FlowRequest>>,
    tx: async_channel::Sender<(Window, (SocketAddr, FlatFlowDataInfo))>,
    config: AggregationConfig,
    stats: AggregationStats,
    shard_id: usize,
}

impl AggregationActor {
    fn new(
        cmd_recv: mpsc::Receiver<AggregationCommand>,
        rx: async_channel::Receiver<Arc<FlowRequest>>,
        tx: async_channel::Sender<(Window, (SocketAddr, FlatFlowDataInfo))>,
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
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        let stats = self.stats.clone();
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

                stream::iter(
                    flow.flatten_data()
                        .into_iter()
                        .filter(|flow| match flow {
                            FlatFlowDataInfo::IPFIX(packet) => {
                                // Exclude records without octetDeltaCount (e.g. option records)
                                packet.set().record().fields().octetDeltaCount.is_some()
                            }
                            _ => false,
                        })
                        .map(move |x| InputMessage::from((peer, x))),
                )
            })
            .window_aggregate(
                self.config.window_duration,
                self.config.lateness,
                (HashMap::new(), self.config.clone()),
                FlowAggregator::init((HashMap::new(), self.config)),
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
                            tokio::spawn(async move {
                                for (_key, message) in cache {
                                    let tags = [
                                        opentelemetry::KeyValue::new("shard_id", opentelemetry::Value::I64(self.shard_id as i64)),
                                        opentelemetry::KeyValue::new(
                                            "network.peer.address",
                                            format!("{}", message.peer.ip()),
                                        ),
                                        opentelemetry::KeyValue::new(
                                            "network.peer.port",
                                            opentelemetry::Value::I64(message.peer.port().into()),
                                        ),
                                    ];
                                    stats.aggregated_messages.add(1, &tags);
                                    let send_closure = tx.send(((window_start, window_end), (message.peer, message.flow)));
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
                                    format!("{}", message.peer.ip()),
                                ),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(message.peer.port().into()),
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
    rx: async_channel::Receiver<(Window, (SocketAddr, FlatFlowDataInfo))>,
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

    pub fn subscribe(&self) -> async_channel::Receiver<(Window, (SocketAddr, FlatFlowDataInfo))> {
        self.rx.clone()
    }
}
