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
use netgauze_flow_pkt::{
    ie::{self, *},
    ipfix::FlatSet,
    FlatFlowInfo,
};
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
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct AggregationStats {
    pub received_messages: Counter<u64>,
    pub aggregated_messages: Counter<u64>,
    pub late_messages: Counter<u64>,
    pub sent_messages: Counter<u64>,
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
        let send_error = meter
            .u64_counter("netgauze.collector.flows.aggregation.send.error")
            .with_description("Number aggregated messages sent upstream error")
            .build();
        Self {
            received_messages,
            aggregated_messages,
            late_messages,
            sent_messages,
            send_error,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    pub window_duration: Duration,
    pub lateness: Duration,
    pub transform: IndexMap<ie::IE, AggrOp>,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        AggregationConfig {
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform: IndexMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputMessage {
    pub peer: SocketAddr,
    pub flow: FlatFlowInfo,
}

impl TimeSeriesData<String> for InputMessage {
    fn get_key(&self) -> String {
        self.peer.ip().to_string()
    }
    fn get_ts(&self) -> chrono::DateTime<chrono::Utc> {
        self.flow.export_time()
    }
}

impl From<(SocketAddr, FlatFlowInfo)> for InputMessage {
    fn from((peer, flow): (SocketAddr, FlatFlowInfo)) -> Self {
        Self { peer, flow }
    }
}

impl InputMessage {
    fn extract_as_key_str(
        &self,
        ie: &IE,
        indices: &Option<Vec<usize>>,
    ) -> Result<String, AggregationError> {
        self.flow.extract_as_key_str(ie, indices)
    }
    fn reduce(
        &mut self,
        incoming: &InputMessage,
        transform: &IndexMap<IE, AggrOp>,
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
    tx: async_channel::Sender<(Window, (SocketAddr, FlatFlowInfo))>,
    config: AggregationConfig,
    stats: AggregationStats,
}

impl AggregationActor {
    fn new(
        cmd_recv: mpsc::Receiver<AggregationCommand>,
        rx: async_channel::Receiver<Arc<FlowRequest>>,
        tx: async_channel::Sender<(Window, (SocketAddr, FlatFlowInfo))>,
        config: AggregationConfig,
        stats: AggregationStats,
    ) -> Self {
        Self {
            cmd_recv,
            rx,
            tx,
            config,
            stats,
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        let agg = self
            .rx
            .flat_map(move |req| {
                let (peer, flow) = req.as_ref().clone();

                let peer_tags = [
                    opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                    opentelemetry::KeyValue::new(
                        "network.peer.port",
                        opentelemetry::Value::I64(peer.port().into()),
                    ),
                ];

                self.stats.received_messages.add(1, &peer_tags);

                stream::iter(
                    flow.flatten()
                        .into_iter()
                        .filter(|flow| match flow {
                            FlatFlowInfo::IPFIX(packet) => match packet.set() {
                                FlatSet::Data { record, .. } => {
                                    // Exclude records without octetDeltaCount (e.g. option records)
                                    record.fields().octetDeltaCount.is_some()
                                }
                                _ => false,
                            },
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
                            for (_key, message) in cache {

                                let peer_tags = [
                                    opentelemetry::KeyValue::new(
                                        "network.peer.address",
                                        format!("{}", message.peer.ip()),
                                    ),
                                    opentelemetry::KeyValue::new(
                                        "network.peer.port",
                                        opentelemetry::Value::I64(message.peer.port().into()),
                                    ),
                                ];
                                self.stats.aggregated_messages.add(1, &peer_tags);

                                if let Err(err) = self.tx.send(((window_start, window_end), (message.peer, message.flow))).await {
                                    error!("Flow Aggregation send error: {err}");
                                    self.stats.send_error.add(1, &peer_tags);
                                } else {
                                    self.stats.sent_messages.add(1, &peer_tags);
                                }
                            }
                        }
                        Some(Either::Right(_)) => {
                            self.stats.late_messages.add(1, &[]);
                            debug!("Late messages: discarding");
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
    rx: async_channel::Receiver<(Window, (SocketAddr, FlatFlowInfo))>,
}

impl AggregationActorHandle {
    pub fn new(
        buffer_size: usize,
        config: AggregationConfig,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        stats: either::Either<opentelemetry::metrics::Meter, AggregationStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (tx, rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => AggregationStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = AggregationActor::new(cmd_recv, flow_rx, tx, config, stats);
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

    pub fn subscribe(&self) -> async_channel::Receiver<(Window, (SocketAddr, FlatFlowInfo))> {
        self.rx.clone()
    }
}
