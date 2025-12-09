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

use crate::flow::renormalization::logic::renormalize;
use either::Either;
use netgauze_flow_pkt::FlowInfo;
use opentelemetry::metrics::Meter;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct RenormalizationStats {
    pub messages_received: opentelemetry::metrics::Counter<u64>,
    pub messages_sent: opentelemetry::metrics::Counter<u64>,
    pub messages_sent_error: opentelemetry::metrics::Counter<u64>,

    pub flows_renormalized: opentelemetry::metrics::Counter<u64>,
    pub flows_processed: opentelemetry::metrics::Counter<u64>,
    // temporary metric until v9 is fully supported
    pub netflow_v9_not_supported: opentelemetry::metrics::Counter<u64>,
    pub ie_missing_or_invalid: opentelemetry::metrics::Counter<u64>,
    pub sampling_algorithm_inferred: opentelemetry::metrics::Counter<u64>,
}

impl RenormalizationStats {
    pub fn new(meter: Meter) -> Self {
        let messages_received = meter
            .u64_counter("netgauze.collector.flows.renormalization.messages.received")
            .with_description("Number of IPFIX/NetFlow messages received for renormalization")
            .build();
        let messages_sent = meter
            .u64_counter("netgauze.collector.flows.renormalization.messages.sent")
            .with_description(
                "Number of IPFIX/NetFlow successfully sent upstream (renormalized or not)",
            )
            .build();
        let messages_sent_error = meter
            .u64_counter("netgauze.collector.flows.renormalization.messages.sent.error")
            .with_description("Number of IPFIX/NetFlow messages that failed to send upstream after renormalization step")
            .build();

        let flows_renormalized = meter
            .u64_counter("netgauze.collector.flows.renormalization.flows.renormalized")
            .with_description("Number of flows successfully renormalized")
            .build();
        let flows_processed = meter
            .u64_counter("netgauze.collector.flows.renormalization.flows.processed")
            .with_description(
                "Number of flows processed for renormalization (including non-renormalizable)",
            )
            .build();
        let netflow_v9_not_supported = meter
            .u64_counter("netgauze.collector.flows.renormalization.netflow.v9.not_supported")
            .with_description(
                "Number of NetFlow v9 flows received but not renormalized (not yet supported)",
            )
            .build();
        let ie_missing_or_invalid = meter
            .u64_counter("netgauze.collector.flows.renormalization.ie.missing_invalid")
            .with_description(
                "Number of flows with missing or invalid information elements for renormalization",
            )
            .build();
        let sampling_algorithm_inferred = meter
            .u64_counter(
                "netgauze.collector.flows.renormalization.sampling_algorithm.inferred",
            )
            .with_description(
                "Number of flows where selector algorithm field was missing, but algorithm was inferred from other fields",
            )
            .build();

        Self {
            messages_received,
            messages_sent,
            messages_sent_error,
            flows_renormalized,
            flows_processed,
            netflow_v9_not_supported,
            ie_missing_or_invalid,
            sampling_algorithm_inferred,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RenormalizationCommand {
    Shutdown,
}

#[derive(Debug)]
struct RenormalizationActor {
    cmd_rx: mpsc::Receiver<RenormalizationCommand>,
    rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
    tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
    stats: RenormalizationStats,
    shard_id: usize,
}

impl RenormalizationActor {
    fn new(
        cmd_rx: mpsc::Receiver<RenormalizationCommand>,
        rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
        tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
        stats: RenormalizationStats,
        shard_id: usize,
    ) -> Self {
        Self {
            cmd_rx,
            rx,
            tx,
            stats,
            shard_id,
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(RenormalizationCommand::Shutdown) => {
                            info!("Shutting down flow renormalization actor");
                        }
                        None => {
                            warn!("Flow renormalization actor terminated due to command channel closing");
                        }
                    }
                    return Ok("Renormalization shutdown successfully".to_string());
                }
                flow = self.rx.recv() => {
                    match flow {
                        Ok((peer, flow)) => {
                            let tags = [
                                opentelemetry::KeyValue::new(
                                    "shard_id",
                                    opentelemetry::Value::I64(self.shard_id as i64),
                                ),
                                opentelemetry::KeyValue::new("network.peer.address", peer.ip().to_string()),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                            ];
                            self.stats.messages_received.add(1, &tags);

                            // call renormalization processing
                            let renormalized = renormalize(peer, flow, &self.stats, &tags);

                            // send renormalized flow to next stage
                            if let Err(err) = self.tx.send((peer, renormalized)).await {
                                error!("Flow renormalization send error: {err}");
                                self.stats.messages_sent_error.add(1, &tags);
                                Err(RenormalizationActorError::SendChannelError)?;
                            }
                            else {
                                self.stats.messages_sent.add(1, &tags);
                            }
                        }
                        Err(err) => {
                            error!("Shutting down due to Renormalization recv error: {err}");
                            Err(RenormalizationActorError::ReceiveChannelError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum RenormalizationActorError {
    ReceiveChannelError,
    SendChannelError,
}

impl std::fmt::Display for RenormalizationActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReceiveChannelError => write!(f, "error in renormalization receive channel"),
            Self::SendChannelError => write!(f, "error in renormalization send channel"),
        }
    }
}

impl std::error::Error for RenormalizationActorError {}

#[derive(Debug, Clone)]
pub enum RenormalizationActorHandleError {
    SendError,
}

impl std::fmt::Display for RenormalizationActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError => write!(f, "Failed to send command to renormalization actor"),
        }
    }
}

impl std::error::Error for RenormalizationActorHandleError {}

/// Handle for controlling and communicating with an renormalization actor.
///
/// Provides a safe interface for:
/// - Sending control commands (shutdown)
/// - Subscribing to renormalized flow output
///
/// The handle can be cloned and shared across multiple components,
/// with all operations being non-blocking and channel-based.
#[derive(Debug, Clone)]
pub struct RenormalizationActorHandle {
    cmd_send: mpsc::Sender<RenormalizationCommand>,
    renormalized_rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
}

impl RenormalizationActorHandle {
    pub fn new(
        buffer_size: usize,
        to_renormalize_rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
        stats: Either<Meter, RenormalizationStats>,
        shard_id: usize,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (renormalized_tx, renormalized_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            Either::Left(meter) => RenormalizationStats::new(meter),
            Either::Right(stats) => stats,
        };
        let actor = RenormalizationActor::new(
            cmd_recv,
            to_renormalize_rx,
            renormalized_tx,
            stats,
            shard_id,
        );
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            renormalized_rx,
        };
        (join_handle, handle)
    }

    /// Request graceful shutdown of the enrichment actor.
    pub async fn shutdown(&self) -> Result<(), RenormalizationActorHandleError> {
        self.cmd_send
            .send(RenormalizationCommand::Shutdown)
            .await
            .map_err(|_| RenormalizationActorHandleError::SendError)
    }

    /// Subscribe to renormalized flow output from the actor.
    ///
    /// Returns a cloneable receiver that will receive all renormalized flows
    /// processed by the actor. Multiple subscribers can receive the same
    /// flow data independently.
    pub fn subscribe(&self) -> async_channel::Receiver<(SocketAddr, FlowInfo)> {
        self.renormalized_rx.clone()
    }
}

#[cfg(test)]
mod tests;
