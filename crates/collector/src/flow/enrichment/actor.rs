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

//! Flow enrichment actor module for real-time flow metadata enrichment.
//!
//! This module provides the core actor implementation for flow enrichment:
//! - `EnrichmentActor` - Main actor that processes flow requests and applies
//!   cached enrichment
//! - `EnrichmentActorHandle` - Handle for controlling and communicating with
//!   the actor
//! - `EnrichmentStats` - Comprehensive metrics collection for enrichment
//!   operations
//!
//! The actor receives flow data and enrichment operations concurrently,
//! maintaining an in-memory cache of peer metadata for fast lookup and field
//! injection. It supports parallel processing through multiple worker shards
//! and provides detailed telemetry for monitoring enrichment performance.
//!
//! ## Architecture
//!
//! The enrichment actor operates on three main channels:
//! - **Command Channel** - Receives control commands (shutdown)
//! - **Enrichment Channel** - Receives cache update operations from external
//!   sources
//! - **Flow Channel** - Receives flow data requiring enrichment
//!
//! ## Flow Processing
//!
//! For each incoming flow:
//! 1. Extract peer IP and observation domain ID
//! 2. Query enrichment cache for matching metadata
//! 3. Apply field enrichment based on scope matching and weight priorities
//! 4. Forward enriched flow to downstream processors
//!
//! ## Supported Flow Types
//!
//! - **IPFIX** - Full enrichment support
//! - **NetFlowV9** - Not yet supported

use crate::flow::enrichment::{cache::EnrichmentCache, EnrichmentOperation};
use netgauze_flow_pkt::{ipfix, FlowInfo};
use netgauze_flow_service::FlowRequest;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

/// Core enrichment actor that processes flow requests using cached metadata.
///
/// The actor maintains an `EnrichmentCache` and processes three types of
/// messages:
/// - Control commands for lifecycle management
/// - Enrichment operations for cache updates
/// - Flow requests for metadata injection
struct EnrichmentActor {
    enrichment_cache: EnrichmentCache,
    cmd_rx: mpsc::Receiver<EnrichmentActorCommand>,
    enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
    flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
    enriched_tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
    stats: EnrichmentStats,
    shard_id: usize,
}

impl EnrichmentActor {
    fn new(
        cmd_rx: mpsc::Receiver<EnrichmentActorCommand>,
        enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        enriched_tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
        stats: EnrichmentStats,
        shard_id: usize,
    ) -> Self {
        Self {
            enrichment_cache: EnrichmentCache::new(),
            cmd_rx,
            enrichment_rx,
            flow_rx,
            enriched_tx,
            stats,
            shard_id,
        }
    }

    /// Update the cache peer count gauge with current cache size
    fn update_cache_metrics(&self) {
        let peer_count = self.enrichment_cache.peer_count() as u64;
        let tags = [opentelemetry::KeyValue::new(
            "shard_id",
            opentelemetry::Value::I64(self.shard_id as i64),
        )];
        self.stats.cache_peer_count.record(peer_count, &tags);
    }

    /// Enrich a flow with cached metadata for the specified peer IP.
    fn enrich(&self, peer_ip: IpAddr, flow: FlowInfo) -> Result<FlowInfo, EnrichmentActorError> {
        debug!("Enriching flow packet from peer: {}", peer_ip);

        let enriched_flow = match flow {
            FlowInfo::IPFIX(pkt) => self
                .enrich_ipfix_packet(peer_ip, pkt)
                .map(FlowInfo::IPFIX)?,
            FlowInfo::NetFlowV9(pkt) => {
                warn!(
                    "NetFlowV9 enrichment not yet implemented for peer {}",
                    peer_ip
                );
                FlowInfo::NetFlowV9(pkt)
            }
        };

        Ok(enriched_flow)
    }

    /// Enriches an IPFIX packet with cached metadata for the specified peer IP.
    ///
    /// Processes each data record in the packet, applying enrichment fields
    /// that match the observation domain and record contents. Template sets
    /// are filtered out and not processed further.
    fn enrich_ipfix_packet(
        &self,
        peer_ip: IpAddr,
        pkt: ipfix::IpfixPacket,
    ) -> Result<ipfix::IpfixPacket, EnrichmentActorError> {
        let export_time = pkt.export_time();
        let sequence_number = pkt.sequence_number();
        let obs_id = pkt.observation_domain_id();

        let enriched_sets = pkt
            .into_sets()
            .into_vec()
            .into_iter()
            .filter_map(|set| match set {
                ipfix::Set::Data { id, records } => {
                    let enriched_records = records
                        .into_vec()
                        .into_iter()
                        .map(|record| {
                            if let Some(enrichment_fields) = self
                                .enrichment_cache
                                .get_enrichment_fields(&peer_ip, obs_id, record.fields())
                            {
                                record.with_fields_added(&enrichment_fields)
                            } else {
                                record
                            }
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

        Ok(ipfix::IpfixPacket::new(
            export_time,
            sequence_number,
            obs_id,
            enriched_sets,
        ))
    }

    /// Main actor event loop.
    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(EnrichmentActorCommand::Shutdown) => {
                            info!("Shutting down flow enrichment actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            warn!("Flow enrichment actor terminated due to command channel closing");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                    }
                }
                enrichment = self.enrichment_rx.recv() => {
                    match enrichment {
                        Ok(op) => {
                            self.stats.received_enrichment_ops.add(1, &[]);
                            self.enrichment_cache.apply_enrichment(op);
                            self.update_cache_metrics();
                        }
                        Err(err) => {
                            warn!("Enrichment channel closed, shutting down: {err:?}");
                            Err(EnrichmentActorError::EnrichmentChannelClosed)?;
                        }
                    }
                }
                flow = self.flow_rx.recv() => {
                    match flow {
                        Ok(req) => {
                            let (peer, flow) = req.as_ref().clone();

                            let peer_tags = [
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
                            self.stats.received_flows.add(1, &peer_tags);

                            let enriched = match self.enrich(peer.ip(), flow) {
                                Ok(enriched) => enriched,
                                Err(err) => {
                                    error!("Failed to enrich flow from {}: {}", peer.ip(), err);
                                    self.stats.enrich_error.add(1, &peer_tags);
                                    continue;
                                }
                            };
                            if let Err(err) = self.enriched_tx.send((peer, enriched)).await {
                                error!("FlowEnrichment send error: {err}");
                                 self.stats.send_error.add(1, &peer_tags);
                            } else {
                                 self.stats.sent.add(1, &peer_tags);
                            }
                        }
                        Err(err) => {
                            error!("Shutting down due to FlowEnrichment recv error: {err}");
                            Err(EnrichmentActorError::FlowReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum EnrichmentActorError {
    EnrichmentChannelClosed,
    FlowReceiveError,
}

impl std::fmt::Display for EnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
        }
    }
}

impl std::error::Error for EnrichmentActorError {}

#[derive(Debug, Clone)]
pub struct EnrichmentStats {
    pub received_flows: opentelemetry::metrics::Counter<u64>,
    pub received_enrichment_ops: opentelemetry::metrics::Counter<u64>,
    pub sent: opentelemetry::metrics::Counter<u64>,
    pub send_error: opentelemetry::metrics::Counter<u64>,
    pub enrich_error: opentelemetry::metrics::Counter<u64>,
    pub cache_peer_count: opentelemetry::metrics::Gauge<u64>,
}

impl EnrichmentStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_flows = meter
            .u64_counter("netgauze.collector.flows.enrichment.received.flows")
            .with_description("Number of flows received for enrichment")
            .build();
        let received_enrichment_ops = meter
            .u64_counter("netgauze.collector.flows.enrichment.received.enrichment.operations")
            .with_description("Number of enrichment updates received from SONATA")
            .build();
        let sent = meter
            .u64_counter("netgauze.collector.flows.enrichment.sent")
            .with_description("Number of enriched flows successfully sent upstream")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.enrichment.sent.error")
            .with_description("Number of enrichment updates sent upstream error")
            .build();
        let enrich_error = meter
            .u64_counter("netgauze.collector.flows.enrichment.enrich.error")
            .with_description("Number of enrichment updates sent upstream error")
            .build();
        let cache_peer_count = meter
            .u64_gauge("netgauze.collector.flows.enrichment.cache.peer_count")
            .with_description("Number of peer IPs with cached metadata entries")
            .build();
        Self {
            received_flows,
            received_enrichment_ops,
            sent,
            send_error,
            enrich_error,
            cache_peer_count,
        }
    }
}

#[derive(Debug)]
pub enum EnrichmentActorHandleError {
    SendError,
}
impl std::fmt::Display for EnrichmentActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrichmentActorHandleError::SendError => {
                write!(f, "Failed to send flow enrichment actor")
            }
        }
    }
}

impl std::error::Error for EnrichmentActorHandleError {}

/// Handle for controlling and communicating with an enrichment actor.
///
/// Provides a safe interface for:
/// - Sending control commands (shutdown)
/// - Pushing enrichment cache updates
/// - Subscribing to enriched flow output
///
/// The handle can be cloned and shared across multiple components,
/// with all operations being non-blocking and channel-based.
#[derive(Debug, Clone)]
pub struct EnrichmentActorHandle {
    cmd_send: mpsc::Sender<EnrichmentActorCommand>,
    enrichment_tx: async_channel::Sender<EnrichmentOperation>,
    enriched_rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
}

impl EnrichmentActorHandle {
    pub fn new(
        buffer_size: usize,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        stats: either::Either<opentelemetry::metrics::Meter, EnrichmentStats>,
        shard_id: usize,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enrichment_tx, enrichment_rx) = async_channel::bounded(buffer_size);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => EnrichmentStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = EnrichmentActor::new(
            cmd_recv,
            enrichment_rx,
            flow_rx,
            enriched_tx,
            stats,
            shard_id,
        );
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            enrichment_tx,
            enriched_rx,
        };
        (join_handle, handle)
    }

    /// Request graceful shutdown of the enrichment actor.
    pub async fn shutdown(&self) -> Result<(), EnrichmentActorHandleError> {
        self.cmd_send
            .send(EnrichmentActorCommand::Shutdown)
            .await
            .map_err(|_| EnrichmentActorHandleError::SendError)
    }

    /// Send an enrichment cache update to the actor.
    ///
    /// Updates are applied asynchronously and will affect subsequent
    /// flow enrichment operations. The operation can be either an
    /// upsert (add/update) or delete.
    pub async fn update_enrichment(
        &self,
        op: EnrichmentOperation,
    ) -> Result<(), EnrichmentActorHandleError> {
        self.enrichment_tx
            .send(op)
            .await
            .map_err(|_| EnrichmentActorHandleError::SendError)
    }

    /// Subscribe to enriched flow output from the actor.
    ///
    /// Returns a cloneable receiver that will receive all enriched flows
    /// processed by the actor. Multiple subscribers can receive the same
    /// flow data independently.
    pub fn subscribe(&self) -> async_channel::Receiver<(SocketAddr, FlowInfo)> {
        self.enriched_rx.clone()
    }
}
