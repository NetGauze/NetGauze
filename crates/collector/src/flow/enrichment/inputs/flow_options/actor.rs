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

//! Flow options handler module for processing IPFIX/NetFlow options data
//! records.
//!
//! This module provides the core functionality for extracting and processing
//! options data from flow packets to enable enrichment metadata collection:
//! - `FlowOptionsActor` - Main actor that processes flow requests and extracts
//!   options data
//! - `FlowOptionsActorHandle` - Handle for controlling and communicating with
//!   the actor
//! - `FlowOptionsActorStats` - Metrics collection for options processing
//!   operations
//!
//! The actor receives flow data containing options templates and data records,
//! extracting scope-based metadata that can be used to enrich subsequent data
//! records. It forwards enrichment operations to registered enrichment actors
//! for cache updates.
//!
//! ## Supported Flow Types
//!
//! - **IPFIX** - Full options template and data record support
//! - **NetFlowV9** - Not yet implemented

use crate::flow::enrichment::{
    inputs::flow_options::normalize::OptionsDataRecord, EnrichmentActorHandle, EnrichmentOperation,
};
use netgauze_flow_pkt::{ipfix, FlowInfo};
use netgauze_flow_service::FlowRequest;
use std::{string::ToString, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy)]
enum FlowOptionsActorCommand {
    Shutdown,
}

#[derive(strum_macros::Display, Debug, Clone)]
pub enum FlowOptionsActorError {
    #[strum(to_string = "error in flow receive channel")]
    FlowReceiveError,
}

impl std::error::Error for FlowOptionsActorError {}

#[derive(Debug, Clone)]
pub struct FlowOptionsActorStats {
    received_flows: opentelemetry::metrics::Counter<u64>,
    send_error: opentelemetry::metrics::Counter<u64>,
    normalization_errors: opentelemetry::metrics::Counter<u64>,
    processed_options_records: opentelemetry::metrics::Counter<u64>,
    enrichment_ops_generated: opentelemetry::metrics::Counter<u64>,
}

impl FlowOptionsActorStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_flows = meter
            .u64_counter("netgauze.collector.flows.handlers.options.received.flows")
            .with_description("Number of Received Flows")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.handlers.options.send_error")
            .with_description("Error sending the enrichment operation to the enrichment actor")
            .build();
        let normalization_errors = meter
            .u64_counter("netgauze.collector.flows.handlers.options.normalization.errors")
            .with_description("Errors during record normalization")
            .build();
        let processed_options_records = meter
            .u64_counter("netgauze.collector.flows.handlers.options.processed.records")
            .with_description("Number of options data records processed")
            .build();
        let enrichment_ops_generated = meter
            .u64_counter("netgauze.collector.flows.handlers.options.enrichment.ops.generated")
            .with_description("Number of enrichment operations generated")
            .build();
        Self {
            received_flows,
            send_error,
            normalization_errors,
            processed_options_records,
            enrichment_ops_generated,
        }
    }
}

/// Core flow options actor that processes flow requests to extract options
/// metadata.
struct FlowOptionsActor {
    cmd_rx: mpsc::Receiver<FlowOptionsActorCommand>,
    flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
    enrichment_handles: Vec<EnrichmentActorHandle>,
    stats: FlowOptionsActorStats,
}

impl FlowOptionsActor {
    fn new(
        cmd_rx: mpsc::Receiver<FlowOptionsActorCommand>,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        enrichment_handles: Vec<EnrichmentActorHandle>,
        stats: FlowOptionsActorStats,
    ) -> Self {
        Self {
            cmd_rx,
            flow_rx,
            enrichment_handles,
            stats,
        }
    }

    /// Send enrichment operations to all registered enrichment actors
    async fn send_enrichment_operations(
        &mut self,
        ops: Vec<EnrichmentOperation>,
        peer_tags: &[opentelemetry::KeyValue],
    ) {
        for op in ops {
            debug!("Sending Enrichment Operation: \n{}", op);
            for handle in &self.enrichment_handles {
                if let Err(err) = handle.update_enrichment(op.clone()).await {
                    warn!("Failed to send enrichment operation: {}", err);
                    self.stats.send_error.add(1, peer_tags);
                }
            }
        }
    }

    /// Main actor event loop
    async fn run(mut self) -> anyhow::Result<String> {
        info!("Starting Flow Options Handler Actor");
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(FlowOptionsActorCommand::Shutdown) => {
                            info!("Flow options actor shutting down");
                            Ok("Flow options actor terminated after a shutdown command".to_string())
                        }
                        None => {
                            warn!("Flow options actor terminated due to empty command channel");
                            Ok("Flow options actor terminated due to empty command channel".to_string())
                        }
                    }
                }
                flow = self.flow_rx.recv() => {
                    match flow {
                        Ok(req) => {
                            let (peer, flow) = req.as_ref().clone();
                            let obs_id = flow.observation_domain_id();

                            let peer_tags = [
                                opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                            ];
                            self.stats.received_flows.add(1, &peer_tags);

                            match flow {
                                FlowInfo::IPFIX(pkt) => {
                                    for set in pkt.into_sets() {

                                        let data_records = if let ipfix::Set::Data { id: _, records } = set {
                                            records
                                        } else {
                                            continue;
                                        };

                                        // Filter and process options data records only
                                        for record in data_records
                                            .into_vec()
                                            .into_iter()
                                            .filter(|record| !record.scope_fields().is_empty()) {

                                            debug!("Options Data record found: {:?}", record);
                                            self.stats.processed_options_records.add(1, &peer_tags);

                                            // Categorize option types
                                            let options_record: OptionsDataRecord = record.try_into()?;

                                            // Construct enrichment operations from options data
                                            let ops = match options_record.into_enrichment_operations(peer.ip(), obs_id) {
                                                Ok(ops) => {
                                                    self.stats.enrichment_ops_generated.add(
                                                        ops.len() as u64,
                                                        &peer_tags,
                                                    );
                                                    ops
                                                },
                                                Err(e) => {
                                                    self.stats.normalization_errors.add(1, &peer_tags);
                                                    error!("Options Data record normalization error: {e}");
                                                    continue;
                                                }
                                            };

                                            // Send enrichment operations to EnrichmentActor
                                            self.send_enrichment_operations(ops, &peer_tags).await;

                                        }
                                    }
                                }
                                FlowInfo::NetFlowV9(_) => {
                                    warn!("NetFlowV9 options processing not yet implemented for peer  {}", peer);
                                }
                            }

                        }
                        Err(err) => {
                            error!("Flow options shutting down due to flow receive error: {err}");
                            Err(FlowOptionsActorError::FlowReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum FlowOptionsActorHandleError {
    SendError(String),
}

/// Handle for controlling and communicating with a flow options actor.
///
/// Provides a safe interface for:
/// - Sending control commands (shutdown)
/// - Managing actor lifecycle through join handles
pub struct FlowOptionsActorHandle {
    cmd_send: mpsc::Sender<FlowOptionsActorCommand>,
}

impl FlowOptionsActorHandle {
    pub fn new(
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        enrichment_handles: Vec<EnrichmentActorHandle>,
        stats: either::Either<opentelemetry::metrics::Meter, FlowOptionsActorStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_rx) = mpsc::channel::<FlowOptionsActorCommand>(1);
        let stats = match stats {
            either::Left(meter) => FlowOptionsActorStats::new(meter),
            either::Right(stats) => stats,
        };
        let actor = FlowOptionsActor::new(cmd_rx, flow_rx, enrichment_handles, stats);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_send };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), FlowOptionsActorHandleError> {
        self.cmd_send
            .send(FlowOptionsActorCommand::Shutdown)
            .await
            .map_err(|e| FlowOptionsActorHandleError::SendError(e.to_string()))
    }
}
