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

//! A module for enriching flow data with additional metadata.
//!
//! This module provides functionality to:
//! - Enrich flow records with additional metadata/labels based on IP addresses
//! - Process aggregated flow records from upstream sources
//! - Forward enriched flows downstream for further processing
//!
//! The main components are:
//! - `FlowEnrichment` - The core actor responsible for enriching flow data
//! - `FlowEnrichmentActorHandle` - The handle used to control the enrichment
//!   actor
//! - `EnrichmentOperation` - Operations to update/delete enrichment data

use crate::flow::EnrichedFlow;
use netgauze_analytics::aggregation::Window;
use netgauze_flow_pkt::FlatFlowInfo;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{error, info, warn};

/// Operations to update or delete enrichment data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnrichmentOperation {
    Upsert(u32, IpAddr, HashMap<String, String>),
    Delete(u32),
}

#[derive(Debug, Clone, Copy)]
pub enum FlowEnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
pub enum FlowEnrichmentActorError {
    EnrichmentChannelClosed,
    FlowReceiveError,
}

impl std::fmt::Display for FlowEnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
        }
    }
}

impl std::error::Error for FlowEnrichmentActorError {}

struct FlowEnrichment {
    labels: HashMap<IpAddr, (u32, HashMap<String, String>)>,
    writer_id: String,
    cmd_rx: mpsc::Receiver<FlowEnrichmentActorCommand>,
    enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
    agg_rx: async_channel::Receiver<(Window, (SocketAddr, FlatFlowInfo))>,
    enriched_tx: async_channel::Sender<EnrichedFlow>,
    default_labels: (u32, HashMap<String, String>),
}

impl FlowEnrichment {
    fn new(
        writer_id: String,
        cmd_rx: mpsc::Receiver<FlowEnrichmentActorCommand>,
        enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
        agg_rx: async_channel::Receiver<(Window, (SocketAddr, FlatFlowInfo))>,
        enriched_tx: async_channel::Sender<EnrichedFlow>,
    ) -> Self {
        let default_labels = (
            0,
            HashMap::from([
                ("pkey".to_string(), "unknown".to_string()),
                ("nkey".to_string(), "unknown".to_string()),
            ]),
        );
        Self {
            writer_id,
            labels: HashMap::new(),
            cmd_rx,
            enrichment_rx,
            agg_rx,
            enriched_tx,
            default_labels,
        }
    }

    fn apply_enrichment(&mut self, op: EnrichmentOperation) {
        match op {
            EnrichmentOperation::Upsert(id, ip, enrichment) => {
                self.labels.insert(ip, (id, enrichment));
            }
            EnrichmentOperation::Delete(id) => {
                let mut to_remove = None;
                for (ip, (i, _)) in &self.labels {
                    if id == *i {
                        to_remove = Some(*ip);
                        break;
                    }
                }
                if let Some(ip) = to_remove {
                    self.labels.remove(&ip);
                }
            }
        }
    }

    fn enrich(&self, window: Window, peer: SocketAddr, flow: FlatFlowInfo) -> EnrichedFlow {
        let (_, labels) = self.labels.get(&peer.ip()).unwrap_or(&self.default_labels);
        let (window_start, window_end) = window;
        let ts = chrono::Utc::now();
        EnrichedFlow {
            labels: labels.clone(),
            peer_src: peer.ip(),
            peer_port: peer.port(),
            writer_id: self.writer_id.clone(),
            ts,
            window_start,
            window_end,
            flow,
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(FlowEnrichmentActorCommand::Shutdown) => {
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
                            self.apply_enrichment(op);
                        }
                        Err(err) => {
                            warn!("Enrichment channel closed, shutting down: {err:?}");
                            Err(FlowEnrichmentActorError::EnrichmentChannelClosed)?;
                        }
                    }
                }
                flow = self.agg_rx.recv() => {
                    match flow {
                        Ok((window, (peer, flat_flow))) => {
                            let enriched = self.enrich(window, peer, flat_flow);
                            if let Err(err) = self.enriched_tx.send(enriched).await {
                                error!("FlowEnrichment send error: {err}");
                            }
                        }
                        Err(err) => {
                            error!("Shutting down due to FlowEnrichment recv error: {err}");
                            Err(FlowEnrichmentActorError::FlowReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum FlowEnrichmentActorHandleError {
    SendError,
}
impl std::fmt::Display for FlowEnrichmentActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowEnrichmentActorHandleError::SendError => {
                write!(f, "Failed to send flow enrichment actor")
            }
        }
    }
}

impl std::error::Error for FlowEnrichmentActorHandleError {}

#[derive(Debug, Clone)]
pub struct FlowEnrichmentActorHandle {
    cmd_send: mpsc::Sender<FlowEnrichmentActorCommand>,
    enrichment_tx: async_channel::Sender<EnrichmentOperation>,
    enriched_rx: async_channel::Receiver<EnrichedFlow>,
}

impl FlowEnrichmentActorHandle {
    pub fn new(
        writer_id: String,
        buffer_size: usize,
        agg_rx: async_channel::Receiver<(Window, (SocketAddr, FlatFlowInfo))>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enrichment_tx, enrichment_rx) = async_channel::bounded(buffer_size);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let actor = FlowEnrichment::new(writer_id, cmd_recv, enrichment_rx, agg_rx, enriched_tx);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            enrichment_tx,
            enriched_rx,
        };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), FlowEnrichmentActorHandleError> {
        self.cmd_send
            .send(FlowEnrichmentActorCommand::Shutdown)
            .await
            .map_err(|_| FlowEnrichmentActorHandleError::SendError)
    }

    pub async fn update_enrichment(
        &self,
        op: EnrichmentOperation,
    ) -> Result<(), FlowEnrichmentActorHandleError> {
        self.enrichment_tx
            .send(op)
            .await
            .map_err(|_| FlowEnrichmentActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<EnrichedFlow> {
        self.enriched_rx.clone()
    }
}
