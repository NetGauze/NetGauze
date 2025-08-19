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

use netgauze_flow_pkt::{
    ie::{netgauze, Field},
    FlowInfo,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{error, info, warn};

/// Operations to update or delete enrichment data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SonataEnrichmentOperation {
    Upsert(u32, IpAddr, HashMap<String, String>),
    Delete(u32),
}

#[derive(Debug, Clone, Copy)]
pub enum SonataEnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum SonataEnrichmentActorError {
    EnrichmentChannelClosed,
    FlowReceiveError,
    MissingRequiredLabel(String),
    FieldAdditionFailed(String),
}

impl std::fmt::Display for SonataEnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
            Self::MissingRequiredLabel(label) => write!(f, "missing required label: {label}"),
            Self::FieldAdditionFailed(msg) => write!(f, "failed to add fields to flow: {msg}"),
        }
    }
}

impl std::error::Error for SonataEnrichmentActorError {}

#[derive(Debug, Clone)]
pub struct SonataEnrichmentStats {
    pub received_flows: opentelemetry::metrics::Counter<u64>,
    pub received_enrichment_ops: opentelemetry::metrics::Counter<u64>,
    pub sent: opentelemetry::metrics::Counter<u64>,
    pub send_error: opentelemetry::metrics::Counter<u64>,
    pub enrich_error: opentelemetry::metrics::Counter<u64>,
}

impl SonataEnrichmentStats {
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
        Self {
            received_flows,
            received_enrichment_ops,
            sent,
            send_error,
            enrich_error,
        }
    }
}

struct SonataEnrichment {
    labels: HashMap<IpAddr, (u32, HashMap<String, String>)>,
    writer_id: String,
    cmd_rx: mpsc::Receiver<SonataEnrichmentActorCommand>,
    enrichment_rx: async_channel::Receiver<SonataEnrichmentOperation>,
    flow_rx: async_channel::Receiver<(IpAddr, FlowInfo)>,
    enriched_tx: async_channel::Sender<(IpAddr, FlowInfo)>,
    default_labels: (u32, HashMap<String, String>),
    stats: SonataEnrichmentStats,
}

impl SonataEnrichment {
    fn new(
        writer_id: String,
        cmd_rx: mpsc::Receiver<SonataEnrichmentActorCommand>,
        enrichment_rx: async_channel::Receiver<SonataEnrichmentOperation>,
        flow_rx: async_channel::Receiver<(IpAddr, FlowInfo)>,
        enriched_tx: async_channel::Sender<(IpAddr, FlowInfo)>,
        stats: SonataEnrichmentStats,
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
            flow_rx,
            enriched_tx,
            default_labels,
            stats,
        }
    }

    fn apply_enrichment(&mut self, op: SonataEnrichmentOperation) {
        match op {
            SonataEnrichmentOperation::Upsert(id, ip, enrichment) => {
                self.labels.insert(ip, (id, enrichment));
            }
            SonataEnrichmentOperation::Delete(id) => {
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

    fn enrich(
        &self,
        peer_ip: IpAddr,
        flow: FlowInfo,
    ) -> Result<FlowInfo, SonataEnrichmentActorError> {
        let (_, labels) = self.labels.get(&peer_ip).unwrap_or(&self.default_labels);

        let node_id = labels
            .get("nkey")
            .ok_or_else(|| SonataEnrichmentActorError::MissingRequiredLabel("nkey".to_string()))?;

        let platform_id = labels
            .get("pkey")
            .ok_or_else(|| SonataEnrichmentActorError::MissingRequiredLabel("pkey".to_string()))?;

        let add_fields = [
            Field::NetGauze(netgauze::Field::nodeId(node_id.as_str().into())),
            Field::NetGauze(netgauze::Field::platformId(platform_id.as_str().into())),
            Field::NetGauze(netgauze::Field::dataCollectionManifestName(
                self.writer_id.as_str().into(),
            )),
        ];

        flow.with_fields_added(&add_fields)
            .map_err(|e| SonataEnrichmentActorError::FieldAdditionFailed(e.to_string()))
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(SonataEnrichmentActorCommand::Shutdown) => {
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
                            self.apply_enrichment(op);
                        }
                        Err(err) => {
                            warn!("Enrichment channel closed, shutting down: {err:?}");
                            Err(SonataEnrichmentActorError::EnrichmentChannelClosed)?;
                        }
                    }
                }
                flow = self.flow_rx.recv() => {
                    match flow {
                        Ok((peer_ip, flow)) => {
                            let peer_tags = [
                                opentelemetry::KeyValue::new(
                                    "network.peer.address",
                                    format!("{peer_ip}"),
                                ),
                            ];
                            self.stats.received_flows.add(1, &peer_tags);
                            let enriched = match self.enrich(peer_ip, flow) {
                                Ok(enriched) => enriched,
                                Err(err) => {
                                    error!("Failed to enrich flow from {}: {}", peer_ip, err);
                                    self.stats.enrich_error.add(1, &peer_tags);
                                    continue;
                                }
                            };
                            if let Err(err) = self.enriched_tx.send((peer_ip, enriched)).await {
                                error!("FlowEnrichment send error: {err}");
                                 self.stats.send_error.add(1, &peer_tags);
                            } else {
                                 self.stats.sent.add(1, &peer_tags);
                            }
                        }
                        Err(err) => {
                            error!("Shutting down due to FlowEnrichment recv error: {err}");
                            Err(SonataEnrichmentActorError::FlowReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum SonataEnrichmentActorHandleError {
    SendError,
}
impl std::fmt::Display for SonataEnrichmentActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SonataEnrichmentActorHandleError::SendError => {
                write!(f, "Failed to send flow enrichment actor")
            }
        }
    }
}

impl std::error::Error for SonataEnrichmentActorHandleError {}

#[derive(Debug, Clone)]
pub struct SonataEnrichmentActorHandle {
    cmd_send: mpsc::Sender<SonataEnrichmentActorCommand>,
    enrichment_tx: async_channel::Sender<SonataEnrichmentOperation>,
    enriched_rx: async_channel::Receiver<(IpAddr, FlowInfo)>,
}

impl SonataEnrichmentActorHandle {
    pub fn new(
        writer_id: String,
        buffer_size: usize,
        flow_rx: async_channel::Receiver<(IpAddr, FlowInfo)>,
        stats: either::Either<opentelemetry::metrics::Meter, SonataEnrichmentStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enrichment_tx, enrichment_rx) = async_channel::bounded(buffer_size);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => SonataEnrichmentStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = SonataEnrichment::new(
            writer_id,
            cmd_recv,
            enrichment_rx,
            flow_rx,
            enriched_tx,
            stats,
        );
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            enrichment_tx,
            enriched_rx,
        };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), SonataEnrichmentActorHandleError> {
        self.cmd_send
            .send(SonataEnrichmentActorCommand::Shutdown)
            .await
            .map_err(|_| SonataEnrichmentActorHandleError::SendError)
    }

    pub async fn update_enrichment(
        &self,
        op: SonataEnrichmentOperation,
    ) -> Result<(), SonataEnrichmentActorHandleError> {
        self.enrichment_tx
            .send(op)
            .await
            .map_err(|_| SonataEnrichmentActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<(IpAddr, FlowInfo)> {
        self.enriched_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use netgauze_flow_pkt::{
        ie::{netgauze, Field},
        ipfix::{DataRecord, IpfixPacket, Set},
        DataSetId, FlowInfo,
    };
    use std::net::IpAddr;

    #[test]
    fn test_apply_enrichment_upsert() {
        // Create actor state
        let mut enrichment = SonataEnrichment::new(
            "test-writer-id".to_string(),
            mpsc::channel(1).1,          // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).0, // dummy sender
            SonataEnrichmentStats::new(opentelemetry::global::meter("dummy")),
        );

        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut labels = HashMap::new();
        labels.insert("nkey".to_string(), "node-1".to_string());
        labels.insert("pkey".to_string(), "platform-1".to_string());

        // Test upsert operation
        let op = SonataEnrichmentOperation::Upsert(123, peer_ip, labels.clone());
        enrichment.apply_enrichment(op);

        assert_eq!(enrichment.labels.get(&peer_ip), Some(&(123, labels)));
    }

    #[test]
    fn test_apply_enrichment_delete() {
        // Create actor state
        let mut enrichment = SonataEnrichment::new(
            "test-writer-id".to_string(),
            mpsc::channel(1).1,          // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).0, // dummy sender
            SonataEnrichmentStats::new(opentelemetry::global::meter("dummy")),
        );

        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer_ip_2: IpAddr = "10.0.0.2".parse().unwrap();
        let mut labels = HashMap::new();
        labels.insert("nkey".to_string(), "node-1".to_string());
        labels.insert("pkey".to_string(), "platform-1".to_string());

        // Insert first some entries
        enrichment.labels.insert(peer_ip, (123, labels.clone()));
        enrichment.labels.insert(peer_ip_2, (456, labels));
        assert!(enrichment.labels.contains_key(&peer_ip));
        assert!(enrichment.labels.contains_key(&peer_ip_2));

        // Test delete operation
        let op = SonataEnrichmentOperation::Delete(123);
        enrichment.apply_enrichment(op);

        assert!(!enrichment.labels.contains_key(&peer_ip));
        assert!(enrichment.labels.contains_key(&peer_ip_2));

        // Test delete non-existing id
        let op = SonataEnrichmentOperation::Delete(1000);
        enrichment.apply_enrichment(op);
        assert!(!enrichment.labels.contains_key(&peer_ip));
        assert!(enrichment.labels.contains_key(&peer_ip_2));
    }

    #[test]
    fn test_apply_enrichment_update_existing() {
        // Create actor state
        let mut enrichment = SonataEnrichment::new(
            "test-writer-id".to_string(),
            mpsc::channel(1).1,          // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).0, // dummy sender
            SonataEnrichmentStats::new(opentelemetry::global::meter("dummy")),
        );

        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Insert initial labels
        let mut initial_labels = HashMap::new();
        initial_labels.insert("nkey".to_string(), "old-node".to_string());
        initial_labels.insert("pkey".to_string(), "old-platform".to_string());
        enrichment.labels.insert(peer_ip, (123, initial_labels));

        // Update with new labels
        let mut new_labels = HashMap::new();
        new_labels.insert("nkey".to_string(), "new-node".to_string());
        new_labels.insert("pkey".to_string(), "new-platform".to_string());

        let op = SonataEnrichmentOperation::Upsert(123, peer_ip, new_labels.clone());
        enrichment.apply_enrichment(op);

        assert_eq!(enrichment.labels.get(&peer_ip), Some(&(123, new_labels)));
    }

    #[test]
    fn test_enrich_with_existing_labels() {
        let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
        let peer_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Create actor state
        let mut enrichment = SonataEnrichment::new(
            "test-writer-id".to_string(),
            mpsc::channel(1).1,          // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).0, // dummy sender
            SonataEnrichmentStats::new(opentelemetry::global::meter("dummy")),
        );

        // Create labels map entry for peer_ip (simulate sonata pushing labels)
        let mut node_labels = HashMap::new();
        node_labels.insert("nkey".to_string(), "test-node-123".to_string());
        node_labels.insert("pkey".to_string(), "test-platform-ABC".to_string());
        enrichment.apply_enrichment(SonataEnrichmentOperation::Upsert(1, peer_ip, node_labels));

        // Create flow to be enriched
        let original_flow = FlowInfo::IPFIX(IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([]),
                    Box::new([
                        Field::octetDeltaCount(5000),
                        Field::packetDeltaCount(5),
                        Field::tcpDestinationPort(80),
                    ]),
                )]),
            }]),
        ));

        // Enrich the flow
        let enriched_flow = enrichment
            .enrich(peer_ip, original_flow)
            .expect("failed to enrich");

        // Create expected enriched flow
        let expected_flow = FlowInfo::IPFIX(IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([]),
                    Box::new([
                        Field::octetDeltaCount(5000),
                        Field::packetDeltaCount(5),
                        Field::tcpDestinationPort(80),
                        Field::NetGauze(netgauze::Field::nodeId("test-node-123".into())),
                        Field::NetGauze(netgauze::Field::platformId("test-platform-ABC".into())),
                        Field::NetGauze(netgauze::Field::dataCollectionManifestName(
                            "test-writer-id".into(),
                        )),
                    ]),
                )]),
            }]),
        ));

        // Compare enriched with expected
        assert_eq!(enriched_flow, expected_flow);
    }

    #[test]
    fn test_enrich_with_default_labels() {
        let export_time = Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap();
        let peer_ip: IpAddr = "192.168.1.200".parse().unwrap(); // IP not in labels map

        // Create actor state
        let enrichment = SonataEnrichment::new(
            "test-writer-id".to_string(),
            mpsc::channel(1).1,          // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).1, // dummy receiver
            async_channel::bounded(1).0, // dummy sender
            SonataEnrichmentStats::new(opentelemetry::global::meter("dummy")),
        );

        // Create flow to be enriched
        let original_flow = FlowInfo::IPFIX(IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([]),
                    Box::new([Field::octetDeltaCount(200), Field::tcpDestinationPort(443)]),
                )]),
            }]),
        ));

        // Enrich the flow
        let enriched_flow = enrichment.enrich(peer_ip, original_flow).unwrap();

        // Create expected enriched flow
        let expected_flow = FlowInfo::IPFIX(IpfixPacket::new(
            export_time,
            0,
            0,
            Box::new([Set::Data {
                id: DataSetId::new(256).unwrap(),
                records: Box::new([DataRecord::new(
                    Box::new([]),
                    Box::new([
                        Field::octetDeltaCount(200),
                        Field::tcpDestinationPort(443),
                        Field::NetGauze(netgauze::Field::nodeId("unknown".into())),
                        Field::NetGauze(netgauze::Field::platformId("unknown".into())),
                        Field::NetGauze(netgauze::Field::dataCollectionManifestName(
                            "test-writer-id".into(),
                        )),
                    ]),
                )]),
            }]),
        ));

        // Compare enriched with expected
        assert_eq!(enriched_flow, expected_flow);
    }
}
