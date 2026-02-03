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

//! A module for processing Yang Push notifications messages.
//!
//! This module provides functionality to:
//! - Cache and manage subscription metadata from Yang-Push Subscription
//!   Started/Modified/Terminated notifications
//! - Enrich Yang-Push notifications with metadata from cached subscriptions
//! - Encapsulate Yang-Push notifications into Telemetry Message objects along
//!   with the relevant metadata
//!
//! The main components are:
//! - `YangPushEnrichmentActor` - The core actor responsible for processing and
//!   enriching Yang Push notifications.
//! - `YangPushEnrichmentActorHandle` - A handle for controlling the enrichment
//!   actor and subscribing to enriched messages.
//! - `YangPushEnrichmentStats` - Metrics for tracking the performance and
//!   behavior of the enrichment process.
use crate::inputs::EnrichmentHandle;
use crate::yang_push::{
    DeleteAllPayload, DeletePayload, EnrichmentOperation, UpsertPayload, Weight,
};
use chrono::Utc;
use netgauze_udp_notif_pkt::decoded::{UdpNotifPacketDecoded, UdpNotifPayload};
use netgauze_udp_notif_pkt::notification::{
    NotificationVariant, SubscriptionId, SubscriptionStartedModified, SubscriptionTerminated,
};
use netgauze_udp_notif_service::{OTL_UDP_NOTIF_MESSAGE_ID_KEY, OTL_UDP_NOTIF_PUBLISHER_ID_KEY};
use netgauze_yang_push::cache::storage::SubscriptionInfo;
use netgauze_yang_push::model::telemetry::{
    EventType, FilterSpec, Label, Manifest, NetworkOperatorMetadata, SessionProtocol,
    TelemetryMessage, TelemetryMessageMetadata, TelemetryMessageWrapper,
    YangPushSubscriptionMetadata,
};
use netgauze_yang_push::{
    ContentId, OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use serde_json::Value;
use shadow_rs::shadow;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use sysinfo::System;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

shadow!(build);

/// Cache for YangPush subscriptions metadata
pub type SubscriptionsCache = HashMap<SubscriptionId, YangPushSubscriptionMetadata>;

/// Weighted Label for Enrichment Cache
#[derive(Debug, Clone, PartialEq, Eq)]
struct WeightedLabel {
    label: Label,
    weight: Weight,
}

#[derive(Debug, Clone, Copy)]
pub enum YangPushEnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display)]
pub enum YangPushEnrichmentActorError {
    #[strum(to_string = "YangPushEnrichmentActor channel closed")]
    EnrichmentChannelClosed,
    #[strum(to_string = "error in YangPushEnrichmentActor receive channel")]
    YangPushReceiveError,
    #[strum(to_string = "received Yang-Push Notification without content")]
    NotificationWithoutContent,
    #[strum(to_string = "failed to serialize UDP-Notif payload")]
    PayloadSerializationError,
}

impl std::error::Error for YangPushEnrichmentActorError {}

#[derive(Debug, Clone)]
pub struct YangPushEnrichmentStats {
    pub received_messages: opentelemetry::metrics::Counter<u64>,
    pub received_enrichment_ops: opentelemetry::metrics::Counter<u64>,
    pub sent_messages: opentelemetry::metrics::Counter<u64>,
    pub send_error: opentelemetry::metrics::Counter<u64>,
    pub udpnotif_payload_decoding_error: opentelemetry::metrics::Counter<u64>,
    pub udpnotif_payload_processing_error: opentelemetry::metrics::Counter<u64>,
    pub peer_subscriptions: opentelemetry::metrics::Gauge<u64>,
    pub subscription_cache_miss: opentelemetry::metrics::Counter<u64>,
}

impl YangPushEnrichmentStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.received.messages")
            .with_description("Number of Yang-Push messages received for enrichment")
            .build();
        let received_enrichment_ops = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.received.enrichment.operations")
            .with_description("Number of enrichment updates received")
            .build();
        let sent_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.sent.messages")
            .with_description("Number of Telemetry Messages successfully sent upstream")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.send.error")
            .with_description("Number of upstream sending errors")
            .build();
        let udpnotif_payload_decoding_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.payload.decoding.error")
            .with_description("Number of errors decoding UDP-Notif payloads")
            .build();
        let udpnotif_payload_processing_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.notification.processing.error")
            .with_description("Number of errors processing Yang Push notifications")
            .build();
        let peer_subscriptions = meter
            .u64_gauge("netgauze.collector.yang_push.enrichment.peer.subscriptions")
            .with_description("Number of active subscriptions per peer")
            .build();
        let subscription_cache_miss = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.subscription.cache.miss")
            .with_description("Number of subscription cache misses")
            .build();
        Self {
            received_messages,
            received_enrichment_ops,
            sent_messages,
            send_error,
            udpnotif_payload_decoding_error,
            udpnotif_payload_processing_error,
            peer_subscriptions,
            subscription_cache_miss,
        }
    }

    /// Updates the gauge tracking the number of subscriptions per peer.
    pub fn update_peer_subscriptions_gauge(&self, peer: &SocketAddr, subscription_count: usize) {
        let peer_tags = [
            opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(peer.port().into()),
            ),
        ];
        self.peer_subscriptions
            .record(subscription_count as u64, &peer_tags);
    }
}

/// Fetches local system information into a Manifest object.
/// (host name, OS version, software version, build info, etc.)
fn fetch_sysinfo_manifest(name: Option<String>) -> Manifest {
    let mut sys = System::new_all();
    sys.refresh_all();

    Manifest::new(
        name.filter(|n| !n.is_empty()).or_else(|| {
            Some(format!(
                "{}@{}",
                build::PROJECT_NAME,
                System::host_name().unwrap_or_else(|| "unknown".to_string())
            ))
        }),
        Some("NetGauze".to_string()),
        Some(3746), // Swisscom AG (temp until NetGauze has its own PEN number)
        Some(format!("{} ({})", build::PKG_VERSION, build::SHORT_COMMIT)),
        Some(build::BUILD_RUST_CHANNEL.to_string()),
        System::os_version(),
        System::name(),
    )
}

/// Actor responsible for enriching Yang Push notifications.
/// Sends enriched TelemetryMessage objects.
struct YangPushEnrichmentActor {
    cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
    enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
    validated_rx:
        async_channel::Receiver<(Option<ContentId>, SubscriptionInfo, UdpNotifPacketDecoded)>,
    enriched_tx:
        async_channel::Sender<(Option<ContentId>, SubscriptionInfo, TelemetryMessageWrapper)>,
    labels: HashMap<IpAddr, HashMap<String, WeightedLabel>>,
    subscriptions: HashMap<SocketAddr, SubscriptionsCache>,
    manifest: Manifest,
    stats: YangPushEnrichmentStats,
}

impl YangPushEnrichmentActor {
    fn new(
        cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
        enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
        validated_rx: async_channel::Receiver<(
            Option<ContentId>,
            SubscriptionInfo,
            UdpNotifPacketDecoded,
        )>,
        enriched_tx: async_channel::Sender<(
            Option<ContentId>,
            SubscriptionInfo,
            TelemetryMessageWrapper,
        )>,
        stats: YangPushEnrichmentStats,
        writer_id: String,
    ) -> Self {
        Self {
            cmd_rx,
            validated_rx,
            enrichment_rx,
            enriched_tx,
            labels: HashMap::new(),
            subscriptions: HashMap::new(),
            manifest: fetch_sysinfo_manifest(Some(writer_id)),
            stats,
        }
    }

    /// Apply an enrichment operation (upsert or delete) to the labels cache.
    ///
    /// All operations use weight-based precedence: higher weights override
    /// lower weights, equal weights favor the incoming operation.
    ///
    /// - **Upsert**: Adds or replaces labels if incoming weight >= current
    ///   weight
    /// - **Delete**: Removes specific labels incoming weight >= current weight
    /// - **DeleteAll**: Removes all labels incoming weight >= current weight
    ///
    /// Empty IP cache entries are automatically cleaned up.
    pub fn apply_enrichment(&mut self, op: EnrichmentOperation) {
        debug!("Apply enrichment operation: {op}");

        match op {
            EnrichmentOperation::Upsert(UpsertPayload {
                ip,
                weight,
                labels: incoming_labels,
            }) => {
                // Early return if no labels are provided
                if incoming_labels.is_empty() {
                    debug!(
                        "Empty labels vector provided for upsert operation for ip={} - cache not modified",
                        ip
                    );
                    return;
                }

                let labels = self.labels.entry(ip).or_insert_with(|| {
                    debug!("Creating new label cache entry for ip={}", ip);
                    HashMap::new()
                });
                for incoming in incoming_labels {
                    let name = incoming.name().to_string();

                    if let Some(current) = labels.get(&name) {
                        if weight >= current.weight {
                            debug!(
                                "Replacing label '{}' for ip={}, weight {}->{}",
                                name, ip, current.weight, weight,
                            );

                            labels.insert(
                                name,
                                WeightedLabel {
                                    label: incoming,
                                    weight,
                                },
                            );
                        } else {
                            debug!(
                                "Ignoring lower weight label '{}' for ip={}, weight: {}<{}",
                                name, ip, weight, current.weight,
                            );
                        }
                    } else {
                        debug!(
                            "Adding new label '{}' for ip={}, weight={}",
                            name, ip, weight
                        );
                        labels.insert(
                            name,
                            WeightedLabel {
                                label: incoming,
                                weight,
                            },
                        );
                    }
                }
                debug!("Updated label cache for {}: {} labels", ip, labels.len());
            }
            EnrichmentOperation::Delete(DeletePayload {
                ip,
                weight,
                label_names,
            }) => {
                // Early return if no label names are provided
                if label_names.is_empty() {
                    debug!(
                        "Empty label_names vector provided for delete operation for ip={} - cache not modified",
                        ip
                    );
                    return;
                }
                if let Some(labels) = self.labels.get_mut(&ip) {
                    for name in label_names {
                        if let Some(current) = labels.get(&name) {
                            if weight >= current.weight {
                                debug!(
                                    "Removing label '{}' for ip={}, weight: {}>={}",
                                    name, ip, weight, current.weight
                                );
                                labels.remove(&name);
                            } else {
                                debug!(
                                    "Ignoring delete for label '{}' (lower weight) for ip={}, weight: {}<{}",
                                    name, ip, weight, current.weight
                                );
                            }
                        }
                        {
                            debug!(
                                "Label '{}' not found for ip={}, nothing to delete",
                                name, ip
                            );
                        }
                    }

                    // cleanup if all labels were removed for ip
                    if labels.is_empty() {
                        debug!("Label cache now empty for ip={}, cleaning up...", ip);
                        self.labels.remove(&ip);
                    }
                } else {
                    debug!("No cache entry for ip={}, nothing to delete", ip);
                }
            }
            EnrichmentOperation::DeleteAll(DeleteAllPayload { ip, weight }) => {
                debug!("DeleteAll received for ip={ip}, weight={weight}");

                if let Some(labels) = self.labels.get_mut(&ip) {
                    labels.retain(|_, wl| weight < wl.weight);

                    // cleanup if all labels were removed for ip
                    if labels.is_empty() {
                        debug!(
                            "Label cache now empty for ip={} after DeleteAll, cleaning up...",
                            ip
                        );
                        self.labels.remove(&ip);
                    }
                } else {
                    debug!(
                        "No cache entry for ip={}, nothing to delete (DeleteAll)",
                        ip
                    );
                }
            }
        }
    }

    /// Caches metadata from SubscriptionStarted and SubscriptionModified
    /// messages.
    fn cache_subscription(
        &mut self,
        peer: SocketAddr,
        sub: &SubscriptionStartedModified,
    ) -> Result<Option<YangPushSubscriptionMetadata>, YangPushEnrichmentActorError> {
        let stream = sub.target().stream().map(|f| f.to_string());

        let datastore = sub.target().datastore().map(|f| f.to_string());

        let xpath_filter: Option<String> = sub
            .target()
            .datastore_xpath_filter()
            .map(|f| f.to_string())
            .or_else(|| sub.target().stream_xpath_filter().map(|f| f.to_string()));

        let subtree_filter: Option<Value> = sub
            .target()
            .datastore_subtree_filter()
            .cloned()
            .or_else(|| sub.target().stream_subtree_filter().cloned());

        let filter_spec = FilterSpec::new(stream, datastore, xpath_filter, subtree_filter);

        let subscription_metadata = YangPushSubscriptionMetadata::new(
            Some(sub.id()),
            filter_spec,
            sub.stop_time().cloned(),
            sub.transport().cloned(),
            sub.encoding().cloned(),
            sub.purpose().map(|id| id.to_string()),
            sub.update_trigger().cloned().map(Into::into),
            sub.module_version().cloned().unwrap_or_default(),
            sub.yang_library_content_id().map(|id| id.to_string()),
        );

        // Insert the subscription metadata into the cache
        let peer_subscriptions = self.subscriptions.entry(peer).or_default();
        peer_subscriptions.insert(sub.id(), subscription_metadata.clone());

        // Update the gauge tracking per-peer subscriptions
        self.stats
            .update_peer_subscriptions_gauge(&peer, peer_subscriptions.len());

        trace!(
            "Yang Push Subscription Cache: {}",
            serde_json::to_string(&self.subscriptions).unwrap()
        );

        Ok(Some(subscription_metadata))
    }

    /// Handles SubscriptionTerminated messages by removing subscription
    /// metadata from the cache.
    fn delete_subscription(
        &mut self,
        peer: SocketAddr,
        sub: &SubscriptionTerminated,
    ) -> Result<Option<YangPushSubscriptionMetadata>, YangPushEnrichmentActorError> {
        // Get and delete subscription information from the cache
        let subscription_metadata = self
            .subscriptions
            .get_mut(&peer)
            .and_then(|subscriptions| subscriptions.remove(&sub.id()));

        // Increment counter if there was a cache miss
        if subscription_metadata.is_none() {
            let peer_tags = [
                opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                opentelemetry::KeyValue::new(
                    "network.peer.port",
                    opentelemetry::Value::I64(peer.port().into()),
                ),
                opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                    opentelemetry::Value::I64(sub.id().into()),
                ),
            ];
            self.stats.subscription_cache_miss.add(1, &peer_tags);
        }

        // Update the gauge tracking per-peer subscriptions
        if let Some(subscriptions) = self.subscriptions.get(&peer) {
            self.stats
                .update_peer_subscriptions_gauge(&peer, subscriptions.len());
        } else {
            self.stats.update_peer_subscriptions_gauge(&peer, 0);
        }

        debug!(
            "Yang Push Subscription Cache: {}",
            serde_json::to_string(&self.subscriptions).unwrap()
        );

        Ok(subscription_metadata)
    }

    /// Retrieves subscription metadata from the cache based on the peer address
    /// and subscription ID.
    fn get_subscription(
        &self,
        peer: SocketAddr,
        subscription_id: SubscriptionId,
    ) -> Result<Option<YangPushSubscriptionMetadata>, YangPushEnrichmentActorError> {
        // Get subscription information from the cache
        let subscription_metadata = self
            .subscriptions
            .get(&peer)
            .and_then(|subscriptions| subscriptions.get(&subscription_id))
            .cloned();

        // Increment counter if there was a cache miss
        if subscription_metadata.is_none() {
            let peer_tags = [
                opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                opentelemetry::KeyValue::new(
                    "network.peer.port",
                    opentelemetry::Value::I64(peer.port().into()),
                ),
                opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                    opentelemetry::Value::I64(subscription_id.into()),
                ),
            ];
            self.stats.subscription_cache_miss.add(1, &peer_tags);
        }

        Ok(subscription_metadata)
    }

    /// Processes Notification and returns the relevant TelemetryMessageMetadata
    fn process_notification(
        &mut self,
        content_id: Option<&ContentId>,
        subscription_info: &SubscriptionInfo,
        decoded_packet: &UdpNotifPacketDecoded,
    ) -> Result<Option<YangPushSubscriptionMetadata>, YangPushEnrichmentActorError> {
        let peer = subscription_info.peer();
        let message_id = decoded_packet.message_id();
        let publisher_id = decoded_packet.publisher_id();
        let cached_content_id = content_id.map(|cid| cid.to_string()).unwrap_or_default();
        let notification_type = decoded_packet
            .notification_type()
            .map(|nt| nt.to_string())
            .unwrap_or("UNKNOWN".to_string());

        let notification = match decoded_packet.payload() {
            UdpNotifPayload::NotificationEnvelope(envelope) => envelope.contents(),
            UdpNotifPayload::NotificationLegacy(notif) => notif.notification(),
        };
        match notification {
            Some(NotificationVariant::SubscriptionStarted(sub_started)) => {
                debug!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=sub_started.id(),
                    router_content_id=sub_started.yang_library_content_id(),
                    target=%sub_started.target(),
                    notification_type,
                    cached_content_id,
                    "Received Subscription Started Message",

                );
                self.cache_subscription(peer, sub_started)
            }
            Some(NotificationVariant::SubscriptionModified(sub_modified)) => {
                debug!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=sub_modified.id(),
                    router_content_id=sub_modified.yang_library_content_id(),
                    target=%sub_modified.target(),
                    notification_type,
                    cached_content_id,
                    "Received Subscription Modified Message",
                );
                self.cache_subscription(peer, sub_modified)
            }
            Some(NotificationVariant::SubscriptionTerminated(sub_terminated)) => {
                debug!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=sub_terminated.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    termination_reason=sub_terminated.reason(),
                    notification_type,
                    cached_content_id,
                    "Received Subscription Terminated Message",
                );
                self.delete_subscription(peer, sub_terminated)
            }
            Some(NotificationVariant::YangPushUpdate(push_update)) => {
                trace!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=push_update.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    notification_type,
                    cached_content_id,
                    "Received Yang Push Update Message",
                );
                self.get_subscription(peer, push_update.id())
            }
            Some(NotificationVariant::YangPushChangeUpdate(push_change_update)) => {
                trace!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=push_change_update.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    notification_type,
                    cached_content_id,
                    "Received Yang Push Change Update Message",
                );
                self.get_subscription(peer, push_change_update.id())
            }
            None => {
                warn!(
                 peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    notification_type,
                    cached_content_id,
                    "Received Notification Message without content",
                );
                Err(YangPushEnrichmentActorError::NotificationWithoutContent)
            }
        }
    }

    /// Processes UDP-Notif a decoded packet and produce a TelemetryMessage
    /// object.
    fn process_decoded_udp_notif_packet(
        &mut self,
        content_id: Option<&ContentId>,
        subscription_info: &SubscriptionInfo,
        decoded_packet: &UdpNotifPacketDecoded,
    ) -> Result<TelemetryMessageWrapper, YangPushEnrichmentActorError> {
        let peer = subscription_info.peer();
        let message_id = decoded_packet.message_id();
        let publisher_id = decoded_packet.publisher_id();
        let notification_type = decoded_packet
            .notification_type()
            .map(|nt| nt.to_string())
            .unwrap_or("UNKNOWN".to_string());

        let labels: Option<Vec<Label>> = self
            .labels
            .get(&peer.ip())
            .map(|l_map| l_map.values().cloned().map(|wl| wl.label).collect());

        // Match on the wrapper and process the notification content
        let node_export_timestamp = match decoded_packet.payload() {
            UdpNotifPayload::NotificationLegacy(legacy) => legacy.event_time(),
            UdpNotifPayload::NotificationEnvelope(envelope) => envelope.event_time(),
        };

        let subscription_metadata =
            self.process_notification(content_id, subscription_info, decoded_packet)?;

        let telemetry_message_metadata = TelemetryMessageMetadata::new(
            Some(node_export_timestamp),
            Utc::now(),
            EventType::Log,
            None,                      // we don't set sequence numbers for now
            SessionProtocol::YangPush, // only option at the moment
            peer.ip(),
            Some(peer.port()),
            None,
            None,
            subscription_metadata,
        );

        // Re-serialize the UDP-Notif payload into JSON
        let json_payload = serde_json::to_value(decoded_packet).map_err(|err| {
            error!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id=%content_id.map(|cid| cid.to_string()).unwrap_or_default(),
                notification_type,
                error=%err,
                "Failed to re-serialize UDP-Notif Payload (should never happen)"
            );
            YangPushEnrichmentActorError::PayloadSerializationError
        })?;

        // Populate metadata and payload in a new TelemetryMessage
        Ok(TelemetryMessageWrapper::new(TelemetryMessage::new(
            None,
            telemetry_message_metadata,
            Some(self.manifest.clone()),
            labels.map(NetworkOperatorMetadata::new),
            Some(json_payload),
        )))
    }

    /// Main loop for the actor: handling commands and incoming notification
    /// messages.
    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(YangPushEnrichmentActorCommand::Shutdown) => {
                            info!("Shutting down Yang Push enrichment actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            warn!("Yang Push enrichment actor terminated due to command channel closing");
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
                            Err(YangPushEnrichmentActorError::EnrichmentChannelClosed)?;
                        }
                    }                }
                msg = self.validated_rx.recv() => {
                    match msg {
                        Ok(msg) => {
                            let (content_id, subscription_info, pkt) = msg;
                            let peer = subscription_info.peer();
                            let message_id = pkt.message_id();
                            let publisher_id = pkt.publisher_id();
                            let peer_tags = [
                                opentelemetry::KeyValue::new(
                                    "network.peer.address",
                                    format!("{}", peer.ip()),
                                ),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                                opentelemetry::KeyValue::new(
                                    OTL_UDP_NOTIF_MESSAGE_ID_KEY,
                                    opentelemetry::Value::I64(message_id.into())
                                ),
                                opentelemetry::KeyValue::new(
                                    OTL_UDP_NOTIF_PUBLISHER_ID_KEY,
                                    opentelemetry::Value::I64(publisher_id.into()),
                                ),
                                opentelemetry::KeyValue::new(
                                    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                                    opentelemetry::Value::I64(subscription_info.id().into()),
                                ),
                                opentelemetry::KeyValue::new(
                                    OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
                                    format!("{}", subscription_info.target()),
                                ),
                                opentelemetry::KeyValue::new(
                                    OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
                                    subscription_info.content_id().to_string(),
                                ),
                                opentelemetry::KeyValue::new(
                                    OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY,
                                    content_id.as_ref().map(|cid| cid.to_string()).unwrap_or_default(),
                                )
                            ];
                            self.stats.received_messages.add(1, &peer_tags);

                            // Process the payload and send the enriched TelemetryMessage
                            match self.process_decoded_udp_notif_packet(content_id.as_ref(), &subscription_info, &pkt) {
                                Ok(telemetry_message) => {
                                    if let Err(err) = self.enriched_tx.send((content_id, subscription_info, telemetry_message)).await {
                                        error!("YangPushEnrichmentActor send error: {err}");
                                        self.stats.send_error.add(1, &peer_tags);
                                    } else {
                                        self.stats.sent_messages.add(1, &peer_tags);
                                    }
                                }
                                Err(err) => {
                                    warn!("Error processing payload: {err}");
                                    self.stats.udpnotif_payload_processing_error.add(1, &peer_tags);
                                }
                            }
                        }
                        Err(err) => {
                            error!("Shutting down YangPushEnrichmentActor due to recv error: {err}");
                            Err(YangPushEnrichmentActorError::YangPushReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum YangPushEnrichmentActorHandleError {
    #[strum(to_string = "failed to send to Yang-Push enrichment actor")]
    SendError,
}

impl std::error::Error for YangPushEnrichmentActorHandleError {}

/// Handle for interacting with the `YangPushEnrichmentActor`.
#[derive(Debug, Clone)]
pub struct YangPushEnrichmentActorHandle {
    cmd_send: mpsc::Sender<YangPushEnrichmentActorCommand>,
    enrichment_tx: async_channel::Sender<EnrichmentOperation>,
    enriched_rx:
        async_channel::Receiver<(Option<ContentId>, SubscriptionInfo, TelemetryMessageWrapper)>,
}

impl YangPushEnrichmentActorHandle {
    pub fn new(
        buffer_size: usize,
        validated_rx: async_channel::Receiver<(
            Option<ContentId>,
            SubscriptionInfo,
            UdpNotifPacketDecoded,
        )>,
        stats: either::Either<opentelemetry::metrics::Meter, YangPushEnrichmentStats>,
        writer_id: String,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enrichment_tx, enrichment_rx) = async_channel::bounded(buffer_size);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => YangPushEnrichmentStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = YangPushEnrichmentActor::new(
            cmd_recv,
            enrichment_rx,
            validated_rx,
            enriched_tx,
            stats,
            writer_id,
        );
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            enrichment_tx,
            enriched_rx,
        };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), YangPushEnrichmentActorHandleError> {
        self.cmd_send
            .send(YangPushEnrichmentActorCommand::Shutdown)
            .await
            .map_err(|_| YangPushEnrichmentActorHandleError::SendError)
    }

    pub fn subscribe(
        &self,
    ) -> async_channel::Receiver<(Option<ContentId>, SubscriptionInfo, TelemetryMessageWrapper)>
    {
        self.enriched_rx.clone()
    }
}

impl EnrichmentHandle<EnrichmentOperation> for YangPushEnrichmentActorHandle {
    /// Send an enrichment cache update to the actor.
    ///
    /// Updates are applied asynchronously and will affect subsequent
    /// Yang-Push enrichment operations. The operation can be either an
    /// upsert (add/update) or delete.
    fn update_enrichment(
        &self,
        op: EnrichmentOperation,
    ) -> futures::future::BoxFuture<'_, Result<(), anyhow::Error>> {
        Box::pin(async move {
            self.enrichment_tx
                .send(op)
                .await
                .map_err(anyhow::Error::from)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use netgauze_udp_notif_pkt::decoded::UdpNotifPacketDecoded;
    use netgauze_udp_notif_pkt::notification::{
        CentiSeconds, Encoding, Target, Transport, UpdateTrigger,
    };
    use netgauze_udp_notif_pkt::raw::{MediaType, UdpNotifPacket};
    use netgauze_yang_push::model::telemetry::{Label, LabelValue};
    use serde_json::json;
    use std::collections::HashMap;
    use std::net::SocketAddr;

    fn create_subscription_started_modified(
        id: SubscriptionId,
        purpose: String,
    ) -> SubscriptionStartedModified {
        SubscriptionStartedModified::new(
            id,
            Target::new(
                None,
                None,
                None,
                None,
                Some("example-datastore-name".to_string()),
                None,
                Some("/example/datastore/xpath".to_string()),
            ),
            None,
            Some(Transport::UDPNotif),
            Some(Encoding::Json),
            Some(purpose),
            Some(UpdateTrigger::Periodic {
                period: Some(CentiSeconds::new(100)),
                anchor_time: None,
            }),
            None,
            None,
            json!({}),
        )
    }

    fn create_subscription_terminated(id: SubscriptionId) -> SubscriptionTerminated {
        SubscriptionTerminated::new(id, "some-termination-reason".to_string(), json!({}))
    }

    fn create_actor() -> YangPushEnrichmentActor {
        YangPushEnrichmentActor {
            cmd_rx: mpsc::channel(10).1,
            enrichment_rx: async_channel::bounded(10).1,
            validated_rx: async_channel::bounded(10).1,
            enriched_tx: async_channel::bounded(10).0,
            labels: HashMap::new(),
            subscriptions: HashMap::new(),
            manifest: fetch_sysinfo_manifest(None),
            stats: YangPushEnrichmentStats::new(opentelemetry::global::meter("my-meter")),
        }
    }

    #[test]
    fn test_cache_and_get_subscription() {
        let mut actor = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Create a SubscriptionStartedModified message and cache it
        let subscription_started =
            create_subscription_started_modified(1, "example-purpose".to_string());
        let result = actor.cache_subscription(peer, &subscription_started);
        assert!(result.is_ok());

        // Check get_subscription method
        let get_result = actor.get_subscription(peer, 1);
        assert!(get_result.is_ok());
        assert_eq!(result.clone().unwrap(), get_result.unwrap());

        // Check if the subscription is cached correctly
        let peer_subscription = match result {
            Ok(Some(metadata)) => metadata,
            _ => panic!("Expected Some(YangPushSubscriptionMetadata), got: {result:?}"),
        };

        assert_eq!(peer_subscription.id(), Some(1));
        assert_eq!(
            peer_subscription.filter_spec().datastore(),
            Some("example-datastore-name")
        );
        assert_eq!(
            peer_subscription.filter_spec().xpath_filter(),
            Some("/example/datastore/xpath")
        );
        assert_eq!(
            peer_subscription.transport().cloned(),
            Some(Transport::UDPNotif)
        );
        assert_eq!(peer_subscription.encoding().cloned(), Some(Encoding::Json));
        assert_eq!(peer_subscription.purpose(), Some("example-purpose"));
        assert_eq!(
            peer_subscription.update_trigger().cloned(),
            Some(
                UpdateTrigger::Periodic {
                    period: Some(CentiSeconds::new(100)),
                    anchor_time: None
                }
                .into()
            )
        );
        assert_eq!(
            peer_subscription.module(),
            Vec::new() // default
        );
        assert_eq!(peer_subscription.yang_library_content_id(), None);

        // Modify the subscription and check if it updates the cache
        let subscription_modified =
            create_subscription_started_modified(1, "updated-purpose".to_string());
        let peer_subscription = actor
            .cache_subscription(peer, &subscription_modified)
            .unwrap();
        assert_eq!(
            peer_subscription.unwrap().purpose(),
            Some("updated-purpose")
        );
    }

    #[test]
    fn test_delete_subscription() {
        let mut actor = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Create a SubscriptionStartedModified message and cache it
        let subscription_started = create_subscription_started_modified(1, "".to_string());
        actor
            .cache_subscription(peer, &subscription_started)
            .unwrap();

        // Ensure the subscription is cached before deletion
        let peer_subscriptions = actor.subscriptions.get(&peer);
        assert!(peer_subscriptions.is_some() && peer_subscriptions.unwrap().contains_key(&1));

        let terminated = create_subscription_terminated(1);
        let result = actor.delete_subscription(peer, &terminated);
        assert!(result.is_ok());

        let peer_subscriptions = actor.subscriptions.get(&peer);
        assert!(peer_subscriptions.is_none() || !peer_subscriptions.unwrap().contains_key(&1));
    }

    #[test]
    fn test_get_subscription_cache_miss() {
        let mut actor = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let subscription_id_1 = create_subscription_started_modified(1, "".to_string());
        let subscription_id_23 = create_subscription_started_modified(23, "".to_string());
        actor.cache_subscription(peer, &subscription_id_1).unwrap();
        actor.cache_subscription(peer, &subscription_id_23).unwrap();

        assert_eq!(actor.subscriptions.len(), 1);
        assert!(actor.subscriptions.contains_key(&peer));
        assert!(actor.subscriptions[&peer].contains_key(&1));
        assert!(actor.subscriptions[&peer].contains_key(&23));
        assert_eq!(actor.subscriptions[&peer].len(), 2);

        let get_result = actor.get_subscription(peer, 12);
        assert!(get_result.is_ok());

        let peer_subscription = get_result.unwrap();
        assert_eq!(peer_subscription, None);
    }

    #[test]
    fn test_process_payload_envelope_without_content() {
        let mut actor = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Create a UdpNotifPayload without content
        let payload = json!({
                    "ietf-yp-notification:envelope": {
                        "event-time": "2025-03-04T07:11:33.252679191+00:00",
                        "hostname": "some-router",
                        "sequence-number": 5,
                      }
        })
        .to_string()
        .into_bytes();

        let packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1,
            1,
            HashMap::new(),
            Bytes::from(payload),
        );

        let subscription_info = SubscriptionInfo::new(
            peer,
            1,
            "test-content-id".to_string(),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-interfaces".to_string()),
            ),
            vec!["ietf-interfaces".to_string()],
        );
        // Attempt to decode the packet (should succeed)
        let decoded: UdpNotifPacketDecoded = (&packet).try_into().unwrap();

        let result = actor.process_decoded_udp_notif_packet(None, &subscription_info, &decoded);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            YangPushEnrichmentActorError::NotificationWithoutContent
        );
    }

    #[test]
    fn test_apply_enrichment_upsert_and_delete() {
        let mut actor = create_actor();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();

        // Upsert two labels with different weights
        let label1 = Label::new(
            "site".to_string(),
            LabelValue::StringValue {
                string_value: "Zurich".to_string(),
            },
        );
        let label2 = Label::new(
            "role".to_string(),
            LabelValue::StringValue {
                string_value: "core".to_string(),
            },
        );
        actor.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
            ip,
            weight: 10,
            labels: vec![label1.clone(), label2.clone()],
        }));

        // Upsert label1 again with higher weight (should replace)
        let label1_updated = Label::new(
            "site".to_string(),
            LabelValue::StringValue {
                string_value: "Bern".to_string(),
            },
        );
        actor.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
            ip,
            weight: 20,
            labels: vec![label1_updated.clone()],
        }));

        // Delete label2 with sufficient weight
        actor.apply_enrichment(EnrichmentOperation::Delete(DeletePayload {
            ip,
            weight: 15,
            label_names: vec!["role".to_string()],
        }));

        // Expected: only label1 ("site": "Bern", weight 20) remains
        let mut expected = HashMap::new();
        expected.insert(
            "site".to_string(),
            WeightedLabel {
                label: label1_updated,
                weight: 20,
            },
        );
        assert_eq!(actor.labels.get(&ip).cloned().unwrap(), expected);
    }

    #[test]
    fn test_apply_enrichment_delete_all() {
        let mut actor = create_actor();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();

        // Upsert two labels
        let label1 = Label::new(
            "env".to_string(),
            LabelValue::StringValue {
                string_value: "PROD".to_string(),
            },
        );
        let label2 = Label::new(
            "rack".to_string(),
            LabelValue::StringValue {
                string_value: "A1".to_string(),
            },
        );
        actor.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
            ip,
            weight: 5,
            labels: vec![label1.clone(), label2.clone()],
        }));

        // Check that labels were added to the cache
        let mut expected = HashMap::new();
        expected.insert(
            "env".to_string(),
            WeightedLabel {
                label: label1,
                weight: 5,
            },
        );
        expected.insert(
            "rack".to_string(),
            WeightedLabel {
                label: label2,
                weight: 5,
            },
        );
        assert_eq!(actor.labels.get(&ip).cloned().unwrap(), expected);

        // DeleteAll with higher weight (should remove all)
        actor.apply_enrichment(EnrichmentOperation::DeleteAll(DeleteAllPayload {
            ip,
            weight: 10,
        }));

        // Expected: no labels for ip
        assert_eq!(actor.labels.get(&ip), None);
    }

    #[test]
    fn test_apply_enrichment_weight_precedence() {
        let mut actor = create_actor();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();

        // Upsert label with weight 10
        let label = Label::new(
            "region".to_string(),
            LabelValue::StringValue {
                string_value: "Switzerland".to_string(),
            },
        );
        actor.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
            ip,
            weight: 10,
            labels: vec![label.clone()],
        }));

        // Try to delete with lower weight (should not delete)
        actor.apply_enrichment(EnrichmentOperation::Delete(DeletePayload {
            ip,
            weight: 5,
            label_names: vec!["region".to_string()],
        }));

        // Expected: label still present
        let mut expected = HashMap::new();
        expected.insert("region".to_string(), WeightedLabel { label, weight: 10 });
        assert_eq!(actor.labels.get(&ip).cloned().unwrap(), expected);
    }

    #[test]
    fn test_apply_enrichment_empty_upsert_and_delete() {
        let mut actor = create_actor();
        let ip: IpAddr = "192.0.2.55".parse().unwrap();

        // Upsert with empty labels (should not modify cache)
        actor.apply_enrichment(EnrichmentOperation::Upsert(UpsertPayload {
            ip,
            weight: 1,
            labels: vec![],
        }));

        // Delete with empty label_names (should not modify cache)
        actor.apply_enrichment(EnrichmentOperation::Delete(DeletePayload {
            ip,
            weight: 1,
            label_names: vec![],
        }));

        // Expected: no labels for ip
        assert_eq!(actor.labels.get(&ip), None);
    }
}
