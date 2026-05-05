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
use netgauze_udp_notif_service::OTL_UDP_NOTIF_PUBLISHER_ID_KEY;
use netgauze_yang_push::cache::storage::SubscriptionInfo;
use netgauze_yang_push::model::telemetry::{
    EventType, Label, Manifest, NetworkOperatorMetadata, SessionProtocol, TelemetryMessage,
    TelemetryMessageMetadata, TelemetryMessageWrapper, YangPushSubscriptionMetadata,
};
use netgauze_yang_push::{
    ContentId, OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

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
        manifest: Manifest,
        stats: YangPushEnrichmentStats,
    ) -> Self {
        Self {
            cmd_rx,
            validated_rx,
            enrichment_rx,
            enriched_tx,
            labels: HashMap::new(),
            manifest,
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

    /// Processes UDP-Notif a decoded packet and produce a TelemetryMessage
    /// object.
    fn process_decoded_udp_notif_packet(
        &mut self,
        content_id: Option<&ContentId>,
        subscription_info: &SubscriptionInfo,
        decoded_packet: &UdpNotifPacketDecoded,
    ) -> Result<TelemetryMessageWrapper, YangPushEnrichmentActorError> {
        if decoded_packet.notification_type().is_none() {
            return Err(YangPushEnrichmentActorError::NotificationWithoutContent);
        }
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

        let subscription_metadata = if !subscription_info.is_empty() {
            Some(YangPushSubscriptionMetadata::from(
                subscription_info.clone(),
            ))
        } else {
            None
        };

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
        let json_payload = serde_json::to_value(decoded_packet.payload()).map_err(|err| {
            error!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id=content_id.map_or("", |v| v),
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
                                    content_id.as_ref().map(|cid| cid.to_string()).unwrap_or_default()
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
        manifest: Manifest,
        stats: either::Either<opentelemetry::metrics::Meter, YangPushEnrichmentStats>,
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
            manifest,
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
    use chrono::TimeZone;
    use netgauze_netconf_proto::yang_push::identities::{Encoding, Transport};
    use netgauze_netconf_proto::yang_push::subscription::YangPushModuleVersion;
    use netgauze_netconf_proto::yang_push::types::SubscriptionId;
    use netgauze_netconf_proto::yanglib::DatastoreName;
    use netgauze_udp_notif_pkt::decoded::UdpNotifPacketDecoded;
    use netgauze_udp_notif_pkt::notification::Target;
    use netgauze_udp_notif_pkt::raw::{MediaType, UdpNotifPacket};
    use netgauze_yang_push::model::telemetry::{Label, LabelValue};
    use opentelemetry::global;
    use serde_json::json;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn test_manifest() -> Manifest {
        Manifest::new(
            Some("test-writer".into()),
            Some("NetGauze".into()),
            Some(3746),
            Some("0.11.0 (f5b7083e)".into()),
            Some("debug".into()),
            Some("26.4.1".into()),
            Some("Darwin".into()),
        )
    }

    #[allow(clippy::type_complexity)]
    fn create_actor_handle() -> (
        async_channel::Sender<(Option<ContentId>, SubscriptionInfo, UdpNotifPacketDecoded)>,
        Manifest,
        JoinHandle<anyhow::Result<String>>,
        YangPushEnrichmentActorHandle,
    ) {
        let test_manifest = test_manifest();
        let (receiver_tx, receiver_rx) = async_channel::bounded(10);
        let (join_handle, actor_handle) = YangPushEnrichmentActorHandle::new(
            100,
            receiver_rx,
            test_manifest.clone(),
            either::Left(global::meter_provider().meter("test")),
        );
        (receiver_tx, test_manifest, join_handle, actor_handle)
    }

    fn create_actor() -> YangPushEnrichmentActor {
        let manifest = test_manifest();
        YangPushEnrichmentActor {
            cmd_rx: mpsc::channel(10).1,
            enrichment_rx: async_channel::bounded(10).1,
            validated_rx: async_channel::bounded(10).1,
            enriched_tx: async_channel::bounded(10).0,
            labels: HashMap::new(),
            manifest,
            stats: YangPushEnrichmentStats::new(opentelemetry::global::meter("my-meter")),
        }
    }

    fn create_subscription_started(
        peer: SocketAddr,
        id: SubscriptionId,
    ) -> (SubscriptionInfo, serde_json::Value, UdpNotifPacketDecoded) {
        let payload = json!({
            "ietf-yp-notification:envelope": {
                "contents": {
                    "ietf-subscribed-notifications:subscription-started": {
                        "encoding": "ietf-subscribed-notifications:encode-json",
                        "id": id,
                        "ietf-yang-push-revision:module-version": [
                            { "name": "openconfig-interfaces", "revision": "2025-06-10" }
                        ],
                        "ietf-yang-push:datastore": "ietf-datastores:operational",
                        "ietf-yang-push:datastore-xpath-filter": "openconfig-interfaces:interfaces",
                        "ietf-yang-push:on-change": { "sync-on-start": true },
                    }
                },
                "event-time": "2025-04-17T15:20:14Z",
                "another-time": "2025-01-01T15:20:14Z",
                "hostname": "ipf-zbl1327-r-daisy-91",
                "sequence-number": 0
            }
        });

        let packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1234,
            5678,
            HashMap::new(),
            Bytes::from(serde_json::to_vec(&payload).unwrap()),
        );

        let decoded: UdpNotifPacketDecoded = (&packet).try_into().unwrap();
        let subscription_info = SubscriptionInfo::new(
            peer,
            id,
            Target::new_datastore(
                DatastoreName::Operational.to_string(),
                either::Right("openconfig-interfaces:interfaces".to_string()),
            ),
            None,
            Some(Transport::UDPNotif),
            Some(Encoding::Json),
            None,
            Box::new([YangPushModuleVersion::new(
                "openconfig-interface".into(),
                Some("2025-06-10".into()),
                None,
            )]),
            "some-content-id".into(),
        );
        (subscription_info, payload, decoded)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_process_payload_empty_subscription() {
        // Set up the enrichment actor and input test data
        let (msgs_tx, test_manifest, join_handle, actor_handle) = create_actor_handle();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let (_subscription_info, json_payload, decoded) = create_subscription_started(peer, 1);
        let empty_subscription_info = SubscriptionInfo::new_empty(peer, 1);

        msgs_tx
            .send((
                Some(empty_subscription_info.content_id().clone()),
                empty_subscription_info.clone(),
                decoded.clone(),
            ))
            .await
            .expect("Failed to send message to the actor");
        tokio::task::yield_now().await;
        let (received_content_id, received_subscription_info, received_enriched) = actor_handle
            .enriched_rx
            .recv()
            .await
            .expect("Failed to receive message");

        let expected_enriched = TelemetryMessageWrapper::new(TelemetryMessage::new(
            None,
            TelemetryMessageMetadata::new(
                Some(Utc.with_ymd_and_hms(2025, 4, 17, 15, 20, 14).unwrap()),
                // copy the collection timestamp from the received message since it's the current
                // system time
                received_enriched
                    .message()
                    .telemetry_message_metadata()
                    .collection_timestamp(),
                EventType::Log,
                None,
                SessionProtocol::YangPush,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                Some(12345),
                None,
                None,
                None,
            ),
            Some(test_manifest.clone()),
            None,
            Some(json_payload),
        ));
        assert_eq!(
            received_content_id.as_ref(),
            Some(empty_subscription_info.content_id())
        );
        assert_eq!(received_subscription_info, empty_subscription_info);
        assert_eq!(received_enriched, expected_enriched);

        // shutdown the actor
        tokio::time::timeout(Duration::from_millis(100), actor_handle.shutdown())
            .await
            .expect("Failed to shutdown the actor")
            .expect("Actor was not shutdown cleanly");
        join_handle.abort();
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_process_payload_envelope() {
        // Set up the enrichment actor and input test data
        let (msgs_tx, test_manifest, join_handle, actor_handle) = create_actor_handle();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let (subscription_info, json_payload, decoded) = create_subscription_started(peer, 1);

        msgs_tx
            .send((
                Some(subscription_info.content_id().clone()),
                subscription_info.clone(),
                decoded.clone(),
            ))
            .await
            .expect("Failed to send message to the actor");
        tokio::task::yield_now().await;
        let (received_content_id, received_subscription_info, received_enriched) = actor_handle
            .enriched_rx
            .recv()
            .await
            .expect("Failed to receive message");

        let expected_metadata = YangPushSubscriptionMetadata::from(subscription_info.clone());
        let expected_enriched = TelemetryMessageWrapper::new(TelemetryMessage::new(
            None,
            TelemetryMessageMetadata::new(
                Some(Utc.with_ymd_and_hms(2025, 4, 17, 15, 20, 14).unwrap()),
                // copy the collection timestamp from the received message since it's the current
                // system time
                received_enriched
                    .message()
                    .telemetry_message_metadata()
                    .collection_timestamp(),
                EventType::Log,
                None,
                SessionProtocol::YangPush,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                Some(12345),
                None,
                None,
                Some(expected_metadata),
            ),
            Some(test_manifest.clone()),
            None,
            Some(json_payload),
        ));
        assert_eq!(
            received_content_id.as_ref(),
            Some(subscription_info.content_id())
        );
        assert_eq!(received_subscription_info, subscription_info);
        assert_eq!(received_enriched, expected_enriched);

        // shutdown the actor
        tokio::time::timeout(Duration::from_millis(100), actor_handle.shutdown())
            .await
            .expect("Failed to shutdown the actor")
            .expect("Actor was not shutdown cleanly");
        join_handle.abort();
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

        let subscription_info = SubscriptionInfo::new_empty(peer, 1);
        // Attempt to decode the packet (should succeed)
        let decoded: UdpNotifPacketDecoded = (&packet).try_into().unwrap();

        let result = actor.process_decoded_udp_notif_packet(None, &subscription_info, &decoded);

        assert_eq!(
            result,
            Err(YangPushEnrichmentActorError::NotificationWithoutContent)
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
