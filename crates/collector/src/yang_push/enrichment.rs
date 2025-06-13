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
use crate::yang_push::telemetry::{
    FilterSpec, Label, LabelValue, Manifest, NetworkOperatorMetadata, SessionProtocol,
    TelemetryMessage, TelemetryMessageMetadata, TelemetryMessageWrapper,
    YangPushSubscriptionMetadata,
};
use netgauze_udp_notif_pkt::{
    yang::notification::{
        NotificationVariant, SubscriptionId, SubscriptionStartedModified, SubscriptionTerminated,
    },
    UdpNotifPacket, UdpNotifPacketDecoded, UdpNotifPayload,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use chrono::Utc;
use shadow_rs::shadow;
use sysinfo::System;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

shadow!(build);

/// Cache for YangPush subscriptions metadata
pub type SubscriptionsCache = HashMap<SubscriptionId, YangPushSubscriptionMetadata>;

#[derive(Debug, Clone, Copy)]
pub enum YangPushEnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YangPushEnrichmentActorError {
    EnrichmentChannelClosed,
    YangPushReceiveError,
    NotificationWithoutContent,
    PayloadSerializationError,
}

impl std::fmt::Display for YangPushEnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::YangPushReceiveError => write!(f, "error in flow receive channel"),
            Self::NotificationWithoutContent => {
                write!(f, "Received Yang Push Notification without content")
            }
            Self::PayloadSerializationError => {
                write!(f, "failed to serialize UDP-Notif Payload")
            }
        }
    }
}

impl std::error::Error for YangPushEnrichmentActorError {}

#[derive(Debug, Clone)]
pub struct YangPushEnrichmentStats {
    pub received_messages: opentelemetry::metrics::Counter<u64>,
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
fn fetch_sysinfo_manifest() -> Manifest {
    let mut sys = System::new_all();
    sys.refresh_all();

    Manifest::new(
        Some(format!(
            "{}@{}",
            build::PROJECT_NAME,
            System::host_name().unwrap_or_else(|| "unknown".to_string())
        )),
        Some("NetGauze".to_string()),
        None,
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
    udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
    enriched_tx: async_channel::Sender<TelemetryMessageWrapper>,
    labels: HashMap<IpAddr, (u32, HashMap<String, String>)>,
    default_labels: (u32, HashMap<String, String>),
    subscriptions: HashMap<SocketAddr, SubscriptionsCache>,
    manifest: Manifest,
    stats: YangPushEnrichmentStats,
}

impl YangPushEnrichmentActor {
    fn new(
        cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        enriched_tx: async_channel::Sender<TelemetryMessageWrapper>,
        stats: YangPushEnrichmentStats,
    ) -> Self {
        let default_labels = (
            0,
            HashMap::from([
                ("pkey".to_string(), "unknown".to_string()),
                ("nkey".to_string(), "unknown".to_string()),
            ]),
        );
        Self {
            cmd_rx,
            udp_notif_rx,
            enriched_tx,
            labels: HashMap::new(),
            default_labels,
            subscriptions: HashMap::new(),
            manifest: fetch_sysinfo_manifest(),
            stats,
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

        debug!(
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
        subscription_id: &SubscriptionId,
    ) -> Result<Option<YangPushSubscriptionMetadata>, YangPushEnrichmentActorError> {
        // Get subscription information from the cache
        let subscription_metadata = self
            .subscriptions
            .get(&peer)
            .and_then(|subscriptions| subscriptions.get(subscription_id))
            .cloned();

        // Increment counter if there was a cache miss
        if subscription_metadata.is_none() {
            let peer_tags = [
                opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                opentelemetry::KeyValue::new(
                    "network.peer.port",
                    opentelemetry::Value::I64(peer.port().into()),
                ),
            ];
            self.stats.subscription_cache_miss.add(1, &peer_tags);
        }

        Ok(subscription_metadata)
    }

    /// Processes Notification and returns the relevant TelemetryMessageMetadata
    fn process_notification(
        &mut self,
        peer: SocketAddr,
        notification: Option<&NotificationVariant>,
    ) -> Result<Option<YangPushSubscriptionMetadata>, YangPushEnrichmentActorError> {
        match notification {
            Some(NotificationVariant::SubscriptionStarted(sub_started)) => {
                debug!(
                    "Received Subscription Started Message (peer: {}, id={})",
                    peer,
                    sub_started.id()
                );
                self.cache_subscription(peer, sub_started)
            }
            Some(NotificationVariant::SubscriptionModified(sub_modified)) => {
                debug!(
                    "Received Subscription Modified Message (peer: {}, id={})",
                    peer,
                    sub_modified.id()
                );
                self.cache_subscription(peer, sub_modified)
            }
            Some(NotificationVariant::SubscriptionTerminated(sub_terminated)) => {
                debug!(
                    "Received Subscription Terminated Message (peer: {}, id={})",
                    peer,
                    sub_terminated.id()
                );
                self.delete_subscription(peer, sub_terminated)
            }
            Some(NotificationVariant::YangPushUpdate(push_update)) => {
                debug!(
                    "Received Yang Push Update Message (peer: {}, id={})",
                    peer,
                    push_update.id()
                );
                self.get_subscription(peer, &push_update.id())
            }
            Some(NotificationVariant::YangPushChangeUpdate(push_change_update)) => {
                debug!(
                    "Received Yang Push Change Update Message (peer: {}, id={})",
                    peer,
                    push_change_update.id()
                );
                self.get_subscription(peer, &push_change_update.id())
            }
            None => {
                warn!(
                    "Received Notification Message (peer: {}) without content",
                    peer
                );
                Err(YangPushEnrichmentActorError::NotificationWithoutContent)
            }
        }
    }

    /// Processes UDP-Notif Payload and produces a TelemetryMessage object.
    fn process_payload(
        &mut self,
        peer: SocketAddr,
        payload: &UdpNotifPayload,
    ) -> Result<TelemetryMessageWrapper, YangPushEnrichmentActorError> {
        // Get sonata labels from the cache
        let (_, labels) = self.labels.get(&peer.ip()).unwrap_or(&self.default_labels);
        let labels: Vec<Label> = labels
            .iter()
            .map(|(key, value)| {
                Label::new(
                    key.clone(),
                    Some(LabelValue::StringValue {
                        string_value: value.clone(),
                    }),
                )
            })
            .collect();

        // Match on the wrapper and process the notification content
        let subscription_metadata = match payload {
            UdpNotifPayload::NotificationLegacy(legacy) => {
                self.process_notification(peer, legacy.notification())?
            }
            UdpNotifPayload::NotificationEnvelope(envelope) => {
                self.process_notification(peer, envelope.contents())?
            }
        };

        let telemetry_message_metadata = TelemetryMessageMetadata::new(
            None,
            Utc::now(),
            SessionProtocol::YangPush, // only option at the moment
            peer.ip(),
            Some(peer.port()),
            None,
            None,
            subscription_metadata,
        );

        // Re-serialize the UDP-Notif payload into JSON
        let json_payload = serde_json::to_value(payload).map_err(|err| {
            error!("Failed to re-serialize UDP-Notif Payload (should never happen): {err}");
            YangPushEnrichmentActorError::PayloadSerializationError
        })?;

        // Populate metadata and payload in a new TelemetryMessage
        Ok(TelemetryMessageWrapper::new(TelemetryMessage::new(
            None,
            telemetry_message_metadata,
            Some(self.manifest.clone()),
            NetworkOperatorMetadata::new(labels),
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
                msg = self.udp_notif_rx.recv() => {
                    match msg {
                        Ok(arc_tuple) => {
                            let (peer, pkt) = arc_tuple.as_ref();
                            let peer_tags = [
                                opentelemetry::KeyValue::new(
                                    "network.peer.address",
                                    format!("{}", peer.ip()),
                                ),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                            ];
                            self.stats.received_messages.add(1, &peer_tags);

                            // Decode the UdpNotifPacket into UdpNotifPacketDecoded
                            let pkt_decoded: UdpNotifPacketDecoded = match pkt.try_into() {
                              Ok(decoded) => decoded,
                              Err(err) => {
                                  warn!("Failed to decode Udp-Notif Payload: {err}");
                                  self.stats.udpnotif_payload_decoding_error.add(1, &peer_tags);
                                  continue;
                              }
                            };

                            // Process the payload and send the enriched TelemetryMessage
                            match self.process_payload(*peer, pkt_decoded.payload()) {
                                Ok(telemetry_message) => {
                                    if let Err(err) = self.enriched_tx.send(telemetry_message).await {
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
                            error!("Shutting down due to FlowEnrichment recv error: {err}");
                            Err(YangPushEnrichmentActorError::YangPushReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum YangPushEnrichmentActorHandleError {
    SendError,
}
impl std::fmt::Display for YangPushEnrichmentActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YangPushEnrichmentActorHandleError::SendError => {
                write!(f, "Failed to send yang-push enrichment actor")
            }
        }
    }
}

impl std::error::Error for YangPushEnrichmentActorHandleError {}

/// Handle for interacting with the `YangPushEnrichmentActor`.
#[derive(Debug, Clone)]
pub struct YangPushEnrichmentActorHandle {
    cmd_send: mpsc::Sender<YangPushEnrichmentActorCommand>,
    enriched_rx: async_channel::Receiver<TelemetryMessageWrapper>,
}

impl YangPushEnrichmentActorHandle {
    pub fn new(
        buffer_size: usize,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        stats: either::Either<opentelemetry::metrics::Meter, YangPushEnrichmentStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => YangPushEnrichmentStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = YangPushEnrichmentActor::new(cmd_recv, udp_notif_rx, enriched_tx, stats);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
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

    pub fn subscribe(&self) -> async_channel::Receiver<TelemetryMessageWrapper> {
        self.enriched_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MediaType;
    use bytes::Bytes;
    use netgauze_udp_notif_pkt::yang::notification::{
        CentiSeconds, Encoding, Target, Transport, UpdateTrigger,
    };
    use serde_json::json;
    use std::{collections::HashMap, net::SocketAddr};

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
            udp_notif_rx: async_channel::bounded(10).1,
            enriched_tx: async_channel::bounded(10).0,
            labels: HashMap::new(),
            default_labels: (0, HashMap::new()),
            subscriptions: HashMap::new(),
            manifest: fetch_sysinfo_manifest(),
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
        let get_result = actor.get_subscription(peer, &1);
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
            peer_subscription.module_version(),
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

        let get_result = actor.get_subscription(peer, &12);
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

        // Attempt to decode the packet (should succeed)
        let decoded: UdpNotifPacketDecoded = (&packet).try_into().unwrap();

        let result = actor.process_payload(peer, decoded.payload());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            YangPushEnrichmentActorError::NotificationWithoutContent
        );
    }
}
