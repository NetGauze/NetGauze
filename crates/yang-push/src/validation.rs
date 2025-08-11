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

use anyhow;
use async_channel;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, trace, warn};
use yang3::{
    context::{Context, ContextFlags},
    data::{DataFormat, DataOperation, DataTree},
};

use netgauze_udp_notif_pkt::UdpNotifPacket;

use crate::{
    model::{
        notification::SubscriptionId,
        udp_notif::{UdpNotifPacketDecoded, UdpNotifPayload},
    },
    validation::UdpNotifPayload::NotificationEnvelope,
};

/// Cache for YangPush subscriptions
type SubscriptionIdx = (SocketAddr, SubscriptionId);
type SubscriptionCache = HashMap<SubscriptionIdx, SubscriptionData>;

#[derive(Debug, Clone)]
struct SubscriptionData {
    yang_lib: String,
    search_dir: String,
    context: Arc<Context>,
}

impl SubscriptionData {
    fn new(yang_lib: String, search_dir: String, context: Arc<Context>) -> Self {
        Self {
            yang_lib,
            search_dir,
            context,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ValidationActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationActorError {
    YangPushReceiveError,
    NotificationWithoutContent,
    PayloadSerializationError,
    PayloadValidationError,
}

impl std::fmt::Display for ValidationActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::YangPushReceiveError => write!(f, "error in flow receive channel"),
            Self::NotificationWithoutContent => {
                write!(f, "Received Yang Push Notification without content")
            }
            Self::PayloadSerializationError => {
                write!(f, "failed to serialize UDP-Notif payload")
            }
            Self::PayloadValidationError => {
                write!(f, "failed to validate UDP-Notif payload")
            }
        }
    }
}

impl std::error::Error for ValidationActorError {}

#[derive(Debug, Clone)]
pub struct ValidationStats {
    pub received_messages: opentelemetry::metrics::Counter<u64>,
    pub sent_messages: opentelemetry::metrics::Counter<u64>,
    pub send_error: opentelemetry::metrics::Counter<u64>,
    pub udpnotif_payload_decoding_error: opentelemetry::metrics::Counter<u64>,
    pub udpnotif_payload_processing_error: opentelemetry::metrics::Counter<u64>,
    pub schemas_cached: opentelemetry::metrics::Gauge<u64>,
    pub peer_subscriptions: opentelemetry::metrics::Gauge<u64>,
    pub subscription_cache_miss: opentelemetry::metrics::Counter<u64>,
}

impl ValidationStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.yang_push.validation.received.messages")
            .with_description("Number of Yang Push messages received for validation")
            .build();
        let sent_messages = meter
            .u64_counter("netgauze.collector.yang_push.validation.sent.messages")
            .with_description("Number of Telemetry Messages successfully sent upstream")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.yang_push.validation.send.error")
            .with_description("Number of upstream sending errors")
            .build();
        let udpnotif_payload_decoding_error = meter
            .u64_counter("netgauze.collector.yang_push.validation.payload.decoding.error")
            .with_description("Number of errors decoding UDP-Notif payloads")
            .build();
        let udpnotif_payload_processing_error = meter
            .u64_counter("netgauze.collector.yang_push.validation.notification.processing.error")
            .with_description("Number of errors processing Yang Push notifications")
            .build();
        let schemas_cached = meter
            .u64_gauge("netgauze.collector.yang_push.validation.peer.schemas")
            .with_description("Number of active schemas per peer")
            .build();
        let peer_subscriptions = meter
            .u64_gauge("netgauze.collector.yang_push.validation.peer.subscriptions")
            .with_description("Number of active subscriptions per peer")
            .build();
        let subscription_cache_miss = meter
            .u64_counter("netgauze.collector.yang_push.validation.subscription.cache.miss")
            .with_description("Number of subscription cache misses")
            .build();
        Self {
            received_messages,
            sent_messages,
            send_error,
            udpnotif_payload_decoding_error,
            udpnotif_payload_processing_error,
            schemas_cached,
            peer_subscriptions,
            subscription_cache_miss,
        }
    }

    /// Updates the gauge tracking the number of schemas per peer.
    pub fn update_peer_subscriptions_gauge(&self, peer: &SocketAddr, subscription_count: usize) {
        let peer_tags = [
            opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(peer.port().into()),
            ),
        ];
        self.schemas_cached
            .record(subscription_count as u64, &peer_tags);
    }
}

/// Actor responsible for validation of Yang Push messages.
#[allow(dead_code)]
struct ValidationActor {
    cmd_rx: mpsc::Receiver<ValidationActorCommand>,
    udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
    validated_tx: async_channel::Sender<String>,
    subscriptions: SubscriptionCache,
    stats: ValidationStats,
}

impl ValidationActor {
    fn new(
        cmd_rx: mpsc::Receiver<ValidationActorCommand>,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        validated_tx: async_channel::Sender<String>,
        stats: ValidationStats,
    ) -> Self {
        info!("Creating Yang Push validation actor");
        Self {
            cmd_rx,
            udp_notif_rx,
            validated_tx,
            subscriptions: HashMap::new(),
            stats,
        }
    }

    /// Main loop for the actor: handling commands and incoming notification
    /// messages.
    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(ValidationActorCommand::Shutdown) => {
                            info!("Shutting down Yang Push validation actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            warn!("Yang Push validation actor terminated due to command channel closing");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.udp_notif_rx.recv() => {
                    match msg {
                        Ok(arc_tuple) => {
                            let (peer, packet) = arc_tuple.as_ref().clone();
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
                            if let Err(err) = self.handle_udp_notif(peer, packet) {
                                self.stats.udpnotif_payload_processing_error.add(1, &peer_tags);
                                error!("Error handling UDP notification: {err}");
                            }
                        }
                        Err(err) => {
                            error!("Shutting down due to Yang Push receive error: {err}");
                            return Err(ValidationActorError::YangPushReceiveError.into());
                        }
                    }
                }
            }
        }
    }

    fn handle_udp_notif(
        &mut self,
        peer: SocketAddr,
        packet: UdpNotifPacket,
    ) -> Result<(), ValidationActorError> {
        // Decode UdpNotifPacket into UdpNotifPacketDecoded
        let pkt_ptr = &packet;
        let decoded: UdpNotifPacketDecoded = match pkt_ptr.try_into() {
            Ok(decoded) => decoded,
            Err(err) => {
                warn!("Failed to decode Udp-Notif Payload: {err}");
                return Ok(());
            }
        };
        let envelope: UdpNotifPayload = decoded.payload().clone();
        let payload = match envelope {
            NotificationEnvelope(payload) => {
                debug!("Received Yang Push notification from peer: {}", peer);
                payload
            }
            _ => {
                warn!(
                    "Received unsupported UDP-Notif payload type: {:?}",
                    envelope
                );
                return Ok(());
            }
        };
        let content = match payload.contents() {
            Some(content) => content,
            None => {
                warn!("Received Yang Push notification without content");
                return Ok(());
            }
        };
        let subscr_id = content.subscription_id();
        trace!(
            "Processing Yang Push notification for peer: {}, subscription ID: {}",
            peer,
            subscr_id
        );
        let msg = match serde_json::to_string(content) {
            Ok(msg) => msg,
            Err(err) => {
                warn!("Failed to serialize Yang Push message: {err}");
                return Ok(());
            }
        };
        trace!("Serialized Yang Push message: {}", msg);

        // Validating YANG data against the loaded schemas
        let _res = self.validate_message(peer, subscr_id, msg.clone()); // TODO

        Ok(())
    }

    fn validate_message(
        &mut self,
        peer: SocketAddr,
        subscr_id: SubscriptionId,
        message: String,
    ) -> Result<(), ValidationActorError> {
        trace!(
            "Validating Yang Push message for peer: {}, subscription ID: {}",
            peer,
            subscr_id
        );
        let sub = match self.get_subscription(peer, subscr_id) {
            Some(sub) => {
                debug!(
                    "Found context for peer: {}, subscription ID: {}",
                    peer, subscr_id
                );
                sub
            }
            None => {
                debug!(
                    "No context found for peer: {}, subscription ID: {}",
                    peer, subscr_id
                );
                self.stats.subscription_cache_miss.add(
                    1,
                    &[
                        opentelemetry::KeyValue::new(
                            "network.peer.address",
                            format!("{}", peer.ip()),
                        ),
                        opentelemetry::KeyValue::new(
                            "network.peer.port",
                            opentelemetry::Value::I64(peer.port().into()),
                        ),
                    ],
                );
                let yanglibrary =
                    "../../assets/yang/E96CB84D-F02B-4FBF-BE86-3580300CD964/yanglib.json"; // TODO
                let search_dir = "../../assets/yang/E96CB84D-F02B-4FBF-BE86-3580300CD964/models"; // TODO
                self.create_subscription(peer, subscr_id, yanglibrary, search_dir)?
            }
        };

        // Validating YANG data against the loaded schemas
        let data_op = DataOperation::NotificationYang;
        let _data_tree =
            match DataTree::parse_op_string(&sub.context, message, DataFormat::JSON, data_op) {
                Ok(tree) => tree,
                Err(err) => {
                    warn!("Failed to parse Yang Push message: {err}");
                    return Err(ValidationActorError::PayloadValidationError);
                }
            };
        Ok(())
    }

    fn get_subscription(
        &self,
        peer: SocketAddr,
        subscr_id: SubscriptionId,
    ) -> Option<&SubscriptionData> {
        // Retrieve the context for the given peer address
        let idx = (peer, subscr_id);
        let subscription = self.subscriptions.get(&idx);
        match subscription {
            Some(subscription) => {
                debug!(
                    "Found subscription: {}, search dir: {}",
                    &subscription.yang_lib, &subscription.search_dir
                );
                Some(subscription)
            }
            None => {
                debug!(
                    "No subscription found for peer {}, subscription ID {}",
                    peer, subscr_id
                );
                None
            }
        }
    }

    fn create_subscription(
        &mut self,
        peer: SocketAddr,
        subscr_id: SubscriptionId,
        yanglibrary: &str,
        search_dir: &str,
    ) -> Result<&SubscriptionData, ValidationActorError> {
        debug!(
            "Creating context for Yang Push validation, Yang library: {}, search dir: {}",
            yanglibrary, search_dir
        );
        // Initialize context
        let format = DataFormat::JSON;
        let flags = ContextFlags::empty();
        match Context::new_from_yang_library_file(yanglibrary, format, search_dir, flags) {
            Ok(ctx) => {
                debug!(
                    "libyang context created successfully, {} modules",
                    ctx.modules(false).count()
                );
                let context = Arc::new(ctx);
                let subscription =
                    SubscriptionData::new(yanglibrary.to_string(), search_dir.to_string(), context);
                self.subscriptions.insert((peer, subscr_id), subscription);
                Ok(&self.subscriptions[&(peer, subscr_id)])
            }
            Err(err) => {
                error!("Failed to create libyang context: {err}");
                Err(ValidationActorError::PayloadValidationError)
            }
        }
    }
}

#[derive(Debug)]
pub enum ValidationActorHandleError {
    SendError,
}
impl std::fmt::Display for ValidationActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationActorHandleError::SendError => {
                write!(f, "Failed to send command to Yang Push validation actor")
            }
        }
    }
}

impl std::error::Error for ValidationActorHandleError {}

/// Handle for interacting with the `ValidationActor`.
#[derive(Debug, Clone)]
pub struct ValidationActorHandle {
    cmd_tx: mpsc::Sender<ValidationActorCommand>,
    validated_rx: async_channel::Receiver<String>,
}

impl ValidationActorHandle {
    pub fn new(
        buffer_size: usize,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        stats: either::Either<opentelemetry::metrics::Meter, ValidationStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (validated_tx, validated_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => ValidationStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = ValidationActor::new(cmd_rx, udp_notif_rx, validated_tx, stats);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_tx,
            validated_rx,
        };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), ValidationActorHandleError> {
        self.cmd_tx
            .send(ValidationActorCommand::Shutdown)
            .await
            .map_err(|_| ValidationActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<String> {
        self.validated_rx.clone()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use bytes::Bytes;
    use netgauze_udp_notif_pkt::MediaType;
    use serde_json::json;

    fn create_actor() -> ValidationActor {
        ValidationActor::new(
            mpsc::channel(10).1,
            async_channel::bounded(10).1,
            async_channel::bounded(10).0,
            ValidationStats::new(opentelemetry::global::meter("test_meter")),
        )
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_message_validation() {
        let mut validator = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let subscr_id = 0;
        let result = validator.validate_message(
            peer,
            subscr_id,
            r###"{
                "ietf-yang-push:push-update": {
                  "datastore-contents": {
                    "ietf-interfaces:interfaces": {
                      "interface": [
                        {
                          "name": "ethernetCsmacd.0.1.0",
                          "oper-status": "up"
                        },
                        {
                          "name": "ethernetCsmacd.0.1.1",
                          "oper-status": "down"
                        }
                      ]
                    }
                  },
                  "id": 1,
                  "ietf-distributed-notif:message-publisher-id": 1234567890,
                  "ietf-yp-observation:point-in-time": "initial-state",
                  "ietf-yp-observation:timestamp": "2025-01-01T01:23:45.678+01:00"
                }
              }"###
                .to_string(),
        );
        assert!(
            result.is_ok(),
            "Message validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_message_validation_fail() {
        let mut validator = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let subscr_id = 0;
        let result = validator.validate_message(
            peer,
            subscr_id,
            r###"{
                "ietf-yang-push:push-update": {
                  "datastore-contents": {
                    "ietf-interfaces:interfaces": {
                      "interface": [
                        {
                          "name": "ethernetCsmacd.0.1.0",
                          "oper-status": "up"
                        },
                        {
                          "name": "ethernetCsmacd.0.1.1",
                          "oper-status": "down"
                        }
                      ]
                    }
                  },
                  "id": "1"
                }
              }"###
                .to_string(),
        );
        assert!(
            result.is_err(),
            "Invalid message got successfully validated"
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_packet_processing_1() {
        let mut validator = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Create UdpNotifPayload
        let payload = json!({
            "ietf-yp-notification:envelope": {
                "contents": {
                    "ietf-yang-push:push-update": {
                        "datastore-contents": {
                            "ietf-interfaces:interfaces": {
                                "interface": [
                                {
                                    "name": "ethernetCsmacd.0.1.0",
                                    "oper-status": "up"
                                },
                                {
                                    "name": "ethernetCsmacd.0.1.1",
                                    "oper-status": "down"
                                }
                                ]
                            }
                        },
                        "id": 1,
                        "ietf-distributed-notif:message-publisher-id": 1234567890,
                        "ietf-yp-observation:point-in-time": "initial-state",
                        "ietf-yp-observation:timestamp": "2025-01-01T01:00:00.000+01:00"
                    }
                },
                "event-time": "2025-01-01T01:23:45.678901234+01:00",
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

        // Validate the packet
        let result = validator.handle_udp_notif(peer, packet);
        assert!(
            result.is_ok(),
            "Packet validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_packet_processing_2() {
        let mut validator = create_actor();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Create UdpNotifPayload
        let payload1 = json!({
            "ietf-yp-notification:envelope": {
                "contents": {
                    "ietf-yang-push:push-update": {
                        "datastore-contents": {
                            "ietf-interfaces:interfaces": {
                                "interface": [
                                {
                                    "name": "ethernetCsmacd.0.1.0",
                                    "oper-status": "up"
                                },
                                {
                                    "name": "ethernetCsmacd.0.1.1",
                                    "oper-status": "down"
                                }
                                ]
                            }
                        },
                        "id": 1,
                        "ietf-distributed-notif:message-publisher-id": 1234567890,
                        "ietf-yp-observation:point-in-time": "initial-state",
                        "ietf-yp-observation:timestamp": "2025-01-01T01:00:00.000+01:00"
                    }
                },
                "event-time": "2025-01-01T01:23:45.678901234+01:00",
                "hostname": "some-router",
                "sequence-number": 5,
            }
        })
        .to_string()
        .into_bytes();

        let payload2 = json!({
            "ietf-yp-notification:envelope": {
                "contents": {
                    "ietf-yang-push:push-update": {
                        "datastore-contents": {
                            "ietf-interfaces:interfaces": {
                                "interface": [
                                {
                                    "name": "ethernetCsmacd.0.1.0",
                                    "oper-status": "down"
                                },
                                {
                                    "name": "ethernetCsmacd.0.1.1",
                                    "oper-status": "up"
                                }
                                ]
                            }
                        },
                        "id": 1,
                        "ietf-distributed-notif:message-publisher-id": 1234567890,
                        "ietf-yp-observation:point-in-time": "initial-state",
                        "ietf-yp-observation:timestamp": "2025-01-01T01:01:00.000+01:00"
                    }
                },
                "event-time": "2025-01-01T01:23:45.678901234+01:00",
                "hostname": "some-router",
                "sequence-number": 6,
            }
        })
        .to_string()
        .into_bytes();

        let packet1 = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1,
            1,
            HashMap::new(),
            Bytes::from(payload1),
        );
        let packet2 = UdpNotifPacket::new(
            MediaType::YangDataJson,
            1,
            1,
            HashMap::new(),
            Bytes::from(payload2),
        );

        // Create a context and validate the packet
        let result1 = validator.handle_udp_notif(peer, packet1);
        assert!(
            result1.is_ok(),
            "Packet validation failed: {:?}",
            result1.err()
        );
        // Check if the context was cached
        let result2 = validator.get_subscription(peer, 1);
        assert!(result2.is_some(), "Context caching failed");
        // Validate the packet against the cached context
        let result3 = validator.handle_udp_notif(peer, packet2);
        assert!(
            result3.is_ok(),
            "Validation against the cached context failed: {:?}",
            result3.err()
        );
    }
}
