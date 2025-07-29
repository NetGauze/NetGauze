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
use std::{collections::HashMap, net::SocketAddr, ops::BitOr, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};
use yang3::{
    context::{Context, ContextFlags},
    data::{DataFormat, DataParserFlags, DataTree, DataValidationFlags},
};

use netgauze_udp_notif_pkt::UdpNotifPacket;

use crate::model::notification::SubscriptionId;

/// Cache for YangPush subscriptions
pub type SubscriptionIdx = (SocketAddr, SubscriptionId);
pub type YangLibrary = String;
pub type SearchDir = String;
pub type SubscriptionData = (YangLibrary, SearchDir, Context);
pub type SubscriptionCache = HashMap<SubscriptionIdx, SubscriptionData>;

#[derive(Debug, Clone, Copy)]
pub enum ValidationActorCommand {
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
    //schema_rx: async_channel::Receiver<Arc<YangSchema>>,
    //schema_tx: async_channel::Sender<Arc<YangSchema>>,
    subscriptions: SubscriptionCache,
    stats: ValidationStats,
}

impl ValidationActor {
    fn new(
        cmd_rx: mpsc::Receiver<ValidationActorCommand>,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        validated_tx: async_channel::Sender<String>,
        //schema_rx: async_channel::Receiver<Arc<YangSchema>>,
        //schema_tx: async_channel::Sender<Arc<YangSchema>>,
        stats: ValidationStats,
    ) -> Self {
        Self {
            cmd_rx,
            udp_notif_rx,
            validated_tx,
            //schema_rx,
            //schema_tx,
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
                /*
                msg = self.schema_rx.recv() => {
                    match msg {
                        Ok(arc_tuple) => {
                            let _peer = arc_tuple.as_ref();
                        }
                        Err(err) => {
                            error!("Shutting down due to schema cache receiving error: {err}");
                            Err(ValidationActorError::YangPushReceiveError)?;
                        }
                    }
                }
                */
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
        // Check if the notification has content
        if packet.payload().is_empty() {
            return Err(ValidationActorError::NotificationWithoutContent);
        }
        let subscr_id = 0; // TODO

        let ctx = match self.get_context(peer, subscr_id) {
            Ok(ctx) => ctx,
            Err(err) => {
                debug!("Found no context for peer {}: {}", peer, err);
                let yanglibrary = "E96CB84D-F02B-4FBF-BE86-3580300CD964"; // TODO
                let search_dir = "models"; // TODO
                &self.create_context(yanglibrary, search_dir).unwrap()
            }
        };

        // Validating YANG data against the loaded schemas
        dbg!(packet.payload());
        let yang_data = packet.payload();

        // TODO: Decode UdpNotifPacket into UdpNotifPacketDecoded

        let data_tree = DataTree::parse_string(
            ctx,
            yang_data,
            DataFormat::JSON,
            DataParserFlags::STRICT,
            DataValidationFlags::empty(),
        )
        .map_err(|_| ValidationActorError::PayloadValidationError)?;

        debug!("Iterating over all data nodes...");
        for dnode in data_tree.traverse() {
            debug!("  {}: {:?}", dnode.path(), dnode.value());
        }

        Ok(())
    }

    fn get_context(
        &self,
        peer: SocketAddr,
        subscr_id: SubscriptionId,
    ) -> Result<&Context, ValidationActorError> {
        // Retrieve the context for the given peer address
        let idx = (peer, subscr_id);
        let subscription = self.subscriptions.get(&idx);
        match subscription {
            Some(subscription) => {
                let (_yanglibrary, _search_dir, ctx) = subscription;
                Ok(ctx)
            }
            None => {
                error!("No subscription found for peer: {}", peer);
                Err(ValidationActorError::YangPushReceiveError)
            }
        }
    }

    fn create_context(
        &self,
        yanglibrary: &str,
        search_dir: &str,
    ) -> Result<Context, ValidationActorError> {
        // Initialize context
        let flags = ContextFlags::NO_YANGLIBRARY.bitor(ContextFlags::REF_IMPLEMENTED);
        let format = DataFormat::XML;
        let ctx = Context::new_from_yang_library_str(yanglibrary, format, search_dir, flags)
            .expect("Failed to create context");
        for schema_module in ctx.modules(false) {
            debug!("schema modules loaded: {}", schema_module.name());
        }
        Ok(ctx)
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
        //let (schema_tx, schema_rx) = async_channel::bounded(buffer_size);
        let (validated_tx, validated_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => ValidationStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = ValidationActor::new(
            cmd_rx,
            udp_notif_rx,
            validated_tx,
            //schema_rx,
            //schema_tx,
            stats,
        );
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
