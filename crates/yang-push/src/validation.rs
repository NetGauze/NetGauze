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
use ipnet::IpNet;
use quick_xml::NsReader;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};
use yang3::context::{Context, ContextFlags};
use yang3::data::{DataFormat, DataOperation, DataTree};
use {anyhow, async_channel};

use crate::model::notification::SubscriptionId;
use crate::model::udp_notif::{UdpNotifPacketDecoded, UdpNotifPayload};
use crate::schema_cache::{ContentId, SchemaInfo, SchemaRequest};

use netgauze_netconf_proto::xml_utils::{XmlDeserialize, XmlParser};
use netgauze_netconf_proto::yanglib::YangLibrary;
use netgauze_udp_notif_pkt::UdpNotifPacket;

// Cache for YangPush subscriptions
type PeerCache = HashMap<Peer, ContentId>;
type SubscriptionCache = HashMap<ContentId, SubscriptionData>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Peer {
    address: SocketAddr,
    subscription_id: SubscriptionId,
}
impl Peer {
    fn new(address: SocketAddr, subscription_id: SubscriptionId) -> Self {
        Self {
            address,
            subscription_id,
        }
    }
}

#[derive(Debug)]
struct SubscriptionData {
    content_id: ContentId,
    yanglib_path: String,
    search_dir: String,
    context: Context,
}
impl SubscriptionData {
    fn new(
        content_id: ContentId,
        yanglib_path: String,
        search_dir: String,
        context: Context,
    ) -> Self {
        Self {
            content_id,
            yanglib_path,
            search_dir,
            context,
        }
    }
    fn get_hash(&self) -> ContentId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.yanglib_path.hash(&mut hasher);
        self.search_dir.hash(&mut hasher);
        // hashing of the context
        self.context
            .modules(false)
            .for_each(|m| m.name().hash(&mut hasher));
        hasher.finish().to_string()
    }
}

#[derive(Clone, Debug)]
pub struct SubscriptionInfo {
    peer_addr: SocketAddr,
    subscription_id: Option<SubscriptionId>,
    content_id: Option<ContentId>,
}
impl SubscriptionInfo {
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            subscription_id: None,
            content_id: None,
        }
    }
    pub fn with_subscription_id(mut self, subscription_id: SubscriptionId) -> Self {
        self.subscription_id = Some(subscription_id);
        self
    }
    pub fn with_content_id(mut self, context_id: ContentId) -> Self {
        self.content_id = Some(context_id);
        self
    }
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
    pub const fn subscription_id(&self) -> Option<SubscriptionId> {
        self.subscription_id
    }
    pub const fn content_id(&self) -> Option<&ContentId> {
        self.content_id.as_ref()
    }
}

#[derive(Debug, Clone, Copy)]
enum ValidationActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display)]
pub enum ValidationActorError {
    #[strum(to_string = "error in Yang Push receive channel")]
    YangPushReceiveError,
    #[strum(to_string = "received Yang Push Notification without content")]
    NotificationWithoutContent,
    #[strum(to_string = "failed to serialize UDP-Notif payload")]
    PayloadSerializationError,
    #[strum(to_string = "failed to validate UDP-Notif payload")]
    PayloadValidationError,
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
            subscription_cache_miss,
        }
    }
}

/// Actor responsible for validation of Yang Push messages.
struct ValidationActor {
    cmd_rx: mpsc::Receiver<ValidationActorCommand>,
    #[allow(dead_code)] // TODO: use this to pre-populate the subscription cache
    custom_schemas: HashMap<IpNet, SchemaInfo>,
    udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
    validated_tx: async_channel::Sender<(SubscriptionInfo, UdpNotifPacketDecoded)>,
    #[allow(dead_code)] // TODO: send schema requests
    schema_req_tx: async_channel::Sender<SchemaRequest>,
    schema_resp_rx: async_channel::Receiver<(SchemaRequest, SchemaInfo)>,
    peers: PeerCache,
    subscriptions: SubscriptionCache,
    stats: ValidationStats,
}

impl ValidationActor {
    fn new(
        cmd_rx: mpsc::Receiver<ValidationActorCommand>,
        custom_schemas: HashMap<IpNet, SchemaInfo>,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        validated_tx: async_channel::Sender<(SubscriptionInfo, UdpNotifPacketDecoded)>,
        schema_req_tx: async_channel::Sender<SchemaRequest>,
        schema_resp_rx: async_channel::Receiver<(SchemaRequest, SchemaInfo)>,
        stats: ValidationStats,
    ) -> Self {
        info!("Creating Yang Push validation actor");

        Self {
            cmd_rx,
            custom_schemas,
            udp_notif_rx,
            validated_tx,
            schema_req_tx,
            schema_resp_rx,
            peers: HashMap::new(),
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
                req = self.schema_resp_rx.recv() => {
                    match req {
                        Ok((_schema_request, _schema_info)) => {
                            // TODO
                        }
                        Err(err) => {
                            error!("Shutting down due to Yang Push receive error: {err}");
                            Err(ValidationActorError::YangPushReceiveError)?;
                        }
                    }
                }
                msg = self.udp_notif_rx.recv() => {
                    match msg {
                        Ok(arc_tuple) => {
                            let (peer_ptr, packet) = arc_tuple.as_ref();
                            let peer = *peer_ptr;
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

                            // Process the payload and forward the validated package
                            match self.handle_udp_notif(peer, packet) {
                                Ok(Some((subscription_info, packet))) => {
                                    if let Err(err) = self.validated_tx.send((subscription_info, packet)).await {
                                        error!("YangPushValidationActor send error: {err}");
                                        self.stats.send_error.add(1, &peer_tags);
                                    } else {
                                        self.stats.sent_messages.add(1, &peer_tags);
                                    }
                                }
                                Ok(None) => {
                                    warn!("No valid payload to process for peer: {}", peer);
                                    self.stats.udpnotif_payload_decoding_error.add(1, &peer_tags);
                                }
                                Err(err) => {
                                    error!("Error handling UDP notification: {err}");
                                    self.stats.udpnotif_payload_processing_error.add(1, &peer_tags);
                                }
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
        peer_addr: SocketAddr,
        packet: &UdpNotifPacket,
    ) -> Result<Option<(SubscriptionInfo, UdpNotifPacketDecoded)>, ValidationActorError> {
        // Decode UdpNotifPacket into UdpNotifPacketDecoded
        let decoded: UdpNotifPacketDecoded = match packet.try_into() {
            Ok(decoded) => decoded,
            Err(err) => {
                warn!("Failed to decode Udp-Notif payload: {err}");
                return Ok(None);
            }
        };
        let mut subscription_info = SubscriptionInfo::new(peer_addr);
        let payload: &UdpNotifPayload = decoded.payload();
        let envelope = match payload {
            UdpNotifPayload::NotificationEnvelope(envelope) => {
                debug!("Received Yang Push notification from peer: {}", peer_addr);
                envelope
            }
            UdpNotifPayload::NotificationLegacy(_) => {
                //TODO: discuss here what we should do...
                trace!("Received unsupported UDP-Notif payload type: {:?}", payload);
                return Ok(Some((subscription_info, decoded)));
            }
        };
        let content = match envelope.contents() {
            Some(content) => content,
            None => {
                warn!("Received Yang Push notification without content");
                return Ok(Some((subscription_info, decoded)));
            }
        };
        let subscr_id = content.subscription_id();
        subscription_info.subscription_id = Some(subscr_id);
        trace!(
            "Processing Yang Push notification for peer: {}, subscription ID: {}",
            peer_addr, subscr_id
        );
        let msg = match serde_json::to_string(content) {
            Ok(msg) => msg,
            Err(err) => {
                warn!("Failed to serialize Yang Push message: {err}");
                return Ok(Some((subscription_info, decoded)));
            }
        };
        trace!("Serialized Yang Push message: {}", msg);

        // Validating YANG data against the loaded schemas
        let peer = Peer::new(peer_addr, subscr_id);
        match self.validate_message(peer, msg.clone()) {
            Ok(subscription) => {
                trace!(
                    "Yang Push message validated successfully for peer: {}, subscription ID: {}, content ID: {}",
                    peer_addr, subscr_id, subscription.content_id,
                );
                subscription_info.content_id = Some(subscription.content_id.clone());
            }
            Err(err) => {
                warn!("Yang Push message validation failed: {err}");
                trace!("Yang Push message validation failed - full message: {msg}");
            }
        }
        Ok(Some((subscription_info, decoded)))
    }

    fn validate_message(
        &mut self,
        peer: Peer,
        message: String,
    ) -> Result<&SubscriptionData, ValidationActorError> {
        trace!(
            "Validating Yang Push message for peer: {}, subscription ID: {}",
            &peer.address, &peer.subscription_id
        );
        // Retrieve or create the context for the given peer and subscription ID
        let subscription = match self.get_or_create_subscription(peer.clone()) {
            Ok(subscription) => subscription,
            Err(err) => {
                error!(
                    "Failed to create context for peer: {}, subscription ID: {}: {err}",
                    &peer.address, &peer.subscription_id
                );
                return Err(ValidationActorError::PayloadValidationError);
            }
        };

        // Validating YANG data against the loaded schemas
        let data_op = DataOperation::NotificationYang;
        let _data_tree = match DataTree::parse_op_string(
            &subscription.context,
            message.clone(),
            DataFormat::JSON,
            data_op,
        ) {
            Ok(tree) => tree,
            Err(err) => {
                warn!("Failed to parse Yang Push message: {err}");
                return Err(ValidationActorError::PayloadValidationError);
            }
        };
        Ok(subscription)
    }

    fn get_or_create_subscription(
        &mut self,
        peer: Peer,
    ) -> Result<&SubscriptionData, ValidationActorError> {
        // Retrieve or create the context for the given peer and subscription ID
        if self.get_subscription(peer.clone()).is_some() {
            return Ok(self.get_subscription(peer).unwrap());
        };

        self.stats.subscription_cache_miss.add(1, &[]);

        // Get schema info from custom_schemas based on peer IP
        let schema_info = self
            .custom_schemas
            .iter()
            .find(|(subnet, _)| subnet.contains(&peer.address.ip()))
            .map(|(_, schema)| schema)
            .ok_or_else(|| {
                error!(
                    "No schema configuration found for peer IP: {}",
                    peer.address.ip()
                );
                ValidationActorError::PayloadValidationError
            })?;

        // Get content_id from schema_info, or extract from yanglib if not provided
        let content_id = match schema_info.content_id() {
            Some(id) => id.to_string(),
            None => {
                // Extract content_id from yanglib file
                let reader = NsReader::from_file(schema_info.yanglib_path()).map_err(|err| {
                    error!(
                        "Failed to read yanglib file {}: {}",
                        schema_info.yanglib_path(),
                        err
                    );
                    ValidationActorError::PayloadValidationError
                })?;
                let mut xml_reader = XmlParser::new(reader).map_err(|err| {
                    error!("Failed to create XML parser: {}", err);
                    ValidationActorError::PayloadValidationError
                })?;
                let yanglib: YangLibrary =
                    YangLibrary::xml_deserialize(&mut xml_reader).map_err(|err| {
                        error!("Failed to deserialize yanglib: {}", err);
                        ValidationActorError::PayloadValidationError
                    })?;

                debug!(
                    "Extracted content_id from yanglib: {}",
                    yanglib.content_id()
                );
                yanglib.content_id().to_string()
            }
        };

        match self.create_subscription(peer.clone(), content_id, schema_info.clone()) {
            Ok(subscription) => Ok(subscription),
            Err(err) => {
                error!(
                    "Failed to create context for peer: {}, subscription ID: {}: {err}",
                    &peer.address, &peer.subscription_id
                );
                Err(ValidationActorError::PayloadValidationError)
            }
        }
    }

    fn get_subscription(&self, peer: Peer) -> Option<&SubscriptionData> {
        // Retrieve the context for the given peer
        let content_id = match self.peers.get(&peer) {
            Some(content_id) => {
                trace!(
                    "Found content ID: {} for peer {}, subscription ID {}",
                    content_id, peer.address, peer.subscription_id
                );
                content_id
            }
            None => {
                // TODO: add peer
                trace!(
                    "No context found for peer {}, subscription ID {}",
                    peer.address, peer.subscription_id
                );
                return None;
            }
        };
        match self.subscriptions.get(content_id) {
            Some(subscription) => {
                debug!(
                    "Found subscription: {}, search dir: {}",
                    &subscription.yanglib_path, &subscription.search_dir
                );
                Some(subscription)
            }
            None => {
                debug!(
                    "No subscription found for peer {}, subscription ID {}",
                    peer.address, peer.subscription_id
                );
                None
            }
        }
    }

    fn create_subscription(
        &mut self,
        peer: Peer,
        content_id: ContentId,
        schema_info: SchemaInfo,
    ) -> Result<&SubscriptionData, ValidationActorError> {
        let search_dir = schema_info.search_dir();
        let yanglib_path = schema_info.yanglib_path();
        let format = DataFormat::XML;

        debug!(
            "Creating context from Yang Library file: {}, search dir: {}, content ID: {}",
            yanglib_path, search_dir, content_id
        );

        let flags = ContextFlags::empty();
        match Context::new_from_yang_library_file(&yanglib_path, format, &search_dir, flags) {
            Ok(context) => {
                debug!(
                    "libyang context created successfully, {} modules",
                    context.modules(false).count()
                );
                let subscription = SubscriptionData::new(
                    content_id.clone(),
                    yanglib_path.to_string(),
                    search_dir.to_string(),
                    context,
                );
                let hash = subscription.get_hash();
                self.peers.insert(peer, hash.clone());
                self.subscriptions.insert(hash.clone(), subscription);
                Ok(&self.subscriptions[&hash])
            }
            Err(err) => {
                error!("Failed to create libyang context: {err}");
                Err(ValidationActorError::PayloadValidationError)
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum ValidationActorHandleError {
    #[strum(to_string = "failed to send command to Yang Push validation actor")]
    SendError,
}

impl std::error::Error for ValidationActorHandleError {}

/// Handle for interacting with the `ValidationActor`.
#[derive(Debug, Clone)]
pub struct ValidationActorHandle {
    cmd_tx: mpsc::Sender<ValidationActorCommand>,
    validated_rx: async_channel::Receiver<(SubscriptionInfo, UdpNotifPacketDecoded)>,
}

impl ValidationActorHandle {
    pub fn new(
        buffer_size: usize,
        custom_schemas: HashMap<IpNet, SchemaInfo>,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        schema_req_tx: async_channel::Sender<SchemaRequest>,
        schema_resp_rx: async_channel::Receiver<(SchemaRequest, SchemaInfo)>,
        stats: either::Either<opentelemetry::metrics::Meter, ValidationStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (validated_tx, validated_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => ValidationStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = ValidationActor::new(
            cmd_rx,
            custom_schemas,
            udp_notif_rx,
            validated_tx,
            schema_req_tx,
            schema_resp_rx,
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

    pub fn subscribe(&self) -> async_channel::Receiver<(SubscriptionInfo, UdpNotifPacketDecoded)> {
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
            HashMap::new(),
            async_channel::bounded(10).1,
            async_channel::bounded(10).0,
            async_channel::bounded(10).0,
            async_channel::bounded(10).1,
            ValidationStats::new(opentelemetry::global::meter("test_meter")),
        )
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_message_validation_ok() {
        let mut validator = create_actor();
        let peer = Peer {
            address: SocketAddr::from(([127, 0, 0, 1], 12345)),
            subscription_id: 0,
        };
        let result = validator.validate_message(
            peer,
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
        let peer = Peer {
            address: SocketAddr::from(([127, 0, 0, 1], 12345)),
            subscription_id: 0,
        };
        let result = validator.validate_message(
            peer,
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
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12345));

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
        let result = validator.handle_udp_notif(peer_addr, &packet);
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
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        let peer = Peer {
            address: peer_addr,
            subscription_id: 1,
        };

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
        let result1 = validator.handle_udp_notif(peer_addr, &packet1);
        assert!(
            result1.is_ok(),
            "Packet validation failed: {:?}",
            result1.err()
        );
        // Check if the context was cached
        let result2 = validator.get_subscription(peer);
        assert!(result2.is_some(), "Context caching failed");
        // Validate the packet against the cached context
        let result3 = validator.handle_udp_notif(peer_addr, &packet2);
        assert!(
            result3.is_ok(),
            "Validation against the cached context failed: {:?}",
            result3.err()
        );
    }
}
