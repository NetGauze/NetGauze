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

// TODO: documentation here
// TODO: also add tests from the pcap that produce enriched telemetrymessages!
// TODO: add tests for all the match arms and conditions below...
// TODO: fix error handling / log messages / otel counters...
// TODO: implement early return...

use crate::{
    notification::{
        Notification, NotificationVariant, SubscriptionStartedModified, SubscriptionTerminated,
        Transport,
    },
    telemetry::{
        DataCollectionMetadata, Label, LabelValue, Manifest, SessionProtocol, TelemetryMessage,
        YangPushFilter, YangPushSubscriptionMetadata,
    },
    yang_push::telemetry::TelemetryMessageMetadata,
    SubscriptionId, UdpNotifPayload,
};

use chrono::Utc;
use colored::*;
use netgauze_udp_notif_pkt::{MediaType, UdpNotifPacket};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use sysinfo::System;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

/// Cache for YangPush subscriptions metadata
pub type SubscriptionsCache = HashMap<SubscriptionId, TelemetryMessageMetadata>;

#[derive(Debug, Clone, Copy)]
pub enum YangPushEnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
pub enum YangPushEnrichmentActorError {
    EnrichmentChannelClosed,
    YangPushReceiveError,
    YangPushUpdateNoSubscriptionInfo,
    UnsupportedMediaType(MediaType),
    UnknownPayload,
}

impl std::fmt::Display for YangPushEnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::YangPushReceiveError => write!(f, "error in flow receive channel"),
            Self::YangPushUpdateNoSubscriptionInfo => {
                write!(
                    f,
                    "Yang Push update received but no subscription information found in the cache"
                )
            }
            Self::UnsupportedMediaType(media_type) => {
                write!(f, "Unsupported udp-notif media type: {:?}", media_type)
            }
            Self::UnknownPayload => {
                write!(f, "unknown udp-notif payload format")
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
    pub enrichment_error: opentelemetry::metrics::Counter<u64>,
}

impl YangPushEnrichmentStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.received.messages")
            .with_description("Number of Yang Push messages received for enrichment")
            .build();
        let sent_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.sent")
            .with_description("Number of enriched Yang Push messages successfully sent upstream")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.sent.error")
            .with_description("Number of upstream sending errors")
            .build();
        let enrichment_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.error")
            .with_description("Number of Yang Push enrichment errors")
            .build();
        Self {
            received_messages,
            sent_messages,
            send_error,
            enrichment_error,
        }
    }
}

// TODO: make name extendable and/or overwritable from writer_id in
// config (e.g. name = writer_id + "@" + host_name) ?
// TODO: move somewhere else?
fn fetch_sysinfo_manifest() -> Manifest {
    let mut sys = System::new_all();
    sys.refresh_all();

    Manifest {
        name: System::host_name(),
        vendor: Some("NetGauze".to_string()),
        vendor_pen: None,
        software_version: Some(env!("CARGO_PKG_VERSION").to_string()), /* TODO: working also for
                                                                        * binary? --> check
                                                                        * better way/static */
        software_flavor: Some({
            if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "release".to_string()
            }
        }),
        os_version: System::os_version(),
        os_type: System::name(),
    }
}

struct YangPushEnrichmentActor {
    cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
    udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
    enriched_tx: async_channel::Sender<TelemetryMessage>,
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
        enriched_tx: async_channel::Sender<TelemetryMessage>,
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

    fn cache_subscription(
        &mut self,
        peer: SocketAddr,
        sub: &SubscriptionStartedModified,
    ) -> Result<TelemetryMessageMetadata, YangPushEnrichmentActorError> {
        let target_datastore = sub.target().datastore().map(|f| f.to_string());

        let target_stream = sub.target().stream().map(|f| f.to_string());

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

        let subscription_metadata = YangPushSubscriptionMetadata {
            id: Some(sub.id()),
            filter: YangPushFilter {
                target_stream,
                target_datastore,
                xpath_filter,
                subtree_filter,
            },
            stop_time: sub.stop_time().cloned(),
            transport: sub.transport().cloned(),
            encoding: sub.encoding().cloned(),
            purpose: sub.purpose().cloned(),
            update_trigger: sub.update_trigger().clone(),
            module_version: sub.module_version().cloned().unwrap_or_default(), /* TODO: test here the default... */
            yang_library_content_id: sub.content_id().map(|id| id.to_string()),
        };

        let telemetry_message_metadata = TelemetryMessageMetadata {
            event_time: None,
            yang_push_subscription: Some(subscription_metadata),
        };

        // Insert the subscription metadata into the cache
        // TODO: counters / warnings here for cache misses?
        let peer_subscriptions = self.subscriptions.entry(peer).or_insert_with(HashMap::new);
        peer_subscriptions.insert(sub.id(), telemetry_message_metadata.clone());

        debug!(
            "Yang Push Subscription Cache: {}",
            serde_json::to_string(&self.subscriptions).unwrap().red()
        );

        Ok(telemetry_message_metadata)
    }

    fn delete_subscription(
        &mut self,
        peer: SocketAddr,
        sub: &SubscriptionTerminated,
    ) -> Result<TelemetryMessageMetadata, YangPushEnrichmentActorError> {
        // Get subscription information from the cache
        // TODO: implement early return with some debug logging if not found in the
        // cache
        let telemetry_message_metadata = self
            .subscriptions
            .get_mut(&peer)
            .and_then(|subscriptions| subscriptions.remove(&sub.id()))
            .unwrap_or_default();

        debug!(
            "Yang Push Subscription Cache: {}",
            serde_json::to_string(&self.subscriptions).unwrap().red()
        );

        Ok(telemetry_message_metadata)
    }

    fn get_subscription(
        &self,
        peer: SocketAddr,
        subscription_id: &SubscriptionId,
    ) -> Result<TelemetryMessageMetadata, YangPushEnrichmentActorError> {
        // Get subscription information from the cache
        // TODO: implement early return with some debug logging if not found in the
        // cache
        let telemetry_message_metadata = self
            .subscriptions
            .get(&peer)
            .and_then(|subscriptions| subscriptions.get(subscription_id))
            .cloned()
            .unwrap_or_default();

        Ok(telemetry_message_metadata)
    }

    // TODO: move to udp-notif-pkt together with Notification definition...
    fn process_notification(
        &mut self,
        peer: SocketAddr,
        message: Notification,
    ) -> Result<TelemetryMessage, YangPushEnrichmentActorError> {
        let timestamp = Utc::now();

        // Get sonata labels from the cache
        let (_, labels) = self.labels.get(&peer.ip()).unwrap_or(&self.default_labels);
        let labels: Vec<Label> = labels
            .iter()
            .map(|(key, value)| Label {
                name: key.clone(),
                value: Some(LabelValue::StringValue {
                    string_values: value.clone(),
                }),
            })
            .collect();

        let telemetry_message_metadata: TelemetryMessageMetadata;

        //TODO: add counters (here or in the functions? let's see...)
        match message.notification() {
            NotificationVariant::SubscriptionStarted(sub_started) => {
                debug!(
                    "Received Subscription Started Message (peer: {}, id={})",
                    peer,
                    sub_started.id()
                );
                telemetry_message_metadata = self.cache_subscription(peer, sub_started)?;
            }
            NotificationVariant::SubscriptionModified(sub_modified) => {
                debug!(
                    "Received Subscription Modified Message (peer: {}, id={})",
                    peer,
                    sub_modified.id()
                );
                telemetry_message_metadata = self.cache_subscription(peer, sub_modified)?;
            }
            NotificationVariant::SubscriptionTerminated(sub_terminated) => {
                debug!(
                    "Received Subscription Terminated Message (peer: {}, id={})",
                    peer,
                    sub_terminated.id()
                );
                telemetry_message_metadata = self.delete_subscription(peer, sub_terminated)?;
            }
            NotificationVariant::YangPushUpdate(push_update) => {
                debug!(
                    "Received Yang Push Update Message (peer: {}, id={})",
                    peer,
                    push_update.id()
                );
                telemetry_message_metadata = self.get_subscription(peer, &push_update.id())?;
            }
        }

        // Infer Session Protocol from Transport
        let mut session_protocol = SessionProtocol::default();
        if let Some(yang_push_subscription) = &telemetry_message_metadata.yang_push_subscription {
            session_protocol = match yang_push_subscription.transport {
                Some(Transport::UDPNotif) | Some(Transport::HTTPSNotif) => {
                    SessionProtocol::YangPush
                }
                _ => SessionProtocol::Unknown,
            };
        }

        // Populate metadata in a new TelemetryMessage
        Ok(TelemetryMessage {
            timestamp,
            session_protocol,
            network_node_manifest: Manifest::default(),
            data_collection_manifest: self.manifest.clone(),
            telemetry_message_metadata,
            data_collection_metadata: DataCollectionMetadata {
                remote_address: peer.ip(),
                remote_port: Some(peer.port()),
                local_address: None, //TODO: get from config?
                local_port: None,    //TODO: get from config?
                labels,
            },
            payload: Some(serde_json::to_value(message).unwrap()), // TODO: handle unwrap better
        })
    }

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
                            let (peer, udp_notif_pkt) = arc_tuple.as_ref();
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

                            // Access the notification from the UdpNotifPacket
                            // TODO: move this to udp-notif-pkt crate
                            // TODO: this needs to be tested
                            let payload: UdpNotifPayload;
                            match udp_notif_pkt.media_type() {
                                MediaType::YangDataJson => {
                                    payload = serde_json::from_slice(udp_notif_pkt.payload())?;
                                }
                                MediaType::YangDataXml => {
                                    let payload_str = std::str::from_utf8(udp_notif_pkt.payload())?;
                                    payload = serde_json::from_str(payload_str)?;
                                }
                                MediaType::YangDataCbor => {
                                    payload = ciborium::de::from_reader(std::io::Cursor::new(udp_notif_pkt.payload()))?;
                                }
                                media_type => {
                                    //TODO: log payload to trace?
                                    payload = UdpNotifPayload::Unknown(udp_notif_pkt.payload().clone());
                                    Err(YangPushEnrichmentActorError::UnsupportedMediaType(media_type))?;
                                }
                            }

                            // Process the notification
                            if let UdpNotifPayload::Notification(notification) = payload {
                              match self.process_notification(*peer, notification) {
                                  Ok(telemetry_message) => {

                                      // TEMP DEBUG STATEMENT
                                      info!("{}", serde_json::to_string(&telemetry_message).unwrap().purple());

                                      // Successfully processed and got a TelemetryMessage
                                      if let Err(err) = self.enriched_tx.send(telemetry_message).await {
                                          error!("YangPushEnrichmentActor send error: {err}");
                                          self.stats.send_error.add(1, &peer_tags);
                                      } else {
                                          self.stats.sent_messages.add(1, &peer_tags);
                                      }
                                  }
                                  Err(err) => {
                                      warn!("Error processing notification: {err}");
                                      self.stats.enrichment_error.add(1, &peer_tags);
                                  }
                              }
                          } else {
                              warn!("YangPushEnrichmentActorError: UnknownPayload");
                              Err(YangPushEnrichmentActorError::UnknownPayload)?;
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

#[derive(Debug, Clone)]
pub struct YangPushEnrichmentActorHandle {
    cmd_send: mpsc::Sender<YangPushEnrichmentActorCommand>,
    enriched_rx: async_channel::Receiver<TelemetryMessage>,
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

    pub fn subscribe(&self) -> async_channel::Receiver<TelemetryMessage> {
        self.enriched_rx.clone()
    }
}
