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

//! YANG Push Notification Validation Actor
//!
//! This module provides an actor-based validation system for UDP-Notif
//! packets carrying YANG-modeled data. The actor validates notification
//! payloads against YANG schemas when available, gracefully handling
//! cases where schemas haven't been loaded yet.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use netgauze_yang_push::validation::ValidationActorHandle;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let (rx, tx, cache_cmd_tx) = /* channel setup */;
//! let (join_handle, handle) = ValidationActorHandle::new(
//!     1000,  // max packets cached per peer
//!     100,   // max packets cached per subscription
//!     rx,    // incoming UDP-Notif packets
//!     tx,    // validated packets output
//!     cache_cmd_tx,  // cache lookup commands
//! )?;
//!
//! // Actor runs in background...
//! handle.shutdown().await?;
//! join_handle.await??;
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! ### Packet Processing Pipeline
//!
//! 1. **Receive**: UDP-Notif packets arrive from the network layer
//! 2. **Decode**: Extract subscription ID and notification type
//! 3. **Bootstrap**: `SubscriptionStarted` notifications trigger YANG library
//!    lookups via the cache actor
//! 4. **Cache or Validate**:
//!    - If YANG schema available: Validate and forward
//!    - If schema pending: Cache packet until schema arrives
//!    - If schema unavailable: Forward unvalidated with empty subscription info
//! 5. **Forward**: Send validated/unvalidated packets downstream
//!
//! ### Two-Level Caching
//!
//! The actor maintains caches at two levels to handle the asynchronous nature
//! of YANG schema retrieval:
//!
//! - **Peer Level**: Groups all subscriptions from the same source IP
//!   - Enforces `max_cached_packets_per_peer` limit across all subscriptions
//!   - Prevents a single peer from consuming excessive memory
//!
//! - **Subscription Level**: Per-subscription state including:
//!   - `SubscriptionInfo`: Metadata from `SubscriptionStarted`
//!   - `yang4::Context`: Loaded YANG schemas for validation
//!   - Buffered packets waiting for schema retrieval
//!   - Enforces `max_cached_packets_per_subscription` limit
//!
//! Packets arriving before schemas are loaded are cached and reprocessed
//! when the cache actor responds with YANG library references.
//!
//! ### Cache Limits
//!
//! Two configurable limits prevent memory exhaustion:
//! - **Per-subscription limit**: protects against slow schema retrieval
//! - **Per-peer limit**: protects against malicious peers creating many
//!   subscriptions
//!
//! When limits are exceeded, new packets are dropped with a warning logged.
//!
//! ## Validation Behavior
//!
//! The actor validates packets when YANG schemas are available:
//!
//! - **Schema available**: Validates using `yang4` library
//!   - Valid packets → forwarded with full `SubscriptionInfo`
//!   - Invalid packets → dropped with error logged
//!
//! - **Schema unavailable**: Forwards unvalidated
//!   - Marked with empty `SubscriptionInfo` (content_id = "EMPTY")
//!   - Downstream can detect and handle unvalidated packets
//!
//! - **Schema loading failed**: Disables validation for subscription
//!   - All future packets forwarded unvalidated
//!   - Warning logged once when schema load fails
//!
//! ## Error Handling
//!
//! - **Non-fatal errors** (per-packet):
//!   - Decode failures: Packet dropped, warning logged
//!   - Validation failures: Packet dropped, warning logged
//!   - Cache full: New packet dropped, warning logged
//!
//! - **Fatal errors** (shutdown triggers):
//!   - Input channel closed: Actor terminates gracefully
//!   - Output channel closed: Actor terminates (backpressure failure)
//!   - Cache channel closed: Actor terminates (dependency failure)
//!   - Shutdown command received: Graceful termination

use crate::ContentId;
use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::cache::storage::SubscriptionInfo;
use netgauze_udp_notif_pkt::decoded::UdpNotifPacketDecoded;
use netgauze_udp_notif_pkt::notification::{
    NotificationVariant, SubscriptionId, SubscriptionStartedModified,
};
use netgauze_udp_notif_pkt::raw::UdpNotifPacket;
use rustc_hash::FxHashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};
use yang4::data::{DataFormat, DataOperation, DataParserFlags, DataValidationFlags};

const OTL_CACHE_DROP_REASON_KEY: &str = "netgauze.udp.notif.yang.push.cache.drop.reason";
const OTL_CACHE_DROP_REASON_SUBSCRIPTION_CACHE_FULL: &str = "subscription cache is full";
const OTL_CACHE_DROP_REASON_PEER_CACHE_FULL: &str = "peer cache is full";

const OTL_UDP_NOTIF_MESSAGE_ID_KEY: &str = "netgauze.udp.notif.message_id";
const OTL_UDP_NOTIF_PUBLISHER_ID_KEY: &str = "netgauze.udp.notif.publisher_id";
const OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY: &str = "netgauze.udp.notif.yang.push.subscription.id";
const OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY: &str =
    "netgauze.udp.notif.yang.push.subscription.target";
const OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY: &str =
    "netgauze.udp.notif.yang.push.subscription.router_content_id";
const OTL_YANG_PUSH_DECODE_ERROR_ID_KEY: &str = "netgauze.udp.notif.yang.push.decode.error";

#[derive(Debug)]
struct CachedSubscription {
    cached_content_id: Option<ContentId>,
    subscription_info: SubscriptionInfo,
    yang_ctx: Option<yang4::context::Context>,
    cached_packets: Vec<Arc<(SocketAddr, UdpNotifPacket)>>,
}

#[derive(Debug, Default)]
struct CachedPeerSubscriptions {
    subscriptions: FxHashMap<SubscriptionId, CachedSubscription>,
}

#[derive(Debug, Clone)]
pub struct ValidationStats {
    pub messages_received: opentelemetry::metrics::Counter<u64>,
    pub messages_decoding_success: opentelemetry::metrics::Counter<u64>,
    pub messages_decoding_fail: opentelemetry::metrics::Counter<u64>,
    pub cache_request_by_subscription_info: opentelemetry::metrics::Counter<u64>,
    pub cache_request_by_subscription_id: opentelemetry::metrics::Counter<u64>,
    pub cached_packets: opentelemetry::metrics::Gauge<u64>,
    pub cache_drop: opentelemetry::metrics::Counter<u64>,
    pub cache_drain: opentelemetry::metrics::Counter<u64>,
    pub cache_yang_ctx_created: opentelemetry::metrics::Counter<u64>,
    pub cache_yang_ctx_invalid: opentelemetry::metrics::Counter<u64>,
    pub cache_yang_ctx_empty: opentelemetry::metrics::Counter<u64>,
    pub validation_success: opentelemetry::metrics::Counter<u64>,
    pub validation_invalid: opentelemetry::metrics::Counter<u64>,
    pub validation_malformed: opentelemetry::metrics::Counter<u64>,
    pub validation_skip: opentelemetry::metrics::Counter<u64>,
    pub messages_sent: opentelemetry::metrics::Counter<u64>,
}

impl ValidationStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let messages_received = meter
            .u64_counter("netgauze.collector.yang_push.validation.messages.received")
            .with_description(
                "Number of Yang Push messages received for validation (before decoding)",
            )
            .build();
        let messages_decoding_success = meter
            .u64_counter("netgauze.collector.yang_push.validation.messages.decode.success")
            .with_description("Number of Yang Push messages decoded successfully (UDP-Notif payload read successfully)")
            .build();
        let messages_decoding_fail = meter
            .u64_counter("netgauze.collector.yang_push.validation.messages.decode.fail")
            .with_description("Number of Yang Push messages dropped because of decoding errors (Couldn't read UDP-Notif payload)")
            .build();
        let cache_request_by_subscription_info = meter
            .u64_counter("netgauze.collector.yang_push.validation.messages.cache.requests.by.subscription_info")
            .with_description("Number of cache requests by subscription info (from subscription-start or subscription-modified messages) to retrieve the schemas for YANG-Push subscriptions")
            .build();
        let cache_request_by_subscription_id = meter
            .u64_counter("netgauze.collector.yang_push.validation.messages.cache.requests.by.subscription_info")
            .with_description("Number of cache requests by Subscription ID to retrieve the schemas for YANG-Push subscriptions")
            .build();
        let cached_packets = meter
            .u64_gauge("netgauze.collector.yang_push.validation.cache.packets")
            .with_description("Number of Yang Push message cached")
            .build();
        let cache_drop = meter
            .u64_counter("netgauze.collector.yang_push.validation.cache.drop")
            .with_description("Number of Yang Push messages dropped because of cache is full")
            .build();
        let cache_drain = meter
            .u64_counter("netgauze.collector.yang_push.validation.cache.drain")
            .with_description("Number of Yang Push messages popped out of the cache and send is going to the validation step")
            .build();
        let cache_yang_ctx_created = meter
            .u64_counter("netgauze.collector.yang_push.validation.cache.yang.ctx.created")
            .with_description("Number of libyang validation context that are successfully created")
            .build();
        let cache_yang_ctx_invalid = meter
            .u64_counter("netgauze.collector.yang_push.validation.cache.yang.ctx.invalid")
            .with_description(
                "Number of libyang validation context that are invalid (e.g., missing schema)",
            )
            .build();
        let cache_yang_ctx_empty = meter
            .u64_counter("netgauze.collector.yang_push.validation.cache.yang.ctx.empty")
            .with_description("Number of libyang validation context that are empty (e.g., schema loading from the router failed)")
            .build();
        let validation_malformed = meter
            .u64_counter("netgauze.collector.yang_push.validation.malformed")
            .with_description(
                "Number of Yang Push messages dropped because they are malformed; e.g., missing subscription info",
            )
            .build();
        let validation_success = meter
            .u64_counter("netgauze.collector.yang_push.validation.success")
            .with_description("Number of Yang Push messages successfully validated")
            .build();
        let validation_invalid = meter
            .u64_counter("netgauze.collector.yang_push.validation.invalid")
            .with_description("Number of Yang Push messages dropped because of validation errors")
            .build();
        let validation_skip = meter
            .u64_counter("netgauze.collector.yang_push.validation.skipped")
            .with_description("Number of Yang Push skipped the validation step because the subscription is not found in the cache")
            .build();
        let messages_sent = meter
            .u64_counter("netgauze.collector.yang_push.validation.messages.sent")
            .with_description("Number of Telemetry Messages successfully sent upstream")
            .build();
        Self {
            messages_received,
            messages_decoding_success,
            messages_decoding_fail,
            cache_request_by_subscription_info,
            cache_request_by_subscription_id,
            cached_packets,
            cache_drop,
            cache_drain,
            cache_yang_ctx_created,
            cache_yang_ctx_invalid,
            cache_yang_ctx_empty,
            validation_success,
            validation_invalid,
            validation_malformed,
            validation_skip,
            messages_sent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display)]
pub enum ValidationActorError {
    #[strum(serialize = "Failed to send cache lookup command")]
    CacheLookupSendError,
    #[strum(serialize = "Failed to receive cache response")]
    CacheResponseReceiveError,
    #[strum(serialize = "Failed to send the decoded UDP-Notif packet")]
    SendError,
}

impl std::error::Error for ValidationActorError {}

#[derive(Debug, Clone, Copy)]
enum ValidationActorCommand {
    Shutdown,
}

struct ValidationActor {
    max_cached_packets_per_peer: usize,
    max_cached_packets_per_subscription: usize,
    peer_cache: FxHashMap<IpAddr, CachedPeerSubscriptions>,
    cmd_rx: mpsc::Receiver<ValidationActorCommand>,
    rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
    tx: async_channel::Sender<(Option<ContentId>, SubscriptionInfo, UdpNotifPacketDecoded)>,
    cache_cmd_tx: async_channel::Sender<CacheLookupCommand>,
    cache_tx: async_channel::Sender<CacheResponse>,
    cache_rx: async_channel::Receiver<CacheResponse>,
    stats: ValidationStats,
}

impl ValidationActor {
    /// Check if the subscription is different from the existing one in the
    /// cache.
    ///
    /// If it is different, remove the existing one from the cache to allow a
    /// new request to the caching actor.
    fn check_subscription_new(&mut self, peer: SocketAddr, subscription_info: &SubscriptionInfo) {
        if let Some(cached_peer_subscriptions) = self.peer_cache.get_mut(&peer.ip()) {
            let is_different = cached_peer_subscriptions
                .subscriptions
                .get(&subscription_info.id())
                .map(|x| x.subscription_info != *subscription_info)
                .unwrap_or(true);
            if is_different {
                trace!(
                    peer=%peer,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    "Subscription changed, removing from cache to allow a new fetch schemas request"
                );
                cached_peer_subscriptions
                    .subscriptions
                    .remove(&subscription_info.id());
            }
            // clear peer if there are no subscriptions left
            if cached_peer_subscriptions.subscriptions.is_empty() {
                self.peer_cache.remove(&peer.ip());
            }
        }
    }

    /// Get the subscription info from the cache or from the SubscriptionStarted
    /// notification, and the cached content id if it's found in the cache.
    ///
    /// If the notification is a SubscriptionStarted, create a new
    /// SubscriptionInfo and return it. If the notification is not a
    /// SubscriptionStarted, look up the subscription info in the cache.
    fn get_subscription_info(
        &mut self,
        peer: SocketAddr,
        decoded: &UdpNotifPacketDecoded,
    ) -> Option<(SubscriptionInfo, Option<Option<String>>)> {
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let notif_contents = if let Some(notif) = decoded.payload().notification_contents() {
            notif
        } else {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                "Received UDP-Notif payload without a notifications content, dropping packet"
            );
            return None;
        };

        let subscription_info = if let NotificationVariant::SubscriptionStarted(
            subscription_started,
        )
        | NotificationVariant::SubscriptionModified(
            subscription_started,
        ) = notif_contents
        {
            let subscription_info = if let Some(subscription_info) =
                self.build_subscription_info(peer, message_id, publisher_id, subscription_started)
            {
                subscription_info
            } else {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    "Received UDP-Notif of subscription started/modified payload without subscription info, dropping packet"
                );
                return None;
            };
            self.check_subscription_new(peer, &subscription_info);
            Some(subscription_info)
        } else {
            self.peer_cache.get(&peer.ip()).and_then(
                |cached_peer_subscriptions: &CachedPeerSubscriptions| {
                    cached_peer_subscriptions
                        .subscriptions
                        .get(&notif_contents.subscription_id())
                        .map(|x| x.subscription_info.clone())
                },
            )
        };
        if let Some(subscription_info) = subscription_info {
            let cached_content_id = self
                .peer_cache
                .get(&peer.ip())
                .and_then(|cached_peer_subscriptions: &CachedPeerSubscriptions| {
                    cached_peer_subscriptions
                        .subscriptions
                        .get(&notif_contents.subscription_id())
                })
                .filter(|x| x.subscription_info == subscription_info)
                .map(|x| x.cached_content_id.clone());

            Some((subscription_info, cached_content_id))
        } else {
            None
        }
    }

    fn cache_packet(
        &mut self,
        subscription_info: SubscriptionInfo,
        message: Arc<(SocketAddr, UdpNotifPacket)>,
    ) -> bool {
        let (peer, packet) = message.as_ref();
        let peer = *peer;
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let subscription_id = subscription_info.id();
        let peer_cache = self.peer_cache.entry(peer.ip()).or_default();
        let total_cached_packets = peer_cache
            .subscriptions
            .values()
            .map(|x| x.cached_packets.len())
            .sum::<usize>();
        let subscription_cache =
            peer_cache
                .subscriptions
                .entry(subscription_id)
                .or_insert(CachedSubscription {
                    cached_content_id: None,
                    subscription_info: subscription_info.clone(),
                    yang_ctx: None,
                    cached_packets: Vec::new(),
                });
        if subscription_cache.cached_packets.len() > self.max_cached_packets_per_subscription {
            // drop the new packet, since the cache is full
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id,
                subscription_target=%subscription_info.target(),
                router_content_id=subscription_info.content_id(),
                "Cache full for subscription, dropping new packet"
            );
            peer_tags.push(opentelemetry::KeyValue::new(
                OTL_CACHE_DROP_REASON_KEY,
                OTL_CACHE_DROP_REASON_SUBSCRIPTION_CACHE_FULL,
            ));
            self.stats.cache_drop.add(1, &peer_tags);
            return false;
        }
        if total_cached_packets > self.max_cached_packets_per_peer {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id,
                subscription_target=%subscription_info.target(),
                router_content_id=subscription_info.content_id(),
                "Cache full for peer, dropping new packet");
            peer_tags.push(opentelemetry::KeyValue::new(
                OTL_CACHE_DROP_REASON_KEY,
                OTL_CACHE_DROP_REASON_PEER_CACHE_FULL,
            ));
            self.stats.cache_drop.add(1, &peer_tags);
            return false;
        }
        trace!(
            peer=%peer,
            message_id,
            publisher_id,
            subscription_id,
            subscription_target=%subscription_info.target(),
            router_content_id=subscription_info.content_id(),
            "Cached UDP-Notif packet"
        );
        self.stats
            .cached_packets
            .record(total_cached_packets as u64, &peer_tags);
        subscription_cache.cached_packets.push(message);
        true
    }

    fn peer_tags_from_packet(
        peer: SocketAddr,
        packet: &UdpNotifPacket,
    ) -> Vec<opentelemetry::KeyValue> {
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();
        Vec::from([
            opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(peer.port().into()),
            ),
            opentelemetry::KeyValue::new(
                OTL_UDP_NOTIF_MESSAGE_ID_KEY,
                opentelemetry::Value::I64(message_id.into()),
            ),
            opentelemetry::KeyValue::new(
                OTL_UDP_NOTIF_PUBLISHER_ID_KEY,
                opentelemetry::Value::I64(publisher_id.into()),
            ),
        ])
    }

    fn extend_peer_targs_with_subscription_info(
        subscription_info: &SubscriptionInfo,
        peer_tags: &mut Vec<opentelemetry::KeyValue>,
    ) {
        peer_tags.push(opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
            opentelemetry::Value::I64(subscription_info.id().into()),
        ));
        peer_tags.push(opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
            format!("{}", subscription_info.target()),
        ));
        peer_tags.push(opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
            subscription_info.content_id().to_string(),
        ));
    }

    fn decode_message(
        &mut self,
        peer: SocketAddr,
        packet: &UdpNotifPacket,
    ) -> Result<UdpNotifPacketDecoded, ()> {
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);

        // Decode the UDP-Notif packet to get subscription ID and payload information
        match UdpNotifPacketDecoded::try_from(packet) {
            Ok(decoded) => {
                let notif_contents = decoded.payload().notification_contents();
                if let Some(notif_contents) = notif_contents {
                    peer_tags.push(opentelemetry::KeyValue::new(
                        OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                        opentelemetry::Value::I64(notif_contents.subscription_id().into()),
                    ));
                }
                self.stats.messages_received.add(1, &peer_tags);
                Ok(decoded)
            }
            Err(err) => {
                if tracing::enabled!(tracing::Level::TRACE) {
                    warn!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        error=%err,
                        "Failed to decode UDP-Notif payload, dropping packet"
                    );
                } else {
                    warn!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        error=%err,
                        "Failed to decode UDP-Notif payload, dropping packet"
                    );
                }
                peer_tags.push(opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_DECODE_ERROR_ID_KEY,
                    format!("{err}"),
                ));
                self.stats.messages_received.add(1, &peer_tags);
                self.stats.messages_decoding_fail.add(1, &peer_tags);
                Err(())
            }
        }
    }

    async fn process_udp_notif_msg(
        &mut self,
        message: Arc<(SocketAddr, UdpNotifPacket)>,
    ) -> Result<(), ValidationActorError> {
        let (peer, packet) = message.as_ref();
        let peer = *peer;
        let decoded = match self.decode_message(peer, packet) {
            Ok(decoded) => decoded,
            // Decoding errors are logged in the [Self::decode_message], and packets are dropped
            // here
            Err(_) => return Ok(()),
        };
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();

        let extract_sub_info = self
            .extract_subscription_info(Arc::clone(&message), peer, &decoded)
            .await?;
        let subscription_info = if let Some(subscription_info) = extract_sub_info {
            subscription_info
        } else {
            return Ok(());
        };
        Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
        let peer_cache = self.peer_cache.entry(peer.ip()).or_default();
        let subscription_cache = peer_cache
            .subscriptions
            .entry(subscription_info.id())
            .or_insert(CachedSubscription {
                cached_content_id: None,
                subscription_info: subscription_info.clone(),
                yang_ctx: None,
                cached_packets: Vec::new(),
            });
        let cached_content_id = if let Some(cached_content_id) =
            subscription_cache.cached_content_id.clone()
            && let Some(yang_ctx) = subscription_cache.yang_ctx.as_ref()
            && !subscription_info.is_empty()
        {
            let validation_result = Self::validate_message(
                packet,
                peer,
                &subscription_info,
                cached_content_id.clone(),
                yang_ctx,
            );
            // logging of error is handled in the [Self::validate_message]
            if validation_result.is_err() {
                self.stats.validation_invalid.add(1, &peer_tags);
                return Ok(());
            }
            Some(cached_content_id)
        } else {
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                "No YANG schemas found, skipping validation step",
            );
            self.stats.validation_skip.add(1, &peer_tags);
            None
        };

        self.tx
            .send((
                cached_content_id.clone(),
                subscription_info.clone(),
                decoded,
            ))
            .await
            .map_err(|_| {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id=?cached_content_id,
                    "Failed to send UDP-Notif message for the next actor to process"
                );
                ValidationActorError::SendError
            })?;
        self.stats.messages_sent.add(1, &peer_tags);
        trace!(
            peer=%peer,
            message_id,
            publisher_id,
            subscription_id=subscription_info.id(),
            router_content_id=subscription_info.content_id(),
            target=%subscription_info.target(),
            cached_content_id=?cached_content_id,
            "Successfully send UDP-Notif message for the next actor to process"
        );
        Ok(())
    }

    fn validate_message(
        packet: &UdpNotifPacket,
        peer: SocketAddr,
        subscription_info: &SubscriptionInfo,
        cached_content_id: ContentId,
        yang_ctx: &yang4::context::Context,
    ) -> Result<(), yang4::Error> {
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        Self::extend_peer_targs_with_subscription_info(subscription_info, &mut peer_tags);
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();

        let mut envelope_ext = None;
        if let Some(ietf_yo_notif) = yang_ctx.get_module_implemented("ietf-yp-notification")
            && let Some(ext) = ietf_yo_notif.extensions().next()
        {
            envelope_ext = Some(ext);
        }
        if let Some(envelope_ext) = envelope_ext {
            let validation_result = yang4::data::DataTree::parse_ext_string(
                &envelope_ext,
                packet.payload(),
                DataFormat::JSON,
                DataParserFlags::STRICT,
                DataValidationFlags::PRESENT,
            );
            if let Err(err) = validation_result {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    error=%err,
                    "Failed to validate UDP-Notif payload using draft-ietf-netconf-notif-envelope, dropping packet"
                );
                return Err(err);
            }
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id,
                "Successfully validated YANG-Push message using draft-ietf-netconf-notif-envelope",
            );
            Ok(())
        } else {
            let validation_result = yang4::data::DataTree::parse_op_string(
                yang_ctx,
                packet.payload(),
                DataFormat::JSON,
                DataParserFlags::STRICT,
                DataOperation::NotificationYang,
            );
            if let Err(err) = validation_result {
                warn!(
                    peer=%peer,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    error=%err, "Failed to validate legacy UDP-Notif payload, dropping packet");
                return Err(err);
            }
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id,
                "Successfully validated YANG-Push message using legacy UDP-Notif payload",
            );
            Ok(())
        }
    }

    /// Get the subscription info from the message, if not present cache and
    /// send a cache request and return none for the subscription info
    async fn extract_subscription_info(
        &mut self,
        message: Arc<(SocketAddr, UdpNotifPacket)>,
        peer: SocketAddr,
        decoded: &UdpNotifPacketDecoded,
    ) -> Result<Option<SubscriptionInfo>, ValidationActorError> {
        let (_, packet) = message.as_ref();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();

        match self.get_subscription_info(peer, decoded) {
            Some((subscription_info, cached_content_id)) => {
                Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
                if cached_content_id.is_some() {
                    return Ok(Some(subscription_info));
                }
                debug!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    subscription_target=%subscription_info.target(),
                    "Received new subscription sending lookup by subscription info request to the cache"
                );
                self.stats
                    .cache_request_by_subscription_info
                    .add(1, &peer_tags);
                self.cache_cmd_tx
                    .send(CacheLookupCommand::LookupBySubscriptionInfo(
                        subscription_info.clone(),
                        self.cache_tx.clone(),
                    ))
                    .await
                    .map_err(|error| {
                        warn!(
                            message_id,
                            publisher_id,
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            subscription_target=%subscription_info.target(),
                            error=%error,
                            "Error sending lookup by subscription info request to the cache"
                        );
                        ValidationActorError::CacheLookupSendError
                    })?;
                self.cache_packet(subscription_info.clone(), message);
                Ok(None)
            }
            None => {
                let subscription_id = decoded
                    .payload()
                    .notification_contents()
                    .map(|x| x.subscription_id());
                if let Some(subscription_id) = subscription_id {
                    debug!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        subscription_id,
                        "Received UDP-Notif packet without subscription info, \
                        caching the packet and looking up subscription info in cache");
                    self.stats
                        .cache_request_by_subscription_info
                        .add(1, &peer_tags);
                    self.cache_cmd_tx
                        .send(CacheLookupCommand::LookupBySubscriptionId {
                            peer,
                            subscription_id,
                            tx: self.cache_tx.clone(),
                        })
                        .await
                        .map_err(|_| ValidationActorError::CacheLookupSendError)?;
                    self.cache_packet(SubscriptionInfo::new_empty(peer, subscription_id), message);
                    return Ok(None);
                }
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    "Received UDP-Notif packet without subscription info nor subscription ID, dropping packet"
                );
                self.stats.validation_invalid.add(1, &peer_tags);
                Ok(None)
            }
        }
    }

    async fn process_cache_response(
        &mut self,
        response: CacheResponse,
    ) -> Result<(), ValidationActorError> {
        let (cached_content_id, subscription_info, yang_lib_ref) = response.into();
        let mut otl_tags = Vec::from([
            opentelemetry::KeyValue::new(
                "network.peer.address",
                format!("{}", subscription_info.peer().ip()),
            ),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(subscription_info.peer().port().into()),
            ),
        ]);
        Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut otl_tags);
        let peer_cache = if let Some(peer_cache) =
            self.peer_cache.get_mut(&subscription_info.peer().ip())
        {
            peer_cache
        } else {
            warn!(
                peer=%subscription_info.peer(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id,
                "Received cache response for subscription from peer that is not in the cache, ignoring the response"
            );
            return Ok(());
        };

        let subscription_cache = if let Some(subscription_cache) =
            peer_cache.subscriptions.get_mut(&subscription_info.id())
        {
            subscription_cache
        } else {
            warn!(
                peer=%subscription_info.peer(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id,
                "Received cache response for subscription that is not in the cache, ignoring the response");
            return Ok(());
        };

        // Update subscription info in the cache
        subscription_cache.subscription_info = subscription_info.clone();
        if let Some(yang_lib_ref) = yang_lib_ref {
            let search_dir = yang_lib_ref.search_dir();
            let yang_ctx_result = yang4::context::Context::new_from_yang_library_file(
                &yang_lib_ref.yang_library_path(),
                DataFormat::XML,
                &search_dir.as_path(),
                yang4::context::ContextFlags::empty(),
            );
            let yang_ctx = match yang_ctx_result {
                Ok(yang_ctx) => {
                    self.stats.cache_yang_ctx_created.add(1, &otl_tags);
                    Some(yang_ctx)
                }
                Err(err) => {
                    self.stats.cache_yang_ctx_invalid.add(1, &otl_tags);
                    warn!(
                        peer=%subscription_info.peer(),
                        subscription_id=subscription_info.id(),
                        router_content_id=subscription_info.content_id(),
                        cached_content_id=yang_lib_ref.content_id(),
                        yang_library_path=%yang_lib_ref.yang_library_path().display(),
                        search_dir=%search_dir.display(),
                        error=%err,
                        "Failed to create YANG context, disabling YANG validation for this subscription");
                    None
                }
            };
            subscription_cache.cached_content_id = cached_content_id.clone();
            subscription_cache.yang_ctx = yang_ctx;
        } else {
            self.stats.cache_yang_ctx_empty.add(1, &otl_tags);
            subscription_cache.cached_content_id = None;
            subscription_cache.yang_ctx = None;
        }
        let cached_packets = std::mem::take(&mut subscription_cache.cached_packets);
        for msg in cached_packets {
            let (peer, packet) = msg.as_ref();
            let peer = *peer;
            let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
            Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
            self.stats.cache_drain.add(1, &peer_tags);
            trace!(
                peer=%peer,
                message_id=packet.message_id(),
                publisher_id=packet.publisher_id(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                subscription_target=%subscription_info.target(),
                cached_content_id,
                "Packet popped out of the cache and being processed by the validation step"
            );
            self.process_udp_notif_msg(msg).await?;
        }
        Ok(())
    }

    fn build_subscription_info(
        &self,
        peer: SocketAddr,
        message_id: u32,
        publisher_id: u32,
        sub_started: &SubscriptionStartedModified,
    ) -> Option<SubscriptionInfo> {
        let modules = match sub_started.module_version() {
            Some(modules) => {
                let mut module_names: Vec<String> =
                    modules.iter().map(|m| m.name().to_string()).collect();
                module_names.push("ietf-subscribed-notifications".to_string());
                module_names
            }
            None => {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=sub_started.id(),
                    subscription_target=%sub_started.target(),
                    "SubscriptionStarted missing module version"
                );
                return None;
            }
        };

        Some(SubscriptionInfo::new(
            peer,
            sub_started.id(),
            sub_started
                .yang_library_content_id()
                .map(|x| x.to_string())
                .unwrap_or_default(),
            sub_started.target().clone(),
            modules,
        ))
    }

    async fn run(mut self) -> Result<String, ValidationActorError> {
        info!("Starting Yang-Push validation actor");
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
                            let msg = "Yang Push validation actor terminated due to command channel closing";
                            warn!(msg);
                            Ok(msg.to_string())
                        }
                    }
                }
                msg = self.rx.recv() => {
                    match msg {
                        Ok(msg) => {
                            if let Err(err) = self.process_udp_notif_msg(msg).await {
                                let err_msg = "Yang Push validation actor UDP-Notif processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "Yang Push validation actor UDP Notif receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
                msg = self.cache_rx.recv() => {
                    match msg {
                        Ok(response) => {
                            if let Err(err) = self.process_cache_response(response).await {
                                let err_msg = "Yang Push validation actor cache response processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "Yang Push validation actor cache receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum ValidationActorHandleError {
    #[strum(serialize = "Failed to send command to actor")]
    SendErr,
}

impl std::error::Error for ValidationActorHandleError {}

#[derive(Debug, Clone)]
pub struct ValidationActorHandle {
    cmd_tx: mpsc::Sender<ValidationActorCommand>,
}

impl ValidationActorHandle {
    pub fn new(
        buffer_size: usize,
        max_cached_packets_per_peer: usize,
        max_cached_packets_per_subscription: usize,
        rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        tx: async_channel::Sender<(Option<ContentId>, SubscriptionInfo, UdpNotifPacketDecoded)>,
        cache_cmd_tx: async_channel::Sender<CacheLookupCommand>,
        stats: either::Either<opentelemetry::metrics::Meter, ValidationStats>,
    ) -> Result<
        (
            tokio::task::JoinHandle<Result<String, ValidationActorError>>,
            Self,
        ),
        ValidationActorHandleError,
    > {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let (cache_tx, cache_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => ValidationStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = ValidationActor {
            max_cached_packets_per_peer,
            max_cached_packets_per_subscription,
            peer_cache: FxHashMap::default(),
            cmd_rx,
            rx,
            tx,
            cache_cmd_tx,
            cache_tx,
            cache_rx,
            stats,
        };
        let handle = ValidationActorHandle { cmd_tx };
        let join_handle = tokio::spawn(async move { actor.run().await });
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), ValidationActorHandleError> {
        self.cmd_tx
            .send(ValidationActorCommand::Shutdown)
            .await
            .map_err(|_| ValidationActorHandleError::SendErr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::actor::tests::setup_actor_with_empty_cache;
    use bytes::Bytes;
    use netgauze_udp_notif_pkt::raw::MediaType;
    use std::collections::HashMap;
    use std::time::Duration;

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_validation_actor_schema_fetched() {
        // Setup caching actor
        let (caching_join_handle, caching_handle, subscription_info, fetcher_count) =
            setup_actor_with_empty_cache();
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 0);
        }

        // Setup channels
        let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
        let (validated_tx, validated_rx) = async_channel::bounded(100);

        // Spawn validation actor
        let (_join_handle, handle) = ValidationActorHandle::new(
            100,
            1000,
            100,
            udp_notif_rx,
            validated_tx,
            caching_handle.request_tx(),
            either::Right(ValidationStats::new(opentelemetry::global::meter(
                "test_meter",
            ))),
        )
        .expect("Failed to spawn validation actor");

        // Create a test peer address
        let peer = subscription_info.peer();
        let payload = serde_json::json!(
            {
                "ietf-yp-notification:envelope": {
                    "event-time": "2025-09-23T14:12:16.024Z",
                    "hostname": "ipf-zbl1327-r-daisy-48",
                    "sequence-number": 0,
                    "contents": {
                        "ietf-subscribed-notifications:subscription-started": {
                            "id": 1,
                            "ietf-yang-push:datastore": "ietf-datastores:operational",
                            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
                            "transport": "ietf-udp-notif-transport:udp-notif",
                            "encoding": "encode-json",
                            "ietf-distributed-notif:message-publisher-id": [
                                16843789
                            ],
                            "ietf-yang-push-revision:module-version": [
                                {
                                    "name": "ietf-interfaces",
                                    "revision": ""
                                }
                            ],
                            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
                            "ietf-yang-push:periodic": {
                                "period": 6000
                            }
                        }
                    }
                }
            }
        );
        let bytes = serde_json::to_vec(&payload).unwrap();
        let subscription_started_packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            10,
            1,
            HashMap::new(),
            Bytes::from(bytes),
        );

        // Send SubscriptionStarted packet
        udp_notif_tx
            .send(Arc::new((peer, subscription_started_packet)))
            .await
            .unwrap();

        // Allow actor to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify packet is validated
        let (content_id, sub_info, _validated) = validated_rx.recv().await.unwrap();
        assert!(content_id.is_some());
        assert!(!sub_info.is_empty());

        // check fetcher was called
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 1);
        }

        // Shutdown actor
        handle.shutdown().await.unwrap();
        caching_handle.shutdown().await.unwrap();
        caching_join_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_validation_actor_schema_not_found() {
        // Setup caching actor
        let (caching_join_handle, caching_handle, subscription_info, fetcher_count) =
            setup_actor_with_empty_cache();
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 0);
        }

        // Setup channels
        let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
        let (validated_tx, validated_rx) = async_channel::bounded(100);

        // Spawn validation actor
        let (_join_handle, handle) = ValidationActorHandle::new(
            100,
            1000,
            100,
            udp_notif_rx,
            validated_tx,
            caching_handle.request_tx(),
            either::Right(ValidationStats::new(opentelemetry::global::meter(
                "test_meter",
            ))),
        )
        .expect("Failed to spawn validation actor");

        // Create a test peer address
        let peer = subscription_info.peer();
        let payload = serde_json::json!(
            {
                "ietf-yp-notification:envelope": {
                    "event-time": "2025-09-23T14:12:16.024Z",
                    "hostname": "ipf-zbl1327-r-daisy-48",
                    "sequence-number": 0,
                    "contents": {
                        "ietf-subscribed-notifications:subscription-started": {
                            "id": 2,
                            "ietf-yang-push:datastore": "ietf-datastores:operational",
                            "ietf-yang-push:datastore-xpath-filter": "/ietf-hardware:hardware",
                            "transport": "ietf-udp-notif-transport:udp-notif",
                            "encoding": "encode-json",
                            "ietf-distributed-notif:message-publisher-id": [
                                16843789
                            ],
                            "ietf-yang-push-revision:module-version": [
                                {
                                    "name": "ietf-hardware",
                                    "revision": ""
                                }
                            ],
                            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
                            "ietf-yang-push:periodic": {
                                "period": 6000
                            }
                        }
                    }
                }
            }
        );
        let bytes = serde_json::to_vec(&payload).unwrap();
        let subscription_started_packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            10,
            1,
            HashMap::new(),
            Bytes::from(bytes),
        );

        // Send SubscriptionStarted packet
        udp_notif_tx
            .send(Arc::new((peer, subscription_started_packet)))
            .await
            .unwrap();

        // Allow actor to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify packet is not validated
        let (content_id, sub_info, _validated) =
            tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
                .await
                .unwrap()
                .unwrap();
        assert!(content_id.is_none());
        assert!(!sub_info.is_empty());

        // check fetcher was called
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 1);
        }

        // Shutdown actor
        handle.shutdown().await.unwrap();
        caching_handle.shutdown().await.unwrap();
        caching_join_handle.await.unwrap().unwrap();
    }
}
