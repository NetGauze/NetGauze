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
//!     Duration::from_secs(60), // pending schema lookup timeout
//!     true,  // validate anydata content (datastore-contents) strictly
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
//! 4. **Cache or Validate** (driven by the per-subscription SchemaState):
//!    - `Resolved` with a loaded context: Validate and forward
//!    - `Pending` (lookup in flight): Buffer *every* packet of the
//!      subscription, including data packets that arrive right after the
//!      `SubscriptionStarted`, so nothing bypasses validation or is forwarded
//!      out of order
//!    - `Unavailable` (cache answered with no schema, or the lookup timed out
//!      after `pending_lookup_timeout`): Forward unvalidated
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
//!   - `yang5::Context`: Loaded YANG schemas for validation
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
//! - **Schema available**: Validates using `yang5` library
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

use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::cache::storage::SubscriptionInfo;
use crate::{
    ContentId, OTL_CACHE_DROP_REASON_KEY, OTL_CACHE_DROP_REASON_PEER_CACHE_FULL,
    OTL_CACHE_DROP_REASON_SUBSCRIPTION_CACHE_FULL, OTL_YANG_PUSH_DECODE_ERROR_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use netgauze_netconf_proto::yang_push::subscription::YangPushModuleVersion;
use netgauze_netconf_proto::yang_push::types::SubscriptionId;
use netgauze_udp_notif_pkt::decoded::{UdpNotifPacketDecoded, UdpNotifPayload};
use netgauze_udp_notif_pkt::notification::{NotificationVariant, SubscriptionStartedModified};
use netgauze_udp_notif_pkt::raw::UdpNotifPacket;
use netgauze_udp_notif_service::{OTL_UDP_NOTIF_PUBLISHER_ID_KEY, UdpNotifRequest};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};
use yang5::data::{DataFormat, DataOperation, DataParserFlags, DataValidationFlags};

/// Default upper bound on how long packets are buffered while a schema lookup
/// is in flight before the subscription is marked SchemaState::Unavailable
/// and the buffered packets are forwarded unvalidated.
pub const DEFAULT_PENDING_LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);

/// How often the actor scans for pending lookups that exceeded the timeout.
const PENDING_LOOKUP_SCAN_INTERVAL: Duration = Duration::from_secs(1);

/// Where a subscription is in the schema-resolution lifecycle.
///
/// Modelling this explicitly (rather than with `Option<ContentId>`) is what
/// prevents packets from being forwarded unvalidated while the cache lookup
/// for their subscription is still outstanding.
#[derive(Debug)]
enum SchemaState {
    /// A lookup was sent to the cache actor and no answer has been received
    /// yet. All packets for this subscription are buffered until the answer
    /// arrives (or the pending timeout expires).
    Pending { since: Instant },
    /// The cache actor answered with a YANG library reference. `yang_ctx` is
    /// `None` only if loading the schemas into libyang failed, in which case
    /// packets are forwarded unvalidated.
    Resolved {
        content_id: ContentId,
        yang_ctx: Option<yang5::context::Context>,
    },
    /// The cache actor answered that no schemas are available for this
    /// subscription (or the lookup timed out). Packets are forwarded
    /// unvalidated.
    Unavailable,
}

#[derive(Debug)]
struct CachedSubscription {
    subscription_info: SubscriptionInfo,
    state: SchemaState,
    cached_packets: Vec<Arc<UdpNotifRequest>>,
}

impl CachedSubscription {
    fn pending(subscription_info: SubscriptionInfo) -> Self {
        Self {
            subscription_info,
            state: SchemaState::Pending {
                since: Instant::now(),
            },
            cached_packets: Vec::new(),
        }
    }

    const fn is_pending(&self) -> bool {
        matches!(self.state, SchemaState::Pending { .. })
    }
}

#[derive(Debug, Default)]
struct CachedPeerSubscriptions {
    subscriptions: FxHashMap<SubscriptionId, CachedSubscription>,
}

/// Outcome of looking a packet's subscription up in the local cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupStatus {
    /// No (matching) entry: a lookup must be sent to the cache actor.
    Missing,
    /// Entry exists and its lookup is still in flight.
    Pending,
    /// Entry exists and the cache actor already answered.
    Settled,
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
    pub cache_lookup_timeout: opentelemetry::metrics::Counter<u64>,
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
        let cache_lookup_timeout = meter
            .u64_counter("netgauze.collector.yang_push.validation.cache.lookup.timeout")
            .with_description("Number of subscriptions whose schema lookup did not get an answer from the cache actor within the pending timeout; their buffered packets are forwarded unvalidated")
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
            cache_lookup_timeout,
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

/// Run CPU-heavy, blocking work without stalling the async runtime: on the
/// multi-thread runtime the worker hands its queued tasks to other workers for
/// the duration (`block_in_place`); on a current-thread runtime (tests) the
/// closure is simply called.
fn run_blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

struct ValidationActor {
    max_cached_packets_per_peer: usize,
    max_cached_packets_per_subscription: usize,
    pending_lookup_timeout: Duration,
    /// Validate the content of `anydata` nodes (the `datastore-contents` of a
    /// push-update, the `datastore-changes` of a push-change-update) against
    /// the subscription's YANG schemas instead of accepting any JSON there
    /// (`yang5::data::DataParserFlags::ANYDATA_STRICT`).
    anydata_strict: bool,
    peer_cache: FxHashMap<IpAddr, CachedPeerSubscriptions>,
    cmd_rx: mpsc::Receiver<ValidationActorCommand>,
    rx: async_channel::Receiver<Arc<UdpNotifRequest>>,
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
    /// new request to the caching actor. Packets that were buffered under the
    /// old entry are returned so the caller can carry them over into the new
    /// entry instead of silently dropping them.
    fn check_subscription_new(
        &mut self,
        peer: SocketAddr,
        subscription_info: &SubscriptionInfo,
    ) -> Vec<Arc<UdpNotifRequest>> {
        let mut displaced = Vec::new();
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
                if let Some(old) = cached_peer_subscriptions
                    .subscriptions
                    .remove(&subscription_info.id())
                {
                    displaced = old.cached_packets;
                }
            }
            // clear peer if there are no subscriptions left
            if cached_peer_subscriptions.subscriptions.is_empty() {
                self.peer_cache.remove(&peer.ip());
            }
        }
        displaced
    }

    /// Get the subscription info from the cache or from the SubscriptionStarted
    /// notification, together with the state of its schema lookup.
    ///
    /// If the notification is a SubscriptionStarted, create a new
    /// SubscriptionInfo and return it. If the notification is not a
    /// SubscriptionStarted, look up the subscription info in the cache.
    ///
    /// For a SubscriptionStarted that differs from the cached entry, the old
    /// entry is removed and any packets buffered under it are returned as the
    /// third element so they can be re-queued under the new entry.
    fn get_subscription_info(
        &mut self,
        peer: SocketAddr,
        collector: SocketAddr,
        interface: Option<String>,
        decoded: &UdpNotifPacketDecoded,
    ) -> Option<(SubscriptionInfo, LookupStatus, Vec<Arc<UdpNotifRequest>>)> {
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

        let mut displaced = Vec::new();
        let subscription_info = if let NotificationVariant::SubscriptionStarted(
            subscription_started,
        )
        | NotificationVariant::SubscriptionModified(
            subscription_started,
        ) = notif_contents
        {
            let subscription_info = if let Some(subscription_info) = self.build_subscription_info(
                peer,
                collector,
                interface,
                message_id,
                publisher_id,
                subscription_started,
            ) {
                subscription_info
            } else {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    notifification_type=%notif_contents.notification_type(),
                    "Received UDP-Notif of subscription started/modified payload without subscription info, dropping packet"
                );
                return None;
            };
            displaced = self.check_subscription_new(peer, &subscription_info);
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
        let subscription_info = subscription_info?;
        let status = self
            .peer_cache
            .get(&peer.ip())
            .and_then(|cached_peer_subscriptions: &CachedPeerSubscriptions| {
                cached_peer_subscriptions
                    .subscriptions
                    .get(&notif_contents.subscription_id())
            })
            .filter(|x| x.subscription_info == subscription_info)
            .map(|x| {
                if x.is_pending() {
                    LookupStatus::Pending
                } else {
                    LookupStatus::Settled
                }
            })
            .unwrap_or(LookupStatus::Missing);
        Some((subscription_info, status, displaced))
    }

    fn cache_packet(
        &mut self,
        subscription_info: SubscriptionInfo,
        message: Arc<UdpNotifRequest>,
    ) -> bool {
        let peer = message.peer_address();
        let packet = message.packet();
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
        let subscription_cache = peer_cache
            .subscriptions
            .entry(subscription_id)
            .or_insert_with(|| CachedSubscription::pending(subscription_info.clone()));
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
        let publisher_id = packet.publisher_id();
        Vec::from([
            opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(peer.port().into()),
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

        // Decode the UDP-Notif packet to get subscription ID and payload
        // information
        match UdpNotifPacketDecoded::try_from(packet) {
            Ok(decoded) => {
                let notif_contents = decoded.payload().notification_contents();
                if let Some(notif_contents) = notif_contents {
                    peer_tags.push(opentelemetry::KeyValue::new(
                        OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                        opentelemetry::Value::I64(notif_contents.subscription_id().into()),
                    ));
                }
                if tracing::enabled!(tracing::Level::TRACE) {
                    let notification_type = decoded
                        .notification_type()
                        .map(|x| x.to_string())
                        .unwrap_or("UNKNOWN".to_string());
                    trace!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        notification_type,
                        "Decoded UDP-Notif payload, starting the validation step"
                    );
                }
                self.stats.messages_received.add(1, &peer_tags);
                Ok(decoded)
            }
            Err(err) => {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    error=%err,
                    "Failed to decode UDP-Notif payload, dropping packet"
                );
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
        message: Arc<UdpNotifRequest>,
    ) -> Result<(), ValidationActorError> {
        let peer = message.peer_address();
        let packet = message.packet();
        let decoded = match self.decode_message(peer, packet) {
            Ok(decoded) => decoded,
            // Decoding errors are logged in the [Self::decode_message],
            // and packets are dropped here
            Err(_) => return Ok(()),
        };
        let notification_type = decoded
            .notification_type()
            .map(|x| x.to_string())
            .unwrap_or("UNKNOWN".to_string());
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let is_legacy = matches!(decoded.payload(), UdpNotifPayload::NotificationLegacy(_));
        let extract_sub_info = self
            .extract_subscription_info(Arc::clone(&message), peer, &decoded)
            .await?;
        let subscription_info = if let Some(subscription_info) = extract_sub_info {
            subscription_info
        } else {
            return Ok(());
        };
        Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
        // `extract_subscription_info` only hands back a subscription whose
        // lookup has settled; anything still pending was buffered there.
        let schema = self
            .peer_cache
            .get(&peer.ip())
            .and_then(|x| x.subscriptions.get(&subscription_info.id()))
            .and_then(|x| match &x.state {
                SchemaState::Resolved {
                    content_id,
                    yang_ctx: Some(yang_ctx),
                } if !subscription_info.is_empty() => Some((content_id.clone(), yang_ctx)),
                _ => None,
            });
        let cached_content_id = if let Some((cached_content_id, yang_ctx)) = schema {
            let validation_result = Self::validate_message(
                packet,
                peer,
                &subscription_info,
                cached_content_id.clone(),
                &notification_type,
                yang_ctx,
                is_legacy,
                self.anydata_strict,
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
                notification_type,
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
                    cached_content_id=cached_content_id.clone().unwrap_or_default(),
                    notification_type,
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
            cached_content_id=cached_content_id.unwrap_or_default(),
            notification_type,
            "Successfully send UDP-Notif message for the next actor to process"
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_message(
        packet: &UdpNotifPacket,
        peer: SocketAddr,
        subscription_info: &SubscriptionInfo,
        cached_content_id: ContentId,
        notification_type: &String,
        yang_ctx: &yang5::context::Context,
        is_legacy: bool,
        anydata_strict: bool,
    ) -> Result<(), yang5::Error> {
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        Self::extend_peer_targs_with_subscription_info(subscription_info, &mut peer_tags);
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();
        let mut parser_flags = DataParserFlags::STRICT;
        if anydata_strict {
            parser_flags |= DataParserFlags::ANYDATA_STRICT;
        }

        if !is_legacy {
            let validation_result = yang5::data::DataTree::parse_string(
                yang_ctx,
                packet.payload(),
                DataFormat::JSON,
                parser_flags,
                DataValidationFlags::PRESENT,
            );
            if let Err(err) = validation_result {
                let v = packet.payload().clone();
                let packet_payload =
                    str::from_utf8(v.as_ref()).unwrap_or("unserializable packet payload");
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    notification_type,
                    error=%err,
                    packet=packet_payload,
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
                notification_type,
                cached_content_id,
                "Successfully validated YANG-Push message using draft-ietf-netconf-notif-envelope",
            );
            Ok(())
        } else {
            let validation_result = yang5::data::DataTree::parse_op_string(
                yang_ctx,
                packet.payload(),
                DataFormat::JSON,
                parser_flags,
                DataOperation::NotificationYang,
            );
            if let Err(err) = validation_result {
                warn!(
                    peer=%peer,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    notification_type,
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
                notification_type,
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
        message: Arc<UdpNotifRequest>,
        peer: SocketAddr,
        decoded: &UdpNotifPacketDecoded,
    ) -> Result<Option<SubscriptionInfo>, ValidationActorError> {
        let collector = message.collector_address();
        let interface = message.collector_interface();
        let packet = message.packet();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let notification_type = decoded
            .notification_type()
            .map(|x| x.to_string())
            .unwrap_or("UNKNOWN".to_string());

        match self.get_subscription_info(peer, collector, interface.map(String::from), decoded) {
            Some((subscription_info, LookupStatus::Settled, _)) => Ok(Some(subscription_info)),
            Some((subscription_info, LookupStatus::Pending, _)) => {
                // A lookup for this subscription is already in flight: hold the
                // packet so it is validated (and forwarded in order) once the
                // cache actor answers, instead of letting it bypass validation.
                trace!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    subscription_target=%subscription_info.target(),
                    notification_type,
                    "Schema lookup in flight for subscription, buffering packet until the cache answers"
                );
                self.cache_packet(subscription_info, message);
                Ok(None)
            }
            Some((subscription_info, LookupStatus::Missing, displaced)) => {
                Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
                debug!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    subscription_target=%subscription_info.target(),
                    notification_type,
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
                            notification_type,
                            error=%error,
                            "Error sending lookup by subscription info request to the cache"
                        );
                        ValidationActorError::CacheLookupSendError
                    })?;
                // Packets that were buffered under the previous version of
                // this subscription arrived earlier, so they go first.
                for old in displaced {
                    self.cache_packet(subscription_info.clone(), old);
                }
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
                        notification_type,
                        "Received UDP-Notif packet without subscription info, \
                        caching the packet and looking up subscription info in cache");
                    self.stats
                        .cache_request_by_subscription_info
                        .add(1, &peer_tags);
                    let subscription_info = SubscriptionInfo::new_empty(
                        collector,
                        interface.map(String::from),
                        peer.ip(),
                        subscription_id,
                    );
                    self.cache_cmd_tx
                        .send(CacheLookupCommand::LookupBySubscriptionId {
                            collector,
                            interface: interface.map(String::from),
                            peer: peer.ip(),
                            subscription_id,
                            tx: self.cache_tx.clone(),
                        })
                        .await
                        .map_err(|_| ValidationActorError::CacheLookupSendError)?;
                    self.cache_packet(subscription_info.clone(), message);
                    return Ok(None);
                }
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    notification_type,
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
        let mut otl_tags = Vec::from([opentelemetry::KeyValue::new(
            "network.peer.address",
            format!("{}", subscription_info.peer()),
        )]);
        Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut otl_tags);
        let peer_cache = if let Some(peer_cache) =
            self.peer_cache.get_mut(&subscription_info.peer())
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
        if let (Some(yang_lib_ref), Some(content_id)) = (yang_lib_ref, cached_content_id.clone()) {
            let search_dir = yang_lib_ref.search_dir();
            // Building a libyang context for a device library (hundreds of
            // modules) takes seconds of CPU. Doing that inline would stall the
            // tokio worker, and with it the UDP listener that shares the
            // runtime: the kernel socket buffer then overflows and packets are
            // lost (observed with 44 subscriptions announced in one second).
            let yang_ctx_result = run_blocking(|| {
                yang5::context::Context::new_from_yang_library_file(
                    &yang_lib_ref.yang_library_path(),
                    DataFormat::XML,
                    &search_dir.as_path(),
                    yang5::context::ContextFlags::empty(),
                )
            });
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
            subscription_cache.state = SchemaState::Resolved {
                content_id,
                yang_ctx,
            };
        } else {
            self.stats.cache_yang_ctx_empty.add(1, &otl_tags);
            subscription_cache.state = SchemaState::Unavailable;
        }
        let cached_packets = std::mem::take(&mut subscription_cache.cached_packets);
        for message in cached_packets {
            let peer = message.peer_address();
            let packet = message.packet();
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
            self.process_udp_notif_msg(message).await?;
        }
        Ok(())
    }

    fn build_subscription_info(
        &self,
        peer: SocketAddr,
        collector: SocketAddr,
        interface: Option<String>,
        message_id: u32,
        publisher_id: u32,
        sub_started: &SubscriptionStartedModified,
    ) -> Option<SubscriptionInfo> {
        let modules = match sub_started.module_version() {
            Some(modules) => {
                let mut modules = modules.to_vec();
                modules.push(YangPushModuleVersion::new(
                    "ietf-subscribed-notifications".into(),
                    None,
                    None,
                ));
                modules.into_boxed_slice()
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
            collector,
            interface,
            peer.ip(),
            sub_started.id(),
            sub_started.target().clone(),
            sub_started.stop_time().cloned(),
            sub_started.transport().cloned(),
            sub_started.encoding().cloned(),
            sub_started.purpose().map(|x| x.into()),
            sub_started.update_trigger().cloned(),
            modules,
            sub_started
                .yang_library_content_id()
                .map(|x| x.to_string())
                .unwrap_or_default(),
        ))
    }

    /// Flip subscriptions whose schema lookup has been pending for longer than
    /// `pending_lookup_timeout` to [SchemaState::Unavailable] and release
    /// their buffered packets unvalidated.
    ///
    /// The cache actor answers every lookup in normal operation (hit, miss, or
    /// fetch failure), so this is a safety net that bounds how long packets
    /// can be held if an answer never arrives.
    async fn expire_pending_lookups(&mut self) -> Result<(), ValidationActorError> {
        let now = Instant::now();
        let mut expired: Vec<(SubscriptionInfo, Vec<Arc<UdpNotifRequest>>)> = Vec::new();
        for peer_cache in self.peer_cache.values_mut() {
            for subscription_cache in peer_cache.subscriptions.values_mut() {
                if let SchemaState::Pending { since } = subscription_cache.state
                    && now.duration_since(since) >= self.pending_lookup_timeout
                {
                    subscription_cache.state = SchemaState::Unavailable;
                    expired.push((
                        subscription_cache.subscription_info.clone(),
                        std::mem::take(&mut subscription_cache.cached_packets),
                    ));
                }
            }
        }
        for (subscription_info, cached_packets) in expired {
            let mut otl_tags = Vec::from([opentelemetry::KeyValue::new(
                "network.peer.address",
                format!("{}", subscription_info.peer()),
            )]);
            Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut otl_tags);
            self.stats.cache_lookup_timeout.add(1, &otl_tags);
            warn!(
                peer=%subscription_info.peer(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                buffered_packets=cached_packets.len(),
                timeout=?self.pending_lookup_timeout,
                "Schema lookup for subscription did not complete within the pending timeout, forwarding buffered packets unvalidated"
            );
            for message in cached_packets {
                let peer = message.peer_address();
                let mut peer_tags = Self::peer_tags_from_packet(peer, message.packet());
                Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
                self.stats.cache_drain.add(1, &peer_tags);
                self.process_udp_notif_msg(message).await?;
            }
        }
        Ok(())
    }

    async fn run(mut self) -> Result<String, ValidationActorError> {
        info!("Starting Yang-Push validation actor");
        let mut expiry_tick = tokio::time::interval(PENDING_LOOKUP_SCAN_INTERVAL);
        expiry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
                _ = expiry_tick.tick() => {
                    if let Err(err) = self.expire_pending_lookups().await {
                        let err_msg = "Yang Push validation actor failed to release packets of a timed-out schema lookup, shutting down";
                        warn!(error=%err, err_msg);
                        return Ok(err_msg.to_string());
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        buffer_size: usize,
        max_cached_packets_per_peer: usize,
        max_cached_packets_per_subscription: usize,
        pending_lookup_timeout: Duration,
        anydata_strict: bool,
        rx: async_channel::Receiver<Arc<UdpNotifRequest>>,
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
            pending_lookup_timeout,
            anydata_strict,
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
            DEFAULT_PENDING_LOOKUP_TIMEOUT,
            false,
            udp_notif_rx,
            validated_tx,
            caching_handle.request_tx(),
            either::Right(ValidationStats::new(opentelemetry::global::meter(
                "test_meter",
            ))),
        )
        .expect("Failed to spawn validation actor");

        // Create a test peer address
        let peer = SocketAddr::new(subscription_info.peer(), 12345);
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
                            "purpose": "test subscription",
                            "ietf-distributed-notif:message-publisher-id": [
                                16843789
                            ],
                            "ietf-yang-push-revision:module-version": [
                                {
                                    "name": "ietf-interfaces",
                                    "revision": "2018-02-20"
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
            .send(Arc::new(UdpNotifRequest::new(
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
                subscription_started_packet,
            )))
            .await
            .unwrap();

        // Allow actor to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify packet is validated
        let (content_id, sub_info, _validated) =
            tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
                .await
                .expect("timeout waiting for response")
                .unwrap();
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
            DEFAULT_PENDING_LOOKUP_TIMEOUT,
            false,
            udp_notif_rx,
            validated_tx,
            caching_handle.request_tx(),
            either::Right(ValidationStats::new(opentelemetry::global::meter(
                "test_meter",
            ))),
        )
        .expect("Failed to spawn validation actor");

        // Create a test peer address
        let peer = SocketAddr::new(subscription_info.peer(), 12345);
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
            .send(Arc::new(UdpNotifRequest::new(
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
                subscription_started_packet,
            )))
            .await
            .unwrap();

        // Allow actor to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify packet is not validated
        let (content_id, sub_info, _validated) =
            tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
                .await
                .expect("timeout waiting for response")
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

    /// Regression test: a data packet that arrives while the schema lookup
    /// triggered by its `SubscriptionStarted` is still in flight must be
    /// buffered and validated once the schemas are available, not forwarded
    /// unvalidated (and out of order) with an empty content id.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_validation_actor_buffers_data_packets_while_lookup_pending() {
        let (caching_join_handle, caching_handle, subscription_info, fetcher_count) =
            setup_actor_with_empty_cache();

        let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
        let (validated_tx, validated_rx) = async_channel::bounded(100);

        let (_join_handle, handle) = ValidationActorHandle::new(
            100,
            1000,
            100,
            DEFAULT_PENDING_LOOKUP_TIMEOUT,
            false,
            udp_notif_rx,
            validated_tx,
            caching_handle.request_tx(),
            either::Right(ValidationStats::new(opentelemetry::global::meter(
                "test_meter",
            ))),
        )
        .expect("Failed to spawn validation actor");

        let peer = SocketAddr::new(subscription_info.peer(), 12345);
        let collector = SocketAddr::from(([127, 0, 0, 1], 10000));
        let started = serde_json::json!(
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
                            "purpose": "test subscription",
                            "ietf-distributed-notif:message-publisher-id": [16843789],
                            "ietf-yang-push-revision:module-version": [
                                {"name": "ietf-interfaces", "revision": "2018-02-20"}
                            ],
                            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
                            "ietf-yang-push:periodic": {"period": 6000}
                        }
                    }
                }
            }
        );
        let push_update = serde_json::json!(
            {
                "ietf-yp-notification:envelope": {
                    "event-time": "2025-09-23T14:12:17.024Z",
                    "hostname": "ipf-zbl1327-r-daisy-48",
                    "sequence-number": 1,
                    "contents": {
                        "ietf-yang-push:push-update": {
                            "id": 1,
                            "datastore-contents": {
                                "ietf-interfaces:interfaces": {
                                    "interface": [{"name": "eth0"}]
                                }
                            }
                        }
                    }
                }
            }
        );
        let mk = |message_id: u32, payload: &serde_json::Value| {
            Arc::new(UdpNotifRequest::new(
                collector,
                None,
                peer,
                UdpNotifPacket::new(
                    MediaType::YangDataJson,
                    10,
                    message_id,
                    HashMap::new(),
                    Bytes::from(serde_json::to_vec(payload).unwrap()),
                ),
            ))
        };

        // Queue the SubscriptionStarted and a data packet back to back, so the
        // data packet is processed before the cache actor can answer the
        // lookup triggered by the SubscriptionStarted.
        udp_notif_tx.send(mk(1, &started)).await.unwrap();
        udp_notif_tx.send(mk(2, &push_update)).await.unwrap();

        let mut received = Vec::new();
        for _ in 0..2 {
            let item = tokio::time::timeout(Duration::from_secs(2), validated_rx.recv())
                .await
                .expect("timeout waiting for forwarded packet")
                .unwrap();
            received.push(item);
        }
        // Nothing else must come out: the data packet is forwarded once.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), validated_rx.recv())
                .await
                .is_err(),
            "unexpected extra packet forwarded"
        );

        let types: Vec<String> = received
            .iter()
            .map(|(_, _, decoded)| {
                decoded
                    .notification_type()
                    .map(|x| x.to_string())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(
            types,
            vec![
                "SubscriptionStarted".to_string(),
                "YangPushUpdate".to_string()
            ],
            "packets must be forwarded in arrival order"
        );
        for (content_id, sub_info, decoded) in &received {
            assert!(
                content_id.is_some(),
                "packet {} was forwarded without a cached content id (bypassed validation)",
                decoded.message_id()
            );
            assert!(!sub_info.is_empty());
        }
        // The lookup was sent exactly once, and the data packet did not
        // trigger a second one.
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 1);
        }

        handle.shutdown().await.unwrap();
        caching_handle.shutdown().await.unwrap();
        caching_join_handle.await.unwrap().unwrap();
    }

    /// Build a SubscriptionStarted + push-update pair for the anydata tests.
    /// `interface` is the JSON object placed in `datastore-contents` ->
    /// `ietf-interfaces:interfaces/interface[0]`.
    fn anydata_test_payloads(
        interface: serde_json::Value,
    ) -> (serde_json::Value, serde_json::Value) {
        let started = serde_json::json!(
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
                            "purpose": "test subscription",
                            "ietf-distributed-notif:message-publisher-id": [16843789],
                            "ietf-yang-push-revision:module-version": [
                                {"name": "ietf-interfaces", "revision": "2018-02-20"}
                            ],
                            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
                            "ietf-yang-push:periodic": {"period": 6000}
                        }
                    }
                }
            }
        );
        let push_update = serde_json::json!(
            {
                "ietf-yp-notification:envelope": {
                    "event-time": "2025-09-23T14:12:17.024Z",
                    "hostname": "ipf-zbl1327-r-daisy-48",
                    "sequence-number": 1,
                    "contents": {
                        "ietf-yang-push:push-update": {
                            "id": 1,
                            "datastore-contents": {
                                "ietf-interfaces:interfaces": {
                                    "interface": [interface]
                                }
                            }
                        }
                    }
                }
            }
        );
        (started, push_update)
    }

    /// Run the validation actor with the given `anydata_strict` setting over a
    /// SubscriptionStarted followed by one push-update and return the
    /// notification types that were forwarded (a packet that fails validation
    /// is dropped, so it does not show up).
    async fn run_anydata_case(anydata_strict: bool, interface: serde_json::Value) -> Vec<String> {
        let (caching_join_handle, caching_handle, subscription_info, _fetcher_count) =
            setup_actor_with_empty_cache();
        let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
        let (validated_tx, validated_rx) = async_channel::bounded(100);
        let (_join_handle, handle) = ValidationActorHandle::new(
            100,
            1000,
            100,
            DEFAULT_PENDING_LOOKUP_TIMEOUT,
            anydata_strict,
            udp_notif_rx,
            validated_tx,
            caching_handle.request_tx(),
            either::Right(ValidationStats::new(opentelemetry::global::meter(
                "test_meter",
            ))),
        )
        .expect("Failed to spawn validation actor");

        let peer = SocketAddr::new(subscription_info.peer(), 12345);
        let collector = SocketAddr::from(([127, 0, 0, 1], 10000));
        let (started, push_update) = anydata_test_payloads(interface);
        let mk = |message_id: u32, payload: &serde_json::Value| {
            Arc::new(UdpNotifRequest::new(
                collector,
                None,
                peer,
                UdpNotifPacket::new(
                    MediaType::YangDataJson,
                    10,
                    message_id,
                    HashMap::new(),
                    Bytes::from(serde_json::to_vec(payload).unwrap()),
                ),
            ))
        };
        udp_notif_tx.send(mk(1, &started)).await.unwrap();
        // wait for the SubscriptionStarted to come out before sending the data
        // packet, so its validation uses the resolved schema and the outcome
        // is not confused with the pending-lookup buffering
        let first = tokio::time::timeout(Duration::from_secs(2), validated_rx.recv())
            .await
            .expect("timeout waiting for SubscriptionStarted")
            .unwrap();
        let mut types = vec![
            first
                .2
                .notification_type()
                .map(|x| x.to_string())
                .unwrap_or_default(),
        ];
        udp_notif_tx.send(mk(2, &push_update)).await.unwrap();
        if let Ok(Ok((_, _, decoded))) =
            tokio::time::timeout(Duration::from_millis(500), validated_rx.recv()).await
        {
            types.push(
                decoded
                    .notification_type()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            );
        }
        handle
            .shutdown()
            .await
            .expect("Failed to shutdown validation actor");
        caching_handle
            .shutdown()
            .await
            .expect("Failed to shutdown caching actor");
        caching_join_handle
            .await
            .expect("Failed to join caching actor")
            .expect("caching actor error");
        types
    }

    /// With `anydata_strict` the `datastore-contents` of a push-update is
    /// validated against the subscription's schemas: an unknown node inside the
    /// interface list entry must be rejected (packet dropped).
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_validation_actor_anydata_strict_rejects_unknown_node() {
        let types = run_anydata_case(
            true,
            serde_json::json!({"name": "eth0", "type": "iana-if-type:ethernetCsmacd", "no-such-leaf": 1}),
        )
        .await;
        assert_eq!(types, vec!["SubscriptionStarted".to_string()]);
    }

    /// With `anydata_strict` valid `datastore-contents` still pass.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_validation_actor_anydata_strict_accepts_valid_content() {
        let types = run_anydata_case(
            true,
            serde_json::json!({"name": "eth0", "type": "iana-if-type:ethernetCsmacd"}),
        )
        .await;
        assert_eq!(
            types,
            vec![
                "SubscriptionStarted".to_string(),
                "YangPushUpdate".to_string()
            ]
        );
    }

    /// Without `anydata_strict` only the envelope is validated: the same
    /// unknown node inside `datastore-contents` is accepted.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_validation_actor_anydata_not_strict_accepts_unknown_node() {
        let types = run_anydata_case(
            false,
            serde_json::json!({"name": "eth0", "type": "iana-if-type:ethernetCsmacd", "no-such-leaf": 1}),
        )
        .await;
        assert_eq!(
            types,
            vec![
                "SubscriptionStarted".to_string(),
                "YangPushUpdate".to_string()
            ]
        );
    }
}
