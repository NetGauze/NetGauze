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

//! Actor-based concurrent interface for YANG Library cache operations.
//!
//! This module provides an asynchronous, message-passing interface to the YANG
//! Library cache using the actor pattern. It enables concurrent access to the
//! cache while automatically fetching missing YANG libraries from remote
//! devices.
//!
//! # Overview
//!
//! The actor module wraps the synchronous [`YangLibraryCache`] from the
//! [`storage`](super::storage) module with an actor-based interface that:
//!
//! - Provides thread-safe, concurrent access to the cache via message passing
//! - Automatically fetches missing YANG libraries from remote devices on cache
//!   miss
//! - Deduplicates concurrent fetch requests for the same subscription
//! - Manages background worker tasks for network operations
//! - Broadcasts results to all waiting requesters
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────┐
//! │ CacheActorHandle    │  ← Public API (cloneable, Send + Sync)
//! │  - request_tx       │
//! │  - cmd_tx           │
//! └──────────┬──────────┘
//!            │ (channels)
//!            ▼
//! ┌───────────────────────┐
//! │ CacheActor            │  ← Private actor (single task)
//! │  - YangLibraryCache   │     - Processes requests sequentially
//! │  - YangLibraryFetcher │     - Manages worker queue
//! │  - pending_requests   │     - Deduplicates fetch operations
//! │  - workers_queue      │
//! └───────────────────────┘
//!            │
//!            ▼
//! ┌─────────────────────┐
//! │ Worker Tasks        │  ← Background fetchers
//! │  - Fetch from NETCONF
//! │  - Parse YANG modules
//! │  - Return results
//! └─────────────────────┘
//! ```
//!
//! # Key Components
//!
//! - [`CacheActorHandle`]: The public handle for interacting with the cache
//!   actor. Provides methods to send lookup requests and shutdown the actor.
//!   Can be cloned and shared across tasks.
//!
//! - `CacheActor`: The internal actor that processes cache requests. Runs in a
//!   single async task and coordinates cache operations, network fetches, and
//!   result distribution.
//!
//! - [`CacheLookupCommand`]: Messages sent to the actor for cache lookup
//!   operations. Supports lookups by subscription info or content ID, with both
//!   streaming and one-shot response modes.
//!
//! # Request Flow
//!
//! ## Cache Hit (Fast Path)
//!
//! ```text
//! Client → Handle → Actor → Cache Lookup → Immediate Response
//!          (async)  (async)  (in-memory)
//! ```
//!
//! ## Cache Miss (Fetch Required)
//!
//! ```text
//! Client 1 → Handle → Actor → Cache Miss → Start Fetch Worker
//!                                             ↓
//! Client 2 → Handle → Actor → Cache Miss → Queue Request (same subscription)
//!                                             ↓
//! Client 3 → Handle → Actor → Cache Miss → Queue Request (same subscription)
//!                                             ↓
//!                                        Worker Completes
//!                                             ↓
//!                                     Store in Cache
//!                                             ↓
//!                              Broadcast to Clients 1, 2, 3
//! ```
//!
//! # Lookup Modes
//!
//! The actor supports two lookup modes:
//!
//! ## Streaming Mode
//!
//! Uses `async_channel::Sender` for response. Multiple requests can share the
//! same sender, enabling pub-sub patterns:
//!
//! - `LookupBySubscriptionInfo`: Cache hit returns immediately; cache miss
//!   triggers fetch and queues the request until the fetch completes.
//! - `LookupByContentId`: Always returns immediately (no fetch on miss).
//!
//! ## One-Shot Mode
//!
//! Uses `oneshot::Sender` for response. Blocks until the result is available:
//!
//! - `LookupBySubscriptionInfoOneShot`: Blocks if cache misses, fetches
//!   synchronously.
//! - `LookupByContentIdOneShot`: Returns immediately (no fetch on miss).
//!
//! # Fetch Deduplication
//!
//! When multiple requests arrive for the same subscription before a fetch
//! completes:
//!
//! 1. The first request triggers the fetch worker
//! 2. Subsequent requests are queued in `pending_requests`
//! 3. When fetch completes, all queued requesters receive the result
//! 4. No redundant network operations occur
//!
//! This prevents "thundering herd" problems when many clients request the same
//! uncached YANG library simultaneously.
//!
//! # Error Handling
//!
//! - **Cache errors**: Returned via [`CacheActorHandleError`]
//! - **Fetch failures**: Logged but don't crash the actor; pending requesters
//!   receive `None`
//! - **Channel closures**: Actor shuts down gracefully
//! - **Worker panics**: Logged as join errors; and the actor continues
//!   processing
//!
//! # Shutdown Behavior
//!
//! When [`CacheActorHandle::shutdown`] is called:
//!
//! 1. All pending worker tasks are aborted
//! 2. Pending requests are not fulfilled
//! 3. Channels are closed (Requesters can detect this by checking is_closed())
//! 4. Actor task exits cleanly
//!
//! The cache state on disk is preserved and can be reloaded on restart.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use std::path::PathBuf;
//! use crate::cache::actor::CacheActorHandle;
//! use crate::cache::fetcher::NetconfYangLibraryFetcher;
//!
//! // Create the actor with a fetcher
//! let fetcher = NetconfYangLibraryFetcher::new(/* ... */);
//! let (join_handle, handle) = CacheActorHandle::new(
//!     100,  // buffer size
//!     either::Right(PathBuf::from("/var/lib/yang-cache")),
//!     fetcher,
//! )?;
//!
//! // Clone the handle for multiple tasks
//! let handle1 = handle.clone();
//! let handle2 = handle.clone();
//!
//! // Task 1: Lookup by subscription info (async)
//! tokio::spawn(async move {
//!     let (tx, rx) = async_channel::unbounded();
//!     let subscription_info = /* ... */;
//!     handle1.request_tx()
//!         .send(CacheLookupCommand::LookupBySubscriptionInfo(subscription_info, tx))
//!         .await?;
//!
//!     if let Some(yang_lib_ref) = rx.recv().await? {
//!         let schemas = yang_lib_ref.load_schemas()?;
//!         // Use schemas...
//!     }
//! });
//!
//! // Task 2: Lookup by content ID (one-shot)
//! tokio::spawn(async move {
//!     let (tx, rx) = oneshot::channel();
//!     let content_id = "abc123".into();
//!     handle2.request_tx()
//!         .send(CacheLookupCommand::LookupByContentIdOneShot(content_id, tx))
//!         .await?;
//!
//!     if let Some(yang_lib_ref) = rx.await? {
//!         // Use yang_lib_ref...
//!     }
//! });
//!
//! // Shutdown when done
//! handle.shutdown().await?;
//! join_handle.await??;
//! ```
//!
//! # Performance Considerations
//!
//! - **Cache hits**: Sub-millisecond latency (in-memory HashMap lookup)
//! - **Cache misses**: Network-bound (depends on device response time and YANG
//!   module count)
//! - **Concurrent requests**: O(1) message passing overhead
//! - **Fetch deduplication**: Prevents N × network_latency for N concurrent
//!   requests

use crate::cache::fetcher::{FetcherResult, YangLibraryFetcher};
use crate::cache::storage::{
    SubscriptionInfo, YangLibraryCache, YangLibraryCacheError, YangLibraryReference,
};
use crate::{
    ContentId, OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use netgauze_udp_notif_pkt::notification::SubscriptionId;
use rustc_hash::FxHashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle};
use tracing::{debug, info, warn};

const OTL_CACHE_REQUEST_TYPE: &str = "netgauze.udp.notif.yang.push.cache.request.type";

#[derive(Debug, Clone)]
pub struct CachingStats {
    pub requests_received: opentelemetry::metrics::Counter<u64>,
    pub pending_cache_requests: opentelemetry::metrics::Gauge<u64>,
    pub cache_hits: opentelemetry::metrics::Counter<u64>,
    pub cache_misses: opentelemetry::metrics::Counter<u64>,
    pub device_fetch_request: opentelemetry::metrics::Counter<u64>,
    pub device_fetch_queue: opentelemetry::metrics::Gauge<u64>,
    pub device_fetch_succeeded: opentelemetry::metrics::Counter<u64>,
    pub device_fetch_failed: opentelemetry::metrics::Counter<u64>,
}

impl CachingStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let requests_received = meter
            .u64_counter("netgauze.collector.yang_push.caching.requests.received")
            .with_description("Number of requests received by the YANG library cache actor")
            .build();
        let pending_cache_requests = meter
            .u64_gauge("netgauze.collector.yang_push.caching.requests.pending")
            .with_description("Number of pending cache requests in the YANG library cache actor that are waiting for fetch to complete")
            .build();
        let cache_hits = meter
            .u64_counter("netgauze.collector.yang_push.caching.requests.cache.hits")
            .with_description("Number of cache hits in the YANG library cache actor")
            .build();
        let cache_misses = meter
            .u64_counter("netgauze.collector.yang_push.caching.requests.cache.misses")
            .with_description("Number of cache misses in the YANG library cache actor")
            .build();
        let device_fetch_request = meter
            .u64_counter("netgauze.collector.yang_push.caching.device.fetch.requests")
            .with_description(
                "Number of device fetch requests initiated by the YANG library cache actor",
            )
            .build();
        let device_fetch_queue = meter
            .u64_gauge("netgauze.collector.yang_push.caching.device.fetch.pending")
            .with_description("Number of device fetch requests that are currently queued in the YANG library cache actor")
            .build();
        let device_fetch_succeeded = meter
            .u64_counter("netgauze.collector.yang_push.caching.device.fetch.response.succeeded")
            .with_description("Number of device fetch requests initiated by the YANG library cache actor and succeeded")
            .build();
        let device_fetch_failed = meter
            .u64_counter("netgauze.collector.yang_push.caching.device.fetch.response.failed")
            .with_description("Number of device fetch requests initiated by the YANG library cache actor and failed")
            .build();
        Self {
            requests_received,
            pending_cache_requests,
            cache_hits,
            cache_misses,
            device_fetch_request,
            device_fetch_queue,
            device_fetch_succeeded,
            device_fetch_failed,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CacheActorCommand {
    Shutdown,
    /// Invoke periodic cleanup operations to prevent memory leaks.
    Cleanup,
}

#[derive(Debug)]
pub enum CacheLookupCommand {
    LookupBySubscriptionInfo(SubscriptionInfo, async_channel::Sender<CacheResponse>),

    LookupBySubscriptionInfoOneShot(SubscriptionInfo, oneshot::Sender<CacheResponse>),

    LookupBySubscriptionId {
        peer: SocketAddr,
        subscription_id: SubscriptionId,
        tx: async_channel::Sender<CacheResponse>,
    },

    LookupBySubscriptionIdOneShot {
        peer: SocketAddr,
        subscription_id: SubscriptionId,
        tx: oneshot::Sender<CacheResponse>,
    },

    LookupByContentId(
        ContentId,
        async_channel::Sender<(ContentId, Option<Arc<YangLibraryReference>>)>,
    ),

    LookupByContentIdOneShot(
        ContentId,
        oneshot::Sender<(ContentId, Option<Arc<YangLibraryReference>>)>,
    ),
}

impl std::fmt::Display for CacheLookupCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LookupBySubscriptionInfo(subscription_info, _) => {
                write!(f, "lookup by subscription info {subscription_info}")
            }
            Self::LookupBySubscriptionInfoOneShot(subscription_info, _) => {
                write!(
                    f,
                    "lookup by subscription info {subscription_info} (one shot)"
                )
            }
            Self::LookupBySubscriptionId {
                peer,
                subscription_id,
                tx: _tx,
            } => {
                write!(
                    f,
                    "lookup by subscription id {subscription_id} from peer {peer}"
                )
            }
            Self::LookupBySubscriptionIdOneShot {
                peer,
                subscription_id,
                tx: _tx,
            } => {
                write!(
                    f,
                    "lookup by subscription id {subscription_id} from peer {peer} (one shot)"
                )
            }
            Self::LookupByContentId(content_id, _) => {
                write!(f, "lookup by content id {content_id}")
            }
            Self::LookupByContentIdOneShot(content_id, _) => {
                write!(f, "lookup by content id {content_id} (one shot)")
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum CacheActorCacheError {}

impl std::error::Error for CacheActorCacheError {}

#[derive(Debug, Clone)]
pub struct CacheResponse {
    cached_content_id: Option<ContentId>,
    subscription_info: SubscriptionInfo,
    yang_lib_ref: Option<Arc<YangLibraryReference>>,
}

impl CacheResponse {
    pub const fn cached_content_id(&self) -> Option<&ContentId> {
        self.cached_content_id.as_ref()
    }

    pub const fn subscription_info(&self) -> &SubscriptionInfo {
        &self.subscription_info
    }

    pub fn yang_lib_ref(&self) -> Option<Arc<YangLibraryReference>> {
        self.yang_lib_ref.as_ref().map(Arc::clone)
    }
}

impl From<CacheResponse>
    for (
        Option<ContentId>,
        SubscriptionInfo,
        Option<Arc<YangLibraryReference>>,
    )
{
    fn from(value: CacheResponse) -> Self {
        (
            value.cached_content_id,
            value.subscription_info,
            value.yang_lib_ref,
        )
    }
}

struct CacheActor<F: YangLibraryFetcher> {
    cmd_rx: mpsc::Receiver<CacheActorCommand>,
    schema_cache: YangLibraryCache,
    requests: async_channel::Receiver<CacheLookupCommand>,
    fetcher: F,
    fetcher_timeout: Duration,
    pending_requests: FxHashMap<SubscriptionInfo, Vec<async_channel::Sender<CacheResponse>>>,
    workers_queue: FuturesUnordered<JoinHandle<FetcherResult>>,
    stats: CachingStats,
}

impl<F: YangLibraryFetcher> CacheActor<F> {
    async fn send_yang_lib_ref(
        subscription_info: &SubscriptionInfo,
        yang_lib_ref: Option<Arc<YangLibraryReference>>,
        sender: async_channel::Sender<CacheResponse>,
    ) {
        let hit = yang_lib_ref.is_some();
        let cached_content_id = yang_lib_ref
            .as_ref()
            .map(|x| x.content_id().clone())
            .unwrap_or("None".to_string());
        let response = CacheResponse {
            cached_content_id: yang_lib_ref.as_ref().map(|x| x.content_id().clone()),
            subscription_info: subscription_info.clone(),
            yang_lib_ref,
        };
        match sender.send(response).await {
            Ok(_) => {
                debug!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    hit,
                    "yang library reference sent to requester"
                );
            }
            Err(err) => {
                warn!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    hit,
                    error = %err,
                    "failed to send yang library reference to requester"
                );
            }
        }
    }

    async fn send_yang_lib_ref_content_id(
        content_id: &ContentId,
        yang_lib_ref: Option<Arc<YangLibraryReference>>,
        sender: async_channel::Sender<(ContentId, Option<Arc<YangLibraryReference>>)>,
    ) {
        let found = yang_lib_ref.is_some();
        let cached_content_id = yang_lib_ref.as_ref().map(|x| x.content_id().clone());
        match sender.send((content_id.clone(), yang_lib_ref)).await {
            Ok(_) => {
                debug!(
                    content_id,
                    found,
                    cached_content_id = cached_content_id.as_deref().unwrap_or("None"),
                    "yang library reference sent to requester"
                );
            }
            Err(err) => {
                warn!(
                    content_id,
                    found,
                    cached_content_id=cached_content_id.as_deref().unwrap_or("None"),
                    error = %err,
                    "failed to send yang library reference to requester"
                );
            }
        }
    }

    fn send_yang_lib_ref_oneshot(
        subscription_info: &SubscriptionInfo,
        yang_lib_ref: Option<Arc<YangLibraryReference>>,
        sender: oneshot::Sender<CacheResponse>,
    ) {
        let hit = yang_lib_ref.is_some();
        let cached_content_id = yang_lib_ref
            .as_ref()
            .map(|x| x.content_id().clone())
            .unwrap_or("None".to_string());
        let response = CacheResponse {
            cached_content_id: yang_lib_ref.as_ref().map(|x| x.content_id().clone()),
            subscription_info: subscription_info.clone(),
            yang_lib_ref,
        };
        match sender.send(response) {
            Ok(_) => {
                debug!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    hit,
                    "yang library reference sent (oneshot) to requester"
                );
            }
            Err(_err) => {
                warn!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    "failed to send (oneshot) yang library reference to requester"
                );
            }
        }
    }

    fn send_yang_lib_ref_oneshot_content_id(
        content_id: &ContentId,
        yang_lib_ref: Option<Arc<YangLibraryReference>>,
        sender: oneshot::Sender<(ContentId, Option<Arc<YangLibraryReference>>)>,
    ) {
        let hit = yang_lib_ref.is_some();
        match sender.send((content_id.clone(), yang_lib_ref)) {
            Ok(_) => {
                debug!(
                    content_id,
                    hit, "yang library reference sent (oneshot) to requester"
                );
            }
            Err(_err) => {
                warn!(
                    content_id,
                    hit, "failed to send (oneshot) yang library reference to requester"
                );
            }
        }
    }

    async fn process_worker_result(&mut self, worker_result: Result<FetcherResult, JoinError>) {
        match worker_result {
            Err(err) => {
                self.stats.device_fetch_failed.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "error.message",
                        format!("{err}"),
                    )],
                );
                warn!(error=%err, "cache actor worker failed to execute a task");
            }
            Ok(Err((subscription_info, err))) => {
                self.stats.device_fetch_failed.add(
                    1,
                    &[
                        opentelemetry::KeyValue::new(
                            "network.peer.address",
                            format!("{}", subscription_info.peer().ip()),
                        ),
                        opentelemetry::KeyValue::new(
                            "network.peer.port",
                            opentelemetry::Value::I64(subscription_info.peer().port().into()),
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
                        opentelemetry::KeyValue::new("error.message", format!("{err}")),
                    ],
                );
                warn!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    error=%err,
                    "network fetcher failed to fetch yang library from device for subscription info"
                );
                let pending_senders = self.pending_requests.remove(&subscription_info);
                self.stats
                    .pending_cache_requests
                    .record(self.pending_requests.len() as u64, &[]);
                if let Some(pending_senders) = pending_senders {
                    for sender in pending_senders {
                        let _ = sender
                            .send(CacheResponse {
                                cached_content_id: None,
                                subscription_info: subscription_info.clone(),
                                yang_lib_ref: None,
                            })
                            .await
                            .map_err(|error| {
                                warn!(
                                    peer=%subscription_info.peer(),
                                    subscription_id=subscription_info.id(),
                                    router_content_id=subscription_info.content_id(),
                                    target=%subscription_info.target(),
                                    error=%error,
                                    "failed to send error response to requester"
                                );
                            });
                        debug!(
                            peer=%subscription_info.peer(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            error=%err,
                            "sent error response to requester due to fetch failure"
                        );
                    }
                }
            }
            Ok(Ok((subscription_info, yang_lib, schemas))) => {
                let otl_tags = [
                    opentelemetry::KeyValue::new(
                        "network.peer.address",
                        format!("{}", subscription_info.peer().ip()),
                    ),
                    opentelemetry::KeyValue::new(
                        "network.peer.port",
                        opentelemetry::Value::I64(subscription_info.peer().port().into()),
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
                        yang_lib.content_id().to_string(),
                    ),
                ];
                self.stats.device_fetch_succeeded.add(1, &otl_tags);
                info!(
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    modules_count = schemas.len(),
                    cached_content_id = yang_lib.content_id(),
                    "fetched yang library from device successfully"
                );
                let result = self.schema_cache.put_yang_library(
                    subscription_info.clone(),
                    yang_lib,
                    schemas,
                );
                let yang_lib_ref = match result {
                    Ok(yang_lib_ref) => {
                        info!(
                            peer=%subscription_info.peer(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            "yang library for subscription info stored in cache successfully"
                        );
                        Some(yang_lib_ref)
                    }
                    Err(err) => {
                        warn!(
                            peer=%subscription_info.peer(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            error=%err,
                            "failed to store yang library in cache"
                        );
                        None
                    }
                };
                let pending_senders = self.pending_requests.remove(&subscription_info);
                self.stats
                    .pending_cache_requests
                    .record(self.pending_requests.len() as u64, &[]);
                if let Some(pending_senders) = pending_senders {
                    for sender in pending_senders {
                        Self::send_yang_lib_ref(&subscription_info, yang_lib_ref.clone(), sender)
                            .await;
                    }
                }
            }
        }
    }

    fn cleanup_closed_senders(&mut self) {
        self.pending_requests.retain(|_, senders| {
            senders.retain(|s| !s.is_closed());
            !senders.is_empty()
        });
        self.stats
            .pending_cache_requests
            .record(self.pending_requests.len() as u64, &[]);
    }

    fn otl_tags_from_subscription_inf(
        subscription_info: &SubscriptionInfo,
    ) -> Vec<opentelemetry::KeyValue> {
        Vec::from([
            opentelemetry::KeyValue::new(
                "network.peer.address",
                format!("{}", subscription_info.peer().ip()),
            ),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(subscription_info.peer().port().into()),
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
            opentelemetry::KeyValue::new(OTL_CACHE_REQUEST_TYPE, "LOOKUP_BY_SUBSCRIPTION_INFO"),
        ])
    }

    async fn process_request(&mut self, request: CacheLookupCommand) {
        match request {
            CacheLookupCommand::LookupBySubscriptionInfo(subscription_info, sender) => {
                let otl_tags = Self::otl_tags_from_subscription_inf(&subscription_info);
                self.stats.requests_received.add(1, otl_tags.as_ref());
                debug!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    "processing cache lookup by subscription info request"
                );
                let yang_lib_ref = self
                    .schema_cache
                    .get_by_subscription_info(&subscription_info);
                match yang_lib_ref {
                    Some(yang_lib_ref) => {
                        info!(
                            peer=%subscription_info.peer(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            cached_content_id=yang_lib_ref.content_id(),
                            "cache hit: yang library reference found in cache"
                        );
                        self.stats.cache_hits.add(1, &otl_tags);
                        Self::send_yang_lib_ref(&subscription_info, Some(yang_lib_ref), sender)
                            .await;
                    }
                    None => {
                        // YANG Library Reference is not found in the cache.
                        // Start a new worker to fetch the YANG Library from the server.
                        self.stats.cache_misses.add(1, &otl_tags);
                        let entry = self
                            .pending_requests
                            .entry(subscription_info.clone())
                            .or_default();
                        let should_fetch = entry.is_empty();
                        entry.push(sender);

                        if should_fetch {
                            info!(
                                peer=%subscription_info.peer(),
                                subscription_id=subscription_info.id(),
                                router_content_id=subscription_info.content_id(),
                                target=%subscription_info.target(),
                                "cache miss: starting fetch from device"
                            );
                            self.stats.device_fetch_request.add(1, &otl_tags);
                            let job_result = tokio::time::timeout(
                                self.fetcher_timeout,
                                self.fetcher.fetch(subscription_info.clone()),
                            )
                            .await;
                            let job = match job_result {
                                Ok(worker_result) => worker_result,
                                Err(err) => {
                                    warn!(
                                        peer=%subscription_info.peer(),
                                        subscription_id=subscription_info.id(),
                                        router_content_id=subscription_info.content_id(),
                                        target=%subscription_info.target(),
                                        error=%err,
                                        "failed to fetch yang library from device"
                                    );
                                    // remove the sender we just added since the fetch failed to
                                    // start
                                    entry.remove(entry.len() - 1);
                                    self.stats.device_fetch_failed.add(1, &otl_tags);
                                    return;
                                }
                            };
                            self.workers_queue.push(job);
                            self.stats
                                .device_fetch_queue
                                .record(self.workers_queue.len() as u64, &[]);
                        } else {
                            debug!(
                                peer=%subscription_info.peer(),
                                subscription_id=subscription_info.id(),
                                router_content_id=subscription_info.content_id(),
                                target=%subscription_info.target(),
                                pending_requests_count=entry.len(),
                                "cache miss: fetch request in progress from the router, queuing request to avoid duplicate requests to the router"
                            );
                        }
                        self.stats
                            .pending_cache_requests
                            .record(self.pending_requests.len() as u64, &otl_tags);
                    }
                }
            }
            CacheLookupCommand::LookupBySubscriptionInfoOneShot(subscription_info, sender) => {
                let mut otl_tags = Self::otl_tags_from_subscription_inf(&subscription_info);
                self.stats.requests_received.add(1, otl_tags.as_ref());
                debug!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    "processing cache lookup by subscription info request (one shot)"
                );
                // fetch the schemas if needed from the device
                if let Some(yang_lib_ref) = self
                    .schema_cache
                    .get_by_subscription_info(&subscription_info)
                {
                    info!(
                        peer=%subscription_info.peer(),
                        subscription_id=subscription_info.id(),
                        router_content_id=subscription_info.content_id(),
                        target=%subscription_info.target(),
                        cached_content_id=yang_lib_ref.content_id(),
                        "cache hit: yang library reference found in cache"
                    );
                    self.stats.cache_hits.add(1, &otl_tags);
                } else {
                    self.stats.cache_misses.add(1, &otl_tags);
                    self.stats.device_fetch_request.add(1, &otl_tags);
                    let worker_result = tokio::time::timeout(
                        self.fetcher_timeout,
                        self.fetcher.fetch_blocking(subscription_info.clone()),
                    )
                    .await;

                    let worker_result = match worker_result {
                        Ok(worker_result) => {
                            self.stats.device_fetch_succeeded.add(1, &otl_tags);
                            worker_result
                        }
                        Err(err) => {
                            otl_tags.push(opentelemetry::KeyValue::new(
                                "error.message",
                                format!("{err}"),
                            ));
                            self.stats.device_fetch_failed.add(1, &otl_tags);
                            Err((subscription_info.clone(), err.into()))
                        }
                    };
                    self.process_worker_result(Ok(worker_result)).await;
                }
                let yang_lib_ref = self
                    .schema_cache
                    .get_by_subscription_info(&subscription_info.clone());
                Self::send_yang_lib_ref_oneshot(&subscription_info, yang_lib_ref, sender);
            }
            CacheLookupCommand::LookupBySubscriptionId {
                peer,
                subscription_id,
                tx,
            } => {
                let otel_tags = [
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
                self.stats.requests_received.add(1, &otel_tags);
                debug!(peer=%peer, subscription_id, "processing cache lookup by subscription id request");
                let response = self
                    .schema_cache
                    .get_by_subscription_id(peer.ip(), subscription_id);
                if let Some((subscription_info, yang_lib_ref)) = response {
                    self.stats.cache_hits.add(1, &otel_tags);
                    Self::send_yang_lib_ref(&subscription_info, yang_lib_ref, tx).await;
                } else {
                    // TODO: lookup subscription direction from router config
                    self.stats.cache_misses.add(1, &otel_tags);
                    warn!(
                        peer=%peer,
                        subscription_id,
                        "cache miss: subscription id not found in cache"
                    );
                }
            }
            CacheLookupCommand::LookupBySubscriptionIdOneShot {
                peer,
                subscription_id,
                tx,
            } => {
                let otel_tags = [
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
                self.stats.requests_received.add(1, &otel_tags);
                debug!(
                    peer=%peer,
                    subscription_id,
                    "processing cache lookup by subscription id request (one shot)");
                let response = self
                    .schema_cache
                    .get_by_subscription_id(peer.ip(), subscription_id);
                if let Some((subscription_info, yang_lib_ref)) = response {
                    self.stats.cache_hits.add(1, &otel_tags);
                    Self::send_yang_lib_ref_oneshot(&subscription_info, yang_lib_ref, tx);
                } else {
                    // TODO: lookup subscription direction from router config
                    self.stats.cache_misses.add(1, &otel_tags);
                    warn!(
                        peer=%peer,
                        subscription_id,
                        "cache miss: subscription id not found in cache"
                    );
                }
            }
            CacheLookupCommand::LookupByContentId(content_id, sender) => {
                let otl_tags = [opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY,
                    content_id.to_string(),
                )];
                self.stats.requests_received.add(1, &otl_tags);
                debug!(content_id, "processing cache lookup request by content id");
                let yang_lib_ref = self.schema_cache.get_by_content_id(&content_id);
                if yang_lib_ref.is_some() {
                    self.stats.cache_hits.add(1, &otl_tags);
                } else {
                    self.stats.cache_misses.add(1, &otl_tags);
                }
                Self::send_yang_lib_ref_content_id(&content_id, yang_lib_ref, sender).await;
            }
            CacheLookupCommand::LookupByContentIdOneShot(content_id, sender) => {
                let otl_tags = [opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY,
                    content_id.to_string(),
                )];
                self.stats.requests_received.add(1, &otl_tags);
                debug!(
                    content_id,
                    "processing cache lookup request by content id (one shot)"
                );
                let yang_lib_ref = self.schema_cache.get_by_content_id(&content_id);
                if yang_lib_ref.is_some() {
                    self.stats.cache_hits.add(1, &otl_tags);
                } else {
                    self.stats.cache_misses.add(1, &otl_tags);
                }
                Self::send_yang_lib_ref_oneshot_content_id(&content_id, yang_lib_ref, sender);
            }
        }
    }

    async fn run(mut self) -> Result<String, CacheActorCacheError> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(CacheActorCommand::Shutdown) => {
                            info!(
                                pending_requests = self.pending_requests.len(),
                                active_workers = self.workers_queue.len(),
                                "cache actor shutting down and aborting all active workers"
                            );
                            for task in self.workers_queue {
                                task.abort();
                            }
                            return Ok("Schema cache shutdown successful".to_string());
                        }
                        Some(CacheActorCommand::Cleanup) => {
                            self.cleanup_closed_senders();
                        }
                        None => {
                            warn!(
                                pending_requests = self.pending_requests.len(),
                                active_workers = self.workers_queue.len(),
                                "cache actor channel closed unexpectedly due to closed command channel"
                            );
                            for task in self.workers_queue {
                                task.abort();
                            }
                            self.stats.device_fetch_queue.record(0, &[]);
                            return Ok("Schema cache shutdown successful".to_string());
                        }
                    }
                }
                work_result = self.workers_queue.next(), if !self.workers_queue.is_empty()=> {
                    if let Some(work_result) = work_result {
                        self.stats.device_fetch_queue.record(self.workers_queue.len() as u64, &[]);
                        self.process_worker_result(work_result).await;
                    }
                }
                request = self.requests.recv() => {
                    if let Ok(request) = request {
                        self.process_request(request).await;
                    } else {
                        self.stats.requests_received.add(1, &[]);
                        warn!(
                            pending_requests = self.pending_requests.len(),
                            active_workers = self.workers_queue.len(),
                            "cache actor channel closed unexpectedly due to closed request channel"
                        );
                        for task in self.workers_queue {
                            task.abort();
                        }
                        self.stats.device_fetch_queue.record(0, &[]);
                        return Ok("Schema cache shutdown successful".to_string())
                    }
                }
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum CacheActorHandleError {
    #[strum(to_string = "failed to send command to the schema caching actor")]
    SendError,

    #[strum(to_string = "failed to fetch yang library from device {0}")]
    CacheError(YangLibraryCacheError),
}

impl std::error::Error for CacheActorHandleError {}

impl From<YangLibraryCacheError> for CacheActorHandleError {
    fn from(err: YangLibraryCacheError) -> Self {
        CacheActorHandleError::CacheError(err)
    }
}

#[derive(Debug, Clone)]
pub struct CacheActorHandle {
    cmd_tx: mpsc::Sender<CacheActorCommand>,
    requests_tx: async_channel::Sender<CacheLookupCommand>,
}

impl CacheActorHandle {
    pub fn new<F: YangLibraryFetcher + Send + Sync + 'static>(
        buffer_size: usize,
        schema_cache: either::Either<YangLibraryCache, PathBuf>,
        fetcher: F,
        fetcher_timeout: Duration,
        stats: either::Either<opentelemetry::metrics::Meter, CachingStats>,
    ) -> Result<(JoinHandle<Result<String, CacheActorCacheError>>, Self), CacheActorHandleError>
    {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (requests_tx, requests_rx) = async_channel::bounded(buffer_size);
        let schema_cache = match schema_cache {
            either::Either::Left(schema_cache) => schema_cache,
            either::Either::Right(root_path) => YangLibraryCache::from_disk(root_path)?,
        };
        let stats = match stats {
            either::Either::Left(meter) => CachingStats::new(meter),
            either::Either::Right(stats) => stats,
        };

        let actor = CacheActor {
            cmd_rx,
            schema_cache,
            requests: requests_rx,
            fetcher,
            fetcher_timeout,
            pending_requests: FxHashMap::default(),
            workers_queue: FuturesUnordered::new(),
            stats,
        };

        let cmd_tx_clone = cmd_tx.clone();
        let handle = Self {
            cmd_tx,
            requests_tx,
        };
        let join_handle = tokio::spawn(actor.run());

        tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                cleanup_interval.tick().await;
                if let Err(err) = cmd_tx_clone.send(CacheActorCommand::Cleanup).await {
                    warn!(error=%err, "failed to send cleanup command to cache actor, stopping periodic cleanup task");
                    break;
                }
            }
        });
        Ok((join_handle, handle))
    }

    pub async fn shutdown(self) -> Result<(), CacheActorHandleError> {
        self.cmd_tx
            .send(CacheActorCommand::Shutdown)
            .await
            .map_err(|_| CacheActorHandleError::SendError)
    }

    pub fn request_tx(&self) -> async_channel::Sender<CacheLookupCommand> {
        self.requests_tx.clone()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cache::fetcher::tests::TestYangLibFetcher;
    use futures_util::stream::FuturesOrdered;
    use netgauze_udp_notif_pkt::notification::Target;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::time::Duration;

    pub(crate) fn test_subscription_info() -> SubscriptionInfo {
        SubscriptionInfo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 830),
            1,
            ContentId::from("ietf-interfaces-lib".to_string()),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='eth0']/statistics".to_string()),
            ),
            vec!["ietf-interfaces".to_string(), "ietf-ip".to_string()],
        )
    }

    fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::create_dir_all(&dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
            } else {
                std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
            }
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn setup_actor_with_loaded_cache() -> (
        JoinHandle<Result<String, CacheActorCacheError>>,
        CacheActorHandle,
        YangLibraryReference,
        SubscriptionInfo,
        Arc<std::sync::Mutex<HashMap<SubscriptionInfo, usize>>>,
    ) {
        let cache_dir = tempfile::tempdir().unwrap();
        let yang_lib_ref_path = cache_dir.path().to_path_buf().join("ietf-interfaces-lib");
        copy_dir_all(
            "../../assets/yang/ietf-interfaces",
            yang_lib_ref_path.as_path(),
        )
        .unwrap();
        let yang_lib_path = yang_lib_ref_path.join("yang-lib.xml");
        let yang_lib_ref = YangLibraryReference::load_from_disk(yang_lib_path, yang_lib_ref_path)
            .expect("Failed to load yang library reference from disk");
        let subscription_info = yang_lib_ref
            .subscriptions_info()
            .expect("Failed to get subscriptions info")[0]
            .clone();
        let yang_lib = yang_lib_ref.yang_library().unwrap();
        let schemas = yang_lib_ref.load_schemas().unwrap();
        let fetcher = TestYangLibFetcher::new(HashMap::from([(
            subscription_info.clone(),
            (yang_lib, schemas),
        )]));
        let fetcher_count = Arc::clone(&fetcher.fetch_counts);
        let (join, handle) = CacheActorHandle::new(
            100,
            either::Right(cache_dir.path().to_path_buf()),
            fetcher,
            Duration::from_secs(1),
            either::Either::Left(opentelemetry::global::meter("test-meter")),
        )
        .expect("Failed to create cache actor");
        (join, handle, yang_lib_ref, subscription_info, fetcher_count)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn setup_actor_with_empty_cache() -> (
        JoinHandle<Result<String, CacheActorCacheError>>,
        CacheActorHandle,
        SubscriptionInfo,
        Arc<std::sync::Mutex<HashMap<SubscriptionInfo, usize>>>,
    ) {
        // Keep the YANG lib reference in a different directory than the cache
        let fetcher_dir = tempfile::tempdir().unwrap();
        let yang_lib_ref_path = fetcher_dir.path().to_path_buf().join("ietf-interfaces-lib");
        copy_dir_all(
            "../../assets/yang/ietf-interfaces",
            yang_lib_ref_path.as_path(),
        )
        .unwrap();
        let yang_lib_path = yang_lib_ref_path.join("yang-lib.xml");
        let yang_lib_ref = YangLibraryReference::load_from_disk(yang_lib_path, yang_lib_ref_path)
            .expect("Failed to load yang library reference from disk");
        let subscription_info = yang_lib_ref
            .subscriptions_info()
            .expect("Failed to get subscriptions info")[0]
            .clone();
        let yang_lib = yang_lib_ref.yang_library().unwrap();
        let schemas = yang_lib_ref.load_schemas().unwrap();
        let fetcher = TestYangLibFetcher::new(HashMap::from([(
            subscription_info.clone(),
            (yang_lib, schemas),
        )]));
        let fetcher_count = Arc::clone(&fetcher.fetch_counts);

        let cache_dir = tempfile::tempdir().unwrap();
        let (join, handle) = CacheActorHandle::new(
            100,
            either::Right(cache_dir.path().to_path_buf()),
            fetcher,
            Duration::from_secs(1),
            either::Either::Left(opentelemetry::global::meter("test-meter")),
        )
        .expect("Failed to create cache actor");
        (join, handle, subscription_info, fetcher_count)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_cache_miss_device_fail() {
        let (join_handle, handle, _cached_lib_ref, _cached_subscription_info, fetcher_count) =
            setup_actor_with_loaded_cache();
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 0);
        }
        let subscription_info = test_subscription_info();

        let (tx, rx) = async_channel::unbounded();
        handle
            .request_tx()
            .send(CacheLookupCommand::LookupBySubscriptionInfo(
                subscription_info.clone(),
                tx,
            ))
            .await
            .unwrap();

        tokio::task::yield_now().await;
        let response = tokio::time::timeout(Duration::from_millis(1000), rx.recv())
            .await
            .expect("timeout waiting for response")
            .expect("failed to receive response");
        assert_eq!(response.subscription_info(), &subscription_info);
        assert_eq!(response.yang_lib_ref(), None);

        // check that the fetcher was called

        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 1);
            assert_eq!(hits_counts.get(&subscription_info), Some(&1));
        }

        tokio::time::timeout(Duration::from_millis(100), handle.shutdown())
            .await
            .expect("timeout during shutdown")
            .expect("failed to shutdown actor");
        tokio::time::timeout(Duration::from_millis(100), join_handle)
            .await
            .expect("timeout during join")
            .expect("failed to join actor")
            .expect("cache actor failed");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_cache_miss_triggers_fetch() {
        let (join_handle, handle, subscription_info, fetcher_count) =
            setup_actor_with_empty_cache();
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 0);
        }

        let (tx, rx) = async_channel::unbounded();
        handle
            .request_tx()
            .send(CacheLookupCommand::LookupBySubscriptionInfo(
                subscription_info.clone(),
                tx,
            ))
            .await
            .unwrap();

        tokio::task::yield_now().await;
        let response = tokio::time::timeout(Duration::from_millis(1000), rx.recv())
            .await
            .expect("timeout waiting for response")
            .expect("failed to receive response");
        assert_eq!(response.subscription_info(), &subscription_info);
        assert!(response.yang_lib_ref().is_some());

        // check that the fetcher was called
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 1);
            assert_eq!(hits_counts.get(&subscription_info), Some(&1));
        }

        let (tx, rx) = async_channel::unbounded();
        handle
            .request_tx()
            .send(CacheLookupCommand::LookupBySubscriptionInfo(
                subscription_info.clone(),
                tx,
            ))
            .await
            .unwrap();

        tokio::task::yield_now().await;
        let response = tokio::time::timeout(Duration::from_millis(1000), rx.recv())
            .await
            .expect("timeout waiting for response")
            .expect("failed to receive response");
        assert_eq!(response.subscription_info(), &subscription_info);
        assert!(response.yang_lib_ref().is_some());

        // check that the fetcher was NOT called
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 1);
            assert_eq!(hits_counts.get(&subscription_info), Some(&1));
        }

        tokio::time::timeout(Duration::from_millis(100), handle.shutdown())
            .await
            .expect("timeout during shutdown")
            .expect("failed to shutdown actor");
        tokio::time::timeout(Duration::from_millis(100), join_handle)
            .await
            .expect("timeout during join")
            .expect("failed to join actor")
            .expect("cache actor failed");
    }

    #[tokio::test]
    async fn test_concurrent_fetch_deduplication() {
        let (join_handle, handle, subscription_info, fetcher_count) =
            setup_actor_with_empty_cache();

        let mut tasks = FuturesOrdered::new();
        for _ in 0..10 {
            let h = handle.clone();
            let sub = subscription_info.clone();
            tasks.push_back(tokio::spawn(async move {
                let (tx, rx) = async_channel::unbounded();
                h.request_tx()
                    .send(CacheLookupCommand::LookupBySubscriptionInfo(sub, tx))
                    .await
                    .unwrap();
                rx.recv().await.unwrap()
            }));
        }

        let results = tasks
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|res| res.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 10);

        // Verify only ONE fetch occurred
        {
            let count = fetcher_count.lock().unwrap();
            assert_eq!(count.get(&subscription_info), Some(&1));
        }

        // Cleanup
        tokio::time::timeout(Duration::from_millis(100), handle.shutdown())
            .await
            .expect("timeout during shutdown")
            .expect("failed to shutdown actor");
        tokio::time::timeout(Duration::from_millis(100), join_handle)
            .await
            .expect("timeout during join")
            .expect("failed to join actor")
            .expect("cache actor failed");
    }
}
