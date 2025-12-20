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

use crate::ContentId;
use crate::cache::fetcher::{FetcherResult, YangLibraryFetcher};
use crate::cache::storage::{
    SubscriptionInfo, YangLibraryCache, YangLibraryCacheError, YangLibraryReference,
};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use netgauze_udp_notif_pkt::notification::SubscriptionId;
use rustc_hash::FxHashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle};

#[derive(Debug, Clone)]
pub enum CacheActorCommand {
    Shutdown,
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
    subscription_info: SubscriptionInfo,
    yang_lib_ref: Option<Arc<YangLibraryReference>>,
}

impl CacheResponse {
    pub const fn subscription_info(&self) -> &SubscriptionInfo {
        &self.subscription_info
    }

    pub fn yang_lib_ref(&self) -> Option<Arc<YangLibraryReference>> {
        self.yang_lib_ref.as_ref().map(Arc::clone)
    }
}

impl From<CacheResponse> for (SubscriptionInfo, Option<Arc<YangLibraryReference>>) {
    fn from(value: CacheResponse) -> Self {
        (value.subscription_info, value.yang_lib_ref)
    }
}

struct CacheActor<F: YangLibraryFetcher> {
    cmd_rx: mpsc::Receiver<CacheActorCommand>,
    schema_cache: YangLibraryCache,
    requests: async_channel::Receiver<CacheLookupCommand>,
    fetcher: F,
    pending_requests: FxHashMap<SubscriptionInfo, Vec<async_channel::Sender<CacheResponse>>>,
    workers_queue: FuturesUnordered<JoinHandle<FetcherResult>>,
}

impl<F: YangLibraryFetcher> CacheActor<F> {
    async fn send_yang_lib_ref(
        subscription_info: &SubscriptionInfo,
        yang_lib_ref: Option<Arc<YangLibraryReference>>,
        sender: async_channel::Sender<CacheResponse>,
    ) {
        let hit = yang_lib_ref.is_some();
        let response = CacheResponse {
            subscription_info: subscription_info.clone(),
            yang_lib_ref,
        };
        match sender.send(response).await {
            Ok(_) => {
                tracing::debug!(subscription_info=%subscription_info, hit, "yang library reference sent to requester");
            }
            Err(err) => {
                tracing::warn!(
                    subscription_info = %subscription_info,
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
        let hit = yang_lib_ref.is_some();
        match sender.send((content_id.clone(), yang_lib_ref)).await {
            Ok(_) => {
                tracing::debug!(content_id, hit, "yang library reference sent to requester");
            }
            Err(err) => {
                tracing::warn!(
                    content_id,
                    hit,
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
        let response = CacheResponse {
            subscription_info: subscription_info.clone(),
            yang_lib_ref,
        };
        match sender.send(response) {
            Ok(_) => {
                tracing::debug!(subscription_info=%subscription_info, hit, "yang library reference sent (oneshot) to requester");
            }
            Err(_err) => {
                tracing::warn!(
                    subscription_info = %subscription_info,
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
                tracing::debug!(
                    content_id,
                    hit,
                    "yang library reference sent (oneshot) to requester"
                );
            }
            Err(_err) => {
                tracing::warn!(
                    content_id,
                    hit,
                    "failed to send (oneshot) yang library reference to requester"
                );
            }
        }
    }

    async fn process_worker_result(&mut self, worker_result: Result<FetcherResult, JoinError>) {
        match worker_result {
            Err(err) => {
                tracing::warn!(error=%err, "cache actor worker failed to execute a task");
            }
            Ok(Err(err)) => {
                tracing::warn!(error=%err, "cache actor worker failed");
            }
            Ok(Ok((subscription_info, yang_lib, schemas))) => {
                tracing::info!(
                    subscription_info = %subscription_info,
                    modules_count = schemas.len(),
                    content_id = yang_lib.content_id(),
                    "fetched yang library from device successfully"
                );
                let result = self.schema_cache.put_yang_library(
                    subscription_info.clone(),
                    yang_lib,
                    schemas,
                );
                let yang_lib_ref = match result {
                    Ok(yang_lib_ref) => {
                        tracing::info!(
                            subscription_info=%subscription_info,
                            "yang library for subscription info stored in cache successfully"
                        );
                        Some(yang_lib_ref)
                    }
                    Err(err) => {
                        tracing::warn!(
                            subscription_info = %subscription_info,
                            error = %err,
                            "failed to store yang library in cache"
                        );
                        None
                    }
                };
                let pending_senders = self.pending_requests.remove(&subscription_info);
                if let Some(pending_senders) = pending_senders {
                    for sender in pending_senders {
                        Self::send_yang_lib_ref(&subscription_info, yang_lib_ref.clone(), sender)
                            .await;
                    }
                }
            }
        }
    }

    async fn process_request(&mut self, request: CacheLookupCommand) {
        match request {
            CacheLookupCommand::LookupBySubscriptionInfo(subscription_info, sender) => {
                tracing::debug!(subscription_info=%subscription_info, "processing cache lookup request");
                let yang_lib_ref = self
                    .schema_cache
                    .get_by_subscription_info(&subscription_info);
                match yang_lib_ref {
                    Some(yang_lib_ref) => {
                        Self::send_yang_lib_ref(&subscription_info, Some(yang_lib_ref), sender)
                            .await;
                    }
                    None => {
                        // YANG Library Reference is not found in the cache.
                        // Start a new worker to fetch the YANG Library from the server.
                        let entry = self
                            .pending_requests
                            .entry(subscription_info.clone())
                            .or_default();
                        let is_first_request = entry.is_empty();
                        entry.push(sender);

                        if is_first_request {
                            tracing::info!(
                                subscription_info = %subscription_info,
                                "cache miss: starting fetch from device"
                            );
                            let job = self.fetcher.fetch(subscription_info).await;
                            self.workers_queue.push(job);
                        } else {
                            tracing::debug!(  // Changed to debug
                                subscription_info = %subscription_info,
                                pending_count = entry.len(),
                                "cache miss: fetch in progress, queuing request"
                            );
                        }
                    }
                }
            }
            CacheLookupCommand::LookupBySubscriptionInfoOneShot(subscription_info, sender) => {
                tracing::debug!(subscription_info=%subscription_info, "processing cache lookup request (one shot)");
                // fetch the schemas if needed from the device
                if self
                    .schema_cache
                    .get_by_subscription_info(&subscription_info)
                    .is_none()
                {
                    let worker_result =
                        self.fetcher.fetch_blocking(subscription_info.clone()).await;
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
                tracing::debug!(peer=%peer, subscription_id, "processing cache lookup request");
                let response = self
                    .schema_cache
                    .get_by_subscription_id(peer.ip(), subscription_id);
                if let Some((subscription_info, yang_lib_ref)) = response {
                    Self::send_yang_lib_ref(&subscription_info, yang_lib_ref, tx).await;
                } else {
                    // TODO: lookup subscription direction from router config
                    tracing::warn!(peer=%peer, subscription_id, "cache miss: subscription id not found in cache");
                }
            }
            CacheLookupCommand::LookupBySubscriptionIdOneShot {
                peer,
                subscription_id,
                tx,
            } => {
                tracing::debug!(peer=%peer, subscription_id, "processing cache lookup request (one shot)");
                let response = self
                    .schema_cache
                    .get_by_subscription_id(peer.ip(), subscription_id);
                if let Some((subscription_info, yang_lib_ref)) = response {
                    Self::send_yang_lib_ref_oneshot(&subscription_info, yang_lib_ref, tx);
                } else {
                    // TODO: lookup subscription direction from router config
                    tracing::warn!(peer=%peer, subscription_id, "cache miss: subscription id not found in cache");
                }
            }
            CacheLookupCommand::LookupByContentId(content_id, sender) => {
                tracing::debug!(content_id, "processing cache lookup request");
                let yang_lib_ref = self.schema_cache.get_by_content_id(&content_id);
                Self::send_yang_lib_ref_content_id(&content_id, yang_lib_ref, sender).await;
            }
            CacheLookupCommand::LookupByContentIdOneShot(content_id, sender) => {
                tracing::debug!(content_id, "processing cache lookup request (one shot)");
                let yang_lib_ref = self.schema_cache.get_by_content_id(&content_id);
                Self::send_yang_lib_ref_oneshot_content_id(&content_id, yang_lib_ref, sender);
            }
        }
    }

    async fn run(mut self) -> Result<String, CacheActorCacheError> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(CacheActorCommand::Shutdown) => {
                            tracing::info!(
                                pending_requests = self.pending_requests.len(),
                                active_workers = self.workers_queue.len(),
                                "cache actor shutting down and aborting all active workers"
                            );
                            for task in self.workers_queue {
                                task.abort();
                            }
                            Ok("Schema cache shutdown successful".to_string())
                        }
                        None => {
                            tracing::warn!(
                                pending_requests = self.pending_requests.len(),
                                active_workers = self.workers_queue.len(),
                                "cache actor channel closed unexpectedly due to closed command channel"
                            );
                            for task in self.workers_queue {
                                task.abort();
                            }
                            Ok("Schema cache shutdown successful".to_string())
                        }
                    }
                }
                work_result = self.workers_queue.next(), if !self.workers_queue.is_empty()=> {
                    if let Some(work_result) = work_result {
                        self.process_worker_result(work_result).await;
                    }
                }
                request = self.requests.recv() => {
                    if let Ok(request) = request {
                        self.process_request(request).await;
                    } else {
                        tracing::warn!(
                            pending_requests = self.pending_requests.len(),
                            active_workers = self.workers_queue.len(),
                            "cache actor channel closed unexpectedly due to closed request channel"
                        );
                        for task in self.workers_queue {
                            task.abort();
                        }
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
    ) -> Result<(JoinHandle<Result<String, CacheActorCacheError>>, Self), CacheActorHandleError>
    {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (requests_tx, requests_rx) = async_channel::bounded(buffer_size);
        let schema_cache = match schema_cache {
            either::Either::Left(schema_cache) => schema_cache,
            either::Either::Right(root_path) => YangLibraryCache::from_disk(root_path)?,
        };

        let actor = CacheActor {
            cmd_rx,
            schema_cache,
            requests: requests_rx,
            fetcher,
            pending_requests: FxHashMap::default(),
            workers_queue: FuturesUnordered::new(),
        };

        let handle = Self {
            cmd_tx,
            requests_tx,
        };
        let join_handle = tokio::spawn(actor.run());
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
