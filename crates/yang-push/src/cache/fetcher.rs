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

//! YANG Library fetching from external sources.
//!
//! This module provides abstractions for retrieving YANG libraries and schemas
//! from network devices. The primary implementation fetches data via NETCONF
//! over SSH.
//!
//! # Architecture
//!
//! - [`YangLibraryFetcher`]: Trait defining the fetch interface
//! - [`NetconfYangLibraryFetcher`]: NETCONF/SSH implementation
//! - [`FetcherResult`]: Type alias for fetch operation results

use crate::cache::storage::{SubscriptionInfo, YangLibraryCacheError};
use netgauze_netconf_proto::capabilities::{Capability, NetconfVersion};
use netgauze_netconf_proto::client::{NetconfSshConnectConfig, SshAuth, SshHandler, connect};
use netgauze_netconf_proto::yang_push::filters::StreamSelectionFilterObjects;
use netgauze_netconf_proto::yang_push::subscription::{
    DatastoreSelectionFilterObjects, Target, YangPushModuleVersion,
};
use netgauze_netconf_proto::yang_push::types::SubscriptionId;
use netgauze_netconf_proto::yanglib::{DatastoreName, PermissiveVersionChecker, YangLibrary};
use rand::RngExt;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{error, info, trace, warn};

pub type FetcherResult = Result<
    (SubscriptionInfo, YangLibrary, HashMap<Box<str>, Box<str>>),
    (SubscriptionInfo, YangLibraryCacheError),
>;

/// Fetch YANG Library and schemas from an external source
pub trait YangLibraryFetcher {
    /// A non-blocking version which returns a [JoinHandle]
    /// to the worker getting the YANG Library and schemas
    fn fetch(
        &self,
        subscription_info: SubscriptionInfo,
    ) -> impl Future<Output = JoinHandle<FetcherResult>> + Send;

    /// A blocking version which returns directly the YANG library and schemas.
    fn fetch_blocking(
        &self,
        subscription_info: SubscriptionInfo,
    ) -> impl Future<Output = FetcherResult> + Send;

    fn fetch_by_subscription_id(
        &self,
        peer: SocketAddr,
        subscription_id: SubscriptionId,
    ) -> impl Future<Output = JoinHandle<FetcherResult>> + Send;

    fn fetch_by_subscription_id_blocking(
        &self,
        peer: SocketAddr,
        subscription_id: SubscriptionId,
    ) -> impl Future<Output = FetcherResult> + Send;
}

#[derive(Clone)]
struct FetchConfig {
    user: String,
    private_key: Arc<russh::keys::ssh_key::PrivateKey>,
    client_config: Arc<russh::client::Config>,
    default_port: u16,
    timeout: std::time::Duration,
}

#[derive(Clone, Copy)]
struct RetryConfig {
    max_retries: u32,
    max_backoff: std::time::Duration,
}

/// A [YangLibraryFetcher] which fetches the YANG Library and schemas
/// from a NETCONF device over SSH.
///
/// TODO: Add support for other authentication methods
/// (e.g., password, keyboard-interactive)
///
/// TODO: Add support for custom ports per device
///
/// TODO: Add peer to management address mapping support for devices using
/// different IP address to send the YANG-Push messages
pub struct NetconfYangLibraryFetcher {
    fetch_cfg: FetchConfig,
    retry_cfg: RetryConfig,
}

/// Base delay for exponential backoff (1 second).
const BASE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

impl NetconfYangLibraryFetcher {
    pub fn new(
        user: String,
        private_key: Arc<russh::keys::ssh_key::PrivateKey>,
        client_config: russh::client::Config,
        default_port: u16,
        default_timeout: std::time::Duration,
    ) -> Self {
        Self {
            fetch_cfg: FetchConfig {
                user,
                private_key,
                client_config: Arc::new(client_config),
                default_port,
                timeout: default_timeout,
            },
            retry_cfg: RetryConfig {
                max_retries: 10,
                max_backoff: std::time::Duration::from_secs(60),
            },
        }
    }

    /// Set the maximum number of retry attempts. Set to 0 to disable retries.
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.retry_cfg.max_retries = max_retries;
        self
    }

    /// Set the maximum backoff duration between retries.
    pub fn with_max_backoff(mut self, max_backoff: std::time::Duration) -> Self {
        self.retry_cfg.max_backoff = max_backoff;
        self
    }

    async fn fetch_from_device(
        cfg: &FetchConfig,
        subscription_info: SubscriptionInfo,
    ) -> FetcherResult {
        let host = SocketAddr::new(subscription_info.peer().ip(), cfg.default_port);
        info!(
            host=%host,
            peer=%subscription_info.peer(),
            subscription_id=subscription_info.id(),
            router_content_id=subscription_info.content_id(),
            target=%subscription_info.target(),
            "starting fetching YANG Library from device",
        );
        let ssh_handler = SshHandler::default();
        let auth = SshAuth::Key {
            user: cfg.user.clone(),
            private_key: Arc::clone(&cfg.private_key),
        };
        let announce_caps = HashSet::from([Capability::NetconfBase(NetconfVersion::V1_1)]);
        let config = NetconfSshConnectConfig::new(
            auth,
            host,
            announce_caps,
            ssh_handler,
            Arc::clone(&cfg.client_config),
        );

        let mut client = match tokio::time::timeout(cfg.timeout, connect(config)).await {
            Ok(Ok(c)) => c,
            Ok(Err(err)) => {
                error!(host=%host,error=%err, "error connecting to device over SSH");
                return Err((subscription_info.clone(), err.into()));
            }
            Err(err) => {
                error!(host=%host,error=%err, "timeout while connecting to device over SSH");
                return Err((subscription_info.clone(), err.into()));
            }
        };
        let modules = subscription_info
            .models()
            .iter()
            .map(|x| x.name())
            .collect::<Vec<_>>();
        // TODO: add timeout to loading YANG Library from the device
        let (yang_lib, schemas) = client
            .load_from_modules(&modules, &PermissiveVersionChecker)
            .await
            .map_err(|err| (subscription_info.clone(), err.into()))?;
        match tokio::time::timeout(cfg.timeout, client.close()).await {
            Ok(Ok(_)) => {
                info!(host=%host,"SSH connection closed successfully");
            }
            Ok(Err(err)) => warn!(host=%host, error=%err, "Error closing SSH connection"),
            Err(err) => {
                warn!(host=%host, error=%err, "Timeout while closing SSH connection")
            }
        }
        info!( host = %host,
            peer=%subscription_info.peer(),
            subscription_id=subscription_info.id(),
            router_content_id=subscription_info.content_id(),
            target=%subscription_info.target(),
            cached_content_id=yang_lib.content_id(),
            schema_count = schemas.len(),
            "YANG Library fetched from device");
        Ok((subscription_info, yang_lib, schemas))
    }

    async fn fetch_from_device_by_id(
        cfg: &FetchConfig,
        peer: SocketAddr,
        subscription_id: SubscriptionId,
    ) -> FetcherResult {
        let host = SocketAddr::new(peer.ip(), cfg.default_port);
        info!(
            host=%host,
            peer=%peer,
            subscription_id,
            "starting fetching YANG Library from device",
        );
        let ssh_handler = SshHandler::default();
        let auth = SshAuth::Key {
            user: cfg.user.clone(),
            private_key: Arc::clone(&cfg.private_key),
        };
        let announce_caps = HashSet::from([Capability::NetconfBase(NetconfVersion::V1_1)]);
        let config = NetconfSshConnectConfig::new(
            auth,
            host,
            announce_caps,
            ssh_handler,
            Arc::clone(&cfg.client_config),
        );
        // Empty subscription info returned in case of errors to keep track of peer and
        // subscription ID
        let empty = SubscriptionInfo::new_empty(peer, subscription_id);
        let mut client = match tokio::time::timeout(cfg.timeout, connect(config)).await {
            Ok(Ok(c)) => c,
            Ok(Err(err)) => {
                error!(host=%host,error=%err, "error connecting to device over SSH");
                return Err((empty, err.into()));
            }
            Err(err) => {
                error!(host=%host,error=%err, "timeout while connecting to device over SSH");
                return Err((empty, err.into()));
            }
        };

        let subscription = client
            .get_yang_push_subscription_by_id(subscription_id)
            .await
            .map_err(|err| (empty.clone(), err.into()))?;
        let router_yang_library = client
            .get_yang_library()
            .await
            .map_err(|err| (empty.clone(), err.into()))?;

        let modules = if let Some(modules) = &subscription.module_version {
            modules.clone().to_vec()
        } else {
            let (ds_name, namespaces) = match &subscription.target {
                Target::Stream(stream_target) => {
                    match &stream_target.filter {
                        StreamSelectionFilterObjects::ByReference(name) => {
                            // references are resolved in the NETCONF client,
                            // if we reach this point, there must be a misconfigured router,
                            return Err((
                                empty,
                                YangLibraryCacheError::IoError(std::io::Error::other(format!(
                                    "cannot fetch YANG Library for stream selection filter by reference for {name}"
                                ))),
                            ));
                        }
                        StreamSelectionFilterObjects::WithInSubscription(filter) => {
                            (DatastoreName::Running, filter.namespaces())
                        }
                    }
                }
                Target::Datastore(datastore_target) => match &datastore_target.selection {
                    DatastoreSelectionFilterObjects::ByReference(name) => {
                        return Err((
                            empty,
                            YangLibraryCacheError::IoError(std::io::Error::other(format!(
                                "cannot fetch YANG Library for datastore selection filter by reference for {name}"
                            ))),
                        ));
                    }
                    DatastoreSelectionFilterObjects::WithInSubscription(filter) => {
                        (datastore_target.datastore.clone(), filter.namespaces())
                    }
                },
            };
            let mut ret = Vec::with_capacity(namespaces.len());
            for (_prefix, namespace) in namespaces {
                let module = router_yang_library.find_module_by_datastore_and_ns(&ds_name, namespace).ok_or_else(|| (empty.clone(), YangLibraryCacheError::IoError(std::io::Error::other(format!("module with namespace {namespace} not found in YANG Library for datastore {ds_name}")))))?;
                ret.push(YangPushModuleVersion::new(
                    module.name().into(),
                    module.revision().map(|x| x.into()),
                    None,
                ));
            }
            ret
        };

        let mut module_names = modules.iter().map(|x| x.name()).collect::<Vec<_>>();
        if !module_names.contains(&"ietf-subscribed-notifications") {
            module_names.push("ietf-subscribed-notifications");
        }
        // TODO: add timeout to loading YANG Library from the device
        let (yang_lib, schemas) = client
            .load_from_modules(&module_names, &PermissiveVersionChecker)
            .await
            .map_err(|err| (empty.clone(), err.into()))?;
        match tokio::time::timeout(cfg.timeout, client.close()).await {
            Ok(Ok(_)) => {
                info!(host=%host,"SSH connection closed successfully");
            }
            Ok(Err(err)) => warn!(host=%host, error=%err, "Error closing SSH connection"),
            Err(err) => {
                warn!(host=%host, error=%err, "Timeout while closing SSH connection")
            }
        }
        let subscription_target = subscription.target.try_into().map_err(|err| {
            (
                empty,
                YangLibraryCacheError::IoError(std::io::Error::other(format!(
                    "invalid subscription target: {err}"
                ))),
            )
        })?;
        let subscription_info = SubscriptionInfo::new(
            peer,
            subscription_id,
            subscription_target,
            subscription.stop_time,
            subscription.transport,
            subscription.encoding,
            subscription.purpose,
            subscription.update_trigger,
            modules.into_boxed_slice(),
            router_yang_library.content_id().to_string(),
        );
        info!( host = %host,
            peer=%peer,
            subscription_id,
            router_content_id=yang_lib.content_id(),
            target=%subscription_info.target(),
            cached_content_id=yang_lib.content_id(),
            schema_count = schemas.len(),
            "YANG Library fetched from device");
        Ok((subscription_info, yang_lib, schemas))
    }

    /// Retry `operation` with exponential backoff and equal jitter.
    ///
    /// `operation` is called up to `retry.max_retries + 1` times. Each failed
    /// attempt waits `base * 2^(attempt-1)` (capped at `retry.max_backoff`)
    /// with equal jitter before the next try.
    async fn with_retry<F, Fut>(retry: RetryConfig, operation: F) -> FetcherResult
    where
        F: Fn() -> Fut,
        Fut: Future<Output = FetcherResult>,
    {
        let mut last_err = None;
        for attempt in 0..=retry.max_retries {
            if attempt > 0 {
                let backoff_secs = BASE_DELAY.as_secs_f64() * 2.0_f64.powi(attempt as i32 - 1);
                let capped = backoff_secs.min(retry.max_backoff.as_secs_f64());
                let half = capped / 2.0;
                let jitter = rand::rng().random_range(0.0..=half);
                let delay = std::time::Duration::from_secs_f64(half + jitter);
                trace!(
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    "retrying YANG Library fetch after backoff",
                );
                tokio::time::sleep(delay).await;
            }
            match operation().await {
                Ok(result) => return Ok(result),
                Err(err) => last_err = Some(err),
            }
        }
        last_err.map(Err).unwrap()
    }
}

impl YangLibraryFetcher for NetconfYangLibraryFetcher {
    async fn fetch(&self, subscription_info: SubscriptionInfo) -> JoinHandle<FetcherResult> {
        let fetch_cfg = self.fetch_cfg.clone();
        let retry_cfg = self.retry_cfg;
        tokio::spawn(async move {
            Self::with_retry(retry_cfg, || {
                Self::fetch_from_device(&fetch_cfg, subscription_info.clone())
            })
            .await
        })
    }

    async fn fetch_blocking(&self, subscription_info: SubscriptionInfo) -> FetcherResult {
        Self::with_retry(self.retry_cfg, || {
            Self::fetch_from_device(&self.fetch_cfg, subscription_info.clone())
        })
        .await
    }

    async fn fetch_by_subscription_id(
        &self,
        peer: SocketAddr,
        subscription_id: SubscriptionId,
    ) -> JoinHandle<FetcherResult> {
        let fetch_cfg = self.fetch_cfg.clone();
        let retry_cfg = self.retry_cfg;
        tokio::spawn(async move {
            Self::with_retry(retry_cfg, || {
                Self::fetch_from_device_by_id(&fetch_cfg, peer, subscription_id)
            })
            .await
        })
    }

    async fn fetch_by_subscription_id_blocking(
        &self,
        peer: SocketAddr,
        subscription_id: SubscriptionId,
    ) -> FetcherResult {
        Self::with_retry(self.retry_cfg, || {
            Self::fetch_from_device_by_id(&self.fetch_cfg, peer, subscription_id)
        })
        .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    #[allow(clippy::type_complexity)]
    pub(crate) struct TestYangLibFetcher {
        pub yang_libs: HashMap<SubscriptionInfo, (YangLibrary, HashMap<Box<str>, Box<str>>)>,
        /// for testing, the number of times a SubscriptionInfo has been fetched
        pub fetch_counts: Arc<Mutex<HashMap<SubscriptionInfo, usize>>>,
    }

    impl TestYangLibFetcher {
        #[allow(clippy::type_complexity)]
        pub(crate) fn new(
            yang_libs: HashMap<SubscriptionInfo, (YangLibrary, HashMap<Box<str>, Box<str>>)>,
        ) -> Self {
            for (subscription_info, (yang_lib, _schemas)) in &yang_libs {
                info!(
                    peer=%subscription_info.peer(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id=yang_lib.content_id(),
                    "Fetcher stored YANG Library in cache",
                )
            }
            Self {
                yang_libs,
                fetch_counts: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        #[allow(clippy::result_large_err)]
        fn get_from_cache(&self, subscription_info: SubscriptionInfo) -> FetcherResult {
            info!(
                peer=%subscription_info.peer(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                "fetching from device by subscription info"
            );
            // Increment counter in the instance state
            {
                let mut counts = self.fetch_counts.lock().unwrap();
                *counts.entry(subscription_info.clone()).or_default() += 1;
            }

            let (yang_lib, schemas) =
                self.yang_libs
                    .get(&subscription_info)
                    .cloned()
                    .ok_or_else(|| {
                        info!(
                            peer=%subscription_info.peer(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            "YANG Library not found in cache"
                        );
                        (
                            subscription_info.clone(),
                            YangLibraryCacheError::IoError(std::io::Error::other("not found")),
                        )
                    })?;
            Ok((subscription_info, yang_lib, schemas))
        }

        #[allow(clippy::result_large_err)]
        fn get_from_cache_by_id(
            &self,
            peer: SocketAddr,
            subscription_id: SubscriptionId,
        ) -> FetcherResult {
            info!(
                peer=%peer,
                subscription_id,
                "fetching from device by id"
            );
            let subscription_info = self
                .yang_libs
                .keys()
                .find(|x| x.id() == subscription_id && x.peer().ip() == peer.ip());
            let subscription_info = if let Some(subscription_info) = subscription_info {
                subscription_info.clone()
            } else {
                SubscriptionInfo::new_empty(peer, subscription_id)
            };
            // Increment counter in the instance state
            {
                let mut counts = self.fetch_counts.lock().unwrap();
                *counts.entry(subscription_info.clone()).or_default() += 1;
            }
            if subscription_info.is_empty() {
                return Err((
                    subscription_info,
                    YangLibraryCacheError::IoError(std::io::Error::other("not found")),
                ));
            }
            let (yang_lib, schemas) =
                self.yang_libs
                    .get(&subscription_info)
                    .cloned()
                    .ok_or_else(|| {
                        info!(
                            peer=%subscription_info.peer(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            "YANG Library not found in cache"
                        );
                        (
                            subscription_info.clone(),
                            YangLibraryCacheError::IoError(std::io::Error::other("not found")),
                        )
                    })?;
            Ok((subscription_info, yang_lib, schemas))
        }
    }

    impl YangLibraryFetcher for TestYangLibFetcher {
        async fn fetch(&self, subscription_info: SubscriptionInfo) -> JoinHandle<FetcherResult> {
            let result = self.get_from_cache(subscription_info);
            tokio::spawn(async move { result })
        }

        async fn fetch_blocking(&self, subscription_info: SubscriptionInfo) -> FetcherResult {
            self.get_from_cache(subscription_info)
        }

        async fn fetch_by_subscription_id(
            &self,
            peer: SocketAddr,
            subscription_id: SubscriptionId,
        ) -> JoinHandle<FetcherResult> {
            let result = self.get_from_cache_by_id(peer, subscription_id);
            tokio::spawn(async move { result })
        }

        async fn fetch_by_subscription_id_blocking(
            &self,
            peer: SocketAddr,
            subscription_id: SubscriptionId,
        ) -> FetcherResult {
            self.get_from_cache_by_id(peer, subscription_id)
        }
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use netgauze_netconf_proto::yanglib::YangLibrary;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn retry_cfg(max_retries: u32) -> RetryConfig {
        RetryConfig {
            max_retries,
            max_backoff: std::time::Duration::from_millis(1),
        }
    }

    fn dummy_peer() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[allow(clippy::result_large_err)]
    fn make_ok() -> FetcherResult {
        let info = SubscriptionInfo::new_empty(dummy_peer(), 1);
        let yang_lib = YangLibrary::new("test-content-id".into(), vec![], vec![], vec![]);
        Ok((info, yang_lib, HashMap::new()))
    }

    #[allow(clippy::result_large_err)]
    fn make_err(msg: &'static str) -> FetcherResult {
        let info = SubscriptionInfo::new_empty(dummy_peer(), 1);
        Err((
            info,
            YangLibraryCacheError::IoError(std::io::Error::other(msg)),
        ))
    }

    /// A single attempt that succeeds immediately — no retries should happen.
    #[tokio::test]
    async fn test_succeeds_on_first_attempt() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let result = NetconfYangLibraryFetcher::with_retry(retry_cfg(5), || {
            let cc = Arc::clone(&cc);
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                make_ok()
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "should not retry on success"
        );
    }

    /// max_retries = 0 means exactly one attempt; failure is returned
    /// immediately.
    #[tokio::test]
    async fn test_no_retry_when_max_retries_zero() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let result = NetconfYangLibraryFetcher::with_retry(retry_cfg(0), || {
            let cc = Arc::clone(&cc);
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                make_err("always fails")
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "should try exactly once"
        );
    }

    /// All attempts fail: the last error is returned and total calls ==
    /// max_retries + 1.
    #[tokio::test]
    async fn test_all_retries_exhausted_returns_last_error() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);
        const MAX_RETRIES: u32 = 3;

        let result = NetconfYangLibraryFetcher::with_retry(retry_cfg(MAX_RETRIES), || {
            let cc = Arc::clone(&cc);
            async move {
                let n = cc.fetch_add(1, Ordering::SeqCst);
                make_err(if n == MAX_RETRIES {
                    "last error"
                } else {
                    "transient"
                })
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            MAX_RETRIES + 1,
            "should attempt max_retries + 1 times total"
        );
    }

    /// Succeeds on the N-th attempt — prior failures must not be surfaced.
    #[tokio::test]
    async fn test_succeeds_after_transient_failures() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);
        const FAIL_FIRST: u32 = 2; // fail twice, succeed on the 3rd call

        let result = NetconfYangLibraryFetcher::with_retry(retry_cfg(5), || {
            let cc = Arc::clone(&cc);
            async move {
                let n = cc.fetch_add(1, Ordering::SeqCst);
                if n < FAIL_FIRST {
                    make_err("transient")
                } else {
                    make_ok()
                }
            }
        })
        .await;

        assert!(result.is_ok(), "should ultimately succeed");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            FAIL_FIRST + 1,
            "should stop retrying once it succeeds"
        );
    }
}
