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
use netgauze_netconf_proto::client::{NetconfSshConnectConfig, SshAuth, SshHandler, connect};
use netgauze_netconf_proto::yanglib::{PermissiveVersionChecker, YangLibrary};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

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
    user: String,
    private_key: Arc<russh::keys::ssh_key::PrivateKey>,
    client_config: Arc<russh::client::Config>,
    default_port: u16,
    default_timeout: std::time::Duration,
}

impl NetconfYangLibraryFetcher {
    pub fn new(
        user: String,
        private_key: Arc<russh::keys::ssh_key::PrivateKey>,
        client_config: russh::client::Config,
        default_port: u16,
        default_timeout: std::time::Duration,
    ) -> Self {
        Self {
            user,
            private_key,
            client_config: Arc::new(client_config),
            default_port,
            default_timeout,
        }
    }

    async fn fetch_from_device(
        timeout_duration: std::time::Duration,
        subscription_info: SubscriptionInfo,
        user: String,
        private_key: Arc<russh::keys::ssh_key::PrivateKey>,
        client_config: Arc<russh::client::Config>,
        default_port: u16,
    ) -> FetcherResult {
        let host = SocketAddr::new(subscription_info.peer().ip(), default_port);
        info!(
            host = %host,
            subscription_info = %subscription_info,
            "fetching YANG Library from device",
        );
        let ssh_handler = SshHandler::default();
        let auth = SshAuth::Key { user, private_key };
        let config = NetconfSshConnectConfig::new(auth, host, ssh_handler, client_config);

        let mut client = match tokio::time::timeout(timeout_duration, connect(config)).await {
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
            .map(|x| x.as_str())
            .collect::<Vec<_>>();
        // TODO: add timeout to loading YANG Library from the device
        let (yang_lib, schemas) = client
            .load_from_modules(&modules, &PermissiveVersionChecker)
            .await
            .map_err(|err| (subscription_info.clone(), err.into()))?;
        match tokio::time::timeout(timeout_duration, client.close()).await {
            Ok(Ok(_)) => {
                info!(host=%host,"SSH connection closed successfully");
            }
            Ok(Err(err)) => warn!(host=%host, error=%err, "Error closing SSH connection"),
            Err(err) => {
                warn!(host=%host, error=%err, "Timeout while closing SSH connection")
            }
        }
        info!( host = %host,
            subscription_info = %subscription_info,
            content_id = %yang_lib.content_id(),
            schema_count = schemas.len(),
            "YANG Library fetched from device");
        Ok((subscription_info, yang_lib, schemas))
    }
}

impl YangLibraryFetcher for NetconfYangLibraryFetcher {
    async fn fetch(&self, subscription_info: SubscriptionInfo) -> JoinHandle<FetcherResult> {
        let f = Self::fetch_from_device(
            self.default_timeout,
            subscription_info,
            self.user.clone(),
            Arc::clone(&self.private_key),
            self.client_config.clone(),
            self.default_port,
        );
        tokio::spawn(f)
    }

    async fn fetch_blocking(&self, subscription_info: SubscriptionInfo) -> FetcherResult {
        Self::fetch_from_device(
            self.default_timeout,
            subscription_info,
            self.user.clone(),
            Arc::clone(&self.private_key),
            self.client_config.clone(),
            self.default_port,
        )
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
            for (sub_info, (yang_lib, _schemas)) in &yang_libs {
                info!(
                    subscription_info=%sub_info,
                    content_id=yang_lib.content_id(),
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
            info!(subscription_info=%subscription_info, "fetching from device");
            // Increment counter in the instance state
            {
                let mut counts = self.fetch_counts.lock().unwrap();
                *counts.entry(subscription_info.clone()).or_default() += 1;
            }

            let (yang_lib, schemas) = self.yang_libs.get(&subscription_info).cloned().ok_or_else(
                || {
                    info!(subscription_info=%subscription_info, "YANG Library not found in cache");
                    (
                        subscription_info.clone(),
                        YangLibraryCacheError::IoError(std::io::Error::other("not found")),
                    )
                },
            )?;
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
    }
}
