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

use std::{collections::HashMap, net::SocketAddr};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

use crate::model::notification::SubscriptionId;

// Cache for YangPush schemas metadata
type SchemaIdx = (SocketAddr, SubscriptionId);
type SchemaCache = HashMap<SchemaIdx, YangSchema>;

#[derive(Debug, Clone)]
pub struct YangSchema {
    pub peer: SocketAddr,
    pub subscription: SubscriptionId,
    pub library: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum SchemaCacheActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display)]
pub enum SchemaCacheActorError {
    #[strum(to_string = "schema request error")]
    SchemaRequestError,
}

impl std::error::Error for SchemaCacheActorError {}

#[derive(Debug, Clone)]
pub struct SchemaCacheStats {
    requests: opentelemetry::metrics::Counter<u64>,
    #[allow(dead_code)]
    schemas_cached: opentelemetry::metrics::Gauge<u64>,
}

impl SchemaCacheStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let requests = meter
            .u64_counter("netgauze.schema_cache.requests")
            .with_description("Number of received schema requests")
            .build();
        let schemas_cached = meter
            .u64_gauge("netgauze.schema_cache.schemas")
            .with_description("Number of cached schemas")
            .build();
        Self {
            requests,
            schemas_cached,
        }
    }
}

struct SchemaCacheActor {
    cmd_rx: mpsc::Receiver<SchemaCacheActorCommand>,
    schema_rx: mpsc::Receiver<YangSchema>,
    schema_tx: mpsc::Sender<YangSchema>,
    schemas: SchemaCache,
    stats: SchemaCacheStats,
}

impl SchemaCacheActor {
    fn new(
        cmd_rx: mpsc::Receiver<SchemaCacheActorCommand>,
        schema_rx: mpsc::Receiver<YangSchema>,
        schema_tx: mpsc::Sender<YangSchema>,
        stats: SchemaCacheStats,
    ) -> Self {
        info!("Creating schema cache actor");
        Self {
            cmd_rx,
            schema_rx,
            schema_tx,
            schemas: HashMap::new(),
            stats,
        }
    }

    // Retrieves subscription metadata from the cache based on the peer address
    // and subscription ID
    fn get_schema(
        &self,
        peer: SocketAddr,
        subscr_id: SubscriptionId,
    ) -> Result<Option<YangSchema>, SchemaCacheActorError> {
        // Get schema information from the cache
        debug!(
            "Retrieving schema for peer: {}, subscription id: {}",
            peer, subscr_id
        );
        let idx = (peer, subscr_id);
        let schema = self.schemas.get(&idx);
        match schema {
            Some(schema) => Ok(Some(schema.clone())),
            None => {
                // TODO: retrieve schema information from peer
                let schema = YangSchema {
                    peer,
                    subscription: subscr_id,
                    library: Some("E96CB84D-F02B-4FBF-BE86-3580300CD964".to_string()),
                    path: Some("models".to_string()),
                };
                Ok(Some(schema))
            }
        }
    }

    // Main loop for the actor: handling commands and incoming notification
    // messages
    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(SchemaCacheActorCommand::Shutdown) => {
                            info!("Shutting down schema cache actor");
                            Ok("Schema cache shutdown successfully".to_string())
                        }
                        None => {
                            warn!("Schema cache actor terminated due to command channel closing");
                            Ok("Schema cache shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.schema_rx.recv() => {
                    let msg = msg.ok_or(SchemaCacheActorError::SchemaRequestError);
                    match msg {
                        Ok(request) => {
                            let peer = request.peer;
                            let subscription = request.subscription;
                            debug!("Received schema request for peer: {}, subscription id: {}",
                                peer, subscription);
                            self.stats.requests.add(1, &[
                                opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                                opentelemetry::KeyValue::new("network.peer.port", opentelemetry::Value::I64(peer.port().into())),
                            ]);
                            let response = self.get_schema(
                                peer,
                                subscription,
                            ) .map_err(|_| SchemaCacheActorError::SchemaRequestError)?;
                            self.schema_tx
                                .send(response.unwrap())
                                .await
                                .map_err(|_| SchemaCacheActorError::SchemaRequestError)?;
                        }
                        Err(err) => {
                            error!("Schema request error: {err}");
                            Err(SchemaCacheActorError::SchemaRequestError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum SchemaCacheActorHandleError {
    #[strum(to_string = "failed to send command to the schema caching actor")]
    SendError,
}

impl std::error::Error for SchemaCacheActorHandleError {}

// Handle for interacting with the `SchemaCacheActor`
#[derive(Debug, Clone)]
pub struct SchemaCacheActorHandle {
    pub(crate) cmd_tx: mpsc::Sender<SchemaCacheActorCommand>,
}

impl SchemaCacheActorHandle {
    pub fn new(
        buffer_size: usize,
        stats: either::Either<opentelemetry::metrics::Meter, SchemaCacheStats>,
    ) -> (JoinHandle<Result<String, anyhow::Error>>, Self) {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (schema_tx, schema_rx) = mpsc::channel(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => SchemaCacheStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = SchemaCacheActor::new(cmd_rx, schema_rx, schema_tx.clone(), stats);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_tx };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), SchemaCacheActorHandleError> {
        self.cmd_tx
            .send(SchemaCacheActorCommand::Shutdown)
            .await
            .map_err(|_| SchemaCacheActorHandleError::SendError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    fn setup_actor() -> (
        JoinHandle<Result<String, anyhow::Error>>,
        SchemaCacheActorHandle,
    ) {
        let meter = opentelemetry::global::meter("test-meter");
        let (join_handle, handle) =
            SchemaCacheActorHandle::new(10, either::Either::Left(meter.clone()));
        (join_handle, handle)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_actor_lifecycle() {
        let (join_handle, handle) = setup_actor();

        // Test shutdown
        let _shutdown_result = handle.shutdown().await;
        // Ensure the actor has terminated
        let result = tokio::time::timeout(Duration::from_secs(5), join_handle).await;
        assert!(result.is_ok(), "actor should have terminated");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_schema() {
        let actor = SchemaCacheActor::new(
            mpsc::channel(10).1,
            mpsc::channel(10).1,
            mpsc::channel(10).0,
            SchemaCacheStats::new(opentelemetry::global::meter("test-meter")),
        );

        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let subscr_id: SubscriptionId = 1;
        let schema = actor.get_schema(peer, subscr_id).unwrap();
        assert!(schema.is_some(), "Schema should not be None");
        assert_eq!(
            schema.clone().expect("Schema should be Some").library,
            Some("E96CB84D-F02B-4FBF-BE86-3580300CD964".to_string())
        );
        assert_eq!(
            schema.clone().expect("Schema should be Some").path,
            Some("models".to_string())
        );
    }
}
