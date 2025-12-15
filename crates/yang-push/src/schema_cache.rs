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

use crate::ContentId;
use schema_registry_converter::schema_registry_common::SuppliedSchema;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

// Cache for YangPush schemas and metadata
type SchemaLookupCache = HashMap<SchemaIdx, ContentId>;
type SchemaInfoCache = HashMap<ContentId, SchemaInfo>;
// TODO: move to native schema struct and integrate in single cache
type SchemaCache = HashMap<ContentId, SuppliedSchema>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SchemaIdx {
    store_content_id: ContentId,
    xpath: String,
    models: Vec<String>,
}
impl SchemaIdx {
    fn new(store_content_id: ContentId, xpath: String, models: Vec<String>) -> Self {
        Self {
            store_content_id,
            xpath,
            models,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchemaInfo {
    yanglib_path: String,
    search_dir: String,
    content_id: Option<ContentId>,
}
impl SchemaInfo {
    fn new() -> Self {
        let content_id: ContentId = "E96CB84D-F02B-4FBF-BE86-3580300CD964".into();
        let top_dir = "../../assets/yang/".to_string() + &content_id + "/";
        let yanglib_path = top_dir.clone() + "yanglib.json";
        let search_dir = top_dir.clone() + "models";
        Self {
            yanglib_path,
            search_dir,
            content_id: Some(content_id),
        }
    }
    pub fn yanglib_path(&self) -> String {
        self.yanglib_path.clone()
    }
    pub fn search_dir(&self) -> String {
        self.search_dir.clone()
    }
    pub fn content_id(&self) -> Option<ContentId> {
        self.content_id.clone()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SchemaRequest {
    peer_address: SocketAddr,
    store_content_id: ContentId,
    xpath: String,
    models: Vec<String>,
}
impl SchemaRequest {
    pub fn new(
        peer_address: SocketAddr,
        store_content_id: ContentId,
        xpath: String,
        models: Vec<String>,
    ) -> Self {
        Self {
            peer_address,
            store_content_id,
            xpath,
            models,
        }
    }
    pub fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    pub fn store_content_id(&self) -> &str {
        &self.store_content_id
    }

    pub fn xpath(&self) -> &str {
        &self.xpath
    }

    pub fn models(&self) -> &[String] {
        &self.models
    }
}

#[derive(Debug, Clone)]
pub enum SchemaCacheActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum SchemaCacheRequest {
    SchemaRequestForPeer(SchemaRequest),
    SchemaRequestForContent(ContentId),
}

#[derive(Debug, Clone)]
pub enum SchemaCacheResponse {
    SchemaResponseForPeer((SchemaRequest, SchemaInfo)),
    SchemaResponseForContent((ContentId, SchemaInfo)),
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
}

impl SchemaCacheStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let requests = meter
            .u64_counter("netgauze.schema_cache.requests")
            .with_description("Number of received schema requests")
            .build();
        Self { requests }
    }
}

struct SchemaCacheActor {
    cmd_rx: mpsc::Receiver<SchemaCacheActorCommand>,
    validation_req_rx: async_channel::Receiver<SchemaRequest>,
    validation_resp_tx: async_channel::Sender<(SchemaRequest, SchemaInfo)>,
    kafka_yang_req_rx: async_channel::Receiver<(ContentId, oneshot::Sender<SuppliedSchema>)>,
    schema_idx: SchemaLookupCache,
    schema_info: SchemaInfoCache,
    schema_cache: SchemaCache,
    stats: SchemaCacheStats,
}

impl SchemaCacheActor {
    fn new(
        cmd_rx: mpsc::Receiver<SchemaCacheActorCommand>,
        validation_req_rx: async_channel::Receiver<SchemaRequest>,
        validation_resp_tx: async_channel::Sender<(SchemaRequest, SchemaInfo)>,
        kafka_yang_req_rx: async_channel::Receiver<(ContentId, oneshot::Sender<SuppliedSchema>)>,
        stats: SchemaCacheStats,
    ) -> Self {
        info!("Creating schema cache actor");
        Self {
            cmd_rx,
            validation_req_rx,
            validation_resp_tx,
            kafka_yang_req_rx,
            schema_idx: HashMap::new(),
            schema_info: HashMap::new(),
            schema_cache: HashMap::new(),
            stats,
        }
    }

    fn get_schema_info(&self, content_id: &ContentId) -> Option<SchemaInfo> {
        self.schema_info.get(content_id).cloned()
    }

    fn get_schema(&self, content_id: &ContentId) -> Option<SuppliedSchema> {
        self.schema_cache.get(content_id).cloned()
    }

    // Retrieves subscription metadata from the cache based on the peer address
    // and subscription ID
    pub fn request_schema(
        &self,
        request: SchemaRequest,
    ) -> Result<Option<SchemaInfo>, SchemaCacheActorError> {
        // Get schema information from the cache
        debug!("Requesting schema info for peer: {}", request.peer_address);
        let res = self.schema_idx.get(&SchemaIdx::new(
            request.store_content_id.clone(),
            request.xpath.clone(),
            request.models.clone(),
        ));
        if res.is_some() {
            let content_id = res.cloned().unwrap();
            let schema = self.get_schema_info(&content_id);
            if schema.is_some() {
                return Ok(schema);
            }
        }

        // TODO: retrieve schema information from peer
        let schema = SchemaInfo::new( /* TODO: request.peer_address, request.subscription_id, */
        );
        Ok(Some(schema))
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
                            Ok("Schema cache shutdown successful".to_string())
                        }
                        None => {
                            warn!("Schema cache actor terminated due to command channel closing");
                            Ok("Schema cache shutdown successful".to_string())
                        }
                    }
                }
                kafka_req = self.kafka_yang_req_rx.recv() => {
                  match kafka_req {
                      Ok((content_id, oneshot_tx)) => {
                          debug!("Received Schema Request from KafkaYang for content_id {}",
                              content_id
                          );
                          match self.get_schema(&content_id) {
                              Some(supplied_schema) => {
                                  if oneshot_tx.send(supplied_schema).is_err() {
                                      warn!("Failed to send schema response: receiver dropped for content ID {}", content_id);
                                  }
                              },
                              None => warn!("Schema not found in cache for content ID {}", content_id),
                          }
                      },
                      Err(err) => {
                          error!("Schema request error: {}", err);
                      }
                  }
                }
                validation_req = self.validation_req_rx.recv() => {
                    match validation_req {
                        Ok(schema_request) => {
                            debug!("Received Schema Request from Validation for peer {}",
                                schema_request.peer_address()
                            );
                            self.stats.requests.add(1, &[
                                opentelemetry::KeyValue::new("network.peer.address", format!("{}", schema_request.peer_address.ip())),
                            ]);
                            match self.request_schema(schema_request.clone()) {
                                 Ok(Some(schema_info)) => {
                                    // Cache the schema information
                                    if let Some(content_id) = &schema_info.content_id {
                                        self.schema_info.insert(content_id.clone(), schema_info.clone());
                                        self.schema_idx.insert(SchemaIdx::new(
                                            schema_request.store_content_id.clone(),
                                            schema_request.xpath.clone(),
                                            schema_request.models.clone(),
                                        ), content_id.clone());
                                    }
                                    // Send back the schema response
                                    self.validation_resp_tx.send((schema_request.clone(), schema_info)).await.unwrap_or_else(|e| {
                                        error!("Failed to send schema response: {}", e);
                                    });
                                    continue;
                                }
                                Ok(None) => {
                                    debug!("Schema not found for peer {}", schema_request.peer_address);
                                }
                                Err(e) => {
                                    error!("Error requesting schema for peer {}: {}", schema_request.peer_address, e);
                                }
                            }
                        }
                        Err(err) => {
                            error!("Schema request error: {}", err);
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

/// Handle for interacting with the `SchemaCacheActor`
#[derive(Debug, Clone)]
pub struct SchemaCacheActorHandle {
    cmd_tx: mpsc::Sender<SchemaCacheActorCommand>,
    pub validation_req_tx: async_channel::Sender<SchemaRequest>,
    pub validation_resp_rx: async_channel::Receiver<(SchemaRequest, SchemaInfo)>,
    pub kafka_yang_req_tx: async_channel::Sender<(ContentId, oneshot::Sender<SuppliedSchema>)>,
}

impl SchemaCacheActorHandle {
    pub fn new(
        buffer_size: usize,
        stats: either::Either<opentelemetry::metrics::Meter, SchemaCacheStats>,
    ) -> (JoinHandle<Result<String, anyhow::Error>>, Self) {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let (validation_req_tx, validation_req_rx) = async_channel::bounded(buffer_size);
        let (validation_resp_tx, validation_resp_rx) = async_channel::bounded(buffer_size);
        let (kafka_yang_req_tx, kafka_yang_req_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => SchemaCacheStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = SchemaCacheActor::new(
            cmd_rx,
            validation_req_rx,
            validation_resp_tx,
            kafka_yang_req_rx,
            stats,
        );
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_tx,
            validation_req_tx,
            validation_resp_rx,
            kafka_yang_req_tx,
        };
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
            async_channel::bounded(10).1,
            async_channel::bounded(10).0,
            async_channel::bounded(10).1,
            SchemaCacheStats::new(opentelemetry::global::meter("test-meter")),
        );
        let request = SchemaRequest {
            peer_address: SocketAddr::from(([127, 0, 0, 1], 12345)),
            store_content_id: "D11685CF-46BD-440D-BE00-38F5C87A0359".to_string(),
            xpath: "".to_string(),
            models: vec!["ietf-interfaces".to_string()],
        };
        let schema = actor.request_schema(request).unwrap();
        assert!(schema.is_some(), "Schema should not be None");
        assert_eq!(
            schema.clone().expect("Schema should be Some").yanglib_path,
            "../../assets/yang/E96CB84D-F02B-4FBF-BE86-3580300CD964/yanglib.json".to_string()
        );
        assert_eq!(
            schema.clone().expect("Schema should be Some").search_dir,
            "../../assets/yang/E96CB84D-F02B-4FBF-BE86-3580300CD964/models".to_string()
        );
    }
}
