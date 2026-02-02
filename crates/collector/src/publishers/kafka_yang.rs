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

//! NetGauze YANG-based Kafka Publisher
//!
//! This module provides functionality for publishing JSON messages to Apache
//! Kafka with support for YANG schema registration to Confluent Schema
//! Registry.
//!
//! # Overview
//!
//! The YANG Kafka publisher consists of several key components:
//!
//! - `YangConverter`: A trait that defines how to convert input data to
//!   YANG-compliant JSON
//! - `KafkaConfig`: Configuration for Kafka connection and YANG schema settings
//! - `KafkaYangPublisherActor`: The main actor that handles message publishing
//! - `KafkaYangPublisherActorHandle`: A handle for controlling the publisher
//!   actor
use crate::publishers::LoggingProducerContext;
use ipnet::IpNet;
use netgauze_netconf_proto::yanglib::{
    DependencyError, PermissiveVersionChecker, SchemaConstructionError, SchemaLoadingError,
    YangLibrary,
};
use netgauze_yang_push::ContentId;
use netgauze_yang_push::cache::actor::CacheLookupCommand;
use netgauze_yang_push::cache::storage::{YangLibraryCacheError, YangLibraryReference};
use rdkafka::config::{ClientConfig, FromClientConfigAndContext};
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::{Header, OwnedHeaders};
use rdkafka::producer::{BaseRecord, Producer, ThreadedProducer};
use schema_registry_client::rest::schema_registry_client::{Client, SchemaRegistryClient};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

/// Maximum polling interval when Kafka message queue is full
const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(5);

// --- config ---

/// Trait for converting input data to YANG-compliant JSON format
pub trait YangConverter<T, E: std::error::Error> {
    /// Get optional subject prefix for schema registry
    fn subject_prefix(&self) -> Option<&str>;

    /// Get root schema name (e.g. ietf-telemetry-message)
    fn root_schema_name(&self) -> &str;

    /// Get the default YANG library to be used for messages without a
    /// content_id.
    ///
    /// If none is returned, then the message will be sent to Kafka without a
    /// schema
    fn default_yang_lib(&self) -> Option<&YangLibraryReference>;

    /// Get a YANG library for to extend the schema from the router with.
    ///
    /// If none is returned, then the message from the router is not extended
    /// with any schema
    fn extension_yang_lib_ref(&self) -> Option<&YangLibraryReference>;

    // Get ContentId from the input message
    fn content_id(&self, input: &T) -> Option<ContentId>;

    /// Extract a key from the input message for Kafka partitioning
    fn get_key(&self, input: &T) -> Option<serde_json::Value>;

    /// Serialize the input data to YANG-compliant JSON
    fn serialize_json(&self, input: T) -> Result<serde_json::Value, E>;
}

/// Configuration for the Kafka YANG publisher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig<C>
where
    C: Serialize,
{
    /// Target Kafka topic for publishing messages
    pub topic: String,

    /// Key/Value producer configs are defined in librdkafka
    pub producer_config: HashMap<String, String>,

    /// Unique identifier for this writer instance
    pub writer_id: String,

    /// URL of the Confluent Schema Registry
    pub schema_registry_url: String,

    /// YANG converter implementation
    pub yang_converter: C,
}

// --- telemetry ---

#[derive(Debug, Clone)]
pub struct KafkaYangPublisherStats {
    received: opentelemetry::metrics::Counter<u64>,
    sent: opentelemetry::metrics::Counter<u64>,
    send_retries: opentelemetry::metrics::Counter<u64>,
    error_decode: opentelemetry::metrics::Counter<u64>,
    error_send: opentelemetry::metrics::Counter<u64>,
    delivered_messages: opentelemetry::metrics::Counter<u64>,
    failed_delivery_messages: opentelemetry::metrics::Counter<u64>,
}

impl KafkaYangPublisherStats {
    fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netgauze.collector.kafka.yang.received")
            .with_description("Received messages from upstream producer")
            .build();
        let sent = meter
            .u64_counter("netgauze.collector.kafka.yang.sent")
            .with_description("Number of messages successfully sent to Kafka")
            .build();
        let send_retries = meter
            .u64_counter("netgauze.collector.kafka.yang.send.retries")
            .with_description("Number of send retries to Kafka due to full queue in librdkafka")
            .build();
        let error_decode = meter
            .u64_counter("netgauze.collector.kafka.yang.error_decode")
            .with_description("Error decoding message into YANG")
            .build();
        let error_send = meter
            .u64_counter("netgauze.collector.kafka.yang.error_send")
            .with_description("Error sending message to Kafka")
            .build();
        let delivered_messages = meter
            .u64_counter("netgauze.collector.kafka.yang.delivered_messages")
            .with_description("Messages confirmed to be delivered to Kafka")
            .build();
        let failed_delivery_messages = meter
            .u64_counter("netgauze.collector.kafka.yang.failed_delivery_messages")
            .with_description("Messages failed delivery to Kafka")
            .build();
        Self {
            received,
            sent,
            send_retries,
            error_decode,
            error_send,
            delivered_messages,
            failed_delivery_messages,
        }
    }
}

// --- actor ---

#[derive(Debug, strum_macros::Display)]
pub enum KafkaYangPublisherActorError<E: std::error::Error> {
    /// Error communicating with the Kafka brokers
    #[strum(to_string = "KafkaError: {0}")]
    KafkaError(KafkaError),

    /// Serde JSON Error
    #[strum(to_string = "JSON Error: {0}")]
    JsonError(serde_json::Error),

    /// Error receiving incoming messages from input async_channel
    #[strum(to_string = "Error receiving messages from upstream producer")]
    ReceiveErr,

    /// YANG converter error
    #[strum(to_string = "YangConverterError: {0}")]
    YangConverterError(E),

    /// Error sending cache lookup request to SchemaCache Actor
    #[strum(to_string = "CacheLookupError")]
    CacheLookupError,

    /// YANG Library schema construction error
    #[strum(to_string = "YANG Library Schema Construction Error: {0}")]
    YangLibSchemaError(SchemaConstructionError),

    /// Yang Library dependency error
    #[strum(to_string = "YANG Library Dependency Error: {0}")]
    YangLibDependencyError(DependencyError),

    /// Schema Registration Error
    #[strum(to_string = "Schema Registration Error: {0}")]
    SchemaRegistrationError(String),

    /// YANG Library Cache Error
    #[strum(to_string = "YANG Library Cache Error: {0}")]
    YangLibraryCacheError(YangLibraryCacheError),

    #[strum(to_string = "YANG Library Schema Loading Error: {0}")]
    SchemaLoadingError(SchemaLoadingError),
}

impl<E: std::error::Error> std::error::Error for KafkaYangPublisherActorError<E> {}

impl<E: std::error::Error> From<KafkaError> for KafkaYangPublisherActorError<E> {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}

impl<E: std::error::Error> From<async_channel::SendError<CacheLookupCommand>>
    for KafkaYangPublisherActorError<E>
{
    fn from(_e: async_channel::SendError<CacheLookupCommand>) -> Self {
        Self::CacheLookupError
    }
}

impl<E: std::error::Error> From<SchemaConstructionError> for KafkaYangPublisherActorError<E> {
    fn from(e: SchemaConstructionError) -> Self {
        Self::YangLibSchemaError(e)
    }
}

impl<E: std::error::Error> From<DependencyError> for KafkaYangPublisherActorError<E> {
    fn from(e: DependencyError) -> Self {
        Self::YangLibDependencyError(e)
    }
}

impl<E: std::error::Error> From<YangLibraryCacheError> for KafkaYangPublisherActorError<E> {
    fn from(e: YangLibraryCacheError) -> Self {
        Self::YangLibraryCacheError(e)
    }
}

impl<E: std::error::Error> From<SchemaLoadingError> for KafkaYangPublisherActorError<E> {
    fn from(e: SchemaLoadingError) -> Self {
        Self::SchemaLoadingError(e)
    }
}

#[derive(Debug, Clone, Copy)]
enum KafkaYangPublisherActorCommand {
    Shutdown,
}

/// The main actor responsible for publishing messages to Kafka with YANG
/// schemas
///
/// The actor handles:
/// - receiving messages from an async channel
/// - converting messages using the provided YANG converter
/// - publishing messages to Kafka with proper schema headers
/// - handling retries and error conditions
struct KafkaYangPublisherActor<T, E: std::error::Error, C: YangConverter<T, E>>
where
    T: Send + Sync,
    E: Send + Sync,
    C: Send + Sync + Serialize,
{
    cmd_rx: mpsc::Receiver<KafkaYangPublisherActorCommand>,
    config: KafkaConfig<C>,
    producer: ThreadedProducer<LoggingProducerContext>,
    msg_recv: async_channel::Receiver<T>,
    stats: KafkaYangPublisherStats,
    sr_client: SchemaRegistryClient,
    /// The default schema id to be used with messages that do not have a
    /// content_id
    default_schema_id: Option<i32>,
    /// Extended YANG library to extend the schemas from the router with,
    #[allow(clippy::type_complexity)]
    extension_yang_library: Option<(YangLibrary, HashMap<Box<str>, Box<str>>)>,
    /// [ContentId] to schema registry ID mapping cache
    schema_id_cache: HashMap<ContentId, i32>,
    cache_req_tx: async_channel::Sender<CacheLookupCommand>,
    _phantom: std::marker::PhantomData<(T, E)>,
}

impl<T, E, C> KafkaYangPublisherActor<T, E, C>
where
    T: Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
    C: YangConverter<T, E> + Send + Sync + Serialize,
{
    /// Create a Kafka producer based on configuration
    fn get_producer(
        stats: &KafkaYangPublisherStats,
        config: &KafkaConfig<C>,
    ) -> Result<ThreadedProducer<LoggingProducerContext>, KafkaYangPublisherActorError<E>> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        let producer_context = LoggingProducerContext {
            telemetry_attributes: Box::new([]),
            delivered_messages: stats.delivered_messages.clone(),
            failed_delivery_messages: stats.failed_delivery_messages.clone(),
        };
        match ThreadedProducer::from_config_and_context(&producer_config, producer_context) {
            Ok(p) => Ok(p),
            Err(err) => {
                error!("Failed to create Kafka producer: {err}");
                Err(err)?
            }
        }
    }

    /// Create a new actor instance from configuration
    async fn from_config(
        cmd_rx: mpsc::Receiver<KafkaYangPublisherActorCommand>,
        config: KafkaConfig<C>,
        custom_schemas: HashMap<IpNet, YangLibraryReference>,
        msg_recv: async_channel::Receiver<T>,
        stats: KafkaYangPublisherStats,
        cache_req_tx: async_channel::Sender<CacheLookupCommand>,
    ) -> Result<Self, KafkaYangPublisherActorError<E>> {
        let producer = Self::get_producer(&stats, &config)?;

        // Create the schema registry Client
        let client_conf = schema_registry_client::rest::client_config::ClientConfig::new(vec![
            config.schema_registry_url.clone(),
        ]);
        let sr_client = SchemaRegistryClient::new(client_conf);

        // Load and register provided default schema
        let default_schema_id =
            if let Some(default_yang_lib_ref) = config.yang_converter.default_yang_lib() {
                let default_schema_id = Self::register_yang_lib_ref(
                    &sr_client,
                    default_yang_lib_ref,
                    config.yang_converter.root_schema_name(),
                    config.yang_converter.subject_prefix(),
                )
                .await?;
                Some(default_schema_id)
            } else {
                None
            };

        let extension_yang_library =
            if let Some(yang_lib_ref) = config.yang_converter.extension_yang_lib_ref() {
                let yang_lib = yang_lib_ref.yang_library()?;
                let schemas =
                    yang_lib.load_schemas_from_search_path(yang_lib_ref.search_dir().as_path())?;
                Some((yang_lib, schemas))
            } else {
                None
            };

        // Load and register provided custom schemas
        // (custom schemas are already extended with the telemetry-message schema)
        let mut schema_id_cache = HashMap::new();

        for yang_lib_ref in custom_schemas.values() {
            let content_id = yang_lib_ref.content_id();
            let schema_id = Self::register_yang_lib_ref(
                &sr_client,
                yang_lib_ref,
                config.yang_converter.root_schema_name(),
                config.yang_converter.subject_prefix(),
            )
            .await?;
            // Store schema registry ID in cache
            schema_id_cache.insert(content_id.to_string(), schema_id);
        }

        info!("Root and custom schema loading and registering complete!");
        info!("Starting Kafka YANG publisher to topic: `{}`", config.topic);

        Ok(Self {
            cmd_rx,
            config,
            producer,
            msg_recv,
            stats,
            sr_client,
            default_schema_id,
            extension_yang_library,
            schema_id_cache,
            cache_req_tx,
            _phantom: std::marker::PhantomData,
        })
    }

    async fn register_yang_lib_ref(
        sr_client: &SchemaRegistryClient,
        yang_lib_ref: &YangLibraryReference,
        root_schema_name: &str,
        subject_prefix: Option<&str>,
    ) -> Result<i32, KafkaYangPublisherActorError<E>> {
        let yang_lib = yang_lib_ref.yang_library()?;
        let schemas =
            yang_lib.load_schemas_from_search_path(yang_lib_ref.search_dir().as_path())?;
        let content_id = yang_lib_ref.content_id();
        let registered_schema = yang_lib
            .register_schema(root_schema_name, subject_prefix, &schemas, sr_client)
            .await?;

        let schema_id = registered_schema.id.ok_or_else(|| {
            KafkaYangPublisherActorError::SchemaRegistrationError(format!(
                "Schema ID not found in registered schema response for content_id: {content_id}"
            ))
        })?;
        Ok(schema_id)
    }

    /// Get schema ID from cache or by registering the schema to the schema
    /// registry
    async fn register_schema(
        &mut self,
        content_id: Option<&str>,
    ) -> Result<Option<i32>, KafkaYangPublisherActorError<E>> {
        let id = if let Some(id) = content_id {
            id
        } else {
            return if let Some(default_schema_id) = self.default_schema_id {
                warn!(
                    "No content ID provided, using default schema ID: {}",
                    default_schema_id
                );
                Ok(Some(default_schema_id))
            } else {
                warn!(
                    "No content ID provided, and no default schema ID configured!, falling back to not using any schema"
                );
                Ok(None)
            };
        };

        // Check if we already have this schema registered
        if let Some(&schema_id) = self.schema_id_cache.get(id) {
            trace!("Found schemaID {schema_id} for contentID {id}");
            return Ok(Some(schema_id));
        }

        // Request schema from SchemaCache Actor
        // (with timeout to prevent hanging)
        let (response_tx, response_rx) = oneshot::channel();

        if let Err(err) = self
            .cache_req_tx
            .send(CacheLookupCommand::LookupByContentIdOneShot(
                id.to_string(),
                response_tx,
            ))
            .await
        {
            warn!("Failed to request schema for content_id: {}", id);
            return Err(err.into());
        }

        // TODO: expose timeout to config
        let (content_id, yang_lib_ref) = match tokio::time::timeout(
            Duration::from_secs(5),
            response_rx,
        )
        .await
        {
            Ok(Ok((content_id, Some(yang_lib_ref)))) => (content_id, yang_lib_ref),
            Ok(Ok((content_id, None))) => {
                warn!(
                    "Schema not found for content ID '{:?}', fallback to using root schema (id={content_id})",
                    self.default_schema_id
                );
                return Ok(self.default_schema_id);
            }
            Ok(Err(_)) => {
                warn!(
                    "Schema request channel closed for content ID '{:?}', fallback to using root schema (id={:?})",
                    id, self.default_schema_id
                );
                return Ok(self.default_schema_id);
            }
            Err(_) => {
                warn!(
                    "Schema request timeout for content ID '{}', fallback to using root schema (id={:?})",
                    id, self.default_schema_id
                );
                return Ok(self.default_schema_id);
            }
        };

        // Handle schema_cache response, extend and register schema
        let mut schemas = yang_lib_ref.load_schemas()?;
        let mut yang_lib = yang_lib_ref.yang_library()?;

        if let Some((extension_yang_lib, extension_schemas)) = self.extension_yang_library.as_ref()
        {
            let mut builder = yang_lib.into_module_set_builder(
                &schemas,
                "ALL".into(),
                &PermissiveVersionChecker,
            )?;
            builder.extend_from_yang_lib(
                extension_yang_lib.clone(),
                extension_schemas,
                &PermissiveVersionChecker,
            )?;

            let (yang_lib_extended, schemas_extended) = builder.build_yang_lib();
            yang_lib = yang_lib_extended;
            schemas = schemas_extended;
        }

        let registered_schema = yang_lib
            .register_schema(
                self.config.yang_converter.root_schema_name(),
                self.config.yang_converter.subject_prefix(),
                &schemas,
                &self.sr_client,
            )
            .await?;

        let schema_id = registered_schema.id.ok_or_else(|| {
            KafkaYangPublisherActorError::SchemaRegistrationError(format!(
                "Schema ID not found in registered schema response for content_id: {id}"
            ))
        })?;
        self.schema_id_cache.insert(content_id, schema_id);
        Ok(Some(schema_id))
    }

    /// Send a single message to Kafka
    ///
    /// This method:
    /// - converts the input message using the YANG converter
    /// - encodes the result as JSON bytes
    /// - extracts the message key (if any)
    /// - sends to Kafka with schema ID in the kafka header
    /// - handles retries for queue full conditions
    ///
    /// If the Kafka queue is full, this method will retry with exponentially
    /// increasing delays up to [`MAX_POLLING_INTERVAL`]. If the maximum
    /// interval is exceeded, the message is dropped and an error is
    /// returned.
    async fn send(&mut self, input: T) -> Result<(), KafkaYangPublisherActorError<E>> {
        let content_id = self.config.yang_converter.content_id(&input);
        let key = self.config.yang_converter.get_key(&input);
        let value = match self.config.yang_converter.serialize_json(input) {
            Ok(json_value) => json_value,
            Err(err) => {
                error!("Error serializing message to JSON: {err}");
                self.stats.error_decode.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "netgauze.json.serialize.error.msg",
                        err.to_string(),
                    )],
                );
                return Err(KafkaYangPublisherActorError::YangConverterError(err));
            }
        };

        let encoded_value = match serde_json::to_vec(&value) {
            Ok(value) => value,
            Err(err) => {
                error!("Error encoding serde_json::value for payload into byte array: {err}");
                self.stats.error_decode.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "netgauze.json.encode.error.msg",
                        err.to_string(),
                    )],
                );
                return Err(KafkaYangPublisherActorError::JsonError(err));
            }
        };

        let encoded_key = match key {
            Some(key) => match serde_json::to_vec(&key) {
                Ok(value) => Some(value),
                Err(err) => {
                    error!("Error encoding serde_json::Value for key into byte array: {err}");
                    self.stats.error_decode.add(
                        1,
                        &[opentelemetry::KeyValue::new(
                            "netgauze.json.encode.error.msg",
                            err.to_string(),
                        )],
                    );
                    return Err(KafkaYangPublisherActorError::JsonError(err));
                }
            },
            None => None,
        };

        // Get schema ID
        let schema_id = self.register_schema(content_id.as_deref()).await?;

        let mut headers = OwnedHeaders::new();
        let schema_id_str = schema_id.map(|id| id.to_string());

        // Create headers with schema ID
        if schema_id_str.is_some() {
            headers = headers.insert(Header {
                key: "schema-id",
                value: schema_id_str.as_deref(),
            });
            headers = headers.insert(Header {
                key: "content-type",
                value: Some("application/yang.data+json"),
            })
        }

        let mut record: BaseRecord<'_, Vec<u8>, Vec<u8>> = match &encoded_key {
            Some(key) => BaseRecord::to(self.config.topic.as_str())
                .payload(&encoded_value)
                .key(key)
                .headers(headers),
            None => BaseRecord::to(self.config.topic.as_str())
                .payload(&encoded_value)
                .headers(headers),
        };

        let mut polling_interval = Duration::from_micros(10);
        loop {
            match self.producer.send(record) {
                Ok(_) => {
                    self.stats.sent.add(1, &[]);
                    return Ok(());
                }
                Err((err, rec)) => match err {
                    KafkaError::MessageProduction(RDKafkaErrorCode::QueueFull) => {
                        // Exponential backoff when the librdkafka is full
                        if polling_interval > MAX_POLLING_INTERVAL {
                            error!("Kafka polling interval exceeded, dropping record");
                            self.stats.error_send.add(
                                1,
                                &[opentelemetry::KeyValue::new(
                                    "netgauze.kafka.sent.error.msg",
                                    err.to_string(),
                                )],
                            );
                            return Err(KafkaYangPublisherActorError::KafkaError(err));
                        }
                        debug!("Kafka message queue is full, sleeping for {polling_interval:?}");
                        self.stats.send_retries.add(1, &[]);
                        tokio::time::sleep(polling_interval).await;
                        polling_interval *= 2;
                        record = rec;
                        continue;
                    }
                    err => {
                        error!("Error sending message: {err}");
                        self.stats.error_send.add(
                            1,
                            &[opentelemetry::KeyValue::new(
                                "netgauze.kafka.sent.error.msg",
                                err.to_string(),
                            )],
                        );
                        return Err(KafkaYangPublisherActorError::KafkaError(err));
                    }
                },
            }
        }
    }

    /// Main actor event loop
    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(KafkaYangPublisherActorCommand::Shutdown) => {
                            info!("Received shutdown signal");
                            if let Err(err) = self.producer.flush(Duration::from_millis(1000)) {
                                error!("Failed to flush messages before shutting down: {err}");
                            }
                            Ok("Shutting down".to_string())
                        }
                        None => {
                            warn!("KafkaYangPublisher terminated due to command channel closing");
                            Ok("KafkaYangPublisher shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.msg_recv.recv() => {
                    match msg {
                        Ok(msg) => {
                            self.stats.received.add(1, &[]);
                            if let Err(err) = self.send(msg).await {
                                error!("Error sending message to Kafka: {err}");
                            }
                        }
                        Err(_) => {
                            return Err(anyhow::anyhow!(KafkaYangPublisherActorError::<E>::ReceiveErr))
                        }
                    }
                }
            }
        }
    }
}

// --- actor handle ---

#[derive(Debug)]
pub enum KafkaYangPublisherActorHandleError {
    SendError,
}

/// Handle for controlling a Kafka YANG publisher actor
#[derive(Debug)]
pub struct KafkaYangPublisherActorHandle<T, E, C>
where
    E: std::error::Error,
    C: YangConverter<T, E>,
{
    cmd_tx: mpsc::Sender<KafkaYangPublisherActorCommand>,
    _phantom: std::marker::PhantomData<(T, E, C)>,
}

impl<T, E, C> KafkaYangPublisherActorHandle<T, E, C>
where
    T: Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
    C: YangConverter<T, E> + Send + Sync + Serialize + 'static,
{
    pub async fn from_config(
        config: KafkaConfig<C>,
        custom_schemas: HashMap<IpNet, YangLibraryReference>,
        msg_recv: async_channel::Receiver<T>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaYangPublisherStats>,
        cache_req_tx: async_channel::Sender<CacheLookupCommand>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaYangPublisherActorError<E>> {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let stats = match stats {
            either::Either::Left(meter) => KafkaYangPublisherStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = KafkaYangPublisherActor::from_config(
            cmd_rx,
            config,
            custom_schemas,
            msg_recv,
            stats,
            cache_req_tx,
        )
        .await?;
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_tx,
            _phantom: std::marker::PhantomData,
        };
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), KafkaYangPublisherActorHandleError> {
        self.cmd_tx
            .send(KafkaYangPublisherActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaYangPublisherActorHandleError::SendError)
    }
}
