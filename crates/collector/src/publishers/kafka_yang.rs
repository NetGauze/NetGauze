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
use netgauze_yang_push::{ContentId, CustomSchema};
use rdkafka::{
    config::{ClientConfig, FromClientConfigAndContext},
    error::{KafkaError, RDKafkaErrorCode},
    message::{Header, OwnedHeaders},
    producer::{BaseRecord, Producer, ThreadedProducer},
};
use schema_registry_converter::{
    async_impl::schema_registry::{post_schema, SrSettings},
    error::SRCError,
    schema_registry_common::{SchemaType, SuppliedReference, SuppliedSchema},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, error, info, trace, warn};

/// Maximum polling interval when Kafka message queue is full
const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(5);

// --- config ---

/// Trait for converting input data to YANG-compliant JSON format
pub trait YangConverter<T, E: std::error::Error> {
    /// Returns the YANG schema definition for the telemetry message
    /// with references being (augmented)imports
    fn get_root_schema(&self) -> Result<SuppliedSchema, E>;

    // Get ContentId from input message
    fn get_content_id(&self, input: &T) -> Option<ContentId>;

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

    /// Error encoding [serde_json::Value] into `Vec<u8>` to send to kafka
    #[strum(to_string = "EncodingError: {0}")]
    EncodingError(serde_json::Error),

    /// Error receiving incoming messages from input async_channel
    #[strum(to_string = "Error receiving messages from upstream producer")]
    ReceiveErr,

    /// Schema registry error
    #[strum(to_string = "SchemaRegistryError: {0}")]
    SchemaRegistryError(SRCError),

    /// SuppliedSchema format error
    #[strum(to_string = "SuppliedSchemaError: {0}")]
    SuppliedSchemaError(String),

    /// YANG converter error
    #[strum(to_string = "YangConverterError: {0}")]
    YangConverterError(E),

    /// Error sending schema request
    #[strum(to_string = "SchemaRequestError: {0}")]
    SchemaRequestError(async_channel::SendError<(String, oneshot::Sender<SuppliedSchema>)>),

    // Error reading from file
    #[strum(to_string = "Failed to read from file: {0}")]
    IoError(std::io::Error),

    // Serde JSON Error
    #[strum(to_string = "JSON Error: {0}")]
    JsonError(serde_json::Error),
}

impl<E: std::error::Error> std::error::Error for KafkaYangPublisherActorError<E> {}

impl<E: std::error::Error> From<KafkaError> for KafkaYangPublisherActorError<E> {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}
impl<E: std::error::Error> From<SRCError> for KafkaYangPublisherActorError<E> {
    fn from(e: SRCError) -> Self {
        Self::SchemaRegistryError(e)
    }
}
impl<E: std::error::Error> From<async_channel::SendError<(String, oneshot::Sender<SuppliedSchema>)>>
    for KafkaYangPublisherActorError<E>
{
    fn from(e: async_channel::SendError<(String, oneshot::Sender<SuppliedSchema>)>) -> Self {
        Self::SchemaRequestError(e)
    }
}
impl<E: std::error::Error> From<std::io::Error> for KafkaYangPublisherActorError<E> {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}
impl<E: std::error::Error> From<serde_json::Error> for KafkaYangPublisherActorError<E> {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
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
    root_schema: SuppliedSchema, // telemetry message root schema
    root_schema_id: u32,         // schema-registry ID for root schema
    schema_id_cache: HashMap<ContentId, u32>, // content_id -> schema_id map
    schema_req_tx: async_channel::Sender<(ContentId, oneshot::Sender<SuppliedSchema>)>,
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

    /// Construct a subject name from schema name + optional a contentID
    fn get_subject_from_schema_name(
        schema: &SuppliedSchema,
        content_id: Option<&str>,
        root: bool,
    ) -> Result<String, KafkaYangPublisherActorError<E>> {
        // Ensure schema type is set to YANG
        if !matches!(schema.schema_type, SchemaType::Other(ref s) if s == "YANG") {
            return Err(KafkaYangPublisherActorError::SuppliedSchemaError(format!(
                "Schema type must be 'YANG', found: {:?}",
                schema.schema_type
            )));
        }

        // Extract schema name
        let schema_name = schema.name.as_ref().ok_or_else(|| {
            KafkaYangPublisherActorError::SuppliedSchemaError("Schema name is required".to_string())
        })?;

        // Create subject name based on schema name and content_id
        match (content_id, root) {
            (Some(content_id), true) => Ok(format!("{schema_name}-{content_id}-root")),
            (Some(content_id), false) => Ok(format!("{schema_name}-{content_id}")),
            (None, true) => Ok(format!("{schema_name}-root")),
            (None, false) => Ok(schema_name.to_string()),
        }
    }

    /// Register a YANG schema with the schema registry
    async fn register_schema_with_registry(
        schema_registry_url: String,
        schema: &SuppliedSchema,
        subject: String,
    ) -> Result<u32, KafkaYangPublisherActorError<E>> {
        let sr_settings = SrSettings::new(schema_registry_url);

        info!("Registering YANG schema with subject '{}'", subject);

        match post_schema(&sr_settings, subject.clone(), schema.clone()).await {
            Ok(schema_result) => {
                info!(
                    "Registered YANG schema with subject '{}' and id {}",
                    subject, schema_result.id
                );
                Ok(schema_result.id)
            }
            Err(err) => {
                error!(
                    "Failed to register YANG schema with subject '{}': {}",
                    subject, err
                );
                Err(KafkaYangPublisherActorError::SchemaRegistryError(err))
            }
        }
    }

    fn parse_custom_schemas(
        custom_schemas: &HashMap<IpNet, CustomSchema>,
    ) -> Result<Vec<(ContentId, SuppliedSchema)>, KafkaYangPublisherActorError<E>> {
        let mut schemas = Vec::new();

        for custom_schema in custom_schemas.values() {
            let schema_content = fs::read_to_string(&custom_schema.schema)?;
            let supplied_schema: SuppliedSchema = serde_json::from_str(&schema_content)?;
            schemas.push((custom_schema.content_id.clone(), supplied_schema));
        }

        Ok(schemas)
    }

    /// Create a new actor instance from configuration
    async fn from_config(
        cmd_rx: mpsc::Receiver<KafkaYangPublisherActorCommand>,
        config: KafkaConfig<C>,
        custom_schemas: HashMap<IpNet, CustomSchema>,
        msg_recv: async_channel::Receiver<T>,
        stats: KafkaYangPublisherStats,
        schema_req_tx: async_channel::Sender<(String, oneshot::Sender<SuppliedSchema>)>,
    ) -> Result<Self, KafkaYangPublisherActorError<E>> {
        let producer = Self::get_producer(&stats, &config)?;

        // Load and register root schema
        let root_schema = config
            .yang_converter
            .get_root_schema()
            .map_err(|err| KafkaYangPublisherActorError::YangConverterError(err))?;
        let root_schema_subject = Self::get_subject_from_schema_name(&root_schema, None, true)?;
        let root_schema_id = Self::register_schema_with_registry(
            config.schema_registry_url.clone(),
            &root_schema,
            root_schema_subject,
        )
        .await?;

        // Load and register provided custom schemas
        let mut schema_id_cache = HashMap::new();
        let custom_supplied_schemas = Self::parse_custom_schemas(&custom_schemas)?;

        for (content_id, schema) in custom_supplied_schemas {
            // Extend root schema by adding custom schema as reference
            let subject = Self::get_subject_from_schema_name(&schema, None, false)?;
            let mut extended_root_schema = root_schema.clone();
            extended_root_schema.references.push(SuppliedReference {
                name: subject.clone(),
                subject,
                schema: schema.schema.clone(),
                references: schema.references,
                properties: schema.properties,
                tags: schema.tags,
            });

            let extended_root_schema_subject =
                Self::get_subject_from_schema_name(&extended_root_schema, Some(&content_id), true)?;
            let schema_id = Self::register_schema_with_registry(
                config.schema_registry_url.clone(),
                &extended_root_schema,
                extended_root_schema_subject,
            )
            .await?;

            // Store schema registry ID in cache
            schema_id_cache.insert(content_id, schema_id);
        }

        info!("Root and custom schema loading and registering complete!");
        info!("Starting Kafka YANG publisher to topic: `{}`", config.topic);

        Ok(Self {
            cmd_rx,
            config,
            producer,
            msg_recv,
            stats,
            root_schema,
            root_schema_id,
            schema_id_cache,
            schema_req_tx,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Extend the telemetry message root schema by appending incoming
    /// message schema to its references
    async fn construct_and_register_schema(
        &self,
        content_id: &str,
        schema: SuppliedSchema,
    ) -> Result<u32, KafkaYangPublisherActorError<E>> {
        let subject = Self::get_subject_from_schema_name(&schema, None, false)?;
        let mut root_schema = self.root_schema.clone();
        root_schema.references.push(SuppliedReference {
            name: subject.clone(),
            subject,
            schema: schema.schema.clone(),
            references: schema.references,
            properties: schema.properties,
            tags: schema.tags,
        });

        let root_schema_subject =
            Self::get_subject_from_schema_name(&root_schema, Some(content_id), true)?;
        Self::register_schema_with_registry(
            self.config.schema_registry_url.clone(),
            &root_schema,
            root_schema_subject,
        )
        .await
    }

    /// Get schema ID from cache or by registering the schema to the schema
    /// registry
    async fn register_schema(
        &mut self,
        content_id: Option<&str>,
    ) -> Result<u32, KafkaYangPublisherActorError<E>> {
        match content_id {
            Some(id) => {
                // Check if we already have this schema registered
                if let Some(&schema_id) = self.schema_id_cache.get(id) {
                    trace!("Found schemaID {schema_id} for contentID {id}");
                    return Ok(schema_id);
                }

                // Request schema from SchemaCache Actor
                // (with timeout to prevent hanging)
                let (response_tx, response_rx) = oneshot::channel();
                if let Err(err) = self.schema_req_tx.send((id.to_string(), response_tx)).await {
                    warn!("Failed to request schema for content_id: {}", id);
                    return Err(err.into());
                }

                // TODO: expose timeout to config
                let schema = match tokio::time::timeout(Duration::from_secs(5), response_rx).await {
                    Ok(Ok(schema)) => schema,
                    Ok(Err(_)) => {
                        warn!("Schema request channel closed for content ID '{}', fallback to using root schema (id={})", id, self.root_schema_id);
                        return Ok(self.root_schema_id);
                    }
                    Err(_) => {
                        warn!("Schema request timeout for content ID '{}', fallback to using root schema (id={})", id, self.root_schema_id);
                        return Ok(self.root_schema_id);
                    }
                };

                // Handle schema_cache response and register schema
                match self.construct_and_register_schema(id, schema).await {
                    Ok(schema_id) => {
                        trace!(
                            "Registered new schema ID {} for content ID '{}'",
                            schema_id,
                            id
                        );
                        self.schema_id_cache.insert(id.to_string(), schema_id);
                        Ok(schema_id)
                    }
                    Err(err) => {
                        error!("Failed to register schema for content ID '{}': {}", id, err);
                        Err(err)
                    }
                }
            }
            None => {
                warn!(
                    "Missing content ID from message: fallback to using root schema (id={})",
                    self.root_schema_id
                );
                Ok(self.root_schema_id)
            }
        }
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
        let content_id = self.config.yang_converter.get_content_id(&input);

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
                return Err(KafkaYangPublisherActorError::EncodingError(err));
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
                    return Err(KafkaYangPublisherActorError::EncodingError(err));
                }
            },
            None => None,
        };

        // Get schema ID
        let schema_id = self.register_schema(content_id.as_deref()).await?;

        // Create headers with schema ID
        let headers = OwnedHeaders::new().insert(Header {
            key: "schema-id",
            value: Some(schema_id.to_string().as_str()),
        });

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
                            Err(KafkaYangPublisherActorError::<E>::ReceiveErr)?
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
        custom_schemas: HashMap<IpNet, CustomSchema>,
        msg_recv: async_channel::Receiver<T>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaYangPublisherStats>,
        schema_req_tx: async_channel::Sender<(ContentId, oneshot::Sender<SuppliedSchema>)>,
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
            schema_req_tx,
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
