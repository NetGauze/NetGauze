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
use netgauze_netconf_proto::xml_utils::{ParsingError, XmlDeserialize, XmlParser};
use netgauze_netconf_proto::yanglib::{
    DependencyError, PermissiveVersionChecker, SchemaConstructionError, YangLibrary,
};
use netgauze_yang_push::schema_cache::{ContentId, SchemaInfo, SchemaInfoError};
use quick_xml::NsReader;
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
    /// Get root schema name (e.g. ietf-telemetry-message)
    fn get_root_schema_name(&self) -> &str;

    /// Get optional subject prefix for schema registry
    fn get_subject_prefix(&self) -> Option<&str>;

    // Get root telemetry-message schema
    fn get_root_schema(&self) -> SchemaInfo;

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

    /// Serde JSON Error
    #[strum(to_string = "JSON Error: {0}")]
    JsonError(serde_json::Error),

    /// Error receiving incoming messages from input async_channel
    #[strum(to_string = "Error receiving messages from upstream producer")]
    ReceiveErr,

    /// YANG converter error
    #[strum(to_string = "YangConverterError: {0}")]
    YangConverterError(E),

    /// Error sending schema request
    #[strum(to_string = "SchemaRequestError: {0}")]
    SchemaRequestError(async_channel::SendError<(String, oneshot::Sender<SchemaInfo>)>),

    /// Error reading from file
    #[strum(to_string = "Failed to read from file: {0}")]
    IoError(std::io::Error),

    /// XML parsing error
    #[strum(to_string = "XML Error: {0}")]
    XmlParsingError(quick_xml::Error),

    /// YANG library parsing error
    #[strum(to_string = "YANG Library Parsing Error: {0}")]
    YangLibParsingError(ParsingError),

    /// YANG Library schema construction error
    #[strum(to_string = "YANG Library Schema Construction Error: {0}")]
    YangLibSchemaError(SchemaConstructionError),

    /// Yang Library dependency error
    #[strum(to_string = "YANG Library Dependency Error: {0}")]
    YangLibDependencyError(DependencyError),

    /// Schema Reading Errors
    #[strum(to_string = "Schema Info Error: {0}")]
    SchemaInfoError(SchemaInfoError),

    /// Schema Registration Error
    #[strum(to_string = "Schema Registration Error: {0}")]
    SchemaRegistrationError(String),
}

impl<E: std::error::Error> std::error::Error for KafkaYangPublisherActorError<E> {}

impl<E: std::error::Error> From<KafkaError> for KafkaYangPublisherActorError<E> {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}
impl<E: std::error::Error> From<async_channel::SendError<(String, oneshot::Sender<SchemaInfo>)>>
    for KafkaYangPublisherActorError<E>
{
    fn from(e: async_channel::SendError<(String, oneshot::Sender<SchemaInfo>)>) -> Self {
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
impl<E: std::error::Error> From<quick_xml::Error> for KafkaYangPublisherActorError<E> {
    fn from(e: quick_xml::Error) -> Self {
        Self::XmlParsingError(e)
    }
}
impl<E: std::error::Error> From<ParsingError> for KafkaYangPublisherActorError<E> {
    fn from(e: ParsingError) -> Self {
        Self::YangLibParsingError(e)
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
impl<E: std::error::Error> From<SchemaInfoError> for KafkaYangPublisherActorError<E> {
    fn from(e: SchemaInfoError) -> Self {
        Self::SchemaInfoError(e)
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
    root_yanglib: YangLibrary,                 // root yang library
    root_schemas: HashMap<Box<str>, Box<str>>, // root schemas
    root_schema_id: i32,                       // schema-registry ID for root schema
    schema_id_cache: HashMap<ContentId, i32>,  // content_id -> schema_id map
    schema_req_tx: async_channel::Sender<(ContentId, oneshot::Sender<SchemaInfo>)>,
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
        custom_schemas: HashMap<IpNet, SchemaInfo>,
        msg_recv: async_channel::Receiver<T>,
        stats: KafkaYangPublisherStats,
        schema_req_tx: async_channel::Sender<(String, oneshot::Sender<SchemaInfo>)>,
    ) -> Result<Self, KafkaYangPublisherActorError<E>> {
        let producer = Self::get_producer(&stats, &config)?;

        // Create schema registry Client
        let client_conf = schema_registry_client::rest::client_config::ClientConfig::new(vec![
            config.schema_registry_url.clone(),
        ]);
        let sr_client = SchemaRegistryClient::new(client_conf);

        // Load and register provided root schema
        let root_schema_info = config.yang_converter.get_root_schema();
        let root_schemas = root_schema_info.read_modules_from_disk()?;

        let reader = NsReader::from_file(root_schema_info.yanglib_path())?;
        let mut xml_reader = XmlParser::new(reader)?;
        let root_yanglib: YangLibrary = YangLibrary::xml_deserialize(&mut xml_reader)?;

        let root_content_id = root_schema_info
            .content_id()
            .unwrap_or(root_yanglib.content_id());

        let registered_root_schema = root_yanglib
            .register_schema(
                config.yang_converter.get_root_schema_name(),
                config.yang_converter.get_subject_prefix(),
                &root_schemas,
                &sr_client,
            )
            .await?;

        let root_schema_id = registered_root_schema.id.ok_or_else(|| {
            KafkaYangPublisherActorError::SchemaRegistrationError(
                format!("Schema ID not found in registered schema response for content_id: {root_content_id}"),
            )
        })?;

        // Load and register provided custom schemas
        // (custom schema are already extended with telemetry-message)
        let mut schema_id_cache = HashMap::new();

        for schema_info in custom_schemas.values() {
            let schemas = schema_info.read_modules_from_disk()?;

            let reader = NsReader::from_file(schema_info.yanglib_path())?;
            let mut xml_reader = XmlParser::new(reader)?;
            let yanglib: YangLibrary = YangLibrary::xml_deserialize(&mut xml_reader)?;

            let content_id = schema_info.content_id().unwrap_or(yanglib.content_id());

            let registered_schema = yanglib
                .register_schema(
                    config.yang_converter.get_root_schema_name(),
                    config.yang_converter.get_subject_prefix(),
                    &schemas,
                    &sr_client,
                )
                .await?;

            let schema_id = registered_schema.id.ok_or_else(|| {
                KafkaYangPublisherActorError::SchemaRegistrationError(format!(
                    "Schema ID not found in registered schema response for content_id: {content_id}"
                ))
            })?;

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
            root_yanglib,
            root_schemas,
            root_schema_id,
            schema_id_cache,
            schema_req_tx,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Get schema ID from cache or by registering the schema to the schema
    /// registry
    async fn register_schema(
        &mut self,
        content_id: Option<&str>,
    ) -> Result<i32, KafkaYangPublisherActorError<E>> {
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
                let schema_info = match tokio::time::timeout(Duration::from_secs(5), response_rx)
                    .await
                {
                    Ok(Ok(schema_info)) => schema_info,
                    Ok(Err(_)) => {
                        warn!(
                            "Schema request channel closed for content ID '{}', fallback to using root schema (id={})",
                            id, self.root_schema_id
                        );
                        return Ok(self.root_schema_id);
                    }
                    Err(_) => {
                        warn!(
                            "Schema request timeout for content ID '{}', fallback to using root schema (id={})",
                            id, self.root_schema_id
                        );
                        return Ok(self.root_schema_id);
                    }
                };

                // Handle schema_cache response, extend and register schema
                let schemas = schema_info.read_modules_from_disk()?;

                let reader = NsReader::from_file(schema_info.yanglib_path())?;
                let mut xml_reader = XmlParser::new(reader)?;
                let yanglib: YangLibrary = YangLibrary::xml_deserialize(&mut xml_reader)?;

                let mut builder = yanglib.into_module_set_builder(
                    &schemas,
                    "ALL".into(),
                    &PermissiveVersionChecker,
                )?;
                builder.extend_from_yang_lib(
                    self.root_yanglib.clone(),
                    &self.root_schemas,
                    &PermissiveVersionChecker,
                )?;

                let (yanglib_extended, schemas_extended) = builder.build_yang_lib();

                let registered_schema = yanglib_extended
                    .register_schema(
                        self.config.yang_converter.get_root_schema_name(),
                        self.config.yang_converter.get_subject_prefix(),
                        &schemas_extended,
                        &self.sr_client,
                    )
                    .await?;

                let schema_id = registered_schema.id.ok_or_else(|| {
                    KafkaYangPublisherActorError::SchemaRegistrationError(format!(
                        "Schema ID not found in registered schema response for content_id: {id}"
                    ))
                })?;

                Ok(schema_id)
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
        custom_schemas: HashMap<IpNet, SchemaInfo>,
        msg_recv: async_channel::Receiver<T>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaYangPublisherStats>,
        schema_req_tx: async_channel::Sender<(ContentId, oneshot::Sender<SchemaInfo>)>,
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
