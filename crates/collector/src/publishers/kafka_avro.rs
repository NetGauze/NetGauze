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

use crate::publishers::LoggingProducerContext;
use apache_avro::types::Value as AvroValue;
use rdkafka::{
    config::{ClientConfig, FromClientConfigAndContext},
    error::{KafkaError, RDKafkaErrorCode},
    producer::{BaseRecord, Producer, ThreadedProducer},
};
use schema_registry_converter::{
    async_impl::{
        avro::AvroEncoder,
        schema_registry::{post_schema, SrSettings},
    },
    avro_common::get_supplied_schema,
    error::SRCError,
    schema_registry_common::{SubjectNameStrategy, SuppliedSchema},
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{collections::HashMap, marker::PhantomData, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(5);

pub trait AvroConverter<T, E: std::error::Error> {
    fn get_avro_schema(&self) -> String;

    fn get_key(&self, input: &T) -> Option<JsonValue>;

    type AvroValues: IntoIterator<Item = AvroValue> + Send;
    fn get_avro_values(&self, input: T) -> Result<Self::AvroValues, E>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig<C> {
    /// Output topic
    pub topic: String,
    /// Key/Value producer configs a defined in librdkafka
    pub producer_config: HashMap<String, String>,
    pub schema_registry_url: String,
    pub writer_id: String,
    pub avro_converter: C,
}

#[derive(Debug, strum_macros::Display)]
pub enum KafkaAvroPublisherActorError {
    #[strum(to_string = "Kafka error: {0}")]
    KafkaError(KafkaError),
    #[strum(to_string = "Avro error: {0}")]
    AvroError(Box<apache_avro::Error>),
    #[strum(to_string = "Source error: {0}")]
    SrcError(SRCError),
    #[strum(to_string = "Transformation error: {0}")]
    TransformationError(String),
    #[strum(to_string = "Error receiving messages from upstream producer")]
    ReceiveErr,
    #[strum(to_string = "Json error: {0}")]
    JsonError(serde_json::Error),
    #[strum(to_string = "Unexpected state: {0}")]
    UnexpectedState(String),
}

impl std::error::Error for KafkaAvroPublisherActorError {}

impl From<KafkaError> for KafkaAvroPublisherActorError {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}

impl From<apache_avro::Error> for KafkaAvroPublisherActorError {
    fn from(e: apache_avro::Error) -> Self {
        Self::AvroError(Box::new(e))
    }
}

impl From<SRCError> for KafkaAvroPublisherActorError {
    fn from(e: SRCError) -> Self {
        Self::SrcError(e)
    }
}

impl From<serde_json::Error> for KafkaAvroPublisherActorError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

#[derive(Debug, Clone)]
pub struct KafkaAvroPublisherStats {
    received: opentelemetry::metrics::Counter<u64>,
    sent: opentelemetry::metrics::Counter<u64>,
    send_retries: opentelemetry::metrics::Counter<u64>,
    error_avro_convert: opentelemetry::metrics::Counter<u64>,
    error_avro_encode: opentelemetry::metrics::Counter<u64>,
    error_key_encode: opentelemetry::metrics::Counter<u64>,
    error_send: opentelemetry::metrics::Counter<u64>,
    delivered_messages: opentelemetry::metrics::Counter<u64>,
    failed_delivery_messages: opentelemetry::metrics::Counter<u64>,
}

impl KafkaAvroPublisherStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netgauze.collector.kafka.avro.received")
            .with_description("Received messages from upstream producer")
            .build();
        let sent = meter
            .u64_counter("netgauze.collector.kafka.avro.sent")
            .with_description("Number of messages successfully sent to Kafka")
            .build();
        let send_retries = meter
            .u64_counter("netgauze.collector.kafka.avro.send.retries")
            .with_description("Number of send retries to Kafka due to full queue in librdkafka")
            .build();
        let error_avro_convert = meter
            .u64_counter("netgauze.collector.kafka.avro.error_avro_convert")
            .with_description("Error converting message into a AVRO value")
            .build();
        let error_avro_encode = meter
            .u64_counter("netgauze.collector.kafka.avro.error_avro_encode")
            .with_description("Error encoding message into AVRO binary array")
            .build();
        let error_key_encode = meter
            .u64_counter("netgauze.collector.kafka.avro.error_key_encode")
            .with_description("Error encoding message into AVRO binary array")
            .build();
        let error_send = meter
            .u64_counter("netgauze.collector.kafka.avro.error_send")
            .with_description("Error sending message to Kafka")
            .build();
        let delivered_messages = meter
            .u64_counter("netgauze.collector.kafka.avro.delivered_messages")
            .with_description("Messages confirmed to be delivered to Kafka")
            .build();
        let failed_delivery_messages = meter
            .u64_counter("netgauze.collector.kafka.avro.failed_delivery_messages")
            .with_description("Messages failed delivery to Kafka")
            .build();

        Self {
            received,
            sent,
            send_retries,
            error_avro_convert,
            error_avro_encode,
            error_key_encode,
            error_send,
            delivered_messages,
            failed_delivery_messages,
        }
    }
}

pub struct KafkaAvroPublisherActor<'a, T, E: std::error::Error, C: AvroConverter<T, E>> {
    cmd_rx: mpsc::Receiver<KafkaAvroPublisherActorCommand>,

    /// Configured kafka options
    config: KafkaConfig<C>,

    /// Subject Name Strategy
    subject_name_strategy: SubjectNameStrategy,

    //// librdkafka producer
    producer: ThreadedProducer<LoggingProducerContext>,

    /// Encoding to avro
    avro_encoder: AvroEncoder<'a>,

    msg_recv: async_channel::Receiver<T>,

    stats: KafkaAvroPublisherStats,

    /// Rust magic for holding types and T, E
    pub _phantom: PhantomData<(T, E)>,
}

impl<T, E, C> KafkaAvroPublisherActor<'_, T, E, C>
where
    E: std::error::Error,
    C: AvroConverter<T, E>,
    KafkaAvroPublisherActorError: From<E>,
{
    pub async fn from_config(
        cmd_rx: mpsc::Receiver<KafkaAvroPublisherActorCommand>,
        config: KafkaConfig<C>,
        msg_recv: async_channel::Receiver<T>,
        stats: KafkaAvroPublisherStats,
    ) -> Result<Self, KafkaAvroPublisherActorError> {
        let sr_settings = SrSettings::new(config.schema_registry_url.clone());
        let avro_encoder = AvroEncoder::new(sr_settings.clone());
        let schema_str = config.avro_converter.get_avro_schema();
        let supplied_schema =
            Self::get_schema(config.topic.clone(), schema_str, sr_settings).await?;
        let subject_name_strategy = SubjectNameStrategy::TopicRecordNameStrategyWithSchema(
            config.topic.clone(),
            supplied_schema.clone(),
        );
        let producer = Self::get_producer(&stats, &config)?;

        Ok(Self {
            cmd_rx,
            config,
            subject_name_strategy,
            producer,
            avro_encoder,
            msg_recv,
            stats,
            _phantom: PhantomData,
        })
    }

    async fn get_schema(
        topic: String,
        schema_str: String,
        sr_settings: SrSettings,
    ) -> Result<SuppliedSchema, KafkaAvroPublisherActorError> {
        let parse_schema = match apache_avro::schema::Schema::parse_str(&schema_str) {
            Ok(schema) => schema,
            Err(err) => {
                error!("Error parsing schema `{err}`, schema string is: `{schema_str}`");
                return Err(err)?;
            }
        };
        let supplied_schema = get_supplied_schema(&parse_schema);
        info!(
            "Starting Kafka AVRO publisher to topic: `{topic}` with schema: `{}`",
            parse_schema.canonical_form()
        );

        let subject_strategy =
            SubjectNameStrategy::TopicRecordNameStrategyWithSchema(topic, supplied_schema.clone());
        let subject = match subject_strategy.get_subject() {
            Ok(subject) => subject,
            Err(err) => {
                error!("Error getting a subject {err}");
                return Err(err)?;
            }
        };
        info!("Registering schema with schema registry");
        match post_schema(&sr_settings, subject.clone(), supplied_schema.clone()).await {
            Ok(schema) => {
                info!(
                    "Registered schema with subject {subject} and id {}",
                    schema.id
                );
            }
            Err(err) => {
                error!("Registering schema in schema registry {err}");
                return Err(err)?;
            }
        }
        Ok(supplied_schema)
    }

    pub fn get_producer(
        stats: &KafkaAvroPublisherStats,
        config: &KafkaConfig<C>,
    ) -> Result<ThreadedProducer<LoggingProducerContext>, KafkaAvroPublisherActorError> {
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

    pub async fn send(&mut self, input: T) -> Result<(), KafkaAvroPublisherActorError> {
        let key = self.config.avro_converter.get_key(&input);
        let encoded_key = match key {
            Some(key) => match serde_json::to_vec(&key) {
                Ok(value) => Some(value),
                Err(err) => {
                    error!("Error encoding key value into byte array: {err}");
                    self.stats.error_key_encode.add(
                        1,
                        &[opentelemetry::KeyValue::new(
                            "netgauze.kafka.key.encode.error.msg",
                            err.to_string(),
                        )],
                    );
                    return Err(err)?;
                }
            },
            None => None,
        };

        let avro_values = match self.config.avro_converter.get_avro_values(input) {
            Ok(avro_values) => avro_values,
            Err(err) => {
                error!("Error getting avro values: {err}");
                self.stats.error_avro_convert.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "netgauze.kafka.avro.convert.error.msg",
                        err.to_string(),
                    )],
                );
                return Err(err)?;
            }
        };

        let mut errors = Vec::new();
        let mut successful_sends = 0;

        for avro_value in avro_values {
            let encoded_avro_value = match self
                .avro_encoder
                .encode_value(avro_value, &self.subject_name_strategy)
                .await
            {
                Ok(result) => result,
                Err(err) => {
                    error!("Error encoding avro value: {err}");
                    self.stats.error_avro_encode.add(
                        1,
                        &[opentelemetry::KeyValue::new(
                            "netgauze.kafka.avro.encode.error.msg",
                            err.to_string(),
                        )],
                    );
                    errors.push(KafkaAvroPublisherActorError::SrcError(err));
                    continue; // skip this and try next avro_value
                }
            };

            // Create record (key, avro_value) to be sent
            let mut record: BaseRecord<'_, Vec<u8>, Vec<u8>> = match &encoded_key {
                Some(key) => BaseRecord::to(self.config.topic.as_str())
                    .payload(&encoded_avro_value)
                    .key(key),
                None => BaseRecord::to(self.config.topic.as_str()).payload(&encoded_avro_value),
            };
            let mut polling_interval = Duration::from_micros(10);

            // Try to send record with retries
            loop {
                match self.producer.send(record) {
                    Ok(_) => {
                        self.stats.sent.add(1, &[]);
                        successful_sends += 1;
                        break; // exit retry loop and move to next avro_value
                    }
                    Err((err, rec)) => {
                        match err {
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
                                    errors.push(KafkaAvroPublisherActorError::KafkaError(err));
                                    break; // exit retry loop and move to next
                                           // avro_value
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
                                errors.push(KafkaAvroPublisherActorError::KafkaError(err));
                                break; // exit retry loop and move to next
                                       // avro_value
                            }
                        }
                    }
                }
            }
        }

        match (successful_sends, errors.len(), errors.into_iter().next()) {
            (0, _, Some(error)) => {
                // All records in the batch failed, return first error
                Err(error)
            }
            (0, _, None) => {
                // This should never happen, but handle gracefully
                error!("Unexpected state: no successful sends in the batch but also no errors recorded");
                Err(KafkaAvroPublisherActorError::UnexpectedState(
                    "no successful sends in the batch but also no errors recorded".to_string(),
                ))
            }
            (_, _, None) => {
                // Batch successfully sent
                Ok(())
            }
            (successful_sends, errors_len, Some(_)) => {
                // Partial success
                warn!(
                    "Partial success: {successful_sends} messages sent, {errors_len} errors occurred",
                );
                Ok(()) // Or Err?
            }
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(KafkaAvroPublisherActorCommand::Shutdown) => {
                            info!("Received shutdown signal");
                            if let Err(err) = self.producer.flush(Duration::from_millis(1000)) {
                                error!("Failed flush messages before shutting down: {err}");
                            }
                            Ok("Shutting down".to_string())
                        }
                        None => {
                            warn!("KafkaAvroPublisher terminated due to command channel closing");
                            Ok("KafkaAvroPublisher shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.msg_recv.recv() =>{
                    match msg{
                        Ok(msg) => {
                            self.stats.received.add(1, &[]);
                            if let Err(err) = self.send(msg).await {
                                error!("Error sending message to Kafka: {err}");
                            }
                        }
                        Err(_) => {
                            Err(KafkaAvroPublisherActorError::ReceiveErr)?
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum KafkaAvroPublisherActorHandleError {
    SendError,
}

#[derive(Debug, Clone, Copy)]
pub enum KafkaAvroPublisherActorCommand {
    Shutdown,
}

#[derive(Debug)]
pub struct KafkaAvroPublisherActorHandle<T, E, C>
where
    E: std::error::Error,
    C: AvroConverter<T, E>,
{
    cmd_tx: mpsc::Sender<KafkaAvroPublisherActorCommand>,
    _phantom: PhantomData<(T, E, C)>,
}

impl<T, E, C> KafkaAvroPublisherActorHandle<T, E, C>
where
    T: Send + 'static,
    E: std::error::Error + Send + 'static,
    C: AvroConverter<T, E> + Send + 'static,
    C::AvroValues: Send,
    <C::AvroValues as IntoIterator>::IntoIter: Send,
    KafkaAvroPublisherActorError: From<E>,
{
    pub async fn from_config(
        config: KafkaConfig<C>,
        msg_recv: async_channel::Receiver<T>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaAvroPublisherStats>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaAvroPublisherActorError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let stats = match stats {
            either::Either::Left(meter) => KafkaAvroPublisherStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = KafkaAvroPublisherActor::from_config(cmd_rx, config, msg_recv, stats).await?;
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_tx,
            _phantom: PhantomData,
        };
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), KafkaAvroPublisherActorHandleError> {
        self.cmd_tx
            .send(KafkaAvroPublisherActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaAvroPublisherActorHandleError::SendError)
    }
}
