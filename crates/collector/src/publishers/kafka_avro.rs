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

use rdkafka::{
    config::{ClientConfig, FromClientConfigAndContext},
    error::{KafkaError, RDKafkaErrorCode},
    message::DeliveryResult,
    producer::{BaseRecord, NoCustomPartitioner, Producer, ProducerContext, ThreadedProducer},
    ClientContext,
};
use schema_registry_converter::{
    async_impl::{avro::AvroEncoder, schema_registry::SrSettings},
    error::SRCError,
    schema_registry_common::{SchemaType, SubjectNameStrategy, SuppliedSchema},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(5);

pub trait AvroConverter<T, E: std::error::Error> {
    fn get_avro_schema(&self) -> String;
    fn get_avro_value(&self, input: T) -> Result<apache_avro::types::Value, E>;
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

#[derive(Debug)]
pub enum KafkaAvroPublisherActorError {
    KafkaError(KafkaError),
    AvroError(apache_avro::Error),
    SrcError(SRCError),
    TransformationError(String),
    ReceiveErr,
}

impl std::fmt::Display for KafkaAvroPublisherActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KafkaError(e) => write!(f, "Kafka error: {e}"),
            Self::AvroError(e) => write!(f, "Avro error: {e}"),
            Self::SrcError(e) => write!(f, "Source error: {e}"),
            Self::TransformationError(e) => write!(f, "Transformation error: {e}"),
            Self::ReceiveErr => write!(f, "Error receiving messages from upstream producer"),
        }
    }
}

impl std::error::Error for KafkaAvroPublisherActorError {}

impl From<KafkaError> for KafkaAvroPublisherActorError {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}

impl From<apache_avro::Error> for KafkaAvroPublisherActorError {
    fn from(e: apache_avro::Error) -> Self {
        Self::AvroError(e)
    }
}

impl From<SRCError> for KafkaAvroPublisherActorError {
    fn from(e: SRCError) -> Self {
        Self::SrcError(e)
    }
}

#[derive(Debug, Clone)]
pub struct KafkaAvroPublisherStats {
    received: opentelemetry::metrics::Counter<u64>,
    sent: opentelemetry::metrics::Counter<u64>,
    send_retries: opentelemetry::metrics::Counter<u64>,
    error_avro_convert: opentelemetry::metrics::Counter<u64>,
    error_avro_encode: opentelemetry::metrics::Counter<u64>,
    error_send: opentelemetry::metrics::Counter<u64>,
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
        let error_send = meter
            .u64_counter("netgauze.collector.kafka.avro.error_send")
            .with_description("Error sending message to Kafka")
            .build();

        Self {
            received,
            sent,
            send_retries,
            error_avro_convert,
            error_avro_encode,
            error_send,
        }
    }
}

/// Producer context with tracing logs enabled
#[derive(Clone)]
pub struct LoggingProducerContext;

impl ClientContext for LoggingProducerContext {}
impl ProducerContext<NoCustomPartitioner> for LoggingProducerContext {
    type DeliveryOpaque = ();

    fn delivery(&self, delivery_result: &DeliveryResult<'_>, _: Self::DeliveryOpaque) {
        match delivery_result {
            Ok(_) => {
                debug!("Message delivered successfully to kafka");
            }
            Err((err, _)) => {
                warn!("Failed to deliver message to kafka: {err}");
            }
        }
    }
}

pub struct KafkaAvroPublisherActor<'a, T, E: std::error::Error, C: AvroConverter<T, E>> {
    cmd_rx: mpsc::Receiver<KafkaAvroPublisherActorCommand>,

    /// Configured kafka options
    config: KafkaConfig<C>,

    /// Schema used for AVRO records by this producer
    supplied_schema: SuppliedSchema,

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
    pub fn from_config(
        cmd_rx: mpsc::Receiver<KafkaAvroPublisherActorCommand>,
        config: KafkaConfig<C>,
        msg_recv: async_channel::Receiver<T>,
        stats: KafkaAvroPublisherStats,
    ) -> Result<Self, KafkaAvroPublisherActorError> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        let producer: ThreadedProducer<LoggingProducerContext> =
            match ThreadedProducer::from_config_and_context(
                &producer_config,
                LoggingProducerContext,
            ) {
                Ok(p) => p,
                Err(err) => {
                    error!("Failed to create Kafka producer: {err}");
                    return Err(err)?;
                }
            };
        let sr_settings = SrSettings::new(config.schema_registry_url.clone());
        let avro_encoder = AvroEncoder::new(sr_settings.clone());
        let schema_str = config.avro_converter.get_avro_schema();
        let parse_schema = match apache_avro::schema::Schema::parse_str(&schema_str) {
            Ok(schema) => schema,
            Err(err) => {
                error!("Error parsing schema `{err}`, schema string is: `{schema_str}`");
                return Err(err)?;
            }
        };
        let supplied_schema = SuppliedSchema {
            name: parse_schema.name().map(|x| x.to_string()),
            schema_type: SchemaType::Avro,
            schema: schema_str,
            references: vec![],
        };

        info!(
            "Starting Kafka AVRO publisher to topic: `{}` with schema: `{}`",
            config.topic,
            parse_schema.canonical_form()
        );
        Ok(Self {
            cmd_rx,
            config,
            supplied_schema,
            producer,
            avro_encoder,
            msg_recv,
            stats,
            _phantom: PhantomData,
        })
    }

    pub async fn send(&mut self, input: T) -> Result<(), KafkaAvroPublisherActorError> {
        let avro_value = match self.config.avro_converter.get_avro_value(input) {
            Ok(avro_value) => avro_value,
            Err(err) => {
                error!("Error getting avro value: {err}");
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
        // TODO: make subject name strategy configurable
        let encoded = match self
            .avro_encoder
            .encode_value(
                avro_value,
                &SubjectNameStrategy::TopicRecordNameStrategyWithSchema(
                    self.config.topic.clone(),
                    self.supplied_schema.clone(),
                ),
            )
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
                return Err(err)?;
            }
        };

        let mut record: BaseRecord<'_, Vec<u8>, Vec<u8>> =
            BaseRecord::to(self.config.topic.as_str()).payload(&encoded);
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
                            return Err(KafkaAvroPublisherActorError::KafkaError(err));
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
                        return Err(KafkaAvroPublisherActorError::KafkaError(err));
                    }
                },
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
    KafkaAvroPublisherActorError: From<E>,
{
    pub fn from_config(
        config: KafkaConfig<C>,
        msg_recv: async_channel::Receiver<T>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaAvroPublisherStats>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaAvroPublisherActorError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let stats = match stats {
            either::Either::Left(meter) => KafkaAvroPublisherStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = KafkaAvroPublisherActor::from_config(cmd_rx, config, msg_recv, stats)?;
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_tx,
            _phantom: PhantomData,
        };
        Ok((join_handle, handle))
    }

    pub async fn shutdown(self) -> Result<(), KafkaAvroPublisherActorHandleError> {
        self.cmd_tx
            .send(KafkaAvroPublisherActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaAvroPublisherActorHandleError::SendError)
    }
}
