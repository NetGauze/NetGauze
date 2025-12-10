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

//! Kafka enrichment input actor module for consuming external enrichment data.
//!
//! This module provides the core actor implementation for Kafka enrichment
//! input:
//! - `KafkaConsumerActor` - Main actor that consumes messages from Kafka topics
//! - `KafkaConsumerActorHandle` - Handle for controlling and communicating with
//!   the actor
//! - `KafkaConsumerStats` - Comprehensive metrics collection for Kafka
//!   operations
//!
//! The actor consumes messages from a Kafka topic and processes enrichment
//! data from various formats, converting them into enrichment operations that
//! are sent to enrichment actors for cache updates.
//!
//! ## Message Processing Flow
//!
//! For each Kafka message:
//! 1. Receive message from subscribed topic
//! 2. Parse message payload based on configured format (Sonata, JsonOps)
//! 3. Generate enrichment operations from parsed data
//! 4. Send operations to all registered enrichment actors
//! 5. Handle send errors with exponential backoff and retry logic
//!
//! ## Supported Message Formats
//!
//! - **JsonOps** - Direct JSON enrichment operations
//! - **Sonata** - Sonata flow enrichment format (custom Swisscom)
//!
//! Additional formats can be added via the `MessageFormat` enum and
//! corresponding message handlers implementing the `MessageHandler` trait.
use crate::inputs::{
    EnrichmentHandle,
    kafka::{
        KafkaConsumerConfig, KafkaMessageFormat,
        handlers::{
            FlowEnrichmentOperationHandler, KafkaMessageHandler, SonataHandler,
            YangPushEnrichmentOperationHandler,
        },
    },
};
use rdkafka::{
    ClientContext, Message, TopicPartitionList,
    config::ClientConfig,
    consumer::{
        BaseConsumer, Consumer, ConsumerContext, Rebalance, stream_consumer::StreamConsumer,
    },
    error::{KafkaError, KafkaResult, RDKafkaErrorCode},
};
use std::{str::Utf8Error, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, trace, warn};

const MAX_BACKOFF_TIME: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum KafkaConsumerActorError {
    Kafka(KafkaError),
    Utf8(Utf8Error),
    JsonSerde(serde_json::Error),
}

impl std::fmt::Display for KafkaConsumerActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kafka(err) => write!(f, "Kafka error: {err}"),
            Self::Utf8(err) => write!(f, "UTF8 error: {err}"),
            Self::JsonSerde(err) => write!(f, "JSON serde error: {err}"),
        }
    }
}

impl std::error::Error for KafkaConsumerActorError {}

impl From<Utf8Error> for KafkaConsumerActorError {
    fn from(err: Utf8Error) -> Self {
        KafkaConsumerActorError::Utf8(err)
    }
}

#[derive(Debug, Clone)]
pub struct KafkaConsumerStats {
    received: opentelemetry::metrics::Counter<u64>,
    empty_payload: opentelemetry::metrics::Counter<u64>,
    message_handling_error: opentelemetry::metrics::Counter<u64>,
    operations_generated: opentelemetry::metrics::Counter<u64>,
    send_error: opentelemetry::metrics::Counter<u64>,
    kafka_reconnect_attempts: opentelemetry::metrics::Counter<u64>,
}

impl KafkaConsumerStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.kafka.received")
            .with_description("Number of received messages from Kafka topic")
            .build();
        let empty_payload = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.kafka.empty_payload")
            .with_description("Number of messages received with empty payload")
            .build();
        let message_handling_error = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.kafka.message_handling_error")
            .with_description("Number of input messages handling error")
            .build();
        let operations_generated = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.kafka.operations_generated")
            .with_description("Number of enrichment operations generated from messages")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.kafka.send_error")
            .with_description("Error sending the EnrichmentOperation to the enrichment actor")
            .build();
        let kafka_reconnect_attempts = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.kafka.reconnect_attempts")
            .with_description("Number of attempts to reconnect to the Kafka brokers")
            .build();
        Self {
            received,
            empty_payload,
            message_handling_error,
            operations_generated,
            send_error,
            kafka_reconnect_attempts,
        }
    }
}

#[derive(Debug)]
enum KafkaConsumerActorCommand {
    Shutdown,
}

/// Configuration context for Kafka consumer operations.
///
/// Provides custom callbacks for librdkafka to handle rebalancing events
/// and commit operations. All callbacks log relevant information for
/// monitoring and debugging purposes.
struct KafkaContext;

impl ClientContext for KafkaContext {}

impl ConsumerContext for KafkaContext {
    fn pre_rebalance(&self, _: &BaseConsumer<Self>, rebalance: &Rebalance<'_>) {
        info!("Pre rebalance {:?}", rebalance);
    }

    fn post_rebalance(&self, _: &BaseConsumer<Self>, rebalance: &Rebalance<'_>) {
        info!("Post rebalance {:?}", rebalance);
    }

    fn commit_callback(&self, result: KafkaResult<()>, _offsets: &TopicPartitionList) {
        info!("Committing offsets: {:?}", result);
    }
}

/// Main Kafka consumer actor that processes enrichment messages.
struct KafkaConsumerActor<T, H, E>
where
    T: std::fmt::Display + Clone + Send + Sync + 'static,
    H: KafkaMessageHandler<T>,
    E: EnrichmentHandle<T>,
{
    cmd_rx: mpsc::Receiver<KafkaConsumerActorCommand>,
    config: KafkaConsumerConfig,
    enrichment_handles: Vec<E>,
    consumer: StreamConsumer<KafkaContext>,
    stats: KafkaConsumerStats,
    message_handler: H,
    otel_tags: Vec<opentelemetry::KeyValue>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, H, E> KafkaConsumerActor<T, H, E>
where
    T: std::fmt::Display + Clone + Send + Sync + 'static,
    H: KafkaMessageHandler<T>,
    E: EnrichmentHandle<T>,
{
    fn new(
        config: KafkaConsumerConfig,
        cmd_rx: mpsc::Receiver<KafkaConsumerActorCommand>,
        enrichment_handles: Vec<E>,
        stats: KafkaConsumerStats,
        message_handler: H,
    ) -> Result<Self, KafkaConsumerActorError> {
        let consumer = Self::init_consumer(&config)?;

        let otel_tags = vec![
            opentelemetry::KeyValue::new("topic", config.topic.clone()),
            opentelemetry::KeyValue::new("handler", config.message_format.to_string()),
        ];

        Ok(Self {
            cmd_rx,
            config,
            enrichment_handles,
            consumer,
            stats,
            message_handler,
            otel_tags,
            _phantom: std::marker::PhantomData,
        })
    }

    fn init_consumer(
        config: &KafkaConsumerConfig,
    ) -> Result<StreamConsumer<KafkaContext>, KafkaConsumerActorError> {
        let mut client_conf = ClientConfig::new();
        for (k, v) in &config.consumer_config {
            client_conf.set(k.clone(), v.clone());
        }
        let consumer: StreamConsumer<KafkaContext> =
            match client_conf.create_with_context(KafkaContext) {
                Ok(consumer) => consumer,
                Err(err) => {
                    error!("Failed to create consumer: {}", err);
                    return Err(KafkaConsumerActorError::Kafka(err));
                }
            };

        if let Err(err) = consumer.subscribe(&[config.topic.as_str()]) {
            error!("Failed to subscribe to topic `{}`: {}", config.topic, err);
            return Err(KafkaConsumerActorError::Kafka(err));
        }

        debug!("Testing broker connectivity for topic: {}", config.topic);
        match consumer.fetch_metadata(Some(&config.topic), std::time::Duration::from_secs(5)) {
            Ok(metadata) => {
                info!("Successfully connected to Kafka brokers");
                if let Some(topic_metadata) = metadata.topics().first() {
                    info!(
                        "Consumer metadata received: topic '{}' has {} partitions",
                        config.topic,
                        topic_metadata.partitions().len()
                    );
                }
            }
            Err(err) => {
                error!(
                    "Failed to connect to Kafka brokers or fetch topic metadata: {}",
                    err
                );
                return Err(KafkaConsumerActorError::Kafka(err));
            }
        }

        Ok(consumer)
    }

    async fn run(mut self) -> anyhow::Result<String> {
        info!(
            "Starting Kafka Consumer Actor for topic={} ({} handler)",
            self.config.topic, self.config.message_format
        );
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(KafkaConsumerActorCommand::Shutdown) => {
                            info!("Kafka consumer actor shutting down");
                            Ok("Kafka consumer actor terminated after a shutdown command".to_string())
                        }
                        None => {
                            info!("Kafka consumer actor terminated due to empty command channel");
                            Ok("Kafka consumer actor terminated due to empty command channel".to_string())
                        }
                    }
                }
                msg = self.consumer.recv() => {
                    self.stats.received.add(1, &self.otel_tags);
                    match msg {
                        Ok(msg) => {
                            let partition = msg.partition();
                            let offset = msg.offset();

                            let payload = match msg.payload() {
                                Some(p) => p,
                                None => {
                                    self.stats.empty_payload.add(1, &self.otel_tags);
                                    warn!("Empty payload at topic \"{}\" partition {partition} and offset {offset}", self.config.topic);
                                    continue;
                                }
                            };

                            let operations = match self
                                .message_handler
                                .handle_message(payload, partition, offset)
                            {
                                Ok(ops) => ops,
                                Err(err) => {
                                    self.stats.message_handling_error.add(1, &self.otel_tags);
                                    warn!(
                                        "Failed to handle message at topic \"{}\": {err}", self.config.topic
                                    );
                                    continue;
                                }
                            };

                            // Track operations generated
                            self.stats.operations_generated.add(operations.len() as u64, &self.otel_tags);
                            trace!("Generated {} operations from message at topic \"{}\" partition {partition} offset {offset}", operations.len(), self.config.topic);

                            // Send enrichment operations to all registered enrichment actors.
                            //
                            // Implements exponential backoff up to MAX_BACKOFF_TIME upon send failures
                            // to handle temporary congestion in enrichment actor channels. Each
                            // operation is sent to all enrichment handles with independent retry
                            // logic.
                            for operation in operations {
                                for handle in &self.enrichment_handles {
                                    let mut backoff_time = Duration::from_micros(10); // initial backoff time 10us

                                    loop {
                                        match handle.update_enrichment(operation.clone()).await {
                                            Ok(_) => break, // successfully sent, exit backoff loop
                                            Err(e) => {
                                                if backoff_time >= MAX_BACKOFF_TIME {
                                                    warn!(
                                                        "Failed to send enrichment operation after {:?}: {}",
                                                        MAX_BACKOFF_TIME, e
                                                    );
                                                    self.stats.send_error.add(1, &self.otel_tags);
                                                    break;
                                                }

                                                debug!(
                                                    "Failed to send enrichment operation, sleeping for {:?}: {}",
                                                    backoff_time, e
                                                );

                                                tokio::time::sleep(backoff_time).await;
                                                backoff_time *= 2;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            match err {
                                KafkaError::MessageConsumption(RDKafkaErrorCode::AllBrokersDown) => {
                                    error!("Kafka consumer has all brokers down, attempting to reconnect: {err}");
                                    loop {
                                        // Sleep to allow the Kafka broker to recover before retrying again.
                                        tokio::time::sleep(Duration::from_secs(60)).await;

                                        self.stats.kafka_reconnect_attempts.add(1, &self.otel_tags);
                                        match Self::init_consumer(&self.config) {
                                            Ok(consumer) => {
                                                self.consumer = consumer;
                                                break; // exit the reconnection loop
                                            },
                                            Err(err) => {
                                                error!("Failed to reconnect to Kafka broker, retrying: {err}");
                                                continue;
                                            }
                                        }
                                    }
                                }
                                KafkaError::MessageConsumption(RDKafkaErrorCode::UnknownTopicOrPartition) => {
                                    error!("Kafka topic doesn't exist, shutting down: {err}");
                                    return Err(anyhow::Error::from(err))
                                }
                                KafkaError::MessageConsumptionFatal(err) => {
                                    error!("Kafka consumer has received fatal consumption error, attempting to reconnect: {err}");
                                    loop {
                                        // Sleep to allow the Kafka broker to recover before retrying again.
                                        tokio::time::sleep(Duration::from_secs(30)).await;

                                        // Reconnection attempt
                                        self.stats.kafka_reconnect_attempts.add(1, &self.otel_tags);
                                        match Self::init_consumer(&self.config) {
                                            Ok(consumer) => {
                                                info!("Successfully reconnected to Kafka brokers");
                                                self.consumer = consumer;
                                                break; // exit the reconnection loop
                                            },
                                            Err(err) => {
                                                error!("Failed to reconnect to Kafka broker, retrying: {err}");
                                                continue;
                                            }
                                        }
                                    }
                                }
                                err => {
                                     warn!("Failed to receive Kafka message, ignoring error: {err}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum KafkaConsumerActorHandleError {
    SendError,
}

/// Handle for controlling and communicating with a Kafka consumer actor.
#[derive(Debug)]
pub struct KafkaConsumerActorHandle {
    cmd_send: mpsc::Sender<KafkaConsumerActorCommand>,
}

impl KafkaConsumerActorHandle {
    pub fn new<T>(
        consumer_config: KafkaConsumerConfig,
        enrichment_handles: Vec<impl EnrichmentHandle<T> + 'static>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaConsumerStats>,
        message_handler: impl KafkaMessageHandler<T> + 'static,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaConsumerActorError>
    where
        T: std::fmt::Display + Clone + Send + Sync + 'static,
    {
        let (cmd_send, cmd_rx) = mpsc::channel::<KafkaConsumerActorCommand>(1);
        let stats = match stats {
            either::Left(meter) => KafkaConsumerStats::new(meter),
            either::Right(stats) => stats,
        };
        let actor = KafkaConsumerActor::new(
            consumer_config,
            cmd_rx,
            enrichment_handles,
            stats,
            message_handler,
        )?;
        let join_handle = tokio::spawn(actor.run());
        Ok((join_handle, KafkaConsumerActorHandle { cmd_send }))
    }

    pub fn from_config<T>(
        consumer_config: &KafkaConsumerConfig,
        enrichment_handles: Vec<impl EnrichmentHandle<T> + 'static>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaConsumerStats>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaConsumerActorError>
    where
        T: std::fmt::Display + Clone + Send + Sync + 'static,
        FlowEnrichmentOperationHandler: KafkaMessageHandler<T>,
        YangPushEnrichmentOperationHandler: KafkaMessageHandler<T>,
        SonataHandler: KafkaMessageHandler<T>,
    {
        match &consumer_config.message_format {
            KafkaMessageFormat::FlowEnrichmentOps => Self::new(
                consumer_config.clone(),
                enrichment_handles,
                stats,
                FlowEnrichmentOperationHandler::new(),
            ),
            KafkaMessageFormat::YangPushEnrichmentOps => Self::new(
                consumer_config.clone(),
                enrichment_handles,
                stats,
                YangPushEnrichmentOperationHandler::new(),
            ),
            KafkaMessageFormat::Sonata(sonata_config) => Self::new(
                consumer_config.clone(),
                enrichment_handles,
                stats,
                SonataHandler::new(sonata_config.clone()),
            ),
        }
    }

    pub async fn shutdown(&self) -> Result<(), KafkaConsumerActorHandleError> {
        self.cmd_send
            .send(KafkaConsumerActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaConsumerActorHandleError::SendError)
    }
}
