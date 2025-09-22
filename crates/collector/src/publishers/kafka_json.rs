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
use rdkafka::{
    config::{ClientConfig, FromClientConfigAndContext},
    error::{KafkaError, RDKafkaErrorCode},
    producer::{BaseRecord, Producer, ThreadedProducer},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(5);

// --- config ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Output topic
    pub topic: String,
    /// Key/Value producer configs are defined in librdkafka
    pub producer_config: HashMap<String, String>,
    pub writer_id: String,
}

// --- telemetry ---

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct KafkaJsonPublisherStats {
    received: opentelemetry::metrics::Counter<u64>,
    sent: opentelemetry::metrics::Counter<u64>,
    send_retries: opentelemetry::metrics::Counter<u64>,
    error_decode: opentelemetry::metrics::Counter<u64>,
    error_send: opentelemetry::metrics::Counter<u64>,
    delivered_messages: opentelemetry::metrics::Counter<u64>,
    failed_delivery_messages: opentelemetry::metrics::Counter<u64>,
}

impl KafkaJsonPublisherStats {
    fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netgauze.collector.kafka.json.received")
            .with_description("Received messages from upstream producer")
            .build();
        let sent = meter
            .u64_counter("netgauze.collector.kafka.json.sent")
            .with_description("Number of messages successfully sent to Kafka")
            .build();
        let send_retries = meter
            .u64_counter("netgauze.collector.kafka.json.send.retries")
            .with_description("Number of send retries to Kafka due to full queue in librdkafka")
            .build();
        let error_decode = meter
            .u64_counter("netgauze.collector.kafka.json.error_decode")
            .with_description("Error decoding message into JSON")
            .build();
        let error_send = meter
            .u64_counter("netgauze.collector.kafka.json.error_send")
            .with_description("Error sending message to Kafka")
            .build();
        let delivered_messages = meter
            .u64_counter("netgauze.collector.kafka.json.delivered_messages")
            .with_description("Messages confirmed to be delivered to Kafka")
            .build();
        let failed_delivery_messages = meter
            .u64_counter("netgauze.collector.kafka.json.failed_delivery_messages")
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
pub enum KafkaJsonPublisherActorError<E: std::error::Error> {
    /// Error communicating with the Kafka brokers
    #[strum(to_string = "Kafka error: {0}")]
    KafkaError(KafkaError),
    /// Error serializing incoming messages into [serde_json::Value]
    #[strum(to_string = "Serialization error: {0}")]
    SerializationError(E),
    /// Error encoding [serde_json::Value] into `Vec<u8>` to send to kafka
    #[strum(to_string = "Encoding error: {0}")]
    EncodingError(serde_json::Error),
    /// Error receiving incoming messages from input async_channel
    #[strum(to_string = "Error receiving messages from upstream producer")]
    ReceiveErr,
}

impl<E: std::error::Error> std::error::Error for KafkaJsonPublisherActorError<E> {}

impl<E: std::error::Error> From<KafkaError> for KafkaJsonPublisherActorError<E> {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}

impl<E: std::error::Error> From<serde_json::Error> for KafkaJsonPublisherActorError<E> {
    fn from(e: serde_json::Error) -> Self {
        Self::EncodingError(e)
    }
}

#[derive(Debug, Clone, Copy)]
enum KafkaJsonPublisherActorCommand {
    Shutdown,
}

struct KafkaJsonPublisherActor<T, F> {
    /// Serialize incoming messages into serde_json values
    serializer: F,

    cmd_rx: mpsc::Receiver<KafkaJsonPublisherActorCommand>,

    /// Configured kafka options
    config: KafkaConfig,

    //// librdkafka producer
    producer: ThreadedProducer<LoggingProducerContext>,

    msg_recv: async_channel::Receiver<T>,

    stats: KafkaJsonPublisherStats,
}

impl<
        T,
        E: std::error::Error + Send + Sync + 'static,
        F: Fn(T, String) -> Result<(Option<serde_json::Value>, serde_json::Value), E>,
    > KafkaJsonPublisherActor<T, F>
{
    fn get_producer(
        stats: &KafkaJsonPublisherStats,
        config: &KafkaConfig,
    ) -> Result<ThreadedProducer<LoggingProducerContext>, KafkaJsonPublisherActorError<E>> {
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

    fn from_config(
        serializer: F,
        cmd_rx: mpsc::Receiver<KafkaJsonPublisherActorCommand>,
        config: KafkaConfig,
        msg_recv: async_channel::Receiver<T>,
        stats: KafkaJsonPublisherStats,
    ) -> Result<Self, KafkaJsonPublisherActorError<E>> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        let producer = Self::get_producer(&stats, &config)?;
        info!("Starting Kafka JSON publisher to topic: `{}`", config.topic);
        Ok(Self {
            serializer,
            cmd_rx,
            config,
            producer,
            msg_recv,
            stats,
        })
    }

    async fn send(&mut self, input: T) -> Result<(), KafkaJsonPublisherActorError<E>> {
        let (key, value) = match (self.serializer)(input, self.config.writer_id.clone()) {
            Ok(result) => result,
            Err(err) => {
                error!("Error decoding message to JSON value: {err}");
                self.stats.error_decode.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "netgauze.json.decode.error.msg",
                        err.to_string(),
                    )],
                );
                return Err(KafkaJsonPublisherActorError::SerializationError(err));
            }
        };
        let encoded_value = match serde_json::to_vec(&value) {
            Ok(value) => value,
            Err(err) => {
                error!("Error encoding serde_json::value for payload into byte array: {err}");
                self.stats.error_decode.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "netgauze.json.decode.error.msg",
                        err.to_string(),
                    )],
                );
                return Err(KafkaJsonPublisherActorError::EncodingError(err));
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
                            "netgauze.json.decode.error.msg",
                            err.to_string(),
                        )],
                    );
                    return Err(KafkaJsonPublisherActorError::EncodingError(err));
                }
            },
            None => None,
        };

        let mut record: BaseRecord<'_, Vec<u8>, Vec<u8>> = match &encoded_key {
            Some(key) => BaseRecord::to(self.config.topic.as_str())
                .payload(&encoded_value)
                .key(key),
            None => BaseRecord::to(self.config.topic.as_str()).payload(&encoded_value),
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
                            return Err(KafkaJsonPublisherActorError::KafkaError(err));
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
                        return Err(KafkaJsonPublisherActorError::KafkaError(err));
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
                        Some(KafkaJsonPublisherActorCommand::Shutdown) => {
                            info!("Received shutdown signal");
                            if let Err(err) = self.producer.flush(Duration::from_millis(1000)) {
                                error!("Failed to flush messages before shutting down: {err}");
                            }
                            Ok("Shutting down".to_string())
                        }
                        None => {
                            warn!("KafkaJsonPublisher terminated due to command channel closing");
                            Ok("KafkaJsonPublisher shutdown successfully".to_string())
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
                            Err(KafkaJsonPublisherActorError::<E>::ReceiveErr)?
                        }
                    }
                }
            }
        }
    }
}

// --- actor handle ---

#[derive(Debug)]
pub enum KafkaJsonPublisherActorHandleError {
    SendError,
}

#[derive(Debug)]
pub struct KafkaJsonPublisherActorHandle {
    cmd_tx: mpsc::Sender<KafkaJsonPublisherActorCommand>,
}

impl KafkaJsonPublisherActorHandle {
    pub fn from_config<
        T: Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
        F: Fn(T, String) -> Result<(Option<serde_json::Value>, serde_json::Value), E> + Send + 'static,
    >(
        serializer: F,
        config: KafkaConfig,
        msg_recv: async_channel::Receiver<T>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaJsonPublisherStats>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaJsonPublisherActorError<E>> {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let stats = match stats {
            either::Either::Left(meter) => KafkaJsonPublisherStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor =
            KafkaJsonPublisherActor::from_config(serializer, cmd_rx, config, msg_recv, stats)?;
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_tx };
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), KafkaJsonPublisherActorHandleError> {
        self.cmd_tx
            .send(KafkaJsonPublisherActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaJsonPublisherActorHandleError::SendError)
    }
}
