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

use netgauze_udp_notif_pkt::{MediaType, UdpNotifPacket};
use rdkafka::{
    config::{ClientConfig, FromClientConfigAndContext},
    error::{KafkaError, RDKafkaErrorCode},
    message::DeliveryResult,
    producer::{BaseRecord, NoCustomPartitioner, Producer, ProducerContext, ThreadedProducer},
    ClientContext,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(5);

// --- config ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Output topic
    topic: String,
    /// Key/Value producer configs are defined in librdkafka
    producer_config: HashMap<String, String>,
    writer_id: String,
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
        Self {
            received,
            sent,
            send_retries,
            error_decode,
            error_send,
        }
    }
}

// --- producer ---

/// Producer context with tracing logs enabled
#[derive(Clone)]
struct LoggingProducerContext;

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

// --- actor ---

#[derive(Debug)]
pub enum KafkaJsonPublisherActorError {
    KafkaError(KafkaError),
    SerializationError(String),
    ReceiveErr,
}

impl std::fmt::Display for KafkaJsonPublisherActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KafkaError(e) => write!(f, "Kafka error: {e}"),
            Self::SerializationError(e) => write!(f, "Serialization error: {e}"),
            Self::ReceiveErr => write!(f, "Error receiving messages from upstream producer"),
        }
    }
}

impl std::error::Error for KafkaJsonPublisherActorError {}

impl From<KafkaError> for KafkaJsonPublisherActorError {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}

impl From<serde_json::Error> for KafkaJsonPublisherActorError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
enum KafkaJsonPublisherActorCommand {
    Shutdown,
}

struct KafkaJsonPublisherActor {
    cmd_rx: mpsc::Receiver<KafkaJsonPublisherActorCommand>,

    /// Configured kafka options
    config: KafkaConfig,

    //// librdkafka producer
    producer: ThreadedProducer<LoggingProducerContext>,

    msg_recv: async_channel::Receiver<std::sync::Arc<(SocketAddr, UdpNotifPacket)>>,

    stats: KafkaJsonPublisherStats,
}

impl KafkaJsonPublisherActor {
    fn get_producer(
        config: &KafkaConfig,
    ) -> Result<ThreadedProducer<LoggingProducerContext>, KafkaJsonPublisherActorError> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        match ThreadedProducer::from_config_and_context(&producer_config, LoggingProducerContext) {
            Ok(p) => Ok(p),
            Err(err) => {
                error!("Failed to create Kafka producer: {err}");
                Err(err)?
            }
        }
    }

    fn from_config(
        cmd_rx: mpsc::Receiver<KafkaJsonPublisherActorCommand>,
        config: KafkaConfig,
        msg_recv: async_channel::Receiver<std::sync::Arc<(SocketAddr, UdpNotifPacket)>>,
        stats: KafkaJsonPublisherStats,
    ) -> Result<Self, KafkaJsonPublisherActorError> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        let producer = Self::get_producer(&config)?;
        info!("Starting Kafka JSON publisher to topic: `{}`", config.topic);
        Ok(Self {
            cmd_rx,
            config,
            producer,
            msg_recv,
            stats,
        })
    }

    fn decode_msg(&self, msg: &UdpNotifPacket) -> Result<Vec<u8>, KafkaJsonPublisherActorError> {
        let mut value = match serde_json::to_value(msg) {
            Ok(value) => value,
            Err(err) => {
                error!("Error decoding message to JSON: {err}");
                self.stats.error_decode.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "netgauze.json.decode.error.msg",
                        err.to_string(),
                    )],
                );
                return Err(KafkaJsonPublisherActorError::SerializationError(
                    err.to_string(),
                ));
            }
        };
        if let serde_json::Value::Object(ref mut val) = &mut value {
            // Add the writer ID to the message
            val.insert(
                "writer_id".to_string(),
                serde_json::Value::String(self.config.writer_id.to_string()),
            );
            // Convert inner payload into human-readable format when possible
            match msg.media_type() {
                MediaType::YangDataJson => {
                    // Deserialize the payload into a JSON object
                    match serde_json::from_slice(msg.payload()) {
                        Ok(payload) => {
                            val.insert("payload".to_string(), payload);
                        }
                        Err(err) => {
                            error!("Error deserializing JSON payload: {err}");
                            self.stats.error_decode.add(
                                1,
                                &[opentelemetry::KeyValue::new(
                                    "netgauze.json.decode.error.msg",
                                    err.to_string(),
                                )],
                            );
                            return Err(KafkaJsonPublisherActorError::SerializationError(
                                err.to_string(),
                            ));
                        }
                    }
                }
                MediaType::YangDataXml => {
                    let payload = std::str::from_utf8(msg.payload())
                        .expect("Couldn't deserialize XML payload");
                    val.insert(
                        "payload".to_string(),
                        serde_json::Value::String(payload.to_string()),
                    );
                }
                MediaType::YangDataCbor => {
                    let payload = std::str::from_utf8(msg.payload())
                        .expect("Couldn't deserialize CBOR payload");
                    val.insert(
                        "payload".to_string(),
                        serde_json::Value::String(payload.to_string()),
                    );
                }
                _ => {
                    let err_msg = format!("Unsupported media type: {:?}", msg.media_type());
                    error!("{err_msg}");
                    self.stats.error_decode.add(
                        1,
                        &[opentelemetry::KeyValue::new(
                            "netgauze.json.decode.error.msg",
                            err_msg.to_string(),
                        )],
                    );
                    return Err(KafkaJsonPublisherActorError::SerializationError(err_msg));
                }
            }
        }
        Ok(serde_json::to_vec(&value)?)
    }

    async fn send(&mut self, input: UdpNotifPacket) -> Result<(), KafkaJsonPublisherActorError> {
        let encoded = self.decode_msg(&input)?;
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
                            let (_addr, msg) = &*msg;
                            if let Err(err) = self.send(msg.clone()).await {
                                error!("Error sending message to Kafka: {err}");
                            }
                        }
                        Err(_) => {
                            Err(KafkaJsonPublisherActorError::ReceiveErr)?
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
    pub fn from_config(
        config: KafkaConfig,
        msg_recv: async_channel::Receiver<std::sync::Arc<(SocketAddr, UdpNotifPacket)>>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaJsonPublisherStats>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaJsonPublisherActorError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let stats = match stats {
            either::Either::Left(meter) => KafkaJsonPublisherStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor: KafkaJsonPublisherActor =
            KafkaJsonPublisherActor::from_config(cmd_rx, config, msg_recv, stats)?;
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_tx };
        Ok((join_handle, handle))
    }

    pub async fn shutdown(self) -> Result<(), KafkaJsonPublisherActorHandleError> {
        self.cmd_tx
            .send(KafkaJsonPublisherActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaJsonPublisherActorHandleError::SendError)
    }
}
