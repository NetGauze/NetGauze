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

use netgauze_udp_notif_pkt::UdpNotifPacket;
use rdkafka::{
    config::ClientConfig,
    error::KafkaError,
    producer::{FutureProducer, FutureRecord, Producer},
    util::Timeout,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{error, info, warn};

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
    error_decode: opentelemetry::metrics::Counter<u64>,
    error_send: opentelemetry::metrics::Counter<u64>,
}

impl KafkaJsonPublisherStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netgauze.collector.kafka.json.received")
            .with_description("Received messages from upstream producer")
            .build();
        let sent = meter
            .u64_counter("netgauze.collector.kafka.json.sent")
            .with_description("Number of messages successfully sent to Kafka")
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
            error_decode,
            error_send,
        }
    }
}

// --- actor ---

#[derive(Debug)]
pub enum KafkaJsonPublisherActorError {
    KafkaError(KafkaError),
    TransformationError(String),
    ReceiveErr,
}

impl std::fmt::Display for KafkaJsonPublisherActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KafkaError(e) => write!(f, "Kafka error: {e}"),
            Self::TransformationError(e) => write!(f, "Transformation error: {e}"),
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

#[derive(Debug, Clone, Copy)]
pub enum KafkaJsonPublisherActorCommand {
    Shutdown,
}

pub struct KafkaJsonPublisherActor {
    cmd_rx: mpsc::Receiver<KafkaJsonPublisherActorCommand>,

    /// Configured kafka options
    config: KafkaConfig,

    //// librdkafka producer
    producer: FutureProducer,

    msg_recv: async_channel::Receiver<
        std::sync::Arc<(std::net::SocketAddr, netgauze_udp_notif_pkt::UdpNotifPacket)>,
    >,

    stats: KafkaJsonPublisherStats,
}

impl KafkaJsonPublisherActor {
    pub fn from_config(
        cmd_rx: mpsc::Receiver<KafkaJsonPublisherActorCommand>,
        config: KafkaConfig,
        msg_recv: async_channel::Receiver<
            std::sync::Arc<(std::net::SocketAddr, netgauze_udp_notif_pkt::UdpNotifPacket)>,
        >,
        stats: KafkaJsonPublisherStats,
    ) -> Result<Self, KafkaJsonPublisherActorError> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        let producer: FutureProducer = match producer_config.create() {
            Ok(p) => p,
            Err(err) => {
                error!("Failed to create Kafka producer: {err}");
                return Err(err)?;
            }
        };
        info!("Starting Kafka JSON publisher to topic: `{}`", config.topic);
        Ok(Self {
            cmd_rx,
            config,
            producer,
            msg_recv,
            stats,
        })
    }

    fn decode_msg(msg: &netgauze_udp_notif_pkt::UdpNotifPacket) -> String {
        use netgauze_udp_notif_pkt::MediaType;
        use serde_json::Value;
        let mut value = serde_json::to_value(msg).expect("Couldn't decode UDP-Notif message");
        // Convert when possible inner payload into human-readable format
        match msg.media_type() {
            MediaType::YangDataJson => {
                let payload = serde_json::from_slice(msg.payload())
                    .expect("Couldn't deserialize JSON payload");
                if let Value::Object(ref mut val) = &mut value {
                    val.insert("payload".to_string(), payload);
                }
            }
            MediaType::YangDataXml => {
                let payload =
                    std::str::from_utf8(msg.payload()).expect("Couldn't deserialize XML payload");
                if let Value::Object(ref mut val) = &mut value {
                    val.insert("payload".to_string(), Value::String(payload.to_string()));
                }
            }
            MediaType::YangDataCbor => {
                let payload =
                    std::str::from_utf8(msg.payload()).expect("Couldn't deserialize CBOR payload");
                if let Value::Object(ref mut val) = &mut value {
                    val.insert("payload".to_string(), Value::String(payload.to_string()));
                }
            }
            _ => {}
        }
        serde_json::to_string(&value).unwrap()
    }

    async fn send(&mut self, input: UdpNotifPacket) -> Result<(), KafkaJsonPublisherActorError> {
        let encoded = Self::decode_msg(&input).into_bytes();
        let fr: FutureRecord<'_, Vec<u8>, Vec<u8>> = FutureRecord {
            topic: self.config.topic.as_str(),
            partition: None,
            payload: Some(&encoded),
            key: None,
            timestamp: None,
            headers: None,
        };
        if let Err((err, _)) = self
            .producer
            .send(fr, Timeout::After(Duration::from_secs(1)))
            .await
        {
            error!("Error sending JSON value: {err}");
            self.stats.error_send.add(
                1,
                &[opentelemetry::KeyValue::new(
                    "netgauze.kafka.sent.error.msg",
                    err.to_string(),
                )],
            );
            return Err(KafkaJsonPublisherActorError::KafkaError(err));
        } else {
            self.stats.sent.add(1, &[]);
        };
        Ok(())
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
        msg_recv: async_channel::Receiver<
            std::sync::Arc<(std::net::SocketAddr, netgauze_udp_notif_pkt::UdpNotifPacket)>,
        >,
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
