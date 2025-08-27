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

use crate::flow::sonata_enrichment::{SonataEnrichmentActorHandle, SonataEnrichmentOperation};
use rdkafka::{
    config::ClientConfig,
    consumer::{
        stream_consumer::StreamConsumer, BaseConsumer, Consumer, ConsumerContext, Rebalance,
    },
    error::{KafkaError, KafkaResult, RDKafkaErrorCode},
    message::BorrowedMessage,
    ClientContext, Message, TopicPartitionList,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, str::Utf8Error, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, trace, warn};

// A context can be used to change the behavior of producers and consumers by
// adding callbacks that will be executed by librdkafka.
// This particular context sets up custom callbacks to log rebalancing events.
struct CosmoSonataContext;

impl ClientContext for CosmoSonataContext {}

impl ConsumerContext for CosmoSonataContext {
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SonataOperation {
    #[serde(rename = "insert")]
    Insert,

    #[serde(rename = "update")]
    Update,

    #[serde(rename = "delete")]
    Delete,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SonataData {
    pub operation: SonataOperation,
    pub id_node: u32,
    pub node: Option<SonataNode>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SonataNode {
    pub hostname: String,
    #[serde(rename = "loopbackAddress")]
    pub loopback_address: IpAddr,

    pub platform: SonataPlatform,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SonataPlatform {
    pub name: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KafkaConsumerConfig {
    /// Output topic
    pub topic: String,
    /// Key/Value producer configs a defined in librdkafka
    pub consumer_config: HashMap<String, String>,
}

#[derive(Debug)]
pub enum SonataActorError {
    KafkaError(KafkaError),
    Utf8Error(Utf8Error),
    JsonError(serde_json::Error),
}

impl std::fmt::Display for SonataActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KafkaError(e) => write!(f, "Kafka error: {e}"),
            SonataActorError::Utf8Error(err) => write!(f, "UTF8 Error: {err}"),
            SonataActorError::JsonError(err) => write!(f, "JSON serde Error: {err}"),
        }
    }
}

impl std::error::Error for SonataActorError {}

impl From<Utf8Error> for SonataActorError {
    fn from(err: Utf8Error) -> Self {
        SonataActorError::Utf8Error(err)
    }
}

#[derive(Debug, Clone)]
pub struct SonataStats {
    received: opentelemetry::metrics::Counter<u64>,
    json_decoding_error: opentelemetry::metrics::Counter<u64>,
    invalid_operation: opentelemetry::metrics::Counter<u64>,
    send_error: opentelemetry::metrics::Counter<u64>,
    kafka_reconnect_attempts: opentelemetry::metrics::Counter<u64>,
}

impl SonataStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netgauze.collector.flows.sonata.received")
            .with_description("Received messages from Kafka topic")
            .build();
        let json_decoding_error = meter
            .u64_counter("netgauze.collector.flows.sonata.json_decoding_error")
            .with_description("Number of messages encountered JSON decoding errors")
            .build();
        let invalid_operation = meter
            .u64_counter("netgauze.collector.flows.sonata.invalid_operation")
            .with_description(
                "Number of messages SONATA messages successfully decoded but invalid semantically",
            )
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.sonata.send_error")
            .with_description(
                "Error sending the SONATA enrichment operation to the enrichment actor",
            )
            .build();
        let kafka_reconnect_attempts = meter
            .u64_counter("netgauze.collector.flows.sonata.kafka.reconnect.attempts")
            .with_description("Number of attempts to reconnect to the Kafka brokers")
            .build();
        Self {
            received,
            json_decoding_error,
            invalid_operation,
            send_error,
            kafka_reconnect_attempts,
        }
    }
}

#[derive(Debug)]
enum SonataActorCommand {
    Shutdown,
}

struct SonataActor {
    cmd_rx: mpsc::Receiver<SonataActorCommand>,
    config: KafkaConsumerConfig,
    enrichment_handles: Vec<SonataEnrichmentActorHandle>,
    consumer: StreamConsumer<CosmoSonataContext>,
    stats: SonataStats,
}

impl SonataActor {
    fn from_config(
        config: KafkaConsumerConfig,
        cmd_rx: mpsc::Receiver<SonataActorCommand>,
        enrichment_handles: Vec<SonataEnrichmentActorHandle>,
        stats: SonataStats,
    ) -> Result<Self, SonataActorError> {
        let consumer = Self::init_consumer(&config)?;
        Ok(Self {
            cmd_rx,
            config,
            enrichment_handles,
            consumer,
            stats,
        })
    }

    fn init_consumer(
        config: &KafkaConsumerConfig,
    ) -> Result<StreamConsumer<CosmoSonataContext>, SonataActorError> {
        let mut client_conf = ClientConfig::new();
        for (k, v) in &config.consumer_config {
            client_conf.set(k.clone(), v.clone());
        }
        let consumer: StreamConsumer<CosmoSonataContext> =
            match client_conf.create_with_context(CosmoSonataContext) {
                Ok(consumer) => consumer,
                Err(err) => {
                    error!("Failed to create consumer: {}", err);
                    return Err(SonataActorError::KafkaError(err));
                }
            };

        if let Err(err) = consumer.subscribe(&[config.topic.as_str()]) {
            error!("Failed to subscribe to topic `{}`: {}", config.topic, err);
            return Err(SonataActorError::KafkaError(err));
        }
        Ok(consumer)
    }

    async fn handle_kafka_msg(&self, msg: BorrowedMessage<'_>) {
        let partition = msg.partition();
        let offset = msg.offset();
        // Deserialize the str payload as a SonataData struct
        let sonata_data = match msg.payload() {
            Some(p) => match serde_json::from_slice::<SonataData>(p) {
                Ok(data) => data,
                Err(err) => {
                    self.stats.json_decoding_error.add(
                        1,
                        &[opentelemetry::KeyValue::new(
                            "netgauze.kafka.sonata.json.err",
                            err.to_string(),
                        )],
                    );
                    warn!("Malformed JSON payload at partition {partition} and offset {offset}: {err}");
                    return;
                }
            },
            None => {
                warn!("Empty sonata payload at partition {partition} and offset {offset}");
                return;
            }
        };

        trace!(
            "Got Sonata message from partition {partition} and offset {offset}: {sonata_data:?}"
        );
        let op = match sonata_data.operation {
            SonataOperation::Insert | SonataOperation::Update => {
                if let Some(node) = sonata_data.node {
                    let labels = HashMap::from([
                        ("nkey".to_string(), node.hostname),
                        ("pkey".to_string(), node.platform.name),
                    ]);
                    SonataEnrichmentOperation::Upsert(
                        sonata_data.id_node,
                        node.loopback_address,
                        labels,
                    )
                } else {
                    warn!(
                        "Invalid sonata node upsert operation without a node value: {:?}",
                        msg.payload_view::<str>()
                    );
                    self.stats.invalid_operation.add(
                        1,
                        &[opentelemetry::KeyValue::new(
                            "netgauze.kafka.sonata.operation.err",
                            "upsert operation without a node value".to_string(),
                        )],
                    );
                    return;
                }
            }
            SonataOperation::Delete => SonataEnrichmentOperation::Delete(sonata_data.id_node),
        };
        debug!("Sonata Enrichment Operation: {op:?}");
        for handle in &self.enrichment_handles {
            if let Err(err) = handle.update_enrichment(op.clone()).await {
                warn!("Failed to update enrichment operation: {err}");
                self.stats.send_error.add(
                    1,
                    &[opentelemetry::KeyValue::new(
                        "netgauze.kafka.sonata.send.err",
                        err.to_string(),
                    )],
                );
            }
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        info!("Starting SonataActor");
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(SonataActorCommand::Shutdown) => {
                            info!("Sonata actor shutting down");
                            Ok("Sonata actor terminated after a shutdown command".to_string())
                        }
                        None => {
                            info!("Sonata actor terminated due to empty command channel");
                            Ok("Sonata actor terminated due to empty command channel".to_string())
                        }
                    }
                }
                msg = self.consumer.recv() => {
                    self.stats.received.add(1, &[]);
                    match msg {
                        Ok(msg) => {
                            self.handle_kafka_msg(msg).await;
                        }
                        Err(err) => {
                            match err {
                                KafkaError::MessageConsumption(RDKafkaErrorCode::AllBrokersDown) => {
                                    error!("Sonata message consumer has all brokers down, attempting to reconnect: {err}");
                                    loop {
                                        // Sleep to allow the Kafka broker to recover before retrying again.
                                        tokio::time::sleep(Duration::from_secs(60)).await;
                                        self.stats.kafka_reconnect_attempts.add(1, &[]);
                                        self.consumer = match Self::init_consumer(&self.config) {
                                            Ok(consumer) => consumer,
                                            Err(err) => {
                                                error!("Failed to reconnect to Kafka broker, retrying again: {err}");
                                                continue;
                                            }
                                        }
                                    }
                                }
                                KafkaError::MessageConsumption(RDKafkaErrorCode::UnknownTopicOrPartition) => {
                                    error!("Sonata topic doesn't exist, shutting down: {err}");
                                    return Err(anyhow::Error::from(err))
                                }
                                KafkaError::MessageConsumptionFatal(err) => {
                                    error!("Sonata message consumer has received fatal consumption error, attempting to reconnect: {err}");
                                    loop {
                                        // Sleep to allow the Kafka broker to recover before retrying again.
                                        tokio::time::sleep(Duration::from_secs(30)).await;
                                        self.stats.kafka_reconnect_attempts.add(1, &[]);
                                        self.consumer = match Self::init_consumer(&self.config) {
                                            Ok(consumer) => consumer,
                                            Err(err) => {
                                                error!("Failed to reconnect to Kafka broker, retrying again: {err}");
                                                continue;
                                            }
                                        }
                                    }
                                }
                                err => {
                                     warn!("Failed to receive Sonata message, ignoring error: {err}");
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
pub enum SonataActorHandleError {
    SendError,
}

#[derive(Debug)]
pub struct SonataActorHandle {
    cmd_send: mpsc::Sender<SonataActorCommand>,
}

impl SonataActorHandle {
    pub fn new(
        consumer_config: KafkaConsumerConfig,
        enrichment_handles: Vec<SonataEnrichmentActorHandle>,
        stats: either::Either<opentelemetry::metrics::Meter, SonataStats>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), SonataActorError> {
        let (cmd_send, cmd_rx) = mpsc::channel::<SonataActorCommand>(1);
        let stats = match stats {
            either::Left(meter) => SonataStats::new(meter),
            either::Right(stats) => stats,
        };
        let actor = SonataActor::from_config(consumer_config, cmd_rx, enrichment_handles, stats)?;
        let join_handle = tokio::spawn(actor.run());
        Ok((join_handle, SonataActorHandle { cmd_send }))
    }

    pub async fn shutdown(&self) -> Result<(), SonataActorHandleError> {
        self.cmd_send
            .send(SonataActorCommand::Shutdown)
            .await
            .map_err(|_| SonataActorHandleError::SendError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    #[test]
    fn test_serialization() {
        let insert = r#"{"operation": "insert", "id_node": 13244, "node": {"hostname": "test-node", "loopbackAddress": "1.1.1.1", "managementAddress": "1.1.1.1", "function": null, "serviceId": null, "customField": null, "nameDaisyServiceTemplate": "migr_bgp_flow2rd_md5", "idNode": "dsy-nod-13244", "idPlatform": "dsy-plt-115", "isDeployed": false, "lastUpdate": "2025-02-20T16:00:53", "platform": {"name": "DAISY-PE", "contactEmail": "Daisy.Telemetry@swisscom.com", "agileOrgUrl": "https://agileorg.scapp.swisscom.com/organisation/10069/overview", "idPlatform": "dsy-plt-115"}}}"#;
        let update = r#"{"operation": "update", "id_node": 13244, "node": {"hostname": "test-node", "loopbackAddress": "1.1.1.2", "managementAddress": "1.1.1.1", "function": null, "serviceId": null, "customField": null, "nameDaisyServiceTemplate": "migr_bgp_flow2rd_md5", "idNode": "dsy-nod-13244", "idPlatform": "dsy-plt-115", "isDeployed": false, "lastUpdate": "2025-02-20T16:03:14", "platform": {"name": "DAISY-PE", "contactEmail": "Daisy.Telemetry@swisscom.com", "agileOrgUrl": "https://agileorg.scapp.swisscom.com/organisation/10069/overview", "idPlatform": "dsy-plt-115"}}}"#;
        let delete = r#"{"operation": "delete", "id_node": 13244, "node": null}"#;
        let insert_data = serde_json::from_str::<SonataData>(insert).unwrap();
        let update_data = serde_json::from_str::<SonataData>(update).unwrap();
        let delete_data = serde_json::from_str::<SonataData>(delete).unwrap();

        let expected_insert = SonataData {
            operation: SonataOperation::Insert,
            id_node: 13244,
            node: Some(SonataNode {
                hostname: "test-node".to_string(),
                loopback_address: IpAddr::from_str("1.1.1.1").unwrap(),
                platform: SonataPlatform {
                    name: "DAISY-PE".to_string(),
                },
            }),
        };
        let expected_update = SonataData {
            operation: SonataOperation::Update,
            id_node: 13244,
            node: Some(SonataNode {
                hostname: "test-node".to_string(),
                loopback_address: IpAddr::from_str("1.1.1.2").unwrap(),
                platform: SonataPlatform {
                    name: "DAISY-PE".to_string(),
                },
            }),
        };
        let expected_delete = SonataData {
            operation: SonataOperation::Delete,
            id_node: 13244,
            node: None,
        };
        assert_eq!(insert_data, expected_insert);
        assert_eq!(update_data, expected_update);
        assert_eq!(delete_data, expected_delete);
    }
}
