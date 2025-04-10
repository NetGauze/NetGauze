// Copyright (C) 2024-present The NetGauze Authors.
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

use crate::{
    config::{FlowConfig, PublisherEndpoint, UdpNotifConfig},
    flow::{enrichment::FlowEnrichmentActorHandle, sonata::SonataActorHandle},
    publishers::{
        http::{HttpPublisherActorHandle, Message},
        kafka_avro::KafkaAvroPublisherActorHandle,
        kafka_json::KafkaJsonPublisherActorHandle,
    },
};
use futures_util::{stream::FuturesUnordered, StreamExt};
use netgauze_flow_pkt::FlatFlowInfo;
use netgauze_flow_service::{flow_supervisor::FlowCollectorsSupervisorActorHandle, FlowRequest};
use netgauze_udp_notif_pkt::MediaType;
use netgauze_udp_notif_service::{supervisor::UdpNotifSupervisorHandle, UdpNotifRequest};
use std::{str::Utf8Error, sync::Arc};
use tracing::{info, warn};

pub mod config;
pub mod flow;
pub mod publishers;

pub async fn init_flow_collection(
    flow_config: FlowConfig,
    meter: opentelemetry::metrics::Meter,
) -> anyhow::Result<()> {
    let supervisor_config = flow_config.supervisor_config();

    let (supervisor_join_handle, supervisor_handle) =
        FlowCollectorsSupervisorActorHandle::new(supervisor_config, meter.clone()).await?;
    let mut http_handles = Vec::new();
    let mut agg_handles = Vec::new();
    let mut enrichment_handles = Vec::new();
    let mut kafka_handles = Vec::new();
    let mut sonata_handles = Vec::new();
    let mut join_set = FuturesUnordered::new();
    for (group_name, publisher_config) in flow_config.publishers {
        info!("Starting publishers group '{group_name}'");

        let mut flow_recvs = Vec::new();
        if let Some(aggregation_config) = publisher_config.aggregation.as_ref() {
            (flow_recvs, _) = supervisor_handle
                .subscribe_shards(aggregation_config.workers, publisher_config.buffer_size)
                .await?;
        } else {
            let (flow_recv, _) = supervisor_handle
                .subscribe(publisher_config.buffer_size)
                .await?;
            flow_recvs.push(flow_recv);
        }

        for (endpoint_name, endpoint) in publisher_config.endpoints {
            info!("Creating publisher '{endpoint_name}'");

            match &endpoint {
                PublisherEndpoint::Http(config) => {
                    let flatten = config.flatten;
                    let flat_converter = |request: Arc<FlowRequest>, writer_id: String| {
                        let (socket, pkt) = request.as_ref();
                        let flattened: Vec<Message<FlatFlowInfo>> = pkt
                            .clone()
                            .flatten()
                            .into_iter()
                            .map(|flat_info| Message::insert {
                                ts: format!("{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
                                peer_src: format!("{}", socket.ip()),
                                writer_id: writer_id.clone(),
                                payload: flat_info,
                            })
                            .collect();
                        flattened
                    };
                    let converter = |request: Arc<FlowRequest>, writer_id: String| {
                        let ret = Message::insert {
                            ts: format!("{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
                            peer_src: format!("{}", request.0.ip()),
                            writer_id,
                            payload: request.1.clone(),
                        };
                        vec![ret]
                    };
                    for flow_recv in &flow_recvs {
                        let (http_join, http_handler) = if flatten {
                            HttpPublisherActorHandle::new(
                                endpoint_name.clone(),
                                config.clone(),
                                flat_converter,
                                flow_recv.clone(),
                                meter.clone(),
                            )?
                        } else {
                            HttpPublisherActorHandle::new(
                                endpoint_name.clone(),
                                config.clone(),
                                converter,
                                flow_recv.clone(),
                                meter.clone(),
                            )?
                        };
                        join_set.push(http_join);
                        http_handles.push(http_handler);
                    }
                }
                PublisherEndpoint::FlowKafkaAvro(config) => {
                    for (shard_id, flow_recv) in flow_recvs.iter().enumerate() {
                        if let Some(aggregation_config) = publisher_config.aggregation.as_ref() {
                            let (agg_join, agg_handle) =
                                flow::aggregation::AggregationActorHandle::new(
                                    publisher_config.buffer_size,
                                    aggregation_config.clone(),
                                    flow_recv.clone(),
                                    either::Left(meter.clone()),
                                    shard_id,
                                );
                            let (enrichment_join, enrichment_handle) =
                                FlowEnrichmentActorHandle::new(
                                    config.writer_id.clone(),
                                    publisher_config.buffer_size,
                                    agg_handle.subscribe(),
                                    either::Left(meter.clone()),
                                );
                            let enriched_rx = enrichment_handle.subscribe();
                            let (kafka_join, kafka_handle) =
                                KafkaAvroPublisherActorHandle::from_config(
                                    config.clone(),
                                    enriched_rx,
                                    either::Left(meter.clone()),
                                )
                                .await?;

                            join_set.push(agg_join);
                            join_set.push(enrichment_join);
                            join_set.push(kafka_join);
                            agg_handles.push(agg_handle);
                            enrichment_handles.push(enrichment_handle);
                            kafka_handles.push(kafka_handle);
                        }
                    }
                    if let Some(kafka_consumer) = publisher_config.sonata_enrichment.as_ref() {
                        let (sonata_join, sonata_handle) = SonataActorHandle::new(
                            kafka_consumer.clone(),
                            enrichment_handles.clone(),
                            either::Left(meter.clone()),
                        )?;
                        join_set.push(sonata_join);
                        sonata_handles.push(sonata_handle);
                    }
                }
                PublisherEndpoint::KafkaJson(_) => {
                    return Err(anyhow::anyhow!(
                        "Kafka JSON publisher not yet supported for Flow"
                    ));
                }
            }
        }
    }
    let ret = tokio::select! {
        _ = supervisor_join_handle => {
            info!("Flow supervisor exited, shutting down all publishers");
            for handler in http_handles {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handler.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down flow http publisher {}", handler.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down flow http publisher {}: {err}", handler.name())
                }
            }
            Ok(())
        },
        _ = join_set.next() => {
            warn!("Flow http publisher exited, shutting down flow collection and publishers");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), supervisor_handle.shutdown()).await;
            for handler in agg_handles {
                let _ = handler.shutdown().await;
            }
            for handler in enrichment_handles {
                let _ = handler.shutdown().await;
            }
            for handler in http_handles {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handler.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down flow http publisher {}", handler.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down flow http publisher {}: {err}", handler.name())
                }
            }
            for handler in kafka_handles {
                let _ = handler.shutdown().await;
            }
            for handler in sonata_handles {
                let _ = handler.shutdown().await;
            }
            Ok(())
        }
    };
    ret
}

pub async fn init_udp_notif_collection(
    udp_notif_config: UdpNotifConfig,
    meter: opentelemetry::metrics::Meter,
) -> anyhow::Result<()> {
    let supervisor_config = udp_notif_config.supervisor_config();
    let (supervisor_join_handle, supervisor_handle) =
        UdpNotifSupervisorHandle::new(supervisor_config, meter.clone()).await;
    let mut join_set = FuturesUnordered::new();
    let mut http_handlers = Vec::new();
    let mut kafka_handles = Vec::new();
    for (group_name, publisher_config) in udp_notif_config.publishers {
        info!("Starting publishers group '{group_name}'");
        let (udp_notif_recv, _) = supervisor_handle
            .subscribe(publisher_config.buffer_size)
            .await?;
        for (endpoint_name, endpoint) in publisher_config.endpoints {
            info!("Creating publisher '{endpoint_name}'");
            match &endpoint {
                PublisherEndpoint::Http(config) => {
                    let (http_join, http_handler) = HttpPublisherActorHandle::new(
                        endpoint_name.clone(),
                        config.clone(),
                        |x: Arc<UdpNotifRequest>, writer_id: String| {
                            vec![Message::insert {
                                ts: format!("{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
                                peer_src: format!("{}", x.0.ip()),
                                writer_id,
                                payload: x.1.clone(),
                            }]
                        },
                        udp_notif_recv.clone(),
                        meter.clone(),
                    )?;
                    join_set.push(http_join);
                    http_handlers.push(http_handler);
                }
                PublisherEndpoint::KafkaJson(config) => {
                    let hdl = KafkaJsonPublisherActorHandle::from_config(
                        serialize_udp_notif,
                        config.clone(),
                        udp_notif_recv.clone(),
                        either::Left(meter.clone()),
                    );
                    match hdl {
                        Ok((kafka_join, kafka_handle)) => {
                            join_set.push(kafka_join);
                            kafka_handles.push(kafka_handle);
                        }
                        Err(err) => {
                            return Err(anyhow::anyhow!(
                                "Error creating KafkaJsonPublisherActorHandle: {err}"
                            ));
                        }
                    }
                }
                PublisherEndpoint::FlowKafkaAvro(_) => {
                    return Err(anyhow::anyhow!(
                        "Kafka Avro publisher not yet supported for UDP Notif"
                    ));
                }
            }
        }
    }
    let ret = tokio::select! {
        _ = supervisor_join_handle => {
            info!("udp-notif supervisor exited, shutting down all publishers");
           for handler in http_handlers {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handler.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down udp-notif http publisher {}", handler.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down udp-notif http publisher {}: {}", handler.name(), err)
                }
            }
            Ok(())
        },
        _ = join_set.next() => {
            warn!("udp-notif http publisher exited, shutting down udp-notif collection and publishers");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), supervisor_handle.shutdown()).await;
            for handler in http_handlers {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handler.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down udp-notif http publisher {}", handler.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down udp-notif http publisher {}: {}", handler.name(), err)
                }
            }
            Ok(())
        }
    };
    ret
}

#[derive(Debug, strum_macros::Display)]
pub enum UdpNotifSerializationError {
    SerializationError(serde_json::Error),
    Utf8Error(Utf8Error),
    UnsupportedMediaType(MediaType),
}

impl std::error::Error for UdpNotifSerializationError {}

impl From<serde_json::Error> for UdpNotifSerializationError {
    fn from(err: serde_json::Error) -> Self {
        UdpNotifSerializationError::SerializationError(err)
    }
}

impl From<Utf8Error> for UdpNotifSerializationError {
    fn from(err: Utf8Error) -> Self {
        UdpNotifSerializationError::Utf8Error(err)
    }
}

fn serialize_udp_notif(
    input: Arc<UdpNotifRequest>,
    writer_id: String,
) -> Result<(Option<serde_json::Value>, serde_json::Value), UdpNotifSerializationError> {
    let (peer, msg) = input.as_ref();
    let mut value = serde_json::to_value(msg)?;
    if let serde_json::Value::Object(ref mut val) = &mut value {
        // Add the writer ID to the message
        val.insert(
            "writer_id".to_string(),
            serde_json::Value::String(writer_id.to_string()),
        );
        // Convert inner payload into human-readable format when possible
        match msg.media_type() {
            MediaType::YangDataJson => {
                // Deserialize the payload into a JSON object
                let payload = serde_json::from_slice(msg.payload())?;
                val.insert("payload".to_string(), payload);
            }
            MediaType::YangDataXml => {
                let payload = std::str::from_utf8(msg.payload())?;
                val.insert(
                    "payload".to_string(),
                    serde_json::Value::String(payload.to_string()),
                );
            }
            MediaType::YangDataCbor => {
                let payload = std::str::from_utf8(msg.payload())?;
                val.insert(
                    "payload".to_string(),
                    serde_json::Value::String(payload.to_string()),
                );
            }
            media_type => {
                return Err(UdpNotifSerializationError::UnsupportedMediaType(media_type));
            }
        }
    }
    Ok((
        Some(serde_json::Value::String(peer.ip().to_string())),
        value,
    ))
}
