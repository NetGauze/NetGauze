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
    flow::{
        aggregation::AggregationActorHandle,
        enrichment::{EnrichmentActorHandle, FlowOptionsActorHandle},
        sonata::SonataActorHandle,
        sonata_enrichment::SonataEnrichmentActorHandle,
    },
    publishers::{
        http::{HttpPublisherActorHandle, Message},
        kafka_avro::KafkaAvroPublisherActorHandle,
        kafka_json::KafkaJsonPublisherActorHandle,
    },
};
use futures_util::{stream::FuturesUnordered, StreamExt};
use netgauze_flow_pkt::FlowInfo;
use netgauze_flow_service::{flow_supervisor::FlowCollectorsSupervisorActorHandle, FlowRequest};
use netgauze_udp_notif_pkt::MediaType;
use netgauze_udp_notif_service::{supervisor::UdpNotifSupervisorHandle, UdpNotifRequest};
use netgauze_yang_push::{
    enrichment::YangPushEnrichmentActorHandle, model::telemetry::TelemetryMessageWrapper,
    validation::ValidationActorHandle,
};
use std::{net::IpAddr, str::Utf8Error, sync::Arc};
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
    let mut enrichment_handles = Vec::new();
    let mut agg_handles = Vec::new();
    let mut flow_options_handles = Vec::new();
    let mut sonata_enrichment_handles = Vec::new();
    let mut kafka_avro_handles = Vec::new();
    let mut kafka_json_handles = Vec::new();
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
                        let (http_join, http_handle) = HttpPublisherActorHandle::new(
                            endpoint_name.clone(),
                            config.clone(),
                            converter,
                            flow_recv.clone(),
                            meter.clone(),
                        )?;
                        join_set.push(http_join);
                        http_handles.push(http_handle);
                    }
                }
                PublisherEndpoint::FlowKafkaAvro(config) => {
                    for (shard_id, flow_recv) in flow_recvs.iter().enumerate() {
                        let (enrichment_join, enrichment_handle) = EnrichmentActorHandle::new(
                            publisher_config.buffer_size,
                            flow_recv.clone(),
                            either::Left(meter.clone()),
                            shard_id,
                        );

                        if let Some(aggregation_config) = publisher_config.aggregation.as_ref() {
                            let (agg_join, agg_handle) = AggregationActorHandle::new(
                                publisher_config.buffer_size,
                                aggregation_config.clone(),
                                enrichment_handle.subscribe(),
                                either::Left(meter.clone()),
                                shard_id,
                            );

                            let (sonata_enrichment_join, sonata_enrichment_handle) =
                                SonataEnrichmentActorHandle::new(
                                    config.writer_id.clone(),
                                    publisher_config.buffer_size,
                                    agg_handle.subscribe(),
                                    either::Left(meter.clone()),
                                );

                            let (kafka_join, kafka_handle) =
                                KafkaAvroPublisherActorHandle::from_config(
                                    config.clone(),
                                    sonata_enrichment_handle.subscribe(),
                                    either::Left(meter.clone()),
                                )
                                .await?;

                            join_set.push(enrichment_join);
                            join_set.push(agg_join);
                            join_set.push(sonata_enrichment_join);
                            join_set.push(kafka_join);
                            enrichment_handles.push(enrichment_handle);
                            agg_handles.push(agg_handle);
                            sonata_enrichment_handles.push(sonata_enrichment_handle);
                            kafka_avro_handles.push(kafka_handle);
                        }
                    }

                    let (flow_recv, _) = supervisor_handle
                        .subscribe(publisher_config.buffer_size)
                        .await?;
                    let (flow_options_join, flow_options_handle) = FlowOptionsActorHandle::new(
                        flow_recv.clone(),
                        enrichment_handles.clone(),
                        either::Left(meter.clone()),
                    );
                    join_set.push(flow_options_join);
                    flow_options_handles.push(flow_options_handle);

                    if let Some(kafka_consumer) = publisher_config.sonata_enrichment.as_ref() {
                        let (sonata_join, sonata_handle) = SonataActorHandle::new(
                            kafka_consumer.clone(),
                            sonata_enrichment_handles.clone(),
                            either::Left(meter.clone()),
                        )?;
                        join_set.push(sonata_join);
                        sonata_handles.push(sonata_handle);
                    }
                }
                PublisherEndpoint::FlowKafkaJson(config) => {
                    for (shard_id, flow_recv) in flow_recvs.iter().enumerate() {
                        let (enrichment_join, enrichment_handle) = EnrichmentActorHandle::new(
                            publisher_config.buffer_size,
                            flow_recv.clone(),
                            either::Left(meter.clone()),
                            shard_id,
                        );

                        if let Some(aggregation_config) = publisher_config.aggregation.as_ref() {
                            let (agg_join, agg_handle) = AggregationActorHandle::new(
                                publisher_config.buffer_size,
                                aggregation_config.clone(),
                                enrichment_handle.subscribe(),
                                either::Left(meter.clone()),
                                shard_id,
                            );

                            let (sonata_enrichment_join, sonata_enrichment_handle) =
                                SonataEnrichmentActorHandle::new(
                                    config.writer_id.clone(),
                                    publisher_config.buffer_size,
                                    agg_handle.subscribe(),
                                    either::Left(meter.clone()),
                                );

                            let (kafka_join, kafka_handle) =
                                KafkaJsonPublisherActorHandle::from_config(
                                    serialize_flow,
                                    config.clone(),
                                    sonata_enrichment_handle.subscribe(),
                                    either::Left(meter.clone()),
                                )?;

                            join_set.push(enrichment_join);
                            join_set.push(agg_join);
                            join_set.push(sonata_enrichment_join);
                            join_set.push(kafka_join);
                            enrichment_handles.push(enrichment_handle);
                            agg_handles.push(agg_handle);
                            sonata_enrichment_handles.push(sonata_enrichment_handle);
                            kafka_json_handles.push(kafka_handle);
                        }
                    }

                    let (flow_recv, _) = supervisor_handle
                        .subscribe(publisher_config.buffer_size)
                        .await?;
                    let (flow_options_join, flow_options_handle) = FlowOptionsActorHandle::new(
                        flow_recv.clone(),
                        enrichment_handles.clone(),
                        either::Left(meter.clone()),
                    );
                    join_set.push(flow_options_join);
                    flow_options_handles.push(flow_options_handle);

                    if let Some(kafka_consumer) = publisher_config.sonata_enrichment.as_ref() {
                        let (sonata_join, sonata_handle) = SonataActorHandle::new(
                            kafka_consumer.clone(),
                            sonata_enrichment_handles.clone(),
                            either::Left(meter.clone()),
                        )?;
                        join_set.push(sonata_join);
                        sonata_handles.push(sonata_handle);
                    }
                }
                PublisherEndpoint::KafkaJson(config) => {
                    for flow_recv in &flow_recvs {
                        let (join_handle, handle) = KafkaJsonPublisherActorHandle::from_config(
                            serialize_flow_req,
                            config.clone(),
                            flow_recv.clone(),
                            either::Left(meter.clone()),
                        )?;
                        join_set.push(join_handle);
                        kafka_json_handles.push(handle);
                    }
                }
                PublisherEndpoint::TelemetryKafkaJson(_) => {
                    return Err(anyhow::anyhow!(
                        "Telemetry KafkaJson publisher not yet supported for Flow"
                    ));
                }
            }
        }
    }
    let ret = tokio::select! {
        supervisor_ret = supervisor_join_handle => {
            info!("Flow supervisor exited, shutting down all publishers");
            for handle in http_handles {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handle.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down flow http publisher {}", handle.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down flow http publisher {}: {err}", handle.name())
                }
            }
            for handle in kafka_avro_handles {
                let _ = handle.shutdown().await;
            }
            for handle in kafka_json_handles {
                let _ = handle.shutdown().await;
            }
            match supervisor_ret {
                Ok(_) => Ok(()),
                Err(err) => Err(anyhow::anyhow!(err)),
            }
        },
        join_ret = join_set.next() => {
            warn!("Flow publisher exited, shutting down flow collection and publishers");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), supervisor_handle.shutdown()).await;
            for handle in enrichment_handles {
                let _ = handle.shutdown().await;
            }
            for handle in agg_handles {
                let _ = handle.shutdown().await;
            }
            for handle in sonata_enrichment_handles {
                let _ = handle.shutdown().await;
            }
            for handle in http_handles {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handle.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down flow http publisher {}", handle.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down flow http publisher {}: {err}", handle.name())
                }
            }
            for handle in kafka_avro_handles {
                let _ = handle.shutdown().await;
            }
            for handle in kafka_json_handles {
                let _ = handle.shutdown().await;
            }
            for handle in flow_options_handles {
                let _ = handle.shutdown().await;
            }
            for handle in sonata_handles {
                let _ = handle.shutdown().await;
            }
            match join_ret {
                None | Some(Ok(Ok(_))) => Ok(()),
                Some(Err(err)) => Err(anyhow::anyhow!(err)),
                Some(Ok(Err(err))) => Err(anyhow::anyhow!(err)),
            }
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
    let mut validation_handles = Vec::new();
    let mut enrichment_handles = Vec::new();
    let mut http_handles = Vec::new();
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
                    let (http_join, http_handle) = HttpPublisherActorHandle::new(
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
                    http_handles.push(http_handle);
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
                PublisherEndpoint::FlowKafkaJson(_) => {
                    return Err(anyhow::anyhow!(
                        "Flow Kafka JSON publisher not supported for UDP Notif"
                    ));
                }
                PublisherEndpoint::FlowKafkaAvro(_) => {
                    return Err(anyhow::anyhow!(
                        "Flow Kafka Avro publisher not supported for UDP Notif"
                    ));
                }
                PublisherEndpoint::TelemetryKafkaJson(config) => {
                    let (validation_join, validation_handle) = ValidationActorHandle::new(
                        publisher_config.buffer_size,
                        udp_notif_recv.clone(),
                        either::Left(meter.clone()),
                    );
                    join_set.push(validation_join);
                    validation_handles.push(validation_handle.clone());

                    let (enrichment_join, enrichment_handle) = YangPushEnrichmentActorHandle::new(
                        publisher_config.buffer_size,
                        udp_notif_recv.clone(),
                        either::Left(meter.clone()),
                    );
                    join_set.push(enrichment_join);
                    enrichment_handles.push(enrichment_handle.clone());

                    let enriched_rx = enrichment_handle.subscribe();
                    let hdl = KafkaJsonPublisherActorHandle::from_config(
                        serialize_yang_push,
                        config.clone(),
                        enriched_rx,
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
            }
        }
    }
    let ret = tokio::select! {
        supervisor_ret = supervisor_join_handle => {
            info!("udp-notif supervisor exited, shutting down all publishers");
           for handle in http_handles {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handle.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down udp-notif http publisher {}", handle.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down udp-notif http publisher {}: {}", handle.name(), err)
                }
            }
            for handle in kafka_handles {
                let _ = handle.shutdown().await;
            }
            match supervisor_ret {
                Ok(_) => Ok(()),
                Err(err) => Err(anyhow::anyhow!(err)),
            }
        },
        join_ret = join_set.next() => {
            warn!("udp-notif http publisher exited, shutting down udp-notif collection and publishers");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), supervisor_handle.shutdown()).await;
            for handle in validation_handles {
                let _ = handle.shutdown().await;
            }
            for handle in enrichment_handles {
                let _ = handle.shutdown().await;
            }
            for handle in http_handles {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handle.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down udp-notif http publisher {}", handle.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down udp-notif http publisher {}: {}", handle.name(), err)
                }
            }
            for handle in kafka_handles {
                let _ = handle.shutdown().await;
            }
            match join_ret {
                None | Some(Ok(Ok(_))) => Ok(()),
                Some(Err(err)) => Err(anyhow::anyhow!(err)),
                Some(Ok(Err(err))) => Err(anyhow::anyhow!(err)),
            }
        }
    };
    ret
}

#[derive(Debug, strum_macros::Display)]
pub enum UdpNotifSerializationError {
    SerializationError(serde_json::Error),
    Utf8Error(Utf8Error),
    CborError(ciborium::de::Error<std::io::Error>),
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

impl From<ciborium::de::Error<std::io::Error>> for UdpNotifSerializationError {
    fn from(err: ciborium::de::Error<std::io::Error>) -> Self {
        UdpNotifSerializationError::CborError(err)
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
                let payload: serde_json::Value =
                    ciborium::de::from_reader(std::io::Cursor::new(msg.payload()))?;
                val.insert("payload".to_string(), payload);
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

fn serialize_yang_push(
    input: TelemetryMessageWrapper,
    _writer_id: String,
) -> Result<(Option<serde_json::Value>, serde_json::Value), UdpNotifSerializationError> {
    let ip = input
        .message()
        .telemetry_message_metadata()
        .export_address();
    let value = serde_json::to_value(input)?;
    let key = serde_json::Value::String(ip.to_string());
    Ok((Some(key), value))
}

#[derive(Debug, strum_macros::Display)]
pub enum FlowSerializationError {
    SerializationError(serde_json::Error),
    Utf8Error(Utf8Error),
}

impl std::error::Error for FlowSerializationError {}

impl From<serde_json::Error> for FlowSerializationError {
    fn from(err: serde_json::Error) -> Self {
        FlowSerializationError::SerializationError(err)
    }
}

fn serialize_flow_req(
    input: Arc<FlowRequest>,
    _writer_id: String,
) -> Result<(Option<serde_json::Value>, serde_json::Value), FlowSerializationError> {
    let (peer, msg) = input.as_ref();
    let value = serde_json::to_value(msg)?;
    let key = serde_json::Value::String(peer.ip().to_string());
    Ok((Some(key), value))
}

fn serialize_flow(
    input: (IpAddr, FlowInfo),
    _writer_id: String,
) -> Result<(Option<serde_json::Value>, serde_json::Value), FlowSerializationError> {
    let (ip, msg) = input;
    let value = serde_json::to_value(msg)?;
    let key = serde_json::Value::String(ip.to_string());
    Ok((Some(key), value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use netgauze_udp_notif_pkt::UdpNotifPacket;
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    #[test]
    fn test_serialize_udp_notif_unknown_media_type() {
        let writer_id = String::from("writer_id");
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let pkt = UdpNotifPacket::new(
            MediaType::Unknown(0xee),
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(&[0xffu8, 0xffu8][..]),
        );

        let request = Arc::new((peer, pkt));
        let serialized = serialize_udp_notif(request.clone(), writer_id.clone());
        assert!(matches!(
            serialized,
            Err(UdpNotifSerializationError::UnsupportedMediaType(
                MediaType::Unknown(0xee)
            ))
        ));
    }

    #[test]
    fn test_serialize_udp_notif_json() {
        let writer_id = String::from("writer_id");
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let pkt = UdpNotifPacket::new(
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(r#"{"id": 1}"#),
        );

        let pkt_invalid_json = UdpNotifPacket::new(
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(r#"{"id""#),
        );

        let expected_value = serde_json::json!(
            {
                "media_type": "YangDataJson",
                "message_id": 33554434,
                "options": {},
                "payload": {"id": 1},
                "publisher_id": 16777217,
                "writer_id": "writer_id"
            }
        );
        let request_invalid = Arc::new((peer, pkt_invalid_json));
        let request_good = Arc::new((peer, pkt));
        let result_invalid = serialize_udp_notif(request_invalid, writer_id.clone());
        let serialized =
            serialize_udp_notif(request_good, writer_id.clone()).expect("failed to serialize json");

        assert!(matches!(
            result_invalid,
            Err(UdpNotifSerializationError::SerializationError(_))
        ));
        assert_eq!(
            serialized,
            (
                Some(serde_json::Value::String(peer.ip().to_string())),
                expected_value
            )
        );
    }

    #[test]
    fn test_serialize_udp_notif_xml() {
        let writer_id = String::from("writer_id");
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let pkt = UdpNotifPacket::new(
            MediaType::YangDataXml,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from("<id>1</id>"),
        );
        let pkt_invalid_utf8 = UdpNotifPacket::new(
            MediaType::YangDataXml,
            0x01000001,
            0x02000002,
            HashMap::new(),
            // A UTF-8 continuation byte (10xxxxxx) without a leading byte
            Bytes::from(vec![0x80]),
        );

        let expected_value = serde_json::json!(
            {
                "media_type": "YangDataXml",
                "message_id": 33554434,
                "options": {},
                "payload": "<id>1</id>",
                "publisher_id": 16777217,
                "writer_id": "writer_id"
            }
        );

        let request_invalid = Arc::new((peer, pkt_invalid_utf8));
        let request_good = Arc::new((peer, pkt));
        let result_invalid = serialize_udp_notif(request_invalid, writer_id.clone());
        let serialized =
            serialize_udp_notif(request_good, writer_id.clone()).expect("failed to serialize json");
        assert!(matches!(
            result_invalid,
            Err(UdpNotifSerializationError::Utf8Error(_))
        ));
        assert_eq!(
            serialized,
            (
                Some(serde_json::Value::String(peer.ip().to_string())),
                expected_value
            )
        );
    }

    #[test]
    fn test_serialize_udp_notif_cbor() {
        let writer_id = String::from("writer_id");
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut cursor = std::io::Cursor::new(vec![]);
        ciborium::ser::into_writer(&serde_json::json!({"id": 1}), &mut cursor)
            .expect("failed to serialize cbor");
        let payload = cursor.into_inner();
        let pkt = UdpNotifPacket::new(
            MediaType::YangDataCbor,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(payload),
        );
        let pkt_invalid = UdpNotifPacket::new(
            MediaType::YangDataCbor,
            0x01000001,
            0x02000002,
            HashMap::new(),
            // Array of length 3, but only contains 2 elements
            Bytes::from(vec![0x83, 0x01, 0x02]),
        );

        let expected_value = serde_json::json!(
            {
                "media_type": "YangDataCbor",
                "message_id": 33554434,
                "options": {},
                "payload": {"id": 1},
                "publisher_id": 16777217,
                "writer_id": "writer_id"
            }
        );

        let request_invalid = Arc::new((peer, pkt_invalid));
        let request_good = Arc::new((peer, pkt));
        let result_invalid = serialize_udp_notif(request_invalid, writer_id.clone());
        let serialized =
            serialize_udp_notif(request_good, writer_id.clone()).expect("failed to serialize json");
        assert!(matches!(
            result_invalid,
            Err(UdpNotifSerializationError::CborError(_))
        ));
        assert_eq!(
            serialized,
            (
                Some(serde_json::Value::String(peer.ip().to_string())),
                expected_value
            )
        );
    }
}
