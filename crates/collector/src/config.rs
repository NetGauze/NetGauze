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

use crate::flow::aggregation::AggregationConfig;
use crate::flow::config::FlowOutputConfig;
use crate::flow::enrichment::EnrichmentConfig;
use crate::publishers::http::HttpPublisherEndpoint;
use crate::publishers::{kafka_avro, kafka_json, kafka_yang};
use crate::yang_push::config::TelemetryYangConverter;
use ipnet::IpNet;
use netgauze_flow_service::flow_supervisor;
use netgauze_udp_notif_service::supervisor as udp_notif_supervisor;
use netgauze_yang_push::cache::storage::YangLibraryReference;
use serde_with::serde_as;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

const NUM_WORKERS_DEFAULT: usize = 1;

pub(crate) const fn default_num_workers() -> usize {
    NUM_WORKERS_DEFAULT
}

const SUBSCRIBER_TIMEOUT_DURATION_DEFAULT: Duration = Duration::from_millis(100);

pub(crate) const fn default_subscriber_timeout_duration() -> Duration {
    SUBSCRIBER_TIMEOUT_DURATION_DEFAULT
}

pub(crate) const fn default_telemetry_timeout() -> Duration {
    Duration::from_secs(5)
}

pub(crate) const fn default_telemetry_interval() -> Duration {
    Duration::from_secs(60)
}

pub(crate) const fn default_cmd_size_buffer() -> usize {
    100
}

pub(crate) const fn default_buffer_size() -> usize {
    1_000
}

pub(crate) const fn default_shards() -> usize {
    1
}

pub(crate) const fn default_max_cached_packets_per_peer() -> usize {
    1000
}

pub(crate) const fn default_max_cached_packets_per_subscription() -> usize {
    100
}

pub(crate) const fn default_netconf_port() -> u16 {
    830
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CollectorConfig {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub logging: LoggingConfig,
    pub telemetry: TelemetryConfig,
    pub flow: Option<FlowConfig>,
    pub udp_notif: Option<UdpNotifConfig>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeConfig {
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub threads: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TelemetryConfig {
    pub url: String,

    /// Id to distinguish multiple instances running at the same site
    pub id: String,

    /// Metrics exporter GRPC timeout
    #[serde(default = "default_telemetry_timeout")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub exporter_timeout: Duration,

    /// Configures the intervening time between exports for a
    /// [opentelemetry_sdk::metrics::PeriodicReader]
    #[serde(default = "default_telemetry_interval")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub reader_interval: Duration,

    /// Configures the time a [opentelemetry_sdk::metrics::PeriodicReader] waits
    /// for an export to complete before canceling it.
    #[serde(default = "default_telemetry_timeout")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub reader_timeout: Duration,
}

impl TelemetryConfig {
    pub fn url(&self) -> &str {
        self.url.as_str()
    }
    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowConfig {
    #[serde(default = "default_subscriber_timeout_duration")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub subscriber_timeout: Duration,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub template_cache_purge_timeout: Option<Duration>,

    #[serde(default = "default_cmd_size_buffer")]
    pub cmd_buffer_size: usize,

    pub listeners: Vec<Binding>,

    pub publishers: HashMap<String, PublisherConfig>,
}

impl FlowConfig {
    pub fn supervisor_config(&self) -> flow_supervisor::SupervisorConfig {
        flow_supervisor::SupervisorConfig {
            binding_addresses: self.listeners.iter().cloned().map(|x| x.into()).collect(),
            subscriber_timeout: self.subscriber_timeout,
            cmd_buffer_size: self.cmd_buffer_size,
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdpNotifConfig {
    #[serde(default = "default_subscriber_timeout_duration")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub subscriber_timeout: Duration,

    #[serde(default = "default_cmd_size_buffer")]
    pub cmd_buffer_size: usize,

    pub listeners: Vec<Binding>,

    /// Location of the cached YANG schemas
    pub cache_location: String,

    #[serde(default = "default_max_cached_packets_per_peer")]
    pub max_cached_packets_per_peer: usize,

    #[serde(default = "default_max_cached_packets_per_subscription")]
    pub max_cached_packets_per_subscription: usize,

    pub netconf: NetconfConfig,

    pub publishers: HashMap<String, PublisherConfig>,
}

impl UdpNotifConfig {
    pub fn supervisor_config(&self) -> udp_notif_supervisor::SupervisorConfig {
        udp_notif_supervisor::SupervisorConfig {
            binding_addresses: self.listeners.iter().cloned().map(|x| x.into()).collect(),
            subscriber_timeout: self.subscriber_timeout,
            cmd_buffer_size: self.cmd_buffer_size,
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetconfConfig {
    pub username: String,
    pub private_key_path: String,
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub password: Option<String>,
    #[serde(default = "default_netconf_port")]
    pub port: u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Binding {
    pub address: SocketAddr,
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub interface: Option<String>,
    #[serde(default = "default_num_workers")]
    pub workers: usize,
}

impl From<Binding> for flow_supervisor::BindingAddress {
    fn from(value: Binding) -> Self {
        flow_supervisor::BindingAddress {
            socket_addr: value.address,
            num_workers: value.workers,
            interface: value.interface,
        }
    }
}

impl From<Binding> for udp_notif_supervisor::BindingAddress {
    fn from(value: Binding) -> Self {
        udp_notif_supervisor::BindingAddress {
            socket_addr: value.address,
            num_workers: value.workers,
            interface: value.interface,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublisherConfig {
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    #[serde(default = "default_shards")]
    pub shards: usize,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub enrichment: Option<EnrichmentConfig>,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub aggregation: Option<AggregationConfig>,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub custom_yang_schemas: Option<HashMap<IpNet, YangLibraryReference>>,

    pub endpoints: HashMap<String, PublisherEndpoint>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PublisherEndpoint {
    /// HTTP publisher endpoint
    Http(HttpPublisherEndpoint),

    /// Kafka JSON publisher endpoint
    KafkaJson(kafka_json::KafkaConfig),

    /// Kafka JSON publisher endpoint (for aggregated flow packets)
    FlowKafkaJson(kafka_json::KafkaConfig),

    /// Kafka Avro publisher endpoint (for aggregated flow packets with avro
    /// conversion)
    FlowKafkaAvro(kafka_avro::KafkaConfig<FlowOutputConfig>),

    /// Kafka JSON publisher endpoint (for validated yang-push telemetry
    /// messages)
    TelemetryKafkaJson(kafka_json::KafkaConfig),

    /// Kafka YANG publisher endpoint
    /// (for validated yang-push telemetry messages and YANG schema
    /// registration)
    TelemetryKafkaYang(kafka_yang::KafkaConfig<TelemetryYangConverter>),
}
