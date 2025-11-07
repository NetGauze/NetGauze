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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod actor;
mod formats;
mod handlers;

pub use actor::KafkaConsumerActorHandle;

pub(crate) const fn default_weight() -> u8 {
    64
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KafkaConfig {
    pub consumers: Vec<KafkaConsumerConfig>,
}

/// Kafka consumer config
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KafkaConsumerConfig {
    pub topic: String,

    pub message_format: KafkaMessageFormat,

    pub consumer_config: HashMap<String, String>,
}

#[derive(strum_macros::Display, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KafkaMessageFormat {
    /// JSON-serialized [`crate::flow::enrichment::EnrichmentOperation`]
    /// messages
    #[strum(to_string = "JSON Flow EnrichmentOperation message")]
    FlowEnrichmentOps,

    /// JSON-serialized [`crate::yang_push::EnrichmentOperation`] messages
    #[strum(to_string = "JSON Yang-Push EnrichmentOperation message")]
    YangPushEnrichmentOps,

    /// Swisscom custom SonataDB insert/update/delete messages
    #[strum(to_string = "Swisscom custom SonataDB message")]
    Sonata(SonataConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SonataConfig {
    #[serde(default = "default_weight")]
    pub weight: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml;
    #[test]
    fn test_kafkaconfig_serialize_to_yaml() {
        let mut consumer_config = HashMap::new();
        consumer_config.insert(
            "bootstrap.servers".to_string(),
            "localhost:9092".to_string(),
        );

        let config = KafkaConfig {
            consumers: vec![
                KafkaConsumerConfig {
                    topic: "enrichment-ops".to_string(),
                    message_format: KafkaMessageFormat::FlowEnrichmentOps,
                    consumer_config: consumer_config.clone(),
                },
                KafkaConsumerConfig {
                    topic: "yang-push-ops".to_string(),
                    message_format: KafkaMessageFormat::YangPushEnrichmentOps,
                    consumer_config: consumer_config.clone(),
                },
                KafkaConsumerConfig {
                    topic: "sonata-db".to_string(),
                    message_format: KafkaMessageFormat::Sonata(SonataConfig { weight: 100 }),
                    consumer_config: consumer_config.clone(),
                },
                KafkaConsumerConfig {
                    topic: "sonata-db-default".to_string(),
                    message_format: KafkaMessageFormat::Sonata(SonataConfig {
                        weight: default_weight(),
                    }),
                    consumer_config,
                },
            ],
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        let expected = r#"consumers:
- topic: enrichment-ops
  message_format: FlowEnrichmentOps
  consumer_config:
    bootstrap.servers: localhost:9092
- topic: yang-push-ops
  message_format: YangPushEnrichmentOps
  consumer_config:
    bootstrap.servers: localhost:9092
- topic: sonata-db
  message_format: !Sonata
    weight: 100
  consumer_config:
    bootstrap.servers: localhost:9092
- topic: sonata-db-default
  message_format: !Sonata
    weight: 64
  consumer_config:
    bootstrap.servers: localhost:9092
"#;
        assert_eq!(yaml, expected);
    }

    #[test]
    fn test_kafkaconfig_deserialize_from_yaml() {
        let yaml = r#"consumers:
- topic: enrichment-ops
  message_format: !FlowEnrichmentOps
  consumer_config:
    bootstrap.servers: localhost:9092
    group.id: test-group
- topic: yang-push-ops
  message_format: !YangPushEnrichmentOps
  consumer_config:
    bootstrap.servers: localhost:9092
    group.id: test-group
- topic: sonata-db
  message_format: !Sonata
    weight: 100
  consumer_config:
    bootstrap.servers: kafka:9092
    group.id: test-group-2
- topic: sonata-db-default
  message_format: !Sonata
  consumer_config:
    bootstrap.servers: kafka:9092
    group.id: test-group-2
"#;

        let config: KafkaConfig = serde_yaml::from_str(yaml).unwrap();

        let mut consumer_config_1 = HashMap::new();
        consumer_config_1.insert(
            "bootstrap.servers".to_string(),
            "localhost:9092".to_string(),
        );
        consumer_config_1.insert("group.id".to_string(), "test-group".to_string());

        let mut consumer_config_2 = HashMap::new();
        consumer_config_2.insert("bootstrap.servers".to_string(), "kafka:9092".to_string());
        consumer_config_2.insert("group.id".to_string(), "test-group-2".to_string());

        let expected = KafkaConfig {
            consumers: vec![
                KafkaConsumerConfig {
                    topic: "enrichment-ops".to_string(),
                    message_format: KafkaMessageFormat::FlowEnrichmentOps,
                    consumer_config: consumer_config_1.clone(),
                },
                KafkaConsumerConfig {
                    topic: "yang-push-ops".to_string(),
                    message_format: KafkaMessageFormat::YangPushEnrichmentOps,
                    consumer_config: consumer_config_1,
                },
                KafkaConsumerConfig {
                    topic: "sonata-db".to_string(),
                    message_format: KafkaMessageFormat::Sonata(SonataConfig { weight: 100 }),
                    consumer_config: consumer_config_2.clone(),
                },
                KafkaConsumerConfig {
                    topic: "sonata-db-default".to_string(),
                    message_format: KafkaMessageFormat::Sonata(SonataConfig { weight: 64 }),
                    consumer_config: consumer_config_2,
                },
            ],
        };

        assert_eq!(config, expected);
    }
}
