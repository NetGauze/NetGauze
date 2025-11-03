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
use crate::{
    flow::enrichment::{DeletePayload, EnrichmentOperation, Scope, UpsertPayload},
    inputs::{
        kafka::{
            formats::sonata::{SonataData, SonataOperation},
            SonataConfig,
        },
        InputProcessingError,
    },
};
use netgauze_flow_pkt::ie::{Field, IE};
use std::{collections::HashMap, net::IpAddr};

/// **Generic Kafka Message Handler Traig**
///
/// Trait for handling different message formats from Kafka
pub trait KafkaMessageHandler<T>: Send + Sync + 'static {
    /// Parse the raw message into a vector of output type `T`
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<T>, InputProcessingError>;
}

/// **Kafka Enrichment Operation Handler**
///
/// Handler for Kafka messages with JSON [`EnrichmentOperation`] format,
/// such as:
///
/// ```json
/// {
///   "Upsert": {
///     "ip": "::ffff:192.168.100.6",
///     "scope": {
///       "obs_domain_id": 1999104,
///       "scope_fields": [
///         {
///           "selectorId": 27
///         }
///       ]
///     },
///     "weight": 205,
///     "fields": [
///       {
///         "applicationName": "APP-NAME"
///       }
///     ]
///   }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct KafkaJsonOpsHandler;

impl KafkaJsonOpsHandler {
    pub fn new() -> Self {
        Self
    }
}

impl KafkaMessageHandler<EnrichmentOperation> for KafkaJsonOpsHandler {
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<EnrichmentOperation>, InputProcessingError> {
        let operation: EnrichmentOperation =
            serde_json::from_slice(payload).map_err(|e| InputProcessingError::JsonError {
                context: format!("KafkaJsonOpsHandler (partition: {partition}, offset: {offset})"),
                reason: e.to_string(),
            })?;

        if !operation.validate() {
            return Ok(vec![]); // drop useless no-field op
        }

        Ok(vec![operation])
    }
}

/// **Kafka Sonata Handler**
///
/// Handler for Kafka messages with JSON [`SonataData`] format
/// (Swisscom custom inventory update messages), such as:
///
/// ```json
/// {
///  "operation": "insert",
///  "id_node": 13244,
///  "node": {
///    "hostname": "HOSTNAME",
///    "loopbackAddress": "192.168.100.6",
///    "platform": {
///      "name": "PLATFORM-NAME",
///    }
///  }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct KafkaSonataHandler {
    config: SonataConfig,

    // sonata id_node -> loopbackAddress mapping
    id_cache: HashMap<u32, IpAddr>,
}

impl KafkaSonataHandler {
    pub fn new(config: SonataConfig) -> Self {
        Self {
            config,
            id_cache: HashMap::new(),
        }
    }
    pub fn config(&self) -> &SonataConfig {
        &self.config
    }
    pub fn id_cache(&self) -> &HashMap<u32, IpAddr> {
        &self.id_cache
    }
    pub fn id_cache_mut(&mut self) -> &mut HashMap<u32, IpAddr> {
        &mut self.id_cache
    }
}

impl KafkaMessageHandler<EnrichmentOperation> for KafkaSonataHandler {
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<EnrichmentOperation>, InputProcessingError> {
        let sonata_data: SonataData =
            serde_json::from_slice(payload).map_err(|e| InputProcessingError::JsonError {
                context: format!("KafkaSonataHandler (partition: {partition}, offset: {offset})"),
                reason: e.to_string(),
            })?;
        let mut operations = Vec::new();

        match sonata_data.operation {
            SonataOperation::Insert | SonataOperation::Update => {
                if let Some(node) = sonata_data.node {
                    let loopback = node.loopback_address;
                    let sonata_id_node = sonata_data.id_node;

                    // Check if we have a cached entry for this node_id
                    if let Some(&old_loopback) = self.id_cache().get(&sonata_id_node) {
                        if loopback != old_loopback {
                            operations.push(EnrichmentOperation::Delete(DeletePayload {
                                ip: old_loopback,
                                scope: Scope::new(0, None),
                                weight: self.config().weight,
                                ies: vec![
                                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
                                ],
                            }));
                        }
                    }

                    // Update cache with new loopback address
                    self.id_cache_mut().insert(sonata_id_node, loopback);

                    // Create Upsert Operation
                    let node_id = Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                        node.hostname.into(),
                    ));
                    let platform_id =
                        Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                            node.platform.name.into(),
                        ));

                    operations.push(EnrichmentOperation::Upsert(UpsertPayload {
                        ip: node.loopback_address,
                        scope: Scope::new(0, None),
                        weight: self.config().weight,
                        fields: vec![node_id, platform_id],
                    }));
                } else {
                    return Err(InputProcessingError::ConversionError {
                        context: format!(
                            "KafkaSonataHandler (partition: {partition}, offset: {offset})"
                        ),
                        reason: format!(
                            "Insert/Update operation missing node data for id_node: {} ",
                            sonata_data.id_node
                        ),
                    });
                }
            }
            SonataOperation::Delete => {
                if let Some(cached_loopback) = self.id_cache_mut().remove(&sonata_data.id_node) {
                    operations.push(EnrichmentOperation::Delete(DeletePayload {
                        ip: cached_loopback,
                        scope: Scope::new(0, None),
                        weight: self.config().weight,
                        ies: vec![
                            IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                            IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
                        ],
                    }));
                }
            }
        };

        Ok(operations
            .into_iter()
            .filter(|op| op.validate()) // drop useless no-field ops
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        flow::enrichment::{DeletePayload, EnrichmentOperation, Scope, UpsertPayload},
        inputs::{
            kafka::{
                handlers::{KafkaMessageHandler, KafkaSonataHandler},
                SonataConfig,
            },
            InputProcessingError,
        },
    };

    #[test]
    fn test_sonata_handler_insert() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;

        let operations = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![EnrichmentOperation::Upsert(UpsertPayload {
            ip: "10.0.0.1".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 10,
            fields: vec![
                Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                    "test-node".into(),
                )),
                Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                    "test-platform".into(),
                )),
            ],
        })];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_update_with_ip_change() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        // First insert
        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        // Update with different IP
        let update_json = r#"{"operation": "update", "id_node": 123, "node": {"hostname": "updated-node", "loopbackAddress": "10.0.0.2", "platform": {"name": "updated-platform"}}}"#;
        let operations = handler
            .handle_message(update_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![
            // Delete old entry
            EnrichmentOperation::Delete(DeletePayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 10,
                ies: vec![
                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
                ],
            }),
            // Insert new entry
            EnrichmentOperation::Upsert(UpsertPayload {
                ip: "10.0.0.2".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 10,
                fields: vec![
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                        "updated-node".into(),
                    )),
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                        "updated-platform".into(),
                    )),
                ],
            }),
        ];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_update_same_ip() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        // First insert
        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        // Update with same IP but different data
        let update_json = r#"{"operation": "update", "id_node": 123, "node": {"hostname": "updated-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "updated-platform"}}}"#;
        let operations = handler
            .handle_message(update_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![
            // Only upsert, no delete since IP is the same
            EnrichmentOperation::Upsert(UpsertPayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 10,
                fields: vec![
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                        "updated-node".into(),
                    )),
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                        "updated-platform".into(),
                    )),
                ],
            }),
        ];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_delete() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        // First insert to have something to delete
        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        // Delete
        let delete_json = r#"{"operation": "delete", "id_node": 123, "node": null}"#;
        let operations = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![EnrichmentOperation::Delete(DeletePayload {
            ip: "10.0.0.1".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 10,
            ies: vec![
                IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
            ],
        })];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_delete_nonexistent() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        // Delete without inserting first
        let delete_json = r#"{"operation": "delete", "id_node": 123, "node": null}"#;
        let operations = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations: Vec<EnrichmentOperation> = vec![];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_invalid_insert() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        let invalid_json = r#"{"operation": "insert", "id_node": 123, "node": null}"#;

        let result = handler.handle_message(invalid_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        let expected_error = InputProcessingError::ConversionError {
            context: "KafkaSonataHandler (partition: 0, offset: 0)".to_string(),
            reason: "Insert/Update operation missing node data for id_node: 123 ".to_string(),
        };

        assert_eq!(result.unwrap_err().to_string(), expected_error.to_string());
    }

    #[test]
    fn test_sonata_handler_invalid_update() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        let invalid_json = r#"{"operation": "update", "id_node": 456, "node": null}"#;

        let result = handler.handle_message(invalid_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        let expected_error = InputProcessingError::ConversionError {
            context: "KafkaSonataHandler (partition: 0, offset: 0)".to_string(),
            reason: "Insert/Update operation missing node data for id_node: 456 ".to_string(),
        };

        assert_eq!(result.unwrap_err().to_string(), expected_error.to_string());
    }

    #[test]
    fn test_sonata_handler_malformed_json() {
        let config = SonataConfig { weight: 10 };
        let mut handler = KafkaSonataHandler::new(config);

        let malformed_json = r#"{"operation": "insert", "id_node": "not_a_number"}"#;

        let result = handler.handle_message(malformed_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        match result.unwrap_err() {
            InputProcessingError::JsonError { context, reason: _ } => {
                assert!(context.contains("KafkaSonataHandler (partition: 0, offset: 0"));
            }
            _ => panic!("Expected JsonError"),
        }
    }
}
