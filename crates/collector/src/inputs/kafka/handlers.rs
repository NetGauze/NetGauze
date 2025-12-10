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
use crate::inputs::{
    InputProcessingError,
    kafka::{
        SonataConfig,
        formats::sonata::{SonataData, SonataOperation},
    },
};
use netgauze_flow_pkt::ie::{Field, IE};
use std::{collections::HashMap, net::IpAddr};

/// **Generic Kafka Message Handler Trait**
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

/// **Flow Enrichment Operation Handler**
///
/// Handler for Kafka messages with JSON
/// [`crate::flow::enrichment::EnrichmentOperation`] format, such as:
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
pub struct FlowEnrichmentOperationHandler;

impl FlowEnrichmentOperationHandler {
    pub fn new() -> Self {
        Self
    }
}

impl KafkaMessageHandler<crate::flow::enrichment::EnrichmentOperation>
    for FlowEnrichmentOperationHandler
{
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<crate::flow::enrichment::EnrichmentOperation>, InputProcessingError> {
        let operation: crate::flow::enrichment::EnrichmentOperation =
            serde_json::from_slice(payload).map_err(|e| InputProcessingError::JsonError {
                context: format!(
                    "FlowEnrichmentOperationHandler (partition: {partition}, offset: {offset})"
                ),
                reason: e.to_string(),
            })?;

        if !operation.validate() {
            return Ok(vec![]); // drop useless no-field op
        }

        Ok(vec![operation])
    }
}

impl KafkaMessageHandler<crate::yang_push::EnrichmentOperation> for FlowEnrichmentOperationHandler {
    fn handle_message(
        &mut self,
        _payload: &[u8],
        _partition: i32,
        _offset: i64,
    ) -> Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> {
        Err(InputProcessingError::UnsupportedOperation {
            handler: "FlowEnrichmentOperationHandler".to_string(),
            reason: "This handler only supports flow::enrichment::EnrichmentOperation".to_string(),
        })
    }
}

/// **YANG-Push Enrichment Operation Handler**
///
/// Handler for Kafka messages with JSON
/// [`crate::yang_push::EnrichmentOperation`] format, such as:
///
/// ```json
/// {
///   "Upsert": {
///     "ip": "192.168.100.6",
///     "weight": 205,
///     "labels": [
///       {
///         "name": "node_id",
///         "string_value": "node-123"
///       }
///     ]
///   }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct YangPushEnrichmentOperationHandler;

impl YangPushEnrichmentOperationHandler {
    pub fn new() -> Self {
        Self
    }
}

impl KafkaMessageHandler<crate::yang_push::EnrichmentOperation>
    for YangPushEnrichmentOperationHandler
{
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> {
        let operation: crate::yang_push::EnrichmentOperation = serde_json::from_slice(payload)
            .map_err(|e| InputProcessingError::JsonError {
                context: format!(
                    "YangPushEnrichmentOperationHandler (partition: {partition}, offset: {offset})"
                ),
                reason: e.to_string(),
            })?;

        if !operation.validate() {
            return Ok(vec![]); // drop useless no-field op
        }

        Ok(vec![operation])
    }
}

impl KafkaMessageHandler<crate::flow::enrichment::EnrichmentOperation>
    for YangPushEnrichmentOperationHandler
{
    fn handle_message(
        &mut self,
        _payload: &[u8],
        _partition: i32,
        _offset: i64,
    ) -> Result<Vec<crate::flow::enrichment::EnrichmentOperation>, InputProcessingError> {
        Err(InputProcessingError::UnsupportedOperation {
            handler: "YangPushEnrichmentOperationHandler".to_string(),
            reason: "This handler only supports yang_push::EnrichmentOperation".to_string(),
        })
    }
}

/// **Sonata Handler**
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
pub struct SonataHandler {
    config: SonataConfig,

    // sonata id_node -> loopbackAddress mapping
    id_cache: HashMap<u32, IpAddr>,
}

impl SonataHandler {
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

impl KafkaMessageHandler<crate::flow::enrichment::EnrichmentOperation> for SonataHandler {
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<crate::flow::enrichment::EnrichmentOperation>, InputProcessingError> {
        let sonata_data: SonataData =
            serde_json::from_slice(payload).map_err(|e| InputProcessingError::JsonError {
                context: format!("SonataHandler (partition: {partition}, offset: {offset})"),
                reason: e.to_string(),
            })?;
        let mut operations = Vec::new();

        match sonata_data.operation {
            SonataOperation::Insert | SonataOperation::Update => {
                if let Some(node) = sonata_data.node {
                    let loopback = node.loopback_address;
                    let sonata_id_node = sonata_data.id_node;

                    // Check if we have a cached entry for this node_id
                    if let Some(&old_loopback) = self.id_cache().get(&sonata_id_node)
                        && loopback != old_loopback
                    {
                        operations.push(crate::flow::enrichment::EnrichmentOperation::Delete(
                            crate::flow::enrichment::DeletePayload {
                                ip: old_loopback,
                                scope: crate::flow::enrichment::Scope::new(0, None),
                                weight: self.config().weight,
                                ies: vec![
                                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
                                ],
                            },
                        ));
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

                    operations.push(crate::flow::enrichment::EnrichmentOperation::Upsert(
                        crate::flow::enrichment::UpsertPayload {
                            ip: node.loopback_address,
                            scope: crate::flow::enrichment::Scope::new(0, None),
                            weight: self.config().weight,
                            fields: vec![node_id, platform_id],
                        },
                    ));
                } else {
                    return Err(InputProcessingError::ConversionError {
                        context: format!(
                            "SonataHandler (partition: {partition}, offset: {offset})"
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
                    operations.push(crate::flow::enrichment::EnrichmentOperation::Delete(
                        crate::flow::enrichment::DeletePayload {
                            ip: cached_loopback,
                            scope: crate::flow::enrichment::Scope::new(0, None),
                            weight: self.config().weight,
                            ies: vec![
                                IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                                IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
                            ],
                        },
                    ));
                }
            }
        };

        Ok(operations
            .into_iter()
            .filter(|op| op.validate()) // drop useless no-field ops
            .collect())
    }
}

impl KafkaMessageHandler<crate::yang_push::EnrichmentOperation> for SonataHandler {
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> {
        let sonata_data: SonataData =
            serde_json::from_slice(payload).map_err(|e| InputProcessingError::JsonError {
                context: format!("SonataHandler (partition: {partition}, offset: {offset})"),
                reason: e.to_string(),
            })?;
        let mut operations = Vec::new();

        match sonata_data.operation {
            SonataOperation::Insert | SonataOperation::Update => {
                if let Some(node) = sonata_data.node {
                    let loopback = node.loopback_address;
                    let sonata_id_node = sonata_data.id_node;

                    // Check if we have a cached entry for this node_id
                    if let Some(&old_loopback) = self.id_cache().get(&sonata_id_node)
                        && loopback != old_loopback
                    {
                        operations.push(crate::yang_push::EnrichmentOperation::Delete(
                            crate::yang_push::DeletePayload {
                                ip: old_loopback,
                                weight: self.config().weight,
                                label_names: vec!["node_id".to_string(), "platform_id".to_string()],
                            },
                        ));
                    }

                    // Update cache with new loopback address
                    self.id_cache_mut().insert(sonata_id_node, loopback);

                    // Create Upsert Operation with labels
                    let node_id_label = netgauze_yang_push::model::telemetry::Label::new(
                        "node_id".to_string(),
                        netgauze_yang_push::model::telemetry::LabelValue::StringValue {
                            string_value: node.hostname,
                        },
                    );
                    let platform_id_label = netgauze_yang_push::model::telemetry::Label::new(
                        "platform_id".to_string(),
                        netgauze_yang_push::model::telemetry::LabelValue::StringValue {
                            string_value: node.platform.name,
                        },
                    );

                    operations.push(crate::yang_push::EnrichmentOperation::Upsert(
                        crate::yang_push::UpsertPayload {
                            ip: node.loopback_address,
                            weight: self.config().weight,
                            labels: vec![node_id_label, platform_id_label],
                        },
                    ));
                } else {
                    return Err(InputProcessingError::ConversionError {
                        context: format!(
                            "SonataHandler (partition: {partition}, offset: {offset})"
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
                    operations.push(crate::yang_push::EnrichmentOperation::Delete(
                        crate::yang_push::DeletePayload {
                            ip: cached_loopback,
                            weight: self.config().weight,
                            label_names: vec!["node_id".to_string(), "platform_id".to_string()],
                        },
                    ));
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
    use crate::inputs::{
        InputProcessingError,
        kafka::{
            SonataConfig,
            handlers::{KafkaMessageHandler, SonataHandler},
        },
    };
    use netgauze_yang_push::model::telemetry::{Label, LabelValue};

    // ** Tests with crate::flow::enrichment::EnrichmentOperation for Flow ** //

    #[test]
    fn test_sonata_handler_insert() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;

        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::flow::enrichment::EnrichmentOperation::Upsert(
            crate::flow::enrichment::UpsertPayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: crate::flow::enrichment::Scope::new(0, None),
                weight: 10,
                fields: vec![
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                        "test-node".into(),
                    )),
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                        "test-platform".into(),
                    )),
                ],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_update_with_ip_change() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        // First insert
        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        let _: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        // Update with different IP
        let update_json = r#"{"operation": "update", "id_node": 123, "node": {"hostname": "updated-node", "loopbackAddress": "10.0.0.2", "platform": {"name": "updated-platform"}}}"#;
        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(update_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![
            // Delete old entry
            crate::flow::enrichment::EnrichmentOperation::Delete(
                crate::flow::enrichment::DeletePayload {
                    ip: "10.0.0.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(0, None),
                    weight: 10,
                    ies: vec![
                        IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                        IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
                    ],
                },
            ),
            // Insert new entry
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "10.0.0.2".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(0, None),
                    weight: 10,
                    fields: vec![
                        Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                            "updated-node".into(),
                        )),
                        Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                            "updated-platform".into(),
                        )),
                    ],
                },
            ),
        ];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_update_same_ip() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        // First insert
        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        let _: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        // Update with same IP but different data
        let update_json = r#"{"operation": "update", "id_node": 123, "node": {"hostname": "updated-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "updated-platform"}}}"#;
        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(update_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![
            // Only upsert, no delete since IP is the same
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "10.0.0.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(0, None),
                    weight: 10,
                    fields: vec![
                        Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                            "updated-node".into(),
                        )),
                        Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                            "updated-platform".into(),
                        )),
                    ],
                },
            ),
        ];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_delete() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        // First insert to have something to delete
        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        let _: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        // Delete
        let delete_json = r#"{"operation": "delete", "id_node": 123, "node": null}"#;
        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::flow::enrichment::EnrichmentOperation::Delete(
            crate::flow::enrichment::DeletePayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: crate::flow::enrichment::Scope::new(0, None),
                weight: 10,
                ies: vec![
                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId),
                    IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::platformId),
                ],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_delete_nonexistent() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        // Delete without inserting first
        let delete_json = r#"{"operation": "delete", "id_node": 123, "node": null}"#;
        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations: Vec<crate::flow::enrichment::EnrichmentOperation> = vec![];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_invalid_insert() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let invalid_json = r#"{"operation": "insert", "id_node": 123, "node": null}"#;

        let result: Result<
            Vec<crate::flow::enrichment::EnrichmentOperation>,
            InputProcessingError,
        > = handler.handle_message(invalid_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        let expected_error = InputProcessingError::ConversionError {
            context: "SonataHandler (partition: 0, offset: 0)".to_string(),
            reason: "Insert/Update operation missing node data for id_node: 123 ".to_string(),
        };

        assert_eq!(result.unwrap_err().to_string(), expected_error.to_string());
    }

    #[test]
    fn test_sonata_handler_invalid_update() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let invalid_json = r#"{"operation": "update", "id_node": 456, "node": null}"#;

        let result: Result<
            Vec<crate::flow::enrichment::EnrichmentOperation>,
            InputProcessingError,
        > = handler.handle_message(invalid_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        let expected_error = InputProcessingError::ConversionError {
            context: "SonataHandler (partition: 0, offset: 0)".to_string(),
            reason: "Insert/Update operation missing node data for id_node: 456 ".to_string(),
        };

        assert_eq!(result.unwrap_err().to_string(), expected_error.to_string());
    }

    #[test]
    fn test_sonata_handler_malformed_json() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let malformed_json = r#"{"operation": "insert", "id_node": "not_a_number"}"#;

        let result: Result<
            Vec<crate::flow::enrichment::EnrichmentOperation>,
            InputProcessingError,
        > = handler.handle_message(malformed_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        match result.unwrap_err() {
            InputProcessingError::JsonError { context, reason: _ } => {
                assert!(context.contains("SonataHandler (partition: 0, offset: 0"));
            }
            _ => panic!("Expected JsonError"),
        }
    }

    #[test]
    fn test_flow_enrichment_handler_valid_upsert() {
        let mut handler = FlowEnrichmentOperationHandler::new();

        let upsert_json = r#"{"Upsert":{"ip":"10.0.0.1","scope":{"obs_domain_id":100,"scope_fields":[{"selectorId":27}]},"weight":50,"fields":[{"applicationName":"test-app"}]}}"#;

        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(upsert_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::flow::enrichment::EnrichmentOperation::Upsert(
            crate::flow::enrichment::UpsertPayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: crate::flow::enrichment::Scope::new(100, Some(vec![Field::selectorId(27)])),
                weight: 50,
                fields: vec![Field::applicationName("test-app".into())],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_flow_enrichment_handler_valid_delete() {
        let mut handler = FlowEnrichmentOperationHandler::new();

        let delete_json = r#"{"Delete":{"ip":"10.0.0.1","scope":{"obs_domain_id":100,"scope_fields":null},"weight":50,"ies":[{"NetGauze":"nodeId"}]}}"#;

        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::flow::enrichment::EnrichmentOperation::Delete(
            crate::flow::enrichment::DeletePayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: crate::flow::enrichment::Scope::new(100, None),
                weight: 50,
                ies: vec![IE::NetGauze(netgauze_flow_pkt::ie::netgauze::IE::nodeId)],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_flow_enrichment_handler_empty_fields() {
        let mut handler = FlowEnrichmentOperationHandler::new();

        let empty_json = r#"{"Upsert":{"ip":"10.0.0.1","scope":{"obs_domain_id":100,"scope_fields":null},"weight":50,"fields":[]}}"#;

        let operations: Vec<crate::flow::enrichment::EnrichmentOperation> =
            handler.handle_message(empty_json.as_bytes(), 0, 0).unwrap();

        let expected_operations: Vec<crate::flow::enrichment::EnrichmentOperation> = vec![];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_flow_enrichment_handler_invalid_json() {
        let mut handler = FlowEnrichmentOperationHandler::new();

        let invalid_json = r#"{"Invalid":"operation"}"#;

        let result: Result<
            Vec<crate::flow::enrichment::EnrichmentOperation>,
            InputProcessingError,
        > = handler.handle_message(invalid_json.as_bytes(), 0, 0);

        assert!(result.is_err());
        match result.unwrap_err() {
            InputProcessingError::JsonError { context, reason: _ } => {
                assert!(context.contains("FlowEnrichmentOperationHandler"));
            }
            _ => panic!("Expected JsonError"),
        }
    }

    #[test]
    fn test_flow_enrichment_handler_unsupported_yang_push() {
        let mut handler = FlowEnrichmentOperationHandler::new();

        let result: Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> =
            handler.handle_message(b"", 0, 0);

        assert!(result.is_err());
        match result.unwrap_err() {
            InputProcessingError::UnsupportedOperation { handler, reason } => {
                assert_eq!(handler, "FlowEnrichmentOperationHandler");
                assert!(reason.contains("flow::enrichment::EnrichmentOperation"));
            }
            _ => panic!("Expected UnsupportedOperation"),
        }
    }

    // ** Tests with crate::yang_push::EnrichmentOperation for YANG-Push ** //

    #[test]
    fn test_yang_push_handler_valid_upsert() {
        let mut handler = YangPushEnrichmentOperationHandler::new();

        let upsert_json = r#"{"Upsert":{"ip":"10.0.0.1","weight":50,"labels":[{"name":"node_id","string-value":"test-node"}]}}"#;

        let operations: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(upsert_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::yang_push::EnrichmentOperation::Upsert(
            crate::yang_push::UpsertPayload {
                ip: "10.0.0.1".parse().unwrap(),
                weight: 50,
                labels: vec![Label::new(
                    "node_id".to_string(),
                    LabelValue::StringValue {
                        string_value: "test-node".to_string(),
                    },
                )],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_yang_push_handler_valid_delete() {
        let mut handler = YangPushEnrichmentOperationHandler::new();

        let delete_json =
            r#"{"Delete":{"ip":"10.0.0.1","weight":50,"label_names":["node_id","platform_id"]}}"#;

        let operations: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::yang_push::EnrichmentOperation::Delete(
            crate::yang_push::DeletePayload {
                ip: "10.0.0.1".parse().unwrap(),
                weight: 50,
                label_names: vec!["node_id".to_string(), "platform_id".to_string()],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_yang_push_handler_empty_labels() {
        let mut handler = YangPushEnrichmentOperationHandler::new();

        let empty_json = r#"{"Upsert":{"ip":"10.0.0.1","weight":50,"labels":[]}}"#;

        let operations: Vec<crate::yang_push::EnrichmentOperation> =
            handler.handle_message(empty_json.as_bytes(), 0, 0).unwrap();

        let expected_operations: Vec<crate::yang_push::EnrichmentOperation> = vec![];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_yang_push_handler_invalid_json() {
        let mut handler = YangPushEnrichmentOperationHandler::new();

        let invalid_json = r#"{"Invalid":"operation"}"#;

        let result: Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> =
            handler.handle_message(invalid_json.as_bytes(), 0, 0);

        assert!(result.is_err());
        match result.unwrap_err() {
            InputProcessingError::JsonError { context, reason: _ } => {
                assert!(context.contains("YangPushEnrichmentOperationHandler"));
            }
            _ => panic!("Expected JsonError"),
        }
    }

    #[test]
    fn test_yang_push_handler_unsupported_flow() {
        let mut handler = YangPushEnrichmentOperationHandler::new();

        let result: Result<
            Vec<crate::flow::enrichment::EnrichmentOperation>,
            InputProcessingError,
        > = handler.handle_message(b"", 0, 0);

        assert!(result.is_err());
        match result.unwrap_err() {
            InputProcessingError::UnsupportedOperation { handler, reason } => {
                assert_eq!(handler, "YangPushEnrichmentOperationHandler");
                assert!(reason.contains("yang_push::EnrichmentOperation"));
            }
            _ => panic!("Expected UnsupportedOperation"),
        }
    }

    #[test]
    fn test_sonata_handler_yang_push_insert() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;

        let operations: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::yang_push::EnrichmentOperation::Upsert(
            crate::yang_push::UpsertPayload {
                ip: "10.0.0.1".parse().unwrap(),
                weight: 10,
                labels: vec![
                    Label::new(
                        "node_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "test-node".to_string(),
                        },
                    ),
                    Label::new(
                        "platform_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "test-platform".to_string(),
                        },
                    ),
                ],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_yang_push_update_with_ip_change() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        let _: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        let update_json = r#"{"operation": "update", "id_node": 123, "node": {"hostname": "updated-node", "loopbackAddress": "10.0.0.2", "platform": {"name": "updated-platform"}}}"#;
        let operations: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(update_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![
            crate::yang_push::EnrichmentOperation::Delete(crate::yang_push::DeletePayload {
                ip: "10.0.0.1".parse().unwrap(),
                weight: 10,
                label_names: vec!["node_id".to_string(), "platform_id".to_string()],
            }),
            crate::yang_push::EnrichmentOperation::Upsert(crate::yang_push::UpsertPayload {
                ip: "10.0.0.2".parse().unwrap(),
                weight: 10,
                labels: vec![
                    Label::new(
                        "node_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "updated-node".to_string(),
                        },
                    ),
                    Label::new(
                        "platform_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "updated-platform".to_string(),
                        },
                    ),
                ],
            }),
        ];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_yang_push_update_same_ip() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        let _: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        let update_json = r#"{"operation": "update", "id_node": 123, "node": {"hostname": "updated-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "updated-platform"}}}"#;
        let operations: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(update_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::yang_push::EnrichmentOperation::Upsert(
            crate::yang_push::UpsertPayload {
                ip: "10.0.0.1".parse().unwrap(),
                weight: 10,
                labels: vec![
                    Label::new(
                        "node_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "updated-node".to_string(),
                        },
                    ),
                    Label::new(
                        "platform_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "updated-platform".to_string(),
                        },
                    ),
                ],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_yang_push_delete() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;
        let _: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        let delete_json = r#"{"operation": "delete", "id_node": 123, "node": null}"#;
        let operations: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![crate::yang_push::EnrichmentOperation::Delete(
            crate::yang_push::DeletePayload {
                ip: "10.0.0.1".parse().unwrap(),
                weight: 10,
                label_names: vec!["node_id".to_string(), "platform_id".to_string()],
            },
        )];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_yang_push_delete_nonexistent() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let delete_json = r#"{"operation": "delete", "id_node": 123, "node": null}"#;
        let operations: Vec<crate::yang_push::EnrichmentOperation> = handler
            .handle_message(delete_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations: Vec<crate::yang_push::EnrichmentOperation> = vec![];

        assert_eq!(operations, expected_operations);
    }
}
