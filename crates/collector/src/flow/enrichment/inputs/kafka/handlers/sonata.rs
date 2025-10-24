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
use crate::flow::enrichment::{
    inputs::kafka::{MessageHandler, SonataConfig},
    EnrichmentOperation, EnrichmentPayload, Scope,
};
use netgauze_flow_pkt::ie::Field;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};

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

#[derive(Debug, Clone)]
pub enum SonataHandlerError {
    /// JSON deserialization failed
    JsonDeserializationError(String),

    /// Operation is semantically invalid (e.g., Insert/Update without node
    /// data)
    InvalidOperation(String),
}

impl std::fmt::Display for SonataHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonDeserializationError(msg) => write!(f, "JSON deserialization error: {msg}"),
            Self::InvalidOperation(msg) => write!(f, "Invalid operation: {msg}"),
        }
    }
}

impl std::error::Error for SonataHandlerError {}

impl From<serde_json::Error> for SonataHandlerError {
    fn from(err: serde_json::Error) -> Self {
        SonataHandlerError::JsonDeserializationError(err.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct SonataHandler {
    config: SonataConfig,

    // sonata id_node -> loopback mapping
    id_cache: HashMap<u32, IpAddr>,
}

impl SonataHandler {
    pub fn new(config: SonataConfig) -> Self {
        Self {
            config,
            id_cache: HashMap::new(),
        }
    }
}

impl MessageHandler for SonataHandler {
    type Error = SonataHandlerError;

    fn handle_message(
        &mut self,
        payload: &[u8],
        _partition: i32,
        _offset: i64,
    ) -> Result<Vec<EnrichmentOperation>, Self::Error> {
        let sonata_data: SonataData = serde_json::from_slice(payload)?;
        let mut operations = Vec::new();

        match sonata_data.operation {
            SonataOperation::Insert | SonataOperation::Update => {
                if let Some(node) = sonata_data.node {
                    let loopback = node.loopback_address;
                    let sonata_id_node = sonata_data.id_node;

                    // Check if we have a cached entry for this node_id
                    if let Some(&old_loopback) = self.id_cache.get(&sonata_id_node) {
                        if loopback != old_loopback {
                            operations.push(EnrichmentOperation::Delete(EnrichmentPayload {
                                ip: old_loopback,
                                scope: Scope {
                                    obs_domain_id: 0,
                                    scope_fields: None,
                                },
                                weight: self.config.weight,
                                fields: Some(vec![
                                    Field::NetGauze(
                                        netgauze_flow_pkt::ie::netgauze::Field::nodeId("".into()),
                                    ),
                                    Field::NetGauze(
                                        netgauze_flow_pkt::ie::netgauze::Field::platformId(
                                            "".into(),
                                        ),
                                    ),
                                ]),
                            }));
                        }
                    }

                    // Update cache with new loopback address
                    self.id_cache.insert(sonata_id_node, loopback);

                    // Create Upsert Operation
                    let node_id = Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                        node.hostname.into(),
                    ));
                    let platform_id =
                        Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                            node.platform.name.into(),
                        ));

                    operations.push(EnrichmentOperation::Upsert(EnrichmentPayload {
                        ip: node.loopback_address,
                        scope: Scope::new(0, None),
                        weight: self.config.weight,
                        fields: Some(vec![node_id, platform_id]),
                    }));
                } else {
                    return Err(SonataHandlerError::InvalidOperation(format!(
                        "Insert/Update operation missing node data for id_node: {}",
                        sonata_data.id_node
                    )));
                }
            }
            SonataOperation::Delete => {
                if let Some(cached_loopback) = self.id_cache.remove(&sonata_data.id_node) {
                    operations.push(EnrichmentOperation::Delete(EnrichmentPayload {
                        ip: cached_loopback,
                        scope: Scope {
                            obs_domain_id: 0,
                            scope_fields: None,
                        },
                        weight: self.config.weight,
                        fields: Some(vec![
                            Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                                "".into(),
                            )),
                            Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                                "".into(),
                            )),
                        ]),
                    }));
                }
            }
        };

        Ok(operations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_sonata_json_serialization() {
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

    #[test]
    fn test_sonata_handler_insert() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let insert_json = r#"{"operation": "insert", "id_node": 123, "node": {"hostname": "test-node", "loopbackAddress": "10.0.0.1", "platform": {"name": "test-platform"}}}"#;

        let operations = handler
            .handle_message(insert_json.as_bytes(), 0, 0)
            .unwrap();

        let expected_operations = vec![EnrichmentOperation::Upsert(EnrichmentPayload {
            ip: "10.0.0.1".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 10,
            fields: Some(vec![
                Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                    "test-node".into(),
                )),
                Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                    "test-platform".into(),
                )),
            ]),
        })];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_update_with_ip_change() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

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
            EnrichmentOperation::Delete(EnrichmentPayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 10,
                fields: Some(vec![
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId("".into())),
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                        "".into(),
                    )),
                ]),
            }),
            // Insert new entry
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "10.0.0.2".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 10,
                fields: Some(vec![
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                        "updated-node".into(),
                    )),
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                        "updated-platform".into(),
                    )),
                ]),
            }),
        ];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_update_same_ip() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

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
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "10.0.0.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 10,
                fields: Some(vec![
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId(
                        "updated-node".into(),
                    )),
                    Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                        "updated-platform".into(),
                    )),
                ]),
            }),
        ];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_delete() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

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

        let expected_operations = vec![EnrichmentOperation::Delete(EnrichmentPayload {
            ip: "10.0.0.1".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 10,
            fields: Some(vec![
                Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::nodeId("".into())),
                Field::NetGauze(netgauze_flow_pkt::ie::netgauze::Field::platformId(
                    "".into(),
                )),
            ]),
        })];

        assert_eq!(operations, expected_operations);
    }

    #[test]
    fn test_sonata_handler_delete_nonexistent() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

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
        let mut handler = SonataHandler::new(config);

        let invalid_json = r#"{"operation": "insert", "id_node": 123, "node": null}"#;

        let result = handler.handle_message(invalid_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        match result.unwrap_err() {
            SonataHandlerError::InvalidOperation(msg) => {
                assert!(msg.contains("Insert/Update operation missing node data"));
                assert!(msg.contains("123"));
            }
            _ => panic!("Expected InvalidOperation error"),
        }
    }

    #[test]
    fn test_sonata_handler_invalid_update() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let invalid_json = r#"{"operation": "update", "id_node": 456, "node": null}"#;

        let result = handler.handle_message(invalid_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        match result.unwrap_err() {
            SonataHandlerError::InvalidOperation(msg) => {
                assert!(msg.contains("Insert/Update operation missing node data"));
                assert!(msg.contains("456"));
            }
            _ => panic!("Expected InvalidOperation error"),
        }
    }

    #[test]
    fn test_sonata_handler_malformed_json() {
        let config = SonataConfig { weight: 10 };
        let mut handler = SonataHandler::new(config);

        let malformed_json = r#"{"operation": "insert", "id_node": "not_a_number"}"#;

        let result = handler.handle_message(malformed_json.as_bytes(), 0, 0);
        assert!(result.is_err());

        match result.unwrap_err() {
            SonataHandlerError::JsonDeserializationError(_) => {}
            _ => panic!("Expected JsonDeserializationError"),
        }
    }
}
