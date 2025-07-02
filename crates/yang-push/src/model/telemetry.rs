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

//! # Telemetry Message Module
//!
//! This module defines the structure and serialization logic for telemetry
//! messages as specified in:
//! - [Telemetry Message](https://datatracker.ietf.org/doc/html/draft-netana-nmop-message-broker-telemetry-message).
//!
//! Key components include:
//!
//! - **TelemetryMessage**: The main structure representing a telemetry message.
//!
//! - **TelemetryMessageWrapper**: A wrapper for the telemetry message needed
//!   for including the module namespace.
//!
//! - **Manifest**: Common metadata structure for both network nodes and data
//!   collection systems, including information such as name, vendor, software
//!   version, etc.
//!
//! - **TelemetryMessageMetadata**: Metadata about the telemetry session between
//!   collector and network node, including timestamps, protocol information,
//!   and addressing details.
//!
//! - **YangPushSubscriptionMetadata**: YANG-Push specific extension for
//!   subscription details when the session protocol is YANG Push.
//!
//! - **NetworkOperatorMetadata**: Operator-specific metadata implemented as
//!   key-value labels that can be used to enrich collected data with custom
//!   information.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

use crate::model::notification::{
    CentiSeconds, ChangeType, Encoding, SubscriptionId, Transport, YangPushModuleVersion,
};

/// Telemetry Message Wrapper
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TelemetryMessageWrapper {
    #[serde(rename = "ietf-telemetry-message:message")]
    message: TelemetryMessage,
}

impl TelemetryMessageWrapper {
    pub fn new(message: TelemetryMessage) -> Self {
        Self { message }
    }
    pub fn message(&self) -> &TelemetryMessage {
        &self.message
    }
}

/// Telemetry Message
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct TelemetryMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    network_node_manifest: Option<Manifest>,

    telemetry_message_metadata: TelemetryMessageMetadata,

    #[serde(skip_serializing_if = "Option::is_none")]
    data_collection_manifest: Option<Manifest>,

    network_operator_metadata: NetworkOperatorMetadata,

    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
}

impl TelemetryMessage {
    pub fn new(
        network_node_manifest: Option<Manifest>,
        telemetry_message_metadata: TelemetryMessageMetadata,
        data_collection_manifest: Option<Manifest>,
        network_operator_metadata: NetworkOperatorMetadata,
        payload: Option<Value>,
    ) -> Self {
        Self {
            network_node_manifest,
            telemetry_message_metadata,
            data_collection_manifest,
            network_operator_metadata,
            payload,
        }
    }
    pub fn network_node_manifest(&self) -> Option<&Manifest> {
        self.network_node_manifest.as_ref()
    }
    pub fn data_collection_manifest(&self) -> Option<&Manifest> {
        self.data_collection_manifest.as_ref()
    }
    pub fn telemetry_message_metadata(&self) -> &TelemetryMessageMetadata {
        &self.telemetry_message_metadata
    }
    pub fn network_operator_metadata(&self) -> &NetworkOperatorMetadata {
        &self.network_operator_metadata
    }
    pub fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }
}

/// Telemetry Session Protocol Type
#[derive(Default, Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum SessionProtocol {
    #[serde(rename = "yp-push")]
    YangPush,

    #[serde(rename = "netconf")]
    Netconf,

    #[serde(rename = "restconf")]
    Restconf,

    #[default]
    #[serde(other)]
    #[serde(rename = "unknown")]
    Unknown,
}

/// Generic Metadata Manifest
#[derive(Default, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Manifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    vendor_pen: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    software_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    software_flavor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    os_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    os_type: Option<String>,
}

impl Manifest {
    pub fn new(
        name: Option<String>,
        vendor: Option<String>,
        vendor_pen: Option<u32>,
        software_version: Option<String>,
        software_flavor: Option<String>,
        os_version: Option<String>,
        os_type: Option<String>,
    ) -> Self {
        Self {
            name,
            vendor,
            vendor_pen,
            software_version,
            software_flavor,
            os_version,
            os_type,
        }
    }
}

/// Telemetry Notification Metadata
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct TelemetryMessageMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    node_export_timestamp: Option<DateTime<Utc>>,

    collection_timestamp: DateTime<Utc>,

    session_protocol: SessionProtocol,

    export_address: IpAddr,

    #[serde(skip_serializing_if = "Option::is_none")]
    export_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    collection_address: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    collection_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ietf-yang-push-telemetry-message:yang-push-subscription")]
    yang_push_subscription: Option<YangPushSubscriptionMetadata>,
}

impl TelemetryMessageMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_export_timestamp: Option<DateTime<Utc>>,
        collection_timestamp: DateTime<Utc>,
        session_protocol: SessionProtocol,
        export_address: IpAddr,
        export_port: Option<u16>,
        collection_address: Option<IpAddr>,
        collection_port: Option<u16>,
        yang_push_subscription: Option<YangPushSubscriptionMetadata>,
    ) -> Self {
        Self {
            node_export_timestamp,
            collection_timestamp,
            session_protocol,
            export_address,
            export_port,
            collection_address,
            collection_port,
            yang_push_subscription,
        }
    }
    pub fn node_export_timestamp(&self) -> Option<DateTime<Utc>> {
        self.node_export_timestamp
    }
    pub fn collection_timestamp(&self) -> DateTime<Utc> {
        self.collection_timestamp
    }
    pub fn session_protocol(&self) -> &SessionProtocol {
        &self.session_protocol
    }
    pub fn export_address(&self) -> IpAddr {
        self.export_address
    }
    pub fn export_port(&self) -> Option<u16> {
        self.export_port
    }
    pub fn collection_address(&self) -> Option<IpAddr> {
        self.collection_address
    }
    pub fn collection_port(&self) -> Option<u16> {
        self.collection_port
    }
    pub fn yang_push_subscription(&self) -> Option<&YangPushSubscriptionMetadata> {
        self.yang_push_subscription.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct YangPushSubscriptionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<SubscriptionId>,

    #[serde(flatten)]
    filter_spec: FilterSpec,

    #[serde(skip_serializing_if = "Option::is_none")]
    stop_time: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<Transport>,

    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<Encoding>,

    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,

    #[serde(flatten)]
    update_trigger: Option<UpdateTrigger>,

    module_version: Vec<YangPushModuleVersion>,

    #[serde(skip_serializing_if = "Option::is_none")]
    yang_library_content_id: Option<String>,
}

impl YangPushSubscriptionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Option<SubscriptionId>,
        filter_spec: FilterSpec,
        stop_time: Option<DateTime<Utc>>,
        transport: Option<Transport>,
        encoding: Option<Encoding>,
        purpose: Option<String>,
        update_trigger: Option<UpdateTrigger>,
        module_version: Vec<YangPushModuleVersion>,
        yang_library_content_id: Option<String>,
    ) -> Self {
        Self {
            id,
            filter_spec,
            stop_time,
            transport,
            encoding,
            purpose,
            update_trigger,
            module_version,
            yang_library_content_id,
        }
    }
    pub fn id(&self) -> Option<SubscriptionId> {
        self.id
    }
    pub fn filter_spec(&self) -> &FilterSpec {
        &self.filter_spec
    }
    pub fn stop_time(&self) -> Option<DateTime<Utc>> {
        self.stop_time
    }
    pub fn transport(&self) -> Option<&Transport> {
        self.transport.as_ref()
    }
    pub fn encoding(&self) -> Option<&Encoding> {
        self.encoding.as_ref()
    }
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }
    pub fn update_trigger(&self) -> Option<&UpdateTrigger> {
        self.update_trigger.as_ref()
    }
    pub fn module_version(&self) -> &[YangPushModuleVersion] {
        &self.module_version
    }
    pub fn yang_library_content_id(&self) -> Option<&str> {
        self.yang_library_content_id.as_deref()
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct FilterSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    datastore: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    xpath_filter: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    subtree_filter: Option<Value>,
}

impl FilterSpec {
    pub fn new(
        stream: Option<String>,
        datastore: Option<String>,
        xpath_filter: Option<String>,
        subtree_filter: Option<Value>,
    ) -> Self {
        Self {
            stream,
            datastore,
            xpath_filter,
            subtree_filter,
        }
    }
    pub fn stream(&self) -> Option<&str> {
        self.stream.as_deref()
    }
    pub fn datastore(&self) -> Option<&str> {
        self.datastore.as_deref()
    }
    pub fn xpath_filter(&self) -> Option<&str> {
        self.xpath_filter.as_deref()
    }
    pub fn subtree_filter(&self) -> Option<&Value> {
        self.subtree_filter.as_ref()
    }
}

/// Update Trigger for Yang Push Subscription
/// (redefined for Telemetry Message)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpdateTrigger {
    #[serde(rename = "periodic")]
    #[serde(rename_all = "kebab-case")]
    Periodic {
        #[serde(skip_serializing_if = "Option::is_none")]
        period: Option<CentiSeconds>,

        #[serde(skip_serializing_if = "Option::is_none")]
        anchor_time: Option<DateTime<Utc>>,
    },

    #[serde(rename = "on-change")]
    #[serde(rename_all = "kebab-case")]
    OnChange {
        #[serde(skip_serializing_if = "Option::is_none")]
        dampening_period: Option<CentiSeconds>,

        #[serde(skip_serializing_if = "Option::is_none")]
        sync_on_start: Option<bool>,

        #[serde(skip_serializing_if = "Option::is_none")]
        excluded_change: Option<Vec<ChangeType>>,
    },
}
impl From<crate::model::notification::UpdateTrigger> for UpdateTrigger {
    fn from(trigger: crate::model::notification::UpdateTrigger) -> Self {
        match trigger {
            crate::model::notification::UpdateTrigger::Periodic {
                period,
                anchor_time,
            } => UpdateTrigger::Periodic {
                period,
                anchor_time,
            },
            crate::model::notification::UpdateTrigger::OnChange {
                dampening_period,
                sync_on_start,
                excluded_change,
            } => UpdateTrigger::OnChange {
                dampening_period,
                sync_on_start,
                excluded_change,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct NetworkOperatorMetadata {
    labels: Vec<Label>,
}

impl NetworkOperatorMetadata {
    pub fn new(labels: Vec<Label>) -> Self {
        Self { labels }
    }
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Label {
    name: String,

    #[serde(flatten)]
    value: Option<LabelValue>,
}

impl Label {
    pub fn new(name: String, value: Option<LabelValue>) -> Self {
        Self { name, value }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum LabelValue {
    StringValue {
        #[serde(rename = "string-value")]
        string_value: String,
    },
    AnydataValue {
        #[serde(rename = "anydata-values")]
        anydata_values: Value,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::notification::CentiSeconds;
    use chrono::{TimeZone, Utc};
    use serde_json;
    use std::vec;

    #[test]
    fn test_telemetry_message_serde() {
        let original_message = TelemetryMessageWrapper {
            message: TelemetryMessage {
                network_node_manifest: Some(Manifest {
                    name: Some("node_id".to_string()),
                    vendor: Some("FRR".to_string()),
                    vendor_pen: None,
                    software_version: None,
                    software_flavor: None,
                    os_version: None,
                    os_type: None,
                }),
                telemetry_message_metadata: TelemetryMessageMetadata {
                    node_export_timestamp: None,
                    collection_timestamp: Utc.timestamp_millis_opt(0).unwrap(),
                    session_protocol: SessionProtocol::YangPush,
                    export_address: "127.0.0.1".parse().unwrap(),
                    export_port: Some(8080),
                    collection_address: None,
                    collection_port: None,
                    yang_push_subscription: Some(YangPushSubscriptionMetadata {
                        id: Some(1),
                        filter_spec: FilterSpec {
                            stream: Some("example-stream-subtree-filter-map".to_string()),
                            datastore: None,
                            xpath_filter: None,
                            subtree_filter: Some(serde_json::json!({
                              "example-map": serde_json::json!({
                                  "e1": "v1",
                                  "e2": "v2",
                              }),
                            })),
                        },
                        stop_time: None,
                        transport: Some(Transport::UDPNotif),
                        encoding: Some(Encoding::Json),
                        purpose: None,
                        update_trigger: Some(UpdateTrigger::Periodic {
                            period: Some(CentiSeconds::new(100)),
                            anchor_time: Some(Utc.timestamp_millis_opt(0).unwrap()),
                        }),
                        module_version: vec![YangPushModuleVersion::new(
                            "example-module".to_string(),
                            Some("2025-01-01".to_string()),
                            Some("1.0.0".to_string()),
                        )],
                        yang_library_content_id: Some("random-content-id".to_string()),
                    }),
                },
                data_collection_manifest: Some(Manifest {
                    name: Some("dev-collector".to_string()),
                    vendor: Some("NetGauze".to_string()),
                    vendor_pen: Some(12345),
                    software_version: Some("1.0.0".to_string()),
                    software_flavor: Some("release".to_string()),
                    os_version: Some("8.10".to_string()),
                    os_type: Some("Rocky Linux".to_string()),
                }),
                network_operator_metadata: NetworkOperatorMetadata {
                    labels: vec![
                        Label {
                            name: "platform_id".to_string(),
                            value: Some(LabelValue::StringValue {
                                string_value: "IETF LAB".to_string(),
                            }),
                        },
                        Label {
                            name: "test_anykey_label".to_string(),
                            value: Some(LabelValue::AnydataValue {
                                anydata_values: serde_json::json!({"key": "value"}),
                            }),
                        },
                    ],
                },
                payload: None,
            },
        };

        // Serialize the TelemetryMessage to JSON
        let serialized = serde_json::to_string(&original_message).expect("Failed to serialize");

        // Expected JSON string
        let expected_json = r#"{"ietf-telemetry-message:message":{"network-node-manifest":{"name":"node_id","vendor":"FRR"},"telemetry-message-metadata":{"collection-timestamp":"1970-01-01T00:00:00Z","session-protocol":"yp-push","export-address":"127.0.0.1","export-port":8080,"ietf-yang-push-telemetry-message:yang-push-subscription":{"id":1,"stream":"example-stream-subtree-filter-map","subtree-filter":{"example-map":{"e1":"v1","e2":"v2"}},"transport":"ietf-udp-notif-transport:udp-notif","encoding":"ietf-subscribed-notifications:encode-json","periodic":{"period":100,"anchor-time":"1970-01-01T00:00:00Z"},"module-version":[{"module-name":"example-module","revision":"2025-01-01","revision-label":"1.0.0"}],"yang-library-content-id":"random-content-id"}},"data-collection-manifest":{"name":"dev-collector","vendor":"NetGauze","vendor-pen":12345,"software-version":"1.0.0","software-flavor":"release","os-version":"8.10","os-type":"Rocky Linux"},"network-operator-metadata":{"labels":[{"name":"platform_id","string-value":"IETF LAB"},{"name":"test_anykey_label","anydata-values":{"key":"value"}}]}}}"#;

        // Assert that the serialized JSON string matches the expected JSON string
        assert_eq!(
            serialized, expected_json,
            "Serialized JSON does not match the expected JSON"
        );

        // Deserialize the JSON string back to a TelemetryMessage
        let deserialized: TelemetryMessageWrapper =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Assert that the original and deserialized messages are equal
        assert_eq!(original_message, deserialized);
    }
}
