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
//! - **TelemetryMessage**: The main structure representing a telemetry message.
//! - **SessionProtocol**: Enum for supported telemetry session protocols (e.g.,
//!   YANG Push, NETCONF).
//! - **Manifest**: Metadata about the network node or data collection system.
//! - **TelemetryMessageMetadata**: Metadata specific to the telemetry
//!   notification, with YANG Push subscription details such as filters,
//!   transport, and encoding.
//! - **DataCollectionMetadata**: Metadata about the data collection, including
//!   remote addresses and labels.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

use netgauze_udp_notif_pkt::yang::notification::{
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
    timestamp: DateTime<Utc>,
    session_protocol: SessionProtocol,
    network_node_manifest: Manifest,
    data_collection_manifest: Manifest,
    telemetry_message_metadata: TelemetryMessageMetadata,
    data_collection_metadata: DataCollectionMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
}

impl TelemetryMessage {
    pub fn new(
        timestamp: DateTime<Utc>,
        session_protocol: SessionProtocol,
        network_node_manifest: Manifest,
        data_collection_manifest: Manifest,
        telemetry_message_metadata: TelemetryMessageMetadata,
        data_collection_metadata: DataCollectionMetadata,
        payload: Option<Value>,
    ) -> Self {
        Self {
            timestamp,
            session_protocol,
            network_node_manifest,
            data_collection_manifest,
            telemetry_message_metadata,
            data_collection_metadata,
            payload,
        }
    }
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    pub fn session_protocol(&self) -> &SessionProtocol {
        &self.session_protocol
    }
    pub fn network_node_manifest(&self) -> &Manifest {
        &self.network_node_manifest
    }
    pub fn data_collection_manifest(&self) -> &Manifest {
        &self.data_collection_manifest
    }
    pub fn telemetry_message_metadata(&self) -> &TelemetryMessageMetadata {
        &self.telemetry_message_metadata
    }
    pub fn data_collection_metadata(&self) -> &DataCollectionMetadata {
        &self.data_collection_metadata
    }
    pub fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }
}

/// Telemetry Session Protocol Type
#[derive(Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
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
#[derive(Default, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TelemetryMessageMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "event-time")]
    event_time: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ietf-yang-push-telemetry-message:yang-push-subscription")]
    yang_push_subscription: Option<YangPushSubscriptionMetadata>,
}

impl TelemetryMessageMetadata {
    pub fn new(
        event_time: Option<DateTime<Utc>>,
        yang_push_subscription: Option<YangPushSubscriptionMetadata>,
    ) -> Self {
        Self {
            event_time,
            yang_push_subscription,
        }
    }
    pub fn event_time(&self) -> Option<DateTime<Utc>> {
        self.event_time
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
    update_trigger: UpdateTrigger,

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
        update_trigger: UpdateTrigger,
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
    pub fn update_trigger(&self) -> &UpdateTrigger {
        &self.update_trigger
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
impl From<netgauze_udp_notif_pkt::yang::notification::UpdateTrigger> for UpdateTrigger {
    fn from(trigger: netgauze_udp_notif_pkt::yang::notification::UpdateTrigger) -> Self {
        match trigger {
            netgauze_udp_notif_pkt::yang::notification::UpdateTrigger::Periodic {
                period,
                anchor_time,
            } => UpdateTrigger::Periodic {
                period,
                anchor_time,
            },
            netgauze_udp_notif_pkt::yang::notification::UpdateTrigger::OnChange {
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
pub struct DataCollectionMetadata {
    remote_address: IpAddr,

    #[serde(skip_serializing_if = "Option::is_none")]
    remote_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    local_address: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    local_port: Option<u16>,

    labels: Vec<Label>,
}

impl DataCollectionMetadata {
    pub fn new(
        remote_address: IpAddr,
        remote_port: Option<u16>,
        local_address: Option<IpAddr>,
        local_port: Option<u16>,
        labels: Vec<Label>,
    ) -> Self {
        Self {
            remote_address,
            remote_port,
            local_address,
            local_port,
            labels,
        }
    }
    pub fn remote_address(&self) -> IpAddr {
        self.remote_address
    }
    pub fn remote_port(&self) -> Option<u16> {
        self.remote_port
    }
    pub fn local_address(&self) -> Option<IpAddr> {
        self.local_address
    }
    pub fn local_port(&self) -> Option<u16> {
        self.local_port
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
    use chrono::{TimeZone, Utc};
    use netgauze_udp_notif_pkt::yang::notification::CentiSeconds;
    use serde_json;
    use std::vec;

    #[test]
    fn test_telemetry_message_serde() {
        let original_message = TelemetryMessageWrapper {
            message: TelemetryMessage {
                timestamp: Utc.timestamp_millis_opt(0).unwrap(),
                session_protocol: SessionProtocol::YangPush,
                network_node_manifest: Manifest {
                    name: Some("node_id".to_string()),
                    vendor: Some("FRR".to_string()),
                    vendor_pen: None,
                    software_version: None,
                    software_flavor: None,
                    os_version: None,
                    os_type: None,
                },
                data_collection_manifest: Manifest {
                    name: Some("dev-collector".to_string()),
                    vendor: Some("NetGauze".to_string()),
                    vendor_pen: Some(12345),
                    software_version: Some("1.0.0".to_string()),
                    software_flavor: Some("release".to_string()),
                    os_version: Some("8.10".to_string()),
                    os_type: Some("Rocky Linux".to_string()),
                },
                telemetry_message_metadata: TelemetryMessageMetadata {
                    event_time: None,
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
                        update_trigger: UpdateTrigger::Periodic {
                            period: Some(CentiSeconds::new(100)),
                            anchor_time: Some(Utc.timestamp_millis_opt(0).unwrap()),
                        },
                        module_version: vec![YangPushModuleVersion {
                            module_name: "example-module".to_string(),
                            revision: Some("2025-01-01".to_string()),
                            revision_label: Some("1.0.0".to_string()),
                        }],
                        yang_library_content_id: Some("random-content-id".to_string()),
                    }),
                },
                data_collection_metadata: DataCollectionMetadata {
                    remote_address: "127.0.0.1".parse().unwrap(),
                    remote_port: Some(8080),
                    local_address: None,
                    local_port: None,
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
        let expected_json = r#"{"ietf-telemetry-message:message":{"timestamp":"1970-01-01T00:00:00Z","session-protocol":"yp-push","network-node-manifest":{"name":"node_id","vendor":"FRR"},"data-collection-manifest":{"name":"dev-collector","vendor":"NetGauze","vendor-pen":12345,"software-version":"1.0.0","software-flavor":"release","os-version":"8.10","os-type":"Rocky Linux"},"telemetry-message-metadata":{"ietf-yang-push-telemetry-message:yang-push-subscription":{"id":1,"stream":"example-stream-subtree-filter-map","subtree-filter":{"example-map":{"e1":"v1","e2":"v2"}},"transport":"ietf-udp-notif-transport:udp-notif","encoding":"ietf-subscribed-notifications:encode-json","periodic":{"period":100,"anchor-time":"1970-01-01T00:00:00Z"},"module-version":[{"module-name":"example-module","revision":"2025-01-01","revision-label":"1.0.0"}],"yang-library-content-id":"random-content-id"}},"data-collection-metadata":{"remote-address":"127.0.0.1","remote-port":8080,"labels":[{"name":"platform_id","string-value":"IETF LAB"},{"name":"test_anykey_label","anydata-values":{"key":"value"}}]}}}"#;

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
