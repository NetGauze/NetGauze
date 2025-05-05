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

// TODO: documentation here...
// TODO: testing: integrate in the pcap_tests (serde with this structs
// definitions to check if all messages are recomposed the same way after
// deserialization!)       --> also add a small tests here in the file for
// this...

/// References:
/// - https://datatracker.ietf.org/doc/html/rfc8639
/// - https://datatracker.ietf.org/doc/html/rfc8641
/// - https://datatracker.ietf.org/doc/html/draft-ietf-netconf-yang-notifications-versioning-08
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CentiSeconds, SubscriptionId};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notification {
    #[serde(rename = "eventTime")]
    event_time: DateTime<Utc>,

    #[serde(rename = "ietf-notification-sequencing:sysName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,

    #[serde(flatten)]
    notification: NotificationVariant,

    #[serde(flatten)]
    extra_fields: Value,
}

impl Notification {
    pub fn event_time(&self) -> &DateTime<Utc> {
        &self.event_time
    }
    pub fn node_id(&self) -> Option<&String> {
        self.node_id.as_ref()
    }
    pub fn notification(&self) -> &NotificationVariant {
        &self.notification
    }
}

/// Notification Variants
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationVariant {
    #[serde(rename = "ietf-subscribed-notifications:subscription-started")]
    SubscriptionStarted(SubscriptionStartedModified),

    #[serde(rename = "ietf-subscribed-notifications:subscription-modified")]
    SubscriptionModified(SubscriptionStartedModified),

    #[serde(rename = "ietf-subscribed-notifications:subscription-terminated")]
    SubscriptionTerminated(SubscriptionTerminated),

    #[serde(rename = "ietf-yang-push:push-update")]
    YangPushUpdate(YangPushUpdate),
}

/// Subscription Started and Modified Message
/// TODO: we could even use this as cache (setting the extra_fields empty)
/// --> we might need to create a new struct where we keep all fields apart from
/// extra_fields     and use this one for the cache (we need to use it to
/// serialize the sub-started message)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionStartedModified {
    id: SubscriptionId,

    #[serde(flatten)]
    target: Target,

    #[serde(rename = "stop-time")]
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

    #[serde(rename = "ietf-yang-push-revision:module-version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    module_version: Option<Vec<YangPushModuleVersion>>,

    #[serde(rename = "ietf-yang-push-revision:content-id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    content_id: Option<String>,

    #[serde(flatten)]
    extra_fields: Value,
}

impl SubscriptionStartedModified {
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn stop_time(&self) -> Option<&DateTime<Utc>> {
        self.stop_time.as_ref()
    }
    pub fn transport(&self) -> Option<&Transport> {
        self.transport.as_ref()
    }
    pub fn encoding(&self) -> Option<&Encoding> {
        self.encoding.as_ref()
    }
    pub fn purpose(&self) -> Option<&String> {
        self.purpose.as_ref()
    }
    pub fn update_trigger(&self) -> &UpdateTrigger {
        &self.update_trigger
    }
    pub fn module_version(&self) -> Option<&Vec<YangPushModuleVersion>> {
        self.module_version.as_ref()
    }
    pub fn content_id(&self) -> Option<&str> {
        self.content_id.as_deref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionTerminated {
    id: SubscriptionId,

    reason: String,

    #[serde(flatten)]
    extra_fields: Value,
}

impl SubscriptionTerminated {
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct YangPushUpdate {
    id: SubscriptionId,

    #[serde(rename = "datastore-contents")]
    datastore_contents: Value,

    #[serde(flatten)]
    extra_fields: Value,
}

impl YangPushUpdate {
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    #[serde(rename = "stream")]
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<String>,

    #[serde(rename = "stream-subtree-filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_subtree_filter: Option<Value>,

    #[serde(rename = "stream-xpath-filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_xpath_filter: Option<String>,

    #[serde(rename = "replay-start-time")]
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_start_time: Option<DateTime<Utc>>,

    #[serde(rename = "ietf-yang-push:datastore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    datastore: Option<String>,

    #[serde(rename = "datastore-subtree-filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    datastore_subtree_filter: Option<Value>,

    #[serde(rename = "ietf-yang-push:datastore-xpath-filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    datastore_xpath_filter: Option<String>,
}

impl Target {
    pub fn stream(&self) -> Option<&str> {
        self.stream.as_deref()
    }
    pub fn stream_subtree_filter(&self) -> Option<&Value> {
        self.stream_subtree_filter.as_ref()
    }
    pub fn stream_xpath_filter(&self) -> Option<&str> {
        self.stream_xpath_filter.as_deref()
    }
    pub fn replay_start_time(&self) -> Option<&DateTime<Utc>> {
        self.replay_start_time.as_ref()
    }
    pub fn datastore(&self) -> Option<&str> {
        self.datastore.as_deref()
    }
    pub fn datastore_subtree_filter(&self) -> Option<&Value> {
        self.datastore_subtree_filter.as_ref()
    }
    pub fn datastore_xpath_filter(&self) -> Option<&str> {
        self.datastore_xpath_filter.as_deref()
    }
}

/// Transport protocol used to deliver the notification message to the data
/// collection
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transport {
    // #[serde(rename = "ssh")]
    // SSH,

    // #[serde(rename = "http")]
    // HTTP,
    #[serde(rename = "ietf-udp-notif-transport:udp-notif")]
    UDPNotif,

    #[serde(rename = "ietf-https-notif:https")]
    HTTPSNotif,

    #[default]
    #[serde(other)]
    #[serde(rename = "unknown")]
    Unknown,
}

// Encoding used for the notification payload
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Encoding {
    #[serde(rename = "encode-xml")]
    Xml,

    #[serde(rename = "encode-json")]
    Json,

    #[serde(rename = "encode-cbor")]
    Cbor,

    #[default]
    #[serde(other)]
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpdateTrigger {
    #[serde(rename = "ietf-yang-push:periodic")]
    #[serde(rename_all = "kebab-case")]
    Periodic {
        period: CentiSeconds,
        anchor_time: Option<DateTime<Utc>>,
    },

    #[serde(rename = "ietf-yang-push:on-change")]
    #[serde(rename_all = "kebab-case")]
    OnChange {
        dampening_period: Option<CentiSeconds>,
        sync_on_start: Option<bool>,
        excluded_change: Option<Vec<ChangeType>>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Create,
    Delete,
    Insert,
    Move,
    Replace,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct YangPushModuleVersion {
    pub module_name: String,

    pub revision: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_label: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use colored::*;
    use serde_json;

    #[test]
    fn test_transport_serialization() {
        // Test serialization
        assert_eq!(
            serde_json::to_string(&Transport::UDPNotif).unwrap(),
            r#""ietf-udp-notif-transport:udp-notif""#
        );
        assert_eq!(
            serde_json::to_string(&Transport::HTTPSNotif).unwrap(),
            r#""ietf-https-notif:https""#
        );
        assert_eq!(
            serde_json::to_string(&Transport::Unknown).unwrap(),
            r#""unknown""#
        );
    }

    #[test]
    fn test_transport_deserialization() {
        // Test deserialization
        assert_eq!(
            serde_json::from_str::<Transport>(r#""ietf-udp-notif-transport:udp-notif""#).unwrap(),
            Transport::UDPNotif
        );
        assert_eq!(
            serde_json::from_str::<Transport>(r#""ietf-https-notif:https""#).unwrap(),
            Transport::HTTPSNotif
        );
        assert_eq!(
            serde_json::from_str::<Transport>(r#""unknown""#).unwrap(),
            Transport::Unknown
        );

        // Test deserialization of unknown/empty values
        assert_eq!(
            serde_json::from_str::<Transport>(r#""unsupported-value""#).unwrap(),
            Transport::Unknown
        );
        assert_eq!(
            serde_json::from_str::<Transport>(r#""""#).unwrap(),
            Transport::Unknown
        );
    }

    #[test]
    fn test_encoding_serialization() {
        // Test serialization
        assert_eq!(
            serde_json::to_string(&Encoding::Xml).unwrap(),
            r#""encode-xml""#
        );
        assert_eq!(
            serde_json::to_string(&Encoding::Json).unwrap(),
            r#""encode-json""#
        );
        assert_eq!(
            serde_json::to_string(&Encoding::Cbor).unwrap(),
            r#""encode-cbor""#
        );
        assert_eq!(
            serde_json::to_string(&Encoding::Unknown).unwrap(),
            r#""unknown""#
        );
    }

    #[test]
    fn test_encoding_deserialization() {
        // Test deserialization
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""encode-xml""#).unwrap(),
            Encoding::Xml
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""encode-json""#).unwrap(),
            Encoding::Json
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""encode-cbor""#).unwrap(),
            Encoding::Cbor
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""unknown""#).unwrap(),
            Encoding::Unknown
        );

        // Test deserialization of unknown/empty values
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""unsupported-value""#).unwrap(),
            Encoding::Unknown
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""""#).unwrap(),
            Encoding::Unknown
        );
    }

    #[test]
    // #[ignore]
    fn test_sub_started_serialization() {
        // Create a SubscriptionStartedModified instance
        let sub_started = SubscriptionStartedModified {
            id: 1,
            target: Target {
                stream: None,
                stream_subtree_filter: None,
                stream_xpath_filter: None,
                replay_start_time: None,
                datastore: Some("example-datastore".to_string()),
                datastore_subtree_filter: None,
                datastore_xpath_filter: Some("/example/datastore/xpath/filter".to_string()),
            },
            encoding: Some(Encoding::Json),
            transport: Some(Transport::UDPNotif),
            stop_time: Some(Utc.timestamp_millis_opt(0).unwrap()),
            purpose: Some("test-purpose".to_string()),
            update_trigger: UpdateTrigger::OnChange {
                dampening_period: Some(CentiSeconds::new(100)),
                sync_on_start: Some(true),
                excluded_change: Some(vec![ChangeType::Create, ChangeType::Replace]),
            },
            module_version: Some(vec![YangPushModuleVersion {
                module_name: "example-module".to_string(),
                revision: "2025-04-25".to_string(),
                revision_label: None,
            }]),
            content_id: Some("content-id".to_string()),
            extra_fields: serde_json::json!({}),
        };

        // Create a Notification instance
        let notification = Notification {
            event_time: Utc.timestamp_millis_opt(0).unwrap(),
            node_id: Some("example-node".to_string()),
            notification: NotificationVariant::SubscriptionStarted(sub_started),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the Notification to JSON
        let serialized = serde_json::to_string(&notification).expect("Serialization failed");

        // Print the serialized JSON
        println!("{}", format!("Serialized JSON: {serialized}").yellow());

        // Deserialize the JSON back to a Notification
        let deserialized: Notification =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        // Serialize again to check if it matches the previous serialization
        let re_serialized = serde_json::to_string(&deserialized).expect("Re-serialization failed");
        println!(
            "{}",
            format!("Re-serialized JSON: {re_serialized}").yellow()
        );

        // Assert that the deserialized Notification matches the original
        assert_eq!(notification, deserialized);
    }
}
