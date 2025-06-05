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

//! # YANG Notification Message
//!
//! This module defines data structures and serialization logic for handling
//! YANG notifications as specified in:
//! - [RFC 8639](https://datatracker.ietf.org/doc/html/rfc8639): Subscription to
//!   YANG Notifications
//! - [RFC 8641](https://datatracker.ietf.org/doc/html/rfc8641): Subscription to
//!   YANG Notifications for Datastore Updates
//! - [Notification Versioning Draft](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-yang-notifications-versioning-08)
//! - [Notification Envelope Draft](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-notif-envelope-01)
//!
//! ## Key components:
//! - **NotificationEnvelope**: Extensible wrapper for Yang-Push notification
//!   messages with metadata like hostname and sequence number.
//! - **NotificationLegacy**: Legacy notification wrapper (deprecated).
//! - **NotificationVariant**: Enumerates specific notification types (e.g.,
//!   subscription started/modified/terminated, YANG push updates, etc.).
//!
//! ## Notes:
//! - `extra_fields` with serde(flatten) annotations is used for handling
//!   additional fields to ensure compatibility with YANG augmentations
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum_macros::Display;

pub type SubscriptionId = u32;

/// Yang-Push Notification Envelope
/// This is an extensible wrapper for Yang-Push notification messages.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct NotificationEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sequence_number: Option<u32>,

    /// Alias for supporting deprecated 'notification-contents'
    /// instead of 'contents' (> draft-ietf-netconf-notif-envelope-01)
    #[serde(alias = "notification-contents")]
    #[serde(skip_serializing_if = "Option::is_none")]
    contents: Option<NotificationVariant>,

    #[serde(flatten)]
    extra_fields: Value,
}

impl NotificationEnvelope {
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    pub fn sequence_number(&self) -> Option<u32> {
        self.sequence_number
    }
    pub fn contents(&self) -> Option<&NotificationVariant> {
        self.contents.as_ref()
    }
}

/// Legacy Yang-Push Notification Wrapper
/// This is deprecated: use NotificationEnvelope instead
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationLegacy {
    #[serde(rename = "ietf-notification-sequencing:sysName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    sys_name: Option<String>,

    #[serde(flatten)]
    notification: Option<NotificationVariant>,

    #[serde(flatten)]
    extra_fields: Value,
}

impl NotificationLegacy {
    pub fn sys_name(&self) -> Option<&str> {
        self.sys_name.as_deref()
    }
    pub fn notification(&self) -> Option<&NotificationVariant> {
        self.notification.as_ref()
    }
}

/// Notification Variants
#[derive(Clone, Debug, Display, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationVariant {
    #[serde(rename = "ietf-subscribed-notifications:subscription-started")]
    SubscriptionStarted(SubscriptionStartedModified),

    #[serde(rename = "ietf-subscribed-notifications:subscription-modified")]
    SubscriptionModified(SubscriptionStartedModified),

    #[serde(rename = "ietf-subscribed-notifications:subscription-terminated")]
    SubscriptionTerminated(SubscriptionTerminated),

    #[serde(rename = "ietf-yang-push:push-update")]
    YangPushUpdate(YangPushUpdate),

    #[serde(rename = "ietf-yang-push:push-change-update")]
    YangPushChangeUpdate(YangPushChangeUpdate),
}

/// Subscription Started and Modified Message
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

    #[serde(rename = "ietf-yang-push-revision:yang-library-content-id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    yang_library_content_id: Option<String>,

    #[serde(flatten)]
    extra_fields: Value,
}

impl SubscriptionStartedModified {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: SubscriptionId,
        target: Target,
        stop_time: Option<DateTime<Utc>>,
        transport: Option<Transport>,
        encoding: Option<Encoding>,
        purpose: Option<String>,
        update_trigger: UpdateTrigger,
        module_version: Option<Vec<YangPushModuleVersion>>,
        yang_library_content_id: Option<String>,
        extra_fields: Value,
    ) -> Self {
        Self {
            id,
            target,
            stop_time,
            transport,
            encoding,
            purpose,
            update_trigger,
            module_version,
            yang_library_content_id,
            extra_fields,
        }
    }
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
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }
    pub fn update_trigger(&self) -> &UpdateTrigger {
        &self.update_trigger
    }
    pub fn module_version(&self) -> Option<&Vec<YangPushModuleVersion>> {
        self.module_version.as_ref()
    }
    pub fn yang_library_content_id(&self) -> Option<&str> {
        self.yang_library_content_id.as_deref()
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
    pub fn new(id: SubscriptionId, reason: String, extra_fields: Value) -> Self {
        Self {
            id,
            reason,
            extra_fields,
        }
    }
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct YangPushUpdate {
    id: SubscriptionId,

    datastore_contents: Value,

    #[serde(flatten)]
    extra_fields: Value,
}

impl YangPushUpdate {
    pub fn new(id: SubscriptionId, datastore_contents: Value, extra_fields: Value) -> Self {
        Self {
            id,
            datastore_contents,
            extra_fields,
        }
    }
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct YangPushChangeUpdate {
    id: SubscriptionId,

    datastore_changes: Value,

    #[serde(flatten)]
    extra_fields: Value,
}

impl YangPushChangeUpdate {
    pub fn new(id: SubscriptionId, datastore_changes: Value, extra_fields: Value) -> Self {
        Self {
            id,
            datastore_changes,
            extra_fields,
        }
    }
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
    pub fn new(
        stream: Option<String>,
        stream_subtree_filter: Option<Value>,
        stream_xpath_filter: Option<String>,
        replay_start_time: Option<DateTime<Utc>>,
        datastore: Option<String>,
        datastore_subtree_filter: Option<Value>,
        datastore_xpath_filter: Option<String>,
    ) -> Self {
        Self {
            stream,
            stream_subtree_filter,
            stream_xpath_filter,
            replay_start_time,
            datastore,
            datastore_subtree_filter,
            datastore_xpath_filter,
        }
    }
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
    #[serde(rename = "ietf-subscribed-notifications:encode-xml")]
    #[serde(alias = "encode-xml")]
    Xml,

    #[serde(rename = "ietf-subscribed-notifications:encode-json")]
    #[serde(alias = "encode-json")]
    Json,

    #[serde(rename = "ietf-udp-notif-transport:encode-cbor")]
    #[serde(alias = "encode-cbor")]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        period: Option<CentiSeconds>,

        #[serde(skip_serializing_if = "Option::is_none")]
        anchor_time: Option<DateTime<Utc>>,
    },

    #[serde(rename = "ietf-yang-push:on-change")]
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CentiSeconds(u32);

impl CentiSeconds {
    pub fn new(value: u32) -> Self {
        CentiSeconds(value)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn to_milliseconds(&self) -> u32 {
        self.0 * 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json;

    #[test]
    fn test_transport_serialization() {
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
        assert_eq!(
            serde_json::to_string(&Encoding::Xml).unwrap(),
            r#""ietf-subscribed-notifications:encode-xml""#
        );

        assert_eq!(
            serde_json::to_string(&Encoding::Json).unwrap(),
            r#""ietf-subscribed-notifications:encode-json""#
        );

        assert_eq!(
            serde_json::to_string(&Encoding::Cbor).unwrap(),
            r#""ietf-udp-notif-transport:encode-cbor""#
        );
        assert_eq!(
            serde_json::to_string(&Encoding::Unknown).unwrap(),
            r#""unknown""#
        );
    }

    #[test]
    fn test_encoding_deserialization() {
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""ietf-subscribed-notifications:encode-xml""#)
                .unwrap(),
            Encoding::Xml
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""encode-xml""#).unwrap(),
            Encoding::Xml
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""ietf-subscribed-notifications:encode-json""#)
                .unwrap(),
            Encoding::Json
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""encode-json""#).unwrap(),
            Encoding::Json
        );
        assert_eq!(
            serde_json::from_str::<Encoding>(r#""ietf-udp-notif-transport:encode-cbor""#).unwrap(),
            Encoding::Cbor
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
    fn test_sub_started_modified_serde() {
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
                revision: Some("2025-04-25".to_string()),
                revision_label: None,
            }]),
            yang_library_content_id: Some("content-id".to_string()),
            extra_fields: serde_json::json!({}),
        };

        // Create a Notification instance
        let notification = NotificationLegacy {
            sys_name: Some("example-node".to_string()),
            notification: Some(NotificationVariant::SubscriptionStarted(
                sub_started.clone(),
            )),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the Notification to JSON
        let serialized = serde_json::to_string(&notification).expect("Serialization failed");

        // Deserialize the JSON back to a Notification
        let deserialized: NotificationLegacy =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        // Assert that the deserialized Notification matches the original
        assert_eq!(notification, deserialized);

        // Create a NotificationEnvelope instance
        let notification_envelope = NotificationEnvelope {
            hostname: Some("example-host".to_string()),
            sequence_number: Some(12345),
            contents: Some(NotificationVariant::SubscriptionStarted(sub_started)),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the NotificationEnvelope to JSON
        let serialized_envelope =
            serde_json::to_string(&notification_envelope).expect("Serialization failed");

        // Deserialize the JSON back to a NotificationEnvelope
        let deserialized_envelope: NotificationEnvelope =
            serde_json::from_str(&serialized_envelope).expect("Deserialization failed");

        // Assert that the deserialized NotificationEnvelope matches the original
        assert_eq!(notification_envelope, deserialized_envelope);
    }

    #[test]
    fn test_sub_started_modified_getters() {
        // Create a Target instance
        let target = Target {
            stream: None,
            stream_subtree_filter: None,
            stream_xpath_filter: None,
            replay_start_time: Some(Utc.timestamp_millis_opt(0).unwrap()),
            datastore: Some("example-datastore".to_string()),
            datastore_subtree_filter: Some(serde_json::json!({"example-map": "example-value"})),
            datastore_xpath_filter: Some("/example/datastore/xpath/filter".to_string()),
        };

        // Target getters
        assert_eq!(target.stream(), None);
        assert_eq!(target.stream_subtree_filter(), None);
        assert_eq!(target.stream_xpath_filter(), None);
        assert_eq!(
            target.replay_start_time(),
            Some(&Utc.timestamp_millis_opt(0).unwrap())
        );
        assert_eq!(target.datastore(), Some("example-datastore"));
        assert_eq!(
            target.datastore_subtree_filter(),
            Some(&serde_json::json!({"example-map": "example-value"}))
        );
        assert_eq!(
            target.datastore_xpath_filter(),
            Some("/example/datastore/xpath/filter")
        );

        // Create a SubscriptionStartedModified instance
        let sub_started = SubscriptionStartedModified {
            id: 1,
            target: target.clone(),
            encoding: Some(Encoding::Json),
            transport: Some(Transport::UDPNotif),
            stop_time: Some(Utc.timestamp_millis_opt(10000).unwrap()),
            purpose: Some("test-purpose".to_string()),
            update_trigger: UpdateTrigger::OnChange {
                dampening_period: Some(CentiSeconds::new(100)),
                sync_on_start: Some(true),
                excluded_change: Some(vec![ChangeType::Create, ChangeType::Replace]),
            },
            module_version: Some(vec![YangPushModuleVersion {
                module_name: "example-module".to_string(),
                revision: Some("2025-04-25".to_string()),
                revision_label: None,
            }]),
            yang_library_content_id: Some("content-id".to_string()),
            extra_fields: serde_json::json!({}),
        };

        // SubscriptionStartedModified getters
        assert_eq!(sub_started.id(), 1);
        assert_eq!(sub_started.target(), &target);
        assert_eq!(
            sub_started.stop_time(),
            Some(&Utc.timestamp_millis_opt(10000).unwrap())
        );
        assert_eq!(sub_started.transport(), Some(&Transport::UDPNotif));
        assert_eq!(sub_started.encoding(), Some(&Encoding::Json));
        assert_eq!(sub_started.purpose(), Some("test-purpose"));
        assert_eq!(sub_started.yang_library_content_id(), Some("content-id"));

        // Create a Notification instance
        let notification = NotificationLegacy {
            sys_name: Some("example-node".to_string()),
            notification: Some(NotificationVariant::SubscriptionStarted(
                sub_started.clone(),
            )),
            extra_fields: serde_json::json!({}),
        };

        // Notification getters
        assert_eq!(notification.sys_name(), Some("example-node"));
        assert!(matches!(
            notification.notification(),
            Some(NotificationVariant::SubscriptionStarted(_))
        ));

        // Create a NotificationEnvelope instance
        let notification_envelope = NotificationEnvelope {
            hostname: Some("example-host".to_string()),
            sequence_number: Some(12345),
            contents: Some(NotificationVariant::SubscriptionStarted(sub_started)),
            extra_fields: serde_json::json!({}),
        };

        // NotificationEnvelope getters
        assert_eq!(notification_envelope.hostname(), Some("example-host"));
        assert_eq!(notification_envelope.sequence_number(), Some(12345));
        assert!(matches!(
            notification_envelope.contents(),
            Some(NotificationVariant::SubscriptionStarted(_))
        ));
    }

    #[test]
    fn test_sub_terminated_serde() {
        // Create a SubscriptionTerminated instance
        let sub_terminated = SubscriptionTerminated {
            id: 1,
            reason: "some-reason".to_string(),
            extra_fields: serde_json::json!({}),
        };

        // Create a Notification instance
        let notification = NotificationLegacy {
            sys_name: Some("example-node".to_string()),
            notification: Some(NotificationVariant::SubscriptionTerminated(
                sub_terminated.clone(),
            )),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the Notification to JSON
        let serialized = serde_json::to_string(&notification).expect("Serialization failed");

        // Deserialize the JSON back to a Notification
        let deserialized: NotificationLegacy =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        // Assert that the deserialized Notification matches the original
        assert_eq!(notification, deserialized);

        // Create a NotificationEnvelope instance
        let notification_envelope = NotificationEnvelope {
            hostname: Some("example-host".to_string()),
            sequence_number: Some(12345),
            contents: Some(NotificationVariant::SubscriptionTerminated(sub_terminated)),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the NotificationEnvelope to JSON
        let serialized_envelope =
            serde_json::to_string(&notification_envelope).expect("Serialization failed");

        // Deserialize the JSON back to a NotificationEnvelope
        let deserialized_envelope: NotificationEnvelope =
            serde_json::from_str(&serialized_envelope).expect("Deserialization failed");

        // Assert that the deserialized NotificationEnvelope matches the original
        assert_eq!(notification_envelope, deserialized_envelope);
    }

    #[test]
    fn test_sub_terminated_getters() {
        // Create a SubscriptionTerminated instance
        let sub_terminated = SubscriptionTerminated {
            id: 2462462462,
            reason: "this-is-the-yang-push-sub-terminated-reason".to_string(),
            extra_fields: serde_json::json!({}),
        };

        // SubscriptionTerminated getters
        assert_eq!(sub_terminated.id(), 2462462462);
        assert_eq!(
            sub_terminated.reason(),
            "this-is-the-yang-push-sub-terminated-reason"
        );
    }

    #[test]
    fn test_yang_push_update_serde() {
        // Create a YangPushUpdate instance
        let yang_push_update = YangPushUpdate {
            id: 1,
            datastore_contents: serde_json::json!({
              "layer1": {
                  "layer2": {
                      "layer3": {
                          "key1": "value1",
                          "key2": 42,
                          "key3": {
                              "subkey1": true,
                              "subkey2": [1, 2, 3],
                              "subkey3": {
                                  "deepkey": "deepvalue"
                              }
                          }
                      },
                      "anotherKey": "anotherValue"
                  },
                  "simpleKey": "simpleValue"
              }
            }),
            extra_fields: serde_json::json!({
                "ietf-distributed-notif:message-publisher-id": 1,
                "ietf-yp-observation:point-in-time": "current-accounting",
                "ietf-yp-observation:timestamp": "2025-05-06T00:00:00Z"
            }),
        };

        // Create a Notification instance
        let notification = NotificationLegacy {
            sys_name: Some("example-node".to_string()),
            notification: Some(NotificationVariant::YangPushUpdate(
                yang_push_update.clone(),
            )),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the Notification to JSON
        let serialized = serde_json::to_string(&notification).expect("Serialization failed");

        // Deserialize the JSON back to a Notification
        let deserialized: NotificationLegacy =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        // Assert that the deserialized Notification matches the original
        assert_eq!(notification, deserialized);

        // Create a NotificationEnvelope instance
        let notification_envelope = NotificationEnvelope {
            hostname: Some("example-host".to_string()),
            sequence_number: Some(12345),
            contents: Some(NotificationVariant::YangPushUpdate(yang_push_update)),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the NotificationEnvelope to JSON
        let serialized_envelope =
            serde_json::to_string(&notification_envelope).expect("Serialization failed");

        // Deserialize the JSON back to a NotificationEnvelope
        let deserialized_envelope: NotificationEnvelope =
            serde_json::from_str(&serialized_envelope).expect("Deserialization failed");

        // Assert that the deserialized NotificationEnvelope matches the original
        assert_eq!(notification_envelope, deserialized_envelope);
    }

    #[test]
    fn test_yang_push_update_getter() {
        // Create a YangPushUpdate instance
        let yang_push_update = YangPushUpdate {
            id: 798798779,
            datastore_contents: serde_json::json!({}),
            extra_fields: serde_json::json!({}),
        };

        // YangPushUpdate getters
        assert_eq!(yang_push_update.id(), 798798779);
    }
}
