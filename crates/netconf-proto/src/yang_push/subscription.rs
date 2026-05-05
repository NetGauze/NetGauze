// Copyright (C) 2026-present The NetGauze Authors.
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

//! Subscription types for YANG-Push and Subscribed Notifications.
//!
//! This module contains the core [`Subscription`] type together with its
//! constituent parts:
//!
//! * [`Target`] – choice between a [`StreamTarget`] ([RFC 8639]) and a
//!   [`DatastoreTarget`] ([RFC 8641]).
//! * [`UpdateTrigger`] – periodic or on-change trigger configuration.
//! * [`DatastoreSelectionFilterObjects`] – inline or by-reference datastore
//!   filter selection.
//!
//! All types implement XML round-trip serialization via
//! [XmlSerialize]/[XmlDeserialize] and `serde` `Serialize`/`Deserialize`.

use crate::xml_utils::{
    ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter, format_datetime,
    parse_datetime, xml_write_optional_text_leaf,
};
use crate::yang_push::filters::{
    DatastoreFilterSpec, StreamFilterSpec, StreamSelectionFilterObjects,
};
use crate::yang_push::identities::{ChangeType, ConfiguredSubscriptionState, Encoding, Transport};
use crate::yang_push::types::{CentiSeconds, SubscriptionId};
use crate::yang_push::{
    DISTRIBUTED_NOTIF_NS, SUBSCRIBED_NOTIFICATIONS_NS, YANG_PUSH_NS, YANG_PUSH_REVISION,
};
use crate::yanglib::DatastoreName;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use quick_xml::events::{BytesText, Event};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    pub id: SubscriptionId,

    #[serde(flatten)]
    pub target: Target,

    #[serde(rename = "stop-time", skip_serializing_if = "Option::is_none")]
    pub stop_time: Option<DateTime<Utc>>,

    #[serde(rename = "dscp", skip_serializing_if = "Option::is_none")]
    pub dscp: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub weighting: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency: Option<SubscriptionId>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Encoding>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Box<str>>,

    #[serde(
        rename = "configured-subscription-state",
        skip_serializing_if = "Option::is_none"
    )]
    pub configured_subscription_state: Option<ConfiguredSubscriptionState>,

    #[serde(
        rename = "ietf-distributed-notif:message-publisher-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub message_publisher_id: Option<Box<[u32]>>,

    #[serde(flatten)]
    pub update_trigger: Option<UpdateTrigger>,

    #[serde(rename = "ietf-yang-push-revision:module-version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_version: Option<Box<[YangPushModuleVersion]>>,

    #[serde(rename = "ietf-yang-push-revision:yang-library-content-id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yang_library_content_id: Option<String>,
}

impl Subscription {
    /// Create a Subscription with only the required attributes
    pub fn new(id: SubscriptionId, target: Target) -> Self {
        Self {
            id,
            target,
            stop_time: None,
            dscp: None,
            weighting: None,
            dependency: None,
            transport: None,
            encoding: None,
            purpose: None,
            configured_subscription_state: None,
            message_publisher_id: None,
            update_trigger: None,
            module_version: None,
            yang_library_content_id: None,
        }
    }
}

/// Subscription target as defined in RFC 8639 and RFC 8641.
///
/// A subscription can target either an event stream (RFC 8639) or a datastore
/// (RFC 8641).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum Target {
    Stream(StreamTarget),
    Datastore(DatastoreTarget),
}

/// Stream subscription target as defined in RFC 8639.
///
/// Specifies which event stream to subscribe to and how to filter events.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct StreamTarget {
    /// Name of the event stream
    pub stream: Box<str>,

    /// Selection filter for stream events
    #[serde(flatten)]
    pub filter: StreamSelectionFilterObjects,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_start_time: Option<DateTime<Utc>>,

    /// Skipped if value is false
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub configured_reply: bool,
}

/// Datastore subscription target as defined in RFC 8641.
///
/// Specifies which datastore to subscribe to, how to filter the data,
/// and when/how updates should be triggered.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct DatastoreTarget {
    /// Datastore, from which to retrieve data (e.g., operational, running)
    #[serde(rename = "ietf-yang-push:datastore", alias = "datastore")]
    pub datastore: DatastoreName,

    /// Selection filter for datastore nodes
    #[serde(flatten)]
    pub selection: DatastoreSelectionFilterObjects,
}

/// Update Trigger
/// ```text
/// UpdateTrigger
/// ├── Periodic
/// │   ├── period: CentiSeconds (update interval in 1/100 seconds)
/// │   └── anchor-time: DateTime (optional reference time)
/// │
/// └── OnChange
///     ├── dampening-period: CentiSeconds (minimum time between updates)
///     ├── sync-on-start: bool (send initial snapshot)
///     └── excluded-change: Vec<ChangeType> (filter change types)
///         ├── Create
///         ├── Delete
///         ├── Insert
///         ├── Move
///         └── Replace
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

// DatastoreTarget XML serialization
impl XmlSerialize for DatastoreTarget {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_PUSH_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_PUSH_NS, "".to_string())]))?;
        }
        let (ns, name): (Box<str>, Box<str>) = self.datastore.clone().into();
        let mut elem = writer.create_ns_element(YANG_PUSH_NS, "datastore")?;
        elem.push_attribute(("xmlns:ds", ns.as_ref()));
        writer.write_event(Event::Start(elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(&format!("ds:{name}"))))?;
        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        self.selection.xml_serialize(writer)?;
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, DatastoreTarget> for DatastoreTarget {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(YANG_PUSH_NS), "datastore")?;
        let name: Box<str> = parser.tag_string()?.trim().into();
        let (ds_ns, ds_name) = parser.resolve_identity_ref(&name)?;
        let datastore = DatastoreName::from((ds_ns.as_str(), ds_name.as_str()));
        parser.close()?;
        let selection = DatastoreSelectionFilterObjects::xml_deserialize(parser)?;
        Ok(Self {
            datastore,
            selection,
        })
    }
}

// StreamTarget XML serialization
impl XmlSerialize for StreamTarget {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer
            .get_namespace_prefix(SUBSCRIBED_NOTIFICATIONS_NS)
            .is_none()
        {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(
                SUBSCRIBED_NOTIFICATIONS_NS,
                "".to_string(),
            )]))?;
        }

        // <stream>
        let stream_elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "stream")?;
        writer.write_event(Event::Start(stream_elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.stream.as_ref())))?;
        writer.write_event(Event::End(stream_elem.to_end()))?;

        // stream-filter (optional — ByReference or inline)
        self.filter.xml_serialize(writer)?;

        // <replay-start-time> (optional)
        if let Some(ref ts) = self.replay_start_time {
            let elem =
                writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "replay-start-time")?;
            writer.write_event(Event::Start(elem.clone()))?;
            writer.write_event(Event::Text(BytesText::new(&format_datetime(ts))))?;
            writer.write_event(Event::End(elem.to_end()))?;
        }

        // <configured-replay/> (optional empty element)
        if self.configured_reply {
            let elem =
                writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "configured-replay")?;
            writer.write_event(Event::Empty(elem))?;
        }

        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, StreamTarget> for StreamTarget {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;

        // Elements can appear in any order per XML/YANG conventions.
        let mut stream: Option<Box<str>> = None;
        let mut filter: Option<StreamSelectionFilterObjects> = None;
        let mut replay_start_time: Option<DateTime<Utc>> = None;
        let mut configured_reply = false;

        // We need to parse sibling elements. The caller already opened the
        // parent container (e.g. <subscription>), so we read children until
        // we've collected the stream target fields (or hit something we
        // don't recognise which signals the end of our scope).
        loop {
            parser.skip_text()?;
            if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream")?;
                stream = Some(parser.tag_string()?.trim().into());
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter-name")
                || parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-subtree-filter")
                || parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-xpath-filter")
            {
                filter = Some(StreamSelectionFilterObjects::xml_deserialize(parser)?);
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "replay-start-time") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "replay-start-time")?;
                let ts_str = parser.tag_string()?;
                replay_start_time = Some(
                    DateTime::parse_from_rfc3339(ts_str.trim())
                        .map_err(|e| ParsingError::InvalidValue(e.to_string()))?
                        .with_timezone(&Utc),
                );
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "configured-replay") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "configured-replay")?;
                configured_reply = true;
                parser.close()?;
            } else {
                break;
            }
        }

        let stream = stream.ok_or_else(|| ParsingError::WrongToken {
            expecting: "<stream>".to_string(),
            found: parser.peek().clone().into_owned(),
        })?;

        Ok(Self {
            stream,
            filter: filter.unwrap_or(StreamSelectionFilterObjects::ByReference("".into())),
            replay_start_time,
            configured_reply,
        })
    }
}

impl XmlSerialize for UpdateTrigger {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_PUSH_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_PUSH_NS, "".to_string())]))?;
        }
        match self {
            Self::Periodic {
                period,
                anchor_time,
            } => {
                let elem = writer.create_ns_element(YANG_PUSH_NS, "periodic")?;
                writer.write_event(Event::Start(elem.clone()))?;
                if let Some(p) = period {
                    let child = writer.create_ns_element(YANG_PUSH_NS, "period")?;
                    writer.write_event(Event::Start(child.clone()))?;
                    writer.write_event(Event::Text(BytesText::new(&p.as_u32().to_string())))?;
                    writer.write_event(Event::End(child.to_end()))?;
                }
                if let Some(ts) = anchor_time {
                    let child = writer.create_ns_element(YANG_PUSH_NS, "anchor-time")?;
                    writer.write_event(Event::Start(child.clone()))?;
                    writer.write_event(Event::Text(BytesText::new(&format_datetime(ts))))?;
                    writer.write_event(Event::End(child.to_end()))?;
                }
                writer.write_event(Event::End(elem.to_end()))?;
            }
            Self::OnChange {
                dampening_period,
                sync_on_start,
                excluded_change,
            } => {
                let elem = writer.create_ns_element(YANG_PUSH_NS, "on-change")?;
                writer.write_event(Event::Start(elem.clone()))?;
                if let Some(dp) = dampening_period {
                    let child = writer.create_ns_element(YANG_PUSH_NS, "dampening-period")?;
                    writer.write_event(Event::Start(child.clone()))?;
                    writer.write_event(Event::Text(BytesText::new(&dp.as_u32().to_string())))?;
                    writer.write_event(Event::End(child.to_end()))?;
                }
                if let Some(sync) = sync_on_start {
                    let child = writer.create_ns_element(YANG_PUSH_NS, "sync-on-start")?;
                    writer.write_event(Event::Start(child.clone()))?;
                    writer.write_event(Event::Text(BytesText::new(if *sync {
                        "true"
                    } else {
                        "false"
                    })))?;
                    writer.write_event(Event::End(child.to_end()))?;
                }
                if let Some(changes) = excluded_change {
                    for change in changes {
                        let child = writer.create_ns_element(YANG_PUSH_NS, "excluded-change")?;
                        writer.write_event(Event::Start(child.clone()))?;
                        let val = match change {
                            ChangeType::Create => "create",
                            ChangeType::Delete => "delete",
                            ChangeType::Insert => "insert",
                            ChangeType::Move => "move",
                            ChangeType::Replace => "replace",
                        };
                        writer.write_event(Event::Text(BytesText::new(val)))?;
                        writer.write_event(Event::End(child.to_end()))?;
                    }
                }
                writer.write_event(Event::End(elem.to_end()))?;
            }
        }
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, UpdateTrigger> for UpdateTrigger {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        if parser.is_tag(Some(YANG_PUSH_NS), "periodic") {
            parser.open(Some(YANG_PUSH_NS), "periodic")?;
            let mut period = None;
            let mut anchor_time = None;
            loop {
                parser.skip_text()?;
                if parser.is_tag(Some(YANG_PUSH_NS), "period") {
                    parser.open(Some(YANG_PUSH_NS), "period")?;
                    let v: u32 = parser.tag_string()?.trim().parse().map_err(
                        |e: std::num::ParseIntError| ParsingError::InvalidValue(e.to_string()),
                    )?;
                    period = Some(CentiSeconds::new(v));
                    parser.close()?;
                } else if parser.is_tag(Some(YANG_PUSH_NS), "anchor-time") {
                    parser.open(Some(YANG_PUSH_NS), "anchor-time")?;
                    anchor_time = Some(parse_datetime(&parser.tag_string()?)?);
                    parser.close()?;
                } else {
                    // Unknown child or end of container — stop
                    break;
                }
            }
            parser.close()?;
            Ok(Self::Periodic {
                period,
                anchor_time,
            })
        } else if parser.is_tag(Some(YANG_PUSH_NS), "on-change") {
            parser.open(Some(YANG_PUSH_NS), "on-change")?;
            let mut dampening_period = None;
            let mut sync_on_start = None;
            let mut excluded_change: Option<Vec<ChangeType>> = None;
            loop {
                parser.skip_text()?;
                if parser.is_tag(Some(YANG_PUSH_NS), "dampening-period") {
                    parser.open(Some(YANG_PUSH_NS), "dampening-period")?;
                    let v: u32 = parser.tag_string()?.trim().parse().map_err(
                        |e: std::num::ParseIntError| ParsingError::InvalidValue(e.to_string()),
                    )?;
                    dampening_period = Some(CentiSeconds::new(v));
                    parser.close()?;
                } else if parser.is_tag(Some(YANG_PUSH_NS), "sync-on-start") {
                    parser.open(Some(YANG_PUSH_NS), "sync-on-start")?;
                    let val = parser.tag_string()?;
                    sync_on_start = Some(val.trim() == "true");
                    parser.close()?;
                } else if parser.is_tag(Some(YANG_PUSH_NS), "excluded-change") {
                    parser.open(Some(YANG_PUSH_NS), "excluded-change")?;
                    let val = parser.tag_string()?;
                    let change = match val.trim() {
                        "create" => ChangeType::Create,
                        "delete" => ChangeType::Delete,
                        "insert" => ChangeType::Insert,
                        "move" => ChangeType::Move,
                        "replace" => ChangeType::Replace,
                        other => {
                            return Err(ParsingError::InvalidValue(other.to_string()));
                        }
                    };
                    excluded_change.get_or_insert_with(Vec::new).push(change);
                    parser.close()?;
                } else {
                    break;
                }
            }
            parser.close()?;
            Ok(Self::OnChange {
                dampening_period,
                sync_on_start,
                excluded_change,
            })
        } else {
            Err(ParsingError::WrongToken {
                expecting: "<periodic> or <on-change>".to_string(),
                found: parser.peek().clone().into_owned(),
            })
        }
    }
}

impl XmlSerialize for Subscription {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer
            .get_namespace_prefix(SUBSCRIBED_NOTIFICATIONS_NS)
            .is_none()
        {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(
                SUBSCRIBED_NOTIFICATIONS_NS,
                "".to_string(),
            )]))?;
        }
        let elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "subscription")?;
        writer.write_event(Event::Start(elem.clone()))?;

        // <id> (mandatory)
        let id_elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "id")?;
        writer.write_event(Event::Start(id_elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(&self.id.to_string())))?;
        writer.write_event(Event::End(id_elem.to_end()))?;

        // target (choice: stream / datastore) — flat children
        match &self.target {
            Target::Stream(stream_target) => stream_target.xml_serialize(writer)?,
            Target::Datastore(ds_target) => ds_target.xml_serialize(writer)?,
        }

        // <stop-time>
        if let Some(ref ts) = self.stop_time {
            let child = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "stop-time")?;
            writer.write_event(Event::Start(child.clone()))?;
            writer.write_event(Event::Text(BytesText::new(&format_datetime(ts))))?;
            writer.write_event(Event::End(child.to_end()))?;
        }

        // <dscp>
        if let Some(dscp) = self.dscp {
            let child = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "dscp")?;
            writer.write_event(Event::Start(child.clone()))?;
            writer.write_event(Event::Text(BytesText::new(&dscp.to_string())))?;
            writer.write_event(Event::End(child.to_end()))?;
        }

        // <weighting>
        if let Some(w) = self.weighting {
            let child = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "weighting")?;
            writer.write_event(Event::Start(child.clone()))?;
            writer.write_event(Event::Text(BytesText::new(&w.to_string())))?;
            writer.write_event(Event::End(child.to_end()))?;
        }

        // <dependency>
        if let Some(dep) = self.dependency {
            let child = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "dependency")?;
            writer.write_event(Event::Start(child.clone()))?;
            writer.write_event(Event::Text(BytesText::new(&dep.to_string())))?;
            writer.write_event(Event::End(child.to_end()))?;
        }

        // <transport>
        if let Some(ref t) = self.transport {
            t.xml_serialize(writer)?;
        }

        // <encoding>
        if let Some(ref enc) = self.encoding {
            enc.xml_serialize(writer)?;
        }

        // <purpose>
        xml_write_optional_text_leaf(
            writer,
            SUBSCRIBED_NOTIFICATIONS_NS,
            "purpose",
            self.purpose.as_deref(),
        )?;

        // <configured-subscription-state> (read-only)
        if let Some(ref state) = self.configured_subscription_state {
            state.xml_serialize(writer)?;
        }

        // <message-publisher-id> (from ietf-distributed-notif, different NS)
        if let Some(message_publisher_ids) = &self.message_publisher_id {
            let mut dn_ns_added = false;
            if writer.get_namespace_prefix(DISTRIBUTED_NOTIF_NS).is_none() {
                dn_ns_added = true;
                writer.push_namespace_binding(IndexMap::from([(
                    DISTRIBUTED_NOTIF_NS,
                    "dn".to_string(),
                )]))?;
            }
            for mpid in message_publisher_ids {
                let child =
                    writer.create_ns_element(DISTRIBUTED_NOTIF_NS, "message-publisher-id")?;
                writer.write_event(Event::Start(child.clone()))?;
                writer.write_event(Event::Text(BytesText::new(&mpid.to_string())))?;
                writer.write_event(Event::End(child.to_end()))?;
            }
            if dn_ns_added {
                writer.pop_namespace_binding();
            }
        }

        // update-trigger (choice: periodic / on-change)
        if let Some(ref trigger) = self.update_trigger {
            trigger.xml_serialize(writer)?;
        }

        // ypr:module-version
        if let Some(module_version) = self.module_version.as_deref() {
            for module_version in module_version {
                module_version.xml_serialize(writer)?;
            }
        }

        // ypr:yang-library-content-id
        if let Some(yang_library_content_id) = self.yang_library_content_id.as_deref() {
            let mut ns_added = false;
            if writer.get_namespace_prefix(YANG_PUSH_REVISION).is_none() {
                ns_added = true;
                writer.push_namespace_binding(IndexMap::from([(
                    YANG_PUSH_REVISION,
                    "ypr".to_string(),
                )]))?;
            }
            let child = writer.create_ns_element(YANG_PUSH_REVISION, "yang-library-content-id")?;
            writer.write_event(Event::Start(child.clone()))?;
            writer.write_event(Event::Text(BytesText::new(yang_library_content_id)))?;
            writer.write_event(Event::End(child.to_end()))?;

            if ns_added {
                writer.pop_namespace_binding();
            }
        }

        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, Subscription> for Subscription {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "subscription")?;

        let mut id: Option<SubscriptionId> = None;
        let mut stop_time = None;
        let mut dscp = None;
        let mut weighting = None;
        let mut dependency = None;
        let mut transport = None;
        let mut encoding = None;
        let mut purpose = None;
        let mut configured_subscription_state = None;
        let mut message_publisher_ids: Option<Vec<u32>> = None;
        let mut update_trigger = None;
        let mut module_versions: Option<Vec<YangPushModuleVersion>> = None;
        let mut yang_library_content_id = None;

        // Target pieces — collected separately because XML elements can
        // appear in any order and the target choice children are interleaved
        // with other subscription leaves.
        // Stream target pieces:
        let mut stream_name: Option<Box<str>> = None;
        let mut stream_filter: Option<StreamSelectionFilterObjects> = None;
        let mut replay_start_time: Option<DateTime<Utc>> = None;
        let mut configured_replay = false;
        // Datastore target pieces:
        let mut ds_datastore: Option<DatastoreName> = None;
        let mut ds_selection: Option<DatastoreSelectionFilterObjects> = None;

        loop {
            parser.skip_text()?;

            // Check for closing </subscription>
            if matches!(parser.peek(), Event::End(_)) {
                break;
            }
            if matches!(parser.peek(), Event::Eof) {
                return Err(ParsingError::Eof);
            }

            // ── ietf-subscribed-notifications elements ──────────────────
            if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "id") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "id")?;
                id = Some(parser.tag_string()?.trim().parse().map_err(
                    |e: std::num::ParseIntError| ParsingError::InvalidValue(e.to_string()),
                )?);
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stop-time") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stop-time")?;
                stop_time = Some(parse_datetime(&parser.tag_string()?)?);
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "dscp") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "dscp")?;
                dscp = Some(parser.tag_string()?.trim().parse().map_err(
                    |e: std::num::ParseIntError| ParsingError::InvalidValue(e.to_string()),
                )?);
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "weighting") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "weighting")?;
                weighting = Some(parser.tag_string()?.trim().parse().map_err(
                    |e: std::num::ParseIntError| ParsingError::InvalidValue(e.to_string()),
                )?);
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "dependency") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "dependency")?;
                dependency = Some(parser.tag_string()?.trim().parse().map_err(
                    |e: std::num::ParseIntError| ParsingError::InvalidValue(e.to_string()),
                )?);
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "transport") {
                transport = Some(Transport::xml_deserialize(parser)?);
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "encoding") {
                encoding = Some(Encoding::xml_deserialize(parser)?);
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "purpose") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "purpose")?;
                purpose = Some(parser.tag_string()?.trim().into());
                parser.close()?;
            } else if parser.is_tag(
                Some(SUBSCRIBED_NOTIFICATIONS_NS),
                "configured-subscription-state",
            ) {
                configured_subscription_state =
                    Some(ConfiguredSubscriptionState::xml_deserialize(parser)?);
            }
            // ── Stream target children ──────────────────────────────────
            else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream")?;
                stream_name = Some(parser.tag_string()?.trim().into());
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter-name") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter-name")?;
                stream_filter = Some(StreamSelectionFilterObjects::ByReference(
                    parser.tag_string()?,
                ));
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-subtree-filter")
                || parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-xpath-filter")
            {
                stream_filter = Some(StreamSelectionFilterObjects::WithInSubscription(
                    StreamFilterSpec::xml_deserialize(parser)?,
                ));
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "replay-start-time") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "replay-start-time")?;
                replay_start_time = Some(parse_datetime(&parser.tag_string()?)?);
                parser.close()?;
            } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "configured-replay") {
                parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "configured-replay")?;
                configured_replay = true;
                parser.close()?;
            }
            // ── Datastore target children ───────────────────────────────
            else if parser.is_tag(Some(YANG_PUSH_NS), "datastore") {
                parser.open(Some(YANG_PUSH_NS), "datastore")?;
                let name: Box<str> = parser.tag_string()?.trim().into();
                let (ds_ns, ds_name) = parser.resolve_identity_ref(&name)?;
                let ds = DatastoreName::from((ds_ns.as_str(), ds_name.as_str()));
                parser.close()?;
                ds_datastore = Some(ds);
            } else if parser.is_tag(Some(YANG_PUSH_NS), "selection-filter-ref") {
                parser.open(Some(YANG_PUSH_NS), "selection-filter-ref")?;
                ds_selection = Some(DatastoreSelectionFilterObjects::ByReference(
                    parser.tag_string()?,
                ));
                parser.close()?;
            } else if parser.is_tag(Some(YANG_PUSH_NS), "datastore-subtree-filter")
                || parser.is_tag(Some(YANG_PUSH_NS), "datastore-xpath-filter")
            {
                ds_selection = Some(DatastoreSelectionFilterObjects::WithInSubscription(
                    DatastoreFilterSpec::xml_deserialize(parser)?,
                ));
            }
            // ── yang-push update trigger ────────────────────────────────
            else if parser.is_tag(Some(YANG_PUSH_NS), "periodic")
                || parser.is_tag(Some(YANG_PUSH_NS), "on-change")
            {
                update_trigger = Some(UpdateTrigger::xml_deserialize(parser)?);
            }
            // ── ietf-distributed-notif augmentation ─────────────────────
            else if parser.is_tag(Some(DISTRIBUTED_NOTIF_NS), "message-publisher-id") {
                parser.open(Some(DISTRIBUTED_NOTIF_NS), "message-publisher-id")?;
                let message_publisher_id =
                    parser
                        .tag_string()?
                        .trim()
                        .parse()
                        .map_err(|e: std::num::ParseIntError| {
                            ParsingError::InvalidValue(e.to_string())
                        })?;
                if let Some(ref mut ids) = message_publisher_ids {
                    ids.push(message_publisher_id);
                } else {
                    message_publisher_ids = Some(vec![message_publisher_id]);
                }
                parser.close()?;
            }
            // ietf-yang-push-revision:module-version
            else if parser.is_tag(Some(YANG_PUSH_REVISION), "module-version") {
                let module_version = YangPushModuleVersion::xml_deserialize(parser)?;
                if let Some(ref mut versions) = module_versions {
                    versions.push(module_version);
                } else {
                    module_versions = Some(vec![module_version]);
                }
            }
            // ietf-yang-push-revision:yang-library-content-id
            else if parser.is_tag(Some(YANG_PUSH_REVISION), "yang-library-content-id") {
                parser.open(Some(YANG_PUSH_REVISION), "yang-library-content-id")?;
                yang_library_content_id = Some(parser.tag_string()?.trim().into());
                parser.close()?;
            }
            // ── Unknown / augmented element — skip gracefully ───────────
            else {
                parser.skip()?;
            }
        }
        parser.close()?; // </subscription>

        let id = id.ok_or_else(|| ParsingError::WrongToken {
            expecting: "<id>".to_string(),
            found: Event::Eof.into_owned(),
        })?;

        // Assemble the target from collected pieces.
        // Determine which target type based on which pieces were collected.
        let target = if let Some(ds) = ds_datastore {
            // Datastore target — <datastore> was present
            Target::Datastore(DatastoreTarget {
                datastore: ds,
                selection: ds_selection
                    .unwrap_or(DatastoreSelectionFilterObjects::ByReference("".into())),
            })
        } else if ds_selection.is_some() {
            // Datastore filter was found but no <datastore> — malformed, but
            // best-effort: treat as datastore with unknown store.
            return Err(ParsingError::WrongToken {
                expecting: "<datastore> (required for datastore target)".to_string(),
                found: Event::Eof.into_owned(),
            });
        } else if let Some(stream) = stream_name {
            Target::Stream(StreamTarget {
                stream,
                filter: stream_filter
                    .unwrap_or(StreamSelectionFilterObjects::ByReference("".into())),
                replay_start_time,
                configured_reply: configured_replay,
            })
        } else {
            return Err(ParsingError::WrongToken {
                expecting: "<stream> or <datastore> (target choice)".to_string(),
                found: Event::Eof.into_owned(),
            });
        };

        Ok(Self {
            id,
            target,
            stop_time,
            dscp,
            weighting,
            dependency,
            transport,
            encoding,
            purpose,
            configured_subscription_state,
            message_publisher_id: message_publisher_ids.map(|x| x.into_boxed_slice()),
            update_trigger,
            module_version: module_versions.map(|x| x.into_boxed_slice()),
            yang_library_content_id,
        })
    }
}

/// Selection filter objects for datastore subscriptions (RFC 8641).
///
/// Filters can be specified by reference to a pre-configured filter,
/// or inline within the subscription.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum DatastoreSelectionFilterObjects {
    /// Reference to a pre-configured filter
    ByReference(Box<str>),

    /// Filter specified within the subscription
    WithInSubscription(DatastoreFilterSpec),
}

// DatastoreSelectionFilterObjects XML serialization
impl XmlSerialize for DatastoreSelectionFilterObjects {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        match self {
            Self::ByReference(filter_name) => {
                let mut ns_added = false;
                if writer.get_namespace_prefix(YANG_PUSH_NS).is_none() {
                    ns_added = true;
                    writer
                        .push_namespace_binding(IndexMap::from([(YANG_PUSH_NS, "".to_string())]))?;
                }
                let elem = writer.create_ns_element(YANG_PUSH_NS, "selection-filter-ref")?;
                writer.write_event(Event::Start(elem.clone()))?;
                writer.write_event(Event::Text(BytesText::new(filter_name.as_ref())))?;
                writer.write_event(Event::End(elem.to_end()))?;
                if ns_added {
                    writer.pop_namespace_binding();
                }
            }
            Self::WithInSubscription(filter_spec) => {
                filter_spec.xml_serialize(writer)?;
            }
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, DatastoreSelectionFilterObjects> for DatastoreSelectionFilterObjects {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;

        if parser.is_tag(Some(YANG_PUSH_NS), "selection-filter-ref") {
            parser.open(Some(YANG_PUSH_NS), "selection-filter-ref")?;
            let filter_name = parser.tag_string()?;
            parser.close()?;
            Ok(Self::ByReference(filter_name))
        } else {
            Ok(Self::WithInSubscription(
                DatastoreFilterSpec::xml_deserialize(parser)?,
            ))
        }
    }
}

/// Module Versioning (draft-ietf-netconf-yang-notifications-versioning)
///
/// The `YangPushModuleVersion` structure provides information about YANG
/// modules:
/// - `name`: Module name
/// - `revision`: Module revision date (e.g., "2025-04-25")
/// - `version`: Semantic version label
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub struct YangPushModuleVersion {
    /// Alias 'module-name' still supported
    /// (draft-ietf-netconf-yang-notifications-versioning < 9)
    #[serde(alias = "module-name")]
    pub name: Box<str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<Box<str>>,

    /// Alias 'revision-label' still supported
    /// (draft-ietf-netconf-yang-notifications-versioning < 9)
    #[serde(alias = "revision-label")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<Box<str>>,
}

impl YangPushModuleVersion {
    pub const fn new(
        name: Box<str>,
        revision: Option<Box<str>>,
        version: Option<Box<str>>,
    ) -> Self {
        Self {
            name,
            revision,
            version,
        }
    }
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl XmlSerialize for YangPushModuleVersion {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_PUSH_REVISION).is_none() {
            ns_added = true;
            writer
                .push_namespace_binding(IndexMap::from([(YANG_PUSH_REVISION, "".to_string())]))?;
        }
        let module_version_start =
            writer.create_ns_element(YANG_PUSH_REVISION, "module-version")?;
        writer.write_event(Event::Start(module_version_start.clone()))?;
        let name_start = writer.create_ns_element(YANG_PUSH_REVISION, "name")?;

        writer.write_event(Event::Start(name_start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.name.as_ref())))?;
        writer.write_event(Event::End(name_start.to_end()))?;

        if let Some(revision) = &self.revision {
            let revision_start = writer.create_ns_element(YANG_PUSH_REVISION, "revision")?;
            writer.write_event(Event::Start(revision_start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(revision.as_ref())))?;
            writer.write_event(Event::End(revision_start.to_end()))?;
        }
        if let Some(version) = &self.version {
            let version_start = writer.create_ns_element(YANG_PUSH_REVISION, "version")?;
            writer.write_event(Event::Start(version_start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(version.as_ref())))?;
            writer.write_event(Event::End(version_start.to_end()))?;
        }
        writer.write_event(Event::End(module_version_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl XmlDeserialize<'_, YangPushModuleVersion> for YangPushModuleVersion {
    fn xml_deserialize(parser: &mut XmlParser<'_, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let module_version_start = parser.open(Some(YANG_PUSH_REVISION), "module-version")?;

        let mut revision: Option<Box<str>> = None;
        let mut version: Option<Box<str>> = None;

        parser.skip_text()?;
        parser.open(Some(YANG_PUSH_REVISION), "name")?;
        let name = parser.tag_string()?.trim().into();
        parser.close()?;

        parser.skip_text()?;
        if parser.is_tag(Some(YANG_PUSH_REVISION), "revision") {
            parser.open(Some(YANG_PUSH_REVISION), "revision")?;
            revision = Some(parser.tag_string()?.trim().into());
            parser.close()?;
        }
        parser.skip_text()?;
        if parser.is_tag(Some(YANG_PUSH_REVISION), "version") {
            parser.open(Some(YANG_PUSH_REVISION), "version")?;
            version = Some(parser.tag_string()?.trim().into());
            parser.close()?;
        }
        while parser.peek() != &Event::End(module_version_start.to_end()) {
            // skip any augmentation
            parser.skip()?;
        }
        parser.close()?; // </module-version>

        Ok(Self {
            name,
            revision,
            version,
        })
    }
}
