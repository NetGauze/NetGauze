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

//! Filter types for YANG-Push and Subscribed Notifications.
//!
//! Provides datastore selection filters ([RFC 8641]) and stream event filters
//! ([RFC 8639]) in both XPath 1.0 and subtree variants, as well as the
//! top-level [`Filters`] container that holds reusable named filters.
//!
//! Each filter type implements [XmlSerialize] and [XmlDeserialize] for NETCONF
//! XML round-tripping.

use crate::xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
use crate::yang_push::{SUBSCRIBED_NOTIFICATIONS_NS, YANG_PUSH_NS};
use indexmap::map::IndexMap;
use quick_xml::events::{BytesText, Event};
use quick_xml::name::Namespace;
use serde::{Deserialize, Serialize};
use std::io;

/// Contains a list of configurable filters that can be applied to
/// subscriptions. This facilitates the reuse of complex filters once defined.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename = "ietf-subscribed-notifications:filters")]
pub struct Filters {
    #[serde(rename = "ietf-subscribed-notifications:stream-filters")]
    pub stream_filters: IndexMap<Box<str>, StreamFilter>,

    #[serde(rename = "ietf-yang-push:selection-filters")]
    pub selection_filters: IndexMap<Box<str>, SelectionFilter>,
}

impl Filters {
    pub fn new<D: IntoIterator<Item = SelectionFilter>, S: IntoIterator<Item = StreamFilter>>(
        stream_filters: S,
        selection_filters: D,
    ) -> Self {
        let selection_filters = selection_filters
            .into_iter()
            .map(|f| (f.filter_id.clone(), f))
            .collect();
        let stream_filters = stream_filters
            .into_iter()
            .map(|f| (f.name.clone(), f))
            .collect();
        Self {
            stream_filters,
            selection_filters,
        }
    }
}

impl XmlSerialize for Filters {
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
        let elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "filters")?;
        writer.write_event(Event::Start(elem.clone()))?;
        for v in self.stream_filters.values() {
            v.xml_serialize(writer)?;
        }
        for v in self.selection_filters.values() {
            v.xml_serialize(writer)?;
        }
        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl XmlDeserialize<'_, Filters> for Filters {
    fn xml_deserialize(parser: &mut XmlParser<'_, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let filters_start = parser
            .is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "filters")
            .then(|| parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "filters"))
            .ok_or_else(|| ParsingError::WrongToken {
                expecting: "<filters>".to_string(),
                found: parser.peek().clone().into_owned(),
            })??;
        parser.skip_text()?;
        let mut stream_filters = Vec::new();
        let mut selection_filters = Vec::new();
        parser.skip_text()?;
        while parser.peek() != &Event::End(filters_start.to_end()) {
            if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter") {
                let stream_filter = StreamFilter::xml_deserialize(parser)?;
                stream_filters.push(stream_filter);
            } else if parser.is_tag(Some(YANG_PUSH_NS), "selection-filter") {
                let selection_filter = SelectionFilter::xml_deserialize(parser)?;
                selection_filters.push(selection_filter);
            } else {
                // Could be an IETF or vendor-specific extension that we don't understand,
                // skip it
                parser.skip()?;
            }
            parser.skip_text()?;
        }
        parser.skip_text()?;
        parser.close()?;
        Ok(Self::new(stream_filters, selection_filters))
    }
}

/// This grouping defines the types of selectors for objects from a datastore.
///
/// See RFC 8641
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename = "ietf-yang-push:selection-filters")]
pub struct SelectionFilter {
    #[serde(rename = "filter-id")]
    pub filter_id: Box<str>,

    #[serde(rename = "filter-spec")]
    pub filter_spec: DatastoreFilterSpec,
}

impl XmlSerialize for SelectionFilter {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_PUSH_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_PUSH_NS, "".to_string())]))?;
        }
        let elem = writer.create_ns_element(YANG_PUSH_NS, "selection-filter")?;
        writer.write_event(Event::Start(elem.clone()))?;

        let filter_id_elem = writer.create_ns_element(YANG_PUSH_NS, "filter-id")?;
        writer.write_event(Event::Start(filter_id_elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.filter_id.as_ref())))?;
        writer.write_event(Event::End(filter_id_elem.to_end()))?;

        self.filter_spec.xml_serialize(writer)?;

        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, SelectionFilter> for SelectionFilter {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let _ = parser
            .is_tag(Some(YANG_PUSH_NS), "selection-filter")
            .then(|| parser.open(Some(YANG_PUSH_NS), "selection-filter"))
            .ok_or_else(|| ParsingError::WrongToken {
                expecting: "<selection-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })??;
        parser.skip_text()?;
        let (filter_id, filter_spec) = if parser.is_tag(Some(YANG_PUSH_NS), "filter-id") {
            parser.open(Some(YANG_PUSH_NS), "filter-id")?;
            let filter_id = parser.tag_string()?.trim().into();
            parser.close()?;
            parser.skip_text()?;
            let spec = DatastoreFilterSpec::xml_deserialize(parser)?;
            (filter_id, spec)
        } else {
            let spec = DatastoreFilterSpec::xml_deserialize(parser)?;
            parser.skip_text()?;
            parser.open(Some(YANG_PUSH_NS), "filter-id")?;
            let filter_id = parser.tag_string()?.trim().into();
            parser.close()?;
            (filter_id, spec)
        };
        parser.skip_text()?;
        parser.close()?;
        Ok(Self {
            filter_id,
            filter_spec,
        })
    }
}

/// This grouping defines the base for filters applied to event streams.
///
/// See RFC 8639
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename = "ietf-subscribed-notifications:stream-filter")]
pub struct StreamFilter {
    pub name: Box<str>,
    #[serde(rename = "filter-spec")]
    pub filter_spec: StreamFilterSpec,
}

impl StreamFilter {
    pub const fn new(name: Box<str>, filter_spec: StreamFilterSpec) -> Self {
        Self { name, filter_spec }
    }
}

impl XmlSerialize for StreamFilter {
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
        let elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "stream-filter")?;
        writer.write_event(Event::Start(elem.clone()))?;

        let name_elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "name")?;
        writer.write_event(Event::Start(name_elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.name.as_ref())))?;
        writer.write_event(Event::End(name_elem.to_end()))?;

        self.filter_spec.xml_serialize(writer)?;

        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, StreamFilter> for StreamFilter {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let _ = parser
            .is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter")
            .then(|| parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter"))
            .ok_or_else(|| ParsingError::WrongToken {
                expecting: "<stream-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })??;
        parser.skip_text()?;
        let (name, filter_spec) = if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "name") {
            parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "name")?;
            let name = parser.tag_string()?.trim().into();
            parser.close()?;
            parser.skip_text()?;
            let spec = StreamFilterSpec::xml_deserialize(parser)?;
            (name, spec)
        } else {
            let spec = StreamFilterSpec::xml_deserialize(parser)?;
            parser.skip_text()?;
            parser.open(Some(YANG_PUSH_NS), "name")?;
            let name = parser.tag_string()?.trim().into();
            parser.close()?;
            (name, spec)
        };
        parser.skip_text()?;
        parser.close()?;
        Ok(Self { name, filter_spec })
    }
}

/// Datastore filter specification (RFC 8641).
///
/// Supports either subtree or XPath filtering.
///
/// Note, DatastoreFilterSpec keeps all the namespaces in scope that are used in
/// the filter along with the prefix mapping.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum DatastoreFilterSpec {
    Subtree(DatastoreSubtreeFilter),
    Xpath(DatastoreXPathFilter),
}

impl DatastoreFilterSpec {
    pub fn namespaces(&self) -> &[(Box<str>, Box<str>)] {
        match self {
            Self::Subtree(subtree) => &subtree.namespaces,
            Self::Xpath(xpath) => &xpath.namespaces,
        }
    }
}

impl XmlSerialize for DatastoreFilterSpec {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        match self {
            Self::Subtree(subtree) => {
                subtree.xml_serialize(writer)?;
            }
            Self::Xpath(xpath) => {
                xpath.xml_serialize(writer)?;
            }
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, DatastoreFilterSpec> for DatastoreFilterSpec {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        if parser.is_tag(Some(YANG_PUSH_NS), "datastore-subtree-filter") {
            let subtree = DatastoreSubtreeFilter::xml_deserialize(parser)?;
            Ok(Self::Subtree(subtree))
        } else if parser.is_tag(Some(YANG_PUSH_NS), "datastore-xpath-filter") {
            let xpath = DatastoreXPathFilter::xml_deserialize(parser)?;
            Ok(Self::Xpath(xpath))
        } else {
            Err(ParsingError::WrongToken {
                expecting: "<datastore-subtree-filter> or <datastore-xpath-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })
        }
    }
}

/// XPath 1.0 filter expression.
/// Namespace: prefix → namespace
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename = "ietf-yang-push:datastore-xpath-filter")]
pub struct DatastoreXPathFilter {
    pub namespaces: Box<[(Box<str>, Box<str>)]>,
    pub path: Box<str>,
}

impl XmlSerialize for DatastoreXPathFilter {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        let mut new_namespaces: IndexMap<Namespace<'_>, String> =
            IndexMap::with_capacity(self.namespaces.len() + 1);
        for (prefix, namespace) in &self.namespaces {
            let ns = Namespace(namespace.as_bytes());
            new_namespaces.insert(ns, prefix.clone().into());
        }
        if writer.get_namespace_prefix(YANG_PUSH_NS).is_none()
            && !new_namespaces.contains_key(&YANG_PUSH_NS)
        {
            new_namespaces.insert(YANG_PUSH_NS, "".to_string());
        }
        if !new_namespaces.is_empty() {
            ns_added = true;
            writer.push_namespace_binding(new_namespaces.to_owned())?;
        }
        let elem = writer.create_ns_element(YANG_PUSH_NS, "datastore-xpath-filter")?;
        writer.write_event(Event::Start(elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.path.as_ref())))?;
        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, DatastoreXPathFilter> for DatastoreXPathFilter {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser
            .is_tag(Some(YANG_PUSH_NS), "datastore-xpath-filter")
            .then(|| parser.open(Some(YANG_PUSH_NS), "datastore-xpath-filter"))
            .ok_or_else(|| ParsingError::WrongToken {
                expecting: "<datastore-xpath-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })??;
        let (path, namespaces) = parser.read_xpath_with_namespaces()?;
        parser.close()?;
        Ok(Self {
            namespaces: namespaces
                .into_iter()
                .map(|(prefix, ns)| (prefix.into_boxed_str(), ns.into_boxed_str()))
                .collect(),
            path: path.trim().into(),
        })
    }
}

/// Subtree filter (RFC 6241 Section 6).
/// Namespace: prefix → namespace
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename = "ietf-yang-push:datastore-subtree-filter")]
pub struct DatastoreSubtreeFilter {
    pub namespaces: Box<[(Box<str>, Box<str>)]>,
    pub subtree: Box<str>,
}

impl XmlSerialize for DatastoreSubtreeFilter {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        let mut new_namespaces: IndexMap<Namespace<'_>, String> =
            IndexMap::with_capacity(self.namespaces.len() + 1);
        for (prefix, namespace) in &self.namespaces {
            let ns = Namespace(namespace.as_bytes());
            new_namespaces.insert(ns, prefix.clone().into());
        }
        if writer.get_namespace_prefix(YANG_PUSH_NS).is_none()
            && !new_namespaces.contains_key(&YANG_PUSH_NS)
        {
            new_namespaces.insert(YANG_PUSH_NS, "".to_string());
        }
        if !new_namespaces.is_empty() {
            ns_added = true;
            writer.push_namespace_binding(new_namespaces.to_owned())?;
        }
        let elem = writer.create_ns_element(YANG_PUSH_NS, "datastore-subtree-filter")?;
        writer.write_event(Event::Start(elem.clone()))?;
        // For subtree filters, write raw XML content
        writer.write_all(self.subtree.as_bytes())?;
        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, DatastoreSubtreeFilter> for DatastoreSubtreeFilter {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser
            .is_tag(Some(YANG_PUSH_NS), "datastore-subtree-filter")
            .then(|| parser.open(Some(YANG_PUSH_NS), "datastore-subtree-filter"))
            .ok_or_else(|| ParsingError::WrongToken {
                expecting: "<datastore-subtree-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })??;
        let subtree = parser.copy_buffer_till_with_namespaces(b"datastore-subtree-filter")?;

        parser.close()?;
        Ok(Self {
            namespaces: subtree
                .namespaces
                .into_iter()
                .map(|(prefix, ns)| (prefix.into_boxed_str(), ns.into_boxed_str()))
                .collect(),
            subtree: subtree.xml.trim().into(),
        })
    }
}

/// Stream filter specification (RFC 8639).
///
/// Supports either subtree or XPath filtering.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum StreamFilterSpec {
    /// Subtree filter (RFC 6241 Section 6)
    Subtree(StreamSubtreeFilter),

    /// XPath 1.0 filter expression
    Xpath(StreamXPathFilter),
}

impl StreamFilterSpec {
    pub fn namespaces(&self) -> &[(Box<str>, Box<str>)] {
        match self {
            Self::Subtree(subtree) => &subtree.namespaces,
            Self::Xpath(xpath) => &xpath.namespaces,
        }
    }
}

impl XmlSerialize for StreamFilterSpec {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        match self {
            Self::Subtree(subtree) => {
                subtree.xml_serialize(writer)?;
            }
            Self::Xpath(xpath) => {
                xpath.xml_serialize(writer)?;
            }
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, StreamFilterSpec> for StreamFilterSpec {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-subtree-filter") {
            let subtree = StreamSubtreeFilter::xml_deserialize(parser)?;
            Ok(Self::Subtree(subtree))
        } else if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-xpath-filter") {
            let xpath = StreamXPathFilter::xml_deserialize(parser)?;
            Ok(Self::Xpath(xpath))
        } else {
            Err(ParsingError::WrongToken {
                expecting: "<stream-subtree-filter> or <stream-xpath-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })
        }
    }
}

/// XPath 1.0 filter expression.
/// Namespace: prefix → namespace
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename = "ietf-subscribed-notifications:stream-xpath-filter")]
pub struct StreamXPathFilter {
    pub namespaces: Box<[(Box<str>, Box<str>)]>,
    pub path: Box<str>,
}

impl XmlSerialize for StreamXPathFilter {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        let mut new_namespaces: IndexMap<Namespace<'_>, String> =
            IndexMap::with_capacity(self.namespaces.len() + 1);
        for (prefix, namespace) in &self.namespaces {
            let ns = Namespace(namespace.as_bytes());
            new_namespaces.insert(ns, prefix.clone().into());
        }
        if writer
            .get_namespace_prefix(SUBSCRIBED_NOTIFICATIONS_NS)
            .is_none()
            && !new_namespaces.contains_key(&SUBSCRIBED_NOTIFICATIONS_NS)
        {
            new_namespaces.insert(SUBSCRIBED_NOTIFICATIONS_NS, "".to_string());
        }
        if !new_namespaces.is_empty() {
            ns_added = true;
            writer.push_namespace_binding(new_namespaces.to_owned())?;
        }
        let elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "stream-xpath-filter")?;
        writer.write_event(Event::Start(elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.path.as_ref())))?;
        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, StreamXPathFilter> for StreamXPathFilter {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser
            .is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-xpath-filter")
            .then(|| parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-xpath-filter"))
            .ok_or_else(|| ParsingError::WrongToken {
                expecting: "<stream-xpath-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })??;
        let (path, namespaces) = parser.read_xpath_with_namespaces()?;
        parser.close()?;
        Ok(Self {
            namespaces: namespaces
                .into_iter()
                .map(|(prefix, ns)| (prefix.into_boxed_str(), ns.into_boxed_str()))
                .collect(),
            path: path.trim().into(),
        })
    }
}

/// Subtree filter (RFC 6241 Section 6).
/// Namespace: prefix → namespace
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename = "ietf-subscribed-notifications:stream-subtree-filter")]
pub struct StreamSubtreeFilter {
    pub namespaces: Box<[(Box<str>, Box<str>)]>,
    pub subtree: Box<str>,
}

impl XmlSerialize for StreamSubtreeFilter {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        let mut new_namespaces: IndexMap<Namespace<'_>, String> =
            IndexMap::with_capacity(self.namespaces.len() + 1);
        for (prefix, namespace) in &self.namespaces {
            let ns = Namespace(namespace.as_bytes());
            new_namespaces.insert(ns, prefix.clone().into());
        }
        if writer
            .get_namespace_prefix(SUBSCRIBED_NOTIFICATIONS_NS)
            .is_none()
            && !new_namespaces.contains_key(&SUBSCRIBED_NOTIFICATIONS_NS)
        {
            new_namespaces.insert(SUBSCRIBED_NOTIFICATIONS_NS, "".to_string());
        }
        if !new_namespaces.is_empty() {
            ns_added = true;
            writer.push_namespace_binding(new_namespaces.to_owned())?;
        }
        let elem =
            writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "stream-subtree-filter")?;
        writer.write_event(Event::Start(elem.clone()))?;
        // For subtree filters, write raw XML content
        writer.write_all(self.subtree.as_bytes())?;
        writer.write_event(Event::End(elem.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, StreamSubtreeFilter> for StreamSubtreeFilter {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser
            .is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-subtree-filter")
            .then(|| parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-subtree-filter"))
            .ok_or_else(|| ParsingError::WrongToken {
                expecting: "<stream-subtree-filter>".to_string(),
                found: parser.peek().clone().into_owned(),
            })??;
        let subtree = parser.copy_buffer_till_with_namespaces(b"stream-subtree-filter")?;

        parser.close()?;
        Ok(Self {
            namespaces: subtree
                .namespaces
                .into_iter()
                .map(|(prefix, ns)| (prefix.into_boxed_str(), ns.into_boxed_str()))
                .collect(),
            subtree: subtree.xml.trim().into(),
        })
    }
}

/// Selection filter objects for stream subscriptions (RFC 8639).
///
/// Filters can be specified by reference to a pre-configured filter,
/// or inline within the subscription.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum StreamSelectionFilterObjects {
    /// Reference to a pre-configured filter
    ByReference(Box<str>),

    /// Filter specified within the subscription
    WithInSubscription(StreamFilterSpec),
}

impl XmlSerialize for StreamSelectionFilterObjects {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        match self {
            Self::ByReference(filter_name) => {
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
                let elem =
                    writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "stream-filter-name")?;
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

impl<'a> XmlDeserialize<'a, StreamSelectionFilterObjects> for StreamSelectionFilterObjects {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;

        if parser.is_tag(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter-name") {
            parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "stream-filter-name")?;
            let filter_name = parser.tag_string()?;
            parser.close()?;
            Ok(Self::ByReference(filter_name))
        } else {
            Ok(Self::WithInSubscription(StreamFilterSpec::xml_deserialize(
                parser,
            )?))
        }
    }
}
