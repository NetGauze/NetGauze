// Copyright (C) 2026-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! YANG identity enumerations for subscribed notifications.
//!
//! This module maps YANG `identityref` values to Rust enums with full XML
//! serialization/deserialization support.
//!
//! * [`ConfiguredSubscriptionState`] – configured subscription lifecycle state
//!   (`valid`, `invalid`, `concluded`).
//! * [`Transport`] – notification transport protocol (UDP-Notif, HTTPS-Notif).
//! * [`Encoding`] – notification payload encoding (XML, JSON, CBOR).
//! * [`ChangeType`] – on-change update trigger change kinds.

use crate::xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
use crate::yang_push::SUBSCRIBED_NOTIFICATIONS_NS;
use quick_xml::events::{BytesText, Event};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfiguredSubscriptionState {
    Valid,
    Invalid,
    Concluded,
}

impl XmlSerialize for ConfiguredSubscriptionState {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let value = match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Concluded => "concluded",
        };
        let elem = writer
            .create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "configured-subscription-state")?;
        writer.write_event(Event::Start(elem.clone()))?;
        writer.write_event(Event::Text(BytesText::new(value)))?;
        writer.write_event(Event::End(elem.to_end()))?;
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, ConfiguredSubscriptionState> for ConfiguredSubscriptionState {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.open(
            Some(SUBSCRIBED_NOTIFICATIONS_NS),
            "configured-subscription-state",
        )?;
        let value = parser.tag_string()?;
        parser.close()?;
        match value.trim() {
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "concluded" => Ok(Self::Concluded),
            other => Err(ParsingError::InvalidValue(other.to_string())),
        }
    }
}

/// Transport protocol used to deliver the notification message to the data
/// collection.
#[derive(Default, Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transport {
    /// UDP-based notification transport
    /// [ietf-udp-notif-transport](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-udp-notif)
    #[serde(rename = "ietf-udp-notif-transport:udp-notif")]
    UDPNotif,

    /// HTTPS-based notification transport
    /// [draft-ietf-netconf-https-notif](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-https-notif)
    #[serde(rename = "ietf-https-notif:https")]
    HTTPSNotif,

    #[default]
    #[serde(other)]
    #[serde(rename = "unknown")]
    Unknown,
}

impl XmlSerialize for Transport {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        // `transport` is an identityref leaf. We resolve the prefix:localname
        // from the identity module namespace.
        let (identity_ns, local_name) = match self {
            Transport::UDPNotif => (
                "urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport",
                "udp-notif",
            ),
            Transport::HTTPSNotif => ("urn:ietf:params:xml:ns:yang:ietf-https-notif", "https"),
            Transport::Unknown => return Ok(()), // skip unknown
        };
        let elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "transport")?;
        let mut start = elem.clone();
        start.push_attribute(("xmlns:tns", identity_ns));
        writer.write_event(Event::Start(start))?;
        writer.write_event(Event::Text(BytesText::new(&format!("tns:{local_name}"))))?;
        writer.write_event(Event::End(elem.to_end()))?;
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, Transport> for Transport {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "transport")?;
        let raw: Box<str> = parser.tag_string()?.trim().into();
        let (_ns_uri, local_name) = parser.resolve_identity_ref(&raw)?;
        parser.close()?;
        match local_name.as_str() {
            "udp-notif" => Ok(Transport::UDPNotif),
            "https" => Ok(Transport::HTTPSNotif),
            _ => Ok(Transport::Unknown),
        }
    }
}

/// Encoding used for the notification payload
#[derive(Default, Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

impl XmlSerialize for Encoding {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let (identity_ns, local_name) = match self {
            Encoding::Xml => (
                "urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                "encode-xml",
            ),
            Encoding::Json => (
                "urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                "encode-json",
            ),
            Encoding::Cbor => (
                "urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport",
                "encode-cbor",
            ),
            Encoding::Unknown => return Ok(()),
        };
        let elem = writer.create_ns_element(SUBSCRIBED_NOTIFICATIONS_NS, "encoding")?;
        let mut start = elem.clone();
        start.push_attribute(("xmlns:enc", identity_ns));
        writer.write_event(Event::Start(start))?;
        writer.write_event(Event::Text(BytesText::new(&format!("enc:{local_name}"))))?;
        writer.write_event(Event::End(elem.to_end()))?;
        Ok(())
    }
}

impl<'a> XmlDeserialize<'a, Encoding> for Encoding {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.open(Some(SUBSCRIBED_NOTIFICATIONS_NS), "encoding")?;
        let raw: Box<str> = parser.tag_string()?.trim().into();
        let (_ns_uri, local_name) = parser.resolve_identity_ref(&raw)?;
        parser.close()?;
        match local_name.as_str() {
            "encode-xml" => Ok(Encoding::Xml),
            "encode-json" => Ok(Encoding::Json),
            "encode-cbor" => Ok(Encoding::Cbor),
            _ => Ok(Encoding::Unknown),
        }
    }
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
