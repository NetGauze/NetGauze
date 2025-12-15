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

//! NETCONF representation in Rust with XML encoding and decoding capabilities.

use crate::capabilities::Capability;
use crate::xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
use crate::yanglib::YangLibrary;
use crate::{NETCONF_MONITORING_NS, NETCONF_NS, YANG_LIBRARY_NS};
use indexmap::IndexMap;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::name::ResolveResult;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::str::FromStr;
use std::sync::Arc;

pub(crate) fn decode_html_entities(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#38;", "&")
        .replace("&#60;", "<")
        .replace("&#62;", ">")
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum NetConfMessage {
    Hello(Hello),
    Rpc(Rpc),
    RpcReply(RpcReply),
}

impl XmlDeserialize<NetConfMessage> for NetConfMessage {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        // Skip XML declaration header if present in the message
        if matches!(parser.peek(), Event::Decl(_)) {
            parser.skip()?;
        }
        // Skip any empty text
        parser.skip_text()?;
        match parser.peek() {
            Event::Start(a) => match a.local_name().into_inner() {
                b"hello" => Ok(NetConfMessage::Hello(Hello::xml_deserialize(parser)?)),
                b"rpc" => Ok(NetConfMessage::Rpc(Rpc::xml_deserialize(parser)?)),
                b"rpc-reply" => Ok(NetConfMessage::RpcReply(RpcReply::xml_deserialize(parser)?)),
                _ => Err(ParsingError::InvalidValue(format!(
                    "invalid start value: {}",
                    std::str::from_utf8(a.local_name().into_inner())?
                ))),
            },
            token => Err(ParsingError::WrongToken {
                expecting: "<hello>, <rpc>, or <rpc-reply>".to_string(),
                found: token.clone(),
            }),
        }
    }
}

impl XmlSerialize for NetConfMessage {
    fn xml_serialize<T: io::Write>(&self, xml: &mut XmlWriter<T>) -> Result<(), quick_xml::Error> {
        match self {
            NetConfMessage::Hello(hello) => hello.xml_serialize(xml),
            NetConfMessage::Rpc(rpc) => rpc.xml_serialize(xml),
            NetConfMessage::RpcReply(rpc) => rpc.xml_serialize(xml),
        }
    }
}

/// ```xml
///  <xs:element name="hello">
///    <xs:complexType>
///      <xs:sequence>
///        <xs:element name="capabilities">
///          <xs:complexType>
///            <xs:sequence>
///              <xs:element name="capability" type="xs:anyURI"
///                          maxOccurs="unbounded"/>
///            </xs:sequence>
///          </xs:complexType>
///        </xs:element>
///        <xs:element name="session-id" type="SessionId"
///                    minOccurs="0"/>
///      </xs:sequence>
///    </xs:complexType>
///  </xs:element>
/// ``
#[derive(PartialEq, Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename = "hello")]
pub struct Hello {
    #[serde(rename = "session-id")]
    session_id: Option<u32>,
    capabilities: HashSet<Capability>,
}

impl Hello {
    pub const fn new(session_id: Option<u32>, capabilities: HashSet<Capability>) -> Self {
        Self {
            session_id,
            capabilities,
        }
    }

    pub const fn session_id(&self) -> Option<u32> {
        self.session_id
    }

    pub const fn capabilities(&self) -> &HashSet<Capability> {
        &self.capabilities
    }
}

impl XmlDeserialize<Hello> for Hello {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Hello, ParsingError> {
        // Skip XML declaration header if present in the message
        if matches!(parser.peek(), Event::Decl(_)) {
            parser.skip()?;
        }
        // Skip any empty text
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "hello")?;
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "capabilities")?;

        let capabilities = parser.collect_xml_sequence::<Capability>()?;
        parser.close()?;
        let session_id = if parser.maybe_open(Some(NETCONF_NS), "session-id")?.is_some() {
            let val = parser.tag_string()?.parse::<u32>()?;
            parser.close()?;
            Some(val)
        } else {
            None
        };
        parser.close()?;
        Ok(Hello::new(session_id, HashSet::from_iter(capabilities)))
    }
}

impl XmlSerialize for Hello {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let hello_start = writer.create_element("hello");
        let capabilities_start = writer.create_element("capabilities");
        writer.write_event(Event::Start(hello_start.clone()))?;
        writer.write_event(Event::Start(capabilities_start.clone()))?;
        for cap in &self.capabilities {
            cap.xml_serialize(writer)?
        }
        writer.write_event(Event::End(capabilities_start.to_end()))?;
        if let Some(session_id) = self.session_id {
            let session_id_start = writer.create_element("session-id");
            writer.write_event(Event::Start(session_id_start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(&session_id.to_string())))?;
            writer.write_event(Event::End(session_id_start.to_end()))?;
        }
        writer.write_event(Event::End(hello_start.to_end()))?;
        Ok(())
    }
}

/// Arbitrary attributes are ignored
/// ```xml
/// <xs:complexType name="rpcType">
///     <xs:sequence>
///         <xs:element ref="rpcOperation"/>
///     </xs:sequence>
///     <xs:attribute name="message-id" type="messageIdType"
///                   use="required"/>
///     <!--
///        Arbitrary attributes can be supplied with <rpc> element.
///       -->
///     <xs:anyAttribute processContents="lax"/>
/// </xs:complexType>
/// <xs:element name="rpc" type="rpcType"/>
/// ```
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Rpc {
    message_id: Box<str>,
    operation: RpcOperation,
}

impl Rpc {
    pub const fn new(message_id: Box<str>, operation: RpcOperation) -> Self {
        Self {
            message_id,
            operation,
        }
    }

    pub const fn message_id(&self) -> &str {
        &self.message_id
    }

    pub const fn operation(&self) -> &RpcOperation {
        &self.operation
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum RpcOperation {
    Raw(Box<str>),
    // TODO: YANG defined to be implemented later
    // YangDefined {
    //     module: Cow<'a, str>,
    //     operation: Cow<'a, str>,
    //     data: yang3::data::DataTree,
    // },
    WellKnown(WellKnownOperation),
}

fn extract_attribute(bytes_start: &BytesStart<'_>, attribute_name: &[u8]) -> Option<Box<str>> {
    bytes_start
        .attributes()
        .map(|attr| match attr {
            Ok(attr) => {
                if attr.key.local_name().into_inner() == attribute_name {
                    match attr.unescape_value() {
                        Ok(value) => Some(value.to_string().into_boxed_str()),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        })
        .find(|x| x.is_some())
        .flatten()
}

/// ```xml
/// <xs:simpleType name="messageIdType">
///     <xs:restriction base="xs:string">
///         <xs:maxLength value="4095"/>
///     </xs:restriction>
/// </xs:simpleType>
/// ```
fn extract_message_id(open: &BytesStart<'_>) -> Result<Option<Box<str>>, ParsingError> {
    let msg_id_attr = extract_attribute(open, b"message-id");
    if let Some(msg_id) = &msg_id_attr
        && msg_id.len() > 4095
    {
        return Err(ParsingError::InvalidValue(format!(
            "message-id length: {} is larger than max 4095",
            msg_id.len()
        )));
    }
    Ok(msg_id_attr)
}

impl XmlDeserialize<Rpc> for Rpc {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Rpc, ParsingError> {
        // Skip any empty text
        parser.skip_text()?;
        let open = parser.open(Some(NETCONF_NS), "rpc")?;
        let message_id = if let Some(msg_id) = extract_message_id(&open)? {
            msg_id
        } else {
            return Err(ParsingError::MissingAttribute("message-id".to_string()));
        };
        let operation = match WellKnownOperation::xml_deserialize(parser) {
            Ok(operation) => RpcOperation::WellKnown(operation),
            Err(ParsingError::Recoverable) => {
                let operation = parser.copy_buffer_till(b"rpc")?;
                RpcOperation::Raw(operation)
            }
            Err(e) => return Err(e),
        };
        Ok(Rpc {
            message_id,
            operation,
        })
    }
}

impl XmlSerialize for Rpc {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut start = writer.create_element("rpc");
        start.push_attribute(("message-id", self.message_id.as_ref()));
        writer.write_event(Event::Start(start.clone()))?;
        match &self.operation {
            RpcOperation::Raw(operation) => {
                writer.write_all(operation.as_bytes())?;
            }
            RpcOperation::WellKnown(wellknown) => {
                wellknown.xml_serialize(writer)?;
            }
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize, strum_macros::Display)]
pub enum YangSchemaFormat {
    #[strum(serialize = "xsd")]
    Xsd,

    #[strum(serialize = "yang")]
    Yang,

    #[strum(serialize = "yin")]
    Yin,

    #[strum(serialize = "rng")]
    Rng,

    #[strum(serialize = "rnc")]
    Rnc,
}

impl XmlDeserialize<YangSchemaFormat> for YangSchemaFormat {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(NETCONF_MONITORING_NS), "format")?;
        let value_str = parser.tag_string()?;
        let value = match value_str.as_ref().trim() {
            "xsd" => YangSchemaFormat::Xsd,
            "yang" => YangSchemaFormat::Yang,
            "yin" => YangSchemaFormat::Yin,
            "rng" => YangSchemaFormat::Rng,
            "rnc" => YangSchemaFormat::Rnc,
            _ => {
                return Err(ParsingError::InvalidValue(format!(
                    "unknown YANG schema format `{value_str}`"
                )));
            }
        };
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for YangSchemaFormat {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(NETCONF_MONITORING_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(
                NETCONF_MONITORING_NS,
                "".to_string(),
            )]))?;
        }
        let start = writer.create_ns_element(NETCONF_MONITORING_NS, "format")?;
        writer.write_event(Event::Start(start.clone()))?;
        match self {
            Self::Xsd => writer.write_event(Event::Text(BytesText::new("xsd")))?,
            Self::Yang => writer.write_event(Event::Text(BytesText::new("yang")))?,
            Self::Yin => writer.write_event(Event::Text(BytesText::new("yin")))?,
            Self::Rng => writer.write_event(Event::Text(BytesText::new("rng")))?,
            Self::Rnc => writer.write_event(Event::Text(BytesText::new("rnc")))?,
        }
        writer.write_event(Event::End(start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize, strum_macros::Display)]
pub enum ConfigSource {
    #[strum(serialize = "candidate")]
    Candidate,

    #[strum(serialize = "running")]
    Running,

    #[strum(serialize = "startup")]
    Startup,
}

impl XmlDeserialize<ConfigSource> for ConfigSource {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "source")?;
        let value = if parser.maybe_open(Some(NETCONF_NS), "candidate")?.is_some() {
            ConfigSource::Candidate
        } else if parser.maybe_open(Some(NETCONF_NS), "running")?.is_some() {
            ConfigSource::Running
        } else if parser.maybe_open(Some(NETCONF_NS), "startup")?.is_some() {
            ConfigSource::Startup
        } else {
            return Err(ParsingError::WrongToken {
                expecting: "<candidate/>, <running/>, <startup/>".into(),
                found: parser.peek().clone(),
            });
        };

        // close source type
        parser.close()?;
        // close source
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ConfigSource {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("source");
        writer.write_event(Event::Start(start.clone()))?;
        match self {
            Self::Candidate => writer.write_event(Event::Empty(BytesStart::new("candidate")))?,
            Self::Running => writer.write_event(Event::Empty(BytesStart::new("running")))?,
            Self::Startup => writer.write_event(Event::Empty(BytesStart::new("startup")))?,
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize, strum_macros::Display)]
pub enum ConfigTarget {
    #[strum(serialize = "candidate")]
    Candidate,

    #[strum(serialize = "running")]
    Running,
}

impl XmlDeserialize<ConfigTarget> for ConfigTarget {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "target")?;
        let value = if parser.maybe_open(Some(NETCONF_NS), "candidate")?.is_some() {
            ConfigTarget::Candidate
        } else if parser.maybe_open(Some(NETCONF_NS), "running")?.is_some() {
            ConfigTarget::Running
        } else {
            return Err(ParsingError::WrongToken {
                expecting: "<candidate/> or <running/>".into(),
                found: parser.peek().clone(),
            });
        };
        // close target type
        parser.close()?;
        // close target
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ConfigTarget {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("target");
        writer.write_event(Event::Start(start.clone()))?;
        match self {
            Self::Candidate => writer.write_event(Event::Empty(BytesStart::new("candidate")))?,
            Self::Running => writer.write_event(Event::Empty(BytesStart::new("running")))?,
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// The default operation to use for edit-config RPC
#[derive(
    Eq, PartialEq, Default, Debug, Copy, Clone, Serialize, Deserialize, strum_macros::Display,
)]
pub enum ConfigUpdateDefaultOperation {
    /// The configuration data in the `<config>` parameter is merged with the
    /// configuration at the corresponding level in the target datastore.
    ///
    /// This is the default behavior.
    #[default]
    #[strum(serialize = "merge")]
    Merge,

    /// The configuration data in the `<config>` parameter completely replaces
    /// the configuration in the target datastore.  This is useful for
    /// loading previously saved configuration data.
    #[strum(serialize = "replace")]
    Replace,

    /// The target datastore is unaffected by the configuration in the
    /// `<config>` parameter, unless and until the incoming configuration
    /// data uses the "operation" attribute to request a different
    /// operation. If the configuration in the `<config>` parameter contains
    /// data for which there is not a corresponding level in the target
    /// datastore, an `<rpc-error>` is returned with an `<error-tag>` value
    /// of data-missing. Using "none" allows operations like "delete" to
    /// avoid unintentionally creating the parent hierarchy of the element
    /// to be deleted.
    #[strum(serialize = "none")]
    None,
}

impl XmlDeserialize<ConfigUpdateDefaultOperation> for ConfigUpdateDefaultOperation {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "default-operation")?;
        let value_str = parser.tag_string()?;
        let value = match value_str.as_ref().trim() {
            "merge" => ConfigUpdateDefaultOperation::Merge,
            "replace" => ConfigUpdateDefaultOperation::Replace,
            "none" => ConfigUpdateDefaultOperation::None,
            _ => {
                return Err(ParsingError::InvalidValue(format!(
                    "unknown default-operation `{value_str}`"
                )));
            }
        };
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ConfigUpdateDefaultOperation {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("default-operation");
        writer.write_event(Event::Start(start.clone()))?;
        match self {
            Self::Merge => writer.write_event(Event::Text(BytesText::new("merge")))?,
            Self::Replace => writer.write_event(Event::Text(BytesText::new("replace")))?,
            Self::None => writer.write_event(Event::Text(BytesText::new("none")))?,
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// Validation options for edit-config RPC.
#[derive(
    Eq, PartialEq, Default, Debug, Copy, Clone, Serialize, Deserialize, strum_macros::Display,
)]
pub enum ConfigEditTestOption {
    /// Perform a validation test before attempting to set.
    /// If validation errors occur, do not perform the `<edit-config>`
    /// operation.
    ///
    /// This is the default test-option.
    #[strum(serialize = "test-then-set")]
    #[default]
    TestThenSet,

    /// Perform a set without a validation test first.
    #[strum(serialize = "set")]
    Set,

    /// Perform only the validation test, without  attempting to set.
    #[strum(serialize = "test-only")]
    TestOnly,
}

impl XmlDeserialize<ConfigEditTestOption> for ConfigEditTestOption {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "test-option")?;
        let value_str = parser.tag_string()?;
        let value = match value_str.as_ref().trim() {
            "test-then-set" => ConfigEditTestOption::TestThenSet,
            "set" => ConfigEditTestOption::Set,
            "test-only" => ConfigEditTestOption::TestOnly,
            _ => {
                return Err(ParsingError::InvalidValue(format!(
                    "unknown test-option `{value_str}`"
                )));
            }
        };
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ConfigEditTestOption {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("test-option");
        writer.write_event(Event::Start(start.clone()))?;
        match self {
            Self::TestThenSet => {
                writer.write_event(Event::Text(BytesText::new("test-then-set")))?
            }
            Self::Set => writer.write_event(Event::Text(BytesText::new("set")))?,
            Self::TestOnly => writer.write_event(Event::Text(BytesText::new("test-only")))?,
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

#[derive(
    Eq, PartialEq, Default, Debug, Copy, Clone, Serialize, Deserialize, strum_macros::Display,
)]
pub enum ConfigErrorOption {
    #[strum(serialize = "stop-on-error")]
    #[default]
    StopOnError,

    #[strum(serialize = "continue-on-error")]
    ContinueOnError,

    #[strum(serialize = "rollback-on-error")]
    RollbackOnError,
}

impl XmlDeserialize<ConfigErrorOption> for ConfigErrorOption {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "error-option")?;
        let value_str = parser.tag_string()?;
        let value = match value_str.as_ref().trim() {
            "stop-on-error" => ConfigErrorOption::StopOnError,
            "continue-on-error" => ConfigErrorOption::ContinueOnError,
            "rollback-on-error" => ConfigErrorOption::RollbackOnError,
            _ => {
                return Err(ParsingError::InvalidValue(format!(
                    "unknown error-option `{value_str}`"
                )));
            }
        };
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ConfigErrorOption {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("error-option");
        writer.write_event(Event::Start(start.clone()))?;
        match self {
            Self::StopOnError => {
                writer.write_event(Event::Text(BytesText::new("stop-on-error")))?
            }
            Self::ContinueOnError => {
                writer.write_event(Event::Text(BytesText::new("continue-on-error")))?
            }
            Self::RollbackOnError => {
                writer.write_event(Event::Text(BytesText::new("rollback-on-error")))?
            }
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Filter {
    Subtree(Box<str>),
    XPath(Box<str>),
}

impl XmlDeserialize<Filter> for Filter {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let filter_start = parser.open(Some(NETCONF_NS), "filter")?;
        let filter_type = extract_attribute(&filter_start, b"type").unwrap_or("subtree".into());
        let filter = match filter_type.as_ref() {
            "subtree" => {
                let value = parser.copy_buffer_till(b"filter")?;
                Filter::Subtree(value)
            }
            "xpath" => {
                let select = extract_attribute(&filter_start, b"select")
                    .ok_or(ParsingError::MissingAttribute("select".into()))?;
                Filter::XPath(select)
            }
            _ => {
                return Err(ParsingError::InvalidValue(format!(
                    "not supported filter type `{filter_type}`, only subtree and xpath are supported"
                )));
            }
        };
        // Close filter
        parser.close()?;
        Ok(filter)
    }
}

impl XmlSerialize for Filter {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut start = writer.create_element("filter");
        match self {
            Filter::Subtree(_) => start.push_attribute(("type", "subtree")),
            Filter::XPath(_) => start.push_attribute(("type", "xpath")),
        }

        match self {
            Filter::Subtree(value) => {
                writer.write_event(Event::Start(start.clone()))?;
                writer.write_all(value.as_bytes())?;
            }
            Filter::XPath(value) => {
                start.push_attribute(("select", value.as_ref()));
                writer.write_event(Event::Start(start.clone()))?;
            }
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// The content for the edit config operation.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum EditConfig {
    /// Inline YANG XML config
    Config(Box<str>),

    /// URL-based config content
    Url(Box<str>),
}

impl XmlDeserialize<EditConfig> for EditConfig {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let value = if parser.maybe_open(Some(NETCONF_NS), "url")?.is_some() {
            let url = parser.tag_string()?;
            parser.close()?;
            EditConfig::Url(url)
        } else if parser.maybe_open(Some(NETCONF_NS), "config")?.is_some() {
            let value = parser.copy_buffer_till(b"config")?;
            parser.close()?;
            EditConfig::Config(value)
        } else {
            return Err(ParsingError::WrongToken {
                expecting: "<url/> or <config/>".into(),
                found: parser.peek().clone(),
            });
        };
        Ok(value)
    }
}

impl XmlSerialize for EditConfig {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        match self {
            EditConfig::Config(value) => {
                let config_start = writer.create_element("config");
                writer.write_event(Event::Start(config_start.clone()))?;
                writer.write_all(value.as_bytes())?;
                writer.write_event(Event::End(config_start.to_end()))?;
            }
            EditConfig::Url(value) => {
                let url_start = writer.create_element("url");
                writer.write_event(Event::Start(url_start.clone()))?;
                writer.write_event(Event::Text(BytesText::new(value)))?;
                writer.write_event(Event::End(url_start.to_end()))?;
            }
        }
        Ok(())
    }
}

/// Easy access for Well-known NETCONF RPC commands
/// at the moment these serve as examples, will be
/// updated in subsequent PRs.
/// TODO: defined NETCONF well-known operations
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum WellKnownOperation {
    /// Retrieve all or part of a specified configuration.
    ///
    /// [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241.html).
    GetConfig {
        source: ConfigSource,
        filter: Filter,
    },

    EditConfig {
        target: ConfigTarget,
        default_operation: ConfigUpdateDefaultOperation,
        test_option: Option<ConfigEditTestOption>,
        error_option: Option<ConfigErrorOption>,
        edit_content: EditConfig,
    },

    /// Retrieve running configuration and device state information.
    Get { filter: Filter },

    /// Retrieve RFC8525 YANG Library
    GetYangLibrary,

    /// Request graceful termination of a NETCONF session.
    ///
    /// [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241.html).
    CloseSession,

    GetSchema {
        /// Identifier for the schema list entry
        identifier: Box<str>,

        /// Version of the schema requested.
        /// If this parameter is not present,
        /// and more than one version of the schema exists on
        /// the server, a 'data-not-unique' error is returned.
        version: Option<Box<str>>,

        /// The data modeling language of the schema.  If this parameter is not
        /// present, and more than one formats of the schema exists on the
        /// server, a 'data-not-unique' error is returned, as described above.
        format: Option<YangSchemaFormat>,
    },
}

impl WellKnownOperation {
    /// Parse get-config operation from [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241.html).
    ///
    /// NOTE: this method assumes that `parser.open` is already called on
    /// get-config
    fn parse_get_config(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let source = ConfigSource::xml_deserialize(parser)?;
        let filter = Filter::xml_deserialize(parser)?;
        // Close get-config
        parser.close()?;
        Ok(WellKnownOperation::GetConfig { source, filter })
    }

    fn serialize_get_config<T: io::Write>(
        writer: &mut XmlWriter<T>,
        source: &ConfigSource,
        filter: &Filter,
    ) -> Result<(), quick_xml::Error> {
        let get_config_start = writer.create_element("get-config");
        writer.write_event(Event::Start(get_config_start.clone()))?;
        source.xml_serialize(writer)?;
        filter.xml_serialize(writer)?;
        writer.write_event(Event::End(get_config_start.to_end()))?;
        Ok(())
    }

    /// Parse edit-config operation from [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241.html).
    ///
    /// NOTE: this method assumes that `parser.open` is already called on
    /// edit-config
    fn parse_edit_config(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let target = ConfigTarget::xml_deserialize(parser)?;

        let default_operation = match ConfigUpdateDefaultOperation::xml_deserialize(parser) {
            Ok(option) => option,
            Err(ParsingError::WrongToken { expecting, .. })
                if expecting == "<default-operation>" =>
            {
                ConfigUpdateDefaultOperation::Merge
            }
            Err(err) => return Err(err),
        };

        let test_option = match ConfigEditTestOption::xml_deserialize(parser) {
            Ok(option) => Some(option),
            Err(ParsingError::WrongToken { expecting, .. }) if expecting == "<test-option>" => None,
            Err(err) => return Err(err),
        };

        let error_option = match ConfigErrorOption::xml_deserialize(parser) {
            Ok(option) => Some(option),
            Err(ParsingError::WrongToken { expecting, .. }) if expecting == "<error-option>" => {
                None
            }
            Err(err) => return Err(err),
        };

        let edit_content = EditConfig::xml_deserialize(parser)?;
        // Close get-config
        parser.close()?;
        Ok(WellKnownOperation::EditConfig {
            target,
            default_operation,
            test_option,
            error_option,
            edit_content,
        })
    }

    fn serialize_edit_config<T: io::Write>(
        writer: &mut XmlWriter<T>,
        target: &ConfigTarget,
        default_operation: &ConfigUpdateDefaultOperation,
        test_option: &Option<ConfigEditTestOption>,
        error_option: &Option<ConfigErrorOption>,
        edit_content: &EditConfig,
    ) -> Result<(), quick_xml::Error> {
        let edit_config_start = writer.create_element("edit-config");
        writer.write_event(Event::Start(edit_config_start.clone()))?;
        target.xml_serialize(writer)?;
        default_operation.xml_serialize(writer)?;
        if let Some(test_option) = test_option {
            test_option.xml_serialize(writer)?;
        }
        if let Some(error_option) = error_option {
            error_option.xml_serialize(writer)?;
        }
        edit_content.xml_serialize(writer)?;
        writer.write_event(Event::End(edit_config_start.to_end()))?;
        Ok(())
    }

    fn parse_get(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let filter = Filter::xml_deserialize(parser)?;
        // Close get
        parser.close()?;
        Ok(WellKnownOperation::Get { filter })
    }

    fn serialize_get<T: io::Write>(
        writer: &mut XmlWriter<T>,
        filter: &Filter,
    ) -> Result<(), quick_xml::Error> {
        let get_start = writer.create_element("get");
        writer.write_event(Event::Start(get_start.clone()))?;
        filter.xml_serialize(writer)?;
        writer.write_event(Event::End(get_start.to_end()))?;
        Ok(())
    }

    fn parse_get_schema(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(NETCONF_MONITORING_NS), "identifier")?;
        let identifier = parser.tag_string()?.trim().into();
        // close identifier
        parser.close()?;
        let version = if parser
            .maybe_open(Some(NETCONF_MONITORING_NS), "version")?
            .is_some()
        {
            let ver = parser.tag_string()?.trim().into();
            // close version
            parser.close()?;
            Some(ver)
        } else {
            None
        };

        let format = match YangSchemaFormat::xml_deserialize(parser) {
            Ok(format) => Some(format),
            Err(ParsingError::WrongToken { expecting, .. }) if expecting == "<format>" => None,
            Err(err) => return Err(err),
        };

        // Close get-schema
        parser.close()?;
        Ok(WellKnownOperation::GetSchema {
            identifier,
            version,
            format,
        })
    }

    fn serialize_get_schema<T: io::Write>(
        writer: &mut XmlWriter<T>,
        identifier: &str,
        version: &Option<Box<str>>,
        format: &Option<YangSchemaFormat>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(NETCONF_MONITORING_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(
                NETCONF_MONITORING_NS,
                "".to_string(),
            )]))?;
        }
        let get_schema_start = writer.create_ns_element(NETCONF_MONITORING_NS, "get-schema")?;
        writer.write_event(Event::Start(get_schema_start.clone()))?;

        let identifier_start = writer.create_ns_element(NETCONF_MONITORING_NS, "identifier")?;
        writer.write_event(Event::Start(identifier_start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(identifier)))?;
        writer.write_event(Event::End(identifier_start.to_end()))?;

        if let Some(version) = version {
            let version_start = writer.create_ns_element(NETCONF_MONITORING_NS, "version")?;
            writer.write_event(Event::Start(version_start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(version)))?;
            writer.write_event(Event::End(version_start.to_end()))?;
        }

        if let Some(format) = format {
            format.xml_serialize(writer)?;
        }
        writer.write_event(Event::End(get_schema_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

impl XmlDeserialize<WellKnownOperation> for WellKnownOperation {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        if parser.maybe_open(Some(NETCONF_NS), "get-config")?.is_some() {
            return Self::parse_get_config(parser);
        }
        if parser
            .maybe_open(Some(NETCONF_NS), "edit-config")?
            .is_some()
        {
            return Self::parse_edit_config(parser);
        }
        if parser.maybe_open(Some(NETCONF_NS), "get")?.is_some() {
            return Self::parse_get(parser);
        }
        if parser
            .maybe_open(Some(NETCONF_NS), "close-session")?
            .is_some()
        {
            parser.close()?;
            return Ok(WellKnownOperation::CloseSession);
        }
        if parser
            .maybe_open(Some(NETCONF_MONITORING_NS), "get-schema")?
            .is_some()
        {
            return Self::parse_get_schema(parser);
        }
        // If we reach here, it means we found an unknown operation
        Err(ParsingError::Recoverable)
    }
}

impl XmlSerialize for WellKnownOperation {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        match self {
            Self::GetConfig { source, filter } => {
                Self::serialize_get_config(writer, source, filter)
            }
            Self::EditConfig {
                target,
                default_operation,
                test_option,
                error_option,
                edit_content,
            } => Self::serialize_edit_config(
                writer,
                target,
                default_operation,
                test_option,
                error_option,
                edit_content,
            ),
            Self::GetYangLibrary => {
                let subtree = r#"<yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
                    </yang-library>
                    <modules-state xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
                    </modules-state>"#;
                Self::Get {
                    filter: Filter::Subtree(subtree.into()),
                }
                .xml_serialize(writer)
            }
            Self::Get { filter } => Self::serialize_get(writer, filter),
            Self::CloseSession => {
                let close_session_start = writer.create_element("close-session");
                writer.write_event(Event::Empty(close_session_start))?;
                Ok(())
            }
            Self::GetSchema {
                identifier,
                version,
                format,
            } => Self::serialize_get_schema(writer, identifier, version, format),
        }
    }
}

// pub struct YangOperationData {
//     context: Arc<yang3::context::Context>,
//     data_tree: yang3::data::DataTree,
// }

/// RPC Reply
/// ```xml
///   <xs:complexType name="rpcReplyType">
///      <xs:choice>
///        <xs:element name="ok"/>
///        <xs:sequence>
///          <xs:element ref="rpc-error"
///                      minOccurs="0" maxOccurs="unbounded"/>
///          <xs:element ref="rpcResponse"
///                      minOccurs="0" maxOccurs="unbounded"/>
///
///        </xs:sequence>
///      </xs:choice>
///      <xs:attribute name="message-id" type="messageIdType"
///                    use="optional"/>
///      <!--
///         Any attributes supplied with <rpc> element must be returned
///         on <rpc-reply>.
///        -->
///      <xs:anyAttribute processContents="lax"/>
///    </xs:complexType>
///    <xs:element name="rpc-reply" type="rpcReplyType"/>
/// ```
#[derive(PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RpcReply {
    message_id: Option<Box<str>>,
    reply: RpcReplyContent,
}

impl RpcReply {
    pub const fn new(message_id: Option<Box<str>>, reply: RpcReplyContent) -> Self {
        Self { message_id, reply }
    }

    pub fn message_id(&self) -> Option<&str> {
        self.message_id.as_ref().map(|x| x.as_ref())
    }

    pub const fn reply(&self) -> &RpcReplyContent {
        &self.reply
    }
}

impl From<RpcReply> for RpcReplyContent {
    fn from(reply: RpcReply) -> Self {
        reply.reply
    }
}

impl XmlDeserialize<RpcReply> for RpcReply {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        let rpc_reply = parser.open(Some(NETCONF_NS), "rpc-reply")?;
        let message_id = extract_message_id(&rpc_reply)?;
        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "ok") {
            parser.close()?;
            return Ok(RpcReply {
                message_id,
                reply: RpcReplyContent::Ok,
            });
        }
        let errors: Vec<RpcError> =
            parser.collect_xml_sequence_with_tag(Some(NETCONF_NS), b"rpc-error")?;
        let responses = match WellKnownRpcResponse::xml_deserialize(parser) {
            Ok(response) => RpcResponse::WellKnown(response),
            Err(ParsingError::Recoverable) => {
                let responses = parser.copy_buffer_till(b"rpc-reply")?;
                RpcResponse::Raw(responses)
            }
            Err(e) => return Err(e),
        };
        parser.close()?;
        Ok(RpcReply {
            message_id,
            reply: RpcReplyContent::ErrorsAndData { errors, responses },
        })
    }
}

impl XmlSerialize for RpcReply {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut start = writer.create_element("rpc-reply");
        if let Some(message_id) = self.message_id.as_ref() {
            start.push_attribute(("message-id", message_id.as_ref()));
        }
        writer.write_event(Event::Start(start.clone()))?;

        match &self.reply {
            RpcReplyContent::Ok => {
                let ok_start = writer.create_element("ok");
                writer.write_event(Event::Empty(ok_start))?;
            }
            RpcReplyContent::ErrorsAndData { errors, responses } => {
                for error in errors {
                    error.xml_serialize(writer)?;
                }
                match responses {
                    RpcResponse::Raw(responses) => {
                        writer.write_all(responses.as_bytes())?;
                    }
                    RpcResponse::WellKnown(wellknown) => {
                        wellknown.xml_serialize(writer)?;
                    }
                }
            }
        }

        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// ```xml
/// <xs:choice>
///     <xs:element name="ok"/>
///     <xs:sequence>
///         <xs:element ref="rpc-error"
///                     minOccurs="0" maxOccurs="unbounded"/>
///         <xs:element ref="rpcResponse"
///                     minOccurs="0" maxOccurs="unbounded"/>
///
///     </xs:sequence>
/// </xs:choice>
/// ```
#[derive(PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged, rename_all = "kebab-case")]
pub enum RpcReplyContent {
    #[default]
    Ok,
    ErrorsAndData {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        errors: Vec<RpcError>, // TODO: use box instead of vec
        // TODO: handle different types of responses as we do with the RPC operations
        responses: RpcResponse,
    },
}

impl RpcReplyContent {
    pub const fn is_ok(&self) -> bool {
        matches!(self, RpcReplyContent::Ok)
    }

    pub const fn has_errors(&self) -> bool {
        if let RpcReplyContent::ErrorsAndData { errors, .. } = self {
            !errors.is_empty()
        } else {
            false
        }
    }

    pub const fn errors(&self) -> Option<&[RpcError]> {
        if let RpcReplyContent::ErrorsAndData { errors, .. } = self {
            Some(errors.as_slice())
        } else {
            None
        }
    }

    pub const fn responses(&self) -> Option<&RpcResponse> {
        if let RpcReplyContent::ErrorsAndData { responses, .. } = self {
            Some(responses)
        } else {
            None
        }
    }
}

impl From<RpcReplyContent> for Option<RpcResponse> {
    fn from(value: RpcReplyContent) -> Self {
        if let RpcReplyContent::ErrorsAndData { responses, .. } = value {
            Some(responses)
        } else {
            None
        }
    }
}

impl From<RpcReplyContent> for Vec<RpcError> {
    fn from(value: RpcReplyContent) -> Self {
        if let RpcReplyContent::ErrorsAndData { errors, .. } = value {
            errors
        } else {
            vec![]
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum RpcResponse {
    Raw(Box<str>),
    WellKnown(WellKnownRpcResponse),
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum WellKnownRpcResponse {
    YangSchema { schema: Box<str> },
    YangLibrary(Arc<YangLibrary>),
    Data(Box<str>),
}

impl WellKnownRpcResponse {
    fn parse_yang_schema(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        let schema = decode_html_entities(parser.tag_string()?.as_ref()).into_boxed_str();
        parser.close()?;
        Ok(WellKnownRpcResponse::YangSchema { schema })
    }
}
impl XmlDeserialize<WellKnownRpcResponse> for WellKnownRpcResponse {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        if parser
            .maybe_open(Some(NETCONF_MONITORING_NS), "data")?
            .is_some()
        {
            return Self::parse_yang_schema(parser);
        }
        if let Some(_data) = parser.maybe_open(Some(NETCONF_NS), "data")? {
            parser.skip_text()?;
            if parser.is_tag(Some(YANG_LIBRARY_NS), "yang-library") {
                let yang_lib = YangLibrary::xml_deserialize(parser)?;
                return Ok(Self::YangLibrary(Arc::new(yang_lib)));
            }
            let data = parser.copy_buffer_till(b"data")?;
            // close data
            parser.close()?;
            return Ok(Self::Data(data));
        }
        Err(ParsingError::Recoverable)
    }
}

impl XmlSerialize for WellKnownRpcResponse {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        match self {
            WellKnownRpcResponse::YangSchema { schema } => {
                let mut ns_added = false;
                if writer.get_namespace_prefix(NETCONF_MONITORING_NS).is_none() {
                    ns_added = true;
                    writer.push_namespace_binding(IndexMap::from([(
                        NETCONF_MONITORING_NS,
                        "".to_string(),
                    )]))?;
                }
                let data_start = writer.create_ns_element(NETCONF_MONITORING_NS, "data")?;
                writer.write_event(Event::Start(data_start.clone()))?;
                writer.write_event(Event::Text(BytesText::new(schema.as_ref())))?;
                writer.write_event(Event::End(data_start.to_end()))?;
                if ns_added {
                    writer.pop_namespace_binding();
                }
            }
            Self::YangLibrary(library) => {
                let data_start = writer.create_element("data");
                writer.write_event(Event::Start(data_start.clone()))?;
                library.xml_serialize(writer)?;
                writer.write_event(Event::End(data_start.to_end()))?;
            }
            Self::Data(data) => {
                let data_start = writer.create_element("data");
                writer.write_event(Event::Start(data_start.clone()))?;
                writer.write_all(data.as_bytes())?;
                writer.write_event(Event::End(data_start.to_end()))?;
            }
        }
        Ok(())
    }
}

///
/// ```xml
///  <xs:complexType name="rpcErrorType">
///      <xs:sequence>
///          <xs:element name="error-type" type="ErrorType"/>
///          <xs:element name="error-tag" type="ErrorTag"/>
///          <xs:element name="error-severity" type="ErrorSeverity"/>
///          <xs:element name="error-app-tag" type="xs:string"
///                      minOccurs="0"/>
///          <xs:element name="error-path" type="xs:string" minOccurs="0"/>
///          <xs:element name="error-message" minOccurs="0">
///              <xs:complexType>
///                  <xs:simpleContent>
///                      <xs:extension base="xs:string">
///                          <xs:attribute ref="xml:lang" use="optional"/>
///                      </xs:extension>
///                  </xs:simpleContent>
///              </xs:complexType>
///          </xs:element>
///          <xs:element name="error-info" type="errorInfoType"
///                      minOccurs="0"/>
///      </xs:sequence>
///  </xs:complexType>
/// ```
#[derive(PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RpcError {
    error_type: ErrorType,
    error_tag: ErrorTag,
    error_severity: ErrorSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_app_tag: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_path: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<ErrorMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_info: Option<ErrorInfo>,
}

impl RpcError {
    pub const fn new(
        error_type: ErrorType,
        error_tag: ErrorTag,
        error_severity: ErrorSeverity,
        error_app_tag: Option<Box<str>>,
        error_path: Option<Box<str>>,
        error_message: Option<ErrorMessage>,
        error_info: Option<ErrorInfo>,
    ) -> Self {
        Self {
            error_type,
            error_tag,
            error_severity,
            error_app_tag,
            error_path,
            error_message,
            error_info,
        }
    }

    pub const fn error_type(&self) -> ErrorType {
        self.error_type
    }

    pub const fn error_tag(&self) -> ErrorTag {
        self.error_tag
    }

    pub const fn error_severity(&self) -> ErrorSeverity {
        self.error_severity
    }
    pub fn error_app_tag(&self) -> Option<&str> {
        self.error_app_tag.as_ref().map(|x| x.as_ref())
    }

    pub fn error_path(&self) -> Option<&str> {
        self.error_path.as_ref().map(|x| x.as_ref())
    }

    pub fn error_message(&self) -> Option<&ErrorMessage> {
        self.error_message.as_ref()
    }

    pub fn error_info(&self) -> Option<&ErrorInfo> {
        self.error_info.as_ref()
    }
}

impl XmlDeserialize<RpcError> for RpcError {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        let mut rpc_error = RpcError::default();
        parser.open(Some(NETCONF_NS), "rpc-error")?;
        // Skip any empty text
        rpc_error.error_type = ErrorType::xml_deserialize(parser)?;
        rpc_error.error_tag = ErrorTag::xml_deserialize(parser)?;
        rpc_error.error_severity = ErrorSeverity::xml_deserialize(parser)?;

        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "error-app-tag") {
            rpc_error.error_app_tag = Some(parser.tag_string()?);
            parser.close()?;
        }
        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "error-path") {
            rpc_error.error_path = Some(parser.tag_string()?);
            parser.close()?;
        }

        // skip empty text
        parser.skip_text()?;
        if parser.is_tag(Some(NETCONF_NS), "error-message") {
            rpc_error.error_message = Some(ErrorMessage::xml_deserialize(parser)?);
        }
        // skip empty text
        parser.skip_text()?;
        if parser.is_tag(Some(NETCONF_NS), "error-info") {
            rpc_error.error_info = Some(ErrorInfo::xml_deserialize(parser)?);
        }
        parser.close()?;
        Ok(rpc_error)
    }
}

impl XmlSerialize for RpcError {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("rpc-error");
        writer.write_event(Event::Start(start.clone()))?;

        self.error_type.xml_serialize(writer)?;
        self.error_tag.xml_serialize(writer)?;
        self.error_severity.xml_serialize(writer)?;

        if let Some(error_app_tag) = &self.error_app_tag {
            let start = writer.create_element("error-app-tag");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(error_app_tag.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }

        if let Some(error_path) = &self.error_path {
            let start = writer.create_element("error-path");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(error_path.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }

        if let Some(error_message) = &self.error_message {
            error_message.xml_serialize(writer)?;
        }

        if let Some(error_info) = &self.error_info {
            error_info.xml_serialize(writer)?;
        }

        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// <xs:element name="error-message" minOccurs="0">
///     <xs:complexType>
///         <xs:simpleContent>
///             <xs:extension base="xs:string">
///                 <xs:attribute ref="xml:lang" use="optional"/>
///             </xs:extension>
///         </xs:simpleContent>
///     </xs:complexType>
/// </xs:element>
#[derive(PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorMessage {
    // TODO: extend error message to support xs:extension
    #[serde(rename = "$text")]
    pub text: Box<str>,
}

impl XmlDeserialize<ErrorMessage> for ErrorMessage {
    fn xml_deserialize(
        parser: &mut XmlParser<impl io::BufRead>,
    ) -> Result<ErrorMessage, ParsingError> {
        // Skip any empty text
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "error-message")?;
        let text = parser.tag_string()?;
        let value = ErrorMessage { text };
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ErrorMessage {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("error-message");
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::from_escaped(format!(
            "{}",
            self.text
        ))))?;
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// ```xml
/// <xs:simpleType name="ErrorType">
///     <xs:restriction base="xs:string">
///         <xs:enumeration value="transport"/>
///         <xs:enumeration value="rpc"/>
///         <xs:enumeration value="protocol"/>
///         <xs:enumeration value="application"/>
///     </xs:restriction>
/// </xs:simpleType>
/// ```
#[derive(
    PartialEq,
    Debug,
    Copy,
    Clone,
    Default,
    Serialize,
    Deserialize,
    strum::EnumString,
    strum::Display,
)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorType {
    #[default]
    #[strum(serialize = "transport")]
    Transport,
    #[strum(serialize = "rpc")]
    Rpc,
    #[strum(serialize = "protocol")]
    Protocol,
    #[strum(serialize = "application")]
    Application,
}

impl XmlDeserialize<ErrorType> for ErrorType {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        // Skip any empty text
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "error-type")?;
        let str_value = parser.tag_string()?;
        let value = ErrorType::from_str(&str_value).map_err(|_| {
            ParsingError::InvalidValue(format!("unexpected <error-type> '{str_value}'"))
        })?;
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ErrorType {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("error-type");
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::from_escaped(format!("{self}"))))?;
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// ```xml
/// <xs:simpleType name="ErrorTag">
///     <xs:restriction base="xs:string">
///         <xs:enumeration value="in-use"/>
///         <xs:enumeration value="invalid-value"/>
///         <xs:enumeration value="too-big"/>
///         <xs:enumeration value="missing-attribute"/>
///         <xs:enumeration value="bad-attribute"/>
///         <xs:enumeration value="unknown-attribute"/>
///         <xs:enumeration value="missing-element"/>
///         <xs:enumeration value="bad-element"/>
///         <xs:enumeration value="unknown-element"/>
///         <xs:enumeration value="unknown-namespace"/>
///         <xs:enumeration value="access-denied"/>
///         <xs:enumeration value="lock-denied"/>
///         <xs:enumeration value="resource-denied"/>
///         <xs:enumeration value="rollback-failed"/>
///         <xs:enumeration value="data-exists"/>
///         <xs:enumeration value="data-missing"/>
///         <xs:enumeration value="operation-not-supported"/>
///         <xs:enumeration value="operation-failed"/>
///         <xs:enumeration value="partial-operation"/>
///         <xs:enumeration value="malformed-message"/>
///     </xs:restriction>
/// </xs:simpleType>
/// ```
#[derive(
    PartialEq,
    Debug,
    Copy,
    Clone,
    Default,
    Serialize,
    Deserialize,
    strum::EnumString,
    strum::Display,
)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorTag {
    #[default]
    #[strum(serialize = "in-use")]
    InUse,
    #[strum(serialize = "invalid-value")]
    InvalidValue,
    #[strum(serialize = "too-big")]
    TooBig,
    #[strum(serialize = "missing-attribute")]
    MissingAttribute,
    #[strum(serialize = "bad-attribute")]
    BadAttribute,
    #[strum(serialize = "unknown-attribute")]
    UnknownAttribute,
    #[strum(serialize = "missing-element")]
    MissingElement,
    #[strum(serialize = "bad-element")]
    BadElement,
    #[strum(serialize = "unknown-element")]
    UnknownElement,
    #[strum(serialize = "unknown-namespace")]
    UnknownNamespace,
    #[strum(serialize = "access-denied")]
    AccessDenied,
    #[strum(serialize = "lock-denied")]
    LockDenied,
    #[strum(serialize = "resource-denied")]
    ResourceDenied,
    #[strum(serialize = "rollback-failed")]
    RollbackFailed,
    #[strum(serialize = "data-exists")]
    DataExists,
    #[strum(serialize = "data-missing")]
    DataMissing,
    #[strum(serialize = "operation-not-supported")]
    OperationNotSupported,
    #[strum(serialize = "operation-failed")]
    OperationFailed,
    #[strum(serialize = "partial-operation")]
    PartialOperation,
    #[strum(serialize = "malformed-message")]
    MalformedMessage,
}

impl XmlDeserialize<ErrorTag> for ErrorTag {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        // Skip any empty text
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "error-tag")?;
        let str_value = parser.tag_string()?;
        let value = ErrorTag::from_str(&str_value).map_err(|_| {
            ParsingError::InvalidValue(format!("unexpected <error-tag> '{str_value}'"))
        })?;
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ErrorTag {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("error-tag");
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::from_escaped(self.to_string())))?;
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// ```xml
/// <xs:simpleType name="ErrorSeverity">
///     <xs:restriction base="xs:string">
///         <xs:enumeration value="error"/>
///         <xs:enumeration value="warning"/>
///     </xs:restriction>
/// </xs:simpleType>
/// ```
#[derive(
    PartialEq,
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Default,
    strum::EnumString,
    strum::Display,
)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorSeverity {
    #[default]
    #[strum(serialize = "error")]
    Error,
    #[strum(serialize = "warning")]
    Warning,
}

impl XmlDeserialize<ErrorSeverity> for ErrorSeverity {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        // Skip any empty text
        parser.skip_text()?;
        parser.open(Some(NETCONF_NS), "error-severity")?;
        let str_value = parser.tag_string()?;
        let value = ErrorSeverity::from_str(&str_value).map_err(|_| {
            ParsingError::InvalidValue(
                format!("unexpected <error-severity> '{str_value}'").to_string(),
            )
        })?;
        parser.close()?;
        Ok(value)
    }
}

impl XmlSerialize for ErrorSeverity {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("error-severity");
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::from_escaped(self.to_string())))?;
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// elements from any other namespace are ignored
/// ```xml
///     <xs:complexType name="errorInfoType">
///         <xs:sequence>
///             <xs:choice>
///                 <xs:element name="session-id" type="SessionIdOrZero"/>
///                 <xs:sequence minOccurs="0" maxOccurs="unbounded">
///                     <xs:sequence>
///                         <xs:element name="bad-attribute" type="xs:QName"
///                                     minOccurs="0" maxOccurs="1"/>
///                         <xs:element name="bad-element" type="xs:QName"
///                                     minOccurs="0" maxOccurs="1"/>
///                         <xs:element name="ok-element" type="xs:QName"
///                                     minOccurs="0" maxOccurs="1"/>
///                         <xs:element name="err-element" type="xs:QName"
///                                     minOccurs="0" maxOccurs="1"/>
///                         <xs:element name="noop-element" type="xs:QName"
///                                     minOccurs="0" maxOccurs="1"/>
///                         <xs:element name="bad-namespace" type="xs:string"
///                                     minOccurs="0" maxOccurs="1"/>
///                     </xs:sequence>
///                 </xs:sequence>
///             </xs:choice>
///             <!-- elements from any other namespace are also allowed
///                  to follow the NETCONF elements -->
///             <xs:any namespace="##other" processContents="lax"
///
///                     minOccurs="0" maxOccurs="unbounded"/>
///         </xs:sequence>
///     </xs:complexType>
/// ```
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorInfo {
    SessionId(u32),
    Error(Box<[ErrorInfoValue]>),
}

impl XmlDeserialize<ErrorInfo> for ErrorInfo {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.open(Some(NETCONF_NS), "error-info")?;
        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "session-id") {
            let session_id = parser.tag_string()?.parse()?;
            // Close for session-id
            parser.close()?;
            // Close for error-info
            parser.close()?;
            return Ok(ErrorInfo::SessionId(session_id));
        }
        let error_info_value: Vec<ErrorInfoValue> = parser.collect_xml_sequence()?;

        // Skipping any additional elements
        loop {
            if let Event::End(end) = parser.peek() {
                let (ns, local) = parser.ns_reader().resolve(end.name(), false);
                if ns == ResolveResult::Bound(NETCONF_NS) && local.into_inner() == b"error-info" {
                    break;
                } else {
                    parser.skip()?;
                }
            } else {
                parser.skip()?;
            }
        }
        parser.close()?;
        Ok(ErrorInfo::Error(error_info_value.into_boxed_slice()))
    }
}

impl XmlSerialize for ErrorInfo {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_element("error-info");
        writer.write_event(Event::Start(start.clone()))?;

        match self {
            ErrorInfo::SessionId(session_id) => {
                let session_id_start = writer.create_element("session-id");
                writer.write_event(Event::Start(session_id_start.clone()))?;
                writer.write_event(Event::Text(BytesText::new(&session_id.to_string())))?;
                writer.write_event(Event::End(session_id_start.to_end()))?;
            }
            ErrorInfo::Error(errors) => {
                for error in errors {
                    error.xml_serialize(writer)?;
                }
            }
        }

        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// ```xml
/// <xs:sequence>
///      <xs:element name="bad-attribute" type="xs:QName"
///                  minOccurs="0" maxOccurs="1"/>
///      <xs:element name="bad-element" type="xs:QName"
///                  minOccurs="0" maxOccurs="1"/>
///      <xs:element name="ok-element" type="xs:QName"
///                  minOccurs="0" maxOccurs="1"/>
///      <xs:element name="err-element" type="xs:QName"
///                  minOccurs="0" maxOccurs="1"/>
///      <xs:element name="noop-element" type="xs:QName"
///                  minOccurs="0" maxOccurs="1"/>
///      <xs:element name="bad-namespace" type="xs:string"
///                  minOccurs="0" maxOccurs="1"/>
///  </xs:sequence>
/// ```xml
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ErrorInfoValue {
    bad_attribute: Option<Box<str>>,
    bad_element: Option<Box<str>>,
    ok_element: Option<Box<str>>,
    error_element: Option<Box<str>>,
    noop_element: Option<Box<str>>,
    bad_namespace: Option<Box<str>>,
}

impl XmlDeserialize<ErrorInfoValue> for ErrorInfoValue {
    fn xml_deserialize(
        parser: &mut XmlParser<impl io::BufRead>,
    ) -> Result<ErrorInfoValue, ParsingError> {
        let mut at_least_one = false;
        let mut value = ErrorInfoValue {
            bad_attribute: None,
            bad_element: None,
            ok_element: None,
            error_element: None,
            noop_element: None,
            bad_namespace: None,
        };

        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "bad-attribute") {
            value.bad_attribute = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "bad-element") {
            value.bad_element = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "ok-element") {
            value.ok_element = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "err-element") {
            value.error_element = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "noop-element") {
            value.noop_element = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(Some(NETCONF_NS), "bad-namespace") {
            value.bad_namespace = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if !at_least_one {
            return Err(ParsingError::Recoverable);
        }
        Ok(value)
    }
}

impl XmlSerialize for ErrorInfoValue {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        if let Some(attr) = &self.bad_attribute {
            let start = writer.create_element("bad-attribute");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(attr.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.bad_element {
            let start = writer.create_element("bad-element");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(elem.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.ok_element {
            let start = writer.create_element("ok-element");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(elem.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.error_element {
            let start = writer.create_element("err-element");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(elem.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.noop_element {
            let start = writer.create_element("noop-element");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(elem.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }
        if let Some(ns) = &self.bad_namespace {
            let start = writer.create_element("bad-namespace");
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::from_escaped(ns.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{NetconfVersion, StandardCapability, YangCapability};
    use crate::tests::{test_parse_error, test_xml_value, test_xml_value_owned};
    use crate::yanglib::{Datastore, DatastoreName, Module, ModuleSet, Schema};
    use quick_xml::events::{BytesEnd, BytesStart};

    #[test]
    fn test_hello() -> Result<(), ParsingError> {
        let input_str = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capabilities>
        <capability>urn:ietf:params:netconf:base:1.1</capability>
        <capability>urn:ietf:params:netconf:capability:startup:1.0</capability>
        <capability>https://example.net/router/2.3/myfeature</capability>
        <capability>urn:example:yang:example-module?module=example-module&amp;revision=2022-12-22</capability>
        <capability>http://openconfig.net/yang/aaa?module=openconfig-aaa&amp;revision=2020-07-30</capability>
        <capability>http://openconfig.net/yang/alarms?module=openconfig-alarms&amp;revision=2018-01-16&amp;deviations=example-openconfig-alarms-deviation</capability>
    </capabilities>
    <session-id>4</session-id>
</hello>"#;
        let expected = Hello {
            session_id: Some(4),
            capabilities: HashSet::from([
                Capability::NetconfBase(NetconfVersion::V1_1),
                Capability::Standard(StandardCapability::Startup),
                Capability::Custom("https://example.net/router/2.3/myfeature".into()),
                Capability::Yang(YangCapability::new(
                    "urn:example:yang:example-module".into(),
                    "example-module".into(),
                    Some(chrono::NaiveDate::from_str("2022-12-22").unwrap()),
                    Box::new([]),
                    Box::new([]),
                )),
                Capability::Yang(YangCapability::new(
                    "http://openconfig.net/yang/aaa".into(),
                    "openconfig-aaa".into(),
                    Some(chrono::NaiveDate::from_str("2020-07-30").unwrap()),
                    Box::new([]),
                    Box::new([]),
                )),
                Capability::Yang(YangCapability::new(
                    "http://openconfig.net/yang/alarms".into(),
                    "openconfig-alarms".into(),
                    Some(chrono::NaiveDate::from_str("2018-01-16").unwrap()),
                    Box::new([]),
                    Box::new(["example-openconfig-alarms-deviation".into()]),
                )),
            ]),
        };

        test_xml_value(input_str, expected)?;
        Ok(())
    }

    #[test]
    fn test_hello_from_rfc_6242() -> Result<(), ParsingError> {
        let input_str = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.1
    </capability>
    <capability>
      urn:ietf:params:netconf:capability:startup:1.0
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>"#;
        let expected = NetConfMessage::Hello(Hello::new(
            Some(4),
            HashSet::from([
                Capability::NetconfBase(NetconfVersion::V1_1),
                Capability::Standard(StandardCapability::Startup),
            ]),
        ));

        test_xml_value(input_str, expected)?;
        Ok(())
    }

    #[test]
    fn test_rpc() -> Result<(), ParsingError> {
        let input_str = r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101"><copy-config><target><startup/></target><source><running/></source></copy-config></rpc>"#;

        let expected = Rpc {
            message_id: "101".into(),
            operation:
            RpcOperation::Raw(r#"<copy-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><target><startup/></target><source><running/></source></copy-config>"#.into()),
        };

        test_xml_value_owned(input_str, expected)?;
        Ok(())
    }

    #[test]
    fn test_error_type() -> Result<(), ParsingError> {
        let input_transport_str =
            r#"<error-type xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">transport</error-type>"#;
        let input_rpc_str =
            r#"<error-type xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">rpc</error-type>"#;
        let input_protocol_str =
            r#"<error-type xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">protocol</error-type>"#;
        let input_application_str = r#"<error-type xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">application</error-type>"#;
        let input_err_str =
            r#"<error-type xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">protocol1</error-type>"#;

        test_xml_value(input_transport_str, ErrorType::Transport)?;
        test_xml_value(input_rpc_str, ErrorType::Rpc)?;
        test_xml_value(input_protocol_str, ErrorType::Protocol)?;
        test_xml_value(input_application_str, ErrorType::Application)?;
        assert!(matches!(
            test_parse_error::<ErrorType>(input_err_str),
            Err(ParsingError::InvalidValue(_))
        ));
        Ok(())
    }

    #[test]
    fn test_error_tag() -> Result<(), ParsingError> {
        let in_use_str =
            r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">in-use</error-tag>"#;
        let invalid_value_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">invalid-value</error-tag>"#;
        let too_big_str =
            r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">too-big</error-tag>"#;
        let missing_attribute_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">missing-attribute</error-tag>"#;
        let bad_attribute_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">bad-attribute</error-tag>"#;
        let unknown_attribute_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">unknown-attribute</error-tag>"#;
        let missing_element_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">missing-element</error-tag>"#;
        let bad_element_str =
            r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">bad-element</error-tag>"#;
        let unknown_element_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">unknown-element</error-tag>"#;
        let unknown_namespace_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">unknown-namespace</error-tag>"#;
        let access_denied_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">access-denied</error-tag>"#;
        let lock_denied_str =
            r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">lock-denied</error-tag>"#;
        let resource_denied_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">resource-denied</error-tag>"#;
        let rollback_failed_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">rollback-failed</error-tag>"#;
        let data_exists_str =
            r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">data-exists</error-tag>"#;
        let data_missing_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">data-missing</error-tag>"#;
        let operation_not_supported_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">operation-not-supported</error-tag>"#;
        let operation_failed_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">operation-failed</error-tag>"#;
        let partial_operation_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">partial-operation</error-tag>"#;
        let malformed_message_str = r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">malformed-message</error-tag>"#;
        let input_err_str =
            r#"<error-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">not valid</error-tag>"#;

        test_xml_value(in_use_str, ErrorTag::InUse)?;
        test_xml_value(invalid_value_str, ErrorTag::InvalidValue)?;
        test_xml_value(too_big_str, ErrorTag::TooBig)?;
        test_xml_value(missing_attribute_str, ErrorTag::MissingAttribute)?;
        test_xml_value(bad_attribute_str, ErrorTag::BadAttribute)?;
        test_xml_value(unknown_attribute_str, ErrorTag::UnknownAttribute)?;
        test_xml_value(missing_element_str, ErrorTag::MissingElement)?;
        test_xml_value(bad_element_str, ErrorTag::BadElement)?;
        test_xml_value(unknown_element_str, ErrorTag::UnknownElement)?;
        test_xml_value(unknown_namespace_str, ErrorTag::UnknownNamespace)?;
        test_xml_value(access_denied_str, ErrorTag::AccessDenied)?;
        test_xml_value(lock_denied_str, ErrorTag::LockDenied)?;
        test_xml_value(resource_denied_str, ErrorTag::ResourceDenied)?;
        test_xml_value(rollback_failed_str, ErrorTag::RollbackFailed)?;
        test_xml_value(data_exists_str, ErrorTag::DataExists)?;
        test_xml_value(data_missing_str, ErrorTag::DataMissing)?;
        test_xml_value(operation_not_supported_str, ErrorTag::OperationNotSupported)?;
        test_xml_value(operation_failed_str, ErrorTag::OperationFailed)?;
        test_xml_value(partial_operation_str, ErrorTag::PartialOperation)?;
        test_xml_value(malformed_message_str, ErrorTag::MalformedMessage)?;
        assert!(matches!(
            test_parse_error::<ErrorTag>(input_err_str),
            Err(ParsingError::InvalidValue(_))
        ));
        Ok(())
    }

    #[test]
    fn test_error_severity() -> Result<(), ParsingError> {
        let error_str = r#"<error-severity xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">error</error-severity>"#;
        let warning_str = r#"<error-severity xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">warning</error-severity>"#;
        let input_err_str = r#"<error-severity xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">invalid</error-severity>"#;

        test_xml_value(error_str, ErrorSeverity::Error)?;
        test_xml_value(warning_str, ErrorSeverity::Warning)?;
        assert!(matches!(
            test_parse_error::<ErrorSeverity>(input_err_str),
            Err(ParsingError::InvalidValue(_))
        ));
        Ok(())
    }

    #[test]
    fn test_error_info() -> Result<(), ParsingError> {
        let session_id_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><session-id>454</session-id></error-info>"#;
        let bad_element_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><bad-element>rpc</bad-element><bad-element>hello</bad-element></error-info>"#;
        let bad_attributes_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><bad-attribute>size</bad-attribute><bad-attribute>color</bad-attribute></error-info>"#;
        let ok_elements_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><ok-element>config</ok-element><ok-element>data</ok-element></error-info>"#;
        let error_elements_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><err-element>filter</err-element><err-element>source</err-element></error-info>"#;
        let noop_elements_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><noop-element>get</noop-element><noop-element>edit-config</noop-element></error-info>"#;
        let bad_namespace_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><bad-namespace>urn:invalid:namespace</bad-namespace></error-info>"#;
        let mixed_error_info_str = r#"<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <bad-attribute>size</bad-attribute>
            <bad-element>rpc</bad-element>
            <ok-element>reply</ok-element>
            <err-element>filter</err-element>
            <noop-element>get</noop-element>
            <bad-namespace>urn:invalid:namespace1</bad-namespace>

            <bad-attribute>message-id</bad-attribute>
            <bad-element>session-id</bad-element>
            <ok-element>config</ok-element>
            <bad-namespace>urn:invalid:namespace2</bad-namespace>

            <ex:other-data xmlns:ex="urn:example:test">some data</ex:other-data>
        </error-info>"#;

        let session_id = ErrorInfo::SessionId(454);
        let bad_attributes = ErrorInfo::Error(
            vec![
                ErrorInfoValue {
                    bad_attribute: Some("size".into()),
                    bad_element: None,
                    ok_element: None,
                    error_element: None,
                    noop_element: None,
                    bad_namespace: None,
                },
                ErrorInfoValue {
                    bad_attribute: Some("color".into()),
                    bad_element: None,
                    ok_element: None,
                    error_element: None,
                    noop_element: None,
                    bad_namespace: None,
                },
            ]
            .into_boxed_slice(),
        );
        let bad_elements = ErrorInfo::Error(
            vec![
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: Some("rpc".into()),
                    ok_element: None,
                    error_element: None,
                    noop_element: None,
                    bad_namespace: None,
                },
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: Some("hello".into()),
                    ok_element: None,
                    error_element: None,
                    noop_element: None,
                    bad_namespace: None,
                },
            ]
            .into_boxed_slice(),
        );

        let ok_elements = ErrorInfo::Error(
            vec![
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: None,
                    ok_element: Some("config".into()),
                    error_element: None,
                    noop_element: None,
                    bad_namespace: None,
                },
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: None,
                    ok_element: Some("data".into()),
                    error_element: None,
                    noop_element: None,
                    bad_namespace: None,
                },
            ]
            .into_boxed_slice(),
        );
        let error_elements = ErrorInfo::Error(
            vec![
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: None,
                    ok_element: None,
                    error_element: Some("filter".into()),
                    noop_element: None,
                    bad_namespace: None,
                },
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: None,
                    ok_element: None,
                    error_element: Some("source".into()),
                    noop_element: None,
                    bad_namespace: None,
                },
            ]
            .into_boxed_slice(),
        );
        let noop_elements = ErrorInfo::Error(
            vec![
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: None,
                    ok_element: None,
                    error_element: None,
                    noop_element: Some("get".into()),
                    bad_namespace: None,
                },
                ErrorInfoValue {
                    bad_attribute: None,
                    bad_element: None,
                    ok_element: None,
                    error_element: None,
                    noop_element: Some("edit-config".into()),
                    bad_namespace: None,
                },
            ]
            .into_boxed_slice(),
        );
        let bad_namespace = ErrorInfo::Error(
            vec![ErrorInfoValue {
                bad_attribute: None,
                bad_element: None,
                ok_element: None,
                error_element: None,
                noop_element: None,
                bad_namespace: Some("urn:invalid:namespace".into()),
            }]
            .into_boxed_slice(),
        );
        let mixed_error_info = ErrorInfo::Error(
            vec![
                ErrorInfoValue {
                    bad_attribute: Some("size".into()),
                    bad_element: Some("rpc".into()),
                    ok_element: Some("reply".into()),
                    error_element: Some("filter".into()),
                    noop_element: Some("get".into()),
                    bad_namespace: Some("urn:invalid:namespace1".into()),
                },
                ErrorInfoValue {
                    bad_attribute: Some("message-id".into()),
                    bad_element: Some("session-id".into()),
                    ok_element: Some("config".into()),
                    error_element: None,
                    noop_element: None,
                    bad_namespace: Some("urn:invalid:namespace2".into()),
                },
            ]
            .into_boxed_slice(),
        );

        test_xml_value(session_id_str, session_id)?;
        test_xml_value(bad_attributes_str, bad_attributes)?;
        test_xml_value(bad_element_str, bad_elements)?;
        test_xml_value(ok_elements_str, ok_elements)?;
        test_xml_value(error_elements_str, error_elements)?;
        test_xml_value(noop_elements_str, noop_elements)?;
        test_xml_value(bad_namespace_str, bad_namespace)?;
        test_xml_value(mixed_error_info_str, mixed_error_info)?;

        Ok(())
    }

    #[test]
    fn test_rpc_error() -> Result<(), ParsingError> {
        let basic_str = r#"<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <error-type>protocol</error-type>
            <error-tag>operation-failed</error-tag>
            <error-severity>error</error-severity>
        </rpc-error>"#;
        let complex_str = r#"<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <error-type>protocol</error-type>
            <error-tag>bad-attribute</error-tag>
            <error-severity>error</error-severity>
            <error-app-tag>too-big</error-app-tag>
            <error-path>/rpc/edit-config/config/top/interface[name="Ethernet0/0"]</error-path>
            <error-message>The requested operation could not be completed.</error-message>
            <error-info>
                <bad-attribute>message-id</bad-attribute>
                <bad-element>rpc</bad-element>
            </error-info>
        </rpc-error>"#;
        let empty_error_info_str = r#"<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <error-type>rpc</error-type>
            <error-tag>missing-attribute</error-tag>
            <error-severity>error</error-severity>
            <error-info></error-info>
        </rpc-error>"#;
        let missing_error_type_str = r#"<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <error-tag>operation-failed</error-tag>
            <error-severity>error</error-severity>
        </rpc-error>"#;
        let missing_error_tag_str = r#"<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <error-type>protocol</error-type>
            <error-severity>error</error-severity>
        </rpc-error>"#;
        let missing_error_severity_str = r#"<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <error-type>protocol</error-type>
            <error-tag>operation-failed</error-tag>
        </rpc-error>"#;

        let basic = RpcError {
            error_type: ErrorType::Protocol,
            error_tag: ErrorTag::OperationFailed,
            error_severity: ErrorSeverity::Error,
            error_app_tag: None,
            error_path: None,
            error_message: None,
            error_info: None,
        };
        let complex = RpcError {
            error_type: ErrorType::Protocol,
            error_tag: ErrorTag::BadAttribute,
            error_severity: ErrorSeverity::Error,
            error_app_tag: Some("too-big".into()),
            error_path: Some(r#"/rpc/edit-config/config/top/interface[name="Ethernet0/0"]"#.into()),
            error_message: Some(ErrorMessage {
                text: "The requested operation could not be completed.".into(),
            }),
            error_info: Some(ErrorInfo::Error(
                vec![ErrorInfoValue {
                    bad_attribute: Some("message-id".into()),
                    bad_element: Some("rpc".into()),
                    ok_element: None,
                    error_element: None,
                    noop_element: None,
                    bad_namespace: None,
                }]
                .into_boxed_slice(),
            )),
        };

        let empty_error_info = RpcError {
            error_type: ErrorType::Rpc,
            error_tag: ErrorTag::MissingAttribute,
            error_severity: ErrorSeverity::Error,
            error_app_tag: None,
            error_path: None,
            error_message: None,
            error_info: Some(ErrorInfo::Error(Box::new([]))),
        };

        test_xml_value(basic_str, basic)?;
        test_xml_value(complex_str, complex)?;
        test_xml_value(empty_error_info_str, empty_error_info)?;

        let missing_error_type = test_parse_error::<RpcError>(missing_error_type_str);
        let expected_missing_error_type = Err(ParsingError::WrongToken {
            expecting: "<error-type>".to_string(),
            found: Event::Start(BytesStart::new("error-tag")),
        });
        assert_eq!(missing_error_type, expected_missing_error_type);

        let missing_error_tag = test_parse_error::<RpcError>(missing_error_tag_str);
        let expected_missing_error_tag = Err(ParsingError::WrongToken {
            expecting: "<error-tag>".to_string(),
            found: Event::Start(BytesStart::new("error-severity")),
        });
        assert_eq!(missing_error_tag, expected_missing_error_tag);

        let missing_error_severity = test_parse_error::<RpcError>(missing_error_severity_str);
        let expected_missing_error_severity = Err(ParsingError::WrongToken {
            expecting: "<error-severity>".to_string(),
            found: Event::End(BytesEnd::new("rpc-error")),
        });
        assert_eq!(missing_error_severity, expected_missing_error_severity);
        Ok(())
    }

    #[test]
    fn test_rpc_reply_rfc() -> Result<(), ParsingError> {
        let input_str1 = r#"<rpc-reply message-id="101"
          xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
       <data attr1="x">
         <top xmlns="https://example.com/schema/1.2/stats">
           <interfaces>
             <interface>
               <ifName>eth0</ifName>
               <ifInOctets>45621</ifInOctets>
               <ifOutOctets>774344</ifOutOctets>
             </interface>
           </interfaces>
         </top>
       </data>
     </rpc-reply>"#;
        let expected_data1 = r#"<top xmlns="https://example.com/schema/1.2/stats">
           <interfaces>
             <interface>
               <ifName>eth0</ifName>
               <ifInOctets>45621</ifInOctets>
               <ifOutOctets>774344</ifOutOctets>
             </interface>
           </interfaces>
         </top>
       "#;

        let expected1 = RpcReply {
            message_id: Some("101".into()),
            reply: RpcReplyContent::ErrorsAndData {
                errors: vec![],
                responses: RpcResponse::WellKnown(WellKnownRpcResponse::Data(
                    expected_data1.into(),
                )),
            },
        };
        test_xml_value(input_str1, expected1)?;
        Ok(())
    }

    #[test]
    fn test_rpc_reply_yang() -> Result<(), ParsingError> {
        let input_str1 = r#"<rpc-reply message-id="103"
         xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">module bar-types {
             //default format (yang) returned
             //latest revision returned
             //is version 2008-06-01 yang module
             //contents here ...
           }</data>
       </rpc-reply>"#;
        let expected_data1 = r#"module bar-types {
             //default format (yang) returned
             //latest revision returned
             //is version 2008-06-01 yang module
             //contents here ...
           }"#;

        let expected1 = RpcReply {
            message_id: Some("103".into()),
            reply: RpcReplyContent::ErrorsAndData {
                errors: vec![],
                responses: RpcResponse::WellKnown(WellKnownRpcResponse::YangSchema {
                    schema: expected_data1.into(),
                }),
            },
        };
        test_xml_value(input_str1, expected1)?;
        Ok(())
    }

    #[test]
    fn test_rpc_reply_content() {
        let data = RpcResponse::Raw("SomeData".into());
        let errors = vec![RpcError::default()];
        let with_ok = RpcReplyContent::Ok;
        let with_data_and_errors = RpcReplyContent::ErrorsAndData {
            errors: errors.clone(),
            responses: data.clone(),
        };
        let with_data_no_errors = RpcReplyContent::ErrorsAndData {
            errors: vec![],
            responses: data.clone(),
        };
        assert!(with_ok.is_ok());
        assert!(!with_data_no_errors.is_ok());
        assert!(!with_data_no_errors.is_ok());

        assert!(!with_ok.has_errors());
        assert!(with_data_and_errors.has_errors());
        assert!(!with_data_no_errors.has_errors());

        assert_eq!(with_ok.errors(), None);
        assert_eq!(with_data_and_errors.errors(), Some(errors.as_slice()));
        assert_eq!(with_data_no_errors.errors(), Some(vec![].as_slice()));

        assert_eq!(with_ok.responses(), None);
        assert_eq!(with_ok.responses(), None);
        assert_eq!(with_data_and_errors.responses(), Some(data).as_ref());
    }

    #[test]
    fn test_with_netconf_message() -> Result<(), ParsingError> {
        let hello_str = r#"<?xml version="1.0"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities></capabilities><session-id>4</session-id></hello>"#;
        let rpc_str = r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101"><copy-config><target><startup/></target><source><running/></source></copy-config></rpc>"#;
        let rpc_reply_str = r#"<?xml version="1.0"?>
        <rpc-reply message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <data></data></rpc-reply>"#;
        let expected_rpc_reply_data = RpcResponse::WellKnown(WellKnownRpcResponse::Data("".into()));

        let hello = NetConfMessage::Hello(Hello::new(Some(4), HashSet::new()));
        let rpc = NetConfMessage::Rpc(Rpc::new("101".into(), RpcOperation::Raw("<copy-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><startup/></target><source><running/></source></copy-config>".into())));
        let rpc_reply = NetConfMessage::RpcReply(RpcReply {
            message_id: Some("101".into()),
            reply: RpcReplyContent::ErrorsAndData {
                errors: vec![],
                responses: expected_rpc_reply_data,
            },
        });
        test_xml_value(hello_str, hello)?;
        test_xml_value(rpc_str, rpc)?;
        test_xml_value(rpc_reply_str, rpc_reply)?;
        Ok(())
    }

    #[test]
    fn test_get_config() -> Result<(), ParsingError> {
        let get_config_str = r#"<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <source>
           <running/>
         </source>
         <filter type="subtree"><top xmlns="http://example.com/schema/1.2/config"><users/></top></filter>
       </get-config>"#;
        let get_config = WellKnownOperation::GetConfig {
            source: ConfigSource::Running,
            filter: Filter::Subtree(
                r#"<top xmlns="http://example.com/schema/1.2/config"><users/></top>"#.into(),
            ),
        };
        test_xml_value(get_config_str, get_config)?;
        Ok(())
    }

    #[test]
    fn test_edit_test_option() -> Result<(), ParsingError> {
        let test_then_set_str = r#"<test-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        test-then-set
       </test-option>"#;
        let set_str =
            r#"<test-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">set</test-option>"#;
        let test_only_str = r#"<test-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        test-only
       </test-option>"#;
        let unknown_value_str =
            r#"<test-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">UNKNOWN</test-option>"#;
        let invalid_tag_str = r#"<some-other-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">INVALID</some-other-tag>"#;

        let test_then_set = ConfigEditTestOption::TestThenSet;
        let set = ConfigEditTestOption::Set;
        let test_only = ConfigEditTestOption::TestOnly;
        let unknown_value = Err(ParsingError::InvalidValue(
            "unknown test-option `UNKNOWN`".to_string(),
        ));
        let invalid_tag = Err(ParsingError::WrongToken {
            expecting: "<test-option>".to_string(),
            found: Event::Start(BytesStart::from_content(
                "some-other-tag xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"",
                14,
            )),
        });

        test_xml_value(test_then_set_str, test_then_set)?;
        test_xml_value(set_str, set)?;
        test_xml_value(test_only_str, test_only)?;
        assert_eq!(
            test_parse_error::<ConfigEditTestOption>(unknown_value_str),
            unknown_value
        );
        assert_eq!(
            test_parse_error::<ConfigEditTestOption>(invalid_tag_str),
            invalid_tag
        );
        Ok(())
    }

    #[test]
    fn test_config_source() -> Result<(), ParsingError> {
        let candidate_str =
            r#"<source xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><candidate/></source>"#;
        let running_str =
            r#"<source xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><running/></source>"#;
        let startup_str = r#"<source xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><startup></startup></source>"#;
        let unknown_value_str =
            r#"<source xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><UNKNOWN/></source>"#;
        let invalid_tag_str = r#"<some-other-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">INVALID</some-other-tag>"#;

        let candidate = ConfigSource::Candidate;
        let running = ConfigSource::Running;
        let startup = ConfigSource::Startup;
        let unknown_value = Err(ParsingError::WrongToken {
            expecting: "<candidate/>, <running/>, <startup/>".into(),
            found: Event::Empty(BytesStart::new("UNKNOWN")).into_owned(),
        });
        let invalid_tag = Err(ParsingError::WrongToken {
            expecting: "<source>".to_string(),
            found: Event::Start(BytesStart::from_content(
                "some-other-tag xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"",
                14,
            )),
        });

        test_xml_value(candidate_str, candidate).expect("candidate");
        test_xml_value(running_str, running).expect("running");
        test_xml_value(startup_str, startup).expect("startup");
        assert_eq!(
            test_parse_error::<ConfigSource>(unknown_value_str),
            unknown_value
        );
        assert_eq!(
            test_parse_error::<ConfigSource>(invalid_tag_str),
            invalid_tag
        );
        Ok(())
    }

    #[test]
    fn test_config_target() -> Result<(), ParsingError> {
        let candidate_str =
            r#"<target xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><candidate/></target>"#;
        let running_str = r#"<target xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><running> </running></target>"#;
        let unknown_value_str =
            r#"<target xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><UNKNOWN/></target>"#;
        let invalid_tag_str = r#"<some-other-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">INVALID</some-other-tag>"#;

        let candidate = ConfigTarget::Candidate;
        let running = ConfigTarget::Running;
        let unknown_value = Err(ParsingError::WrongToken {
            expecting: "<candidate/> or <running/>".to_string(),
            found: Event::Empty(BytesStart::from_content("UNKNOWN", 7)),
        });
        let invalid_tag = Err(ParsingError::WrongToken {
            expecting: "<target>".to_string(),
            found: Event::Start(BytesStart::from_content(
                "some-other-tag xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"",
                14,
            )),
        });

        test_xml_value(candidate_str, candidate)?;
        test_xml_value(running_str, running)?;
        assert_eq!(
            test_parse_error::<ConfigTarget>(unknown_value_str),
            unknown_value
        );
        assert_eq!(
            test_parse_error::<ConfigTarget>(invalid_tag_str),
            invalid_tag
        );
        Ok(())
    }

    #[test]
    fn test_config_update_default_operation() -> Result<(), ParsingError> {
        let merge_str = r#"<default-operation xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">merge</default-operation>"#;
        let replace_str = r#"<default-operation xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">replace</default-operation>"#;
        let none_str = r#"<default-operation xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">none</default-operation>"#;
        let unknown_value_str = r#"<default-operation xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">UNKNOWN</default-operation>"#;
        let invalid_tag_str = r#"<some-other-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">INVALID</some-other-tag>"#;

        let merge = ConfigUpdateDefaultOperation::Merge;
        let replace = ConfigUpdateDefaultOperation::Replace;
        let none = ConfigUpdateDefaultOperation::None;
        let unknown_value = Err(ParsingError::InvalidValue(
            "unknown default-operation `UNKNOWN`".to_string(),
        ));
        let invalid_tag = Err(ParsingError::WrongToken {
            expecting: "<default-operation>".to_string(),
            found: Event::Start(BytesStart::from_content(
                "some-other-tag xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"",
                14,
            )),
        });

        test_xml_value(merge_str, merge)?;
        test_xml_value(replace_str, replace)?;
        test_xml_value(none_str, none)?;
        assert_eq!(
            test_parse_error::<ConfigUpdateDefaultOperation>(unknown_value_str),
            unknown_value
        );
        assert_eq!(
            test_parse_error::<ConfigUpdateDefaultOperation>(invalid_tag_str),
            invalid_tag
        );
        Ok(())
    }

    #[test]
    fn test_filter_subtree() -> Result<(), ParsingError> {
        let subtree_str = r#"<filter type="subtree" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><top xmlns="http://example.com/schema/1.2/config"><users/></top></filter>"#;
        let subtree_no_type_str = r#"<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><top xmlns="http://example.com/schema/1.2/config"><users/></top></filter>"#;
        let subtree_complex_str = r#"<filter type="subtree" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <top xmlns="http://example.com/schema/1.2/config">
                    <users>
                        <user>
                            <name>fred</name>
                        </user>
                    </users>
                </top>
            </filter>"#;
        let subtree_empty_str =
            r#"<filter type="subtree" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"></filter>"#;

        let expected_subtree = Filter::Subtree(
            r#"<top xmlns="http://example.com/schema/1.2/config"><users/></top>"#.into(),
        );
        let expected_subtree_no_type = Filter::Subtree(
            r#"<top xmlns="http://example.com/schema/1.2/config"><users/></top>"#.into(),
        );
        let expected_subtree_complex = Filter::Subtree(
            r#"
                <top xmlns="http://example.com/schema/1.2/config">
                    <users>
                        <user>
                            <name>fred</name>
                        </user>
                    </users>
                </top>
            "#
            .into(),
        );
        let expected_subtree_empty = Filter::Subtree("".into());

        test_xml_value(subtree_str, expected_subtree)?;
        test_xml_value(subtree_no_type_str, expected_subtree_no_type)?;
        test_xml_value(subtree_complex_str, expected_subtree_complex)?;
        test_xml_value(subtree_empty_str, expected_subtree_empty)?;
        Ok(())
    }

    #[test]
    fn test_filter_xpath() -> Result<(), ParsingError> {
        let xpath_str = r#"<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:t="http://example.com/schema/1.2/config" type="xpath" select="/t:top/t:users/t:user[t:name='fred']"/>"#;
        let xpath_complex_str = r#"<filter type="xpath" select="/top/interfaces/interface[enabled='true' and type='ethernet']" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>"#;
        let xpath_namespace_str = r#"<filter type="xpath" select="/ex:top/ex:users" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:ex="http://example.com/schema"/>"#;
        let xpath_with_content_str = r#"<filter type="xpath" select="/top/users" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">ignored content</filter>"#;
        let xpath_empty_select_str =
            r#"<filter type="xpath" select="" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>"#;

        let expected_xpath = Filter::XPath("/t:top/t:users/t:user[t:name='fred']".into());
        let expected_xpath_complex =
            Filter::XPath("/top/interfaces/interface[enabled='true' and type='ethernet']".into());
        let expected_xpath_namespace = Filter::XPath("/ex:top/ex:users".into());
        let expected_xpath_with_content = Filter::XPath("/top/users".into());
        let expected_xpath_empty = Filter::XPath("".into());

        test_xml_value(xpath_str, expected_xpath).expect("failed to test xpath");
        test_xml_value(xpath_complex_str, expected_xpath_complex)
            .expect("failed to test complex xpath");
        test_xml_value(xpath_namespace_str, expected_xpath_namespace)
            .expect("failed to test xpath namespace");
        test_xml_value(xpath_with_content_str, expected_xpath_with_content)
            .expect("failed to test xpath with content xpath");
        test_xml_value(xpath_empty_select_str, expected_xpath_empty)
            .expect("failed to test xpath empty select");
        Ok(())
    }

    #[test]
    fn test_filter_edge_cases() -> Result<(), ParsingError> {
        // Invalid type attribute
        let invalid_type_str =
            r#"<filter type="invalid" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>"#;
        let invalid_type_result = test_parse_error::<Filter>(invalid_type_str);
        assert!(matches!(
            invalid_type_result,
            Err(ParsingError::InvalidValue(_))
        ));

        // XPath without select attribute
        let xpath_no_select_str =
            r#"<filter type="xpath" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>"#;
        let xpath_no_select_result = test_parse_error::<Filter>(xpath_no_select_str);
        assert!(matches!(
            xpath_no_select_result,
            Err(ParsingError::MissingAttribute(_))
        ));

        // Mixed content in subtree filter
        let mixed_content_str = r#"<filter type="subtree" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                Some text
                <top xmlns="http://example.com/schema/1.2/config">
                    <users/>
                </top>
                More text
            </filter>"#;
        let expected_mixed = Filter::Subtree(
            r#"
                Some text
                <top xmlns="http://example.com/schema/1.2/config">
                    <users/>
                </top>
                More text
            "#
            .into(),
        );
        test_xml_value(mixed_content_str, expected_mixed)?;

        // Multiple namespace declarations
        let multi_ns_str = r#"<filter type="subtree" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <top xmlns="http://example.com/schema" xmlns:x="http://other.com">
                    <x:element/>
                </top>
            </filter>"#;
        let expected_multi_ns = Filter::Subtree(
            r#"
                <top xmlns="http://example.com/schema" xmlns:x="http://other.com">
                    <x:element/>
                </top>
            "#
            .into(),
        );
        test_xml_value(multi_ns_str, expected_multi_ns)?;

        // Case sensitivity check
        let case_sensitive_type_str =
            r#"<filter type="SUBTREE" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>"#;
        let case_sensitive_result = test_parse_error::<Filter>(case_sensitive_type_str);
        assert!(matches!(
            case_sensitive_result,
            Err(ParsingError::InvalidValue(_))
        ));
        Ok(())
    }

    #[test]
    fn test_config_error_option() -> Result<(), ParsingError> {
        let stop_on_error_str = r#"<error-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">stop-on-error</error-option>"#;
        let continue_on_error_str = r#"<error-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">continue-on-error</error-option>"#;
        let rollback_on_error_str = r#"<error-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">rollback-on-error</error-option>"#;
        let unknown_value_str = r#"<error-option xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">UNKNOWN</error-option>"#;
        let invalid_tag_str = r#"<some-other-tag xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">INVALID</some-other-tag>"#;

        let stop_on_error = ConfigErrorOption::StopOnError;
        let continue_on_error = ConfigErrorOption::ContinueOnError;
        let rollback_on_error = ConfigErrorOption::RollbackOnError;
        let unknown_value = Err(ParsingError::InvalidValue(
            "unknown error-option `UNKNOWN`".to_string(),
        ));
        let invalid_tag = Err(ParsingError::WrongToken {
            expecting: "<error-option>".to_string(),
            found: Event::Start(BytesStart::from_content(
                "some-other-tag xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"",
                14,
            )),
        });

        test_xml_value(stop_on_error_str, stop_on_error)?;
        test_xml_value(continue_on_error_str, continue_on_error)?;
        test_xml_value(rollback_on_error_str, rollback_on_error)?;
        assert_eq!(
            test_parse_error::<ConfigErrorOption>(unknown_value_str),
            unknown_value
        );
        assert_eq!(
            test_parse_error::<ConfigErrorOption>(invalid_tag_str),
            invalid_tag
        );
        Ok(())
    }

    #[test]
    fn test_edit_config() -> Result<(), ParsingError> {
        let edit_config_str = r#"<edit-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <target>
           <running/>
         </target>
         <default-operation>merge</default-operation>
         <test-option>test-then-set</test-option>
         <error-option>stop-on-error</error-option>
         <config>
           <top xmlns="http://example.com/schema/1.2/config">
             <users>
               <user>
                 <name>fred</name>
                 <uid>1000</uid>
               </user>
             </users>
           </top>
         </config>
       </edit-config>"#;

        let expected_edit_config = WellKnownOperation::EditConfig {
            target: ConfigTarget::Running,
            default_operation: ConfigUpdateDefaultOperation::Merge,
            test_option: Some(ConfigEditTestOption::TestThenSet),
            error_option: Some(ConfigErrorOption::StopOnError),
            edit_content: EditConfig::Config(
                r#"
           <top xmlns="http://example.com/schema/1.2/config">
             <users>
               <user>
                 <name>fred</name>
                 <uid>1000</uid>
               </user>
             </users>
           </top>
         "#
                .into(),
            ),
        };

        test_xml_value(edit_config_str, expected_edit_config)?;
        Ok(())
    }

    #[test]
    fn test_edit_content() -> Result<(), ParsingError> {
        let config_str = r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
           <top xmlns="http://example.com/schema/1.2/config">
             <users>
               <user>
                 <name>fred</name>
                 <uid>1000</uid>
               </user>
             </users>
           </top>
         </config>"#;
        let url_str = r#"<url xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">http://example.com/configs/base-config.xml</url>"#;

        let expected_config = EditConfig::Config(
            r#"
           <top xmlns="http://example.com/schema/1.2/config">
             <users>
               <user>
                 <name>fred</name>
                 <uid>1000</uid>
               </user>
             </users>
           </top>
         "#
            .into(),
        );
        let expected_url = EditConfig::Url("http://example.com/configs/base-config.xml".into());

        test_xml_value(config_str, expected_config)?;
        test_xml_value(url_str, expected_url)?;
        Ok(())
    }

    #[test]
    fn test_get() -> Result<(), ParsingError> {
        let get_str = r#"<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <filter type="subtree"><top xmlns="http://example.com/schema/1.2/stats"><interfaces/></top></filter>
       </get>"#;
        let get = WellKnownOperation::Get {
            filter: Filter::Subtree(
                r#"<top xmlns="http://example.com/schema/1.2/stats"><interfaces/></top>"#.into(),
            ),
        };
        test_xml_value(get_str, get)?;
        Ok(())
    }

    #[test]
    fn test_get_rpc() -> Result<(), ParsingError> {
        let get_str = r#"<rpc message-id="123" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><get>
         <filter type="subtree"><top xmlns="http://example.com/schema/1.2/stats"><interfaces/></top></filter>
       </get></rpc>"#;
        let get = Rpc::new(
            "123".into(),
            RpcOperation::WellKnown(WellKnownOperation::Get {
                filter: Filter::Subtree(
                    r#"<top xmlns="http://example.com/schema/1.2/stats"><interfaces/></top>"#
                        .into(),
                ),
            }),
        );
        test_xml_value(get_str, get)?;
        Ok(())
    }

    #[test]
    fn test_get_schema() -> Result<(), ParsingError> {
        let get_schema_str = r#"<get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
            <identifier>foo</identifier>
            <version>  1.0</version>
            <format>  yang  </format>
        </get-schema>"#;
        let get_schema = WellKnownOperation::GetSchema {
            identifier: "foo".into(),
            version: Some("1.0".into()),
            format: Some(YangSchemaFormat::Yang),
        };
        test_xml_value(get_schema_str, get_schema)?;
        Ok(())
    }

    #[test]
    fn test_get_schema_rpc() -> Result<(), ParsingError> {
        let get_schema_str = r#"<rpc message-id="123" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
                <identifier>foo</identifier>
                <version>  1.0</version>
                <format>  yang  </format>
            </get-schema>
        </rpc>"#;
        let get_schema = Rpc::new(
            "123".into(),
            RpcOperation::WellKnown(WellKnownOperation::GetSchema {
                identifier: "foo".into(),
                version: Some("1.0".into()),
                format: Some(YangSchemaFormat::Yang),
            }),
        );
        test_xml_value(get_schema_str, get_schema)?;
        Ok(())
    }

    #[test]
    fn test_get_schema_response() -> Result<(), ParsingError> {
        let get_schema_response_str = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
           message-id="10110">
  <data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">module tiny-example {
  yang-version 1.1;
  namespace "http://example.com/tiny";
  prefix "tiny";

  leaf hostname {
    type string {
      pattern "[a-zA-Z0-9\-]+";
    }
    description "System hostname";
  }

  leaf admin-email {
    type string {
      pattern "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}";
    }
    description "Admin's email &lt;required&gt;";
  }

  leaf threshold {
    type uint32;
    must ". &gt; 100 and . &lt; 1000" {
      error-message "Value must be &gt; 100 &amp; &lt; 1000";
    }
  }
}</data>
</rpc-reply>"#;
        let get_schema_response = RpcReply::new(
            Some("10110".into()),
            RpcReplyContent::ErrorsAndData {
                errors: vec![],
                responses: RpcResponse::WellKnown(WellKnownRpcResponse::YangSchema {
                    schema: r#"module tiny-example {
  yang-version 1.1;
  namespace "http://example.com/tiny";
  prefix "tiny";

  leaf hostname {
    type string {
      pattern "[a-zA-Z0-9\-]+";
    }
    description "System hostname";
  }

  leaf admin-email {
    type string {
      pattern "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}";
    }
    description "Admin's email <required>";
  }

  leaf threshold {
    type uint32;
    must ". > 100 and . < 1000" {
      error-message "Value must be > 100 & < 1000";
    }
  }
}"#
                    .into(),
                }),
            },
        );

        test_xml_value(get_schema_response_str, get_schema_response)?;
        Ok(())
    }

    #[test]
    fn test_yang_library_rfc8525() -> Result<(), ParsingError> {
        // RFC 8525 Appendix C - Example YANG Library Instance for an Advanced Server
        let library_str = r#"<yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library" xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">
     <module-set>
       <name>state-only-modules</name>
       <module>
         <name>ietf-hardware</name>
         <revision>2018-03-13</revision>
         <namespace>
           urn:ietf:params:xml:ns:yang:ietf-hardware
         </namespace>
         <deviation>example-vendor-hardware-deviations</deviation>
       </module>
       <module>
         <name>ietf-routing</name>
         <revision>2018-03-13</revision>
         <namespace>
           urn:ietf:params:xml:ns:yang:ietf-routing
         </namespace>
         <feature>multiple-ribs</feature>
         <feature>router-id</feature>
       </module>
     </module-set>
     <schema>
       <name>state-schema</name>
       <module-set>state-only-modules</module-set>
     </schema>
     <datastore>
       <name>ds:operational</name>
       <schema>state-schema</schema>
     </datastore>
     <content-id>14782ab9bd56b92aacc156a2958fbe12312fb285</content-id>
   </yang-library>"#;

        let input_str = format!(
            r#"<?xml version='1.0' encoding='UTF-8'?>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:uuid:a8ba4055-2d26-431f-ad49-620f073b921c">
  <data>
  {library_str}</data></rpc-reply>"#
        );

        let expected_library = YangLibrary::new(
            "14782ab9bd56b92aacc156a2958fbe12312fb285".into(),
            vec![ModuleSet::new(
                "state-only-modules".into(),
                vec![
                    Module::new(
                        "ietf-hardware".into(),
                        Some("2018-03-13".into()),
                        "urn:ietf:params:xml:ns:yang:ietf-hardware".into(),
                        Box::new([]),
                        Box::new(["example-vendor-hardware-deviations".into()]),
                        Box::new([]),
                        Box::new([]),
                        Box::new([]),
                    ),
                    Module::new(
                        "ietf-routing".into(),
                        Some("2018-03-13".into()),
                        "urn:ietf:params:xml:ns:yang:ietf-routing".into(),
                        Box::new(["multiple-ribs".into(), "router-id".into()]),
                        Box::new([]),
                        Box::new([]),
                        Box::new([]),
                        Box::new([]),
                    ),
                ],
                vec![],
            )],
            vec![Schema::new(
                "state-schema".into(),
                Box::new(["state-only-modules".into()]),
            )],
            vec![Datastore::new(
                DatastoreName::Operational,
                "state-schema".into(),
            )],
        );
        let expect_rpc_reply = RpcReplyContent::ErrorsAndData {
            errors: vec![],
            responses: RpcResponse::WellKnown(WellKnownRpcResponse::YangLibrary(Arc::new(
                expected_library,
            ))),
        };
        let expected = NetConfMessage::RpcReply(RpcReply::new(
            Some("urn:uuid:a8ba4055-2d26-431f-ad49-620f073b921c".into()),
            expect_rpc_reply,
        ));

        test_xml_value(&input_str, expected)?;
        Ok(())
    }
}
