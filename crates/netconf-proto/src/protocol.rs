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

use crate::{
    capabilities::{Capability, CapabilityImpl},
    xml_parser::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
};
use quick_xml::{
    events::{BytesStart, BytesText, Event},
    name::{Namespace, ResolveResult},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io, str::FromStr};

pub(crate) const NETCONF_NS_STR: &[u8] = b"urn:ietf:params:xml:ns:netconf:base:1.0";
pub(crate) const NETCONF_NS: Namespace<'static> = Namespace(NETCONF_NS_STR);

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
            token => Err(ParsingError::WrongToken(format!("{token:?}"))),
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

#[derive(PartialEq, Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename = "hello")]
pub struct Hello {
    pub capabilities: HashMap<Box<str>, Capability>,
    #[serde(rename = "session-id")]
    pub session_id: Option<u32>,
}

impl XmlDeserialize<Hello> for Hello {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Hello, ParsingError> {
        // Skip XML declaration header if present in the message
        if matches!(parser.peek(), Event::Decl(_)) {
            parser.skip()?;
        }
        // Skip any empty text
        parser.skip_text()?;
        parser.open_start(NETCONF_NS_STR, "hello")?;
        parser.open_start_check_missing(NETCONF_NS_STR, "capabilities")?;
        let capabilities = parser
            .collect::<Capability>()?
            .into_iter()
            .map(|x| (x.shorthand(), x))
            .collect::<HashMap<Box<str>, Capability>>();
        parser.close()?;
        let session_id = if parser.maybe_open(NETCONF_NS_STR, "session-id")?.is_some() {
            let val = parser.tag_string()?.parse::<u32>()?;
            parser.close()?;
            Some(val)
        } else {
            None
        };
        parser.close()?;
        Ok(Hello {
            capabilities,
            session_id,
        })
    }
}

impl XmlSerialize for Hello {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let hello_start = writer.create_nc_element("hello");
        let capabilities_start = writer.create_nc_element("capabilities");
        writer
            .inner
            .write_event(Event::Start(hello_start.clone()))?;
        writer
            .inner
            .write_event(Event::Start(capabilities_start.clone()))?;
        for cap in &self.capabilities {
            cap.1.xml_serialize(writer)?
        }
        writer
            .inner
            .write_event(Event::End(capabilities_start.to_end()))?;
        if let Some(session_id) = self.session_id {
            let session_id_start = writer.create_nc_element("session-id");
            writer
                .inner
                .write_event(Event::Start(session_id_start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(&format!("{session_id}"))))?;
            writer
                .inner
                .write_event(Event::End(session_id_start.to_end()))?;
        }
        writer.inner.write_event(Event::End(hello_start.to_end()))?;
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
#[derive(PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Rpc {
    pub message_id: String,
    pub operation: String,
}

impl XmlDeserialize<Rpc> for Rpc {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Rpc, ParsingError> {
        // Skip XML declaration header if present in the message
        if matches!(parser.peek(), Event::Decl(_)) {
            parser.skip()?;
        }
        // Skip any empty text
        parser.skip_text()?;
        let open = parser.open(NETCONF_NS_STR, "rpc")?;
        let open = if let Event::Start(open) = open {
            open
        } else {
            return Err(ParsingError::WrongToken(format!("{open:?}")));
        };
        let message_id = if let Some(msg_id) = extract_message_id(open)? {
            msg_id
        } else {
            return Err(ParsingError::MissingAttribute);
        };
        let operation = parser.copy_buffer_till(b"rpc")?;
        parser.close()?;
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
        let mut start = writer.create_nc_element("rpc");
        start.push_attribute(("message-id", self.message_id.as_str()));
        writer.inner.write_event(Event::Start(start.clone()))?;
        writer
            .inner
            .get_mut()
            .write_all(self.operation.as_bytes())?;
        writer.inner.write_event(Event::End(start.to_end()))?;
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
#[serde(rename_all = "kebab-case")]
pub enum RpcReplyValue {
    #[default]
    Ok,
    Data(Vec<RpcError>, String),
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
    pub error_type: Vec<ErrorType>,
    pub error_tag: Vec<ErrorTag>,
    pub error_severity: Vec<ErrorSeverity>,
    pub error_app_tag: Vec<String>,
    pub error_path: Vec<String>,
    pub error_message: Vec<String>,
    pub error_info: Vec<ErrorInfo>,
}

impl XmlDeserialize<RpcError> for RpcError {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        let mut rpc_error = RpcError::default();
        parser.open(NETCONF_NS_STR, "rpc-error")?;
        rpc_error.error_type = parser.collect_tag(NETCONF_NS_STR, b"error-type")?;
        if rpc_error.error_type.is_empty() {
            return Err(ParsingError::MissingChild("error-type".to_string()));
        }
        rpc_error.error_tag = parser.collect_tag(NETCONF_NS_STR, b"error-tag")?;
        if rpc_error.error_tag.is_empty() {
            return Err(ParsingError::MissingChild("error-tag".to_string()));
        }
        rpc_error.error_severity = parser.collect_tag(NETCONF_NS_STR, b"error-severity")?;
        if rpc_error.error_severity.is_empty() {
            return Err(ParsingError::MissingChild("error-severity".to_string()));
        }
        while let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "error-app-tag") {
            rpc_error.error_app_tag.push(parser.tag_string()?);
            parser.close()?;
        }
        while let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "error-path") {
            rpc_error.error_path.push(parser.tag_string()?);
            parser.close()?;
        }
        while let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "error-message") {
            rpc_error.error_message.push(parser.tag_string()?);
            parser.close()?;
        }
        rpc_error.error_info = parser.collect_tag(NETCONF_NS_STR, b"error-info")?;
        parser.close()?;
        Ok(rpc_error)
    }
}

impl XmlSerialize for RpcError {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_nc_element("rpc-error");
        writer.inner.write_event(Event::Start(start.clone()))?;

        for error_type in &self.error_type {
            error_type.xml_serialize(writer)?;
        }

        for error_tag in &self.error_tag {
            error_tag.xml_serialize(writer)?;
        }

        for error_severity in &self.error_severity {
            error_severity.xml_serialize(writer)?;
        }

        for error_app_tag in &self.error_app_tag {
            let start = writer.create_nc_element("error-app-tag");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(error_app_tag)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }

        for error_path in &self.error_path {
            let start = writer.create_nc_element("error-path");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(error_path)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }

        for error_message in &self.error_message {
            let start = writer.create_nc_element("error-message");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(error_message)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }

        for error_info in &self.error_info {
            error_info.xml_serialize(writer)?;
        }

        writer.inner.write_event(Event::End(start.to_end()))?;
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
    Error(Vec<ErrorInfoValue>),
}

impl XmlDeserialize<ErrorInfo> for ErrorInfo {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.open(NETCONF_NS_STR, "error-info")?;
        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "session-id") {
            let session_id = parser.tag_string()?.parse()?;
            // Close for session-id
            parser.close()?;
            // Close for error-info
            parser.close()?;
            return Ok(ErrorInfo::SessionId(session_id));
        }
        let error_info_value: Vec<ErrorInfoValue> = parser.collect()?;

        // Skipping any additional elements
        loop {
            if let Event::End(end) = parser.peek() {
                let (ns, local) = parser.rdr.resolve(end.name(), false);
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
        Ok(ErrorInfo::Error(error_info_value))
    }
}

impl XmlSerialize for ErrorInfo {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_nc_element("error-info");
        writer.inner.write_event(Event::Start(start.clone()))?;

        match self {
            ErrorInfo::SessionId(session_id) => {
                let session_id_start = writer.create_nc_element("session-id");
                writer
                    .inner
                    .write_event(Event::Start(session_id_start.clone()))?;
                writer
                    .inner
                    .write_event(Event::Text(BytesText::new(&session_id.to_string())))?;
                writer
                    .inner
                    .write_event(Event::End(session_id_start.to_end()))?;
            }
            ErrorInfo::Error(errors) => {
                for error in errors {
                    error.xml_serialize(writer)?;
                }
            }
        }

        writer.inner.write_event(Event::End(start.to_end()))?;
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
    bad_attributes: Option<String>,
    bad_elements: Option<String>,
    ok_elements: Option<String>,
    error_elements: Option<String>,
    noop_elements: Option<String>,
    bad_namespace: Option<String>,
}

impl XmlDeserialize<ErrorInfoValue> for ErrorInfoValue {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        let mut at_least_one = false;
        let mut value = ErrorInfoValue {
            bad_attributes: None,
            bad_elements: None,
            ok_elements: None,
            error_elements: None,
            noop_elements: None,
            bad_namespace: None,
        };

        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "bad-attribute") {
            value.bad_attributes = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "bad-element") {
            value.bad_elements = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "ok-element") {
            value.ok_elements = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "err-element") {
            value.error_elements = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "noop-element") {
            value.noop_elements = Some(parser.tag_string()?);
            parser.close()?;
            at_least_one = true
        }

        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "bad-namespace") {
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
        if let Some(attr) = &self.bad_attributes {
            let start = writer.create_nc_element("bad-attribute");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(attr)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.bad_elements {
            let start = writer.create_nc_element("bad-element");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(elem)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.ok_elements {
            let start = writer.create_nc_element("ok-element");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(elem)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.error_elements {
            let start = writer.create_nc_element("err-element");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(elem)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }
        if let Some(elem) = &self.noop_elements {
            let start = writer.create_nc_element("noop-element");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer
                .inner
                .write_event(Event::Text(BytesText::new(elem)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }
        if let Some(ns) = &self.bad_namespace {
            let start = writer.create_nc_element("bad-namespace");
            writer.inner.write_event(Event::Start(start.clone()))?;
            writer.inner.write_event(Event::Text(BytesText::new(ns)))?;
            writer.inner.write_event(Event::End(start.to_end()))?;
        }
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
        parser.open(NETCONF_NS_STR, "error-type")?;
        let str_value = parser.tag_string()?;
        let value = ErrorType::from_str(&str_value).map_err(|_| {
            ParsingError::InvalidValue(format!("unexpected <error-type> '{str_value}'").to_string())
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
        let start = writer.create_nc_element("error-type");
        writer.inner.write_event(Event::Start(start.clone()))?;
        writer
            .inner
            .write_event(Event::Text(BytesText::new(&format!("{self}"))))?;
        writer.inner.write_event(Event::End(start.to_end()))?;
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
        parser.open(NETCONF_NS_STR, "error-tag")?;
        let str_value = parser.tag_string()?;
        let value = ErrorTag::from_str(&str_value).map_err(|_| {
            ParsingError::InvalidValue(format!("unexpected <error-tag> '{str_value}'").to_string())
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
        let start = writer.create_nc_element("error-tag");
        writer.inner.write_event(Event::Start(start.clone()))?;
        writer
            .inner
            .write_event(Event::Text(BytesText::new(&format!("{self}"))))?;
        writer.inner.write_event(Event::End(start.to_end()))?;
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
        parser.open(NETCONF_NS_STR, "error-severity")?;
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
        let start = writer.create_nc_element("error-severity");
        writer.inner.write_event(Event::Start(start.clone()))?;
        writer
            .inner
            .write_event(Event::Text(BytesText::new(&format!("{self}"))))?;
        writer.inner.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// ```xml
/// <xs:complexType name="rpcReplyType">
///     <xs:choice>
///         <xs:element name="ok"/>
///         <xs:sequence>
///             <xs:element ref="rpc-error"
///                         minOccurs="0" maxOccurs="unbounded"/>
///             <xs:element ref="rpcResponse"
///                         minOccurs="0" maxOccurs="unbounded"/>
///
///         </xs:sequence>
///     </xs:choice>
///     <xs:attribute name="message-id" type="messageIdType"
///                   use="optional"/>
///     <!--
///        Any attributes supplied with <rpc> element must be returned
///        on <rpc-reply>.
///       -->
///     <xs:anyAttribute processContents="lax"/>
/// </xs:complexType>
/// <xs:element name="rpc-reply" type="rpcReplyType"/>
/// ```
#[derive(PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RpcReply {
    pub message_id: Option<String>,
    pub reply: RpcReplyValue,
}

impl XmlDeserialize<RpcReply> for RpcReply {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        let rpc_reply = parser.open(NETCONF_NS_STR, "rpc-reply")?;
        let rpc_reply = if let Event::Start(open) = rpc_reply {
            open
        } else {
            return Err(ParsingError::WrongToken(format!("{rpc_reply:?}")));
        };
        let message_id = extract_message_id(rpc_reply)?;
        if let Ok(Some(_)) = parser.maybe_open(NETCONF_NS_STR, "ok") {
            parser.close()?;
            return Ok(RpcReply {
                message_id,
                reply: RpcReplyValue::Ok,
            });
        }
        let errors: Vec<RpcError> = parser.collect_tag(NETCONF_NS_STR, b"rpc-error")?;
        let data = parser.copy_buffer_till(b"rpc-reply")?;
        parser.close()?;
        Ok(RpcReply {
            message_id,
            reply: RpcReplyValue::Data(errors, data),
        })
    }
}

impl XmlSerialize for RpcReply {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut start = writer.create_nc_element("rpc-reply");
        if let Some(message_id) = &self.message_id {
            start.push_attribute(("message-id", message_id.as_str()));
        }
        writer.inner.write_event(Event::Start(start.clone()))?;

        match &self.reply {
            RpcReplyValue::Ok => {
                let ok_start = writer.create_nc_element("ok");
                writer.inner.write_event(Event::Empty(ok_start))?;
            }
            RpcReplyValue::Data(errors, data) => {
                for error in errors {
                    error.xml_serialize(writer)?;
                }
                writer.inner.get_mut().write_all(data.as_bytes())?;
            }
        }

        writer.inner.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// ```xml
/// <xs:simpleType name="messageIdType">
///     <xs:restriction base="xs:string">
///         <xs:maxLength value="4095"/>
///     </xs:restriction>
/// </xs:simpleType>
/// ```
fn extract_message_id(open: BytesStart<'_>) -> Result<Option<String>, ParsingError> {
    let msg_id_attr = open
        .attributes()
        .find(|attr| match attr {
            Ok(attr) => {
                if attr.key.local_name().into_inner() == b"message-id" {
                    attr.unescape_value().is_ok()
                } else {
                    false
                }
            }
            Err(_) => false,
        })
        .map(|attr| match attr {
            Ok(attr) => match attr.unescape_value() {
                Ok(value) => value.to_string(),
                Err(_) => unreachable!(),
            },
            Err(_) => unreachable!(),
        });
    if let Some(msg_id) = &msg_id_attr {
        if msg_id.len() > 4095 {
            return Err(ParsingError::InvalidValue(format!(
                "message-id length: {} is larger than max 4095",
                msg_id.len()
            )));
        }
    }
    Ok(msg_id_attr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capabilities::{Base, Startup, YangModule},
        tests::test_xml_value,
    };
    use quick_xml::{reader::NsReader, DeError};
    use std::fmt::Debug;
    use yang3::data::Data;

    fn test_parse_error<T: XmlDeserialize<T> + XmlSerialize + PartialEq + Debug>(
        input_str: &str,
    ) -> Result<(), ParsingError> {
        // Check first we can deserialize value correctly
        let reader = NsReader::from_str(input_str);
        let mut xml_parser = XmlParser::new(reader)?;
        let ret = <T as XmlDeserialize<T>>::xml_deserialize(&mut xml_parser);
        assert!(ret.is_err(), "Expected an error but parsed successfully");
        ret.map(|_| ())
    }

    #[test]
    fn test_capability() -> Result<(), ParsingError> {
        let input_str = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">urn:ietf:params:netconf:base:1.1</capability>"#;
        let expected = Capability::Base(Base::V1_1);
        test_xml_value(input_str, expected)?;
        Ok(())
    }

    #[test]
    fn test_hello() -> Result<(), ParsingError> {
        let input_str = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capabilities>
        <capability>urn:ietf:params:netconf:base:1.1</capability>
        <capability>urn:ietf:params:netconf:capability:startup:1.0</capability>
        <capability>https://example.net/router/2.3/myfeature</capability>
        <capability>urn:example:yang:example-module?module=example-module&amp;revision=2022-12-22</capability>
    </capabilities>
    <session-id>4</session-id>
</hello>"#;
        let expected = Hello {
            session_id: Some(4),
            capabilities: HashMap::from([
                (Box::from(":base:1.1"), Capability::Base(Base::V1_1)),
                (Box::from(":startup"), Capability::Startup(Startup::V1_0)),
                (
                    Box::from("https://example.net/router/2.3/myfeature"),
                    Capability::Unknown("https://example.net/router/2.3/myfeature".into()),
                ),
                (
                    Box::from(":example-module"),
                    Capability::YangModule(YangModule {
                        ns: "urn:example:yang:example-module".into(),
                        module: "example-module".into(),
                        revision: "2022-12-22".into(),
                        features: Box::new([]),
                        deviations: Box::new([]),
                    }),
                ),
            ]),
        };

        test_xml_value(input_str, expected)?;
        Ok(())
    }

    #[test]
    fn test_hello_custom() -> Result<(), ParsingError> {
        let input_str = r#"?xml version="1.0" encoding="UTF-8"?>
    <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <capabilities>
        <capability>https://www.example.com/netconf/capability/discard-commit/1.0</capability>
        <capability>http://openconfig.net/yang/aaa?module=openconfig-aaa&amp;revision=2020-07-30</capability>
        <capability>http://openconfig.net/yang/alarms?module=openconfig-alarms&amp;revision=2018-01-16&amp;deviations=example-openconfig-alarms-deviation</capability>
      </capabilities>
      <session-id>6077</session-id>
    </hello>"#;
        let expected = Hello {
            session_id: Some(6077),
            capabilities: HashMap::from([
                (
                    Box::from("https://www.example.com/netconf/capability/discard-commit/1.0"),
                    Capability::Unknown(
                        "https://www.example.com/netconf/capability/discard-commit/1.0".into(),
                    ),
                ),
                (
                    Box::from(":openconfig-aaa"),
                    Capability::YangModule(YangModule {
                        ns: "http://openconfig.net/yang/aaa".into(),
                        module: "openconfig-aaa".into(),
                        revision: "2020-07-30".into(),
                        features: Box::new([]),
                        deviations: Box::new([]),
                    }),
                ),
                (
                    Box::from(":openconfig-alarms"),
                    Capability::YangModule(YangModule {
                        ns: "http://openconfig.net/yang/alarms".into(),
                        module: "openconfig-alarms".into(),
                        revision: "2018-01-16".into(),
                        features: Box::new([]),
                        deviations: Box::new([Box::from("example-openconfig-alarms-deviation")]),
                    }),
                ),
            ]),
        };

        test_xml_value(input_str, expected)?;
        Ok(())
    }

    #[test]
    fn test_rpc() -> Result<(), DeError> {
        let input_str = r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101"><copy-config><target><startup/></target><source><running/></source></copy-config></rpc>"#;
        let reader = NsReader::from_str(input_str);
        let mut xml_parser = XmlParser::new(reader).unwrap();
        let writer = quick_xml::writer::Writer::new(io::Cursor::new(Vec::new()));
        let mut xml_writer = XmlWriter {
            inner: writer,
            ns_to_apply: vec![(
                "xmlns".into(),
                "urn:ietf:params:xml:ns:netconf:base:1.0".to_string(),
            )],
        };
        let expected = Rpc {
            message_id: "101".to_string(),
            operation: r#"<copy-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><target><startup/></target><source><running/></source></copy-config>"#.to_string(),
        };

        let parsed = Rpc::xml_deserialize(&mut xml_parser).unwrap();
        parsed.xml_serialize(&mut xml_writer)?;

        assert_eq!(parsed, expected);
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
        let bad_attributes = ErrorInfo::Error(vec![
            ErrorInfoValue {
                bad_attributes: Some("size".to_string()),
                bad_elements: None,
                ok_elements: None,
                error_elements: None,
                noop_elements: None,
                bad_namespace: None,
            },
            ErrorInfoValue {
                bad_attributes: Some("color".to_string()),
                bad_elements: None,
                ok_elements: None,
                error_elements: None,
                noop_elements: None,
                bad_namespace: None,
            },
        ]);
        let bad_elements = ErrorInfo::Error(vec![
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: Some("rpc".to_string()),
                ok_elements: None,
                error_elements: None,
                noop_elements: None,
                bad_namespace: None,
            },
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: Some("hello".to_string()),
                ok_elements: None,
                error_elements: None,
                noop_elements: None,
                bad_namespace: None,
            },
        ]);

        let ok_elements = ErrorInfo::Error(vec![
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: None,
                ok_elements: Some("config".to_string()),
                error_elements: None,
                noop_elements: None,
                bad_namespace: None,
            },
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: None,
                ok_elements: Some("data".to_string()),
                error_elements: None,
                noop_elements: None,
                bad_namespace: None,
            },
        ]);
        let error_elements = ErrorInfo::Error(vec![
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: None,
                ok_elements: None,
                error_elements: Some("filter".to_string()),
                noop_elements: None,
                bad_namespace: None,
            },
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: None,
                ok_elements: None,
                error_elements: Some("source".to_string()),
                noop_elements: None,
                bad_namespace: None,
            },
        ]);
        let noop_elements = ErrorInfo::Error(vec![
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: None,
                ok_elements: None,
                error_elements: None,
                noop_elements: Some("get".to_string()),
                bad_namespace: None,
            },
            ErrorInfoValue {
                bad_attributes: None,
                bad_elements: None,
                ok_elements: None,
                error_elements: None,
                noop_elements: Some("edit-config".to_string()),
                bad_namespace: None,
            },
        ]);
        let bad_namespace = ErrorInfo::Error(vec![ErrorInfoValue {
            bad_attributes: None,
            bad_elements: None,
            ok_elements: None,
            error_elements: None,
            noop_elements: None,
            bad_namespace: Some("urn:invalid:namespace".to_string()),
        }]);
        let mixed_error_info = ErrorInfo::Error(vec![
            ErrorInfoValue {
                bad_attributes: Some("size".to_string()),
                bad_elements: Some("rpc".to_string()),
                ok_elements: Some("reply".to_string()),
                error_elements: Some("filter".to_string()),
                noop_elements: Some("get".to_string()),
                bad_namespace: Some("urn:invalid:namespace1".to_string()),
            },
            ErrorInfoValue {
                bad_attributes: Some("message-id".to_string()),
                bad_elements: Some("session-id".to_string()),
                ok_elements: Some("config".to_string()),
                error_elements: None,
                noop_elements: None,
                bad_namespace: Some("urn:invalid:namespace2".to_string()),
            },
        ]);

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
        let multiple_seq_str = r#"<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <error-type>application</error-type>
            <error-type>protocol</error-type>
            <error-tag>invalid-value</error-tag>
            <error-tag>bad-element</error-tag>
            <error-severity>error</error-severity>
            <error-severity>warning</error-severity>
            <error-app-tag>config-invalid</error-app-tag>
            <error-app-tag>retry-request</error-app-tag>
            <error-path>/configuration/system</error-path>
            <error-path>/configuration/interfaces</error-path>
            <error-message>Configuration is invalid</error-message>
            <error-message>Request needs to be retried</error-message>
            <error-info>
                <bad-element>parameter</bad-element>
                <bad-namespace>urn:example:invalid</bad-namespace>
            </error-info>
            <error-info>
                <ok-element>other-param</ok-element>
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
            error_type: vec![ErrorType::Protocol],
            error_tag: vec![ErrorTag::OperationFailed],
            error_severity: vec![ErrorSeverity::Error],
            error_app_tag: vec![],
            error_path: vec![],
            error_message: vec![],
            error_info: vec![],
        };
        let complex = RpcError {
            error_type: vec![ErrorType::Protocol],
            error_tag: vec![ErrorTag::BadAttribute],
            error_severity: vec![ErrorSeverity::Error],
            error_app_tag: vec!["too-big".to_string()],
            error_path: vec![
                "/rpc/edit-config/config/top/interface[name=\"Ethernet0/0\"]".to_string(),
            ],
            error_message: vec!["The requested operation could not be completed.".to_string()],
            error_info: vec![ErrorInfo::Error(vec![ErrorInfoValue {
                bad_attributes: Some("message-id".to_string()),
                bad_elements: Some("rpc".to_string()),
                ok_elements: None,
                error_elements: None,
                noop_elements: None,
                bad_namespace: None,
            }])],
        };
        let multiple_seq = RpcError {
            error_type: vec![ErrorType::Application, ErrorType::Protocol],
            error_tag: vec![ErrorTag::InvalidValue, ErrorTag::BadElement],
            error_severity: vec![ErrorSeverity::Error, ErrorSeverity::Warning],
            error_app_tag: vec!["config-invalid".to_string(), "retry-request".to_string()],
            error_path: vec![
                "/configuration/system".to_string(),
                "/configuration/interfaces".to_string(),
            ],
            error_message: vec![
                "Configuration is invalid".to_string(),
                "Request needs to be retried".to_string(),
            ],
            error_info: vec![
                ErrorInfo::Error(vec![ErrorInfoValue {
                    bad_attributes: None,
                    bad_elements: Some("parameter".to_string()),
                    ok_elements: None,
                    error_elements: None,
                    noop_elements: None,
                    bad_namespace: Some("urn:example:invalid".to_string()),
                }]),
                ErrorInfo::Error(vec![ErrorInfoValue {
                    bad_attributes: None,
                    bad_elements: None,
                    ok_elements: Some("other-param".to_string()),
                    error_elements: None,
                    noop_elements: None,
                    bad_namespace: None,
                }]),
            ],
        };
        let empty_error_info = RpcError {
            error_type: vec![ErrorType::Rpc],
            error_tag: vec![ErrorTag::MissingAttribute],
            error_severity: vec![ErrorSeverity::Error],
            error_app_tag: vec![],
            error_path: vec![],
            error_message: vec![],
            error_info: vec![ErrorInfo::Error(vec![])],
        };

        test_xml_value(basic_str, basic)?;
        test_xml_value(complex_str, complex)?;
        test_xml_value(multiple_seq_str, multiple_seq)?;
        test_xml_value(empty_error_info_str, empty_error_info)?;
        assert!(matches!(
            test_parse_error::<RpcError>(missing_error_type_str),
            Err(ParsingError::MissingChild(_))
        ));
        assert!(matches!(
            test_parse_error::<RpcError>(missing_error_tag_str),
            Err(ParsingError::MissingChild(_))
        ));
        assert!(matches!(
            test_parse_error::<RpcError>(missing_error_severity_str),
            Err(ParsingError::MissingChild(_))
        ));
        Ok(())
    }
    // #[test]
    // fn test_rpc_error() -> Result<(), ParsingError> {
    //     let input_str = r#"<rpc-error
    // xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    //         <error-type>protocol</error-type>
    //         <error-tag>bad-attribute</error-tag>
    //         <error-severity>error</error-severity>
    //         <error-app-tag>too-big</error-app-tag>
    //         <error-path>/rpc/edit-config/config/top/interface[name="
    // Ethernet0/0"]</error-path>         <error-message>The requested
    // operation could not be completed.</error-message>
    //         <error-info>
    //             <bad-attribute>message-id</bad-attribute>
    //             <bad-element>rpc</bad-element>
    //         </error-info>
    //     </rpc-error>"#;

    //     let expected = RpcError {
    //         error_type: vec![ErrorType::Protocol],
    //         error_tag: vec![ErrorTag::BadAttribute],
    //         error_severity: vec![ErrorSeverity::Error],
    //         error_app_tag: vec!["too-big".to_string()],
    //         error_path: vec![
    //
    // "/rpc/edit-config/config/top/interface[name=\"Ethernet0/0\"]".
    // to_string(),         ],
    //         error_message: vec!["The requested operation could not be
    // completed.".to_string()],         error_info:
    // vec![ErrorInfo::Error(vec![ErrorInfoValue {
    // bad_attributes: Some("message-id".to_string()),
    // bad_elements: Some("rpc".to_string()),             ok_elements: None,
    //             error_elements: None,
    //             noop_elements: None,
    //             bad_namespace: None,
    //         }])],
    //     };

    //     test_value(input_str, expected)
    // }

    // #[test]
    // fn test_rpc_error_rfc() -> Result<(), ParsingError> {
    //     // Example from Page 18 of [RFC 6241](https://tools.ietf.org/html/rfc6241)
    //     let input1_str = r#"<rpc-error
    // xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    //       <error-type>rpc</error-type>
    //       <error-tag>missing-attribute</error-tag>
    //       <error-severity>error</error-severity>
    //       <error-info>
    //         <bad-attribute>message-id</bad-attribute>
    //         <bad-element>rpc</bad-element>
    //       </error-info>
    //     </rpc-error>"#;
    //     let expected1 = RpcError {
    //         error_type: "rpc".to_string(),
    //         error_tag: "missing-attribute".to_string(),
    //         error_severity: "error".to_string(),
    //         error_info: ErrorInfo::Error(vec![ErrorInfoValue {
    //             bad_attributes: Some("message-id".to_string()),
    //             bad_elements: Some("rpc".to_string()),
    //             ok_elements: None,
    //             error_elements: None,
    //             noop_elements: None,
    //             bad_namespace: None,
    //         }]),
    //     };
    //     test_value(input1_str, expected1)?;
    //     Ok(())
    // }
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
        let expected_data1 = r#"<data attr1="x" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
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
     "#;

        let expected1 = RpcReply {
            message_id: Some("101".to_string()),
            reply: RpcReplyValue::Data(vec![], expected_data1.to_string()),
        };
        test_xml_value(input_str1, expected1)?;
        Ok(())
    }

    #[test]
    fn test_rpc_reply_yang() -> Result<(), ParsingError> {
        let input_str1 = r#"<rpc-reply message-id="103"
         xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
           module bar-types {
             //default format (yang) returned
             //latest revision returned
             //is version 2008-06-01 yang module
             //contents here ...
           }
         </data>
       </rpc-reply>"#;
        let expected_data1 = r#"<data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
           module bar-types {
             //default format (yang) returned
             //latest revision returned
             //is version 2008-06-01 yang module
             //contents here ...
           }
         </data>
       "#;

        let expected1 = RpcReply {
            message_id: Some("103".to_string()),
            reply: RpcReplyValue::Data(vec![], expected_data1.to_string()),
        };
        test_xml_value(input_str1, expected1)?;
        Ok(())
    }

    #[test]
    fn test_libyang() -> Result<(), ParsingError> {
        let reply_str1 = r#"<rpc-reply message-id="103" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <ok/>
       </rpc-reply>"#;
        let mut ctx = yang3::context::Context::new(yang3::context::ContextFlags::NO_YANGLIBRARY)
            .expect("Failed to create context");
        ctx.set_searchdir("../../assets/yang/")
            .expect("Failed to set YANG search directory");
        ctx.load_module(
            "ietf-netconf",
            Some("2011-06-01"),
            &[
                "writable-running",
                "candidate",
                "confirmed-commit",
                "rollback-on-error",
                "validate",
                "startup",
                "url",
                "xpath",
            ],
        )
        .expect("Failed to load module");

        ctx.load_module("ietf-netconf-monitoring", Some("2010-10-04"), &[])
            .expect("Failed to load module");

        ctx.load_module("ietf-yang-library", Some("2019-01-04"), &[])
            .expect("Failed to load module");
        ctx.load_module("ietf-datastores", Some("2018-02-14"), &[])
            .expect("Failed to load module");
        let input_str = r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101"><copy-config><target><startup/></target><source><running/></source></copy-config></rpc>"#;
        let mut owning_ref = yang3::data::DataTreeOwningRef::parse_netconf_rpc_op(&ctx, input_str)
            .expect("Failed to parse rpc");
        let out = owning_ref
            .print_string(
                yang3::data::DataFormat::XML,
                yang3::data::DataPrinterFlags::all(),
            )
            .expect("Failed to serialize");
        owning_ref
            .parse_netconf_reply_op(reply_str1)
            .expect("Failed to parse reply");
        Ok(())
    }

    #[test]
    fn test_with_decl() -> Result<(), ParsingError> {
        let input_str1 = r#"<?xml version="1.0"?>
        <rpc-reply message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <data></data></rpc-reply>"#;
        let expected_data = r#"<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"></data>"#;
        let expected1 = NetConfMessage::RpcReply(RpcReply {
            message_id: Some("101".to_string()),
            reply: RpcReplyValue::Data(vec![], expected_data.to_string()),
        });
        test_xml_value(input_str1, expected1)?;
        Ok(())
    }
}
