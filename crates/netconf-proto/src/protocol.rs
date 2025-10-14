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

use crate::{
    capabilities::Capability,
    xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
    NETCONF_NS,
};
use quick_xml::{
    events::{BytesStart, BytesText, Event},
    name::ResolveResult,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io, str::FromStr};

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
        let operation = parser.copy_buffer_till(b"rpc")?;
        let operation = RpcOperation::Raw(operation);
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
            _ => todo!(),
        }
        writer.write_event(Event::End(start.to_end()))?;
        Ok(())
    }
}

/// Easy access for Well-known NETCONF RPC commands
/// at the moment these serve as examples, will be
/// updated in subsequent PRs.
/// TODO: defined NETCONF well-known operations
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum WellKnownOperation {
    // Vendor CLI passthrough
    CiscoCli {
        command: Box<str>,
    },
    JuniperCommand {
        format: Box<str>,
        command: Box<str>,
    },
    HuaweiCli {
        command: Box<str>,
    },

    // Legacy operations
    JuniperGetConfiguration {
        database: Option<Box<str>>,
        format: Option<Box<str>>,
        filter: Option<Box<str>>,
    },

    // Diagnostic operations
    GenericReboot,
    GenericFactoryReset,
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
        let responses = parser.copy_buffer_till(b"rpc-reply")?;
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
                writer.write_all(responses.as_bytes())?;
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
        responses: Box<str>,
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

    pub const fn responses(&self) -> Option<&str> {
        if let RpcReplyContent::ErrorsAndData { responses, .. } = self {
            Some(responses)
        } else {
            None
        }
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
    use crate::{
        capabilities::{NetconfVersion, StandardCapability, YangCapability},
        tests::{test_parse_error, test_xml_value, test_xml_value_owned},
    };
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
            message_id: Some("101".into()),
            reply: RpcReplyContent::ErrorsAndData {
                errors: vec![],
                responses: expected_data1.into(),
            },
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
            message_id: Some("103".into()),
            reply: RpcReplyContent::ErrorsAndData {
                errors: vec![],
                responses: expected_data1.into(),
            },
        };
        test_xml_value(input_str1, expected1)?;
        Ok(())
    }

    #[test]
    fn test_rpc_reply_content() {
        let data: Box<str> = "SomeData".into();
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
        assert_eq!(with_data_and_errors.responses(), Some(data.as_ref()));
    }

    #[test]
    fn test_with_netconf_message() -> Result<(), ParsingError> {
        let hello_str = r#"<?xml version="1.0"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities></capabilities><session-id>4</session-id></hello>"#;
        let rpc_str = r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101"><copy-config><target><startup/></target><source><running/></source></copy-config></rpc>"#;
        let rpc_reply_str = r#"<?xml version="1.0"?>
        <rpc-reply message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
         <data></data></rpc-reply>"#;
        let expected_rpc_reply_data =
            r#"<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"></data>"#;

        let hello = NetConfMessage::Hello(Hello::new(Some(4), HashSet::new()));
        let rpc = NetConfMessage::Rpc(Rpc::new("101".into(), RpcOperation::Raw("<copy-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><startup/></target><source><running/></source></copy-config>".into())));
        let rpc_reply = NetConfMessage::RpcReply(RpcReply {
            message_id: Some("101".into()),
            reply: RpcReplyContent::ErrorsAndData {
                errors: vec![],
                responses: expected_rpc_reply_data.into(),
            },
        });
        test_xml_value(hello_str, hello)?;
        test_xml_value(rpc_str, rpc)?;
        test_xml_value(rpc_reply_str, rpc_reply)?;
        Ok(())
    }
}
