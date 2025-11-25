// Copyright (C) 2025-present The NetGauze Authors.
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

//! Low-level XML parsing utils

use crate::NETCONF_NS;
use indexmap::IndexMap;
use quick_xml::{
    events::{BytesStart, Event},
    name::{Namespace, NamespaceError, ResolveResult},
    reader::NsReader,
};
use std::{
    collections::{HashMap, HashSet},
    fmt, io,
};

/// XML Serialization trait
pub trait XmlSerialize {
    fn xml_serialize<T: io::Write>(&self, xml: &mut XmlWriter<T>) -> Result<(), quick_xml::Error>;
}

/// XML Deserialization trait
pub trait XmlDeserialize<T: Sized> {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<T, ParsingError>;
}

#[derive(Debug, strum_macros::Display)]
pub enum XmlWriterError {
    UndefinedNamespace(String),
    DuplicateNamespacePrefix(String),
}

impl std::error::Error for XmlWriterError {}

impl From<XmlWriterError> for quick_xml::Error {
    fn from(value: XmlWriterError) -> Self {
        match value {
            XmlWriterError::UndefinedNamespace(ns) => {
                quick_xml::Error::Namespace(NamespaceError::UnknownPrefix(ns.as_bytes().to_vec()))
            }
            XmlWriterError::DuplicateNamespacePrefix(prefix) => quick_xml::Error::Namespace(
                NamespaceError::InvalidPrefixForXmlns(prefix.as_bytes().to_vec()),
            ),
        }
    }
}

/// Transform a Rust object into an XML stream of characters
pub struct XmlWriter<T: io::Write> {
    inner: quick_xml::writer::Writer<T>,
    // Stack of multiple namespace bindings since XML allows to overwrite the bindings
    namespace_bindings: Vec<IndexMap<Namespace<'static>, String>>,
    // Namespaces has been appended to the xml element
    ns_applied: bool,
}

impl<T: io::Write> XmlWriter<T> {
    pub fn new(inner: quick_xml::writer::Writer<T>) -> Self {
        let namespace_bindings = vec![IndexMap::from([(NETCONF_NS, "".to_string())])];
        let ns_applied = false;
        Self {
            inner,
            namespace_bindings,
            ns_applied,
        }
    }

    pub fn new_with_custom_namespaces(
        inner: quick_xml::writer::Writer<T>,
        namespace_binding: IndexMap<Namespace<'static>, String>,
    ) -> Result<Self, XmlWriterError> {
        Self::check_duplicate_prefixes(&namespace_binding)?;
        let ns_applied = false;
        let namespace_bindings = vec![namespace_binding];
        Ok(Self {
            inner,
            namespace_bindings,
            ns_applied,
        })
    }

    /// create a new XML element with the default namespace
    pub fn create_element(&mut self, name: &'static str) -> BytesStart<'static> {
        let mut start = BytesStart::new(name);
        self.apply_namespaces(&mut start);
        start
    }

    pub fn get_namespace_prefix(&self, ns: Namespace<'static>) -> Option<&String> {
        self.namespace_bindings
            .iter()
            .rev()
            .find_map(|map| map.get(&ns))
    }

    /// Create a new element with specific namespace prefix
    /// Note, the namespace must have been registered beforehand,
    /// either with [XmlWriter::new_with_custom_namespaces] or
    /// [XmlWriter::push_namespace_binding]
    pub fn create_ns_element(
        &mut self,
        ns: Namespace<'static>,
        name: &str,
    ) -> Result<BytesStart<'static>, XmlWriterError> {
        // the namespace must have been defined before
        // find the prefix binding for this namespace based
        // on the latest binding in the stack [self.namespace_bindings]
        let prefix = if let Some(prefix) = self.get_namespace_prefix(ns) {
            prefix
        } else {
            return Err(XmlWriterError::UndefinedNamespace(
                String::from_utf8(ns.into_inner().to_vec()).unwrap_or("UNKNOWN".to_string()),
            ));
        };
        let mut start = if prefix.is_empty() {
            BytesStart::new(name.to_string())
        } else {
            BytesStart::new(format!("{prefix}:{name}"))
        };
        self.apply_namespaces(&mut start);
        Ok(start)
    }

    pub fn push_namespace_binding(
        &mut self,
        namespace_binding: IndexMap<Namespace<'static>, String>,
    ) -> Result<(), XmlWriterError> {
        Self::check_duplicate_prefixes(&namespace_binding)?;
        self.ns_applied = false;
        self.namespace_bindings.push(namespace_binding);
        Ok(())
    }

    pub fn pop_namespace_binding(&mut self) -> Option<IndexMap<Namespace<'static>, String>> {
        self.namespace_bindings.pop()
    }

    pub fn write_event<'a, E: Into<Event<'a>>>(&mut self, event: E) -> io::Result<()> {
        self.inner.write_event(event.into())
    }

    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.get_mut().write_all(buf)
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }

    fn apply_namespaces(&mut self, start: &mut BytesStart<'_>) {
        if !self.ns_applied {
            if let Some(bindings) = self.namespace_bindings.last() {
                for (namespace, prefix) in bindings {
                    if prefix.is_empty() {
                        start.push_attribute(("xmlns".as_bytes(), namespace.as_ref()));
                    } else {
                        start.push_attribute((
                            format!("xmlns:{prefix}").as_bytes(),
                            namespace.as_ref(),
                        ));
                    }
                }
            }
            self.ns_applied = true;
        }
    }

    fn check_duplicate_prefixes(
        namespace_binding: &IndexMap<Namespace<'static>, String>,
    ) -> Result<(), XmlWriterError> {
        // Check for duplicate prefix values in the new namespace binding
        let mut seen_prefixes = HashSet::new();
        for prefix in namespace_binding.values() {
            if !seen_prefixes.insert(prefix) {
                return Err(XmlWriterError::DuplicateNamespacePrefix(prefix.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum ParsingError {
    /// Standard IO error
    #[strum(to_string = "std::io:Error: `{0}`")]
    StdIo(io::Error),

    /// recoverable errors that a parser need to retry
    Recoverable,

    /// Unexpected XML token found
    WrongToken {
        expecting: String,
        found: Event<'static>,
    },

    MissingAttribute(String),

    #[strum(to_string = "required XML element `{0}` is missing")]
    MissingElement(String),

    /// Invalid value error when converting from XML provided value to Rust type
    InvalidValue(String),

    /// Error when trying to skip a node
    SkipError(String),

    /// Error when trying to decode UTF-8
    Utf8Error(std::str::Utf8Error),

    /// Error from quick-xml
    QuickXml(quick_xml::Error),

    /// Error when parsing an integer
    Int(std::num::ParseIntError),

    #[strum(to_string = "Found EOF while expecting data")]
    Eof,

    /// Error from quick-xml encoding
    EncodingError(quick_xml::encoding::EncodingError),
}

impl PartialEq for ParsingError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::StdIo(left), Self::StdIo(right)) => left.to_string() == right.to_string(),
            (Self::Recoverable, Self::Recoverable) => true,
            (
                Self::WrongToken {
                    expecting: left_exp,
                    found: left_found,
                },
                Self::WrongToken {
                    expecting: right_exp,
                    found: right_found,
                },
            ) => left_exp == right_exp && left_found == right_found,
            (Self::MissingAttribute(left), Self::MissingAttribute(right)) => left == right,
            (Self::InvalidValue(left), Self::InvalidValue(right)) => left == right,
            (Self::SkipError(left), Self::SkipError(right)) => left == right,
            (Self::Utf8Error(left), Self::Utf8Error(right)) => left == right,
            (Self::QuickXml(left), Self::QuickXml(right)) => left.to_string() == right.to_string(),
            (Self::Int(left), Self::Int(right)) => left == right,
            (Self::Eof, Self::Eof) => true,
            (Self::EncodingError(left), Self::EncodingError(right)) => left == right,
            _ => false,
        }
    }
}

impl std::error::Error for ParsingError {}

impl From<quick_xml::Error> for ParsingError {
    fn from(value: quick_xml::Error) -> Self {
        Self::QuickXml(value)
    }
}

impl From<std::str::Utf8Error> for ParsingError {
    fn from(value: std::str::Utf8Error) -> Self {
        Self::Utf8Error(value)
    }
}

impl From<std::num::ParseIntError> for ParsingError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::Int(value)
    }
}

impl From<io::Error> for ParsingError {
    fn from(value: io::Error) -> Self {
        Self::StdIo(value)
    }
}

impl From<quick_xml::encoding::EncodingError> for ParsingError {
    fn from(value: quick_xml::encoding::EncodingError) -> Self {
        Self::EncodingError(value)
    }
}

/// Transform an XML stream of characters into a Rust object
pub struct XmlParser<R: Sized> {
    ns_reader: NsReader<R>,
    current: Event<'static>,
    previous: Event<'static>,
    parents: Vec<Event<'static>>,
    buf: Vec<u8>,
}

impl<R: io::BufRead> XmlParser<R> {
    pub fn new(mut ns_reader: NsReader<R>) -> Result<Self, ParsingError> {
        let mut buf: Vec<u8> = vec![];
        let current = ns_reader.read_event_into(&mut buf)?.into_owned();
        let parents = vec![];
        let previous = Event::Eof;
        buf.clear();
        Ok(Self {
            ns_reader,
            current,
            previous,
            parents,
            buf,
        })
    }

    pub const fn ns_reader(&self) -> &NsReader<R> {
        &self.ns_reader
    }

    /// read one more tag
    pub fn next_event(&mut self) -> Result<Event<'static>, ParsingError> {
        self.buf.clear();
        let evt = self.ns_reader.read_event_into(&mut self.buf)?.into_owned();
        self.previous = std::mem::replace(&mut self.current, evt);
        Ok(self.previous.clone())
    }

    pub const fn peek(&self) -> &Event<'static> {
        &self.current
    }

    pub const fn previous(&self) -> &Event<'static> {
        &self.previous
    }
    /// skip a node at the current level
    pub fn skip(&mut self) -> Result<Event<'static>, ParsingError> {
        match &self.current {
            Event::Start(b) => {
                let _span = self
                    .ns_reader
                    .read_to_end_into(b.to_end().name(), &mut self.buf)?;
                self.next_event()
            }
            Event::End(e) => Err(ParsingError::SkipError(format!(
                "Cannot skip a closing tag, call close() to close </{}>",
                std::str::from_utf8(e.name().local_name().into_inner())?
            ))),
            Event::Eof => Err(ParsingError::Eof),
            _ => self.next_event(),
        }
    }

    pub fn skip_text(&mut self) -> Result<(), ParsingError> {
        while let Event::Text(_) = self.peek() {
            self.skip()?;
        }
        Ok(())
    }

    /// check if this is the desired tag
    pub fn is_tag(&self, ns: Option<Namespace<'_>>, key: &str) -> bool {
        let qname = match self.peek() {
            Event::Start(bs) | Event::Empty(bs) => bs.name(),
            Event::End(be) => be.name(),
            _ => return false,
        };

        let (resolved, local) = self.ns_reader.resolve_element(qname);
        if local.into_inner() != key.as_bytes() {
            return false;
        }
        let expected = match ns {
            Some(ns) => ResolveResult::Bound(ns),
            None => ResolveResult::Unbound,
        };
        resolved == expected
    }

    /// Open the next XML tag that matches `ns:key`,
    /// if another XML element found, fail with a [ParsingError::WrongToken]`
    pub fn open(
        &mut self,
        ns: Option<Namespace<'_>>,
        key: &str,
    ) -> Result<BytesStart<'static>, ParsingError> {
        let evt = match self.peek() {
            Event::Empty(_) if self.is_tag(ns, key) => {
                // hack to make `prev_attr` works
                // here we duplicate the current tag
                // as in other words, we virtually moved one token
                // which is useful for prev_attr and any logic based on
                // self.prev + self.open() on empty nodes
                self.previous = self.current.clone();
                self.current.clone()
            }
            Event::Start(_) if self.is_tag(ns, key) => self.next_event()?,
            e => {
                return Err(ParsingError::WrongToken {
                    expecting: format!("<{key}>"),
                    found: e.clone().into_owned(),
                });
            }
        };
        self.parents.push(evt.clone());
        match evt {
            Event::Start(b) | Event::Empty(b) => Ok(b),
            _ => unreachable!("Only Start and Empty event should be observed after peeking"),
        }
    }

    /// Open the next XML tag only if it matches the `ns:key`,
    /// otherwise return None.
    pub fn maybe_open(
        &mut self,
        ns: Option<Namespace<'_>>,
        key: &str,
    ) -> Result<Option<BytesStart<'static>>, ParsingError> {
        self.skip_text()?;
        match self.open(ns, key) {
            Ok(v) => Ok(Some(v)),
            Err(ParsingError::Recoverable) | Err(ParsingError::WrongToken { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    #[inline]
    fn ensure_parent_has_child(&self) -> Result<(), ParsingError> {
        match self.parent_has_child() {
            true => Ok(()),
            false => Err(ParsingError::Recoverable),
        }
    }

    #[inline]
    pub fn tag_string(&mut self) -> Result<Box<str>, ParsingError> {
        self.ensure_parent_has_child()?;
        let mut accumulator = String::new();
        loop {
            match self.peek() {
                Event::CData(unescaped) => {
                    let decoded = unescaped.decode()?;
                    accumulator.push_str(decoded.as_ref());
                    self.next_event()?
                }
                Event::Text(escaped) => {
                    let decoded = escaped.decode()?;
                    accumulator.push_str(decoded.as_ref());
                    self.next_event()?
                }
                Event::GeneralRef(general_ref) => {
                    let decoded = general_ref.decode()?;
                    let replaced = match decoded.as_ref() {
                        "quot" => "\"",
                        "apos" => "'",
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        _ => decoded.as_ref(),
                    };
                    accumulator.push_str(replaced);
                    self.next_event()?
                }
                Event::End(_) | Event::Start(_) | Event::Empty(_) => {
                    if accumulator.is_empty() {
                        return Err(ParsingError::WrongToken {
                            expecting: "text".to_string(),
                            found: self.peek().clone(),
                        });
                    }
                    return Ok(accumulator.into());
                }
                _ => self.next_event()?,
            };
        }
    }

    #[inline]
    pub fn parent_has_child(&self) -> bool {
        matches!(self.parents.last(), Some(Event::Start(_)) | None)
    }

    pub fn close(&mut self) -> Result<Event<'static>, ParsingError> {
        // Handle the empty case
        if !self.parent_has_child() {
            self.parents.pop();
            return self.next_event();
        }

        // Handle the start/end case
        loop {
            match self.peek() {
                Event::End(_) => {
                    self.parents.pop();
                    return self.next_event();
                }
                _ => self.skip()?,
            };
        }
    }

    /// Copy buffer content until a specific end tag is reached.
    ///
    /// This method reads and copies all XML events to a string buffer until it
    /// encounters an end tag matching the provided `tag` parameter.
    ///
    /// # Namespace Handling
    ///
    /// The method explicitly handles namespace declarations to ensure the
    /// copied XML fragment remains valid when extracted from its original
    /// context. When copying the first start tag:
    /// - It checks if the element already has an explicit `xmlns` attribute
    /// - If not, it resolves the element's namespace from the parser context
    ///   and adds it
    /// - This prevents namespace loss when the fragment is used independently
    ///
    /// # Performance Implications
    ///
    /// - Creates an in-memory copy of all events until the end tag
    /// - Performs UTF-8 conversion which may fail on invalid sequences
    /// - The namespace resolution only occurs once (on the first start tag) to
    ///   minimize overhead
    pub fn copy_buffer_till(&mut self, tag: &'_ [u8]) -> Result<Box<str>, ParsingError> {
        let cursor = io::Cursor::new(vec![]);
        let mut writer = quick_xml::writer::Writer::new(cursor);
        let mut wrote_ns = false;
        loop {
            if let Event::End(b) = self.peek() {
                if b.local_name().into_inner() == tag {
                    break;
                }
            }
            if let Event::Eof = self.peek() {
                return Err(ParsingError::Eof);
            }
            if !wrote_ns {
                if let Event::Start(a) = &mut self.current {
                    let attrs = a
                        .attributes()
                        .flatten()
                        .map(|x| {
                            (
                                std::str::from_utf8(x.key.local_name().into_inner())
                                    .unwrap()
                                    .to_string(),
                                std::str::from_utf8(&x.value).unwrap().to_string(),
                            )
                        })
                        .collect::<HashMap<_, _>>();
                    if !attrs.contains_key("xmlns") {
                        let (ns, _) = self.ns_reader.resolve(a.name(), false);
                        if let ResolveResult::Bound(ns) = ns {
                            a.push_attribute((&b"xmlns"[..], ns.0));
                        }
                    }
                    wrote_ns = true;
                    writer.write_event(Event::Start(a.clone()))?;
                } else {
                    writer.write_event(self.current.clone())?;
                }
            } else {
                writer.write_event(self.current.clone())?;
            }
            self.next_event()?;
        }
        let ret = std::str::from_utf8(&writer.into_inner().into_inner())?.to_string();
        Ok(ret.into())
    }

    /// Deserializes all elements inside an XML sequence, till an end tag of the
    /// element openned before calling this method is reached.
    pub fn collect_xml_sequence<N: XmlDeserialize<N> + fmt::Debug + PartialEq + Sync>(
        &mut self,
    ) -> Result<Vec<N>, ParsingError> {
        if !self.parent_has_child() {
            return Ok(vec![]);
        }
        let mut acc = Vec::new();
        loop {
            self.skip_text()?;
            let ret = N::xml_deserialize(self);
            match ret {
                Err(ParsingError::WrongToken { .. }) | Err(ParsingError::Recoverable) => {
                    match self.peek() {
                        Event::End(_) => return Ok(acc),
                        _ => {
                            self.skip()?;
                        }
                    }
                }
                Ok(v) => acc.push(v),
                Err(e) => return Err(e),
            }
        }
    }

    /// Deserializes all elements inside an XML sequence with a specific tag,
    /// till an end tag of the element opened before calling this method is
    /// reached. This variant filters elements by their namespace and tag
    /// name.
    pub fn collect_xml_sequence_with_tag<
        N: XmlDeserialize<N> + XmlSerialize + fmt::Debug + PartialEq + Sync,
    >(
        &mut self,
        ns: Option<Namespace<'_>>,
        tag: &'_ [u8],
    ) -> Result<Vec<N>, ParsingError> {
        let mut acc = Vec::new();
        let resolved_ns = if let Some(ns) = ns {
            ResolveResult::Bound(ns)
        } else {
            ResolveResult::Unbound
        };
        if !self.parent_has_child() {
            return Ok(acc);
        }
        loop {
            self.skip_text()?;
            if let Event::Start(ref e) = self.current {
                let (n, l) = self.ns_reader.resolve(e.name(), false);
                if !(n == resolved_ns && l.into_inner() == tag) {
                    return Ok(acc);
                }
            } else {
                return Ok(acc);
            }
            let ret = N::xml_deserialize(self);
            match ret {
                Err(ParsingError::Recoverable) => match self.peek() {
                    Event::End(_) => return Ok(acc),
                    _ => {
                        self.skip()?;
                    }
                },
                Ok(v) => acc.push(v),
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::{BytesDecl, BytesEnd, BytesText};

    fn create_parser(xml: &'_ str) -> XmlParser<&'_ [u8]> {
        let ns_reader = NsReader::from_reader(xml.as_bytes());
        XmlParser::new(ns_reader).expect("Failed to create parser")
    }

    #[test]
    fn test_parser_creation() {
        let xml_with_decl = r#"<?xml version="1.0"?><root></root>"#;
        let xml_without_decl = r#"<root></root>"#;
        let xml_empty = "";

        let parser_with_decl = create_parser(xml_with_decl);
        let parser_without_decl = create_parser(xml_without_decl);
        let parser_empty = create_parser(xml_empty);

        assert_eq!(
            parser_with_decl.peek(),
            &Event::Decl(BytesDecl::new("1.0", None, None))
        );
        assert_eq!(
            parser_without_decl.peek(),
            &Event::Start(BytesStart::new("root"))
        );
        assert_eq!(parser_empty.peek(), &Event::Eof);
    }

    #[test]
    fn test_skip_top_elements() {
        let xml = r#"<?xml version="1.0"?><root><child1>text</child1><child2>123</child2></root>"#;
        let mut parser = create_parser(xml);

        // Skip XML declaration
        assert!(matches!(parser.peek(), Event::Decl(_)));
        let result = parser.skip();
        assert_eq!(result, Ok(Event::Decl(BytesDecl::new("1.0", None, None))));
        // Next Event should read the root tag
        assert_eq!(parser.peek(), &Event::Start(BytesStart::new("root")));

        // Skip root start tag
        let result = parser.skip();
        assert_eq!(result, Ok(Event::Start(BytesStart::new("root"))));
        // next event is EoF
        assert_eq!(parser.peek(), &Event::Eof);

        // no more elements to skip
        let result = parser.skip();
        assert_eq!(result, Err(ParsingError::Eof));
    }

    #[test]
    fn test_skip_child_elements() {
        let xml =
            r#"<root xmlns="urn:ietf:example"><child1>text</child1><child2>123</child2></root>"#;
        let mut parser = create_parser(xml);

        // open root element, and arrive at child1
        parser
            .open(Some(Namespace(b"urn:ietf:example")), "root")
            .expect("failed to open root");
        assert_eq!(parser.peek(), &Event::Start(BytesStart::new("child1")));

        // Skip child1 tag
        let result = parser.skip();
        assert_eq!(result, Ok(Event::Start(BytesStart::new("child1"))));
        // no more elements to skip
        assert_eq!(parser.peek(), &Event::Start(BytesStart::new("child2")));

        // Skip child2 tag
        let result = parser.skip();
        assert_eq!(result, Ok(Event::Start(BytesStart::new("child2"))));
        // no more elements to skip
        assert_eq!(parser.peek(), &Event::End(BytesEnd::new("root")));

        // Cannot skip anymore without closing root
        let result = parser.skip();
        assert_eq!(
            result,
            Err(ParsingError::SkipError(
                "Cannot skip a closing tag, call close() to close </root>".to_string()
            ))
        );
        assert_eq!(parser.peek(), &Event::End(BytesEnd::new("root")));

        // Close root
        let result = parser.close();
        assert_eq!(result, Ok(Event::End(BytesEnd::new("root"))));
        assert_eq!(parser.peek(), &Event::Eof);
    }

    #[test]
    fn test_skip_text() {
        let xml = r#"<root xmlns="urn:ietf:example">text1 text2 text3</root>"#;
        let mut parser = create_parser(xml);

        // open root element, and arrive at text
        parser
            .open(Some(Namespace(b"urn:ietf:example")), "root")
            .expect("failed to open root");
        assert_eq!(
            parser.peek(),
            &Event::Text(BytesText::new("text1 text2 text3"))
        );

        // Should skip all text nodes
        let result = parser.skip_text();
        assert_eq!(result, Ok(()));
        assert_eq!(parser.peek(), &Event::End(BytesEnd::new("root")));
    }
    #[test]
    fn test_is_tag_with_namespace() {
        let xml = r#"<root xmlns:ns="https://example.com"><ns:child/></root>"#;
        let mut parser = create_parser(xml);

        let is_match = parser.is_tag(None, "root");
        assert!(is_match);

        parser.open(None, "root").expect("failed to open root");
        let is_match = parser.is_tag(Some(Namespace(b"https://example.com")), "child");
        assert!(is_match);

        let is_not_match = parser.is_tag(Some(Namespace(b"https://wrong.com")), "child");
        assert!(!is_not_match);

        let is_not_match = parser.is_tag(Some(Namespace(b"https://example.com")), "wrong");
        assert!(!is_not_match);
    }

    #[test]
    fn test_is_tag_on_text_returns_false() {
        let xml = r#"<root>text</root>"#;
        let mut parser = create_parser(xml);
        parser.skip().unwrap(); // Skip root start

        let is_tag = parser.is_tag(None, "anything");
        assert!(!is_tag);
    }

    #[test]
    fn test_open_matching_tag() {
        let xml = r#"<root xmlns="https://example.com"><child/></root>"#;
        let mut parser = create_parser(xml);
        // first nothing is open
        assert_eq!(parser.parents, vec![]);
        assert_eq!(parser.previous(), &Event::Eof);

        // Open root
        let result_root = parser.open(Some(Namespace(b"https://example.com")), "root");
        let expected_root = BytesStart::from_content("root xmlns=\"https://example.com\"", 4);
        assert_eq!(result_root, Ok(expected_root.clone()));
        assert_eq!(parser.parents, vec![Event::Start(expected_root.clone())]);
        assert_eq!(parser.previous(), &Event::Start(expected_root.clone()));

        // Open child
        let result_child = parser.open(Some(Namespace(b"https://example.com")), "child");
        let expected_child = BytesStart::new("child");
        assert_eq!(result_child, Ok(expected_child.clone()));
        assert_eq!(
            parser.parents,
            vec![
                Event::Start(expected_root.clone()),
                Event::Empty(expected_child.clone())
            ]
        );
        assert_eq!(parser.previous(), &Event::Empty(expected_child.clone()));

        // close child
        parser.close().unwrap();
        assert_eq!(parser.parents, vec![Event::Start(expected_root.clone())]);
        assert_eq!(parser.previous(), &Event::Empty(expected_child));

        // close root
        parser.close().unwrap();
        assert_eq!(parser.parents, vec![]);
        assert_eq!(parser.previous(), &Event::End(BytesEnd::new("root")));
    }

    #[test]
    fn test_open_wrong_tag_fails() {
        let xml = r#"<root xmlns="https://example.com"><child/></root>"#;
        let mut parser = create_parser(xml);

        let result = parser.open(Some(Namespace(b"https://example.com")), "wrong");
        assert_eq!(
            result,
            Err(ParsingError::WrongToken {
                expecting: "<wrong>".to_string(),
                found: Event::Start(
                    BytesStart::from_content("root xmlns=\"https://example.com\"", 4).into_owned()
                )
            })
        );
        // check pointer didn't move after the wrong open
        assert_eq!(
            parser.peek(),
            &Event::Start(BytesStart::from_content(
                "root xmlns=\"https://example.com\"",
                4
            ))
        );
    }

    #[test]
    fn test_maybe_open_existing_tag() {
        let xml = r#"<root xmlns="https://example.com"><child/></root>"#;
        let mut parser = create_parser(xml);
        let expected = Ok(Some(
            BytesStart::from_content("root xmlns=\"https://example.com\"", 4).into_owned(),
        ));

        let result = parser.maybe_open(Some(Namespace(b"https://example.com")), "root");
        assert_eq!(result, expected);
        // check pointer did move after the `maybe_open` succeeded
        assert_eq!(
            parser.peek(),
            &Event::Empty(BytesStart::from_content("child", 5))
        );
    }

    #[test]
    fn test_maybe_open_non_existing_tag() {
        let xml = r#"<root xmlns="https://example.com"><child/></root>"#;
        let mut parser = create_parser(xml);
        let expected = Ok(None);
        let result = parser.maybe_open(Some(Namespace(b"https://example.com")), "wrong");
        assert_eq!(result, expected);

        // check pointer didn't move after the `maybe_open` didn't return anything
        assert_eq!(
            parser.peek(),
            &Event::Start(
                BytesStart::from_content("root xmlns=\"https://example.com\"", 4).into_owned()
            )
        );
    }

    #[test]
    fn test_tag_string_with_text() {
        let xml = r#"<root>Hello World</root>"#;
        let mut parser = create_parser(xml);
        parser.open(None, "root").expect("failed to open root");

        let result = parser.tag_string();
        assert_eq!(result, Ok("Hello World".into()));

        parser.close().expect("failed to close root");
    }

    #[test]
    fn test_tag_string_with_cdata() {
        let xml = r#"<root><![CDATA[Hello <World>]]></root>"#;
        let mut parser = create_parser(xml);

        parser.open(None, "root").expect("failed to open root");

        let result = parser.tag_string();
        assert_eq!(result, Ok("Hello <World>".into()));

        parser.close().expect("failed to close root");
    }

    #[test]
    fn test_tag_string_on_non_text_fails() {
        let xml = r#"<root><child/></root>"#;
        let mut parser = create_parser(xml);

        parser.open(None, "root").expect("failed to open root");

        let result = parser.tag_string();
        assert_eq!(
            result,
            Err(ParsingError::WrongToken {
                expecting: "text".to_string(),
                found: Event::Empty(BytesStart::new("child").into_owned())
            })
        );

        parser.close().expect("failed to close root");
    }

    #[test]
    fn test_parent_has_child() {
        let xml = r#"<root><child/></root>"#;
        let mut parser = create_parser(xml);

        // Initially no parent
        assert!(parser.parent_has_child());

        parser.open(None, "root").unwrap();
        assert!(parser.parent_has_child());

        parser.open(None, "child").unwrap();
        // Empty element doesn't count as having children
        assert!(!parser.parent_has_child());
    }

    #[test]
    fn test_close_skips_content() {
        let xml = r#"<root>text1<child/>text2</root>"#;
        let mut parser = create_parser(xml);

        parser.open(None, "root").unwrap();

        let result = parser.close();
        assert_eq!(result, Ok(Event::End(BytesEnd::new("root"))));
        assert_eq!(parser.parents, vec![]);
    }

    #[test]
    fn test_writer_creation() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns_to_apply =
            IndexMap::from([(Namespace(b"https://example.com"), "xmlns".to_string())]);
        let xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply.clone())
            .expect("failed creating writer");
        assert_eq!(xml_writer.namespace_bindings, vec![ns_to_apply]);
    }

    #[test]
    fn test_create_element_without_namespace() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns_to_apply = IndexMap::new();
        let mut xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply)
            .expect("failed creating writer");

        let element = xml_writer.create_element("root");
        assert_eq!(element.name().as_ref(), b"root");
        assert!(xml_writer.ns_applied);
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn test_create_element_with_namespace() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns_to_apply = IndexMap::from([
            (Namespace(b"https://example.com"), "".to_string()),
            (Namespace(b"https://custom.com"), "ns".to_string()),
        ]);
        let mut xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply)
            .expect("failed creating writer");

        let element = xml_writer.create_element("root");
        assert_eq!(element.name().as_ref(), b"root");
        // Namespaces should be cleared after creating element
        assert!(xml_writer.ns_applied);

        // Check attributes were added
        let mut attrs: Vec<(Box<[u8]>, Box<[u8]>)> = element
            .attributes()
            .map(|x| x.expect("failed to decode attribute"))
            .map(|x| (x.key.as_ref().into(), x.value.as_ref().into()))
            .collect();
        attrs.sort_by(|x, y| x.0.cmp(&y.0));
        let expected: Vec<(Box<[u8]>, Box<[u8]>)> = vec![
            ((*b"xmlns").into(), (*b"https://example.com").into()),
            ((*b"xmlns:ns").into(), (*b"https://custom.com").into()),
        ];
        assert_eq!(attrs, expected);
    }

    #[test]
    fn test_create_ns_element_without_namespace() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns_to_apply = IndexMap::new();
        let mut xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply)
            .expect("failed creating writer");

        let element = xml_writer.create_ns_element(Namespace(b"ns"), "child");
        assert!(element.is_err());
        assert!(!xml_writer.ns_applied);
    }

    #[test]
    fn test_create_ns_element_with_namespace() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns = Namespace(b"https://custom.com");
        let ns_to_apply = IndexMap::from([(ns, "ns".to_string())]);
        let mut xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply)
            .expect("failed creating writer");

        let element = xml_writer
            .create_ns_element(ns, "child")
            .expect("failed to create an xml element with namespace prefix");
        assert_eq!(element.name().as_ref(), b"ns:child");
        // Namespaces should be cleared after creating element
        assert!(xml_writer.ns_applied);

        // Check attributes were added
        let mut attrs = element.attributes();
        let attr = attrs.next().unwrap().unwrap();
        assert_eq!(attr.key.as_ref(), b"xmlns:ns");
        assert_eq!(attr.value.as_ref(), b"https://custom.com");
    }

    #[test]
    fn test_write_event() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns_to_apply = IndexMap::new();
        let mut xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply)
            .expect("failed creating writer");

        let start = BytesStart::new("root");
        let result = xml_writer.write_event(Event::Start(start));
        assert!(result.is_ok());

        let text = BytesText::new("Hello World");
        let result = xml_writer.write_event(Event::Text(text));
        assert!(result.is_ok());

        let end = BytesEnd::new("root");
        let result = xml_writer.write_event(Event::End(end));
        assert!(result.is_ok());

        let inner = xml_writer.into_inner();
        let xml_str = std::str::from_utf8(inner).unwrap();
        assert_eq!(xml_str, "<root>Hello World</root>");
    }

    #[test]
    fn test_write_complex_document() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns_to_apply = IndexMap::new();
        let mut xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply)
            .expect("failed creating writer");

        // Write XML declaration
        let decl = BytesDecl::new("1.0", Some("UTF-8"), None);
        xml_writer.write_event(Event::Decl(decl)).unwrap();

        // Write root element with namespace
        let mut root = xml_writer.create_element("root");
        root.push_attribute(("xmlns", "https://example.com"));
        xml_writer.write_event(Event::Start(root)).unwrap();

        let ns = Namespace(b"https://example2.com");
        xml_writer
            .push_namespace_binding(IndexMap::from([(ns, "ns".to_string())]))
            .expect("failed adding namespace binding");
        // Write child element
        let child = xml_writer
            .create_ns_element(ns, "child")
            .expect("failed to create an xml element with a namespace prefix");
        xml_writer.write_event(Event::Start(child)).unwrap();

        // Write text content
        let text = BytesText::new("Content");
        xml_writer.write_event(Event::Text(text)).unwrap();

        // Close child
        let end_child = BytesEnd::new("ns:child");
        xml_writer.write_event(Event::End(end_child)).unwrap();

        // Close root
        let end_root = BytesEnd::new("root");
        xml_writer.write_event(Event::End(end_root)).unwrap();

        let inner = xml_writer.into_inner();
        let xml_str = std::str::from_utf8(inner).unwrap();
        assert_eq!(
            xml_str,
            r#"<?xml version="1.0" encoding="UTF-8"?><root xmlns="https://example.com"><ns:child xmlns:ns="https://example2.com">Content</ns:child></root>"#
        );
    }

    #[test]
    fn test_namespace_cleared_after_use() {
        let mut buffer = Vec::new();
        let writer = quick_xml::writer::Writer::new(&mut buffer);
        let ns_to_apply = IndexMap::from([
            (Namespace(b"https://example.com"), "".to_string()),
            (Namespace(b"https://custom.com"), "ns".to_string()),
        ]);
        let mut xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply)
            .expect("failed creating writer");

        // Create first element - should have namespaces
        let element1 = xml_writer.create_element("root");
        let attrs1: Vec<_> = element1.attributes().collect();
        assert_eq!(attrs1.len(), 2);
        assert!(xml_writer.ns_applied);

        // Create second element - should not have namespaces
        let element2 = xml_writer.create_element("child");
        let attrs2: Vec<_> = element2.attributes().collect();
        assert_eq!(attrs2.len(), 0);
        assert!(xml_writer.ns_applied);
    }
}
