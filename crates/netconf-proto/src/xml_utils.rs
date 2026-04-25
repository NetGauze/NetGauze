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
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{Namespace, NamespaceError, PrefixDeclaration, ResolveResult};
use quick_xml::reader::NsReader;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::{fmt, io};

/// XML Serialization trait
pub trait XmlSerialize {
    fn xml_serialize<T: io::Write>(&self, xml: &mut XmlWriter<T>) -> Result<(), quick_xml::Error>;
}

/// XML Deserialization trait
pub trait XmlDeserialize<'a, T: Sized> {
    fn xml_deserialize(parser: &mut XmlParser<'a, impl io::BufRead>) -> Result<T, ParsingError>;
}

#[derive(Debug, strum_macros::Display)]
pub enum XmlWriterError {
    #[strum(to_string = "undefined namespace: `{0}`")]
    UndefinedNamespace(String),
    #[strum(to_string = "duplicate namespace prefix: `{0}`")]
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
    namespace_bindings: Vec<IndexMap<Cow<'static, [u8]>, String>>,
    // Namespaces has been appended to the xml element
    ns_applied: bool,
}

impl<T: io::Write> XmlWriter<T> {
    pub fn new(inner: quick_xml::writer::Writer<T>) -> Self {
        let namespace_bindings = vec![IndexMap::from([(
            Cow::Borrowed(NETCONF_NS.as_ref()),
            "".to_string(),
        )])];
        let ns_applied = false;
        Self {
            inner,
            namespace_bindings,
            ns_applied,
        }
    }

    pub fn new_with_custom_namespaces(
        inner: quick_xml::writer::Writer<T>,
        namespace_binding: IndexMap<Namespace<'_>, String>,
    ) -> Result<Self, XmlWriterError> {
        Self::check_duplicate_prefixes(&namespace_binding)?;
        let ns_applied = false;
        let mut cow_ns = IndexMap::with_capacity(namespace_binding.len());
        for (ns, prefix) in namespace_binding {
            cow_ns.insert(Cow::Owned(ns.as_ref().to_vec()), prefix);
        }
        let namespace_bindings = vec![cow_ns];
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

    pub fn get_namespace_prefix(&self, ns: Namespace<'_>) -> Option<String> {
        self.namespace_bindings
            .iter()
            .rev()
            .find_map(|map| map.get(&Cow::Borrowed(ns.as_ref())).cloned())
    }

    /// Create a new element with specific namespace prefix
    /// Note, the namespace must have been registered beforehand,
    /// either with [XmlWriter::new_with_custom_namespaces] or
    /// [XmlWriter::push_namespace_binding]
    pub fn create_ns_element(
        &mut self,
        ns: Namespace<'_>,
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
        namespace_binding: IndexMap<Namespace<'_>, String>,
    ) -> Result<(), XmlWriterError> {
        Self::check_duplicate_prefixes(&namespace_binding)?;
        self.ns_applied = false;
        let mut cow_ns = IndexMap::with_capacity(namespace_binding.len());
        for (ns, prefix) in namespace_binding {
            cow_ns.insert(Cow::Owned(ns.as_ref().to_vec()), prefix);
        }
        self.namespace_bindings.push(cow_ns);
        Ok(())
    }

    pub fn pop_namespace_binding(&mut self) -> Option<IndexMap<Cow<'static, [u8]>, String>> {
        self.namespace_bindings.pop()
    }

    pub fn write_event<'b, E: Into<Event<'b>>>(&mut self, event: E) -> io::Result<()> {
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
        namespace_binding: &IndexMap<Namespace<'_>, String>,
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
    #[strum(to_string = "Wrong token, expecting `{expecting}` found `{found:?}`")]
    WrongToken {
        expecting: String,
        found: Event<'static>,
    },

    #[strum(to_string = "required XML attribute `{0}` is missing")]
    MissingAttribute(String),

    #[strum(to_string = "required XML element `{0}` is missing")]
    MissingElement(String),

    /// Invalid value error when converting from XML provided value to Rust type
    #[strum(to_string = "Invalid value: `{0}`")]
    InvalidValue(String),

    /// Error when trying to skip a node
    #[strum(to_string = "Skip error: {0}")]
    SkipError(String),

    /// Error when trying to decode UTF-8
    #[strum(to_string = "{0}")]
    Utf8Error(std::str::Utf8Error),

    /// Error from quick-xml
    #[strum(to_string = "{0}")]
    QuickXml(quick_xml::Error),

    /// Error when parsing an integer
    #[strum(to_string = "{0}")]
    Int(std::num::ParseIntError),

    #[strum(to_string = "Found EOF while expecting data")]
    Eof,

    /// Error from quick-xml encoding
    #[strum(to_string = "{0}")]
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

/// Output of [`XmlParser::copy_buffer_till_with_namespaces`].
pub struct CopiedSubtree {
    /// Raw XML of the copied region, verbatim — no injected xmlns attributes.
    pub xml: Box<str>,
    /// Prefix → URI bindings actually referenced by any element or attribute
    /// inside the region. The empty key represents the default namespace
    /// and is only present if an unprefixed element appeared.
    pub namespaces: IndexMap<String, String>,
}

/// Transform an XML stream of characters into a Rust object
pub struct XmlParser<'a, R: Sized> {
    ns_reader: NsReader<R>,
    current: Event<'a>,
    previous: Event<'a>,
    parents: Vec<Event<'a>>,
    buf: Vec<u8>,
}

impl<'a, R: io::BufRead> XmlParser<'a, R> {
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
    pub fn next_event(&mut self) -> Result<Event<'a>, ParsingError> {
        self.buf.clear();
        let evt = self.ns_reader.read_event_into(&mut self.buf)?.into_owned();
        self.previous = std::mem::replace(&mut self.current, evt);
        Ok(self.previous.clone())
    }

    pub const fn peek(&self) -> &Event<'a> {
        &self.current
    }

    pub const fn previous(&self) -> &Event<'a> {
        &self.previous
    }
    /// skip a node at the current level
    pub fn skip(&mut self) -> Result<Event<'a>, ParsingError> {
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
        while matches!(self.peek(), Event::Text(_)) || matches!(self.peek(), Event::Comment(_)) {
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

        let (resolved, local) = self.ns_reader.resolver().resolve_element(qname);
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
        ns: Option<Namespace<'a>>,
        key: &str,
    ) -> Result<BytesStart<'a>, ParsingError> {
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
        ns: Option<Namespace<'a>>,
        key: &str,
    ) -> Result<Option<BytesStart<'a>>, ParsingError> {
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
                            found: self.peek().clone().into_owned(),
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

    pub fn close(&mut self) -> Result<Event<'a>, ParsingError> {
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
            if let Event::End(b) = self.peek()
                && b.local_name().into_inner() == tag
            {
                break;
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
                        let (ns, _) = self.ns_reader.resolver().resolve(a.name(), true);
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

    /// Copy every event between the current position and the end tag whose
    /// local name matches `tag`, recording which namespace prefixes are
    /// actually referenced inside.
    ///
    /// Unlike naive text extraction, this resolves each element and attribute
    /// QName against the parser's namespace resolver at the moment it is seen,
    /// so bindings that go out of scope before the closing tag (e.g. ,declared
    /// on a now-closed child element) are still captured correctly.
    ///
    /// The returned XML is not modified: no `xmlns` attributes are injected.
    /// Callers that need a self-contained fragment can construct one from
    /// [`CopiedSubtree::namespaces`].
    pub fn copy_buffer_till_with_namespaces(
        &mut self,
        tag: &'_ [u8],
    ) -> Result<CopiedSubtree, ParsingError> {
        let mut writer = quick_xml::writer::Writer::new(io::Cursor::new(Vec::new()));
        let mut namespaces: IndexMap<String, String> = IndexMap::new();

        loop {
            if let Event::End(b) = self.peek()
                && b.local_name().into_inner() == tag
            {
                break;
            }
            if let Event::Eof = self.peek() {
                return Err(ParsingError::Eof);
            }

            // Record prefix usage on Start/Empty. We resolve NOW so that bindings
            // declared on inner elements are captured even after those elements
            // close and their bindings are popped from the resolver stack.
            if let Event::Start(e) | Event::Empty(e) = self.peek() {
                Self::record_element_usage(e, &self.ns_reader, &mut namespaces);
            }

            writer.write_event(self.current.clone())?;
            self.next_event()?;
        }

        let bytes = writer.into_inner().into_inner();
        let xml: Box<str> = std::str::from_utf8(&bytes)?.to_string().into();
        Ok(CopiedSubtree { xml, namespaces })
    }

    /// Deserializes all elements inside an XML sequence, till an end tag of the
    /// element openned before calling this method is reached.
    pub fn collect_xml_sequence<N: XmlDeserialize<'a, N> + fmt::Debug + PartialEq + Sync>(
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
        N: XmlDeserialize<'a, N> + XmlSerialize + fmt::Debug + PartialEq + Sync,
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
                let (n, l) = self.ns_reader.resolver().resolve(e.name(), true);
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

    pub fn read_xpath_with_namespaces(
        &mut self,
    ) -> Result<(Box<str>, IndexMap<String, String>), ParsingError> {
        // Snapshot every prefix currently in scope BEFORE advancing the reader.
        let mut all_namespaces = IndexMap::new();
        for (decl, Namespace(ns)) in self.ns_reader().resolver().bindings() {
            let prefix = match decl {
                PrefixDeclaration::Default => String::from(""),
                PrefixDeclaration::Named(p) => String::from_utf8_lossy(p).into_owned(),
            };
            all_namespaces.insert(prefix, String::from_utf8_lossy(ns).into_owned());
        }
        let path = self.tag_string()?;
        let used_namespaces = Self::find_xpath_prefixes(&path);
        let namespaces: IndexMap<String, String> = all_namespaces
            .into_iter()
            .filter(|(prefix, _)| used_namespaces.contains(prefix))
            .collect();
        Ok((path, namespaces))
    }

    fn record_element_usage(
        e: &BytesStart<'_>,
        ns_reader: &NsReader<R>,
        out: &mut IndexMap<String, String>,
    ) {
        use quick_xml::name::ResolveResult;

        // Element QName: prefix (or empty for default namespace).
        let prefix = match e.name().prefix() {
            Some(p) => String::from_utf8_lossy(p.as_ref()).into_owned(),
            None => String::new(),
        };
        if !out.contains_key(&prefix)
            && let (ResolveResult::Bound(Namespace(uri)), _) =
                ns_reader.resolver().resolve_element(e.name())
        {
            out.insert(prefix, String::from_utf8_lossy(uri).into_owned());
        }

        // Attributes: only prefixed ones carry a namespace; xmlns* are bindings,
        // not usages, so skip them.
        for attr in e.attributes().flatten() {
            let key = attr.key.as_ref();
            if key == b"xmlns" || key.starts_with(b"xmlns:") {
                continue;
            }
            if let Some(p) = attr.key.prefix() {
                let prefix = String::from_utf8_lossy(p.as_ref()).into_owned();
                if out.contains_key(&prefix) {
                    continue;
                }
                if let (ResolveResult::Bound(Namespace(uri)), _) =
                    ns_reader.resolver().resolve_attribute(attr.key)
                {
                    out.insert(prefix, String::from_utf8_lossy(uri).into_owned());
                }
            }
        }
    }

    /// Find prefixes used within an Xpath expression
    fn find_xpath_prefixes(xpath: &str) -> HashSet<String> {
        let mut prefixes = HashSet::new();
        let mut chars = xpath.char_indices().peekable();
        let mut in_single = false;
        let mut in_double = false;

        while let Some((i, c)) = chars.next() {
            // Skip over string literals — colons inside them aren't prefixes.
            if in_single {
                if c == '\'' {
                    in_single = false;
                }
                continue;
            }
            if in_double {
                if c == '"' {
                    in_double = false;
                }
                continue;
            }
            match c {
                '\'' => in_single = true,
                '"' => in_double = true,
                c if c.is_ascii_alphabetic() || c == '_' => {
                    let start = i;
                    let mut end = i + c.len_utf8();
                    while let Some(&(_, nc)) = chars.peek() {
                        if nc.is_ascii_alphanumeric() || nc == '_' || nc == '-' || nc == '.' {
                            chars.next();
                            end += nc.len_utf8();
                        } else {
                            break;
                        }
                    }
                    // A prefix is an NCName followed by exactly one ':'
                    // (two colons = axis specifier like `child::`).
                    if let Some(&(_, ':')) = chars.peek() {
                        let mut look = chars.clone();
                        look.next();
                        let is_axis = matches!(look.peek(), Some(&(_, ':')));
                        if !is_axis {
                            prefixes.insert(xpath[start..end].to_string());
                            chars.next(); // consume the ':'
                        }
                    }
                }
                _ => {}
            }
        }
        prefixes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::{BytesDecl, BytesEnd, BytesText};

    fn create_parser(xml: &str) -> XmlParser<'_, &[u8]> {
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
        let cow_bindings = IndexMap::from([(
            Cow::Owned(b"https://example.com".to_vec()),
            "xmlns".to_string(),
        )]);
        let xml_writer = XmlWriter::new_with_custom_namespaces(writer, ns_to_apply.clone())
            .expect("failed creating writer");
        assert_eq!(xml_writer.namespace_bindings, vec![cow_bindings]);
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

    fn set<const N: usize>(items: [&str; N]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn assert_prefixes(expr: &str, expected: HashSet<String>) {
        assert_eq!(
            XmlParser::<io::Cursor<&[u8]>>::find_xpath_prefixes(expr),
            expected,
            "unexpected prefix set for: {expr}"
        );
    }

    #[test]
    fn test_find_xpath_prefixes_yields_empty_when_no_qnames_present() {
        // Empty/whitespace input, unprefixed paths, pure numeric/operator
        // expressions, the `current()` function, and bare node tests all
        // contain no QNames — so nothing should be reported.
        for expr in [
            "",
            "   \n\t",
            "/interfaces/interface/name",
            "1 + 2.5 - 3 <= 4 and 5 != 6",
            "current()",
            "node() | text() | comment() | processing-instruction()",
        ] {
            assert_prefixes(expr, HashSet::new());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_test_extracts_prefixes_from_simple_location_paths() {
        // Motivating Huawei debug case, RFC 8641 Figure 12 (`/ex:foo`),
        // the subscribed-notifications `/int:interfaces` example,
        // prefix deduplication, and multi-prefix paths.
        let cases: &[(&str, HashSet<String>)] = &[
            (
                "/debug:debug/debug:board-resouce-states/debug:board-resouce-state",
                set(["debug"]),
            ),
            ("/ex:foo", set(["ex"])),
            ("/int:interfaces", set(["int"])),
            ("/if:interfaces/if:interface/if:name", set(["if"])),
            ("/a:x/b:y/c:z", set(["a", "b", "c"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_recognizes_full_ncname_charset_in_prefixes() {
        // NCName permits letters, digits, `_`, `-`, `.`
        // (the last three may not start the name).
        let cases: &[(&str, HashSet<String>)] = &[
            // Hyphenated — common in OpenConfig.
            (
                "/oc-if:interfaces/oc-if:interface[oc-if:name='eth0']",
                set(["oc-if"]),
            ),
            // Dot in the middle (legal NCName, rare in practice).
            ("/a.b:c", set(["a.b"])),
            // Underscore-leading.
            ("/_ns:leaf", set(["_ns"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_handles_prefixed_wildcards_and_attributes() {
        let cases: &[(&str, HashSet<String>)] = &[
            ("/ex:*", set(["ex"])),
            ("//@ex:id", set(["ex"])),
            ("/if:interface[@nc:operation='delete']", set(["if", "nc"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_xpath_axes_are_never_reported_as_prefixes() {
        // Every XPath 1.0 axis name followed by `::` must be skipped,
        // since the `::` is an axis separator rather than a prefix colon.
        const AXES: &[&str] = &[
            "ancestor",
            "ancestor-or-self",
            "attribute",
            "child",
            "descendant",
            "descendant-or-self",
            "following",
            "following-sibling",
            "namespace",
            "parent",
            "preceding",
            "preceding-sibling",
            "self",
        ];
        for axis in AXES {
            assert_prefixes(&format!("{axis}::node()"), HashSet::new());
        }
        // Axes can still coexist with real prefixes in the same expression.
        assert_prefixes("descendant::if:interface/child::if:name", set(["if"]));
    }

    #[test]
    fn test_find_xpath_prefixes_skips_colons_inside_string_literals() {
        // Single-quoted identityref comparisons (RFC 7950 §9.10),
        // double-quoted variants, and mixed-quote expressions.
        let cases: &[(&str, HashSet<String>)] = &[
            ("../crypto = 'mc:aes'", HashSet::new()),
            ("name() = \"ns:bogus\"", HashSet::new()),
            ("@a:x = 'p:q' or @b:y = \"r:s\"", set(["a", "b"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_handles_compound_expressions() {
        // Function calls, leafref-style predicates with current(),
        // unions, boolean ops across modules, and nested predicates.
        let cases: &[(&str, HashSet<String>)] = &[
            ("ex:size(@id)", set(["ex"])),
            (
                "/if:interfaces/if:interface[if:name = current()/../if:name]",
                set(["if"]),
            ),
            ("/a:foo | /b:bar", set(["a", "b"])),
            (
                "(/if:interfaces/if:interface/if:enabled = 'true') \
                 and count(/rt:routing/rt:routes) > 0",
                set(["if", "rt"]),
            ),
            ("/a:x[a:y[b:z = '1']/a:w = c:fn()]", set(["a", "b", "c"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_real_world_yang_expressions() {
        // ietf-interfaces-style `must`: only `if:` is a live prefix;
        // the `ianaift:*` tokens are identityref values inside string
        // literals and must not be reported.
        let must_expr = "(/if:interfaces/if:interface[if:name=current()]/if:type \
                         = 'ianaift:ethernetCsmacd') \
                         or \
                         (/if:interfaces/if:interface[if:name=current()]/if:type \
                         = 'ianaift:ieee8023adLag')";
        assert_prefixes(must_expr, set(["if"]));

        // Multi-module subscriber filter for yp:datastore-xpath-filter.
        let filter_expr = "/if:interfaces/if:interface[if:name='eth0'] \
                           | /rt:routing/rt:ribs/rt:rib[rt:name=current()/ref:rib]";
        assert_prefixes(filter_expr, set(["if", "rt", "ref"]));
    }

    #[test]
    fn test_find_xpath_prefixes_whitespace_between_ncname_and_colon_breaks_qname() {
        // In XPath 1.0 a QName is lexically `NCName ':' NCName` with no
        // whitespace. `if : interfaces` is three tokens, so `if` must not
        // be reported as a prefix. This behavior is intentional.
        assert_prefixes("  /  if : interfaces  ", HashSet::new());
    }

    #[test]
    fn test_read_xpath_with_namespaces_basic_filter() {
        // One prefix declared on the filter element, used in the path.
        // Both should round-trip.
        let xml = r#"<datastore-xpath-filter
        xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
        xmlns:ex="urn:example:debug">/ex:debug/ex:board-resouce-states</datastore-xpath-filter>"#;
        let mut parser = create_parser(xml);
        parser
            .open(
                Some(Namespace(
                    b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                )),
                "datastore-xpath-filter",
            )
            .expect("failed to open filter");

        let (path, namespaces) = parser
            .read_xpath_with_namespaces()
            .expect("read_xpath_with_namespaces failed");

        assert_eq!(path.as_ref(), "/ex:debug/ex:board-resouce-states");
        assert_eq!(
            namespaces,
            IndexMap::from([("ex".to_string(), "urn:example:debug".to_string())]),
        );
    }

    #[test]
    fn test_read_xpath_with_namespaces_drops_unused_bindings() {
        // Two prefixes declared, only one referenced. The default namespace
        // and `unused:` must NOT appear in the result — this is the whole
        // point of filtering by find_xpath_prefixes.
        let xml = r#"<datastore-xpath-filter
        xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
        xmlns:if="urn:example:interfaces"
        xmlns:unused="urn:example:not-referenced">/if:interfaces/if:interface</datastore-xpath-filter>"#;
        let mut parser = create_parser(xml);
        parser
            .open(
                Some(Namespace(
                    b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                )),
                "datastore-xpath-filter",
            )
            .unwrap();

        let (path, namespaces) = parser.read_xpath_with_namespaces().unwrap();

        assert_eq!(path.as_ref(), "/if:interfaces/if:interface");
        assert_eq!(
            namespaces,
            IndexMap::from([("if".to_string(), "urn:example:interfaces".to_string())]),
        );
    }

    #[test]
    fn test_read_xpath_with_namespaces_inherits_ancestor_bindings() {
        // RFC 7950 §9.13.2 requires referenced prefixes to be in the XML
        // namespace scope of the value's element — but "in scope" includes
        // ancestor declarations. Here `if:` is declared on <filters>, not
        // on <datastore-xpath-filter>, and must still be picked up.
        let xml = r#"<filters
        xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
        xmlns:if="urn:example:interfaces">
        <datastore-xpath-filter>/if:interfaces</datastore-xpath-filter>
    </filters>"#;
        let mut parser = create_parser(xml);
        parser
            .open(
                Some(Namespace(
                    b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                )),
                "filters",
            )
            .unwrap();
        parser.skip_text().unwrap();
        parser
            .open(
                Some(Namespace(
                    b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                )),
                "datastore-xpath-filter",
            )
            .unwrap();

        let (path, namespaces) = parser.read_xpath_with_namespaces().unwrap();

        assert_eq!(path.as_ref(), "/if:interfaces");
        assert_eq!(
            namespaces,
            IndexMap::from([("if".to_string(), "urn:example:interfaces".to_string())]),
        );
    }

    #[test]
    fn test_read_xpath_with_namespaces_inner_binding_shadows_ancestor() {
        // Same prefix declared at two levels with different URIs — the
        // resolver must return the inner one, since we snapshot bindings at
        // the moment we're sitting on the filter element's start tag.
        let xml = r#"<outer xmlns:p="urn:example:wrong">
        <datastore-xpath-filter
            xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
            xmlns:p="urn:example:right">/p:foo</datastore-xpath-filter>
    </outer>"#;
        let mut parser = create_parser(xml);
        parser.open(None, "outer").unwrap();
        parser.skip_text().unwrap();
        parser
            .open(
                Some(Namespace(
                    b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                )),
                "datastore-xpath-filter",
            )
            .unwrap();

        let (path, namespaces) = parser.read_xpath_with_namespaces().unwrap();

        assert_eq!(path.as_ref(), "/p:foo");
        assert_eq!(
            namespaces,
            IndexMap::from([("p".to_string(), "urn:example:right".to_string())]),
        );
    }

    #[test]
    fn test_read_xpath_with_namespaces_undeclared_prefix_is_silently_dropped() {
        // RFC 7950 §9.13.2 says prefixes used in an instance value MUST be
        // declared in scope. If a sender violates that, find_xpath_prefixes
        // still extracts `bogus`, but no binding exists to map it to a URI,
        // so it's filtered out of the result. The function favors permissive
        // parsing over rejecting malformed input.
        let xml = r#"<datastore-xpath-filter
        xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">/bogus:foo</datastore-xpath-filter>"#;
        let expected: IndexMap<String, String> = IndexMap::new();

        let mut parser = create_parser(xml);
        parser
            .open(
                Some(Namespace(
                    b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                )),
                "datastore-xpath-filter",
            )
            .unwrap();

        let (path, namespaces) = parser.read_xpath_with_namespaces().unwrap();

        assert_eq!(path.as_ref(), "/bogus:foo");
        assert_eq!(namespaces, expected);
    }

    #[test]
    fn test_read_xpath_with_namespaces_multiple_modules_and_literal_prefixes() {
        // Real-world `must`-style filter mixing live prefixes with prefixed
        // identityref values inside string literals. The `t:` token appears
        // only inside quotes, so even though it's declared, it shouldn't end
        // up in the namespace map (find_xpath_prefixes correctly skips it).
        // Conversely `if:` is live and must be kept.
        let xml = r#"<datastore-xpath-filter
        xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
        xmlns:if="urn:example:interfaces"
        xmlns:t="urn:example:if-types">/if:interfaces/if:interface[if:type='t:ethernetCsmacd']</datastore-xpath-filter>"#;
        let mut parser = create_parser(xml);
        parser
            .open(
                Some(Namespace(
                    b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications",
                )),
                "datastore-xpath-filter",
            )
            .unwrap();

        let (path, namespaces) = parser.read_xpath_with_namespaces().unwrap();

        assert_eq!(
            path.as_ref(),
            "/if:interfaces/if:interface[if:type='t:ethernetCsmacd']",
        );
        assert_eq!(
            namespaces,
            IndexMap::from([("if".to_string(), "urn:example:interfaces".to_string())]),
        );
    }
}
