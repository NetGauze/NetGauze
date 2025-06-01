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

//! Low-level XML parsing utils

use quick_xml::{
    events::{BytesStart, Event},
    name::{Namespace, ResolveResult},
    reader::NsReader,
};
use std::{collections::HashMap, io};

/// XML Serialization trait
/// inspired by https://github.com/deuxfleurs-org/aerogramme
pub trait XmlSerialize {
    fn xml_serialize<T: io::Write>(&self, xml: &mut XmlWriter<T>) -> Result<(), quick_xml::Error>;
}

/// XML Deserialization trait
/// inspired by https://github.com/deuxfleurs-org/aerogramme
pub trait XmlDeserialize<T: Sized> {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<T, ParsingError>;
}

#[derive(Debug)]
pub enum ParsingError {
    StdIo(io::Error),
    Recoverable,
    MissingChild(String),
    MissingAttribute,
    WrongToken(String),
    TagNotFound,
    InvalidValue(String),
    Utf8Error(std::str::Utf8Error),
    QuickXml(quick_xml::Error),
    Int(std::num::ParseIntError),
    Eof,
}

impl std::fmt::Display for ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recoverable => write!(f, "Recoverable"),
            Self::MissingChild(e) => write!(f, "Missing child `{e}`"),
            Self::MissingAttribute => write!(f, "Missing attribute"),
            Self::WrongToken(token) => write!(f, "Wrong token: `{token}`"),
            Self::TagNotFound => write!(f, "Tag not found"),
            Self::InvalidValue(e) => write!(f, "Invalid value `{e}`"),
            Self::Utf8Error(e) => write!(f, "Utf8 Error `{e}`"),
            Self::QuickXml(e) => write!(f, "Quick XML error {e}"),
            Self::Int(e) => write!(f, "Number parsing error `{e}`"),
            Self::StdIo(e) => write!(f, "Std IO Error {e}"),
            Self::Eof => write!(f, "Found EOF while expecting data"),
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

/// Transform a Rust object into an XML stream of characters
pub struct XmlWriter<T: io::Write> {
    pub inner: quick_xml::writer::Writer<T>,
    pub ns_to_apply: Vec<(String, String)>,
}

impl<T: io::Write> XmlWriter<T> {
    pub fn new(inner: quick_xml::writer::Writer<T>) -> Self {
        Self {
            inner,
            ns_to_apply: vec![(
                "xmlns".into(),
                "urn:ietf:params:xml:ns:netconf:base:1.0".to_string(),
            )],
        }
    }
}

impl<T: io::Write> XmlWriter<T> {
    pub fn create_nc_element(&mut self, name: &'static str) -> BytesStart<'static> {
        let mut start = BytesStart::new(name);
        if !self.ns_to_apply.is_empty() {
            start.extend_attributes(
                self.ns_to_apply
                    .iter()
                    .map(|(k, n)| (k.as_str(), n.as_str())),
            );
            self.ns_to_apply.clear()
        }
        start
    }

    pub fn create_ns_element(&mut self, ns: &str, name: &str) -> BytesStart<'static> {
        let mut start = BytesStart::new(format!("{ns}:{name}"));
        if !self.ns_to_apply.is_empty() {
            start.extend_attributes(
                self.ns_to_apply
                    .iter()
                    .map(|(k, n)| (k.as_str(), n.as_str())),
            );
            self.ns_to_apply.clear()
        }
        start
    }
}

/// Transform an XML stream of characters into a Rust object
pub struct XmlParser<T: io::BufRead> {
    pub rdr: NsReader<T>,
    cur: Event<'static>,
    prev: Event<'static>,
    parents: Vec<Event<'static>>,
    buf: Vec<u8>,
}

impl<T: io::BufRead> XmlParser<T> {
    pub fn new(mut rdr: NsReader<T>) -> Result<Self, ParsingError> {
        let mut buf: Vec<u8> = vec![];
        let cur = rdr.read_event_into(&mut buf)?.into_owned();
        let parents = vec![];
        let prev = Event::Eof;
        buf.clear();
        Ok(Self {
            rdr,
            cur,
            prev,
            parents,
            buf,
        })
    }

    /// read one more tag
    /// do not expose it publicly
    fn next(&mut self) -> Result<Event<'static>, ParsingError> {
        self.buf.clear();
        let evt = self.rdr.read_event_into(&mut self.buf)?.into_owned();
        self.prev = std::mem::replace(&mut self.cur, evt);
        Ok(self.prev.clone())
    }

    /// skip a node at the current level
    /// I would like to make this one private but not ready
    pub fn skip(&mut self) -> Result<Event<'static>, ParsingError> {
        match &self.cur {
            Event::Start(b) => {
                let _span = self
                    .rdr
                    .read_to_end_into(b.to_end().name(), &mut self.buf)?;
                self.next()
            }
            Event::End(_) => Err(ParsingError::WrongToken(format!("{:?}", self.cur))),
            Event::Eof => Err(ParsingError::Eof),
            _ => self.next(),
        }
    }

    pub fn skip_text(&mut self) -> Result<(), ParsingError> {
        while let Event::Text(_) = self.peek() {
            self.skip()?;
        }
        Ok(())
    }

    /// check if this is the desired tag
    fn is_tag(&self, ns: &[u8], key: &str) -> bool {
        let qname = match self.peek() {
            Event::Start(bs) | Event::Empty(bs) => bs.name(),
            Event::End(be) => be.name(),
            _ => return false,
        };

        let (extr_ns, local) = self.rdr.resolve_element(qname);

        if local.into_inner() != key.as_bytes() {
            return false;
        }

        match extr_ns {
            ResolveResult::Bound(v) => v.into_inner() == ns,
            _ => false,
        }
    }

    pub fn parent_has_child(&self) -> bool {
        matches!(self.parents.last(), Some(Event::Start(_)) | None)
    }

    fn ensure_parent_has_child(&self) -> Result<(), ParsingError> {
        match self.parent_has_child() {
            true => Ok(()),
            false => Err(ParsingError::Recoverable),
        }
    }

    pub const fn peek(&self) -> &Event<'static> {
        &self.cur
    }

    pub const fn previous(&self) -> &Event<'static> {
        &self.prev
    }

    // TODO support namespaces
    pub fn copy_buffer_till(&mut self, tag: &'_ [u8]) -> Result<String, ParsingError> {
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
                if let Event::Start(a) = &mut self.cur {
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
                        let (ns, _) = self.rdr.resolve(a.name(), false);
                        if let ResolveResult::Bound(ns) = ns {
                            a.push_attribute((&b"xmlns"[..], ns.0));
                        }
                    }
                    wrote_ns = true;
                    writer.write_event(Event::Start(a.clone()))?;
                } else {
                    writer.write_event(self.cur.clone())?;
                }
            } else {
                writer.write_event(self.cur.clone())?;
            }
            self.next()?;
        }
        let ret = std::str::from_utf8(&writer.into_inner().into_inner())?.to_string();
        Ok(ret)
        // match self.cur {
        //     Event::Start(_) => {
        //         if !self.buf.is_empty() {
        //             let first = std::str::from_utf8(&self.buf)?;
        //             buf.extend_from_slice(format!("<{first}>").as_bytes());
        //         }
        //     }
        //     Event::Text(_) => {
        //         if !self.buf.is_empty() {
        //             let first = std::str::from_utf8(&self.buf)?;
        //             buf.extend_from_slice(format!("{first}<").as_bytes());
        //         }
        //     }
        //     _ => {}
        // }
        // loop {
        //     match inner.fill_buf() {
        //         Ok(n) => {
        //             if n.is_empty() {
        //                 eprintln!("N IS EMPTY");
        //                 break
        //             }
        //             match n.windows(tag.len()).position(|w| w == tag) {
        //                 Some(pos) => {
        //                     buf.extend_from_slice(&n[..pos]);
        //                     break;
        //                 }
        //                 None => {
        //                     buf.extend_from_slice(&n[..n.len()]);
        //                 }
        //             }
        //         },
        //         Err(e) => return Err(e)?,
        //     }
        // }
        // let ret = std::str::from_utf8(&buf)?.to_string();
        // Ok(ret)
    }

    // NEW API
    pub fn tag_string(&mut self) -> Result<String, ParsingError> {
        self.ensure_parent_has_child()?;

        let mut acc = String::new();
        loop {
            match self.peek() {
                Event::CData(unescaped) => {
                    acc.push_str(std::str::from_utf8(unescaped.as_ref())?);
                    self.next()?
                }
                Event::Text(escaped) => {
                    acc.push_str(escaped.unescape()?.as_ref());
                    self.next()?
                }
                Event::End(_) | Event::Start(_) | Event::Empty(_) => return Ok(acc),
                _ => self.next()?,
            };
        }
    }
    //
    // pub fn maybe_read<N: QRead<N> + QWrite + std::fmt::Debug + PartialEq +
    // Clone + Sync>(     &mut self,
    //     t: &mut Option<N>,
    //     dirty: &mut bool,
    // ) -> Result<(), ParsingError> {
    //     if !self.parent_has_child() {
    //         return Ok(());
    //     }
    //
    //     match N::qread(self) {
    //         Ok(v) => {
    //             *t = Some(v);
    //             *dirty = true;
    //             Ok(())
    //         }
    //         Err(ParsingError::Recoverable) => Ok(()),
    //         Err(e) => Err(e),
    //     }
    // }
    //
    // pub fn maybe_push<N: QRead<T> + QWrite + std::fmt::Debug + PartialEq +
    // Clone + Sync>(     &mut self,
    //     t: &mut Vec<N>,
    //     dirty: &mut bool,
    // ) -> Result<(), ParsingError> {
    //     if !self.parent_has_child() {
    //         return Ok(());
    //     }
    //
    //     match N::qread(self) {
    //         Ok(v) => {
    //             t.push(v);
    //             *dirty = true;
    //             Ok(())
    //         }
    //         Err(ParsingError::Recoverable) => Ok(()),
    //         Err(e) => Err(e),
    //     }
    // }
    //
    // pub fn find<N: QRead<T> + QWrite + std::fmt::Debug + PartialEq + Clone
    // + Sync>(&mut self) -> Result<N, ParsingError> {
    //   self.ensure_parent_has_child()?;
    //
    //     loop {
    //         // Try parse
    //         match N::qread(self) {
    //             Err(ParsingError::Recoverable) => (),
    //             otherwise => return otherwise,
    //         }
    //
    //         // If recovered, skip the element
    //         self.skip()?;
    //     }
    // }

    // pub fn maybe_find<N: QRead<T> + QWrite + std::fmt::Debug + PartialEq +
    // Clone + Sync>(&mut self) -> Result<Option<N>, ParsingError> {     // We can'
    // t find anything inside a self-closed tag     if !self.parent_has_child()
    // {         return Ok(None);
    //     }
    //
    //     loop {
    //         // Try parse
    //         match N::qread(self) {
    //             Err(ParsingError::Recoverable) => (),
    //             otherwise => return otherwise.map(Some),
    //         }
    //
    //         // Skip or stop
    //         match self.peek() {
    //             Event::End(_) => return Ok(None),
    //             _ => self.skip()?,
    //         };
    //     }
    // }

    pub fn collect<N: XmlDeserialize<N> + XmlSerialize + std::fmt::Debug + PartialEq + Sync>(
        &mut self,
    ) -> Result<Vec<N>, ParsingError> {
        let mut acc = Vec::new();
        if !self.parent_has_child() {
            return Ok(acc);
        }
        loop {
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

    pub fn collect_tag<N: XmlDeserialize<N> + XmlSerialize + std::fmt::Debug + PartialEq + Sync>(
        &mut self,
        ns: &'_ [u8],
        tag: &'_ [u8],
    ) -> Result<Vec<N>, ParsingError> {
        let mut acc = Vec::new();
        let resolved_ns = ResolveResult::Bound(Namespace(ns));
        if !self.parent_has_child() {
            return Ok(acc);
        }
        loop {
            self.skip_text()?;
            if let Event::Start(ref e) = self.cur {
                let (n, l) = self.rdr.resolve(e.name(), false);
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

    pub fn open(&mut self, ns: &[u8], key: &str) -> Result<Event<'static>, ParsingError> {
        let evt = match self.peek() {
            Event::Empty(_) if self.is_tag(ns, key) => {
                // hack to make `prev_attr` works
                // here we duplicate the current tag
                // as in other words, we virtually moved one token
                // which is useful for prev_attr and any logic based on
                // self.prev + self.open() on empty nodes
                self.prev = self.cur.clone();
                self.cur.clone()
            }
            Event::Start(_) if self.is_tag(ns, key) => self.next()?,
            _ => return Err(ParsingError::Recoverable),
        };
        self.parents.push(evt.clone());
        Ok(evt)
    }

    pub fn open_start(&mut self, ns: &[u8], key: &str) -> Result<Event<'static>, ParsingError> {
        self.skip_text()?;
        let evt = match self.peek() {
            Event::Start(_) if self.is_tag(ns, key) => self.next()?,
            _ => return Err(ParsingError::Recoverable),
        };
        self.parents.push(evt.clone());
        Ok(evt)
    }

    pub fn open_start_check_missing(
        &mut self,
        ns: &[u8],
        key: &str,
    ) -> Result<Event<'static>, ParsingError> {
        self.skip_text()?;
        let evt = match self.peek() {
            Event::Start(_) if self.is_tag(ns, key) => self.next()?,
            _ => return Err(ParsingError::MissingChild(key.into())),
        };
        self.parents.push(evt.clone());
        Ok(evt)
    }

    pub fn maybe_open(
        &mut self,
        ns: &[u8],
        key: &str,
    ) -> Result<Option<Event<'static>>, ParsingError> {
        self.skip_text()?;
        match self.open(ns, key) {
            Ok(v) => Ok(Some(v)),
            Err(ParsingError::Recoverable) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn maybe_open_start(
        &mut self,
        ns: &[u8],
        key: &str,
    ) -> Result<Option<Event<'static>>, ParsingError> {
        match self.open_start(ns, key) {
            Ok(v) => Ok(Some(v)),
            Err(ParsingError::Recoverable) => Ok(None),
            Err(e) => Err(e),
        }
    }
    //
    // pub fn prev_attr(&self, attr: &str) -> Option<String> {
    //     match &self.prev {
    //         Event::Start(bs) | Event::Empty(bs) => match
    // bs.try_get_attribute(attr) {             Ok(Some(attr)) => attr
    //                 .decode_and_unescape_value(&self.rdr)
    //                 .ok()
    //                 .map(|v| v.into_owned()),
    //             _ => None,
    //         },
    //         _ => None,
    //     }
    // }
    //
    // // find stop tag
    pub fn close(&mut self) -> Result<Event<'static>, ParsingError> {
        // Handle the empty case
        if !self.parent_has_child() {
            self.parents.pop();
            return self.next();
        }

        // Handle the start/end case
        loop {
            match self.peek() {
                Event::End(_) => {
                    self.parents.pop();
                    return self.next();
                }
                _ => self.skip()?,
            };
        }
    }
}
