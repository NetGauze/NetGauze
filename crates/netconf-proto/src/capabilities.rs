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

//! NETCONF capabilities as defined in IANA: [Network Configuration Protocol (NETCONF) Capability URNs](https://www.iana.org/assignments/netconf-capability-urns/netconf-capability-urns.xhtml)

use crate::xml_parser::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
use quick_xml::events::{BytesText, Event};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io, str::FromStr};

/// Capabilities trait for NETCONF.
pub trait CapabilityImpl {
    /// Shorthand name for capability, e.g. `:candidate`
    fn shorthand(&self) -> Box<str>;

    fn identifier(&self) -> Box<str>;

    /// URN for capability with query string,
    /// e.g. `urn:ietf:params:xml:ns:yang:ietf-yang-metadata?
    /// module=ietf-yang-metadata&revision=2016-08-05`.
    ///
    /// If the capability does not have a query string, this should return the
    /// same as `identifier`.
    fn urn(&self) -> Box<str>;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename = "capability")]
pub enum Capability {
    WritableRunning(WritableRunning),
    Candidate(Candidate),
    ConfirmedCommit(ConfirmedCommit),
    RollbackOnError(RollbackOnError),
    Validate(Validate),
    Startup(Startup),
    Url(Url),
    Xpath(Xpath),
    Notification(Notification),
    Interleave(Interleave),
    PartialLock(PartialLock),
    WithDefaults(WithDefaults),
    Base(Base),
    Time(Time),
    YangLibrary(YangLibrary),
    WithOperationalDefaults(WithOperationalDefaults),
    YangModule {
        ns: Box<str>,
        module: Box<str>,
        revision: Box<str>,
    },
    Unknown(Box<str>),
}

impl CapabilityImpl for Capability {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::WritableRunning(v) => v.shorthand(),
            Self::Candidate(v) => v.shorthand(),
            Self::ConfirmedCommit(v) => v.shorthand(),
            Self::RollbackOnError(v) => v.shorthand(),
            Self::Validate(v) => v.shorthand(),
            Self::Startup(v) => v.shorthand(),
            Self::Url(v) => v.shorthand(),
            Self::Xpath(v) => v.shorthand(),
            Self::Notification(v) => v.shorthand(),
            Self::Interleave(v) => v.shorthand(),
            Self::PartialLock(v) => v.shorthand(),
            Self::WithDefaults(v) => v.shorthand(),
            Self::Base(v) => v.shorthand(),
            Self::Time(v) => v.shorthand(),
            Self::YangLibrary(v) => v.shorthand(),
            Self::WithOperationalDefaults(v) => v.shorthand(),
            Self::YangModule { module, .. } => format!(":{module}").into(),
            Self::Unknown(v) => v.clone(),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::WritableRunning(v) => v.identifier(),
            Self::Candidate(v) => v.identifier(),
            Self::ConfirmedCommit(v) => v.identifier(),
            Self::RollbackOnError(v) => v.identifier(),
            Self::Validate(v) => v.identifier(),
            Self::Startup(v) => v.identifier(),
            Self::Url(v) => v.identifier(),
            Self::Xpath(v) => v.identifier(),
            Self::Notification(v) => v.identifier(),
            Self::Interleave(v) => v.identifier(),
            Self::PartialLock(v) => v.identifier(),
            Self::WithDefaults(v) => v.identifier(),
            Self::Base(v) => v.identifier(),
            Self::Time(v) => v.identifier(),
            Self::YangLibrary(v) => v.identifier(),
            Self::WithOperationalDefaults(v) => v.identifier(),
            Self::YangModule { ns, .. } => format!("{ns}").into(),
            Self::Unknown(v) => v.clone(),
        }
    }

    fn urn(&self) -> Box<str> {
        match self {
            Self::WritableRunning(v) => v.urn(),
            Self::Candidate(v) => v.urn(),
            Self::ConfirmedCommit(v) => v.urn(),
            Self::RollbackOnError(v) => v.urn(),
            Self::Validate(v) => v.urn(),
            Self::Startup(v) => v.urn(),
            Self::Url(v) => v.urn(),
            Self::Xpath(v) => v.urn(),
            Self::Notification(v) => v.urn(),
            Self::Interleave(v) => v.urn(),
            Self::PartialLock(v) => v.urn(),
            Self::WithDefaults(v) => v.urn(),
            Self::Base(v) => v.urn(),
            Self::Time(v) => v.urn(),
            Self::YangLibrary(v) => v.urn(),
            Self::WithOperationalDefaults(v) => v.urn(),
            Self::YangModule {
                ns,
                module,
                revision,
            } => format!("{ns}?module={module}&revision={revision}").into(),
            Self::Unknown(v) => v.clone(),
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WritableRunning(v) => v.fmt(f),
            Self::Candidate(v) => v.fmt(f),
            Self::ConfirmedCommit(v) => v.fmt(f),
            Self::RollbackOnError(v) => v.fmt(f),
            Self::Validate(v) => v.fmt(f),
            Self::Startup(v) => v.fmt(f),
            Self::Url(v) => v.fmt(f),
            Self::Xpath(v) => v.fmt(f),
            Self::Notification(v) => v.fmt(f),
            Self::Interleave(v) => v.fmt(f),
            Self::PartialLock(v) => v.fmt(f),
            Self::WithDefaults(v) => v.fmt(f),
            Self::Base(v) => v.fmt(f),
            Self::Time(v) => v.fmt(f),
            Self::YangLibrary(v) => v.fmt(f),
            Self::WithOperationalDefaults(v) => v.fmt(f),
            Self::YangModule { .. } => self.shorthand().fmt(f),
            Self::Unknown(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Debug)]
pub enum CapabilityParsingError {
    UrnError(iri_string::validate::Error),
    MissingParam { urn: Box<str>, param: Box<str> },
}

impl std::fmt::Display for CapabilityParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UrnError(e) => e.fmt(f),
            Self::MissingParam { urn, param } => {
                write!(f, "{urn}: missing required parameter {param}")
            }
        }
    }
}

impl std::error::Error for CapabilityParsingError {}

impl From<iri_string::validate::Error> for CapabilityParsingError {
    fn from(e: iri_string::validate::Error) -> Self {
        Self::UrnError(e)
    }
}

fn extract_params(query: &'_ str) -> HashMap<&'_ str, &'_ str> {
    query
        .split('&')
        .filter_map(|pair| match pair.split_once('=') {
            Some((key, value)) => Some((key, value)),
            _ => None,
        })
        .collect::<HashMap<&str, &str>>()
}

fn extract_module_revision(
    query: &'_ str,
    urn: &'_ str,
) -> Result<(Box<str>, Box<str>), CapabilityParsingError> {
    let params = extract_params(query);
    let module = if let Some(module) = params.get("module") {
        *module
    } else {
        return Err(CapabilityParsingError::MissingParam {
            urn: urn.into(),
            param: "module".into(),
        });
    };
    let revision = if let Some(revision) = params.get("revision") {
        *revision
    } else {
        return Err(CapabilityParsingError::MissingParam {
            urn: urn.into(),
            param: "revision".into(),
        });
    };

    Ok((module.into(), revision.into()))
}

impl FromStr for Capability {
    type Err = CapabilityParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = iri_string::types::UriStr::new(s)?;
        match (
            uri.scheme_str(),
            uri.authority_str(),
            uri.path_str(),
            uri.query_str(),
            uri.fragment(),
        ) {
            ("urn", None, "ietf:params:netconf:capability:writable-running:1.0", None, None) => {
                Ok(Self::WritableRunning(WritableRunning::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:candidate:1.0", None, None) => {
                Ok(Self::Candidate(Candidate::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:confirmed-commit:1.0", None, None) => {
                Ok(Self::ConfirmedCommit(ConfirmedCommit::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:confirmed-commit:1.1", None, None) => {
                Ok(Self::ConfirmedCommit(ConfirmedCommit::V1_1))
            }
            ("urn", None, "ietf:params:netconf:capability:rollback-on-error:1.0", None, None) => {
                Ok(Self::RollbackOnError(RollbackOnError::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:validate:1.0", None, None) => {
                Ok(Self::Validate(Validate::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:validate:1.1", None, None) => {
                Ok(Self::Validate(Validate::V1_1))
            }
            ("urn", None, "ietf:params:netconf:capability:startup:1.0", None, None) => {
                Ok(Self::Startup(Startup::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:url:1.0", Some(query), None) => {
                let schemes = query
                    .split('&')
                    .filter_map(|pair| match pair.split_once('=') {
                        Some(("scheme", values)) => Some(values.split(',')),
                        _ => None,
                    })
                    .flatten()
                    .map(Box::from)
                    .collect();
                Ok(Self::Url(Url::V1_0(schemes)))
            }
            ("urn", None, "ietf:params:netconf:capability:xpath:1.0", None, None) => {
                Ok(Self::Xpath(Xpath::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:notification:1.0", None, None) => {
                Ok(Self::Notification(Notification::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:interleave:1.0", None, None) => {
                Ok(Self::Interleave(Interleave::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:partial-lock:1.0", None, None) => {
                Ok(Self::PartialLock(PartialLock::V1_0))
            }
            ("urn", None, "ietf:params:netconf:base:1.0", None, None) => Ok(Self::Base(Base::V1_0)),
            ("urn", None, "ietf:params:netconf:base:1.1", None, None) => Ok(Self::Base(Base::V1_1)),
            ("urn", None, "ietf:params:netconf:capability:time:1.0", None, None) => {
                Ok(Self::Time(Time::V1_0))
            }
            ("urn", None, "ietf:params:netconf:capability:yang-library:1.0", Some(query), None) => {
                let params = extract_params(query);
                let revision = if let Some(revision) = params.get("revision") {
                    *revision
                } else {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: s.into(),
                        param: "revision".into(),
                    });
                };
                let module_set_id = if let Some(module_set_id) = params.get("module-set-id") {
                    *module_set_id
                } else {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: s.into(),
                        param: "module-set-id".into(),
                    });
                };
                Ok(Self::YangLibrary(YangLibrary::V1_0 {
                    revision: revision.into(),
                    module_set_id: module_set_id.into(),
                }))
            }
            ("urn", None, "ietf:params:netconf:capability:yang-library:1.1", Some(query), None) => {
                let params = extract_params(query);
                let revision = if let Some(revision) = params.get("revision") {
                    *revision
                } else {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: s.into(),
                        param: "revision".into(),
                    });
                };
                let content_id = if let Some(content_id) = params.get("content-id") {
                    *content_id
                } else {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: s.into(),
                        param: "content-id".into(),
                    });
                };
                Ok(Self::YangLibrary(YangLibrary::V1_1 {
                    revision: revision.into(),
                    content_id: content_id.into(),
                }))
            }
            (
                "urn",
                None,
                "ietf:params:netconf:capability:with-operational-defaults:1.0",
                None,
                None,
            ) => Ok(Self::WithOperationalDefaults(WithOperationalDefaults::V1_0)),
            (
                "urn",
                None,
                "ietf:params:netconf:capability:with-defaults:1.0",
                Some(query),
                None,
            ) => Ok(Self::WithDefaults(WithDefaults::V1_0(query.to_owned()))),
            ("urn", None, ns, Some(query), None) => {
                if let Ok((module, revision)) = extract_module_revision(query, ns) {
                    Ok(Self::YangModule {
                        ns: format!("urn:{ns}").into(),
                        module,
                        revision,
                    })
                } else {
                    Ok(Self::Unknown(s.into()))
                }
            }
            _ => Ok(Self::Unknown(s.into())),
        }
    }
}

impl XmlDeserialize<Capability> for Capability {
    fn xml_deserialize(
        parser: &mut XmlParser<impl io::BufRead>,
    ) -> Result<Capability, ParsingError> {
        parser.open_start(crate::protocol::NETCONF_NS_STR, "capability")?;
        let body = parser.tag_string()?;
        parser.close()?;
        Ok(Capability::from_str(&body).unwrap())
    }
}

impl XmlSerialize for Capability {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_nc_element("capability");
        let end = start.to_end();
        writer.inner.write_event(Event::Start(start.clone()))?;
        writer
            .inner
            .write_event(Event::Text(BytesText::new(&self.urn())))?;
        writer.inner.write_event(Event::End(end))?;
        Ok(())
    }
}

/// See [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WritableRunning {
    #[serde(alias = ":writable-running")]
    #[serde(rename = "urn:ietf:params:netconf:capability:writable-running:1.0")]
    V1_0,
}

impl CapabilityImpl for WritableRunning {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":writable-running"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:writable-running:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for WritableRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Candidate {
    #[serde(alias = ":candidate")]
    #[serde(rename = "urn:ietf:params:netconf:capability:candidate:1.0")]
    V1_0,
}

impl CapabilityImpl for Candidate {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":candidate"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:candidate:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC4741](https://datatracker.ietf.org/doc/html/rfc4741)
/// and [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfirmedCommit {
    #[serde(alias = ":confirmed-commit")]
    #[serde(rename = "urn:ietf:params:netconf:capability:confirmed-commit:1.0")]
    V1_0,

    #[serde(alias = ":confirmed-commit:1.1")]
    #[serde(rename = "urn:ietf:params:netconf:capability:confirmed-commit:1.1")]
    V1_1,
}

impl CapabilityImpl for ConfirmedCommit {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":confirmed-commit"),
            Self::V1_1 => Box::from(":confirmed-commit:1.1"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:confirmed-commit:1.0"),
            Self::V1_1 => Box::from("urn:ietf:params:netconf:capability:confirmed-commit:1.1"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for ConfirmedCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RollbackOnError {
    #[serde(alias = ":rollback-on-error")]
    #[serde(rename = "urn:ietf:params:netconf:capability:rollback-on-error:1.0")]
    V1_0,
}

impl CapabilityImpl for RollbackOnError {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":rollback-on-error"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:rollback-on-error:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for RollbackOnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC4741](https://datatracker.ietf.org/doc/html/rfc4741)
/// and [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Validate {
    #[serde(alias = ":validate")]
    #[serde(rename = "urn:ietf:params:netconf:capability:validate:1.0")]
    V1_0,

    #[serde(alias = ":validate:1.1")]
    #[serde(rename = "urn:ietf:params:netconf:capability:validate:1.1")]
    V1_1,
}

impl CapabilityImpl for Validate {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":validate"),
            Self::V1_1 => Box::from(":validate:1.1"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:validate:1.0"),
            Self::V1_1 => Box::from("urn:ietf:params:netconf:capability:validate:1.1"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Validate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// `:startup` urn:ietf:params:netconf:capability:startup:1.0 [RFC6241]
/// See [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Startup {
    #[serde(alias = ":startup")]
    #[serde(rename = "urn:ietf:params:netconf:capability:startup:1.0")]
    V1_0,
}

impl CapabilityImpl for Startup {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":startup"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:startup:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Startup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// The `:url` capability is identified by the following capability string:
/// ```text
///   urn:ietf:params:netconf:capability:url:1.0?scheme={name,...}
/// ```
///
/// The `:url` capability URI MUST contain a "scheme" argument assigned a
/// comma-separated list of scheme names indicating which schemes the
/// NETCONF peer supports.  For example:
/// ```text
///   urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file
/// ```
/// See [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Url {
    V1_0(Vec<Box<str>>),
}

impl CapabilityImpl for Url {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0(_) => Box::from(":url"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0(_) => Box::from("urn:ietf:params:netconf:capability:url:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        match self {
            Self::V1_0(schemas) => {
                format!("{}?schema={}", self.identifier(), schemas.join(",")).into()
            }
        }
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

//:xpath	urn:ietf:params:netconf:capability:xpath:1.0	[RFC6241]
/// See [RFC6241](https://datatracker.ietf.org/doc/html/rfc6241)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Xpath {
    V1_0,
}

impl CapabilityImpl for Xpath {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":xpath"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:xpath:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Xpath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC5277](https://datatracker.ietf.org/doc/html/rfc5277)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Notification {
    V1_0,
}

impl CapabilityImpl for Notification {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":notification"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:notification:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Notification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC5277](https://datatracker.ietf.org/doc/html/rfc5277)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Interleave {
    V1_0,
}

impl CapabilityImpl for Interleave {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":interleave"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:interleave:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Interleave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC5717](https://datatracker.ietf.org/doc/html/rfc5717)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PartialLock {
    V1_0,
}

impl CapabilityImpl for PartialLock {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":partial-lock"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:partial-lock:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for PartialLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC6243](https://datatracker.ietf.org/doc/html/rfc6243)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WithDefaults {
    V1_0(String),
}

impl CapabilityImpl for WithDefaults {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0(_) => Box::from(":with-defaults"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0(_) => Box::from("urn:ietf:params:netconf:capability:with-defaults:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for WithDefaults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Base {
    V1_0,
    V1_1,
}

impl CapabilityImpl for Base {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":base"),
            Self::V1_1 => Box::from(":base:1.1"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:base:1.0"),
            Self::V1_1 => Box::from("urn:ietf:params:netconf:base:1.1"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Base {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC7758](https://datatracker.ietf.org/doc/html/rfc7758)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Time {
    V1_0,
}

impl CapabilityImpl for Time {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":time"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from("urn:ietf:params:netconf:capability:time:1.0"),
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC7950](https://datatracker.ietf.org/doc/html/rfc7950)
/// and [RFC8526](https://datatracker.ietf.org/doc/html/rfc8526)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum YangLibrary {
    V1_0 {
        revision: Box<str>,
        module_set_id: Box<str>,
    },
    V1_1 {
        revision: Box<str>,
        content_id: Box<str>,
    },
}

impl CapabilityImpl for YangLibrary {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 { .. } => Box::from(":yang-library"),
            Self::V1_1 { .. } => Box::from(":yang-library:1.1"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 { .. } => Box::from("urn:ietf:params:netconf:capability:yang-library:1.0"),
            Self::V1_1 { .. } => Box::from("urn:ietf:params:netconf:capability:yang-library:1.1"),
        }
    }

    fn urn(&self) -> Box<str> {
        match self {
            Self::V1_0 {
                revision,
                module_set_id,
            } => format!(
                "{}:?revision={revision}&module-set-id={module_set_id}",
                self.identifier()
            )
            .into(),
            Self::V1_1 {
                revision,
                content_id,
            } => format!(
                "{}:?revision={revision}&content-id={content_id}",
                self.identifier()
            )
            .into(),
        }
    }
}

impl std::fmt::Display for YangLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}

/// See [RFC8526](https://datatracker.ietf.org/doc/html/rfc8526)
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WithOperationalDefaults {
    V1_0,
}

impl CapabilityImpl for WithOperationalDefaults {
    fn shorthand(&self) -> Box<str> {
        match self {
            Self::V1_0 => Box::from(":with-operational-defaults"),
        }
    }

    fn identifier(&self) -> Box<str> {
        match self {
            Self::V1_0 => {
                Box::from("urn:ietf:params:netconf:capability:with-operational-defaults:1.0")
            }
        }
    }

    fn urn(&self) -> Box<str> {
        self.identifier()
    }
}

impl std::fmt::Display for WithOperationalDefaults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.shorthand())
    }
}
