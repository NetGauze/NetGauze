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

use crate::{
    decode_html_entities,
    xml_parser::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
};
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
        features: Box<[Box<str>]>,
        deviations: Box<[Box<str>]>,
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
                features,
                deviations,
            } => match (features.is_empty(), deviations.is_empty()) {
                (true, true) => format!("{ns}?module={module}&revision={revision}").into(),
                (true, false) => format!(
                    "{ns}?module={module}&revision={revision}&deviations={}",
                    deviations.join(",")
                )
                .into(),
                (false, true) => format!(
                    "{ns}?module={module}&revision={revision}&features={}",
                    features.join(",")
                )
                .into(),
                (false, false) => format!(
                    "{ns}?module={module}&revision={revision}&features={}&deviations={}",
                    features.join(","),
                    deviations.join(",")
                )
                .into(),
            },
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
            Self::YangModule { .. } => self.urn().fmt(f),
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

fn extract_params(query: &'_ str) -> HashMap<String, String> {
    decode_html_entities(query)
        .split("&")
        .filter_map(|pair| match pair.split_once('=') {
            Some((key, value)) => Some((key.into(), value.into())),
            _ => None,
        })
        .collect::<HashMap<String, String>>()
}

fn extract_module_revision(
    params: &HashMap<String, String>,
    urn: &'_ str,
) -> Result<(Box<str>, Box<str>, Box<[Box<str>]>, Box<[Box<str>]>), CapabilityParsingError> {
    let module: Box<str> = if let Some(module) = params.get("module") {
        module.as_str().into()
    } else {
        return Err(CapabilityParsingError::MissingParam {
            urn: urn.into(),
            param: "module".into(),
        });
    };
    let revision: Box<str> = if let Some(revision) = params.get("revision") {
        revision.as_str().into()
    } else {
        return Err(CapabilityParsingError::MissingParam {
            urn: urn.into(),
            param: "revision".into(),
        });
    };
    let features = if let Some(features) = params.get("features") {
        features
            .split(',')
            .map(|s| s.into())
            .collect::<Box<[Box<str>]>>()
    } else {
        Box::new([])
    };
    let deviations = if let Some(deviations) = params.get("deviations") {
        deviations
            .split(',')
            .map(|s| s.into())
            .collect::<Box<[Box<str>]>>()
    } else {
        Box::new([])
    };
    Ok((module, revision, features, deviations))
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
                let schemes: Vec<Box<str>> = query
                    .split('&')
                    .filter_map(|pair| match pair.split_once('=') {
                        Some(("scheme", values)) => {
                            if values.is_empty() {
                                return None;
                            }
                            Some(values.split(','))
                        }
                        _ => None,
                    })
                    .flatten()
                    .map(Box::from)
                    .collect();
                if schemes.is_empty() {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: "ietf:params:netconf:capability:url:1.0".into(),
                        param: "scheme".into(),
                    });
                }
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
                let revision: Box<str> = if let Some(revision) = params.get("revision") {
                    revision.as_str().into()
                } else {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: s.into(),
                        param: "revision".into(),
                    });
                };
                let module_set_id: Box<str> =
                    if let Some(module_set_id) = params.get("module-set-id") {
                        module_set_id.as_str().into()
                    } else {
                        return Err(CapabilityParsingError::MissingParam {
                            urn: s.into(),
                            param: "module-set-id".into(),
                        });
                    };
                Ok(Self::YangLibrary(YangLibrary::V1_0 {
                    revision,
                    module_set_id,
                }))
            }
            ("urn", None, "ietf:params:netconf:capability:yang-library:1.1", Some(query), None) => {
                let params = extract_params(query);
                let revision: Box<str> = if let Some(revision) = params.get("revision") {
                    revision.as_str().into()
                } else {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: s.into(),
                        param: "revision".into(),
                    });
                };
                let content_id: Box<str> = if let Some(content_id) = params.get("content-id") {
                    content_id.as_str().into()
                } else {
                    return Err(CapabilityParsingError::MissingParam {
                        urn: s.into(),
                        param: "content-id".into(),
                    });
                };
                Ok(Self::YangLibrary(YangLibrary::V1_1 {
                    revision,
                    content_id,
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
            ("urn", None, path, Some(query), None) => {
                let params = extract_params(query);
                if let Ok((module, revision, features, deviations)) =
                    extract_module_revision(&params, path)
                {
                    Ok(Self::YangModule {
                        ns: format!("urn:{path}").into(),
                        module,
                        revision,
                        features,
                        deviations,
                    })
                } else {
                    Ok(Self::Unknown(s.into()))
                }
            }
            ("http", Some(authority), ns, Some(query), None) => {
                let params = extract_params(query);
                if let Ok((module, revision, features, deviations)) =
                    extract_module_revision(&params, ns)
                {
                    Ok(Self::YangModule {
                        ns: format!("http://{authority}{ns}").into(),
                        module,
                        revision,
                        features,
                        deviations,
                    })
                } else {
                    Ok(Self::Unknown(s.into()))
                }
            }
            ("https", Some(authority), ns, Some(query), None) => {
                let params = extract_params(query);
                if let Ok((module, revision, features, deviations)) =
                    extract_module_revision(&params, ns)
                {
                    Ok(Self::YangModule {
                        ns: format!("https://{authority}{ns}").into(),
                        module,
                        revision,
                        features,
                        deviations,
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
        let body = decode_html_entities(&parser.tag_string()?);
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
                format!("{}?scheme={}", self.identifier(), schemas.join(",")).into()
            }
        }
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
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
        write!(f, "{}", self.urn())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_from_str;
    #[test]
    fn test_writable_running_capability() -> Result<(), ParsingError> {
        let input = "urn:ietf:params:netconf:capability:writable-running:1.0";
        let expected = Capability::WritableRunning(WritableRunning::V1_0);
        assert_eq!(expected.shorthand().as_ref(), ":writable-running");
        assert_eq!(
            expected.identifier().as_ref(),
            "urn:ietf:params:netconf:capability:writable-running:1.0"
        );
        assert_eq!(
            expected.urn().as_ref(),
            "urn:ietf:params:netconf:capability:writable-running:1.0"
        );
        test_from_str(input, &expected)
    }

    #[test]
    fn test_candidate_capability() -> Result<(), ParsingError> {
        let input = "urn:ietf:params:netconf:capability:candidate:1.0";
        let expected = Capability::Candidate(Candidate::V1_0);
        assert_eq!(expected.shorthand().as_ref(), ":candidate");
        assert_eq!(
            expected.identifier().as_ref(),
            "urn:ietf:params:netconf:capability:candidate:1.0"
        );
        assert_eq!(
            expected.urn().as_ref(),
            "urn:ietf:params:netconf:capability:candidate:1.0"
        );
        test_from_str(input, &expected)
    }

    #[test]
    fn test_url_capability_single_scheme() -> Result<(), ParsingError> {
        let input = "urn:ietf:params:netconf:capability:url:1.0?scheme=http";
        let expected = Capability::Url(Url::V1_0(vec!["http".into()]));
        test_from_str(input, &expected)
    }

    #[test]
    fn test_url_capability_multiple_schemes() -> Result<(), ParsingError> {
        let input = "urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file";
        let expected = Capability::Url(Url::V1_0(vec!["http".into(), "ftp".into(), "file".into()]));
        test_from_str(input, &expected)
    }

    #[test]
    fn test_url_capability_empty_schemes() {
        let input = "urn:ietf:params:netconf:capability:url:1.0?scheme=";
        let parsed = Capability::from_str(input.trim());
        assert!(parsed.is_err());
    }

    #[test]
    fn test_url_capability_no_query() -> Result<(), ParsingError> {
        let input = "urn:ietf:params:netconf:capability:url:1.0";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_urn() -> Result<(), ParsingError> {
        let input = "urn:example:yang:example-module?module=example-module&revision=2022-12-22";
        let expected = Capability::YangModule {
            ns: "urn:example:yang:example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new([]),
            deviations: Box::new([]),
        };
        test_from_str(input, &expected)
    }

    /// YANG Module must have both revision and module name, otherwise it's not
    /// valid
    #[test]
    fn test_yang_urn_without_revision() -> Result<(), ParsingError> {
        let input = "urn:example:yang:example-module?module=example-module";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }

    /// YANG Module must have both revision and module name, otherwise it's not
    /// valid
    #[test]
    fn test_yang_urn_without_module() -> Result<(), ParsingError> {
        let input = "urn:example:yang:example-module?revision=2022-12-22";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }

    /// YANG Module must have both revision and module name, otherwise it's not
    /// valid
    #[test]
    fn test_yang_urn_plain() -> Result<(), ParsingError> {
        let input = "urn:example:yang:example-module";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_urn_with_features() -> Result<(), ParsingError> {
        let input = "urn:example:yang:example-module?module=example-module&revision=2022-12-22&features=feature1,feature2";
        let expected = Capability::YangModule {
            ns: "urn:example:yang:example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new(["feature1".into(), "feature2".into()]),
            deviations: Box::new([]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_urn_with_deviations() -> Result<(), ParsingError> {
        let input = "urn:example:yang:example-module?module=example-module&revision=2022-12-22&deviations=deviation1,deviation2";
        let expected = Capability::YangModule {
            ns: "urn:example:yang:example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new([]),
            deviations: Box::new(["deviation1".into(), "deviation2".into()]),
        };
        test_from_str(input, &expected)
    }
    #[test]
    fn test_yang_urn_with_features_and_deviations() -> Result<(), ParsingError> {
        let input = "urn:example:yang:example-module?module=example-module&revision=2022-12-22&features=feature1,feature2&deviations=deviation1,deviation2";
        let expected = Capability::YangModule {
            ns: "urn:example:yang:example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new(["feature1".into(), "feature2".into()]),
            deviations: Box::new(["deviation1".into(), "deviation2".into()]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_http_urn() -> Result<(), ParsingError> {
        let input =
            "http://example.com/yang/example-module?module=example-module&revision=2022-12-22";
        let expected = Capability::YangModule {
            ns: "http://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new([]),
            deviations: Box::new([]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_https_urn() -> Result<(), ParsingError> {
        let input =
            "https://example.com/yang/example-module?module=example-module&revision=2022-12-22";
        let expected = Capability::YangModule {
            ns: "https://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new([]),
            deviations: Box::new([]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_http_urn_with_features() -> Result<(), ParsingError> {
        let input = "http://example.com/yang/example-module?module=example-module&revision=2022-12-22&features=feature1,feature2";
        let expected = Capability::YangModule {
            ns: "http://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new(["feature1".into(), "feature2".into()]),
            deviations: Box::new([]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_https_urn_with_features() -> Result<(), ParsingError> {
        let input = "https://example.com/yang/example-module?module=example-module&revision=2022-12-22&features=feature1,feature2";
        let expected = Capability::YangModule {
            ns: "https://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new(["feature1".into(), "feature2".into()]),
            deviations: Box::new([]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_http_urn_with_deviations() -> Result<(), ParsingError> {
        let input = "http://example.com/yang/example-module?module=example-module&revision=2022-12-22&deviations=deviation1,deviation2";
        let expected = Capability::YangModule {
            ns: "http://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new([]),
            deviations: Box::new(["deviation1".into(), "deviation2".into()]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_https_urn_with_deviations() -> Result<(), ParsingError> {
        let input = "https://example.com/yang/example-module?module=example-module&revision=2022-12-22&deviations=deviation1,deviation2";
        let expected = Capability::YangModule {
            ns: "https://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new([]),
            deviations: Box::new(["deviation1".into(), "deviation2".into()]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_http_urn_with_features_and_deviations() -> Result<(), ParsingError> {
        let input = "http://example.com/yang/example-module?module=example-module&revision=2022-12-22&features=feature1,feature2&deviations=deviation1,deviation2";
        let expected = Capability::YangModule {
            ns: "http://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new(["feature1".into(), "feature2".into()]),
            deviations: Box::new(["deviation1".into(), "deviation2".into()]),
        };
        test_from_str(input, &expected)
    }

    #[test]
    fn test_yang_https_urn_with_features_and_deviations() -> Result<(), ParsingError> {
        let input = "https://example.com/yang/example-module?module=example-module&revision=2022-12-22&features=feature1,feature2&deviations=deviation1,deviation2";
        let expected = Capability::YangModule {
            ns: "https://example.com/yang/example-module".into(),
            module: "example-module".into(),
            revision: "2022-12-22".into(),
            features: Box::new(["feature1".into(), "feature2".into()]),
            deviations: Box::new(["deviation1".into(), "deviation2".into()]),
        };
        test_from_str(input, &expected)
    }

    /// HTTP YANG Module must have both revision and module name, otherwise it's
    /// not valid
    #[test]
    fn test_yang_http_urn_without_revision() -> Result<(), ParsingError> {
        let input = "http://example.com/yang/example-module?module=example-module";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }

    /// HTTPS YANG Module must have both revision and module name, otherwise
    /// it's not valid
    #[test]
    fn test_yang_https_urn_without_revision() -> Result<(), ParsingError> {
        let input = "https://example.com/yang/example-module?module=example-module";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }

    /// HTTP YANG Module must have both revision and module name, otherwise it's
    /// not valid
    #[test]
    fn test_yang_http_urn_without_module() -> Result<(), ParsingError> {
        let input = "http://example.com/yang/example-module?revision=2022-12-22";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }

    /// HTTPS YANG Module must have both revision and module name, otherwise
    /// it's not valid
    #[test]
    fn test_yang_https_urn_without_module() -> Result<(), ParsingError> {
        let input = "https://example.com/yang/example-module?revision=2022-12-22";
        let expected = Capability::Unknown(input.into());
        test_from_str(input, &expected)
    }
}
