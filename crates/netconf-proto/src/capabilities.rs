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
    xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
    NETCONF_NS_STR,
};
use quick_xml::events::{BytesText, Event};
use serde::{Deserialize, Serialize};
use std::{fmt, io, str::FromStr};

const CAP_WRITABLE: &str = "urn:ietf:params:netconf:capability:writable-running:1.0";
const CAP_CANDIDATE: &str = "urn:ietf:params:netconf:capability:candidate:1.0";
const CAP_CONFIRMED_COMMIT_1_0: &str = "urn:ietf:params:netconf:capability:confirmed-commit:1.0";
const CAP_CONFIRMED_COMMIT_1_1: &str = "urn:ietf:params:netconf:capability:confirmed-commit:1.1";
const CAP_ROLLBACK_ON_ERROR: &str = "urn:ietf:params:netconf:capability:rollback-on-error:1.0";
const CAP_VALIDATE_1_0: &str = "urn:ietf:params:netconf:capability:validate:1.0";
const CAP_VALIDATE_1_1: &str = "urn:ietf:params:netconf:capability:validate:1.1";
const CAP_STARTUP: &str = "urn:ietf:params:netconf:capability:startup:1.0";
const CAP_URL: &str = "urn:ietf:params:netconf:capability:url:1.0";
const CAP_XPATH: &str = "urn:ietf:params:netconf:capability:xpath:1.0";
const CAP_NOTIFICATION: &str = "urn:ietf:params:netconf:capability:notification:1.0";
const CAP_INTERLEAVE: &str = "urn:ietf:params:netconf:capability:interleave:1.0";
const CAP_PARTIAL_LOCK: &str = "urn:ietf:params:netconf:capability:partial-lock:1.0";
const CAP_WITH_DEFAULTS: &str = "urn:ietf:params:netconf:capability:with-defaults:1.0";
const CAP_BASE_1_0: &str = "urn:ietf:params:netconf:base:1.0";
const CAP_BASE_1_1: &str = "urn:ietf:params:netconf:base:1.1";
const CAP_TIME: &str = "urn:ietf:params:netconf:capability:time:1.0";
const CAP_YANG_LIBRARY_V_1_0: &str = "urn:ietf:params:netconf:capability:yang-library:1.0";
const CAP_YANG_LIBRARY_V_1_1: &str = "urn:ietf:params:netconf:capability:yang-library:1.1";
const CAP_WITH_OPERATIONAL_DEFAULTS: &str =
    "urn:ietf:params:netconf:capability:with-operational-defaults:1.0";

/// NETCONF capabilities representation as defined in
/// [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241.html)
///
/// NetconfBase, YANG Library, and YANG capabilities are handled differently
/// because they carry special meaning that's important to have fast access to
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display)]
pub enum Capability {
    #[strum(serialize = "{0}")]
    NetconfBase(NetconfVersion),

    #[strum(serialize = "{0}")]
    YangLibrary(YangLibrary),

    #[strum(serialize = "{0}")]
    Standard(StandardCapability),

    #[strum(serialize = "{0}")]
    Yang(YangCapability),

    #[strum(serialize = "{0}")]
    Custom(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display)]
pub enum CapabilityParsingError {
    #[strum(to_string = "URL schema `{0}` for :url capability is not recognized")]
    InvalidUrlScheme(String),

    #[strum(to_string = "URL schema for :url capability is not defined")]
    UrlSchemeIsNotDefined,

    #[strum(to_string = "URN schema `{0}` YANG capability is not recognized")]
    InvalidYangUrnSchema(String),

    #[strum(to_string = "Invalid YANG Library capability: `{0}`")]
    InvalidYangLibrary(String),
}

impl std::error::Error for CapabilityParsingError {}

impl From<CapabilityParsingError> for ParsingError {
    fn from(value: CapabilityParsingError) -> Self {
        Self::InvalidValue(value.to_string())
    }
}

impl FromStr for Capability {
    type Err = CapabilityParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            CAP_WRITABLE => Ok(Capability::Standard(StandardCapability::WritableRunning)),
            CAP_CANDIDATE => Ok(Capability::Standard(StandardCapability::Candidate)),
            CAP_CONFIRMED_COMMIT_1_0 => Ok(Capability::Standard(
                StandardCapability::ConfirmedCommitV1_0,
            )),
            CAP_CONFIRMED_COMMIT_1_1 => Ok(Capability::Standard(
                StandardCapability::ConfirmedCommitV1_1,
            )),
            CAP_ROLLBACK_ON_ERROR => Ok(Capability::Standard(StandardCapability::RollbackOnError)),
            CAP_VALIDATE_1_0 => Ok(Capability::Standard(StandardCapability::ValidateV1_0)),
            CAP_VALIDATE_1_1 => Ok(Capability::Standard(StandardCapability::ValidateV1_1)),
            CAP_STARTUP => Ok(Capability::Standard(StandardCapability::Startup)),
            CAP_XPATH => Ok(Capability::Standard(StandardCapability::Xpath)),
            CAP_NOTIFICATION => Ok(Capability::Standard(StandardCapability::Notification)),
            CAP_INTERLEAVE => Ok(Capability::Standard(StandardCapability::Interleave)),
            CAP_PARTIAL_LOCK => Ok(Capability::Standard(StandardCapability::PartialLock)),
            CAP_WITH_DEFAULTS => Ok(Capability::Standard(StandardCapability::WithDefaults)),
            CAP_BASE_1_0 => Ok(Capability::NetconfBase(NetconfVersion::V1_0)),
            CAP_BASE_1_1 => Ok(Capability::NetconfBase(NetconfVersion::V1_1)),
            CAP_TIME => Ok(Capability::Standard(StandardCapability::Time)),
            CAP_WITH_OPERATIONAL_DEFAULTS => Ok(Capability::Standard(
                StandardCapability::WithOperationalDefaults,
            )),
            cap if s.starts_with(CAP_URL) => {
                let scheme_str = if let Some(scheme_str) = cap
                    .strip_prefix(CAP_URL)
                    .and_then(|x| x.strip_prefix("?scheme="))
                {
                    scheme_str
                } else {
                    return Err(CapabilityParsingError::UrlSchemeIsNotDefined);
                };
                let scheme = match scheme_str {
                    "http" => UrlScheme::Http,
                    "https" => UrlScheme::Https,
                    "ftp" => UrlScheme::Ftp,
                    "sftp" => UrlScheme::Sftp,
                    "file" => UrlScheme::File,
                    "scp" => UrlScheme::Scp,
                    _ => {
                        return Err(CapabilityParsingError::InvalidUrlScheme(
                            scheme_str.to_string(),
                        ));
                    }
                };
                Ok(Capability::Standard(StandardCapability::Url(scheme)))
            }
            cap if s.starts_with(CAP_YANG_LIBRARY_V_1_0) => {
                let params = if let Some(params) = s
                    .strip_prefix(CAP_YANG_LIBRARY_V_1_0)
                    .and_then(|x| x.strip_prefix("?"))
                {
                    params
                } else {
                    return Err(CapabilityParsingError::InvalidYangLibrary(cap.to_string()));
                };
                let mut revision = None;
                let mut module_set_id = None;
                for param in params.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key {
                            "revision" => {
                                revision =
                                    Some(chrono::NaiveDate::from_str(value).map_err(|err| {
                                        CapabilityParsingError::InvalidYangUrnSchema(
                                            err.to_string(),
                                        )
                                    })?);
                            }
                            "module-set-id" => {
                                module_set_id = Some(value.into());
                            }
                            _ => {
                                return Err(CapabilityParsingError::InvalidYangLibrary(
                                    cap.to_string(),
                                ));
                            }
                        }
                    }
                }
                let revision = revision
                    .ok_or_else(|| CapabilityParsingError::InvalidYangLibrary(cap.to_string()))?;
                let module_set_id = module_set_id
                    .ok_or_else(|| CapabilityParsingError::InvalidYangLibrary(cap.to_string()))?;
                Ok(Capability::YangLibrary(YangLibrary::V1_0 {
                    revision,
                    module_set_id,
                }))
            }
            cap if s.starts_with(CAP_YANG_LIBRARY_V_1_1) => {
                let params = if let Some(params) = s
                    .strip_prefix(CAP_YANG_LIBRARY_V_1_1)
                    .and_then(|x| x.strip_prefix("?"))
                {
                    params
                } else {
                    return Err(CapabilityParsingError::InvalidYangLibrary(cap.to_string()));
                };
                let mut revision = None;
                let mut content_id = None;
                for param in params.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key {
                            "revision" => {
                                revision =
                                    Some(chrono::NaiveDate::from_str(value).map_err(|err| {
                                        CapabilityParsingError::InvalidYangUrnSchema(
                                            err.to_string(),
                                        )
                                    })?);
                            }
                            "content-id" => {
                                content_id = Some(value.into());
                            }
                            _ => {
                                return Err(CapabilityParsingError::InvalidYangLibrary(
                                    cap.to_string(),
                                ));
                            }
                        }
                    }
                }
                let revision = revision
                    .ok_or_else(|| CapabilityParsingError::InvalidYangLibrary(cap.to_string()))?;
                let content_id = content_id
                    .ok_or_else(|| CapabilityParsingError::InvalidYangLibrary(cap.to_string()))?;
                Ok(Capability::YangLibrary(YangLibrary::V1_1 {
                    revision,
                    content_id,
                }))
            }
            cap if cap.starts_with("urn")
                || cap.starts_with("http://")
                || cap.starts_with("https://") =>
            {
                let (urn, params) = if let Some((urn, params)) = cap.split_once('?') {
                    (urn, params)
                } else {
                    return Ok(Capability::Custom(s.into()));
                };

                let mut module_name = None;
                let mut revision = None;
                let mut features = Vec::new();
                let mut deviations = Vec::new();

                for param in params.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key {
                            "module" => module_name = Some(value.into()),
                            "revision" => {
                                revision =
                                    Some(chrono::NaiveDate::from_str(value).map_err(|err| {
                                        CapabilityParsingError::InvalidYangUrnSchema(
                                            err.to_string(),
                                        )
                                    })?)
                            }
                            "features" => {
                                features = value.split(',').map(|f| f.into()).collect();
                            }
                            "deviations" => {
                                deviations = value.split(',').map(|d| d.into()).collect();
                            }
                            _ => {
                                return Ok(Capability::Custom(s.into()));
                            }
                        }
                    }
                }

                let module_name: Box<str> = module_name
                    .ok_or_else(|| CapabilityParsingError::InvalidYangUrnSchema(cap.to_string()))?;
                Ok(Capability::Yang(YangCapability::new(
                    urn.into(),
                    module_name,
                    revision,
                    features.into_boxed_slice(),
                    deviations.into_boxed_slice(),
                )))
            }
            _ => Ok(Capability::Custom(s.into())),
        }
    }
}

impl XmlDeserialize<Capability> for Capability {
    fn xml_deserialize(
        parser: &mut XmlParser<impl io::BufRead>,
    ) -> Result<Capability, ParsingError> {
        parser.open(Some(NETCONF_NS_STR), "capability")?;
        let body = parser.tag_string()?;
        let cap = Capability::from_str(&body)?;
        parser.close()?;
        Ok(cap)
    }
}

impl XmlSerialize for Capability {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let start = writer.create_nc_element("capability");
        let end = start.to_end();
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(&self.to_string())))?;
        writer.write_event(Event::End(end))?;
        Ok(())
    }
}

/// NETCONF protocol version
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display,
)]
pub enum NetconfVersion {
    #[strum(serialize = "urn:ietf:params:netconf:base:1.0")]
    V1_0,
    #[strum(serialize = "urn:ietf:params:netconf:base:1.1")]
    V1_1,
}

/// NETCONF protocol version
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display)]
pub enum YangLibrary {
    #[strum(
        serialize = "urn:ietf:params:netconf:capability:yang-library:1.0?revision={revision}&module-set-id={module_set_id}"
    )]
    V1_0 {
        revision: chrono::NaiveDate,
        module_set_id: Box<str>,
    },

    #[strum(
        serialize = "urn:ietf:params:netconf:capability:yang-library:1.1?revision={revision}&content-id={content_id}"
    )]
    V1_1 {
        revision: chrono::NaiveDate,
        content_id: Box<str>,
    },
}

/// Standard NETCONF capabilities as defined in
/// [IANA Network Configuration Protocol (NETCONF) Capability URNs](https://www.iana.org/assignments/netconf-capability-urns/netconf-capability-urns.xhtml)
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display,
)]
pub enum StandardCapability {
    #[strum(serialize = "urn:ietf:params:netconf:capability:writable-running:1.0")]
    WritableRunning,

    #[strum(serialize = "urn:ietf:params:netconf:capability:candidate:1.0")]
    Candidate,

    #[strum(serialize = "urn:ietf:params:netconf:capability:confirmed-commit:1.0")]
    ConfirmedCommitV1_0,

    #[strum(serialize = "urn:ietf:params:netconf:capability:confirmed-commit:1.1")]
    ConfirmedCommitV1_1,

    #[strum(serialize = "urn:ietf:params:netconf:capability:rollback-on-error:1.0")]
    RollbackOnError,

    #[strum(serialize = "urn:ietf:params:netconf:capability:validate:1.0")]
    ValidateV1_0,

    #[strum(serialize = "urn:ietf:params:netconf:capability:validate:1.1")]
    ValidateV1_1,

    #[strum(serialize = "urn:ietf:params:netconf:capability:startup:1.0")]
    Startup,

    #[strum(
        serialize = "urn:ietf:params:netconf:capability:url:1.0",
        to_string = "urn:ietf:params:netconf:capability:url:1.0?scheme={0}"
    )]
    Url(UrlScheme),

    #[strum(serialize = "urn:ietf:params:netconf:capability:xpath:1.0")]
    Xpath,

    #[strum(serialize = "urn:ietf:params:netconf:capability:notification:1.0")]
    Notification,

    #[strum(serialize = "urn:ietf:params:netconf:capability:interleave:1.0")]
    Interleave,

    #[strum(serialize = "urn:ietf:params:netconf:capability:partial-lock:1.0")]
    PartialLock,

    #[strum(serialize = "urn:ietf:params:netconf:capability:with-defaults:1.0")]
    WithDefaults,

    #[strum(serialize = "urn:ietf:params:netconf:capability:time:1.0")]
    Time,

    #[strum(serialize = "urn:ietf:params:netconf:capability:with-operational-defaults:1.0")]
    WithOperationalDefaults,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display,
)]
pub enum UrlScheme {
    #[strum(serialize = "http")]
    Http,

    #[strum(serialize = "https")]
    Https,

    #[strum(serialize = "ftp")]
    Ftp,

    #[strum(serialize = "sftp")]
    Sftp,

    #[strum(serialize = "file")]
    File,

    #[strum(serialize = "scp")]
    Scp,
}

/// YANG module capability with revision and features
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct YangCapability {
    urn: Box<str>,
    module_name: Box<str>,
    revision: Option<chrono::NaiveDate>,
    features: Box<[Box<str>]>,
    deviations: Box<[Box<str>]>,
}

impl YangCapability {
    pub const fn new(
        urn: Box<str>,
        module_name: Box<str>,
        revision: Option<chrono::NaiveDate>,
        features: Box<[Box<str>]>,
        deviations: Box<[Box<str>]>,
    ) -> Self {
        Self {
            urn,
            module_name,
            revision,
            features,
            deviations,
        }
    }

    pub const fn module_name(&self) -> &'_ str {
        &self.module_name
    }

    pub const fn revision(&self) -> Option<chrono::NaiveDate> {
        self.revision
    }

    pub fn features(&self) -> &[Box<str>] {
        &self.features
    }

    pub fn deviations(&self) -> &[Box<str>] {
        &self.deviations
    }
}

impl fmt::Display for YangCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.urn)?;

        let mut params = Vec::with_capacity(self.features.len() + self.deviations.len() + 2);

        params.push(format!("module={}", self.module_name));

        if let Some(ref rev) = self.revision {
            params.push(format!("revision={rev}"));
        }

        if !self.features.is_empty() {
            params.push(format!("features={}", self.features.join(",")));
        }

        if !self.deviations.is_empty() {
            params.push(format!("deviations={}", self.deviations.join(",")));
        }

        if !params.is_empty() {
            write!(f, "?{}", params.join("&"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_xml_value;
    use std::{str::FromStr, string::ToString};

    #[test]
    fn test_netconf_base_capability() -> Result<(), ParsingError> {
        let base_1_0_str = "urn:ietf:params:netconf:base:1.0";
        let base_1_1_str = "urn:ietf:params:netconf:base:1.1";
        let cap_base_1_0_str = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">urn:ietf:params:netconf:base:1.0</capability>"#;
        let cap_base_1_1_str = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">urn:ietf:params:netconf:base:1.1</capability>"#;

        let base_1_0 = NetconfVersion::V1_0;
        let base_1_1 = NetconfVersion::V1_1;
        let cap_base_1_0 = Capability::NetconfBase(base_1_0);
        let cap_base_1_1 = Capability::NetconfBase(base_1_1);

        assert_eq!(base_1_0.to_string(), base_1_0_str);
        assert_eq!(base_1_1.to_string(), base_1_1_str);

        assert_eq!(cap_base_1_0.to_string(), base_1_0_str);
        assert_eq!(cap_base_1_1.to_string(), base_1_1_str);
        assert_eq!(Capability::from_str(base_1_0_str), Ok(cap_base_1_0.clone()));
        assert_eq!(Capability::from_str(base_1_1_str), Ok(cap_base_1_1.clone()));
        test_xml_value(cap_base_1_0_str, cap_base_1_0)?;
        test_xml_value(cap_base_1_1_str, cap_base_1_1)?;
        Ok(())
    }

    #[test]
    fn test_writeable_running() -> Result<(), ParsingError> {
        let writeable_running_str = "urn:ietf:params:netconf:capability:writable-running:1.0";
        let cap_writeable_running_str = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">urn:ietf:params:netconf:capability:writable-running:1.0</capability>"#;

        let writable_running = StandardCapability::WritableRunning;
        let cap_writable_running = Capability::Standard(writable_running);

        assert_eq!(writable_running.to_string(), writeable_running_str);
        assert_eq!(cap_writable_running.to_string(), writeable_running_str);
        assert_eq!(
            Capability::from_str(writeable_running_str),
            Ok(cap_writable_running.clone())
        );
        test_xml_value(cap_writeable_running_str, cap_writable_running)?;
        Ok(())
    }

    #[test]
    fn test_yang_urn_with_features_and_deviations() -> Result<(), ParsingError> {
        let input = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces&amp;revision=2018-02-20&amp;features=arbitrary-names,if-mib&amp;deviations=example-interfaces-deviations</capability>"#;
        let expected = Capability::Yang(YangCapability::new(
            "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            "ietf-interfaces".into(),
            Some(chrono::NaiveDate::from_str("2018-02-20").unwrap()),
            Box::new(["arbitrary-names".into(), "if-mib".into()]),
            Box::new(["example-interfaces-deviations".into()]),
        ));

        test_xml_value(input, expected)?;
        Ok(())
    }

    #[test]
    fn test_yang_https_urn_with_features_and_deviations() -> Result<(), ParsingError> {
        let input = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">http://openconfig.net/yang/alarms?module=openconfig-alarms&amp;revision=2018-01-16&amp;deviations=example-openconfig-alarms-deviation</capability>"#;
        let expected = Capability::Yang(YangCapability::new(
            "http://openconfig.net/yang/alarms".into(),
            "openconfig-alarms".into(),
            Some(chrono::NaiveDate::from_str("2018-01-16").unwrap()),
            Box::new([]),
            Box::new(["example-openconfig-alarms-deviation".into()]),
        ));

        test_xml_value(input, expected)?;
        Ok(())
    }

    #[test]
    fn test_yang_library_1_0() -> Result<(), ParsingError> {
        let input = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">urn:ietf:params:netconf:capability:yang-library:1.0?revision=2016-06-21&amp;module-set-id=12345</capability>"#;
        let expected = Capability::YangLibrary(YangLibrary::V1_0 {
            revision: chrono::NaiveDate::from_str("2016-06-21").unwrap(),
            module_set_id: "12345".into(),
        });

        test_xml_value(input, expected)?;
        Ok(())
    }

    #[test]
    fn test_yang_library_1_1() -> Result<(), ParsingError> {
        let input = r#"<capability xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&amp;content-id=12345</capability>"#;
        let expected = Capability::YangLibrary(YangLibrary::V1_1 {
            revision: chrono::NaiveDate::from_str("2019-01-04").unwrap(),
            content_id: "12345".into(),
        });

        test_xml_value(input, expected)?;
        Ok(())
    }
}
