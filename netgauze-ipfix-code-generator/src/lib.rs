// Copyright (C) 2022-present The NetGauze Authors.
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

pub mod xml_parser;

pub const DEFAULT_ENUM_DERIVE: &str = "#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]\n";
pub const DEFAULT_STRUCT_DERIVE: &str =
    "#[derive(Copy, Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]\n";

/// Represent Information Element as read form a registry
#[derive(Debug, Clone)]
pub struct InformationElement {
    pub name: String,
    pub data_type: String,
    pub group: Option<String>,
    pub data_type_semantics: Option<String>,
    pub element_id: u16,
    pub applicability: Option<String>,
    pub status: String,
    pub description: String,
    pub revision: u32,
    pub date: String,
    pub references: Option<String>,
    pub xrefs: Vec<Xref>,
    pub units: Option<String>,
    pub range: Option<String>,
}

/// Describes simple registries such as
/// [IPFIX Information Element Data Types](https://www.iana.org/assignments/ipfix/ipfix.xml#ipfix-information-element-data-types)
/// And [IPFIX Information Element Semantics](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-element-semantics)
#[derive(Debug)]
pub struct SimpleRegistry {
    pub value: u8,
    pub description: String,
    pub comments: Option<String>,
    pub xref: Vec<Xref>,
}

/// Describes `<xref>` tag to link to a resource
#[derive(Debug, Clone)]
pub struct Xref {
    pub ty: String,
    pub data: String,
}

/// Convert [Xref] to markdown link
///
///```rust
/// use netgauze_ipfix_code_generator::{generate_xref_link, Xref};
///
/// let rfc = Xref {
///     ty: "rfc".to_string(),
///     data: "rfc123".to_string(),
/// };
/// let rfc_errata = Xref {
///     ty: "rfc-errata".to_string(),
///     data: "1234".to_string(),
/// };
/// let other = Xref {
///     ty: "person".to_string(),
///     data: "John Smith".to_string(),
/// };
/// assert_eq!(
///     generate_xref_link(&rfc),
///     Some("[RFC123](https://datatracker.ietf.org/doc/html/rfc123)".to_string())
/// );
/// assert_eq!(
///     generate_xref_link(&rfc_errata),
///     Some(
///         "[RFC Errata 1234](https://www.rfc-editor.org/errata_search.php?eid=1234)".to_string()
///     )
/// );
/// assert_eq!(generate_xref_link(&other), None)
/// ```
pub fn generate_xref_link(xref: &Xref) -> Option<String> {
    match xref.ty.as_str() {
        "rfc" => Some(format!(
            "[{}](https://datatracker.ietf.org/doc/html/{})",
            xref.data.to_uppercase(),
            xref.data,
        )),
        "rfc-errata" => Some(format!(
            "[RFC Errata {}](https://www.rfc-editor.org/errata_search.php?eid={})",
            xref.data, xref.data,
        )),
        "person" => None,
        other => todo!("Handle xref of type {}", other),
    }
}

/// Generate InformationElementDataType
pub fn generate_ie_data_type(data_types: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(DEFAULT_ENUM_DERIVE);
    ret.push_str("pub enum InformationElementDataType {\n");
    for x in data_types.iter() {
        for xref in x.xref.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("  /// {}\n", xref).as_str());
        }
        ret.push_str(format!("  {} = {},\n", x.description, x.value).as_str());
    }
    ret.push_str("}\n");
    ret
}

/// Generate code for `InformationElementUnits`
pub fn generate_ie_units(entries: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(DEFAULT_ENUM_DERIVE);
    ret.push_str("pub enum InformationElementUnits {\n");
    for entry in entries.iter() {
        ret.push('\n');
        if let Some(comments) = entry.comments.as_ref() {
            ret.push_str(format!("  /// {}\n", comments).as_str());
            ret.push_str("  ///\n");
        }
        for xref in entry.xref.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("  /// {}\n", xref).as_str());
        }
        // Note: this an special exception, since `4-octet words` is not valid rust id
        let description = if entry.description == "4-octet words" {
            "fourOctetWords"
        } else {
            &entry.description
        };
        ret.push_str(format!("  {} = {},\n", description, entry.value).as_str());
    }
    ret.push_str("}\n");
    ret
}

/// Generate rust code for `InformationElementSemantics`
pub fn generate_ie_semantics(data_types: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(DEFAULT_ENUM_DERIVE);
    ret.push_str("pub enum InformationElementSemantics {\n");
    for x in data_types.iter() {
        ret.push('\n');
        for xref in x.xref.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("  /// {}\n", xref).as_str());
        }
        ret.push_str(format!("  {} = {},\n", x.description, x.value).as_str());
    }
    ret.push_str("}\n");
    ret
}

fn generate_impl_ie_template_for_ie(name_prefix: &String, ie: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    ret.push_str(
        format!(
            "impl super::InformationElementTemplate for {}InformationElementId {{\n",
            name_prefix
        )
        .as_str(),
    );
    ret.push_str("    fn semantics(&self) -> Option<super::InformationElementSemantics> {\n");
    ret.push_str("        match self {\n");
    for ie in ie {
        ret.push_str(
            format!(
                "            Self::{} => {},\n",
                ie.name,
                ie.data_type_semantics
                    .as_ref()
                    .map(|x| format!("Some(super::InformationElementSemantics::{})", x))
                    .unwrap_or_else(|| "None".to_string())
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn data_type(&self) -> super::InformationElementDataType {\n");
    ret.push_str("        match self {\n");
    for ie in ie {
        ret.push_str(
            format!(
                "            Self::{} => super::InformationElementDataType::{},\n",
                ie.name, ie.data_type
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn units(&self) -> Option<super::InformationElementUnits> {\n");
    ret.push_str("        match self {\n");
    for ie in ie {
        ret.push_str(
            format!(
                "            Self::{} => {},\n",
                ie.name,
                ie.units
                    .as_ref()
                    .map(|x| format!("Some(super::InformationElementUnits::{})", x))
                    .unwrap_or_else(|| "None".to_string())
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn value_range(&self) -> Option<std::ops::Range<u64>> {\n");
    ret.push_str("        match self {\n");
    for ie in ie {
        ret.push_str(
            format!(
                "            Self::{} => {},\n",
                ie.name,
                ie.range
                    .as_ref()
                    .map(|x| {
                        let mut parts = vec![];
                        for part in x.split('-') {
                            parts.push(part)
                        }
                        format!(
                            "Some(std::ops::Range{{start: {}, end: {} + 1}})",
                            parts.first().unwrap(),
                            parts.get(1).unwrap()
                        )
                    })
                    .unwrap_or_else(|| "None".to_string())
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("}\n");
    ret
}

fn generate_from_for_ie(name_prefix: &String) -> String {
    let mut ret = String::new();
    ret.push_str(DEFAULT_STRUCT_DERIVE);
    ret.push_str(
        format!(
            "pub struct {}UndefinedInformationElementId(pub u16);\n",
            name_prefix
        )
        .as_str(),
    );

    ret.push_str(
        format!(
            "impl From<{}InformationElementId> for u16 {{\n",
            name_prefix
        )
        .as_str(),
    );
    ret.push_str(
        format!(
            "    fn from(value: {}InformationElementId) -> Self {{\n",
            name_prefix
        )
        .as_str(),
    );
    ret.push_str("        value as u16\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str(
        format!(
            "impl TryFrom<u16> for {}InformationElementId {{\n",
            name_prefix
        )
        .as_str(),
    );
    ret.push_str(
        format!(
            "    type Error = {}UndefinedInformationElementId;\n\n",
            name_prefix
        )
        .as_str(),
    );
    ret.push_str("    fn try_from(value: u16) -> Result<Self, Self::Error> {\n");
    ret.push_str("       match Self::from_repr(value) {\n");
    ret.push_str("           Some(val) => Ok(val),\n");
    ret.push_str(
        format!(
            "           None => Err({}UndefinedInformationElementId(value)),\n",
            name_prefix
        )
        .as_str(),
    );
    ret.push_str("       }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

/// Generate an enum of InformationElementIDs.
/// The name of the enum includes a `name_prefix` to distinguish between
/// different names spaces; i.e. IANA vs enterprise space.
pub fn generate_information_element_ids(
    name_prefix: String,
    ie: &Vec<InformationElement>,
) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u16)]\n");
    ret.push_str(
        "#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]\n",
    );
    ret.push_str(format!("pub enum {}InformationElementId {{\n", name_prefix).as_str());
    for ie in ie {
        for line in ie.description.split('\n') {
            ret.push_str(format!("    /// {}\n", line.trim()).as_str());
        }
        if !ie.description.is_empty() && !ie.xrefs.is_empty() {
            ret.push_str("    ///\n");
        }
        for xref in ie.xrefs.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("    /// Reference: {}\n", xref).as_str());
        }
        ret.push_str(format!("    {} = {},\n", ie.name, ie.element_id).as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str(generate_impl_ie_template_for_ie(&name_prefix, ie).as_str());
    ret.push_str(generate_from_for_ie(&name_prefix).as_str());

    ret
}

/// Information Elements can be either current or deprecated, no IANA registry
/// for it at the moment, it's hard coded here.
pub fn generate_ie_status() -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(
        "#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]\n",
    );
    ret.push_str("pub enum InformationElementStatus {\n");
    ret.push_str("    current = 0,\n");
    ret.push_str("    deprecated = 1,\n");
    ret.push_str("}\n");
    ret
}

/// `TryFrom` block for  InformationElementId
fn generate_ie_try_from_pen_code(name_prefixes: &Vec<(String, String, u32)>) -> String {
    let mut ret = String::new();
    ret.push_str("impl TryFrom<(u32, u16)> for InformationElementId {\n");
    ret.push_str("    type Error = InformationElementIdError;\n\n");
    ret.push_str("    fn try_from(value: (u32, u16)) -> Result<Self, Self::Error> {\n");
    ret.push_str("        let (pen, code) = value;\n");
    ret.push_str("        match pen {\n");
    for (name, pkg, pen) in name_prefixes {
        ret.push_str(format!("            {} => {{\n", pen).as_str());
        ret.push_str(
            format!(
                "                match {}::InformationElementId::try_from(code) {{\n",
                pkg
            )
            .as_str(),
        );
        ret.push_str(format!("                    Ok(ie) => Ok(Self::{}(ie)),\n", name).as_str());
        ret.push_str(
            format!(
                "                    Err(err) => Err(InformationElementIdError::{}(err)),\n",
                name
            )
            .as_str(),
        );
        ret.push_str("                }\n");
        ret.push_str("            }\n");
    }
    ret.push_str(
        "           unknown => Ok(InformationElementId::Unknown{pen: unknown, code: code}),\n",
    );
    ret.push_str("       }\n");
    ret.push_str("   }\n");
    ret.push_str("}\n");
    ret
}

fn generate_ie_template_trait_for_ie(name_prefixes: &Vec<(String, String, u32)>) -> String {
    let mut ret = String::new();
    ret.push_str("impl super::InformationElementTemplate for InformationElementId {\n");
    ret.push_str("    fn semantics(&self) -> Option<InformationElementSemantics> {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => None,\n");
    for (name, _, _) in name_prefixes {
        ret.push_str(format!("            Self::{}(ie) => ie.semantics(),\n", name).as_str());
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");

    ret.push_str("    fn data_type(&self) -> InformationElementDataType {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => InformationElementDataType::octetArray,\n");
    for (name, _, _) in name_prefixes {
        ret.push_str(format!("            Self::{}(ie) => ie.data_type(),\n", name).as_str());
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");

    ret.push_str("    fn units(&self) -> Option<InformationElementUnits> {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => None,\n");
    for (name, _, _) in name_prefixes {
        ret.push_str(format!("            Self::{}(ie) => ie.units(),\n", name).as_str());
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");

    ret.push_str("    fn value_range(&self) -> Option<std::ops::Range<u64>> {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => None,\n");
    for (name, _, _) in name_prefixes {
        ret.push_str(format!("            Self::{}(ie) => ie.value_range(),\n", name).as_str());
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");

    ret.push_str("}\n\n");
    ret
}

pub fn generate_ie_ids(name_prefixes: Vec<(String, String, u32)>) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str(DEFAULT_STRUCT_DERIVE);
    ret.push_str("pub enum InformationElementId {\n");
    for (name, pkg, _) in &name_prefixes {
        ret.push_str("    Unknown{pen: u32, code: u16},\n");
        ret.push_str(format!("    {}({}::InformationElementId),\n", name, pkg).as_str());
    }
    ret.push_str("}\n");

    ret.push_str(DEFAULT_STRUCT_DERIVE);
    ret.push_str("pub enum InformationElementIdError {\n");
    for (name, pkg, _) in &name_prefixes {
        ret.push_str(format!("    {}({}::UndefinedInformationElementId),\n", name, pkg).as_str());
    }
    ret.push_str("}\n");

    ret.push_str(generate_ie_try_from_pen_code(&name_prefixes).as_str());
    ret.push_str(generate_ie_template_trait_for_ie(&name_prefixes).as_str());

    ret
}

pub fn generate_ie_values(name_prefix: String, ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    for ie in ies {
        let rust_type = match ie.data_type.as_str() {
            "octetArray" => "Vec<u8>",
            "unsigned8" => "u8",
            "unsigned16" => "u16",
            "unsigned32" => "u32",
            "unsigned64" => "u64",
            "signed8" => "i8",
            "signed16" => "i16",
            "signed32" => "i32",
            "signed64" => "i64",
            "float32" => "f32",
            "float64" => "f64",
            "boolean" => "bool",
            "macAddress" => "[u8; 6]",
            "string" => "String",
            "dateTimeSeconds" => "chrono::DateTime<chrono::Utc>",
            "dateTimeMilliseconds" => "chrono::DateTime<chrono::Utc>",
            "dateTimeMicroseconds" => "chrono::DateTime<chrono::Utc>",
            "dateTimeNanoseconds" => "chrono::DateTime<chrono::Utc>",
            "ipv4Address" => "std::net::Ipv4Addr",
            "ipv6Address" => "std::net::Ipv6Addr",
            "basicList" => "String",
            "subTemplateList" => "String",
            "subTemplateMultiList" => "String",
            other => todo!("Implement rust data type conversion for {}", other),
        };
        ret.push_str("#[allow(non_camel_case_types)]\n");
        ret.push_str(DEFAULT_STRUCT_DERIVE);
        ret.push_str(
            format!(
                "pub struct {}{}(pub {});\n\n",
                name_prefix, ie.name, rust_type
            )
            .as_str(),
        );

        match rust_type {
            "u8" => {
                ret.push_str(
                    format!("impl From<&[u8; 1]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: &[u8; 1]) -> Self {\n");
                ret.push_str("        Self(value[0])\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(format!("impl From<u8> for {}{}{{\n", name_prefix, ie.name).as_str());
                ret.push_str("    fn from(value: u8) -> Self {\n");
                ret.push_str("        Self(value)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");
                ret.push('\n');
            }
            "u16" => {
                ret.push_str(
                    format!("impl From<&[u8; 1]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: &[u8; 1]) -> Self {\n");
                ret.push_str("        Self(value[0] as u16)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(
                    format!("impl From<[u8; 2]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
                ret.push_str("        Self(u16::from_be_bytes(value))\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(format!("impl From<u16> for {}{}{{\n", name_prefix, ie.name).as_str());
                ret.push_str("    fn from(value: u16) -> Self {\n");
                ret.push_str("        Self(value)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");
                ret.push('\n');
            }
            "u32" => {
                ret.push_str(
                    format!("impl From<&[u8; 1]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: &[u8; 1]) -> Self {\n");
                ret.push_str("        Self(value[0] as u32)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(
                    format!("impl From<[u8; 2]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
                ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
                ret.push_str("        Self(tmp as u32)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(
                    format!("impl From<[u8; 4]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
                ret.push_str("        Self(u32::from_be_bytes(value))\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(format!("impl From<u32> for {}{}{{\n", name_prefix, ie.name).as_str());
                ret.push_str("    fn from(value: u32) -> Self {\n");
                ret.push_str("        Self(value)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");
                ret.push('\n');
            }
            "u64" => {
                ret.push_str(
                    format!("impl From<&[u8; 1]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: &[u8; 1]) -> Self {\n");
                ret.push_str("        Self(value[0] as u64)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(
                    format!("impl From<[u8; 2]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
                ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
                ret.push_str("        Self(tmp as u64)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(
                    format!("impl From<[u8; 4]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
                ret.push_str("        let tmp = u32::from_be_bytes(value);\n");
                ret.push_str("        Self(tmp as u64)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(
                    format!("impl From<[u8; 8]> for {}{}{{\n", name_prefix, ie.name).as_str(),
                );
                ret.push_str("    fn from(value: [u8; 8]) -> Self {\n");
                ret.push_str("        Self(u64::from_be_bytes(value))\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");

                ret.push_str(format!("impl From<u64> for {}{}{{\n", name_prefix, ie.name).as_str());
                ret.push_str("    fn from(value: u64) -> Self {\n");
                ret.push_str("        Self(value)\n");
                ret.push_str("    }\n");
                ret.push_str("}\n");
                ret.push('\n');
            }
            _ => {}
        }
    }
    ret
}
