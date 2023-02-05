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

//! Generate Rust code for the given Netflow/IPFIX definitions
use crate::{InformationElement, SimpleRegistry, Xref};

fn generate_derive(num_enum: bool, copy: bool, eq: bool) -> String {
    let mut base = "".to_string();
    if num_enum {
        base.push_str("strum_macros::Display, strum_macros::FromRepr, ");
    }
    if copy {
        base.push_str("Copy, ");
    }
    if eq {
        base.push_str("Eq, ");
    }
    base.push_str("Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize");
    format!("#[derive({base})]\n")
}

/// Convert [Xref] to markdown link
fn generate_xref_link(xref: &Xref) -> Option<String> {
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
        "html" => Some(format!("[{}]({})", xref.data, xref.data)),
        other => todo!("Handle xref of type {}", other),
    }
}

/// Generate InformationElementDataType
/// Currently we manually write this provide option for user defined types
#[allow(dead_code)]
pub(crate) fn generate_ie_data_type(data_types: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(generate_derive(true, true, true).as_str());
    ret.push_str("pub enum InformationElementDataType {\n");
    for x in data_types.iter() {
        for xref in x.xref.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("  /// {xref}\n").as_str());
        }
        ret.push_str(format!("  {} = {},\n", x.description, x.value).as_str());
    }
    ret.push_str("}\n");
    ret
}

/// Generate code for `InformationElementUnits`
pub(crate) fn generate_ie_units(entries: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(generate_derive(true, true, true).as_str());
    ret.push_str("pub enum InformationElementUnits {\n");
    for entry in entries.iter() {
        ret.push('\n');
        if let Some(comments) = entry.comments.as_ref() {
            ret.push_str(format!("  /// {comments}\n").as_str());
            ret.push_str("  ///\n");
        }
        for xref in entry.xref.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("  /// {xref}\n").as_str());
        }
        // Note: this an special exception, since `4-octet words` is not valid rust id
        let description = if entry.description == "4-octet words" {
            "fourOctetWords"
        } else {
            &entry.description
        };
        ret.push_str(format!("  {} = {},\n", description, entry.value).as_str());
    }
    ret.push_str("}\n\n");
    ret
}

/// Generate rust code for `InformationElementSemantics`
pub(crate) fn generate_ie_semantics(data_types: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(generate_derive(true, true, true).as_str());
    ret.push_str("pub enum InformationElementSemantics {\n");
    for x in data_types.iter() {
        ret.push('\n');
        for xref in x.xref.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("  /// {xref}\n").as_str());
        }
        ret.push_str(format!("  {} = {},\n", x.description, x.value).as_str());
    }
    ret.push_str("}\n\n");
    ret
}

fn generate_impl_ie_template_for_ie(ie: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    ret.push_str("impl super::InformationElementTemplate for InformationElementId {\n");
    ret.push_str("    fn semantics(&self) -> Option<super::InformationElementSemantics> {\n");
    ret.push_str("        match self {\n");
    for ie in ie {
        ret.push_str(
            format!(
                "            Self::{} => {},\n",
                ie.name,
                ie.data_type_semantics
                    .as_ref()
                    .map(|x| format!("Some(super::InformationElementSemantics::{x})"))
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
                    .map(|x| format!("Some(super::InformationElementUnits::{x})"))
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
                        let start = parts.first().expect("Couldn't parse units range");
                        let end = parts.get(1).unwrap().trim();
                        let end = if end.starts_with("0x") {
                            u64::from_str_radix(end.trim_start_matches("0x"), 16).unwrap()
                        } else {
                            end.parse::<u64>().unwrap()
                        };
                        format!(
                            "Some(std::ops::Range{{start: {}, end: {}}})",
                            start,
                            end + 1
                        )
                    })
                    .unwrap_or_else(|| "None".to_string())
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn id(&self) -> u16 {\n");
    ret.push_str("        (*self) as u16\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn pen(&self) -> u32 {\n");
    ret.push_str(format!("        {}\n", ie.first().unwrap().pen).as_str());
    ret.push_str("    }\n\n");

    ret.push_str("}\n");
    ret
}

fn generate_from_for_ie() -> String {
    let mut ret = String::new();
    ret.push_str(generate_derive(false, true, true).as_str());
    ret.push_str("pub struct UndefinedInformationElementId(pub u16);\n");

    ret.push_str("impl From<InformationElementId> for u16 {\n");
    ret.push_str("    fn from(value: InformationElementId) -> Self {\n");
    ret.push_str("        value as u16\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl TryFrom<u16> for InformationElementId {\n");
    ret.push_str("    type Error = UndefinedInformationElementId;\n\n");
    ret.push_str("    fn try_from(value: u16) -> Result<Self, Self::Error> {\n");
    ret.push_str("       match Self::from_repr(value) {\n");
    ret.push_str("           Some(val) => Ok(val),\n");
    ret.push_str("           None => Err(UndefinedInformationElementId(value)),\n");
    ret.push_str("       }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

/// Generate an enum of InformationElementIDs.
/// different names spaces; i.e. IANA vs enterprise space.
pub(crate) fn generate_information_element_ids(ie: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u16)]\n");
    ret.push_str(generate_derive(true, true, true).as_str());
    ret.push_str("pub enum InformationElementId {\n");
    for ie in ie {
        for line in ie.description.split('\n') {
            ret.push_str(format!("    /// {}\n", line.trim()).as_str());
        }
        if !ie.description.is_empty() && !ie.xrefs.is_empty() {
            ret.push_str("    ///\n");
        }
        for xref in ie.xrefs.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("    /// Reference: {xref}\n").as_str());
        }
        ret.push_str(format!("    {} = {},\n", ie.name, ie.element_id).as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str(generate_impl_ie_template_for_ie(ie).as_str());
    ret.push_str(generate_from_for_ie().as_str());
    ret
}

/// Information Elements can be either current or deprecated, no IANA registry
/// for it at the moment, it's hard coded here.
pub(crate) fn generate_ie_status() -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(generate_derive(true, true, true).as_str());
    ret.push_str("pub enum InformationElementStatus {\n");
    ret.push_str("    current = 0,\n");
    ret.push_str("    deprecated = 1,\n");
    ret.push_str("}\n\n");
    ret
}

/// Use at the beginning of ie_generated for defining custom types
pub(crate) fn generate_common_types() -> String {
    "pub type MacAddress = [u8; 6];\n\n".to_string()
}

/// `TryFrom` block for  InformationElementId
fn generate_ie_try_from_pen_code(
    iana_ies: &Vec<InformationElement>,
    name_prefixes: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("impl TryFrom<(u32, u16)> for InformationElementId {\n");
    ret.push_str("    type Error = InformationElementIdError;\n\n");
    ret.push_str("    fn try_from(value: (u32, u16)) -> Result<Self, Self::Error> {\n");
    ret.push_str("        let (pen, code) = value;\n");
    ret.push_str("        match pen {\n");
    ret.push_str("            0 => {\n");
    ret.push_str("                match code {\n");
    for ie in iana_ies {
        ret.push_str(
            format!(
                "                    {} =>  Ok(InformationElementId::{}),\n",
                ie.element_id, ie.name
            )
            .as_str(),
        );
    }
    ret.push_str("                    _ =>  Err(InformationElementIdError::UndefinedIANAInformationElementId(code)),\n");
    ret.push_str("                }\n");
    ret.push_str("            }\n");
    for (name, pkg, pen) in name_prefixes {
        ret.push_str(format!("            {pen} => {{\n").as_str());
        ret.push_str(
            format!("                match {pkg}::InformationElementId::try_from(code) {{\n")
                .as_str(),
        );
        ret.push_str(format!("                    Ok(ie) => Ok(Self::{name}(ie)),\n").as_str());
        ret.push_str(
            format!(
                "                    Err(err) => Err(InformationElementIdError::{name}(err)),\n"
            )
            .as_str(),
        );
        ret.push_str("                }\n");
        ret.push_str("            }\n");
    }
    ret.push_str(
        "           unknown => Ok(InformationElementId::Unknown{pen: unknown, id: code}),\n",
    );
    ret.push_str("       }\n");
    ret.push_str("   }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_ie_template_trait_for_main(
    iana_ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("impl super::InformationElementTemplate for InformationElementId {\n");
    ret.push_str("    fn semantics(&self) -> Option<InformationElementSemantics> {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => None,\n");
    for (name, _, _) in vendors {
        ret.push_str(format!("            Self::{name}(ie) => ie.semantics(),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(
            format!(
                "            Self::{} => {},\n",
                ie.name,
                ie.data_type_semantics
                    .as_ref()
                    .map(|x| format!("Some(InformationElementSemantics::{x})"))
                    .unwrap_or_else(|| "None".to_string())
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn data_type(&self) -> InformationElementDataType {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => InformationElementDataType::octetArray,\n");
    for (name, _, _) in vendors {
        ret.push_str(format!("            Self::{name}(ie) => ie.data_type(),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(
            format!(
                "            Self::{} => InformationElementDataType::{},\n",
                ie.name, ie.data_type
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn units(&self) -> Option<InformationElementUnits> {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => None,\n");
    for (name, _, _) in vendors {
        ret.push_str(format!("            Self::{name}(ie) => ie.units(),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(
            format!(
                "            Self::{} => {},\n",
                ie.name,
                ie.units
                    .as_ref()
                    .map(|x| format!("Some(super::InformationElementUnits::{x})"))
                    .unwrap_or_else(|| "None".to_string())
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn value_range(&self) -> Option<std::ops::Range<u64>> {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{..} => None,\n");
    for (name, _, _) in vendors {
        ret.push_str(format!("            Self::{name}(ie) => ie.value_range(),\n").as_str());
    }
    for ie in iana_ies {
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
                        let start = parts.first().expect("Couldn't parse units range");
                        let end = parts.get(1).unwrap().trim();
                        let end = if end.starts_with("0x") {
                            u64::from_str_radix(end.trim_start_matches("0x"), 16).unwrap()
                        } else {
                            end.parse::<u64>().unwrap()
                        };
                        format!(
                            "Some(std::ops::Range{{start: {}, end: {}}})",
                            start,
                            end + 1
                        )
                    })
                    .unwrap_or_else(|| "None".to_string())
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn id(&self) -> u16{\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{id, ..} => *id,\n");
    for (name, _pkg, _) in vendors {
        ret.push_str(format!("            Self::{name}(vendor_ie) => vendor_ie.id(),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(format!("            Self::{} => {},\n", ie.name, ie.element_id).as_str());
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("    fn pen(&self) -> u32{\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{pen, ..} => *pen,\n");
    for (name, _pkg, _) in vendors {
        ret.push_str(format!("            Self::{name}(vendor_ie) => vendor_ie.pen(),\n").as_str());
    }
    // Rest is IANA with PEN 0
    ret.push_str("            _ => 0,\n");
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");

    ret.push_str("}\n\n");
    ret
}

fn generate_ie_field_enum_for_ie(
    iana_ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str(generate_derive(false, false, false).as_str());
    ret.push_str("pub enum Field {\n");
    ret.push_str("    Unknown(Vec<u8>),\n");
    for (name, pkg, _) in vendors {
        ret.push_str(format!("    {name}({pkg}::Field),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(format!("    {}({}),\n", ie.name, ie.name).as_str());
    }
    ret.push_str("}\n\n");
    ret
}

pub(crate) fn generate_ie_ids(
    iana_ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str(generate_derive(false, true, true).as_str());
    ret.push_str("pub enum InformationElementId {\n");
    ret.push_str("    Unknown{pen: u32, id: u16},\n");
    for (name, pkg, _) in vendors {
        ret.push_str(format!("    {name}({pkg}::InformationElementId),\n").as_str());
    }
    for ie in iana_ies {
        for line in ie.description.split('\n') {
            ret.push_str(format!("    /// {}\n", line.trim()).as_str());
        }
        if !ie.description.is_empty() && !ie.xrefs.is_empty() {
            ret.push_str("    ///\n");
        }
        for xref in ie.xrefs.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("    /// Reference: {xref}\n").as_str());
        }
        ret.push_str(format!("    {},\n", ie.name).as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str(generate_derive(false, true, true).as_str());
    ret.push_str("pub enum InformationElementIdError {\n");
    ret.push_str("    UndefinedIANAInformationElementId(u16),\n");
    for (name, pkg, _) in vendors {
        ret.push_str(format!("    {name}({pkg}::UndefinedInformationElementId),\n").as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str(generate_ie_try_from_pen_code(iana_ies, vendors).as_str());
    ret.push_str(generate_ie_template_trait_for_main(iana_ies, vendors).as_str());
    ret.push_str(generate_ie_field_enum_for_ie(iana_ies, vendors).as_str());

    ret
}

/// Held out temporary, we might not need this
#[allow(dead_code)]
fn generate_ie_value_converters(rust_type: &str, ie_name: &String) -> String {
    let mut ret = String::new();
    match rust_type {
        "u8" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0])\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u8> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u8) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u16" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u16)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        Self(u16::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u16> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u16) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u32" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u32)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u32)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 4]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
            ret.push_str("        Self(u32::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u32> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u32) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u64" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 4]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
            ret.push_str("        let tmp = u32::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 8]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 8]) -> Self {\n");
            ret.push_str("        Self(u64::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");

            ret.push_str(format!("impl From<u64> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u64) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        _ => {
            // TODO: generate converts for the rest of data types
        }
    }
    ret
}

fn get_std_deserializer_error(ty_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {ty_name}ParsingError {{\n").as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    ret.push_str("    InvalidLength(u16),\n");
    ret.push_str("}\n\n");
    ret
}

fn get_time_millis_deserializer_error(ty_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {ty_name}ParsingError {{\n").as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    ret.push_str("    InvalidLength(u16),\n");
    ret.push_str("    InvalidTimestampMillis(u64),\n");
    ret.push_str("}\n\n");
    ret
}

fn get_timestamp_deserializer_error(ty_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {ty_name}ParsingError {{\n").as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    ret.push_str("    InvalidLength(u16),\n");
    ret.push_str("    InvalidTimestamp(u32),\n");
    ret.push_str("}\n\n");
    ret
}

fn get_timestamp_fraction_deserializer_error(ty_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {ty_name}ParsingError {{\n").as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    ret.push_str("    InvalidLength(u16),\n");
    ret.push_str("    InvalidTimestamp(u32, u32),\n");
    ret.push_str("}\n\n");
    ret
}

fn get_deserializer_header(ty_name: &str) -> String {
    let mut header = format!("impl<'a> netgauze_parse_utils::ReadablePDUWithOneInput<'a, u16, Located{ty_name}ParsingError<'a>> for {ty_name} {{\n");
    header.push_str("    #[inline]\n");
    header.push_str(format!("    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, Located{ty_name}ParsingError<'a>> {{\n").as_str());
    header
}

fn generate_u8_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => nom::number::complete::be_u8(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_u16_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                (buf, value as u16)\n");
    ret.push_str("            }\n");
    ret.push_str("            2 => nom::number::complete::be_u16(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_u32_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let len = length as usize;\n");
    ret.push_str("        if length > 4 || buf.input_len() < len {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        }\n");
    ret.push_str("        let mut res = 0u32;\n");
    ret.push_str("        for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("            res = (res << 8) + byte as u32;\n");
    ret.push_str("        }\n");
    ret.push_str(format!("        Ok((buf.slice(len..), {ie_name}(res)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_u64_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let len = length as usize;\n");
    ret.push_str("        if length > 8 || buf.input_len() < len {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        }\n");
    ret.push_str("        let mut res = 0u64;\n");
    ret.push_str("        for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("            res = (res << 8) + byte as u64;\n");
    ret.push_str("        }\n");
    ret.push_str(format!("        Ok((buf.slice(len..), {ie_name}(res)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_i8_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => nom::number::complete::be_i8(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_i16_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let len = length as usize;\n");
    ret.push_str("        if length > 2 || buf.input_len() < len {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        }\n");
    ret.push_str("        let mut res = 0u16;\n");
    ret.push_str("        let mut first = true;\n");
    ret.push_str("        for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("            if first {\n");
    ret.push_str("                if byte & 0x80 != 0 {\n");
    ret.push_str("                    res = u16::MAX;\n");
    ret.push_str("                }\n");
    ret.push_str("                first = false;\n");
    ret.push_str("            }\n");
    ret.push_str("            res = (res << 8) + byte as u16;\n");
    ret.push_str("        }\n");
    ret.push_str(format!("        Ok((buf.slice(len..), {ie_name}(res as i16)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_i32_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let len = length as usize;\n");
    ret.push_str("        if length > 4 || buf.input_len() < len {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        }\n");
    ret.push_str("        let mut res = 0u32;\n");
    ret.push_str("        let mut first = true;\n");
    ret.push_str("        for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("            if first {\n");
    ret.push_str("                if byte & 0x80 != 0 {\n");
    ret.push_str("                    res = u32::MAX;\n");
    ret.push_str("                }\n");
    ret.push_str("                first = false;\n");
    ret.push_str("            }\n");
    ret.push_str("            res = (res << 8) + byte as u32;\n");
    ret.push_str("        }\n");
    ret.push_str(format!("        Ok((buf.slice(len..), {ie_name}(res as i32)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_i64_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let len = length as usize;\n");
    ret.push_str("        if length > 8 || buf.input_len() < len {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        }\n");
    ret.push_str("        let mut res = 0u64;\n");
    ret.push_str("        let mut first = true;\n");
    ret.push_str("        for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("            if first {\n");
    ret.push_str("                if byte & 0x80 != 0 {\n");
    ret.push_str("                    res = u64::MAX;\n");
    ret.push_str("                }\n");
    ret.push_str("                first = false;\n");
    ret.push_str("            }\n");
    ret.push_str("            res = (res << 8) + byte as u64;\n");
    ret.push_str("        }\n");
    ret.push_str(format!("        Ok((buf.slice(len..), {ie_name}(res as i64)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_f32_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => nom::number::complete::be_f32(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_f64_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => nom::number::complete::be_f64(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_bool_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => nom::number::complete::be_u8(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))))\n").as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value != 0)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_mac_address_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        if length != 6 {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))));\n").as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, b0) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b1) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b2) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b3) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b4) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b5) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str(format!("        Ok((buf, {ie_name}([b0, b1, b2, b3, b4, b5])))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_string_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let header = get_deserializer_header(ie_name.as_str());
    let mut string_error = String::new();
    string_error.push_str("#[allow(non_camel_case_types)]\n");
    string_error.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    string_error.push_str(format!("pub enum {ie_name}ParsingError {{\n").as_str());
    string_error.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    string_error.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    string_error.push_str("    Utf8Error(String),\n");
    string_error.push_str("}\n\n");

    string_error.push_str("impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error>\n");
    string_error.push_str(format!("for Located{ie_name}ParsingError<'a>\n").as_str());
    string_error.push_str("{\n");
    string_error.push_str("    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {\n");
    string_error.push_str(format!("        Located{ie_name}ParsingError::new(\n").as_str());
    string_error.push_str("            input,\n");
    string_error.push_str(
        format!("            {ie_name}ParsingError::Utf8Error(error.to_string()),\n").as_str(),
    );
    string_error.push_str("        )\n");
    string_error.push_str("    }\n");
    string_error.push_str("}\n");

    ret.push_str(string_error.as_str());
    ret.push_str(header.as_str());

    ret.push_str("        let (buf, value) =\n");
    ret.push_str("            nom::combinator::map_res(nom::bytes::complete::take(length), |str_buf: netgauze_parse_utils::Span<'_>| {\n");
    ret.push_str("                let nul_range_end = str_buf\n");
    ret.push_str("                    .iter()\n");
    ret.push_str("                    .position(|&c| c == b'\\0')\n");
    ret.push_str("                    .unwrap_or(str_buf.len());\n");
    ret.push_str(
        "                let result = ::std::str::from_utf8(&str_buf[..nul_range_end]);\n",
    );
    ret.push_str("                result.map(|x| x.to_string())\n");
    ret.push_str("            })(buf)?;\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n");
    ret
}

fn generate_ipv4_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        if length != 4 {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))));\n").as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, ip) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("        let value = std::net::Ipv4Addr::from(ip);\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_ipv6_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        if length != 16 {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))));\n").as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, ip) = nom::number::complete::be_u128(buf)?;\n");
    ret.push_str("        let value = std::net::Ipv6Addr::from(ip);\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_date_time_seconds(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_timestamp_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        if length != 4 {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))));\n").as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, secs) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("        let value = match chrono::Utc.timestamp_opt(secs as i64, 0) {\n");
    ret.push_str("            chrono::LocalResult::Single(val) => val,\n");
    ret.push_str("            _ => {\n");
    ret.push_str(format!("                  return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidTimestamp(secs))));\n").as_str());
    ret.push_str("            }\n");
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_date_time_milli(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_time_millis_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        if length != 8 {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))));\n").as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, millis) = nom::number::complete::be_u64(buf)?;\n");
    ret.push_str("        let value = match chrono::Utc.timestamp_millis_opt(millis as i64) {\n");
    ret.push_str("            chrono::LocalResult::Single(val) => val,\n");
    ret.push_str("            _ => {\n");
    ret.push_str(format!("                  return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidTimestampMillis(millis))));\n").as_str());
    ret.push_str("            }\n");
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_date_time_micro(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_timestamp_fraction_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        if length != 8 {\n");
    ret.push_str(format!("            return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidLength(length))));\n").as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, seconds) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("        let (buf, fraction) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("        // Convert 1/2^32 of a second to nanoseconds\n");
    ret.push_str(
        "        let f: u32 = (1_000_000_000f64 * (fraction as f64 / u32::MAX as f64)) as u32;\n",
    );
    ret.push_str("        let value = match chrono::Utc.timestamp_opt(seconds as i64, f) {\n");
    ret.push_str("            chrono::LocalResult::Single(val) => val,\n");
    ret.push_str("            _ => {\n");
    ret.push_str(format!("                  return Err(nom::Err::Error(Located{ie_name}ParsingError::new(buf, {ie_name}ParsingError::InvalidTimestamp(seconds, fraction))));\n").as_str());
    ret.push_str("            }\n");
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_vec_u8_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    let std_error = get_std_deserializer_error(ie_name.as_str());
    let header = get_deserializer_header(ie_name.as_str());
    ret.push_str(std_error.as_str());
    ret.push_str(header.as_str());
    ret.push_str("        let (buf, value) = nom::multi::count(nom::number::complete::be_u8, length as usize)(buf)?;\n");
    ret.push_str(format!("        Ok((buf, {ie_name}(value)))\n").as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_ie_deserializer(data_type: &str, ie_name: &String) -> String {
    let mut ret = String::new();
    let gen = match data_type {
        "octetArray" => generate_vec_u8_deserializer(ie_name),
        "unsigned8" => generate_u8_deserializer(ie_name),
        "unsigned16" => generate_u16_deserializer(ie_name),
        "unsigned32" => generate_u32_deserializer(ie_name),
        "unsigned64" => generate_u64_deserializer(ie_name),
        "signed8" => generate_i8_deserializer(ie_name),
        "signed16" => generate_i16_deserializer(ie_name),
        "signed32" => generate_i32_deserializer(ie_name),
        "signed64" => generate_i64_deserializer(ie_name),
        "float32" => generate_f32_deserializer(ie_name),
        "float64" => generate_f64_deserializer(ie_name),
        "boolean" => generate_bool_deserializer(ie_name),
        "macAddress" => generate_mac_address_deserializer(ie_name),
        "string" => generate_string_deserializer(ie_name),
        "dateTimeSeconds" => generate_date_time_seconds(ie_name),
        "dateTimeMilliseconds" => generate_date_time_milli(ie_name),
        "dateTimeMicroseconds" => generate_date_time_micro(ie_name),
        // Nano and micro are using the same representation,
        // see https://www.rfc-editor.org/rfc/rfc7011.html#section-6.1.9
        "dateTimeNanoseconds" => generate_date_time_micro(ie_name),
        "ipv4Address" => generate_ipv4_deserializer(ie_name),
        "ipv6Address" => generate_ipv6_deserializer(ie_name),
        // TODO: better parsing for IPFIX structured Data
        "basicList" => generate_vec_u8_deserializer(ie_name),
        "subTemplateList" => generate_vec_u8_deserializer(ie_name),
        "subTemplateMultiList" => generate_vec_u8_deserializer(ie_name),
        ty => todo!("Unsupported deserialization for type: {}", ty),
    };
    ret.push_str(gen.as_str());
    ret
}

pub(crate) fn generate_pkg_ie_deserializers(
    vendor_mod: &str,
    ies: &Vec<InformationElement>,
) -> String {
    let mut ret = String::new();
    // Not every vendor is using time based values
    if ies.iter().any(|x| x.data_type.contains("String")) {
        ret.push_str("use nom::InputIter;\n");
    }
    if ies.iter().any(|x| x.data_type.contains("chrono")) {
        ret.push_str("use chrono::TimeZone;\n");
    }
    ret.push_str(format!("use crate::ie::{vendor_mod}::*;\n\n").as_str());

    for ie in ies {
        ret.push_str(generate_ie_deserializer(&ie.data_type, &ie.name).as_str());
    }

    ret.push_str(generate_ie_values_deserializers(ies).as_str());
    ret
}

pub(crate) fn generate_pkg_ie_serializers(
    vendor_mod: &str,
    ies: &Vec<InformationElement>,
) -> String {
    let mut ret = String::new();
    ret.push_str("use byteorder::WriteBytesExt;\n");
    ret.push_str(format!("use crate::ie::{vendor_mod}::*;\n\n").as_str());

    for ie in ies {
        ret.push_str(generate_ie_serializer(&ie.data_type, &ie.name).as_str());
    }
    let ty_name = "Field";
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]\n");
    ret.push_str(format!("pub enum {ty_name}WritingError {{\n").as_str());
    ret.push_str("    StdIOError(#[from_std_io_error] String),\n");
    for ie in ies {
        ret.push_str(format!("    {}Error(#[from] {}WritingError),\n", ie.name, ie.name).as_str());
    }
    ret.push_str("}\n\n");
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ty_name}WritingError> for {ty_name} {{\n"
        )
            .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 0;\n\n");
    ret.push_str("    fn len(&self, length: Option<u16>) -> usize {\n");
    ret.push_str("        match self {\n");
    for ie in ies {
        ret.push_str(
            format!(
                "            Self::{}(value) => value.len(length),\n",
                ie.name
            )
            .as_str(),
        );
    }

    ret.push_str("         }\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), {ty_name}WritingError> {{\n").as_str());
    ret.push_str("        match self {\n");
    for ie in ies {
        ret.push_str(
            format!(
                "           Self::{}(value) => value.write(writer, length)?,\n",
                ie.name
            )
            .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("        Ok(())\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret
}

pub(crate) fn generate_fields_enum(ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    let not_copy = ies.iter().any(|x| {
        get_rust_type(&x.data_type) == "Vec<u8>" || get_rust_type(&x.data_type) == "String"
    });
    let not_eq = ies
        .iter()
        .any(|x| get_rust_type(&x.data_type) == "f32" || get_rust_type(&x.data_type) == "f64");
    ret.push_str(generate_derive(false, !not_copy, !not_eq).as_str());
    ret.push_str("pub enum Field {\n");
    for ie in ies {
        ret.push_str(format!("    {}({}),\n", ie.name, ie.name).as_str());
    }
    ret.push_str("}\n");
    ret
}

fn get_rust_type(data_type: &str) -> String {
    let rust_type = match data_type {
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
        "macAddress" => "super::MacAddress",
        "string" => "String",
        "dateTimeSeconds" => "chrono::DateTime<chrono::Utc>",
        "dateTimeMilliseconds" => "chrono::DateTime<chrono::Utc>",
        "dateTimeMicroseconds" => "chrono::DateTime<chrono::Utc>",
        "dateTimeNanoseconds" => "chrono::DateTime<chrono::Utc>",
        "ipv4Address" => "std::net::Ipv4Addr",
        "ipv6Address" => "std::net::Ipv6Addr",
        "basicList" => "Vec<u8>",
        "subTemplateList" => "Vec<u8>",
        "subTemplateMultiList" => "Vec<u8>",
        other => todo!("Implement rust data type conversion for {}", other),
    };
    rust_type.to_string()
}

pub(crate) fn generate_ie_values(ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    for ie in ies {
        let rust_type = get_rust_type(&ie.data_type);
        ret.push_str("#[allow(non_camel_case_types)]\n");
        let generate_derive = generate_derive(
            false,
            rust_type != "Vec<u8>" && rust_type != "String",
            rust_type != "f32" && rust_type != "f64",
        );
        ret.push_str(generate_derive.as_str());
        ret.push_str(format!("pub struct {}(pub {});\n\n", ie.name, rust_type).as_str());

        // TODO: check if value converters are needed
        //ret.push_str(generate_ie_value_converters(&rust_type,
        // &ie.name).as_str());
    }
    ret
}

fn generate_ie_values_deserializers(ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    let ty_name = "Field";
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {ty_name}ParsingError {{\n").as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    for ie in ies {
        ret.push_str(
            format!(
                "    {}Error(#[from_located(module = \"self\")] {}ParsingError),\n",
                ie.name, ie.name
            )
            .as_str(),
        );
    }
    ret.push_str("}\n");
    ret.push_str("\n\n");

    ret.push_str(format!("impl<'a> netgauze_parse_utils::ReadablePDUWithTwoInputs<'a, &InformationElementId, u16, Located{ty_name}ParsingError<'a>>\n").as_str());
    ret.push_str(format!("for {ty_name} {{\n").as_str());
    ret.push_str("    #[inline]\n");
    ret.push_str("    fn from_wire(\n");
    ret.push_str("        buf: netgauze_parse_utils::Span<'a>,\n");
    ret.push_str("        ie: &InformationElementId,\n");
    ret.push_str("        length: u16,\n");
    ret.push_str(format!("    ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, Located{ty_name}ParsingError<'a>> {{\n").as_str());
    ret.push_str("        let (buf, value) = match ie {\n");
    for ie in ies {
        ret.push_str(format!("            InformationElementId::{} => {{\n", ie.name).as_str());
        ret.push_str(format!("                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, Located{}ParsingError<'_>, Located{}ParsingError<'_>, {}>(buf, length)?;\n", ie.name, ty_name, ie.name).as_str());
        ret.push_str(format!("                (buf, Field::{}(value))\n", ie.name).as_str());
        ret.push_str("            }\n");
    }
    ret.push_str("        };\n");
    ret.push_str("       Ok((buf, value))\n");
    ret.push_str("    }\n");
    ret.push_str("}\n");

    ret
}

pub(crate) fn generate_ie_deser_main(
    iana_ies: &Vec<InformationElement>,
    vendor_prefixes: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("use nom::{InputLength, InputIter, Slice};\n");
    ret.push_str("use chrono::TimeZone;\n\n\n");
    // Generate IANA Deser
    for ie in iana_ies {
        ret.push_str(generate_ie_deserializer(&ie.data_type, &ie.name).as_str());
    }

    let ty_name = "Field";
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {ty_name}ParsingError {{\n").as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    for (name, pkg, _) in vendor_prefixes {
        let value_name = format!("{pkg}::FieldParsingError");
        ret.push_str(
            format!("    {name}Error(#[from_located(module = \"\")] {value_name}),\n").as_str(),
        );
    }
    for ie in iana_ies {
        ret.push_str(
            format!(
                "    {}Error(#[from_located(module = \"self\")] {}ParsingError),\n",
                ie.name, ie.name
            )
            .as_str(),
        );
    }
    ret.push_str("}\n");
    ret.push_str("\n\n");

    ret.push_str("impl<'a> netgauze_parse_utils::ReadablePDUWithTwoInputs<'a, &InformationElementId, u16, LocatedFieldParsingError<'a>>\n");
    ret.push_str("for Field {\n");
    ret.push_str("    #[inline]\n");
    ret.push_str("    fn from_wire(\n");
    ret.push_str("        buf: netgauze_parse_utils::Span<'a>,\n");
    ret.push_str("        ie: &InformationElementId,\n");
    ret.push_str("        length: u16,\n");
    ret.push_str("    ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedFieldParsingError<'a>> {\n");
    ret.push_str("        let (buf, value) = match ie {\n");
    for (name, _, _) in vendor_prefixes {
        ret.push_str(
            format!("            InformationElementId::{name}(value_ie) => {{\n").as_str(),
        );
        ret.push_str("                let (buf, value) = netgauze_parse_utils::parse_into_located_two_inputs(buf, value_ie, length)?;\n");
        ret.push_str(format!("                (buf, crate::ie::Field::{name}(value))\n").as_str());
        ret.push_str("            }\n");
    }
    for ie in iana_ies {
        ret.push_str(format!("            InformationElementId::{} => {{\n", ie.name).as_str());
        ret.push_str("                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input(buf, length)?;\n");
        ret.push_str(
            format!(
                "                (buf, crate::ie::Field::{}(value))\n",
                ie.name
            )
            .as_str(),
        );
        ret.push_str("            }\n");
    }
    ret.push_str("            _ => todo!(\"Handle unknown IEs\")\n");
    ret.push_str("        };\n");
    ret.push_str("        Ok((buf, value))\n");
    ret.push_str("    }\n");
    ret.push_str("}\n");

    ret
}

fn get_std_serializer_error(ty_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]\n");
    ret.push_str(format!("pub enum {ty_name}WritingError {{\n").as_str());
    ret.push_str("    StdIOError(#[from_std_io_error] String),\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_num8_serializer(num_type: &str, ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name.as_str()).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 1;\n\n");
    ret.push_str("     fn len(&self, _length: Option<u16>) -> usize {\n");
    ret.push_str("         Self::BASE_LENGTH\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str(format!("         writer.write_{num_type}(self.0)?;\n").as_str());
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_num_serializer(num_type: &str, length: u16, ie_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str(format!("    const BASE_LENGTH: usize = {length};\n\n").as_str());
    ret.push_str("     fn len(&self, length: Option<u16>) -> usize {\n");
    ret.push_str("         match length {\n");
    ret.push_str("             None => Self::BASE_LENGTH,\n");
    ret.push_str("             Some(len) => len as usize,\n");
    ret.push_str("         }\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());

    ret.push_str("         match length {\n");
    ret.push_str(
        format!(
            "             None => writer.write_{num_type}::<byteorder::NetworkEndian>(self.0)?,\n"
        )
        .as_str(),
    );
    ret.push_str("             Some(len) => {\n");
    ret.push_str("                 let be_bytes = self.0.to_be_bytes();\n");
    ret.push_str("                 let begin_offset = be_bytes.len() - len as usize;\n");
    ret.push_str("                 writer.write_all(&be_bytes[begin_offset..])?;\n");
    ret.push_str("             }\n");
    ret.push_str("         }\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_array_serializer(ie_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 0;\n\n");
    ret.push_str("     fn len(&self, _length: Option<u16>) -> usize {\n");
    ret.push_str("         self.0.len()\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str("         writer.write_all(&self.0)?;\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_ip_serializer(length: u16, ie_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str(format!("    const BASE_LENGTH: usize = {length};\n\n").as_str());
    ret.push_str("     fn len(&self, _length: Option<u16>) -> usize {\n");
    ret.push_str("         Self::BASE_LENGTH\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str("         writer.write_all(&self.0.octets())?;\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_string_serializer(ie_name: &str) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 0;\n\n");
    ret.push_str("     fn len(&self, length: Option<u16>) -> usize {\n");
    ret.push_str("         match length {\n");
    ret.push_str("             None => self.0.len(),\n");
    ret.push_str("             Some(len) => len as usize,\n");
    ret.push_str("         }\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str("         writer.write_all(self.0.as_bytes())?;\n");
    ret.push_str("         match length {\n");
    ret.push_str("             None => {},\n");
    ret.push_str("             Some(len) => {\n");
    ret.push_str("                  for _ in self.0.as_bytes().len()..(len as usize) {\n");
    ret.push_str("                      writer.write_u8(0)?\n");
    ret.push_str("                  }\n");
    ret.push_str("             }\n");
    ret.push_str("         }\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_bool_serializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name.as_str()).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 1;\n\n");
    ret.push_str("     fn len(&self, _length: Option<u16>) -> usize {\n");
    ret.push_str("         Self::BASE_LENGTH\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str("         writer.write_u8(self.0.into())?;\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_seconds_serializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name.as_str()).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 4;\n\n");
    ret.push_str("     fn len(&self, _length: Option<u16>) -> usize {\n");
    ret.push_str("         Self::BASE_LENGTH\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str(
        "         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;\n",
    );
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_milli_seconds_serializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name.as_str()).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 8;\n\n");
    ret.push_str("     fn len(&self, _length: Option<u16>) -> usize {\n");
    ret.push_str("         Self::BASE_LENGTH\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str(
        "         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;\n",
    );
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_fraction_serializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str(get_std_serializer_error(ie_name.as_str()).as_str());
    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ie_name}WritingError> for {ie_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 8;\n\n");
    ret.push_str("     fn len(&self, _length: Option<u16>) -> usize {\n");
    ret.push_str("         Self::BASE_LENGTH\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), {ie_name}WritingError> {{\n").as_str());
    ret.push_str(
        "         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;\n",
    );
    ret.push_str("         let nanos = self.0.timestamp_subsec_nanos();\n");
    ret.push_str("         // Convert 1/2**32 of a second to a fraction of a nano second\n");
    ret.push_str("         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;\n");
    ret.push_str("         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_ie_serializer(data_type: &str, ie_name: &String) -> String {
    let mut ret = String::new();
    let gen = match data_type {
        "octetArray" => generate_array_serializer(ie_name),
        "unsigned8" => generate_num8_serializer("u8", ie_name),
        "unsigned16" => generate_num_serializer("u16", 2, ie_name),
        "unsigned32" => generate_num_serializer("u32", 4, ie_name),
        "unsigned64" => generate_num_serializer("u64", 8, ie_name),
        "signed8" => generate_num8_serializer("i8", ie_name),
        "signed16" => generate_num_serializer("i16", 2, ie_name),
        "signed32" => generate_num_serializer("i32", 4, ie_name),
        "signed64" => generate_num_serializer("i64", 8, ie_name),
        "float32" => generate_num_serializer("f32", 4, ie_name),
        "float64" => generate_num_serializer("f64", 8, ie_name),
        "boolean" => generate_bool_serializer(ie_name),
        "macAddress" => generate_array_serializer(ie_name),
        "string" => generate_string_serializer(ie_name),
        "dateTimeSeconds" => generate_seconds_serializer(ie_name),
        "dateTimeMilliseconds" => generate_milli_seconds_serializer(ie_name),
        "dateTimeMicroseconds" => generate_fraction_serializer(ie_name),
        //// Nano and micro are using the same representation,
        //// see https://www.rfc-editor.org/rfc/rfc7011.html#section-6.1.9
        "dateTimeNanoseconds" => generate_fraction_serializer(ie_name),
        "ipv4Address" => generate_ip_serializer(4, ie_name),
        "ipv6Address" => generate_ip_serializer(16, ie_name),
        //// TODO: better parsing for IPFIX structured Data
        "basicList" => generate_array_serializer(ie_name),
        "subTemplateList" => generate_array_serializer(ie_name),
        "subTemplateMultiList" => generate_array_serializer(ie_name),
        ty => todo!("Unsupported serialization for type: {}", ty),
    };
    ret.push_str(gen.as_str());
    ret
}

pub(crate) fn generate_ie_ser_main(
    iana_ies: &Vec<InformationElement>,
    vendor_prefixes: &[(String, String, u32)],
) -> String {
    let mut ret = String::new();
    ret.push_str("use byteorder::WriteBytesExt;\n\n\n");

    for ie in iana_ies {
        ret.push_str(generate_ie_serializer(&ie.data_type, &ie.name).as_str());
    }

    let ty_name = "Field";
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]\n");
    ret.push_str(format!("pub enum {ty_name}WritingError {{\n").as_str());
    ret.push_str("    StdIOError(#[from_std_io_error] String),\n");
    for (name, pkg, _) in vendor_prefixes {
        ret.push_str(format!("    {name}Error(#[from] {pkg}::FieldWritingError),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(format!("    {}Error(#[from] {}WritingError),\n", ie.name, ie.name).as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str(
        format!(
            "impl netgauze_parse_utils::WritablePDUWithOneInput<Option<u16>, {ty_name}WritingError> for {ty_name} {{\n"
        )
        .as_str(),
    );
    ret.push_str("    const BASE_LENGTH: usize = 0;\n\n");
    ret.push_str("    fn len(&self, length: Option<u16>) -> usize {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown(value) => value.len(),\n");
    for (name, _, _) in vendor_prefixes {
        ret.push_str(format!("            Self::{name}(value) => value.len(length),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(
            format!(
                "            Self::{}(value) => value.len(length),\n",
                ie.name
            )
            .as_str(),
        );
    }

    ret.push_str("         }\n");
    ret.push_str("     }\n\n");
    ret.push_str(format!("     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), {ty_name}WritingError> {{\n").as_str());
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown(value) => writer.write_all(value)?,\n");
    for (name, _pkg, _) in vendor_prefixes {
        ret.push_str(
            format!("            Self::{name}(value) => value.write(writer, length)?,\n").as_str(),
        );
    }
    for ie in iana_ies {
        ret.push_str(
            format!(
                "            Self::{}(value) => value.write(writer, length)?,\n",
                ie.name
            )
            .as_str(),
        );
    }
    ret.push_str("         }\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}
