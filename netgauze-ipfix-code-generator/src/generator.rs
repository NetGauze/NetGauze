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
    format!("#[derive({})]\n", base)
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
            ret.push_str(format!("  /// {}\n", xref).as_str());
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
pub(crate) fn generate_ie_semantics(data_types: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(generate_derive(true, true, true).as_str());
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
            ret.push_str(format!("    /// Reference: {}\n", xref).as_str());
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
    ret.push_str("}\n");
    ret
}

/// Use at the beginning of ie_generated for defining custom types
pub(crate) fn generate_common_types() -> String {
    "pub type MacAddress = [u8; 6];\n\n".to_string()
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
        "           unknown => Ok(InformationElementId::Unknown{pen: unknown, id: code}),\n",
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

    ret.push_str("    fn id(&self) -> u16 {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{id, ..} => *id,\n");
    for (name, _, _) in name_prefixes {
        ret.push_str(format!("            Self::{}(ie) => ie.id(),\n", name).as_str());
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");

    ret.push_str("    fn pen(&self) -> u32 {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{pen, ..} => *pen,\n");
    for (name, _, _) in name_prefixes {
        ret.push_str(format!("            Self::{}(ie) => ie.pen(),\n", name).as_str());
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");

    ret.push_str("}\n\n");
    ret
}

fn generate_ie_record_enum_for_ie(name_prefixes: &Vec<(String, String, u32)>) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str(generate_derive(false, false, false).as_str());
    ret.push_str("pub enum Record {\n");
    ret.push_str("    Unknown(Vec<u8>),\n");
    for (name, pkg, _) in name_prefixes {
        ret.push_str(format!("    {}({}::Record),\n", name, pkg).as_str());
    }
    ret.push_str("}\n\n");
    ret
}

pub(crate) fn generate_ie_ids(name_prefixes: &Vec<(String, String, u32)>) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str(generate_derive(false, true, true).as_str());
    ret.push_str("pub enum InformationElementId {\n");
    for (name, pkg, _) in name_prefixes {
        ret.push_str("    Unknown{pen: u32, id: u16},\n");
        ret.push_str(format!("    {}({}::InformationElementId),\n", name, pkg).as_str());
    }
    ret.push_str("}\n");

    ret.push_str(generate_derive(false, true, true).as_str());
    ret.push_str("pub enum InformationElementIdError {\n");
    for (name, pkg, _) in name_prefixes {
        ret.push_str(format!("    {}({}::UndefinedInformationElementId),\n", name, pkg).as_str());
    }
    ret.push_str("}\n");

    ret.push_str(generate_ie_try_from_pen_code(name_prefixes).as_str());
    ret.push_str(generate_ie_template_trait_for_ie(name_prefixes).as_str());
    ret.push_str(generate_ie_record_enum_for_ie(name_prefixes).as_str());

    ret
}

/// Held out temporary, we might not need this
#[allow(dead_code)]
fn generate_ie_value_converters(rust_type: &str, ie_name: &String) -> String {
    let mut ret = String::new();
    match rust_type {
        "u8" => {
            ret.push_str(format!("impl From<[u8; 1]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0])\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u8> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: u8) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u16" => {
            ret.push_str(format!("impl From<[u8; 1]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u16)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        Self(u16::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u16> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: u16) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u32" => {
            ret.push_str(format!("impl From<[u8; 1]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u32)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u32)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 4]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
            ret.push_str("        Self(u32::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u32> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: u32) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u64" => {
            ret.push_str(format!("impl From<[u8; 1]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 4]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
            ret.push_str("        let tmp = u32::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 8]> for {} {{\n", ie_name).as_str());
            ret.push_str("    fn from(value: [u8; 8]) -> Self {\n");
            ret.push_str("        Self(u64::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");

            ret.push_str(format!("impl From<u64> for {} {{\n", ie_name).as_str());
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
    ret.push_str(format!("pub enum {}ParsingError {{\n", ty_name).as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    ret.push_str("    InvalidLength(u16),\n");
    ret.push_str("}\n\n");
    ret
}

fn get_deserializer_header(ty_name: &str) -> String {
    let mut header = format!("impl<'a> netgauze_parse_utils::ReadablePDUWithOneInput<'a, u16, Located{}ParsingError<'a>> for {} {{\n", ty_name, ty_name);
    header.push_str(format!("    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, Located{}ParsingError<'a>> {{\n", ty_name).as_str());
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
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                (buf, value as u32)\n");
    ret.push_str("            }\n");
    ret.push_str("            2 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_u16(buf)?;\n");
    ret.push_str("                (buf, value as u32)\n");
    ret.push_str("            }\n");
    ret.push_str("            4 => nom::number::complete::be_u32(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                (buf, value as u64)\n");
    ret.push_str("            }\n");
    ret.push_str("            2 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_u16(buf)?;\n");
    ret.push_str("                (buf, value as u64)\n");
    ret.push_str("            }\n");
    ret.push_str("            4 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("                (buf, value as u64)\n");
    ret.push_str("            }\n");
    ret.push_str("            8 => nom::number::complete::be_u64(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_i8(buf)?;\n");
    ret.push_str("                (buf, value as i16)\n");
    ret.push_str("            }\n");
    ret.push_str("            2 => nom::number::complete::be_i16(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_i8(buf)?;\n");
    ret.push_str("                (buf, value as i32)\n");
    ret.push_str("            }\n");
    ret.push_str("            2 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_i16(buf)?;\n");
    ret.push_str("                (buf, value as i32)\n");
    ret.push_str("            }\n");
    ret.push_str("            4 => nom::number::complete::be_i32(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str("        let (buf, value) = match length {\n");
    ret.push_str("            1 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_i8(buf)?;\n");
    ret.push_str("                (buf, value as i64)\n");
    ret.push_str("            }\n");
    ret.push_str("            2 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_i16(buf)?;\n");
    ret.push_str("                (buf, value as i64)\n");
    ret.push_str("            }\n");
    ret.push_str("            4 => {\n");
    ret.push_str("                let (buf, value) = nom::number::complete::be_i32(buf)?;\n");
    ret.push_str("                (buf, value as i64)\n");
    ret.push_str("            }\n");
    ret.push_str("            8 => nom::number::complete::be_i64(buf)?,\n");
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str(format!("            _ => return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))))\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str(format!("        Ok((buf, {}(value != 0)))\n", ie_name).as_str());
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
    ret.push_str(format!("            return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))));\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, b0) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b1) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b2) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b3) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b4) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("        let (buf, b5) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str(format!("        Ok((buf, {}([b0, b1, b2, b3, b4, b5])))\n", ie_name).as_str());
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
    string_error.push_str(format!("pub enum {}ParsingError {{\n", ie_name).as_str());
    string_error.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    string_error.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    string_error.push_str("    FromUtf8Error(String),\n");
    string_error.push_str("}\n\n");

    string_error.push_str("impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::string::FromUtf8Error>\n");
    string_error.push_str(format!("for Located{}ParsingError<'a>\n", ie_name).as_str());
    string_error.push_str("{\n");
    string_error.push_str("    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::string::FromUtf8Error) -> Self {\n");
    string_error.push_str(format!("        Located{}ParsingError::new(\n", ie_name).as_str());
    string_error.push_str("            input,\n");
    string_error.push_str(
        format!(
            "            {}ParsingError::FromUtf8Error(error.to_string()),\n",
            ie_name
        )
        .as_str(),
    );
    string_error.push_str("        )\n");
    string_error.push_str("    }\n");
    string_error.push_str("}\n");

    ret.push_str(string_error.as_str());
    ret.push_str(header.as_str());

    ret.push_str("        let (buf, value) =\n");
    ret.push_str("            nom::combinator::map_res(nom::bytes::complete::take(length), |x: netgauze_parse_utils::Span<'_>| {\n");
    ret.push_str("                String::from_utf8(x.to_vec())\n");
    ret.push_str("            })(buf)?;\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str(format!("            return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))));\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, ip) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("        let value = std::net::Ipv4Addr::from(ip);\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
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
    ret.push_str(format!("            return Err(nom::Err::Error(Located{}ParsingError::new(buf, {}ParsingError::InvalidLength(length))));\n", ie_name, ie_name).as_str());
    ret.push_str("        };\n");
    ret.push_str("        let (buf, ip) = nom::number::complete::be_u128(buf)?;\n");
    ret.push_str("        let value = std::net::Ipv6Addr::from(ip);\n");
    ret.push_str(format!("        Ok((buf, {}(value)))\n", ie_name).as_str());
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

fn generate_ie_deserializer(data_type: &str, ie_name: &String) -> String {
    let mut ret = String::new();
    let gen = match data_type {
        "octetArray" => "".to_string(),
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
        "dateTimeSeconds" => "".to_string(),
        "dateTimeMilliseconds" => "".to_string(),
        "dateTimeMicroseconds" => "".to_string(),
        "dateTimeNanoseconds" => "".to_string(),
        "ipv4Address" => generate_ipv4_deserializer(ie_name),
        "ipv6Address" => generate_ipv6_deserializer(ie_name),
        "basicList" => "".to_string(),
        "subTemplateList" => "".to_string(),
        "subTemplateMultiList" => "".to_string(),
        ty => todo!("Unsupported deserialization for type: {}", ty),
    };
    ret.push_str(gen.as_str());
    ret
}

pub(crate) fn generate_pkg_ie_deserializers(ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    ret.push_str(format!("use crate::ie::{}::*;\n\n", "iana").as_str());

    for ie in ies {
        ret.push_str(generate_ie_deserializer(&ie.data_type, &ie.name).as_str());
    }

    ret.push_str(generate_ie_values_deserializers(ies).as_str());
    ret
}

fn generate_records_enum(ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str(generate_derive(false, false, false).as_str());
    ret.push_str("pub enum Record {\n");
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
    ret.push_str(generate_records_enum(ies).as_str());
    ret
}

fn generate_ie_values_deserializers(ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    let ty_name = "Record";
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {}ParsingError {{\n", ty_name).as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    for ie in ies {
        // TODO don't skip data types once we deserialize all of them
        let rust_type = get_rust_type(&ie.data_type);
        if rust_type.as_str() == "chrono::DateTime<chrono::Utc>" || rust_type.as_str() == "Vec<u8>"
        {
            continue;
        }
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

    ret.push_str(format!("impl<'a> netgauze_parse_utils::ReadablePDUWithTwoInputs<'a, &InformationElementId, u16, Located{}ParsingError<'a>>\n", ty_name).as_str());
    ret.push_str(format!("for {} {{\n", ty_name).as_str());
    ret.push_str("    fn from_wire(\n");
    ret.push_str("        buf: netgauze_parse_utils::Span<'a>,\n");
    ret.push_str("        ie: &InformationElementId,\n");
    ret.push_str("        length: u16,\n");
    ret.push_str(format!("    ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, Located{}ParsingError<'a>> {{\n", ty_name).as_str());
    ret.push_str("        let (buf, value) = match ie {\n");
    for ie in ies {
        // TODO don't skip data types once we deserialize all of them
        let rust_type = get_rust_type(&ie.data_type);
        if rust_type.as_str() == "chrono::DateTime<chrono::Utc>" || rust_type.as_str() == "Vec<u8>"
        {
            continue;
        }
        ret.push_str(format!("            InformationElementId::{} => {{\n", ie.name).as_str());
        ret.push_str(format!("                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, Located{}ParsingError<'_>, Located{}ParsingError<'_>, {}>(buf, length)?;\n", ie.name, ty_name, ie.name).as_str());
        ret.push_str(format!("                (buf, Record::{}(value))\n", ie.name).as_str());
        ret.push_str("            }\n");
    }
    ret.push_str("            _ => todo!(\"Handle deser for IE\")\n");
    ret.push_str("        };\n");
    ret.push_str("       Ok((buf, value))\n");
    ret.push_str("    }\n");
    ret.push_str("}\n");
    ret
}

pub(crate) fn generate_ie_record_enum_for_ie_deserializer(
    name_prefixes: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    let ty_name = "Record";
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str(format!("pub enum {}ParsingError {{\n", ty_name).as_str());
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    for (name, pkg, _) in name_prefixes {
        let value_name = format!("{}::RecordParsingError", pkg);
        ret.push_str(
            format!(
                "    {}Error(#[from_located(module = \"\")] {}),\n",
                name, value_name
            )
            .as_str(),
        );
    }
    ret.push_str("}\n");
    ret.push_str("\n\n");

    ret.push_str("impl<'a> netgauze_parse_utils::ReadablePDUWithTwoInputs<'a, &InformationElementId, u16, LocatedRecordParsingError<'a>>\n");
    ret.push_str("for Record {\n");
    ret.push_str("    fn from_wire(\n");
    ret.push_str("        buf: netgauze_parse_utils::Span<'a>,\n");
    ret.push_str("        ie: &InformationElementId,\n");
    ret.push_str("        length: u16,\n");
    ret.push_str("    ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedRecordParsingError<'a>> {\n");
    ret.push_str("        let (buf, value) = match ie {\n");
    for (name, _, _) in name_prefixes {
        ret.push_str(
            format!(
                "            InformationElementId::{}(value_ie) => {{\n",
                name
            )
            .as_str(),
        );
        ret.push_str("                let (buf, value) = netgauze_parse_utils::parse_into_located_two_inputs(buf, value_ie, length)?;\n");
        ret.push_str(
            format!(
                "                (buf, crate::ie::Record::{}(value))\n",
                name
            )
            .as_str(),
        );
        ret.push_str("            }\n");
    }
    ret.push_str("            _ => todo!(),\n");
    ret.push_str("        };\n");
    ret.push_str("        Ok((buf, value))\n");
    ret.push_str("    }\n");
    ret.push_str("}\n");
    ret
}
