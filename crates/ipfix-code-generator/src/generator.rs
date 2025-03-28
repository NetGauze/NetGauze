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
use crate::{
    generator_aggregation::*, generator_sub_registries::*, InformationElement,
    InformationElementSubRegistry, SimpleRegistry, Xref,
};

pub fn generate_derive(
    num_enum: bool,
    from_repr: bool,
    copy: bool,
    eq: bool,
    hash: bool,
    ord: bool,
) -> String {
    let mut base = "".to_string();
    if num_enum {
        base.push_str("strum_macros::Display, ");
    }
    if from_repr {
        base.push_str("strum_macros::FromRepr, ");
    }
    if copy {
        base.push_str("Copy, ");
    }
    if eq {
        base.push_str("Eq, ");
    }
    if hash {
        base.push_str("Hash, ");
    }
    if ord {
        base.push_str("PartialOrd, Ord, ");
    }
    base.push_str("Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize");
    format!("#[derive({base})]\n")
}

/// Convert [Xref] to markdown link
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
        "draft" => Some(format!(
            "[RFC Draft {}](https://datatracker.ietf.org/doc/html/{})",
            xref.data.to_uppercase(),
            xref.data,
        )),
        "person" => None,
        "html" => Some(format!("[{}]({})", xref.data, xref.data)),
        _ => None,
    }
}

/// Generate `InformationElementDataType`
/// Currently we manually write this provide option for user defined types
#[allow(dead_code)]
pub(crate) fn generate_ie_data_type(data_types: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(generate_derive(true, true, true, true, true, false).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum InformationElementDataType {\n");
    for x in data_types {
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
    ret.push_str(generate_derive(true, true, true, true, true, false).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum InformationElementUnits {\n");
    for entry in entries {
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
    ret.push_str(generate_derive(true, true, true, true, true, false).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum InformationElementSemantics {\n");
    for x in data_types {
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
    ret.push_str("impl super::InformationElementTemplate for IE {\n");
    ret.push_str("    fn semantics(&self) -> Option<super::InformationElementSemantics> {\n");
    ret.push_str("        match self {\n");
    for ie in ie {
        ret.push_str(
            format!(
                "            Self::{} => {},\n",
                ie.name,
                ie.data_type_semantics
                    .as_ref()
                    .map_or("None".to_string(), |x| format!(
                        "Some(super::InformationElementSemantics::{x})"
                    ))
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
                ie.units.as_ref().map_or("None".to_string(), |x| format!(
                    "Some(super::InformationElementUnits::{x})"
                ))
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
                ie.range.as_ref().map_or("None".to_string(), |x| {
                    let mut parts = vec![];
                    for part in x.split('-') {
                        parts.push(part);
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
    ret.push_str(generate_derive(false, false, true, true, true, false).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub struct UndefinedIE(pub u16);\n\n");

    ret.push_str("impl From<IE> for u16 {\n");
    ret.push_str("    fn from(value: IE) -> Self {\n");
    ret.push_str("        value as u16\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl TryFrom<u16> for IE {\n");
    ret.push_str("    type Error = UndefinedIE;\n\n");
    ret.push_str("    fn try_from(value: u16) -> Result<Self, Self::Error> {\n");
    ret.push_str("       // Remove Enterprise bit\n");
    ret.push_str("       let value = value & 0x7FFF;\n");
    ret.push_str("       match Self::from_repr(value) {\n");
    ret.push_str("           Some(val) => Ok(val),\n");
    ret.push_str("           None => Err(UndefinedIE(value)),\n");
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
    ret.push_str(generate_derive(true, true, true, true, true, true).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum IE {\n");
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
    ret.push_str(generate_derive(true, true, true, true, true, false).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum InformationElementStatus {\n");
    ret.push_str("    current = 0,\n");
    ret.push_str("    deprecated = 1,\n");
    ret.push_str("}\n\n");
    ret
}

/// Use at the beginning of `ie_generated` for defining custom types
pub(crate) fn generate_common_types() -> String {
    let mut ret = String::new();
    ret.push_str("pub type MacAddress = [u8; 6];\n\n");
    ret.push_str(
        r##"/// A trait to indicate that we can get the [IE] for a given element
pub trait HasIE {
    fn ie(&self) -> IE;
}

"##,
    );
    ret
}

/// `TryFrom` block for  InformationElementId
fn generate_ie_try_from_pen_code(
    iana_ies: &Vec<InformationElement>,
    name_prefixes: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("impl TryFrom<(u32, u16)> for IE {\n");
    ret.push_str("    type Error = IEError;\n\n");
    ret.push_str("    fn try_from(value: (u32, u16)) -> Result<Self, Self::Error> {\n");
    ret.push_str("        let (pen, code) = value;\n");
    ret.push_str("        match pen {\n");
    ret.push_str("            0 => {\n");
    ret.push_str("                match code {\n");
    for ie in iana_ies {
        ret.push_str(
            format!(
                "                    {} =>  Ok(IE::{}),\n",
                ie.element_id, ie.name
            )
            .as_str(),
        );
    }
    ret.push_str("                    _ =>  Err(IEError::UndefinedIANAIE(code)),\n");
    ret.push_str("                }\n");
    ret.push_str("            }\n");
    for (name, pkg, pen) in name_prefixes {
        ret.push_str(format!("            {pen} => {{\n").as_str());
        ret.push_str(format!("                match {pkg}::IE::try_from(code) {{\n").as_str());
        ret.push_str(format!("                    Ok(ie) => Ok(Self::{name}(ie)),\n").as_str());
        ret.push_str(
            format!("                    Err(err) => Err(IEError::{name}(err)),\n").as_str(),
        );
        ret.push_str("                }\n");
        ret.push_str("            }\n");
    }
    ret.push_str("           unknown => Ok(IE::Unknown{pen: unknown, id: code}),\n");
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
    ret.push_str("impl super::InformationElementTemplate for IE {\n");
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
                    .map_or("None".to_string(), |x| format!(
                        "Some(InformationElementSemantics::{x})"
                    ))
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
                ie.units.as_ref().map_or("None".to_string(), |x| format!(
                    "Some(super::InformationElementUnits::{x})"
                ))
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
                ie.range.as_ref().map_or("None".to_string(), |x| {
                    let mut parts = vec![];
                    for part in x.split('-') {
                        parts.push(part);
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
    ret.push_str(generate_derive(true, false, false, true, true, true).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum Field {\n");
    ret.push_str("    Unknown{pen: u32, id: u16, value: Box<[u8]>},\n");
    for (name, pkg, _) in vendors {
        ret.push_str(format!("    {name}({pkg}::Field),\n").as_str());
    }
    for ie in iana_ies {
        if ie.name == "tcpControlBits" {
            ret.push_str(
                format!("    {}(netgauze_iana::tcp::TCPHeaderFlags),\n", ie.name).as_str(),
            );
        } else {
            let rust_type = get_rust_type(&ie.data_type, &ie.name);
            let field_type = if ie.subregistry.is_some() {
                ie.name.clone()
            } else {
                rust_type
            };
            let fuzz = if field_type.contains("Date") {
                "#[cfg_attr(feature = \"fuzz\", arbitrary(with = crate::arbitrary_datetime))] "
            } else {
                ""
            };
            ret.push_str(format!("    {}({fuzz}{field_type}),\n", ie.name).as_str());
        }
    }

    ret.push_str("}\n\n");

    ret.push_str("impl HasIE for Field {\n");
    ret.push_str("    /// Get the [IE] element for a given field\n");
    ret.push_str("    fn ie(&self) -> IE {\n");
    ret.push_str("        match self {\n");
    ret.push_str(
        "            Self::Unknown{pen, id, value: _value} => IE::Unknown{pen: *pen, id: *id},\n",
    );
    for (name, _pkg, _) in vendors {
        ret.push_str(format!("            Self::{name}(x) => IE::{name}(x.ie()),\n").as_str());
    }
    for ie in iana_ies {
        ret.push_str(format!("            Self::{}(_) => IE::{},\n", ie.name, ie.name).as_str());
    }
    ret.push_str("        }\n\n");
    ret.push_str("    }\n\n");
    ret.push_str("}\n\n");

    ret.push_str("#[derive(Debug, Clone, strum_macros::Display)]\n");
    ret.push_str("pub enum FieldConversionError {\n");
    ret.push_str("    InvalidType,\n");
    ret.push_str("}\n\n");
    ret.push_str("impl std::error::Error for FieldConversionError {}\n\n");
    ret.push_str(generate_into_for_field(iana_ies, vendors).as_str());
    ret
}

pub(crate) fn generate_ie_ids(
    iana_ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str(generate_derive(true, false, true, true, true, true).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum IE {\n");
    ret.push_str("    Unknown{pen: u32, id: u16},\n");
    for (name, pkg, _) in vendors {
        ret.push_str(format!("    {name}({pkg}::IE),\n").as_str());
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

    ret.push_str(generate_derive(false, false, true, true, true, false).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum IEError {\n");
    ret.push_str("    UndefinedIANAIE(u16),\n");
    for (name, pkg, _) in vendors {
        ret.push_str(format!("    {name}({pkg}::UndefinedIE),\n").as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str("impl std::fmt::Display for IEError {\n");
    ret.push_str("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::UndefinedIANAIE(id) => write!(f, \"invalid IE id {id}\"),\n");
    for (name, pkg, _) in vendors {
        ret.push_str(
            format!("            Self::{name}(e) => write!(f, \"invalid {pkg} IE {{}}\", e.0),\n")
                .as_str(),
        );
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::error::Error for IEError {}\n\n");

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

fn generate_u8_deserializer(ie_name: &String, enum_subreg: bool) -> String {
    let mut ret = String::new();
    ret.push_str("                let (buf, value) = match length {\n");
    ret.push_str("                    1 => nom::number::complete::be_u8(buf)?,\n");
    ret.push_str(format!("                   _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");

    if enum_subreg {
        ret.push_str(format!("                let enum_val = {ie_name}::from(value);\n").as_str());
        ret.push_str(format!("                (buf, Field::{ie_name}(enum_val))\n").as_str());
    } else if ie_name == "tcpControlBits" {
        ret.push_str("               (buf, netgauze_iana::tcp::TCPHeaderFlags::from(value))\n");
    } else {
        ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    }
    ret.push_str("            }\n");
    ret
}

fn generate_u16_deserializer(ie_name: &String, enum_subreg: bool) -> String {
    let mut ret = String::new();
    ret.push_str("                let (buf, value) = match length {\n");
    ret.push_str("                    1 => {\n");
    ret.push_str(
        "                        let (buf, value) = nom::number::complete::be_u8(buf)?;\n",
    );
    ret.push_str("                        (buf, value as u16)\n");
    ret.push_str("                    }\n");
    ret.push_str("                    2 => nom::number::complete::be_u16(buf)?,\n");
    ret.push_str(format!("                    _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");

    if enum_subreg {
        ret.push_str(format!("                let enum_val = {ie_name}::from(value);\n").as_str());
        ret.push_str(format!("                (buf, Field::{ie_name}(enum_val))\n").as_str());
    } else if ie_name == "tcpControlBits" {
        ret.push_str(format!("                (buf, Field::{ie_name}(netgauze_iana::tcp::TCPHeaderFlags::from(value)))\n").as_str());
    } else {
        ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    }

    ret.push_str("            }\n");
    ret
}

fn generate_u32_deserializer(ie_name: &String, enum_subreg: bool) -> String {
    let mut ret = String::new();
    ret.push_str("                let len = length as usize;\n");
    ret.push_str("                if length > 4 || buf.input_len() < len {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                }\n");
    ret.push_str("                let mut res = 0u32;\n");
    ret.push_str("                for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("                    res = (res << 8) + byte as u32;\n");
    ret.push_str("                }\n");

    if enum_subreg {
        ret.push_str(format!("                let enum_val = {ie_name}::from(res);\n").as_str());
        ret.push_str(
            format!("                (buf.slice(len..), Field::{ie_name}(enum_val))\n").as_str(),
        );
    } else {
        ret.push_str(
            format!("                (buf.slice(len..), Field::{ie_name}(res))\n").as_str(),
        );
    }

    ret.push_str("            }\n");
    ret
}

fn generate_u64_deserializer(ie_name: &String, enum_subreg: bool) -> String {
    let mut ret = String::new();
    ret.push_str("                let len = length as usize;\n");
    ret.push_str("                if length > 8 || buf.input_len() < len {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                }\n");
    ret.push_str("                let mut res = 0u64;\n");
    ret.push_str("                for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("                    res = (res << 8) + byte as u64;\n");
    ret.push_str("                }\n");

    if enum_subreg {
        ret.push_str(format!("                let enum_val = {ie_name}::from(res);\n").as_str());
        ret.push_str(
            format!("                (buf.slice(len..), Field::{ie_name}(enum_val))\n").as_str(),
        );
    } else {
        ret.push_str(
            format!("                (buf.slice(len..), Field::{ie_name}(res))\n").as_str(),
        );
    }

    ret.push_str("            }\n");
    ret
}

fn generate_u256_deserializer(ie_name: &String, enum_subreg: bool) -> String {
    let mut ret = String::new();
    ret.push_str("                let len = length as usize;\n");
    ret.push_str("                if length > 32 || buf.input_len() < len {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                }\n");
    ret.push_str("                let mut ret: [u8; 32] = [0; 32];\n");
    ret.push_str("                ret.copy_from_slice(buf.slice(..8).fragment());\n");
    if enum_subreg {
        ret.push_str(format!("                let enum_val = {ie_name}::from(ret);\n").as_str());
        ret.push_str(
            format!("                (buf.slice(len..), Field::{ie_name}(enum_val))\n").as_str(),
        );
    } else {
        ret.push_str(
            format!("                (buf.slice(len..), Field::{ie_name}(Box::new(ret)))\n")
                .as_str(),
        );
    }

    ret.push_str("            }\n");
    ret
}

fn generate_i8_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let (buf, value) = match length {\n");
    ret.push_str("                    1 => nom::number::complete::be_i8(buf)?,\n");
    ret.push_str(format!("                    _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_i16_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let len = length as usize;\n");
    ret.push_str("                if length > 2 || buf.input_len() < len {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                }\n");
    ret.push_str("                let mut res = 0u16;\n");
    ret.push_str("                let mut first = true;\n");
    ret.push_str("                for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("                    if first {\n");
    ret.push_str("                        if byte & 0x80 != 0 {\n");
    ret.push_str("                            res = u16::MAX;\n");
    ret.push_str("                        }\n");
    ret.push_str("                        first = false;\n");
    ret.push_str("                    }\n");
    ret.push_str("                    res = (res << 8) + byte as u16;\n");
    ret.push_str("                }\n");
    ret.push_str("                (buf.slice(len..), res as i16))\n");
    ret.push_str("            }\n");
    ret
}

fn generate_i32_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let len = length as usize;\n");
    ret.push_str("                if length > 4 || buf.input_len() < len {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                }\n");
    ret.push_str("                let mut res = 0u32;\n");
    ret.push_str("                let mut first = true;\n");
    ret.push_str("                for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("                    if first {\n");
    ret.push_str("                        if byte & 0x80 != 0 {\n");
    ret.push_str("                            res = u32::MAX;\n");
    ret.push_str("                        }\n");
    ret.push_str("                        first = false;\n");
    ret.push_str("                    }\n");
    ret.push_str("                    res = (res << 8) + byte as u32;\n");
    ret.push_str("                }\n");
    ret.push_str(
        format!("                (buf.slice(len..), Field::{ie_name}(res as i32))\n").as_str(),
    );
    ret.push_str("            }\n");
    ret
}

fn generate_i64_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let len = length as usize;\n");
    ret.push_str("                if length > 8 || buf.input_len() < len {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                }\n");
    ret.push_str("                let mut res = 0u64;\n");
    ret.push_str("                let mut first = true;\n");
    ret.push_str("                for byte in buf.iter_elements().take(len) {\n");
    ret.push_str("                    if first {\n");
    ret.push_str("                        if byte & 0x80 != 0 {\n");
    ret.push_str("                            res = u64::MAX;\n");
    ret.push_str("                        }\n");
    ret.push_str("                        first = false;\n");
    ret.push_str("                    }\n");
    ret.push_str("                    res = (res << 8) + byte as u64;\n");
    ret.push_str("                }\n");
    ret.push_str("                (buf.slice(len..), res as i64)\n");
    ret.push_str("            }\n");
    ret
}

fn generate_f32_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let (buf, value) = match length {\n");
    ret.push_str("                    1 => nom::number::complete::be_f32(buf)?,\n");
    ret.push_str(format!("                    _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value.into()))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_f64_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let (buf, value) = match length {\n");
    ret.push_str("                    1 => nom::number::complete::be_f64(buf)?,\n");
    ret.push_str(format!("                    _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value.into()))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_bool_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let (buf, value) = match length {\n");
    ret.push_str("                    1 => nom::number::complete::be_u8(buf)?,\n");
    ret.push_str(format!("                    _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value != 0))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_mac_address_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length != 6 {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str("                let (buf, b0) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                let (buf, b1) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                let (buf, b2) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                let (buf, b3) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                let (buf, b4) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str("                let (buf, b5) = nom::number::complete::be_u8(buf)?;\n");
    ret.push_str(
        format!("                (buf, Field::{ie_name}([b0, b1, b2, b3, b4, b5]))\n").as_str(),
    );
    ret.push_str("            }\n");
    ret
}

fn generate_string_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length == u16::MAX {\n");
    ret.push_str(
        "                    let (buf, short_length) = nom::number::complete::be_u8(buf)?;\n",
    );
    ret.push_str("                    let (buf, variable_length) = if short_length == u8::MAX {\n");
    ret.push_str("                        let mut variable_length: u32= 0;\n");
    ret.push_str(
        "                        let (buf, part1) = nom::number::complete::be_u8(buf)?;\n",
    );
    ret.push_str(
        "                        let (buf, part2) = nom::number::complete::be_u8(buf)?;\n",
    );
    ret.push_str(
        "                        let (buf, part3) = nom::number::complete::be_u8(buf)?;\n",
    );
    ret.push_str(
        "                        variable_length = (variable_length << 8) + part1  as u32;\n",
    );
    ret.push_str(
        "                        variable_length = (variable_length << 8) + part2  as u32;\n",
    );
    ret.push_str(
        "                        variable_length = (variable_length << 8) + part3  as u32;\n",
    );
    ret.push_str("                        (buf, variable_length)\n");
    ret.push_str("                    } else {\n");
    ret.push_str("                        (buf, short_length as u32)\n");
    ret.push_str("                    };\n");
    ret.push_str("                    let (buf, value) = nom::combinator::map_res(nom::bytes::complete::take(variable_length), |str_buf: netgauze_parse_utils::Span<'_>| {\n");
    ret.push_str("                        let result = ::std::str::from_utf8(&str_buf);\n");
    ret.push_str("                        result.map(|x| x.into())\n");
    ret.push_str("                    })(buf)?;\n");
    ret.push_str(format!("                    (buf,  Field::{ie_name}(value))\n").as_str());
    ret.push_str("                } else {\n");
    ret.push_str("                    let (buf, value) =\n");
    ret.push_str("                        nom::combinator::map_res(nom::bytes::complete::take(length), |str_buf: netgauze_parse_utils::Span<'_>| {\n");
    ret.push_str("                            let nul_range_end = str_buf\n");
    ret.push_str("                                .iter()\n");
    ret.push_str("                                .position(|&c| c == b'\0')\n");
    ret.push_str("                                .unwrap_or(str_buf.len());\n");
    ret.push_str("                            let result = ::std::str::from_utf8(&str_buf[..nul_range_end]);\n", );
    ret.push_str("                            result.map(|x| x.into())\n");
    ret.push_str("                        })(buf)?;\n");
    ret.push_str(format!("                    (buf,  Field::{ie_name}(value))\n").as_str());
    ret.push_str("                }\n");
    ret.push_str("            }\n");
    ret
}

fn generate_ipv4_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length != 4 {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str("                let (buf, ip) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("                let value = std::net::Ipv4Addr::from(ip);\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_ipv6_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length != 16 {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str("                let (buf, ip) = nom::number::complete::be_u128(buf)?;\n");
    ret.push_str("                let value = std::net::Ipv6Addr::from(ip);\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_date_time_seconds(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length != 4 {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str("                let (buf, secs) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("                let value = match chrono::Utc.timestamp_opt(secs as i64, 0) {\n");
    ret.push_str("                    chrono::LocalResult::Single(val) => val,\n");
    ret.push_str("                    _ => {\n");
    ret.push_str(format!("                        return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidTimestamp{{ie_name: \"{ie_name}\".to_string(), seconds: secs}})));\n").as_str());
    ret.push_str("                    }\n");
    ret.push_str("                };\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_date_time_milli(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length != 8 {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str("                let (buf, millis) = nom::number::complete::be_u64(buf)?;\n");
    ret.push_str(
        "                let value = match chrono::Utc.timestamp_millis_opt(millis as i64) {\n",
    );
    ret.push_str("                    chrono::LocalResult::Single(val) => val,\n");
    ret.push_str("                    _ => {\n");
    ret.push_str(format!("                        return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidTimestampMillis{{ie_name: \"{ie_name}\".to_string(), millis}})));\n").as_str());
    ret.push_str("                    }\n");
    ret.push_str("                };\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_date_time_micro(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length != 8 {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str("                let (buf, seconds) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("                let (buf, fraction) = nom::number::complete::be_u32(buf)?;\n");
    ret.push_str("                // Convert 1/2^32 of a second to nanoseconds\n");
    ret.push_str(
        "                let f: u32 = (1_000_000_000f64 * (fraction as f64 / u32::MAX as f64)) as u32;\n",
    );
    ret.push_str(
        "                let value = match chrono::Utc.timestamp_opt(seconds as i64, f) {\n",
    );
    ret.push_str("                    chrono::LocalResult::Single(val) => val,\n");
    ret.push_str("                    _ => {\n");
    ret.push_str(format!("                         return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidTimestampFraction{{ie_name: \"{ie_name}\".to_string(), seconds, fraction}})));\n").as_str());
    ret.push_str("                    }\n");
    ret.push_str("                };\n");
    ret.push_str(format!("                (buf, Field::{ie_name}(value))\n").as_str());
    ret.push_str("            }\n");
    ret
}

fn generate_vec_u8_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                let (buf, value) = nom::multi::count(nom::number::complete::be_u8, length as usize)(buf)?;\n");
    ret.push_str(
        format!("                (buf, Field::{ie_name}(value.into_boxed_slice()))\n").as_str(),
    );
    ret.push_str("            }\n");
    ret
}

fn generate_mpls_deserializer(ie_name: &String) -> String {
    let mut ret = String::new();
    ret.push_str("                if length != 3 {\n");
    ret.push_str(format!("                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{{ie_name: \"{ie_name}\".to_string(), length}})))\n").as_str());
    ret.push_str("                };\n");
    ret.push_str("                let (buf, value) = nom::multi::count(nom::number::complete::be_u8, length as usize)(buf)?;\n");
    ret.push_str(
        format!("                (buf, Field::{ie_name}([value[0], value[1], value[2]]))\n")
            .as_str(),
    );
    ret.push_str("            }\n");
    ret
}

fn generate_ie_deserializer(data_type: &str, ie_name: &String, enum_subreg: bool) -> String {
    let mut ret = String::new();
    let gen = match data_type {
        "octetArray" => {
            if is_mpls_type(ie_name) {
                generate_mpls_deserializer(ie_name)
            } else {
                generate_vec_u8_deserializer(ie_name)
            }
        }
        "unsigned8" => generate_u8_deserializer(ie_name, enum_subreg),
        "unsigned16" => generate_u16_deserializer(ie_name, enum_subreg),
        "unsigned32" => generate_u32_deserializer(ie_name, enum_subreg),
        "unsigned64" => generate_u64_deserializer(ie_name, enum_subreg),
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
        "unsigned256" => generate_u256_deserializer(ie_name, enum_subreg),
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
    // Not every vendor contains big integer types
    if ies.iter().any(|x| {
        [
            "unsigned32",
            "unsigned64",
            "signed16",
            "signed32",
            "signed64",
        ]
        .contains(&x.data_type.as_str())
    }) {
        ret.push_str("use nom::{InputIter, InputLength, Slice};\n");
    }
    // Not every vendor is using time based values
    if ies.iter().any(|x| x.data_type.contains("Time")) {
        ret.push_str("use chrono::TimeZone;\n");
    }
    ret.push_str(format!("use crate::ie::{vendor_mod}::*;\n\n").as_str());
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

    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]\n");
    ret.push_str("pub enum FieldWritingError {\n");
    ret.push_str("    StdIOError(#[from_std_io_error] String),\n");
    ret.push_str("    InvalidLength{ie_name: String, length: u16},\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::fmt::Display for FieldWritingError {\n");
    ret.push_str("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::StdIOError(err) => write!(f, \"{err}\"),\n");
    ret.push_str("            Self::InvalidLength{ie_name, length} => write!(f, \"writing error of {ie_name} invalid length {length}\"),\n");
    ret.push_str("        }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::error::Error for FieldWritingError {}\n\n");

    ret.push_str("impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {\n");
    ret.push_str("    const BASE_LENGTH: usize = 0;\n\n");
    ret.push_str("    fn len(&self, length: Option<u16>) -> usize {\n");
    ret.push_str("        match self {\n");
    for ie in ies {
        match ie.data_type.as_str() {
            "octetArray" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "unsigned8" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                1\n");
            }
            "unsigned16" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 2,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "unsigned32" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 4,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "unsigned64" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 8,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "signed8" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                1\n");
            }
            "signed16" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 2,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "signed32" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 4,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "signed64" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 8,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "float32" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 4,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "float64" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 8,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "boolean" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                1\n");
            }
            "macAddress" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "string" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => value.len(),\n");
                ret.push_str("                    Some(len) => if len == u16::MAX {\n");
                ret.push_str("                        if value.len() < u8::MAX as usize {\n");
                ret.push_str("                            // One octet for the length field\n");
                ret.push_str("                            value.len() + 1\n");
                ret.push_str("                        } else {\n");
                ret.push_str("                            // 4 octets for the length field, first is 255 and other three carries the len\n");
                ret.push_str("                            value.len() + 4\n");
                ret.push_str("                        }\n");
                ret.push_str("                    } else {\n");
                ret.push_str("                        len as usize\n");
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "dateTimeSeconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                4\n");
            }
            "dateTimeMilliseconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                8\n");
            }
            "dateTimeMicroseconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                8\n");
            }
            "dateTimeNanoseconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                8\n");
            }
            "ipv4Address" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                4\n");
            }
            "ipv6Address" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                16\n");
            }
            "basicList" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "subTemplateList" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "subTemplateMultiList" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "unsigned256" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
        ret.push_str("            }\n");
    }
    ret.push_str("         }\n");
    ret.push_str("     }\n\n");
    ret.push_str("    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {\n");
    ret.push_str("        match self {\n");
    for ie in ies {
        ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
        match ie.data_type.as_str() {
            "octetArray" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "unsigned8" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let num_val = u8::from(*value);\n");
                    ret.push_str("                writer.write_u8(num_val)?\n");
                } else {
                    ret.push_str("                writer.write_u8(*value)?\n");
                }
            }
            "unsigned16" => {
                if ie.subregistry.is_some() || ie.name == "tcpControlBits" {
                    ret.push_str("                let value = u16::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_u16::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "unsigned32" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = u32::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_u32::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "unsigned64" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = u64::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_u64::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "signed8" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let num_val = i8::from(*value);\n");
                    ret.push_str("                writer.write_i8(num_val)?\n");
                } else {
                    ret.push_str("                writer.write_i8(*value)?\n");
                }
            }
            "signed16" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = i16::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_i16::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "signed32" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = i32::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_i32::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "signed64" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = i64::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_i64::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "float32" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = f32::from(*value);\n");
                } else {
                    ret.push_str("                let value = value.0;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_f32::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "float64" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = f64::from(value.0);\n");
                } else {
                    ret.push_str("                let value = value.0;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_f64::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "boolean" => {
                ret.push_str("                writer.write_u8(*value as u8)?\n");
            }
            "macAddress" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "string" => {
                ret.push_str("                match length {\n");
                ret.push_str("                    Some(u16::MAX) | None => {\n");
                ret.push_str("                        let bytes = value.as_bytes();\n");
                ret.push_str("                        if bytes.len() < u8::MAX as usize {\n");
                ret.push_str("                            writer.write_u8(bytes.len() as u8)?;\n");
                ret.push_str("                        } else {\n");
                ret.push_str("                            writer.write_u8(u8::MAX)?;\n");
                ret.push_str("                            writer.write_all(&bytes.len().to_be_bytes()[1..])?;\n");
                ret.push_str("                        }\n");
                ret.push_str("                        writer.write_all(value.as_bytes())?;\n");
                ret.push_str("                    }\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        writer.write_all(value.as_bytes())?;\n");
                ret.push_str("                        // fill the rest with zeros\n");
                ret.push_str("                        for _ in value.len()..(len as usize) {\n");
                ret.push_str("                            writer.write_u8(0)?\n");
                ret.push_str("                        }\n");
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "dateTimeSeconds" => {
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;\n");
            }
            "dateTimeMilliseconds" => {
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;\n", );
                ret.push_str("                let nanos = value.timestamp_subsec_nanos();\n");
                ret.push_str("                // Convert 1/2**32 of a second to a fraction of a nano second\n");
                ret.push_str("                let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;\n");
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;\n");
            }
            "dateTimeMicroseconds" => {
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;\n", );
                ret.push_str("                let nanos = value.timestamp_subsec_nanos();\n");
                ret.push_str("                // Convert 1/2**32 of a second to a fraction of a nano second\n");
                ret.push_str("                let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;\n");
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;\n");
            }
            "dateTimeNanoseconds" => {
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;\n", );
                ret.push_str("                let nanos = value.timestamp_subsec_nanos();\n");
                ret.push_str("                // Convert 1/2**32 of a second to a fraction of a nano second\n");
                ret.push_str("                let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;\n");
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;\n");
            }
            "ipv4Address" => {
                ret.push_str("                writer.write_all(&value.octets())?\n");
            }
            "ipv6Address" => {
                ret.push_str("                writer.write_all(&value.octets())?\n");
            }
            "basicList" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "subTemplateList" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "subTemplateMultiList" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "unsigned256" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
        ret.push_str("            }\n");
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
        get_rust_type(&x.data_type, &x.name) == "Box<[u8]>"
            || get_rust_type(&x.data_type, &x.name) == "Box<str>"
    });
    ret.push_str(generate_derive(true, false, !not_copy, true, true, true).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum Field {\n");
    for ie in ies {
        let rust_type = get_rust_type(&ie.data_type, &ie.name);
        let field_type = if ie.subregistry.is_some() {
            ie.name.clone()
        } else {
            rust_type
        };
        ret.push_str(format!("    {}({field_type}),\n", ie.name).as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str("impl Field {\n");
    ret.push_str("    /// Get the [IE] element for a given field\n");
    ret.push_str("    pub const fn ie(&self) -> IE {\n");
    ret.push_str("        match self {\n");
    for ie in ies {
        ret.push_str(format!("            Self::{}(_) => IE::{},\n", ie.name, ie.name).as_str());
    }
    ret.push_str("        }\n\n");
    ret.push_str("    }\n\n");
    ret.push_str("}\n\n");

    ret.push_str(generate_into_for_field(ies, &vec![]).as_str());

    ret
}

/// Generates `impl TryInto<NativeRustType> for Field` to convert any field to
/// its native rust type Additionally for fields that could be represented as
/// String, a TryInto is generated Some special formatting is applied for
/// MacAddress to make it human-readable.
pub fn generate_into_for_field(
    ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    // note this list is the inverse of what is defined in `get_rust_type`
    let rust_converted_types = [
        "u8",
        "u16",
        "u32",
        "u64",
        "i8",
        "i16",
        "i32",
        "i64",
        "ordered_float::OrderedFloat<f32>",
        "ordered_float::OrderedFloat<f64>",
        "bool",
        "super::MacAddress",
        "String",
        "chrono::DateTime<chrono::Utc>",
        "std::net::Ipv4Addr",
        "std::net::Ipv6Addr",
        "Box<[u8]>",
        "Box<[u8; 32]>",
        "Vec<String>",
    ];
    for convert_rust_type in rust_converted_types {
        ret.push_str(format!("impl TryInto<{convert_rust_type}> for Field {{\n").as_str());
        ret.push_str("    type Error = crate::FieldConversionError;\n\n");
        ret.push_str(
            format!("    fn try_into(self) -> Result<{convert_rust_type}, Self::Error> {{\n")
                .as_str(),
        );
        ret.push_str("        match self {\n");
        if !vendors.is_empty() {
            // only IANA have unknown, thus we check vendor is not configured
            ret.push_str("            Self::Unknown{ .. } => Err(Self::Error::InvalidType),\n");
        }
        for (name, _pkg, _) in vendors {
            ret.push_str(
                format!("            Self::{name}(value) => value.try_into(),\n").as_str(),
            );
        }
        for ie in ies {
            let ie_rust_type = get_rust_type(&ie.data_type, &ie.name);
            if ie_rust_type == convert_rust_type
                && ie.subregistry.is_none()
                && ie.name != "tcpControlBits"
            {
                // Native type converstion
                ret.push_str(
                    format!("            Self::{}(value) => Ok(value),\n", ie.name).as_str(),
                );
            } else if convert_rust_type == "String"
                && ie_rust_type != "Box<[u8]>"
                && ie_rust_type != "[u8; 3]"
                && ie_rust_type != "Box<[u8; 32]>"
                && ie_rust_type != "super::MacAddress"
            {
                // Convert to using the defined Display implementation of the method
                ret.push_str(
                    format!(
                        "            Self::{}(value) => Ok(format!(\"{{value}}\")),\n",
                        ie.name
                    )
                    .as_str(),
                );
            } else if convert_rust_type == "String" && ie_rust_type == "super::MacAddress" {
                // convert MacAddresses to human-readable string
                ret.push_str(format!("            Self::{}(value) => Ok(value.iter().map(|x| format!(\"{{x:x}}\")).collect::<Vec<_>>().join(\":\").to_string()),\n", ie.name).as_str());
            } else if convert_rust_type == "Vec<String>" && ie.name == "tcpControlBits" {
                ret.push_str(
                    format!(
                        "            Self::{}(value) => Ok(value.to_vec()),\n",
                        ie.name
                    )
                    .as_str(),
                );
            } else if convert_rust_type == "String" && is_mpls_type(&ie.name) {
                ret.push_str(format!("            Self::{}(value) => Ok(u32::from_be_bytes([0, value[0], value[1], value[2]]).to_string()),\n", ie.name).as_str());
            } else {
                ret.push_str(
                    format!(
                        "            Self::{}(_) => Err(Self::Error::InvalidType),\n",
                        ie.name
                    )
                    .as_str(),
                );
            }
        }
        ret.push_str("        }\n");
        ret.push_str("    }\n");
        ret.push_str("}\n\n");
    }
    ret
}

pub fn get_rust_type(data_type: &str, ie_name: &str) -> String {
    let rust_type = match data_type {
        "octetArray" => "Box<[u8]>",
        "unsigned8" => "u8",
        "unsigned16" => "u16",
        "unsigned32" => "u32",
        "unsigned64" => "u64",
        "signed8" => "i8",
        "signed16" => "i16",
        "signed32" => "i32",
        "signed64" => "i64",
        "float32" => "ordered_float::OrderedFloat<f32>",
        "float64" => "ordered_float::OrderedFloat<f64>",
        "boolean" => "bool",
        "macAddress" => "super::MacAddress",
        "string" => "Box<str>",
        "dateTimeSeconds"
        | "dateTimeMilliseconds"
        | "dateTimeMicroseconds"
        | "dateTimeNanoseconds" => "chrono::DateTime<chrono::Utc>",
        "ipv4Address" => "std::net::Ipv4Addr",
        "ipv6Address" => "std::net::Ipv6Addr",
        "basicList" | "subTemplateList" | "subTemplateMultiList" => "Box<[u8]>",
        "unsigned256" => "Box<[u8; 32]>",
        other => todo!("Implement rust data type conversion for {}", other),
    };
    if is_mpls_type(ie_name) {
        "[u8; 3]".to_string()
    } else {
        rust_type.to_string()
    }
}

fn is_mpls_type(ie_name: &str) -> bool {
    ie_name.eq("mplsTopLabelStackSection") || ie_name.starts_with("mplsLabelStackSection")
}

pub(crate) fn generate_ie_values(
    ies: &Vec<InformationElement>,
    vendor_name: Option<String>,
) -> String {
    let mut ret = String::new();
    for ie in ies {
        let rust_type = get_rust_type(&ie.data_type, &ie.name);

        // Check if we have an InformationElementSubRegistry and is of type
        // ValueNameDescRegistry
        let strum_macros = matches!(
            ie.subregistry.as_ref().and_then(|v| v.first()),
            Some(InformationElementSubRegistry::ValueNameDescRegistry(_))
        );
        let gen_derive = generate_derive(
            true,
            strum_macros,
            rust_type != "Box<[u8]>" && rust_type != "Box<str>",
            true,
            true,
            true,
        );

        if let Some(ie_subregistry) = &ie.subregistry {
            ret.push_str("#[allow(non_camel_case_types)]\n");
            ret.push_str(gen_derive.as_str());
            ret.push_str(
                generate_subregistry_enum_and_impl(&ie.name, &rust_type, ie_subregistry).as_str(),
            );
            match &vendor_name {
                None => {
                    ret.push_str(format!("impl HasIE for {} {{\n", ie.name).as_str());
                    ret.push_str("    fn ie(&self) -> IE {\n");
                    ret.push_str(format!("        IE::{}\n", ie.name).as_str());
                    ret.push_str("   }\n");
                    ret.push_str("}\n\n");
                }
                Some(name) => {
                    ret.push_str(format!("impl crate::HasIE for {} {{\n", ie.name).as_str());
                    ret.push_str("    fn ie(&self) -> crate::IE {\n");
                    ret.push_str(format!("        crate::IE::{name}(IE::{})\n", ie.name).as_str());
                    ret.push_str("   }\n");
                    ret.push_str("}\n\n");
                }
            }
        } else if ie.name == "tcpControlBits" {
            ret.push_str("impl HasIE for netgauze_iana::tcp::TCPHeaderFlags {\n");
            ret.push_str("    fn ie(&self) -> IE {\n");
            ret.push_str(format!("        IE::{}\n", ie.name).as_str());
            ret.push_str("   }\n");
            ret.push_str("}\n\n");
        }

        // TODO: check if value converters are needed
        // ret.push_str(generate_ie_value_converters(&rust_type,
        // &ie.name).as_str());
    }
    ret
}

fn generate_ie_values_deserializers(ies: &Vec<InformationElement>) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str("pub enum FieldParsingError {\n");
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    ret.push_str("    InvalidLength{ie_name: String, length: u16},\n");
    ret.push_str("    InvalidTimestamp{ie_name: String, seconds: u32},\n");
    ret.push_str("    InvalidTimestampMillis{ie_name: String, millis: u64},\n");
    ret.push_str("    InvalidTimestampFraction{ie_name: String, seconds: u32, fraction: u32},\n");
    ret.push_str("    Utf8Error(String),\n");
    ret.push_str("}\n");
    ret.push_str("\n\n");

    ret.push_str("impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error>\n");
    ret.push_str("for LocatedFieldParsingError<'a>\n");
    ret.push_str("{\n");
    ret.push_str("    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {\n");
    ret.push_str("        LocatedFieldParsingError::new(\n");
    ret.push_str("            input,\n");
    ret.push_str("            FieldParsingError::Utf8Error(error.to_string()),\n");
    ret.push_str("        )\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::fmt::Display for FieldParsingError {\n");
    ret.push_str("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n");
    ret.push_str("        match self {\n");
    ret.push_str(
        "           Self::NomError(err) => write!(f, \"Nom error {}\", nom::Err::Error(err)),\n",
    );
    #[allow(clippy::literal_string_with_formatting_args)]
    ret.push_str("           Self::InvalidLength{ie_name, length} => write!(f, \"error parsing {ie_name} invalid field length {length}\"),\n", );
    ret.push_str("           Self::InvalidTimestamp{ie_name, seconds} => write!(f, \"error parsing {ie_name} invalid timestamp {seconds}\"),\n", );
    ret.push_str("           Self::InvalidTimestampMillis{ie_name, millis} => write!(f, \"error parsing {ie_name} invalid timestamp {millis}\"),\n", );
    ret.push_str("           Self::InvalidTimestampFraction{ie_name, seconds, fraction} => write!(f, \"error parsing {ie_name} invalid timestamp fraction ({seconds}, {fraction})\"),\n");
    ret.push_str("           Self::Utf8Error(val) => write!(f, \"utf8 error {val}\"),\n");
    ret.push_str("        }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::error::Error for FieldParsingError {}\n\n");

    ret.push_str("impl<'a> netgauze_parse_utils::ReadablePduWithTwoInputs<'a, &IE, u16, LocatedFieldParsingError<'a>>\n");
    ret.push_str("for Field {\n");
    ret.push_str("    #[inline]\n");
    ret.push_str("    fn from_wire(\n");
    ret.push_str("        buf: netgauze_parse_utils::Span<'a>,\n");
    ret.push_str("        ie: &IE,\n");
    ret.push_str("        length: u16,\n");
    ret.push_str("    ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedFieldParsingError<'a>> {\n");
    ret.push_str("        let (buf, value) = match ie {\n");
    for ie in ies {
        ret.push_str(format!("            IE::{} => {{\n", ie.name).as_str());
        ret.push_str(&generate_ie_deserializer(
            &ie.data_type,
            &ie.name,
            ie.subregistry.is_some(),
        ));
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
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]\n");
    ret.push_str("pub enum FieldParsingError {\n");
    ret.push_str("    #[serde(with = \"netgauze_parse_utils::ErrorKindSerdeDeref\")]\n");
    ret.push_str("    NomError(#[from_nom] nom::error::ErrorKind),\n");
    ret.push_str("    UnknownInformationElement(IE),\n");
    for (name, pkg, _) in vendor_prefixes {
        let value_name = format!("{pkg}::FieldParsingError");
        ret.push_str(
            format!("    {name}Error(#[from_located(module = \"\")] {value_name}),\n").as_str(),
        );
    }
    ret.push_str("    InvalidLength{ie_name: String, length: u16},\n");
    ret.push_str("    InvalidTimestamp{ie_name: String, seconds: u32},\n");
    ret.push_str("    InvalidTimestampMillis{ie_name: String, millis: u64},\n");
    ret.push_str("    InvalidTimestampFraction{ie_name: String, seconds: u32, fraction: u32},\n");
    ret.push_str("    Utf8Error(String),\n");
    ret.push_str("}\n");
    ret.push_str("\n\n");

    ret.push_str("impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error>\n");
    ret.push_str("for LocatedFieldParsingError<'a>\n");
    ret.push_str("{\n");
    ret.push_str("    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {\n");
    ret.push_str("        LocatedFieldParsingError::new(\n");
    ret.push_str("            input,\n");
    ret.push_str("            FieldParsingError::Utf8Error(error.to_string()),\n");
    ret.push_str("        )\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::fmt::Display for FieldParsingError {\n");
    ret.push_str("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n");
    ret.push_str("        match self {\n");
    ret.push_str(
        "           Self::NomError(err) => write!(f, \"Nom error {}\", nom::Err::Error(err)),\n",
    );
    #[allow(clippy::literal_string_with_formatting_args)]
    ret.push_str("           Self::UnknownInformationElement(ie) => write!(f, \"unknown information element {ie:?}\"),\n");
    for (name, _pkg, _) in vendor_prefixes {
        ret.push_str(
            format!("           Self::{name}Error(err) => write!(f, \"{{err}}\"),\n").as_str(),
        );
    }
    ret.push_str("           Self::InvalidLength{ie_name, length} => write!(f, \"error parsing {ie_name} invalid field length {length}\"),\n", );
    ret.push_str("           Self::InvalidTimestamp{ie_name, seconds} => write!(f, \"error parsing {ie_name} invalid timestamp {seconds}\"),\n", );
    ret.push_str("           Self::InvalidTimestampMillis{ie_name, millis} => write!(f, \"error parsing {ie_name} invalid timestamp {millis}\"),\n", );
    ret.push_str("           Self::InvalidTimestampFraction{ie_name, seconds, fraction} => write!(f, \"error parsing {ie_name} invalid timestamp fraction ({seconds}, {fraction})\"),\n");
    ret.push_str("           Self::Utf8Error(val) => write!(f, \"utf8 error {val}\"),\n");
    ret.push_str("        }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::error::Error for FieldParsingError {}\n\n");

    ret.push_str("impl<'a> netgauze_parse_utils::ReadablePduWithTwoInputs<'a, &IE, u16, LocatedFieldParsingError<'a>>\n");
    ret.push_str("for Field {\n");
    ret.push_str("    #[inline]\n");
    ret.push_str("    fn from_wire(\n");
    ret.push_str("        buf: netgauze_parse_utils::Span<'a>,\n");
    ret.push_str("        ie: &IE,\n");
    ret.push_str("        length: u16,\n");
    ret.push_str("    ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedFieldParsingError<'a>> {\n");
    ret.push_str("        let (buf, value) = match ie {\n");
    for (name, _, _) in vendor_prefixes {
        ret.push_str(format!("            IE::{name}(value_ie) => {{\n").as_str());
        ret.push_str("                let (buf, value) = netgauze_parse_utils::parse_into_located_two_inputs(buf, value_ie, length)?;\n");
        ret.push_str(format!("                (buf, crate::ie::Field::{name}(value))\n").as_str());
        ret.push_str("            }\n");
    }
    for ie in iana_ies {
        ret.push_str(format!("            IE::{} => {{\n", ie.name).as_str());
        ret.push_str(&generate_ie_deserializer(
            &ie.data_type,
            &ie.name,
            ie.subregistry.is_some(),
        ));
    }
    ret.push_str("            ie => {\n");
    ret.push_str("                // todo Handle unknown IEs\n");
    ret.push_str("                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::UnknownInformationElement(*ie))))\n");
    ret.push_str("            }\n");
    ret.push_str("        };\n");
    ret.push_str("        Ok((buf, value))\n");
    ret.push_str("    }\n");
    ret.push_str("}\n");

    ret
}

pub(crate) fn generate_ie_ser_main(
    iana_ies: &Vec<InformationElement>,
    vendor_prefixes: &[(String, String, u32)],
) -> String {
    let mut ret = String::new();
    ret.push_str("use byteorder::WriteBytesExt;\n\n\n");

    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]\n");
    ret.push_str("pub enum FieldWritingError {\n");
    ret.push_str("    StdIOError(#[from_std_io_error] String),\n");
    for (name, pkg, _) in vendor_prefixes {
        ret.push_str(format!("    {name}Error(#[from] {pkg}::FieldWritingError),\n").as_str());
    }
    ret.push_str("    InvalidLength{ie_name: String, length: u16},\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::fmt::Display for FieldWritingError {\n");
    ret.push_str("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::StdIOError(err) => write!(f, \"{err}\"),\n");
    for (name, pkg, _) in vendor_prefixes {
        ret.push_str(format!("            Self::{name}Error(err) => write!(f, \"writing error of {pkg}{{err}}\"),\n").as_str());
    }
    ret.push_str("            Self::InvalidLength{ie_name, length} => write!(f, \"writing error of {ie_name} invalid length {length}\"),\n");
    ret.push_str("        }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl std::error::Error for FieldWritingError {}\n\n");

    ret.push_str("impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {\n");
    ret.push_str("    const BASE_LENGTH: usize = 0;\n\n");
    ret.push_str("    fn len(&self, length: Option<u16>) -> usize {\n");
    ret.push_str("        match self {\n");
    ret.push_str("            Self::Unknown{pen: _pen, id: _id, value} => value.len(),\n");
    for (name, _, _) in vendor_prefixes {
        ret.push_str(format!("            Self::{name}(value) => value.len(length),\n").as_str());
    }
    for ie in iana_ies {
        match ie.data_type.as_str() {
            "octetArray" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "unsigned8" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                1\n");
            }
            "unsigned16" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 2,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "unsigned32" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 4,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "unsigned64" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 8,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "signed8" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                1\n");
            }
            "signed16" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 2,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "signed32" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 4,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "signed64" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 8,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "float32" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 4,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "float64" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => 8,\n");
                ret.push_str("                    Some(len) => len as usize,\n");
                ret.push_str("                }\n");
            }
            "boolean" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                1\n");
            }
            "macAddress" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "string" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                match length {\n");
                ret.push_str("                    None => value.len(),\n");
                ret.push_str("                    Some(len) => if len == u16::MAX {\n");
                ret.push_str("                        if value.len() < u8::MAX as usize {\n");
                ret.push_str("                            // One octet for the length field\n");
                ret.push_str("                            value.len() + 1\n");
                ret.push_str("                        } else {\n");
                ret.push_str("                            // 4 octets for the length field, first is 255 and other three carries the len\n");
                ret.push_str("                            value.len() + 4\n");
                ret.push_str("                        }\n");
                ret.push_str("                    } else {\n");
                ret.push_str("                        len as usize\n");
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "dateTimeSeconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                4\n");
            }
            "dateTimeMilliseconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                8\n");
            }
            "dateTimeMicroseconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                8\n");
            }
            "dateTimeNanoseconds" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                8\n");
            }
            "ipv4Address" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                4\n");
            }
            "ipv6Address" => {
                ret.push_str(format!("            Self::{}(_value) => {{\n", ie.name).as_str());
                ret.push_str("                16\n");
            }
            "basicList" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "subTemplateList" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "subTemplateMultiList" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            "unsigned256" => {
                ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
                ret.push_str("                value.len()\n");
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
        ret.push_str("            }\n");
    }

    ret.push_str("         }\n");
    ret.push_str("     }\n\n");
    ret.push_str("    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {\n");
    ret.push_str("        match self {\n");
    ret.push_str(
        "            Self::Unknown{pen: _pen, id: _id, value} => writer.write_all(value)?,\n",
    );
    for (name, _pkg, _) in vendor_prefixes {
        ret.push_str(
            format!("            Self::{name}(value) => value.write(writer, length)?,\n").as_str(),
        );
    }
    for ie in iana_ies {
        ret.push_str(format!("            Self::{}(value) => {{\n", ie.name).as_str());
        match ie.data_type.as_str() {
            "octetArray" => {
                ret.push_str("                writer.write_all(value.as_ref())?\n");
            }
            "unsigned8" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let num_val = u8::from(*value);\n");
                    ret.push_str("                writer.write_u8(num_val)?\n");
                } else {
                    ret.push_str("                writer.write_u8(*value)?\n");
                }
            }
            "unsigned16" => {
                if ie.subregistry.is_some() || ie.name == "tcpControlBits" {
                    ret.push_str("                let value = u16::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_u16::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "unsigned32" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = u32::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_u32::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "unsigned64" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = u64::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_u64::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "signed8" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let num_val = i8::from(*value);\n");
                    ret.push_str("                writer.write_i8(num_val)?\n");
                } else {
                    ret.push_str("                writer.write_i8(*value)?\n");
                }
            }
            "signed16" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = i16::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_i16::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "signed32" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = i32::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_i32::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "signed64" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = i64::from(*value);\n");
                } else {
                    ret.push_str("                let value = *value;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_i64::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "float32" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = f32::from(*value);\n");
                } else {
                    ret.push_str("                let value = value.0;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_f32::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "float64" => {
                if ie.subregistry.is_some() {
                    ret.push_str("                let value = f64::from(*value);\n");
                } else {
                    ret.push_str("                let value = value.0;\n");
                }
                ret.push_str("                match length {\n");
                ret.push_str("                    None => writer.write_f64::<byteorder::NetworkEndian>(value)?,\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        let be_bytes = value.to_be_bytes();\n");
                ret.push_str("                        if usize::from(len) > be_bytes.len() {\n");
                ret.push_str(format!("                           return Err(FieldWritingError::InvalidLength{{ie_name: \"{}\".to_string(), length: len}});\n", ie.name).as_str());
                ret.push_str("                        }\n");
                ret.push_str(
                    "                        let begin_offset = be_bytes.len() - len as usize;\n",
                );
                ret.push_str(
                    "                        writer.write_all(&be_bytes[begin_offset..])?\n",
                );
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "boolean" => {
                ret.push_str("                writer.write_u8(*value as u8)?\n");
            }
            "macAddress" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "string" => {
                ret.push_str("                match length {\n");
                ret.push_str("                    Some(u16::MAX) | None => {\n");
                ret.push_str("                        let bytes = value.as_bytes();\n");
                ret.push_str("                        if bytes.len() < u8::MAX as usize {\n");
                ret.push_str("                            writer.write_u8(bytes.len() as u8)?;\n");
                ret.push_str("                        } else {\n");
                ret.push_str("                            writer.write_u8(u8::MAX)?;\n");
                ret.push_str("                            writer.write_all(&bytes.len().to_be_bytes()[1..])?;\n");
                ret.push_str("                        }\n");
                ret.push_str("                        writer.write_all(value.as_bytes())?;\n");
                ret.push_str("                    }\n");
                ret.push_str("                    Some(len) => {\n");
                ret.push_str("                        writer.write_all(value.as_bytes())?;\n");
                ret.push_str("                        // fill the rest with zeros\n");
                ret.push_str("                        for _ in value.len()..(len as usize) {\n");
                ret.push_str("                            writer.write_u8(0)?\n");
                ret.push_str("                        }\n");
                ret.push_str("                    }\n");
                ret.push_str("                }\n");
            }
            "dateTimeSeconds" => {
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;\n");
            }
            "dateTimeMilliseconds" => {
                ret.push_str("                writer.write_u64::<byteorder::NetworkEndian>(value.timestamp_millis() as u64)?;\n", );
            }
            "dateTimeMicroseconds" => {
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;\n", );
                ret.push_str("                let nanos = value.timestamp_subsec_nanos();\n");
                ret.push_str("                // Convert 1/2**32 of a second to a fraction of a nano second\n");
                ret.push_str("                let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;\n");
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;\n");
            }
            "dateTimeNanoseconds" => {
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;\n", );
                ret.push_str("                let nanos = value.timestamp_subsec_nanos();\n");
                ret.push_str("                // Convert 1/2**32 of a second to a fraction of a nano second\n");
                ret.push_str("                let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;\n");
                ret.push_str("                writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;\n");
            }
            "ipv4Address" => {
                ret.push_str("                writer.write_all(&value.octets())?\n");
            }
            "ipv6Address" => {
                ret.push_str("                writer.write_all(&value.octets())?\n");
            }
            "basicList" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "subTemplateList" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "subTemplateMultiList" => {
                ret.push_str("                writer.write_all(value)?\n");
            }
            "unsigned256" => {
                ret.push_str("                writer.write_all(value.as_ref())?\n");
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
        ret.push_str("            }\n");
    }
    ret.push_str("         }\n");
    ret.push_str("         Ok(())\n");
    ret.push_str("     }\n");
    ret.push_str("}\n\n");
    ret
}

/// Generates `get(&self, ie: IE) -> Vec<Field>`  for `Fields`
pub fn impl_get_field(
    iana_ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("    pub fn get(&self, ie: IE) -> Vec<Field> {\n");
    ret.push_str("        match ie {\n");
    if !vendors.is_empty() {
        ret.push_str("            IE::Unknown { .. } => Vec::with_capacity(0),\n");
    }
    for (name, pkg, _) in vendors {
        ret.push_str(format!("            IE::{name}(vendor_ie) => {{\n").as_str());
        ret.push_str(format!("                if let Some(value) = &self.{pkg} {{\n").as_str());
        ret.push_str(format!("                    value.get(vendor_ie).into_iter().map(Field::{name}).collect()\n").as_str());
        ret.push_str("                } else {\n");
        ret.push_str("                     Vec::with_capacity(0)\n");
        ret.push_str("                }\n");
        ret.push_str("            }\n");
    }
    for ie in iana_ies {
        ret.push_str(format!("            IE::{} => {{\n", ie.name).as_str());
        ret.push_str(
            format!(
                "                if let Some(values) = &self.{name} {{\n",
                name = ie.name
            )
            .as_str(),
        );
        ret.push_str(
            format!(
                "                    values.iter().cloned().map(Field::{name}).collect()\n",
                name = ie.name
            )
            .as_str(),
        );
        ret.push_str("                } else {\n");
        ret.push_str("                    Vec::with_capacity(0)\n");
        ret.push_str("                }\n");
        ret.push_str("            }\n");
    }
    ret.push_str("        }\n");
    ret.push_str("    }\n");
    ret
}

pub fn generate_flat_ie_struct(
    iana_ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_snake_case)]\n");
    ret.push_str(generate_derive(false, false, false, false, false, false).as_str());
    ret.push_str("#[derive(Default)]\n");
    ret.push_str("pub struct Fields {\n");
    // TODO: Handle unknown fields
    //ret.push_str("    Unknown{pen: u32, id: u16, value: Box<[u8]>},\n");
    for (_name, pkg, _) in vendors {
        ret.push_str(format!("    pub {pkg}: Option<{pkg}::Fields>,\n").as_str());
    }
    for ie in iana_ies {
        let field_type = if ie.name == "tcpControlBits" {
            "netgauze_iana::tcp::TCPHeaderFlags".to_string()
        } else {
            let rust_type = get_rust_type(&ie.data_type, &ie.name);
            if ie.subregistry.is_some() {
                ie.name.clone()
            } else {
                rust_type
            }
        };
        ret.push_str("    #[serde(skip_serializing_if = \"::std::option::Option::is_none\")]\n");
        ret.push_str(format!("    pub {}: Option<Vec<{field_type}>>,\n", ie.name).as_str());
    }
    ret.push_str("}\n\n");

    ret.push_str("impl From<Box<[Field]>> for Fields {\n");
    ret.push_str("    fn from(fields: Box<[Field]>) -> Self {\n");
    ret.push_str("        let mut out = Fields::default();\n");
    for (_name, pkg, _) in vendors {
        ret.push_str(format!("        let mut {pkg}_fields = vec![];\n").as_str());
    }
    ret.push_str("        for field in fields {\n");
    ret.push_str("            match field {\n");
    for (name, pkg, _) in vendors {
        ret.push_str(
            format!("                Field::{name}(value) => {pkg}_fields.push(value),\n").as_str(),
        );
    }
    // Only IANA has the unknown value
    if !vendors.is_empty() {
        ret.push_str("                Field::Unknown{..} => {},\n");
    }
    for ie in iana_ies {
        ret.push_str(format!("                Field::{}(value) => {{\n", ie.name).as_str());
        ret.push_str(format!("                    if out.{}.is_none() {{\n", ie.name).as_str());
        ret.push_str(
            format!(
                "                        out.{} = Some(Vec::with_capacity(1));\n",
                ie.name
            )
            .as_str(),
        );
        ret.push_str("                    }\n");
        ret.push_str(
            format!(
                "                    if let Some(inner) = out.{}.as_mut() {{\n",
                ie.name
            )
            .as_str(),
        );
        ret.push_str("                        inner.push(value);\n");
        ret.push_str("                    }\n");
        ret.push_str("                }\n");
    }
    ret.push_str("            }\n");
    ret.push_str("        }\n");

    for (_name, pkg, _) in vendors {
        ret.push_str(format!("        out.{pkg} = if {pkg}_fields.is_empty() {{ None }} else {{ Some({pkg}_fields.into_boxed_slice().into()) }};\n").as_str());
    }
    ret.push_str("        out\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");

    ret.push_str("impl Fields {\n");

    ret.push_str(impl_get_field(iana_ies, vendors).as_str());
    ret.push_str(impl_extract_as_key_str().as_str());
    ret.push_str(impl_reduce(iana_ies, vendors).as_str());

    ret.push_str("}\n\n");

    ret
}
