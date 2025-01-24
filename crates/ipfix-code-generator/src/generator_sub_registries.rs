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

use crate::{
    generator::{generate_derive, generate_xref_link},
    xml_parsers::sub_registries::SubRegistry,
    InformationElementSubRegistry,
};

/// Generate code (enum and implementations) for IE Subregistries
pub fn generate_subregistry_enum_and_impl(
    ie_name: &String,
    rust_type: &String,
    ie_subregistry: &[InformationElementSubRegistry],
) -> String {
    let mut ret = String::new();

    ret.push_str(generate_enum(ie_name, rust_type, ie_subregistry).as_str());
    ret.push_str(generate_from_impl_for_rust_type(ie_name, rust_type, ie_subregistry).as_str());
    ret.push_str(generate_from_impl_for_enum_type(ie_name, rust_type, ie_subregistry).as_str());

    // Add structs and type converters for reason-code registries
    for rec in ie_subregistry {
        if let InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) = rec {
            let enum_name = format!("{}{}Reason", ie_name, rec.name);
            ret.push_str("#[allow(non_camel_case_types)]\n");

            let gen_derive = generate_derive(
                false,
                rust_type != "Vec<u8>" && rust_type != "String",
                rust_type != "f32" && rust_type != "f64",
            );
            ret.push_str(gen_derive.as_str());
            ret.push_str(generate_enum(&enum_name, rust_type, &rec.reason_code_reg).as_str());
            ret.push_str(
                generate_from_impl_for_rust_type(&enum_name, rust_type, &rec.reason_code_reg)
                    .as_str(),
            );
            ret.push_str(
                generate_from_impl_for_enum_type(&enum_name, rust_type, &rec.reason_code_reg)
                    .as_str(),
            );
        }
    }
    ret
}

/// Generate Description and Ref for a given Subregistry
pub fn generate_desc_and_refs_common(rec: &dyn SubRegistry) -> String {
    let mut ret = String::new();
    for line in SubRegistry::description(rec).split('\n') {
        ret.push_str(format!("    /// {}\n", line.trim()).as_str());
    }
    if !SubRegistry::description(rec).is_empty() && !SubRegistry::xrefs(rec).is_empty() {
        ret.push_str("    ///\n");
    }
    for xref in SubRegistry::xrefs(rec)
        .iter()
        .filter_map(generate_xref_link)
    {
        ret.push_str(format!("    /// Reference: {xref}\n").as_str());
    }
    ret
}

/// Generate Enum Type for Subregistry
pub fn generate_enum(
    enum_name: &String,
    rust_type: &String,
    registry: &[InformationElementSubRegistry],
) -> String {
    let mut ret = String::new();
    ret.push_str(format!("#[repr({rust_type})]\n").as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str(format!("pub enum {enum_name} {{\n").as_str());

    for rec in registry {
        match rec {
            InformationElementSubRegistry::ValueNameDescRegistry(rec) => {
                ret.push_str(generate_desc_and_refs_common(rec).as_str());
                ret.push_str(format!("    {} = {},\n", rec.name, rec.value).as_str());
            }
            InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) => {
                ret.push_str(generate_desc_and_refs_common(rec).as_str());
                ret.push_str(
                    format!("    {}({}{}Reason),\n", rec.name, enum_name, rec.name).as_str(),
                );
            }
        }
    }
    ret.push_str(format!("    Unassigned({rust_type}),\n").as_str());
    ret.push_str("}\n\n");
    ret
}

/// Generate From trait implementation from subregistry to rust_type
pub fn generate_from_impl_for_rust_type(
    enum_name: &String,
    rust_type: &String,
    registry: &[InformationElementSubRegistry],
) -> String {
    let mut ret = String::new();
    ret.push_str(format!("impl From<{enum_name}> for {rust_type} {{\n").as_str());
    ret.push_str(format!("    fn from(value: {enum_name}) -> Self {{\n").as_str());
    ret.push_str("        match value {\n");

    for rec in registry {
        match rec {
            InformationElementSubRegistry::ValueNameDescRegistry(rec) => {
                ret.push_str(
                    format!(
                        "            {}::{} => {},\n",
                        enum_name, rec.name, rec.value
                    )
                    .as_str(),
                );
            }
            InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) => {
                ret.push_str(
                    format!(
                        "            {}::{}(x) => {}::from(x),\n",
                        enum_name, rec.name, rust_type
                    )
                    .as_str(),
                );
            }
        }
    }
    ret.push_str(format!("            {enum_name}::Unassigned(x) => x,\n").as_str());
    ret.push_str("        }\n");
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}

/// Generate From trait implementation from rust_type to subregistry
pub fn generate_from_impl_for_enum_type(
    enum_name: &String,
    rust_type: &String,
    registry: &[InformationElementSubRegistry],
) -> String {
    let mut ret = String::new();
    ret.push_str(format!("impl From<{}> for {} {{\n", &rust_type, enum_name).as_str());
    ret.push_str(format!("    fn from(value: {rust_type}) -> Self {{\n").as_str());

    if let Some(first) = registry.first() {
        if let InformationElementSubRegistry::ValueNameDescRegistry(_) = first {
            ret.push_str("        match value {\n");
        }
    } else {
        // Empty registry
        ret.push_str("        let x = value;\n");
    }

    for (idx, rec) in registry.iter().enumerate() {
        match rec {
            InformationElementSubRegistry::ValueNameDescRegistry(rec) => {
                ret.push_str(
                    format!(
                        "            {} => {}::{},\n",
                        rec.value, enum_name, rec.name
                    )
                    .as_str(),
                );
            }
            InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) => {
                if idx == 0 {
                    ret.push_str(
                        format!(
                            "            if ({}..={}).contains(&value) {{\n",
                            64 * idx,
                            64 * (idx + 1) - 1
                        )
                        .as_str(),
                    );
                } else {
                    ret.push_str(
                        format!(
                            "            else if ({}..={}).contains(&value) {{\n",
                            64 * idx,
                            64 * (idx + 1) - 1
                        )
                        .as_str(),
                    );
                }
                ret.push_str(
                    format!(
                        "                {}::{}({}{}Reason::from(value))\n",
                        enum_name, rec.name, enum_name, rec.name
                    )
                    .as_str(),
                );
                ret.push_str("            }\n");
            }
        }
    }

    if let Some(first) = registry.first() {
        match first {
            InformationElementSubRegistry::ValueNameDescRegistry(_) => {
                ret.push_str(format!("            x => {enum_name}::Unassigned(x),\n").as_str());
                ret.push_str("        }\n");
            }
            InformationElementSubRegistry::ReasonCodeNestedRegistry(_) => {
                ret.push_str("            else {\n");
                ret.push_str(format!("                {enum_name}::Unassigned(value)\n").as_str());
                ret.push_str("            }\n");
            }
        }
    } else {
        // Empty registry
        ret.push_str(format!("        {enum_name}::Unassigned(x)\n").as_str());
    }
    ret.push_str("    }\n");
    ret.push_str("}\n\n");
    ret
}
