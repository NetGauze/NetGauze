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

use crate::xml_parsers::xml_common::*;
use crate::{
    InformationElementSubRegistry, ReasonCodeNestedRegistry, SubRegistryType,
    ValueNameDescRegistry, Xref,
};

use regex::Regex;
use roxmltree::Node;

const MAX_WORDS_NAME: usize = 10;
const MAX_CHARS_DISPLAY_NAME: usize = 50;

/// Subregistry Trait with getter functions for common values
pub trait SubRegistry {
    fn name(&self) -> &str;
    fn display_name(&self) -> &str;
    fn description(&self) -> &str;
    fn comments(&self) -> &Option<String>;
    fn parameters(&self) -> &Option<String>;
    fn xrefs(&self) -> &Vec<Xref>;
}

impl SubRegistry for ValueNameDescRegistry {
    fn name(&self) -> &str {
        &self.name
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn comments(&self) -> &Option<String> {
        &self.comments
    }

    fn parameters(&self) -> &Option<String> {
        &self.parameters
    }

    fn xrefs(&self) -> &Vec<Xref> {
        &self.xrefs
    }
}

impl SubRegistry for ReasonCodeNestedRegistry {
    fn name(&self) -> &str {
        &self.name
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn comments(&self) -> &Option<String> {
        &self.comments
    }

    fn parameters(&self) -> &Option<String> {
        &self.parameters
    }

    fn xrefs(&self) -> &Vec<Xref> {
        &self.xrefs
    }
}

/// Wrapper to call the appropriate sub-registry parsing function based on the
/// registry_type. Returns a `Vec<InformationElementSubRegistry>`
pub fn parse_subregistry(
    node: &Node<'_, '_>,
    registry_type: SubRegistryType,
) -> (u16, Vec<InformationElementSubRegistry>) {
    match registry_type {
        SubRegistryType::ValueNameDescRegistry => {
            let (ie_id, reg) = parse_val_name_desc_u8_registry(node);
            let ie_subreg: Vec<InformationElementSubRegistry> = reg
                .into_iter()
                .map(InformationElementSubRegistry::ValueNameDescRegistry)
                .collect();
            (ie_id, ie_subreg)
        }
        SubRegistryType::ReasonCodeNestedRegistry => {
            let (ie_id, reg) = parse_reason_code_nested_u8_registry_2bit(node);
            let ie_subreg: Vec<InformationElementSubRegistry> = reg
                .into_iter()
                .map(InformationElementSubRegistry::ReasonCodeNestedRegistry)
                .collect();
            (ie_id, ie_subreg)
        }
    }
}

/// Parse generic sub-registries with value (or id), name and/or description,
/// and optionally a comment, and parameter set. Examples:
/// - [flowEndReason (Value 136)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason)
/// - [flowSelectorAlgorithm (Value 390)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flowselectoralgorithm)
pub fn parse_val_name_desc_u8_registry(node: &Node<'_, '_>) -> (u16, Vec<ValueNameDescRegistry>) {
    let mut ret = Vec::new();

    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "record").into())
        .collect::<Vec<_>>();

    let title = get_string_child(node, (IANA_NAMESPACE, "title").into()).unwrap_or_default();

    let ie_id_regex = Regex::new(r"Value (\d+)").unwrap();
    let ie_id = ie_id_regex
        .captures(&title)
        .and_then(|captures| captures.get(1))
        .and_then(|capture| capture.as_str().parse().ok())
        .unwrap_or(0);

    for child in &children {
        let value = get_string_child(child, (IANA_NAMESPACE, "value").into()).map(|x| {
            if let Some(hex_value) = x.strip_prefix("0x") {
                u8::from_str_radix(hex_value, 16)
            } else if let Some(bin_value) = x.strip_prefix("0b") {
                u8::from_str_radix(bin_value, 2)
            } else if let Some(bin_value) = x.strip_suffix('b') {
                u8::from_str_radix(bin_value, 2)
            } else {
                x.parse::<u8>()
            }
        });

        // If value column is not present, fallback to id (e.g. psamp-parameters
        // registry)
        let value = match value {
            Some(_) => value,
            None => get_string_child(child, (IANA_NAMESPACE, "id").into()).map(|x| {
                if let Some(hex_value) = x.strip_prefix("0x") {
                    u8::from_str_radix(hex_value, 16)
                } else if let Some(bin_value) = x.strip_prefix("0b") {
                    u8::from_str_radix(bin_value, 2)
                } else if let Some(bin_value) = x.strip_suffix('b') {
                    u8::from_str_radix(bin_value, 2)
                } else {
                    x.parse::<u8>()
                }
            }),
        };

        let name_parsed = get_string_child(child, (IANA_NAMESPACE, "name").into());

        // TODO: also consider unassigned and experimentation values
        if Some(true)
            == name_parsed
                .as_ref()
                .map(|x| x.as_str() == UNASSIGNED || x.contains(EXPERIMENTATION))
        {
            continue;
        }

        let description_parsed = parse_simple_description_string(child);
        if Some(true)
            == description_parsed
                .as_ref()
                .map(|x| x.as_str() == UNASSIGNED || x.contains(EXPERIMENTATION))
        {
            continue;
        }

        // Populate name, display_name, and description
        // - name is always a usable enum variant type name (if not there in the
        //   registry, take it from the description)
        // - display_name matches the IANA registry name (apart from when name is
        //   populated from description field)
        let mut name: String;
        let mut display_name: String;
        let description: String;
        if let Some(Ok(value)) = value {
            if value == u8::MAX {
                // TODO: also consider unassigned and experimentation values
                continue;
            }

            if let Some(name_parsed) = name_parsed {
                display_name = name_parsed.clone();

                (_, name) = xml_string_to_enum_type(&name_parsed);
                if let Some(desc_parsed) = description_parsed {
                    description = desc_parsed;
                } else {
                    description = name_parsed;
                }
            } else if let Some(mut desc_parsed) = description_parsed {
                description = desc_parsed.clone();

                let desc_words_amount: usize;
                (desc_words_amount, desc_parsed) = xml_string_to_enum_type(&desc_parsed);

                if desc_words_amount < MAX_WORDS_NAME {
                    display_name = desc_parsed.clone();
                    name = desc_parsed;
                } else {
                    display_name = format!("Value{value}");
                    name = format!("Value{value}");
                }

                if description.len() < MAX_CHARS_DISPLAY_NAME {
                    display_name = description.clone();
                }
            } else {
                log::info!("Skipping sub-registry: missing both name and description!");
                continue;
            }

            // Handle duplicates
            if name == *RESERVED || name == *PRIVATE {
                name = format!("{name}{value}");
            }

            let comments = get_string_child(child, (IANA_NAMESPACE, "comments").into());
            let parameters = get_string_child(child, (IANA_NAMESPACE, "parameters").into());
            let xrefs = parse_xref(child);

            ret.push(ValueNameDescRegistry {
                value,
                name,
                display_name,
                description,
                comments,
                parameters,
                xrefs,
            });
        }
    }

    (ie_id, ret)
}

/// Parse sub-registries with nested (first 2bit = status) registries for reason
/// code, such as: [Forwarding Status (Value 89)](https://www.iana.org/assignments/ipfix/ipfix.xml#forwarding-status)
pub fn parse_reason_code_nested_u8_registry_2bit(
    node: &Node<'_, '_>,
) -> (u16, Vec<ReasonCodeNestedRegistry>) {
    let (ie_id, subreg) = parse_val_name_desc_u8_registry(node);

    let ret: Vec<ReasonCodeNestedRegistry> = subreg
        .iter()
        .map(|subreg| {
            let val_bin_str = format!("{:02b}", subreg.value);
            let reason_code_pattern = format!(r".*-{val_bin_str}b");
            let reason_code_reg_pattern = Regex::new(&reason_code_pattern).unwrap();
            let reason_code_node = find_node_by_regex(node, &reason_code_reg_pattern).unwrap();
            ReasonCodeNestedRegistry {
                value: subreg.value << 6,
                name: SubRegistry::name(subreg).to_string(),
                display_name: SubRegistry::display_name(subreg).to_string(),
                description: SubRegistry::description(subreg).to_string(),
                comments: SubRegistry::comments(subreg).to_owned(),
                parameters: SubRegistry::parameters(subreg).to_owned(),
                xrefs: SubRegistry::xrefs(subreg).to_owned(),
                reason_code_reg: {
                    let (_, reg) = parse_val_name_desc_u8_registry(&reason_code_node);
                    let reg: Vec<InformationElementSubRegistry> = reg
                        .into_iter()
                        .map(InformationElementSubRegistry::ValueNameDescRegistry)
                        .collect();
                    reg
                },
            }
        })
        .collect();

    (ie_id, ret)
}
