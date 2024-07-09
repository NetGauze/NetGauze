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

use crate::{InformationElement, InformationElementSubRegistry, SimpleRegistry, Xref};
use regex::{Captures, Regex, Replacer};
use roxmltree::{ExpandedName, Node};
use std::collections::HashMap;

const IANA_NAMESPACE: &str = "http://www.iana.org/assignments";
const ID_IE_DATA_TYPES: &str = "ipfix-information-element-data-types";
pub(crate) const ID_IE: &str = "ipfix-information-elements";
const ID_SEMANTICS: &str = "ipfix-information-element-semantics";
const ID_UNITS: &str = "ipfix-information-element-units";
const UNASSIGNED: &str = "Unassigned";
const RESERVED: &str = "Reserved";
const UNKNOWN: &str = "Unknown";
const PRIVATE: &str = "Private";
const ASSIGNED_FOR_NF_V9: &str = "Assigned for NetFlow v9 compatibility";
pub(crate) const ID_SUBREG_DEFAULT_PATTERN: &str = "ipfix-";
pub const ID_SUBREG_FW_STATUS: &str = "forwarding-status";
pub const ID_SUBREG_CLASS_ENG_ID: &str = "classification-engine-ids";

const MAX_WORDS_NAME: usize = 10;

struct RfcLinkSwapper;
impl Replacer for RfcLinkSwapper {
    fn replace_append(&mut self, caps: &Captures<'_>, dst: &mut String) {
        dst.push_str("[RFC");
        dst.push_str(&caps["RFCNUM"]);
        dst.push_str("](https://datatracker.ietf.org/doc/rfc");
        dst.push_str(&caps["RFCNUM"]);
        dst.push(')');
    }
}

struct HttpLinkSwapper;
impl Replacer for HttpLinkSwapper {
    fn replace_append(&mut self, caps: &Captures<'_>, dst: &mut String) {
        dst.push('<');
        dst.push_str(&caps["href"]);
        dst.push('>');
    }
}

/// Find descendant node by it's ID
/// If multiple nodes with the same ID exists, the first one is returned
pub(crate) fn find_node_by_id<'a, 'input>(
    node: &'input Node<'a, 'input>,
    id: &str,
) -> Option<Node<'a, 'input>> {
    node.descendants().find(|x| x.attribute("id") == Some(id))
}

/// Return all children nodes matching the regex (ignoring root node)
pub(crate) fn find_nodes_by_regex<'a, 'input>(
    node: &'input Node<'a, 'input>,
    regex: &Regex,
) -> Vec<Node<'a, 'input>> {
    node.children()
        .filter(|x| {
            !x.is_root()
                && x.attribute("id")
                    .map(|id| regex.is_match(id))
                    .unwrap_or(false)
        })
        .collect()
}

/// Get the text value of an XML node if applicable
/// For example `<a>bb</a>` returns `Some("bb".to_string())`,
/// while `<a><b/></a>` returns `None`
fn get_string_child(node: &Node<'_, '_>, tag_name: ExpandedName<'_, '_>) -> Option<String> {
    node.children()
        .find(|x| x.tag_name() == tag_name)
        .map(|x| x.text().map(|txt| txt.trim().to_string()))
        .unwrap_or_default()
}

/// Parse tags such as `<xref type="rfc">rfc1233</xref>`
fn parse_xref(node: &Node<'_, '_>) -> Vec<Xref> {
    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "xref").into())
        .collect::<Vec<_>>();
    let mut xrefs = Vec::new();
    for child in children {
        let ty = child.attribute("type").map(ToString::to_string);
        let data = child.attribute("data").map(ToString::to_string);
        if let (Some(ty), Some(data)) = (ty, data) {
            xrefs.push(Xref { ty, data });
        }
    }
    xrefs
}

/// Parse simple registries with just value, description, and optionally
/// a comment [IPFIX Information Element Data Types](https://www.iana.org/assignments/ipfix/ipfix.xml#ipfix-information-element-data-types)
/// And [IPFIX Information Element Semantics](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-element-semantics)
pub(crate) fn parse_simple_registry(node: &Node<'_, '_>) -> Vec<SimpleRegistry> {
    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "record").into())
        .collect::<Vec<_>>();
    let mut ret = Vec::new();
    for child in &children {
        let value = get_string_child(child, (IANA_NAMESPACE, "value").into())
            .map(|x| x.as_str().parse::<u8>());
        let description = get_string_child(child, (IANA_NAMESPACE, "description").into());
        if Some(true) == description.as_ref().map(|x| x.as_str() == UNASSIGNED) {
            continue;
        }
        let comments = get_string_child(child, (IANA_NAMESPACE, "comments").into());
        let xref = parse_xref(child);
        if let (Some(Ok(value)), Some(description)) = (value, description) {
            let description = if description.trim() == "4-octet words" {
                "fourOctetWords".to_string()
            } else {
                description
            };
            ret.push(SimpleRegistry {
                value,
                description,
                comments,
                xref,
            });
        }
    }
    ret
}

pub fn parse_subreg_description_string(node: &Node<'_, '_>) -> Option<String> {
    if let Some(description) = node
        .children()
        .find(|x| x.tag_name() == (IANA_NAMESPACE, "description").into())
    {
        let mut desc_text = String::new();
        let body = description.text().map(|txt| txt.trim().to_string());

        if let Some(body) = body {
            if !body.trim().is_empty() {
                desc_text.push_str(body.trim());
            }
        }
        let re = Regex::new(r"\[RFC(?<RFCNUM>\d+)]").unwrap();
        let desc_text = re.replace(&desc_text, RfcLinkSwapper).to_string();
        let re = Regex::new(r"(?<href>https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*))").unwrap();
        let desc_text = re.replace(&desc_text, HttpLinkSwapper);
        Some(desc_text.to_string())
    } else {
        None
    }
}

/// Convert a (complex) description string to a usable enum type name
/// Use e.g. for registries missing a name field where we need to use a
/// (possibly complex) description string.
///
/// - removes line breaks and trimming
/// - only selects text preceding any ":", useful for e.g. [IPFIX MPLS label type (Value 46)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-mpls-label-type)
/// - removes ascii punctuation
/// - removes spaces
///
/// TODO: feedback to Benoit
fn xml_string_to_enum_type(input: &str) -> (usize, String) {
    // Multiline --> one-line
    let str_one_line = input
        .lines()
        .map(|line| line.trim())
        .collect::<Vec<&str>>()
        .join(" ")
        .to_string();

    // Select text before ":" if that's present
    let str_before_column = str_one_line
        .split(':')
        .next()
        .unwrap_or(&str_one_line)
        .trim()
        .to_string();

    // Remove spaces
    let str_words: Vec<&str> = str_before_column.split_whitespace().collect();
    let str_words_amount = str_words.len();
    let str_without_spaces = str_before_column
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation())
        .collect::<String>();

    (str_words_amount, str_without_spaces)
}

/// Parse generic sub-registries with value, name and/or description, and
/// optionally a comment, and parameter set. Examples:
/// - [flowEndReason (Value 136)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason)
/// - [flowSelectorAlgorithm (Value 390)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flowselectoralgorithm)
pub(crate) fn parse_subregistry(node: &Node<'_, '_>) -> (u16, Vec<InformationElementSubRegistry>) {
    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "record").into())
        .collect::<Vec<_>>();

    let mut ret = Vec::new();
    let title = get_string_child(node, (IANA_NAMESPACE, "title").into());
    let ie_id_regex = Regex::new(r"Value (\d+)").unwrap();
    let ie_id: u16 = match ie_id_regex.captures(&title.unwrap()) {
        Some(captured) => captured[1].parse().unwrap(),
        None => 0,
    };

    for child in &children {
        let value = get_string_child(child, (IANA_NAMESPACE, "value").into()).map(|x| {
            if let Some(hex_value) = x.strip_prefix("0x") {
                u8::from_str_radix(hex_value, 16)
            } else if let Some(bin_value) = x.strip_prefix("0b") {
                u8::from_str_radix(bin_value, 2)
            } else {
                x.parse::<u8>()
            }
        });

        let name_parsed = get_string_child(child, (IANA_NAMESPACE, "name").into());
        if Some(true) == name_parsed.as_ref().map(|x| x.as_str() == UNASSIGNED) {
            continue;
        }

        let description_parsed = parse_subreg_description_string(child);
        if Some(true)
            == description_parsed
                .as_ref()
                .map(|x| x.as_str() == UNASSIGNED)
        {
            continue;
        }

        // Populate name, description
        // If name not there, take it from the description
        let mut name: String;
        let description: String;
        if let Some(Ok(value)) = value {
            if let Some(name_parsed) = name_parsed {
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
                    name = desc_parsed;
                } else {
                    name = format!("Value{value}");
                }
            } else {
                log::info!("Skipping sub-registry: missing both name and description!");
                continue;
            }

            // Handle duplicates
            if name == *RESERVED || name == *UNKNOWN || name == *PRIVATE {
                name = format!("{name}{value}");
            }

            let comments = get_string_child(child, (IANA_NAMESPACE, "comments").into());
            let parameters = get_string_child(child, (IANA_NAMESPACE, "parameters").into());
            let xrefs = parse_xref(child);

            ret.push(InformationElementSubRegistry {
                value,
                name,
                description,
                comments,
                parameters,
                xrefs,
            });
        }
    }
    (ie_id, ret)
}

/// Parse subregisty for the forwardingStatus IE
/// [Forwarding Status (Value 89)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#forwarding-status)
/// TODO: feedback to Benoit
pub(crate) fn parse_fw_status_subregistry(
    node: &Node<'_, '_>,
) -> (u16, Vec<InformationElementSubRegistry>) {
    // HashMap to store Forwarding Status Type
    let mut fw_status_type_desc_map: HashMap<u8, (String, Vec<Xref>)> = HashMap::new();

    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "record").into())
        .collect::<Vec<_>>();

    let mut ret = Vec::new();
    let title = get_string_child(node, (IANA_NAMESPACE, "title").into());
    let ie_id_regex = Regex::new(r"Value (\d+)").unwrap();
    let ie_id: u16 = match ie_id_regex.captures(&title.unwrap()) {
        Some(captured) => captured[1].parse().unwrap(),
        None => 0,
    };

    for child in &children {
        let value = get_string_child(child, (IANA_NAMESPACE, "value").into()).map(|x| {
            let bin_value = x.trim_end_matches('b');
            u8::from_str_radix(bin_value, 2)
        });
        let description = get_string_child(child, (IANA_NAMESPACE, "description").into());
        let xref = parse_xref(child);

        if let Some(Ok(value)) = value {
            fw_status_type_desc_map.insert(value, (description.unwrap(), xref));
        }
    }

    let fw_status_subregistry_pattern = Regex::new(&format!(r"{ID_SUBREG_FW_STATUS}-")).unwrap();
    let fw_status_subregistry_nodes = find_nodes_by_regex(node, &fw_status_subregistry_pattern);

    // Get Forwarding Status reason codes from sub-subregistries
    for subregistry_node in fw_status_subregistry_nodes {
        let fw_status_type = subregistry_node
            .attribute("id")
            .unwrap()
            .trim_start_matches(&format!(r"{ID_SUBREG_FW_STATUS}-"))
            .trim_end_matches('b');
        let fw_status_type_value = u8::from_str_radix(fw_status_type, 2).unwrap();
        let fw_status_type_desc = fw_status_type_desc_map
            .get(&fw_status_type_value)
            .unwrap()
            .0
            .to_string();
        let fw_status_type_xref = fw_status_type_desc_map
            .get(&fw_status_type_value)
            .unwrap()
            .1
            .clone();

        let children = subregistry_node
            .children()
            .filter(|x| x.tag_name() == (IANA_NAMESPACE, "record").into())
            .collect::<Vec<_>>();

        let mut entries = 0;
        for child in &children {
            let value = get_string_child(child, (IANA_NAMESPACE, "value").into()).map(|x| {
                let hex_value = x.trim_start_matches("0x");
                u8::from_str_radix(hex_value, 16)
            });
            let description =
                get_string_child(child, (IANA_NAMESPACE, "description").into()).unwrap();
            let name =
                format!("{}{}", fw_status_type_desc.clone(), description.trim()).replace(" ", "");
            let xrefs = parse_xref(child);

            if let Some(Ok(value)) = value {
                ret.push(InformationElementSubRegistry {
                    value,
                    name,
                    description: format!("{} {}", fw_status_type_desc.clone(), description),
                    comments: None,
                    parameters: None,
                    xrefs,
                });
                entries += 1;
            }
        }

        // No entries in the reason sub-subregistry
        if entries == 0 {
            let mut name = fw_status_type_desc.clone();
            let value = fw_status_type_value;

            // Handle duplicates
            if name == *RESERVED || name == *UNKNOWN || name == *PRIVATE {
                name = format!("{name}{value}");
            }

            ret.push(InformationElementSubRegistry {
                value,
                name,
                description: fw_status_type_desc,
                comments: None,
                parameters: None,
                xrefs: fw_status_type_xref,
            });
        }
    }

    (ie_id, ret)
}

/// Parse IANA Subregistries for the Information Elements
pub(crate) fn parse_ie_subregistries(
    node: &Node<'_, '_>,
    _pen: u32,
) -> HashMap<u16, Vec<InformationElementSubRegistry>> {
    // Subregistry nodes (following ipfix- naming pattern)
    let iana_ie_subreg_pattern = Regex::new(ID_SUBREG_DEFAULT_PATTERN).unwrap();
    let mut iana_ie_subreg_nodes = find_nodes_by_regex(node, &iana_ie_subreg_pattern);

    // Classification Engine Id subregistry node
    if let Some(iana_ie_subreg_class_eng_id) = find_node_by_id(node, ID_SUBREG_CLASS_ENG_ID) {
        iana_ie_subreg_nodes.push(iana_ie_subreg_class_eng_id);
    }

    // HashMap <IE_ID, Vec<InformationElementSubRegistry>>
    let mut ie_subregs: HashMap<u16, Vec<InformationElementSubRegistry>> = HashMap::new();
    for node in iana_ie_subreg_nodes {
        ie_subregs.extend(vec![parse_subregistry(&node)]);
    }

    // Parse Forwarding Status (Value 89) subregistry
    if let Some(iana_ie_subreg_fw_status) = find_node_by_id(node, ID_SUBREG_FW_STATUS) {
        ie_subregs.extend(vec![parse_fw_status_subregistry(&iana_ie_subreg_fw_status)]);
    }

    //dbg!(&ie_subregs);
    ie_subregs
}

pub fn parse_description_string(node: &Node<'_, '_>) -> Option<String> {
    if let Some(description) = node
        .children()
        .find(|x| x.tag_name() == (IANA_NAMESPACE, "description").into())
    {
        let mut desc_text = String::new();
        let mut first = true;
        for cc in description.children() {
            if !first {
                desc_text.push('\n');
                first = false;
            }
            if cc.tag_name() == (IANA_NAMESPACE, "paragraph").into() {
                let body = cc.text().map(|txt| txt.trim().to_string());
                if let Some(body) = body {
                    if !body.trim().is_empty() {
                        desc_text.push_str(body.trim());
                    }
                }
            }
            if cc.tag_name() == (IANA_NAMESPACE, "artwork").into() {
                let body = cc.text().map(|txt| txt.trim().to_string());
                if let Some(body) = body {
                    desc_text.push_str("\n\n```text\n");
                    desc_text.push_str(body.as_str());
                    desc_text.push_str("\n```\n");
                }
            }
        }
        let re = Regex::new(r"\[RFC(?<RFCNUM>\d+)]").unwrap();
        let desc_text = re.replace(&desc_text, RfcLinkSwapper).to_string();
        let re = Regex::new(r"(?<href>https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*))").unwrap();
        let desc_text = re.replace(&desc_text, HttpLinkSwapper);
        Some(desc_text.to_string())
    } else {
        None
    }
}

pub(crate) fn parse_information_elements(node: &Node<'_, '_>, pen: u32) -> Vec<InformationElement> {
    let iana_ie_subreg_parsed = parse_ie_subregistries(node, pen);

    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "record").into())
        .collect::<Vec<_>>();
    let mut ret = vec![];
    for child in &children {
        let name = get_string_child(child, (IANA_NAMESPACE, "name").into());
        let name = if let Some(name) = name {
            if name.as_str() == ASSIGNED_FOR_NF_V9 {
                log::info!("Skipping Netflow V9 element {name}");
                continue;
            }
            if name == *UNASSIGNED {
                log::info!("Skipping unsigned name: {child:?}");
                continue;
            }
            if name == *RESERVED {
                log::info!("Skipping reserved name: {child:?}");
                continue;
            }
            name
        } else {
            log::info!("Skipping a child with no name: {child:?}");
            continue;
        };

        let Some(data_type) =
            get_string_child(child, (IANA_NAMESPACE, "dataType").into()).map(|data_type| {
                if name.as_str() == "samplerId"
                    || name.as_str().eq_ignore_ascii_case("forwardingStatus")
                {
                    "unsigned32".to_string()
                } else {
                    data_type
                }
            })
        else {
            log::info!("Skipping {name} a child with no data type defined: {child:?}");
            continue;
        };
        let group = get_string_child(child, (IANA_NAMESPACE, "group").into());
        let data_type_semantics =
            get_string_child(child, (IANA_NAMESPACE, "dataTypeSemantics").into());
        let element_id = get_string_child(child, (IANA_NAMESPACE, "elementId").into())
            .map(|x| x.as_str().parse::<u16>());
        let element_id = match element_id {
            Some(Ok(element_id)) => element_id,
            Some(Err(err)) => {
                log::info!(
                    "Skipping {name} a child with invalid element id defined `{err:?}`: {child:?}"
                );
                continue;
            }
            None => {
                log::info!("Skipping {name} a child with no element id defined: {child:?}");
                continue;
            }
        };
        let applicability = get_string_child(child, (IANA_NAMESPACE, "applicability").into());
        let status =
            if let Some(status) = get_string_child(child, (IANA_NAMESPACE, "status").into()) {
                status
            } else {
                log::info!("Skipping {name} a child with no status defined: {child:?}");
                continue;
            };
        let description = match parse_description_string(child) {
            Some(description) => description,
            None => {
                log::info!("Skipping {name} a child with no description defined: {child:?}");
                continue;
            }
        };

        let revision = if let Some(revision) =
            get_string_child(child, (IANA_NAMESPACE, "revision").into())
        {
            let rev = match revision.as_str().parse::<u32>() {
                Ok(rev) => rev,
                Err(err) => {
                    log::info!("Skipping {name} a child with invalid revision defined `{err:?}`: {child:?}");
                    continue;
                }
            };
            rev
        } else {
            log::info!("Skipping {name} a child with no revision defined: {child:?}");
            continue;
        };
        let date = if let Some(data) = get_string_child(child, (IANA_NAMESPACE, "date").into()) {
            data
        } else {
            log::info!("Skipping {name} a child with no date defined: {child:?}");
            continue;
        };
        let references = if let Some(references) = child
            .children()
            .find(|x| x.tag_name() == (IANA_NAMESPACE, "references").into())
        {
            get_string_child(&references, (IANA_NAMESPACE, "paragraph").into())
        } else {
            None
        };
        let xrefs = parse_xref(child);
        let units = get_string_child(child, (IANA_NAMESPACE, "units").into());
        let units = units.map(|x| {
            if x == "4-octet words" {
                "fourOctetWords".to_string()
            } else {
                x
            }
        });
        let range = get_string_child(child, (IANA_NAMESPACE, "range").into());

        let subregistry = iana_ie_subreg_parsed.get(&element_id).cloned();

        let ie = InformationElement {
            pen,
            name,
            data_type,
            group,
            data_type_semantics,
            element_id,
            applicability,
            status,
            description,
            revision,
            date,
            references,
            xrefs,
            units,
            range,
            subregistry,
        };
        ret.push(ie);
    }
    ret
}

/// Parse data types, data type semantics, and units registries
pub(crate) fn parse_iana_common_values(
    iana_root: &Node<'_, '_>,
) -> (
    Vec<SimpleRegistry>,
    Vec<SimpleRegistry>,
    Vec<SimpleRegistry>,
) {
    let data_types_node = find_node_by_id(iana_root, ID_IE_DATA_TYPES).unwrap();
    let data_types_parsed = parse_simple_registry(&data_types_node);

    let semantics_node = find_node_by_id(iana_root, ID_SEMANTICS).unwrap();
    let semantics_parsed = parse_simple_registry(&semantics_node);

    let units_node = find_node_by_id(iana_root, ID_UNITS).unwrap();
    let units_parsed = parse_simple_registry(&units_node);

    (data_types_parsed, semantics_parsed, units_parsed)
}
