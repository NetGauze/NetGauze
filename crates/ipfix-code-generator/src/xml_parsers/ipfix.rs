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
    xml_parsers::{sub_registries::parse_subregistry, xml_common::*},
    InformationElement, InformationElementSubRegistry, SimpleRegistry, SubRegistryType,
};
use regex::Regex;
use roxmltree::Node;
use std::collections::HashMap;

const ID_IE_DATA_TYPES: &str = "ipfix-information-element-data-types";
pub(crate) const ID_IE: &str = "ipfix-information-elements";
const ID_SEMANTICS: &str = "ipfix-information-element-semantics";
const ID_UNITS: &str = "ipfix-information-element-units";
const ASSIGNED_FOR_NF_V9: &str = "Assigned for NetFlow v9 compatibility";
pub(crate) const ID_SUBREG_DEFAULT_ID_PATTERN: &str = "ipfix-";
pub const ID_SUBREG_FW_STATUS: &str = "forwarding-status";
pub const ID_SUBREG_CLASS_ENG_ID: &str = "classification-engine-ids";

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

/// Parse Information Elements Subregistries from the main Registry XML
pub(crate) fn parse_ie_subregistries(
    node: &Node<'_, '_>,
    _pen: u32,
) -> HashMap<u16, Vec<InformationElementSubRegistry>> {
    // Subregistry nodes (following ipfix- naming pattern)
    let ie_subreg_pattern = Regex::new(ID_SUBREG_DEFAULT_ID_PATTERN).unwrap();
    let mut ie_subreg_nodes = find_nodes_by_regex(node, &ie_subreg_pattern);

    // Classification Engine Id subregistry node
    if let Some(ie_subreg_class_eng_id) = find_node_by_id(node, ID_SUBREG_CLASS_ENG_ID) {
        ie_subreg_nodes.push(ie_subreg_class_eng_id);
    }

    // HashMap <IE_ID, Vec<InformationElementSubRegistry>>
    let mut ie_subregs: HashMap<u16, Vec<InformationElementSubRegistry>> = HashMap::new();
    for node in ie_subreg_nodes {
        ie_subregs.extend(vec![parse_subregistry(
            &node,
            SubRegistryType::ValueNameDescRegistry,
        )]);
    }

    // Parse Forwarding Status (Value 89) subregistry
    if let Some(ie_subreg_fw_status) = find_node_by_id(node, ID_SUBREG_FW_STATUS) {
        ie_subregs.extend(vec![parse_subregistry(
            &ie_subreg_fw_status,
            SubRegistryType::ReasonCodeNestedRegistry,
        )]);
    }

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

pub(crate) fn parse_information_elements(
    node: &Node<'_, '_>,
    pen: u32,
    ext_subregs: HashMap<u16, Vec<InformationElementSubRegistry>>,
) -> Vec<InformationElement> {
    // Parse any sub-registries in the main registry
    let mut ie_subreg_parsed = parse_ie_subregistries(node, pen);

    // Add external sub-registries (if for an IE we already have a sub-registry,
    // this will be overwritten by the externally provided one)
    ie_subreg_parsed.extend(ext_subregs);

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

        let subregistry = ie_subreg_parsed.get(&element_id).cloned();

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
