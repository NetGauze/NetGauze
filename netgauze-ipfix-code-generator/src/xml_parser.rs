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

use crate::{InformationElement, SimpleRegistry, Xref};
use roxmltree::{ExpandedName, Node};

pub const IPFIX_URL: &str = "https://www.iana.org/assignments/ipfix/ipfix.xml";
pub const IANA_NAMESPACE: &str = "http://www.iana.org/assignments";
pub const ID_IE_DATA_TYPES: &str = "ipfix-information-element-data-types";
pub const ID_IE: &str = "ipfix-information-elements";
pub const ID_SEMANTICS: &str = "ipfix-information-element-semantics";
pub const ID_UNITS: &str = "ipfix-information-element-units";
pub const UNASSIGNED: &str = "Unassigned";
pub const RESERVED: &str = "Reserved";
pub const ASSIGNED_FOR_NF_V9: &str = "Assigned for NetFlow v9 compatibility";

/// Find descendant node by it's ID
/// If multiple nodes with the same ID exists, the first one is returned
pub fn find_node_by_id<'a, 'input>(
    node: &'input Node<'a, 'input>,
    id: &str,
) -> Option<Node<'a, 'input>> {
    node.descendants().find(|x| x.attribute("id") == Some(id))
}

/// Get the text value of an XML node if applicable
/// For example `<a>bb</a>` returns `Some("bb".to_string())`,
/// while `<a><b/></a>` returns `None`
pub fn get_string_child<'a, 'input>(
    node: &'input Node<'a, 'input>,
    tag_name: ExpandedName,
) -> Option<String> {
    node.children()
        .find(|x| x.tag_name() == tag_name)
        .map(|x| x.text().map(|txt| txt.trim().to_string()))
        .unwrap_or_default()
}

/// Parse tags such as `<xref type="rfc">rfc1233</xref>`
pub fn parse_xref<'a, 'input>(node: &'input Node<'a, 'input>) -> Vec<Xref> {
    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "xref").into())
        .collect::<Vec<_>>();
    let mut xrefs = Vec::new();
    for child in children {
        let ty = child.attribute("type").map(|x| x.to_string());
        let data = child.attribute("data").map(|x| x.to_string());
        if let (Some(ty), Some(data)) = (ty, data) {
            xrefs.push(Xref { ty, data });
        }
    }
    xrefs
}

/// Parse simple registries with just value, name (description), and optionally
/// a comment [IPFIX Information Element Data Types](https://www.iana.org/assignments/ipfix/ipfix.xml#ipfix-information-element-data-types)
/// And [IPFIX Information Element Semantics](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-element-semantics)
pub fn parse_simple_registry<'a, 'input>(node: &'input Node<'a, 'input>) -> Vec<SimpleRegistry> {
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

pub fn parse_description_string<'a, 'input>(node: &'input Node<'a, 'input>) -> Option<String> {
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
        Some(desc_text)
    } else {
        None
    }
}

pub fn parse_information_elements<'a, 'input>(
    node: &'input Node<'a, 'input>,
) -> Vec<InformationElement> {
    let children = node
        .children()
        .filter(|x| x.tag_name() == (IANA_NAMESPACE, "record").into())
        .collect::<Vec<_>>();
    let mut ret = vec![];
    for child in &children {
        let name = get_string_child(child, (IANA_NAMESPACE, "name").into());
        if Some(true)
            == name
                .as_ref()
                .map(|x| x.as_str() == UNASSIGNED || x.as_str() == RESERVED)
        {
            continue;
        }
        let data_type = get_string_child(child, (IANA_NAMESPACE, "dataType").into());
        let group = get_string_child(child, (IANA_NAMESPACE, "group").into());
        let data_type_semantics =
            get_string_child(child, (IANA_NAMESPACE, "dataTypeSemantics").into());
        let element_id = get_string_child(child, (IANA_NAMESPACE, "elementId").into())
            .map(|x| x.as_str().parse::<u16>());
        let applicability = get_string_child(child, (IANA_NAMESPACE, "applicability").into());
        let status = get_string_child(child, (IANA_NAMESPACE, "status").into());
        let description = parse_description_string(child);

        let revision = get_string_child(child, (IANA_NAMESPACE, "revision").into())
            .map(|x| x.as_str().parse::<u32>());
        let date = get_string_child(child, (IANA_NAMESPACE, "date").into());
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
        let range = get_string_child(child, (IANA_NAMESPACE, "range").into());

        if Some(true) == name.as_ref().map(|x| x.as_str() == ASSIGNED_FOR_NF_V9) {
            log::info!(
                "Skipping Netflow V9 element {:?} with element id: {:?}",
                name,
                element_id
            );
            continue;
        }

        if None == name {
            log::info!("Skipping a child with no name: {:?}", child);
            continue;
        }
        let ie = InformationElement {
            name: name.unwrap(),
            data_type: data_type.unwrap(),
            group,
            data_type_semantics,
            element_id: element_id.unwrap().unwrap(),
            applicability,
            status: status.unwrap(),
            description: description.unwrap(),
            revision: revision.unwrap().unwrap(),
            date: date.unwrap(),
            references,
            xrefs,
            units,
            range,
        };
        ret.push(ie);
    }
    ret
}

/// Parse data types, data type semantics, and units registries
pub fn parse_iana_common_values<'a, 'input>(
    iana_root: &'input Node<'a, 'input>,
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
