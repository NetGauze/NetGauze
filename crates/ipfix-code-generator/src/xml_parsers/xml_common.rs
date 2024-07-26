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

use crate::Xref;
use regex::{Captures, Regex, Replacer};
use roxmltree::{ExpandedName, Node};

pub const IANA_NAMESPACE: &str = "http://www.iana.org/assignments";
pub const UNASSIGNED: &str = "Unassigned";
pub const RESERVED: &str = "Reserved";
pub const UNKNOWN: &str = "Unknown";
pub const PRIVATE: &str = "Private";
pub const EXPERIMENTATION: &str = "experimentation";

pub struct RfcLinkSwapper;
impl Replacer for RfcLinkSwapper {
    fn replace_append(&mut self, caps: &Captures<'_>, dst: &mut String) {
        dst.push_str("[RFC");
        dst.push_str(&caps["RFCNUM"]);
        dst.push_str("](https://datatracker.ietf.org/doc/rfc");
        dst.push_str(&caps["RFCNUM"]);
        dst.push(')');
    }
}

pub struct HttpLinkSwapper;
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

/// Find descendant node with ID matching on a regex
pub(crate) fn find_node_by_regex<'a, 'input>(
    node: &'input Node<'a, 'input>,
    regex: &Regex,
) -> Option<Node<'a, 'input>> {
    node.children().find(|x| {
        !x.is_root()
            && x.attribute("id")
                .map(|id| regex.is_match(id))
                .unwrap_or(false)
    })
}

/// Return all children nodes with ID matching the regex (ignoring root node)
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
pub fn get_string_child(node: &Node<'_, '_>, tag_name: ExpandedName<'_, '_>) -> Option<String> {
    node.children()
        .find(|x| x.tag_name() == tag_name)
        .map(|x| x.text().map(|txt| txt.trim().to_string()))
        .unwrap_or_default()
}

/// Parse tags such as `<xref type="rfc">rfc1233</xref>`
pub fn parse_xref(node: &Node<'_, '_>) -> Vec<Xref> {
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

fn replace_first_numeric_char(value: &str) -> String {
    match value.chars().next() {
        Some('0') => "Zero".to_string() + &value[1..],
        Some('1') => "One".to_string() + &value[1..],
        Some('2') => "Two".to_string() + &value[1..],
        Some('3') => "Three".to_string() + &value[1..],
        Some('4') => "Four".to_string() + &value[1..],
        Some('5') => "Five".to_string() + &value[1..],
        Some('6') => "Six".to_string() + &value[1..],
        Some('7') => "Seven".to_string() + &value[1..],
        Some('8') => "Eight".to_string() + &value[1..],
        Some('9') => "Nine".to_string() + &value[1..],
        _ => value.to_string(),
    }
}

/// Convert a description string to a usable enum type name
/// Use e.g. for registries missing a name field where we need
/// to use a (possibly complex) description string.
///
/// - removes line breaks and trimming
/// - only selects text preceding any ":", useful for e.g. [IPFIX MPLS label type (Value 46)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-mpls-label-type)
/// - removes ascii punctuation
/// - removes spaces
/// - replaces first numeric char (e.g. 3PC --> ThreePC)
///
/// TODO: feedback to Benoit
pub fn xml_string_to_enum_type(input: &str) -> (usize, String) {
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
    let mut str_without_spaces = str_before_column
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation())
        .collect::<String>();

    // Replace first numeric char if we have one
    if let Some(first_char) = str_without_spaces.chars().next() {
        if first_char.is_numeric() {
            str_without_spaces = replace_first_numeric_char(&str_without_spaces);
        }
    }

    (str_words_amount, str_without_spaces)
}

/// Parse a simple description string
pub fn parse_simple_description_string(node: &Node<'_, '_>) -> Option<String> {
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
