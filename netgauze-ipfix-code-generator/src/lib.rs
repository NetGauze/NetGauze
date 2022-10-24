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
    generator::*,
    xml_parser::{find_node_by_id, parse_iana_common_values, parse_information_elements, ID_IE},
};
use std::{ffi::OsString, fs, path::Path};
use thiserror::Error;

mod generator;
pub mod xml_parser;

const APP_USER_AGENT: &str = "curl/7.79.1";
const GENERATED_VENDOR_MAIN_SUFFIX: &str = "generated.rs";
const GENERATED_VENDOR_DESER_SUFFIX: &str = "deser_generated.rs";

/// Represent Information Element as read form a registry
#[derive(Debug, Clone)]
pub struct InformationElement {
    pub pen: u32,
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

/// From where to pull the IPFIX definitions
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum RegistrySource {
    /// The registry data is directly encoded here
    String(String),

    /// Pull from an HTTP URL
    Http(String),

    /// Pull from a file accessible on the local filesystem.
    File(String),
}

/// IPFIX can be defined in multiple ways
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum RegistryType {
    /// Use the IANA format as used in [IANA Flow IE](https://www.iana.org/assignments/ipfix/ipfix.xml)
    /// and defined by the schema [IANA Schema](https://www.iana.org/assignments/ipfix/ipfix.rng)
    IanaXML,
}

/// Configuration for a single IPFIX FLow IE entities definition
/// Could be the main IANA registry or a vendor specific source
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SourceConfig {
    source: RegistrySource,
    registry_type: RegistryType,
    /// Private Enterprise Number
    pen: u32,
    /// rust sub-module name under which the IPFIX information will be generated
    mod_name: String,
    /// Name use for various top-level enums (use rust CamelCase convention)
    name: String,
}

impl SourceConfig {
    pub const fn new(
        source: RegistrySource,
        registry_type: RegistryType,
        pen: u32,
        mod_name: String,
        name: String,
    ) -> Self {
        Self {
            source,
            pen,
            registry_type,
            mod_name,
            name,
        }
    }

    pub fn source(&self) -> &RegistrySource {
        &self.source
    }

    pub fn registry_type(&self) -> &RegistryType {
        &self.registry_type
    }

    pub fn pen(&self) -> u32 {
        self.pen
    }

    pub fn mod_name(&self) -> &String {
        &self.mod_name
    }

    pub fn name(&self) -> &String {
        &self.name
    }
}

/// Configuration to generate IPFIX/Netflow entities
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Config {
    iana: SourceConfig,
    vendors: Vec<SourceConfig>,
}

impl Config {
    pub const fn new(iana: SourceConfig, vendors: Vec<SourceConfig>) -> Self {
        Self { iana, vendors }
    }

    pub fn iana(&self) -> &SourceConfig {
        &self.iana
    }

    pub fn vendors(&self) -> &Vec<SourceConfig> {
        &self.vendors
    }
}

#[derive(Error, Debug)]
pub enum GetStringSourceError {
    #[error("http request error")]
    HttpError(#[from] reqwest::Error),
    #[error("reading data from filesystem error")]
    StdIoError(#[from] std::io::Error),
}

/// Get the data from an XML source, and return the root node
fn get_string_source(source: &RegistrySource) -> Result<String, GetStringSourceError> {
    let str = match source {
        RegistrySource::String(xml_string) => xml_string.clone(),
        RegistrySource::Http(url) => {
            let client = reqwest::blocking::ClientBuilder::new()
                .user_agent(APP_USER_AGENT)
                .build()?;
            let resp = client.get(url).send()?;
            resp.text()?
        }
        RegistrySource::File(path) => std::fs::read_to_string(path)?,
    };
    Ok(str)
}

#[derive(Error, Debug)]
pub enum GenerateIanaConfigError {
    #[error("writing generated code to filesystem error")]
    StdIoError(#[from] std::io::Error),

    #[error("error getting registry data from the source")]
    SourceError(#[from] GetStringSourceError),

    #[error("error parsing xml data from the given source")]
    XmlParsingError(#[from] roxmltree::Error),

    #[error("registry type is not supported")]
    UnsupportedRegistryType(RegistryType),
}

/// Specifically generate the IANA configs, unlike vendor specific registries,
/// IANA generate more types related to the IPFIX protocol itself
fn generate_iana(
    out_dir: &OsString,
    config: &SourceConfig,
) -> Result<String, GenerateIanaConfigError> {
    if config.registry_type != RegistryType::IanaXML {
        return Err(GenerateIanaConfigError::UnsupportedRegistryType(
            config.registry_type.clone(),
        ));
    }
    let xml_string = get_string_source(&config.source)?;
    let xml_doc = roxmltree::Document::parse(xml_string.as_str())?;
    let root = xml_doc.root();

    let (_data_types_parsed, semantics_parsed, units_parsed) = parse_iana_common_values(&root);
    let semantics_generated = generate_ie_semantics(&semantics_parsed);
    let units_generated = generate_ie_units(&units_parsed);

    let iana_ie_node = find_node_by_id(&root, ID_IE).unwrap();
    let iana_ie_node_parsed = parse_information_elements(&iana_ie_node, 0);
    let iana_ie_generated = generate_information_element_ids(&iana_ie_node_parsed);

    let iana_deser_generated = generate_pkg_ie_deserializers(&iana_ie_node_parsed);

    let mut iana_output = String::new();
    iana_output.push_str(iana_ie_generated.as_str());
    iana_output.push_str("\n\n");
    iana_output.push_str(generate_ie_values(&iana_ie_node_parsed).as_str());

    let iana_dest_path = Path::new(&out_dir).join(format!("iana_{}", GENERATED_VENDOR_MAIN_SUFFIX));
    fs::write(&iana_dest_path, iana_output)?;

    let iana_deser_dest_path =
        Path::new(&out_dir).join(format!("iana_{}", GENERATED_VENDOR_DESER_SUFFIX));
    fs::write(&iana_deser_dest_path, iana_deser_generated)?;

    let mut ret = String::new();
    ret.push_str(semantics_generated.as_str());
    ret.push_str(units_generated.as_str());
    Ok(ret)
}

#[derive(Error, Debug)]
pub enum GenerateError {
    #[error("writing generated code to filesystem error")]
    StdIoError(#[from] std::io::Error),

    #[error("error in generating IANA configs")]
    GenerateIanaConfigError(#[from] GenerateIanaConfigError),
}

pub fn generate(out_dir: &OsString, config: &Config) -> Result<(), GenerateError> {
    let iana_gen = generate_iana(out_dir, config.iana())?;

    let mut ie_output = String::new();
    ie_output.push_str(generate_common_types().as_str());
    ie_output.push_str(generate_ie_status().as_str());

    ie_output.push_str(iana_gen.as_str());

    let mut ie_deser = String::new();
    ie_deser.push_str("use crate::ie::*;\n\n");

    let mut names = vec![(
        config.iana.name.clone(),
        config.iana.mod_name.clone(),
        config.iana.pen(),
    )];
    for vendor in &config.vendors {
        names.push((vendor.name.clone(), vendor.mod_name.clone(), vendor.pen));
    }
    ie_output.push_str(generate_ie_ids(&names).as_str());

    ie_output.push_str(
        format!(
            "pub mod {} {{include!(concat!(env!(\"OUT_DIR\"), \"/{}_{}\"));}}\n\n",
            config.iana.mod_name(),
            config.iana.mod_name(),
            GENERATED_VENDOR_MAIN_SUFFIX
        )
        .as_str(),
    );
    ie_deser.push_str(
        format!(
            "pub mod {} {{include!(concat!(env!(\"OUT_DIR\"), \"/{}_{}\"));}}\n\n",
            config.iana.mod_name(),
            config.iana.mod_name(),
            GENERATED_VENDOR_DESER_SUFFIX
        )
        .as_str(),
    );
    for vendor in &config.vendors {
        ie_output.push_str(
            format!(
                "pub mod {} {{include!(concat!(env!(\"OUT_DIR\"), \"/{}_{}\"));}}\n\n",
                vendor.mod_name(),
                vendor.mod_name(),
                GENERATED_VENDOR_MAIN_SUFFIX
            )
            .as_str(),
        );
        ie_deser.push_str(
            format!(
                "pub mod {} {{include!(concat!(env!(\"OUT_DIR\"), \"/{}_{}\"));}}\n\n",
                vendor.mod_name(),
                vendor.mod_name(),
                GENERATED_VENDOR_DESER_SUFFIX
            )
            .as_str(),
        );
    }

    ie_deser.push_str(generate_ie_record_enum_for_ie_deserializer(&names).as_str());
    let ie_dest_path = Path::new(&out_dir).join("ie_generated.rs");
    fs::write(&ie_dest_path, ie_output)?;

    let ie_deser_dest_path = Path::new(&out_dir).join("ie_deser_generated.rs");
    fs::write(&ie_deser_dest_path, ie_deser)?;
    Ok(())
}
