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
    xml_parsers::{
        ipfix::{parse_iana_common_values, parse_information_elements, ID_IE},
        xml_common::find_node_by_id,
    },
};
use std::{collections::HashMap, ffi::OsString, fs, path::Path};
use thiserror::Error;
use xml_parsers::sub_registries::parse_subregistry;

mod generator;
mod generator_aggregation;
mod generator_sub_registries;

pub mod xml_parsers {
    pub mod ipfix;
    pub mod sub_registries;
    pub mod xml_common;
}

const APP_USER_AGENT: &str = "curl/7.79.1";
const GENERATED_VENDOR_MAIN_SUFFIX: &str = "generated.rs";
const GENERATED_VENDOR_DESER_SUFFIX: &str = "deser_generated.rs";
const GENERATED_VENDOR_SER_SUFFIX: &str = "ser_generated.rs";

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
    pub subregistry: Option<Vec<InformationElementSubRegistry>>,
}

/// There could be different types of subregistries that require a different
/// parsing and/or code generator.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub enum SubRegistryType {
    /// Simple sub-registries with Value and (Name and/or Description)
    /// plus optional comment, parameters, xrefs, such as:
    /// [flowEndReason (Value 136)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason)
    ValueNameDescRegistry,
    /// Sub-registries with nested registries for reason code, such as:
    /// [Forwarding Status (Value 89)](https://www.iana.org/assignments/ipfix/ipfix.xml#forwarding-status)
    ReasonCodeNestedRegistry,
}

/// Abstracts Information Element sub-registries types
#[derive(Debug, Clone)]
pub enum InformationElementSubRegistry {
    ValueNameDescRegistry(ValueNameDescRegistry),
    ReasonCodeNestedRegistry(ReasonCodeNestedRegistry),
}

/// Describes simple sub-registries with Value and (Name and/or Description)
/// plus optional comment, parameters, xrefs, such as:
/// [flowEndReason (Value 136)](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason)
#[derive(Debug, Clone, Default)]
pub struct ValueNameDescRegistry {
    pub value: u8,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub comments: Option<String>,
    pub parameters: Option<String>,
    pub xrefs: Vec<Xref>,
}

/// Describes sub-registries with nested registries for reason code, such as:
/// [Forwarding Status (Value 89)](https://www.iana.org/assignments/ipfix/ipfix.xml#forwarding-status)
#[derive(Debug, Clone, Default)]
pub struct ReasonCodeNestedRegistry {
    pub value: u8,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub comments: Option<String>,
    pub parameters: Option<String>,
    pub xrefs: Vec<Xref>,
    pub reason_code_reg: Vec<InformationElementSubRegistry>,
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

/// Configuration for a single IPFIX Flow IE entities definition
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
    /// External IANA subregistries for the IEs
    ext_subregs_source: Option<Vec<ExternalSubRegistrySource>>,
}

impl SourceConfig {
    pub const fn new(
        source: RegistrySource,
        registry_type: RegistryType,
        pen: u32,
        mod_name: String,
        name: String,
        ext_subregs_source: Option<Vec<ExternalSubRegistrySource>>,
    ) -> Self {
        Self {
            source,
            registry_type,
            pen,
            mod_name,
            name,
            ext_subregs_source,
        }
    }

    pub const fn source(&self) -> &RegistrySource {
        &self.source
    }

    pub const fn registry_type(&self) -> &RegistryType {
        &self.registry_type
    }

    pub const fn pen(&self) -> u32 {
        self.pen
    }

    pub const fn mod_name(&self) -> &String {
        &self.mod_name
    }

    pub const fn name(&self) -> &String {
        &self.name
    }

    pub const fn ext_subregs_source(&self) -> &Option<Vec<ExternalSubRegistrySource>> {
        &self.ext_subregs_source
    }
}

/// From where to pull the external sub-registries
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ExternalSubRegistrySource {
    source: RegistrySource,
    // Subregistry type to be used for parsing
    registry_type: SubRegistryType,
    // ID which identifies the registry in the XML document
    registry_id: String,
    // Information Element ID to which the SubRegistry is referencing
    ie_id: u16,
}

impl ExternalSubRegistrySource {
    pub const fn new(
        source: RegistrySource,
        registry_type: SubRegistryType,
        registry_id: String,
        ie_id: u16,
    ) -> Self {
        Self {
            source,
            registry_type,
            registry_id,
            ie_id,
        }
    }

    pub const fn registry_type(&self) -> &SubRegistryType {
        &self.registry_type
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

    pub const fn iana(&self) -> &SourceConfig {
        &self.iana
    }

    pub const fn vendors(&self) -> &Vec<SourceConfig> {
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
pub fn get_string_source(source: &RegistrySource) -> Result<String, GetStringSourceError> {
    let str = match source {
        RegistrySource::String(xml_string) => xml_string.clone(),
        RegistrySource::Http(url) => {
            let client = reqwest::blocking::ClientBuilder::new()
                .user_agent(APP_USER_AGENT)
                .build()?;
            let resp = client.get(url).send()?;
            resp.text()?
        }
        RegistrySource::File(path) => fs::read_to_string(path)?,
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
fn generate_vendor_ie(
    out_dir: &OsString,
    config: &SourceConfig,
) -> Result<(), GenerateIanaConfigError> {
    if config.registry_type != RegistryType::IanaXML {
        return Err(GenerateIanaConfigError::UnsupportedRegistryType(
            config.registry_type.clone(),
        ));
    }
    let ipfix_xml_string = get_string_source(&config.source)?;
    let ipfix_xml_doc = roxmltree::Document::parse(ipfix_xml_string.as_str())?;
    let ipfix_root = ipfix_xml_doc.root();

    // Parse any external sub-registries provided:
    let mut ext_subregs: HashMap<u16, Vec<InformationElementSubRegistry>> = HashMap::new();
    if let Some(ext_subregs_source) = &config.ext_subregs_source {
        for subreg in ext_subregs_source {
            let subreg_xml_string = get_string_source(&subreg.source)?;
            let subreg_xml_doc = roxmltree::Document::parse(subreg_xml_string.as_str())?;
            let subreg_root = subreg_xml_doc.root();

            let subreg_node = find_node_by_id(&subreg_root, &subreg.registry_id).unwrap();
            ext_subregs.insert(
                subreg.ie_id,
                parse_subregistry(&subreg_node, subreg.registry_type).1,
            );
        }
    }

    let ipfix_ie_node = find_node_by_id(&ipfix_root, ID_IE).unwrap();
    let ie_parsed = parse_information_elements(&ipfix_ie_node, config.pen, ext_subregs);

    let ie_generated = generate_information_element_ids(&ie_parsed);

    let deser_generated = generate_pkg_ie_deserializers(config.mod_name.as_str(), &ie_parsed);
    let ser_generated = generate_pkg_ie_serializers(config.mod_name.as_str(), &ie_parsed);

    let mut output = String::new();
    output.push_str(ie_generated.as_str());
    output.push_str("\n\n");

    output.push_str(generate_ie_values(&ie_parsed, Some(config.name().clone())).as_str());
    output.push_str(generate_fields_enum(&ie_parsed).as_str());

    output.push_str(generate_flat_ie_struct(&ie_parsed, &vec![]).as_str());

    let dest_path = Path::new(&out_dir).join(format!(
        "{}_{}",
        config.mod_name, GENERATED_VENDOR_MAIN_SUFFIX
    ));
    fs::write(dest_path, output)?;

    let deser_dest_path = Path::new(&out_dir).join(format!(
        "{}_{}",
        config.mod_name, GENERATED_VENDOR_DESER_SUFFIX
    ));
    fs::write(deser_dest_path, deser_generated)?;

    let ser_dest_path = Path::new(&out_dir).join(format!(
        "{}_{}",
        config.mod_name, GENERATED_VENDOR_SER_SUFFIX
    ));
    fs::write(ser_dest_path, ser_generated)?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum GenerateError {
    #[error("writing generated code to filesystem error")]
    StdIoError(#[from] std::io::Error),

    #[error("error in generating IANA configs")]
    GenerateIanaConfigError(#[from] GenerateIanaConfigError),

    #[error("error getting registry data from the source")]
    SourceError(#[from] GetStringSourceError),

    #[error("error parsing xml data from the given source")]
    XmlParsingError(#[from] roxmltree::Error),

    #[error("registry type is not supported")]
    UnsupportedRegistryType(RegistryType),
}

pub fn generate(out_dir: &OsString, config: &Config) -> Result<(), GenerateError> {
    let mut ie_output = String::new();
    ie_output.push_str(generate_common_types().as_str());
    ie_output.push_str(generate_ie_status().as_str());

    // Start parsing the IANA registry
    let ipfix_xml_string = get_string_source(&config.iana.source)?;
    let ipfix_xml_doc = roxmltree::Document::parse(ipfix_xml_string.as_str())?;
    let iana_ipfix_root = ipfix_xml_doc.root();

    let (_data_types_parsed, semantics_parsed, units_parsed) =
        parse_iana_common_values(&iana_ipfix_root);
    let semantics_generated = generate_ie_semantics(&semantics_parsed);
    let units_generated = generate_ie_units(&units_parsed);
    ie_output.push_str(semantics_generated.as_str());
    ie_output.push_str(units_generated.as_str());

    // Parse any external sub-registries provided:
    let mut ext_subregs: HashMap<u16, Vec<InformationElementSubRegistry>> = HashMap::new();
    if let Some(ext_subregs_source) = &config.iana.ext_subregs_source {
        for subreg in ext_subregs_source {
            let subreg_xml_string = get_string_source(&subreg.source)?;
            let subreg_xml_doc = roxmltree::Document::parse(subreg_xml_string.as_str())?;
            let subreg_root = subreg_xml_doc.root();

            let subreg_node = find_node_by_id(&subreg_root, &subreg.registry_id).unwrap();
            ext_subregs.insert(
                subreg.ie_id,
                parse_subregistry(&subreg_node, subreg.registry_type).1,
            );
        }
    }

    let iana_ipfix_ie_node = find_node_by_id(&iana_ipfix_root, ID_IE).unwrap();
    let iana_ie_parsed = parse_information_elements(&iana_ipfix_ie_node, 0, ext_subregs);


    let mut vendors = vec![];
    for vendor in &config.vendors {
        vendors.push((vendor.name.clone(), vendor.mod_name.clone(), vendor.pen));
        generate_vendor_ie(out_dir, vendor)?;
    }

    // Generate IANA IE and reference to vendor specific IEs
    ie_output.push_str(generate_ie_ids(&iana_ie_parsed, &vendors).as_str());
    ie_output.push_str(generate_ie_values(&iana_ie_parsed, None).as_str());

    let mut ie_deser = String::new();
    let mut ie_ser = String::new();
    ie_deser.push_str("use crate::ie::*;\n\n");
    ie_ser.push_str("use crate::ie::*;\n\n");

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
        ie_ser.push_str(
            format!(
                "pub mod {} {{include!(concat!(env!(\"OUT_DIR\"), \"/{}_{}\"));}}\n\n",
                vendor.mod_name(),
                vendor.mod_name(),
                GENERATED_VENDOR_SER_SUFFIX
            )
            .as_str(),
        );
    }

    ie_output.push_str(generate_flat_ie_struct(&iana_ie_parsed, &vendors).as_str());
    ie_deser.push_str(generate_ie_deser_main(&iana_ie_parsed, &vendors).as_str());
    ie_ser.push_str(generate_ie_ser_main(&iana_ie_parsed, &vendors).as_str());

    let ie_dest_path = Path::new(&out_dir).join("ie_generated.rs");
    fs::write(ie_dest_path, ie_output)?;

    let ie_deser_dest_path = Path::new(&out_dir).join("ie_deser_generated.rs");
    fs::write(ie_deser_dest_path, ie_deser)?;

    let ie_ser_dest_path = Path::new(&out_dir).join("ie_ser_generated.rs");
    fs::write(ie_ser_dest_path, ie_ser)?;
    Ok(())
}
