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

use netgauze_ipfix_code_generator::{
    generate, Config, ExternalSubRegistrySource, RegistrySource, RegistryType, SourceConfig,
    SubRegistryType,
};
use std::env;

fn main() {
    let out_dir = env::var_os("OUT_DIR").expect("Couldn't find OUT_DIR in OS env variables");
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let registry_path = std::path::Path::new(&manifest_dir).join("registry");
    let subregistry_path = registry_path.join("subregistry");

    // IPFIX Information Elements SubRegistry Path
    let ipfix_elements_path = subregistry_path
        .join("iana_ipfix_information_elements.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load ipfixElements registry file");

    // Protocol Numbers SubRegistry Path
    let protocol_numbers_path = subregistry_path
        .join("iana_protocol_numbers.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load protocolNumbers registry");

    // FlowDirection SubRegistry Path
    let flow_direction_path = subregistry_path
        .join("iana_flow_direction.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load flowDirection registry file");

    let nokia_path = registry_path
        .join("nokia.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load nokia registry file");
    let nokia_source = SourceConfig::new(
        RegistrySource::File(nokia_path),
        RegistryType::IanaXML,
        637,
        "nokia".to_string(),
        "Nokia".to_string(),
        None,
    );

    // Add any external sub-registries for VMWare
    let external_subregs = vec![
        ExternalSubRegistrySource::new(
            RegistrySource::File(protocol_numbers_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            880,
        ),
        ExternalSubRegistrySource::new(
            RegistrySource::File(flow_direction_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("ipfix-flow-direction"),
            954,
        ),
    ];
    let vmware_path = registry_path
        .join("vmware.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load VMWare registry file");
    let vmware_source = SourceConfig::new(
        RegistrySource::File(vmware_path),
        RegistryType::IanaXML,
        6876,
        "vmware".to_string(),
        "VMWare".to_string(),
        Some(external_subregs),
    );

    // Add any external sub-registries for IANA
    let external_subregs = vec![
        ExternalSubRegistrySource::new(
            RegistrySource::File(protocol_numbers_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            4,
        ),
        ExternalSubRegistrySource::new(
            RegistrySource::File(flow_direction_path),
            SubRegistryType::ValueNameDescRegistry,
            String::from("ipfix-flow-direction"),
            61,
        ),
    ];
    let iana_source = SourceConfig::new(
        RegistrySource::File(ipfix_elements_path.clone()),
        RegistryType::IanaXML,
        0,
        "iana".to_string(),
        "IANA".to_string(),
        Some(external_subregs),
    );
    let configs = Config::new(iana_source, vec![nokia_source, vmware_source]);
    generate(&out_dir, &configs).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
