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
use std::{env, path::Path};

const IPFIX_URL: &str = "https://www.iana.org/assignments/ipfix/ipfix.xml";
const PROTOCOL_NUMBERS_URL: &str =
    "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml";
const PSAMP_PARAMETERS_URL: &str =
    "https://www.iana.org/assignments/psamp-parameters/psamp-parameters.xml";
const SEGMENT_ROUTING_URL: &str =
    "https://www.iana.org/assignments/segment-routing/segment-routing.xml";

fn get_iana_config(
    poll_iana_registry: bool,
    registry_path: &Path,
    sub_registry_path: &Path,
) -> SourceConfig {
    // FlowDirection SubRegistry Path
    let flow_direction_path = sub_registry_path
        .join("iana_flow_direction.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load flowDirection registry file");

    // Add any external sub-registries for IANA
    let mut external_sub_registries = vec![ExternalSubRegistrySource::new(
        RegistrySource::File(flow_direction_path.clone()),
        SubRegistryType::ValueNameDescRegistry,
        String::from("ipfix-flow-direction"),
        61,
    )];
    if poll_iana_registry {
        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::Http(PROTOCOL_NUMBERS_URL.to_string()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            4,
        ));
        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::Http(PSAMP_PARAMETERS_URL.to_string()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("psamp-parameters-1"),
            304,
        ));
        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::Http(SEGMENT_ROUTING_URL.to_string()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("srv6-endpoint-behaviors"),
            502,
        ));
        SourceConfig::new(
            RegistrySource::Http(IPFIX_URL.to_string()),
            RegistryType::IanaXML,
            0,
            "iana".to_string(),
            "IANA".to_string(),
            Some(external_sub_registries),
        )
    } else {
        // IPFIX Information Elements Registry Path
        let ipfix_elements_path = registry_path
            .join("iana_ipfix_information_elements.xml")
            .into_os_string()
            .into_string()
            .expect("Couldn't load ipfixElements registry file");

        // Protocol Numbers SubRegistry Path
        let protocol_numbers_path = sub_registry_path
            .join("iana_protocol_numbers.xml")
            .into_os_string()
            .into_string()
            .expect("Couldn't load protocolNumbers registry file");

        // Segment Routing SubRegistry Path
        let segment_routing_path = sub_registry_path
            .join("iana_segment_routing.xml")
            .into_os_string()
            .into_string()
            .expect("Couldn't load segmentRouting registry file");

        // Psamp Parameters SubRegistry Path
        let psamp_parameters_path = sub_registry_path
            .join("iana_psamp_parameters.xml")
            .into_os_string()
            .into_string()
            .expect("Couldn't load psampParameters registry");

        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::File(protocol_numbers_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            4,
        ));
        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::File(segment_routing_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("srv6-endpoint-behaviors"),
            502,
        ));

        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::File(psamp_parameters_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("psamp-parameters-1"),
            304,
        ));

        SourceConfig::new(
            RegistrySource::File(ipfix_elements_path.clone()),
            RegistryType::IanaXML,
            0,
            "iana".to_string(),
            "IANA".to_string(),
            Some(external_sub_registries),
        )
    }
}

fn get_nokia_config(registry_path: &Path) -> SourceConfig {
    let nokia_path = registry_path
        .join("nokia.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load nokia registry file");
    SourceConfig::new(
        RegistrySource::File(nokia_path),
        RegistryType::IanaXML,
        637,
        "nokia".to_string(),
        "Nokia".to_string(),
        None,
    )
}

fn get_netgauze_config(registry_path: &Path) -> SourceConfig {
    let netgauze_path = registry_path
        .join("netgauze.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load netgauze registry file");
    SourceConfig::new(
        RegistrySource::File(netgauze_path),
        RegistryType::IanaXML,
        3746, // Swisscom AG
        "netgauze".to_string(),
        "NetGauze".to_string(),
        None,
    )
}

fn get_vmware_config(
    poll_iana_registry: bool,
    registry_path: &Path,
    sub_registry_path: &Path,
) -> SourceConfig {
    // FlowDirection SubRegistry Path
    let flow_direction_path = sub_registry_path
        .join("iana_flow_direction.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load flowDirection registry file");

    let mut external_sub_registries = vec![ExternalSubRegistrySource::new(
        RegistrySource::File(flow_direction_path.clone()),
        SubRegistryType::ValueNameDescRegistry,
        String::from("ipfix-flow-direction"),
        954,
    )];

    // // Protocol Numbers SubRegistry Path is either loaded from IANA or locally
    if poll_iana_registry {
        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::Http(PROTOCOL_NUMBERS_URL.to_string()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            880,
        ));
    } else {
        let protocol_numbers_path = sub_registry_path
            .join("iana_protocol_numbers.xml")
            .into_os_string()
            .into_string()
            .expect("Couldn't load protocolNumbers registry");
        external_sub_registries.push(ExternalSubRegistrySource::new(
            RegistrySource::File(protocol_numbers_path.clone()),
            SubRegistryType::ValueNameDescRegistry,
            String::from("protocol-numbers-1"),
            880,
        ));
    };

    let vmware_path = registry_path
        .join("vmware.xml")
        .into_os_string()
        .into_string()
        .expect("Couldn't load VMWare registry file");
    SourceConfig::new(
        RegistrySource::File(vmware_path),
        RegistryType::IanaXML,
        6876,
        "vmware".to_string(),
        "VMWare".to_string(),
        Some(external_sub_registries),
    )
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").expect("Couldn't find OUT_DIR in OS env variables");
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let registry_path = Path::new(&manifest_dir).join("registry");
    let sub_registry_path = registry_path.join("subregistry");

    let iana_source = get_iana_config(
        cfg!(feature = "iana-upstream-build"),
        &registry_path,
        &sub_registry_path,
    );
    let nokia_source = get_nokia_config(&registry_path);
    let netgauze_config = get_netgauze_config(&registry_path);
    let vmware_source = get_vmware_config(
        cfg!(feature = "iana-upstream-build"),
        &registry_path,
        &sub_registry_path,
    );
    let configs = Config::new(
        iana_source,
        vec![nokia_source, netgauze_config, vmware_source],
    );
    generate(&out_dir, &configs).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
