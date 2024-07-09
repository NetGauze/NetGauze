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

use netgauze_ipfix_code_generator::{generate, Config, RegistrySource, RegistryType, SourceConfig};
use std::env;

const IPFIX_URL: &str = "https://www.iana.org/assignments/ipfix/ipfix.xml";

fn main() {
    let out_dir = env::var_os("OUT_DIR").expect("Couldn't find OUT_DIR in OS env variables");
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let registry_path = std::path::Path::new(&manifest_dir).join("registry");
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
    );
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
    );
    let iana_source = SourceConfig::new(
        RegistrySource::Http(IPFIX_URL.to_string()),
        RegistryType::IanaXML,
        0,
        "iana".to_string(),
        "IANA".to_string(),
    );
    let configs = Config::new(iana_source, vec![nokia_source, vmware_source]);
    generate(&out_dir, &configs).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
