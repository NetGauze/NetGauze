# Generate Rust code bindings for IPFIX Information Elements

## Example:

To include the generated IANA and custom registry Information elements, in `build.rs` add the following code

```rust
use std::env;

use netgauze_ipfix_code_generator::{Config, generate, RegistrySource, RegistryType, SourceConfig};

const IPFIX_URL: &str = "https://www.iana.org/assignments/ipfix/ipfix.xml";

fn main() {
    let out_dir = env::var_os("OUT_DIR").expect("Couldn't find OUT_DIR in OS env variables");
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let registry_path = std::path::Path::new(&manifest_dir).join("registry");
    // Add custom registry, the xml file must follow the IANA schema
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
    let iana_source = SourceConfig::new(
        RegistrySource::Http(IPFIX_URL.to_string()),
        RegistryType::IanaXML,
        0,
        "iana".to_string(),
        "IANA".to_string(),
    );
    let configs = Config::new(iana_source, vec![nokia_source]);
    generate(&out_dir, &configs).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
```
