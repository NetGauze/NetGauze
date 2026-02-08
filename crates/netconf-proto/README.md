# netgauze-netconf-proto

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netgauze-netconf-proto.svg

[crates-url]: https://crates.io/crates/netgauze-netconf-proto

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/NetGauze/NetGauze/blob/main/LICENSE

[docs-badge]: https://docs.rs/netgauze-netconf-proto/badge.svg

[docs-url]: https://docs.rs/netgauze-netconf-proto


Low-level NETCONF protocol implementation with XML serialization and
NETCONF-over-SSH client helpers. This crate provides the building blocks for
NETCONF message handling, YANG library utilities, and schema dependency tools.

## Features

- NETCONF message model (`Hello`, `Rpc`, `RpcReply`) with XML (de)serialization
- NETCONF-over-SSH client configuration and session helpers
- XML parsing/writing utilities with namespace support
- YANG library model (RFC 8525) with dependency graph support
- Optional schema registry integration helpers

## Modules

- `protocol`: NETCONF messages and XML encoding/decoding
- `client`: SSH client and session helpers
- `codec`: NETCONF framing over SSH channels
- `xml_utils`: XML parser/writer traits and helpers
- `yanglib`: YANG library model and dependency graph utilities
- `capabilities`: NETCONF capability types

## Usage

Parse a NETCONF `<hello>` message:

```rust,ignore
use netgauze_netconf_proto::protocol::{NetConfMessage, Hello};
use netgauze_netconf_proto::xml_utils::{XmlParser, XmlDeserialize};
use quick_xml::NsReader;

let xml = r#"
    <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        <capabilities>
            <capability>urn:ietf:params:netconf:base:1.0</capability>
        </capabilities>
    </hello>"#;

let mut reader = NsReader::from_str(xml);
let mut parser = XmlParser::new(reader)?;
let hello = Hello::xml_deserialize(&mut parser)?;
```

Connect to a NETCONF server and load YANG dependencies:

```rust,ignore
use netgauze_netconf_proto::client::{NetconfSshConnectConfig, SshAuth, SshHandler, connect};
use netgauze_netconf_proto::yanglib::PermissiveVersionChecker;
use std::sync::Arc;

let auth = SshAuth::Password { user, password };
let config = NetconfSshConnectConfig::new(auth, host, SshHandler::default(), Arc::new(ssh_cfg));
let mut client = connect(config).await?;
let (yang_lib, schemas) = client
    .load_from_modules(&["ietf-interfaces"], &PermissiveVersionChecker)
    .await?;
```

## Examples

- `examples/example.rs`: Connect to a device and load YANG modules
- `examples/fetch_schemas.rs`: Fetch schemas, save to disk, or register with a
  schema registry

Run an example:

```sh
cargo run --example example -- --help
```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
