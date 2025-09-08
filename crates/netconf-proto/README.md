# netgauze-netconf-proto

Low-level NETCONF protocol implementation for Rust with XML serialization and deserialization support.

### Message Types

- `Hello` - NETCONF session establishment
- `Rpc` - RPC request messages
- `RpcReply` - RPC response messages with support for ok/error responses
- `RpcError` - Detailed error information per RFC 6241

## Usage

```rust
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
