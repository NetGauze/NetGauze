# NetGauze (under-development)

[![Rust](https://github.com/NetGauze/NetGauze/actions/workflows/rust.yml/badge.svg)](https://github.com/NetGauze/NetGauze/actions/workflows/rust.yml)

A collection of network related libraries that includes protocol parsers and daemons.
This project is still in an early stage.

## Supported Protocols

1. BGP
    1. Packet representation and wire format
       serialization/deserialization: [`netgauze-bgp-pkt`](crates/bgp-pkt/README.md)
2. BMP
    1. Packet representation and wire format
       serialization/deserialization: [`netgauze-bmp-pkt`](crates/bmp-pkt/README.md)
    2. Service building block to receive BMP messages: [`netgauze-bmp-service`](crates/bmp-service/README.md)
3. Netflow V9 and IPFIX
    1. Packet representation and wire format
       serialization/deserialization: [`netgauze-flow-pkt`](crates/flow-pkt/README.md)
    2. Service building block to receive messages: [`netgauze-flow-service`](crates/flow-service/README.md)

# Development documentation

*Running Packet Serde Fuzzer*

- Fuzzing BGP
  ```cargo fuzz run fuzz-bgp-pkt```

- Fuzzing BMP
  ```cargo fuzz run fuzz-bmp-pkt```

- Fuzzing IPFIX
  ```cargo fuzz run fuzz-ipfix-pkt```

- Fuzzing Netflow V9
  ```cargo fuzz run fuzz-netflow-v9-pkt```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
