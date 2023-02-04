# NetGauze (under-development)

[![Rust](https://github.com/NetGauze/NetGauze/actions/workflows/rust.yml/badge.svg)](https://github.com/NetGauze/NetGauze/actions/workflows/rust.yml)

A collection of network related libraries that includes protocol parsers and daemons.
This project is still in an early stage.

## Supported Protocols

1. BGP, `netgauze-bgp-pkt`
2. BMP, `netgauze-bmp-pkt`
3. Netflow V9 and IPFIX `netgauze-flow-pkt`

# Development documentation

*Running Packet Serde Fuzzer*
```cargo fuzz run fuzz-bgp-pkt```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
