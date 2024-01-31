# NetGauze (under-development)

[<img alt="github" src="https://img.shields.io/badge/github-netgauze/netgauze-8da0cb??style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/NetGauze/NetGauze)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/NetGauze/NetGauze/ci.yml?branch=main&style=for-the-badge" height="20">](https://github.com/NetGauze/NetGauze/actions?query=branch%3Amain)
[![codecov](https://codecov.io/gh/NetGauze/NetGauze/graph/badge.svg?token=QYU92L6YZJ)](https://codecov.io/gh/NetGauze/NetGauze)

A collection of network related libraries that includes protocol parsers and daemons.
This project is still in an early stage.

## Supported Protocols

1. BGP
    1. Packet representation and wire format
       serialization/deserialization: [`netgauze-bgp-pkt`](crates/bgp-pkt/README.md)
    2. BGP Speaker (including connection management and FSM): [`netgauze-bgp-speaker`](crates/bgp-speaker/README.md)
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

- Fuzzing BGP Peer
  ```cargo +nightly fuzz run fuzz-bgp-peer```

- Fuzzing BGP pkt serde
  ```
  cargo +nightly fuzz run fuzz-bgp-pkt
  cargo +nightly fuzz run fuzz-bgp-pkt-serialize
  ```

- Fuzzing BMP pkt serde
  ```
  cargo +nightly fuzz run fuzz-bmp-pkt
  cargo +nightly fuzz run fuzz-bmp-pkt-serialize
  ```

- Fuzzing IPFIX
  ```cargo +nightly fuzz run fuzz-ipfix-pkt```

- Fuzzing Netflow V9
  ```cargo +nightly fuzz run fuzz-netflow-v9-pkt```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
