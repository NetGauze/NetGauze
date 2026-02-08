# Services to receive udp-notif packets

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netgauze-udp-notif-service.svg

[crates-url]: https://crates.io/crates/netgauze-udp-notif-service

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/NetGauze/NetGauze/blob/main/LICENSE

[docs-badge]: https://docs.rs/netgauze-udp-notif-service/badge.svg

[docs-url]: https://docs.rs/netgauze-udp-notif-service


Building blocks to develop udp-notif collectors.
See [udp-notif-print](examples/udp-notif-print.rs) for a simple
example to receive udp-notif packets from the network.

## Features

- UDP-Notif packet decoding and framing
- Actor-based listener for async runtimes
- Subscription management and fan-out
- Example services for printing and actor pipelines

## Usage (high-level)

Create a UDP-Notif actor, subscribe to packet streams, and process decoded packets. See the examples directory for
end-to-end wiring.

## Run example

Simple server that will listen to udp-notif packets.
It decodes the packets and prints them out to the console.

```cargo run --example udp-notif-print```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
