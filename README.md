# NetGauze: Weaving network protocols into one toolkit

[<img alt="github" src="https://img.shields.io/badge/github-netgauze/netgauze-8da0cb??style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/NetGauze/NetGauze)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/NetGauze/NetGauze/ci.yml?branch=main&style=for-the-badge" height="20">](https://github.com/NetGauze/NetGauze/actions?query=branch%3Amain)
[![codecov](https://codecov.io/gh/NetGauze/NetGauze/graph/badge.svg?token=QYU92L6YZJ)](https://codecov.io/gh/NetGauze/NetGauze)

NetGauze is a set of Rust libraries and programs for network monitoring, telemetry collection, and protocol analysis. It
provides high-performance, type-safe packet parsing and serialization for key network protocols, along with a
network telemetry collector daemon that can be used to collect and process telemetry data from multiple sources.

NetGauze leverages Rust's type system to ensure protocol correctness at compile time when possible — packets are
represented as rich, immutable data structures where invalid states are unrepresentable.

## Protocol Libraries

### BGP

- Packet representation and wire format serialization/deserialization: [`netgauze-bgp-pkt`](crates/bgp-pkt/README.md)
- BGP Speaker with connection management and fine-state-machine (FSM): [
  `netgauze-bgp-speaker`](crates/bgp-speaker/README.md)

Supports BGP-4, MP-BGP (IPv4/IPv6 Unicast & Multicast, MPLS VPN, EVPN, BGP-LS), 4-octet ASN, Add-Path, Route Refresh,
Extended Messages, and communities (standard, extended, large).

### BMP

- Packet representation and wire format serialization/deserialization: [`netgauze-bmp-pkt`](crates/bmp-pkt/README.md)
- Support for BMP v3 and v4, including all message types and peer states.
- Service building block for receiving BMP messages: [`netgauze-bmp-service`](crates/bmp-service/README.md)

### IPFIX and NetFlow V9

- Packet representation and wire format serialization/deserialization: [`netgauze-flow-pkt`](crates/flow-pkt/README.md)
- Service building block for receiving messages: [`netgauze-flow-service`](crates/flow-service/README.md)

Includes a code generator for IANA IPFIX Information Elements as well as support for enterprise-specific IEs (e.g.,
VMware, Nokia).

### UDP-Notif

- Packet representation and wire format serialization/deserialization: [
  `netgauze-udp-notif-pkt`](crates/udp-notif-pkt/README.md)
- Service building block for receiving messages: [`netgauze-udp-notif-service`](crates/udp-notif-service/README.md)

### YANG Push

- Data models and YANG validation: [`netgauze-yang-push`](crates/yang-push/README.md)

### NETCONF

- Protocol types, XML parsing, and SSH client wiring: [`netgauze-netconf-proto`](crates/netconf-proto/README.md)

## Collector Daemon

[`netgauze-collector`](crates/collector/README.md) is a network telemetry collector that ties the protocol libraries
together into a deployable service.

**Inputs:** IPFIX/NetFlow V9, UDP-Notif, YANG Push, and Kafka for enrichment data, while BMP and BGP are currently
work in progress.

**Publishers:** Kafka (Avro, JSON, YANG)

**Features:**

- Flow aggregation and enrichment
- OpenTelemetry metrics export (OTLP)
- jemalloc memory allocator for production workloads
- YAML-based configuration with per-module log filtering
- RPM packaging support

```bash
cargo run -p netgauze-collector -- /path/to/config.yaml
```

See example configurations in [`crates/collector/`](crates/collector/).

## Tools

### PCAP Decoder

[`netgauze-pcap-decoder`](crates/pcap-decoder/README.md) — Swiss army knife CLI tool to decode BGP, BMP, IPFIX/NetFlow,
and UDP-Notif from PCAP files into JSON Lines format.

```bash
cargo run -p netgauze-pcap-decoder -- --protocol bmp --ports 11019 input.pcap -o output.jsonl
```

## Foundational Crates

These crates provide shared infrastructure used across the protocol libraries:

| Crate                                           | Purpose                                                          |
|-------------------------------------------------|------------------------------------------------------------------|
| [`netgauze-iana`](crates/iana/)                 | IANA registry constants for address families, capabilities, etc. |
| [`netgauze-parse-utils`](crates/parse-utils/)   | Traits and helpers for nom-based protocol parsing                |
| [`netgauze-serde-macros`](crates/serde-macros/) | Procedural macros for error location tracking in parsers         |
| [`netgauze-locate`](crates/locate/)             | Binary span types for tracking byte positions during parsing     |
| [`netgauze-analytics`](crates/analytics/)       | Analytics and aggregation primitives                             |

## Quick Start

Add the crate you need to your `Cargo.toml`:

```toml
[dependencies]
netgauze-bgp-pkt = "0.9"
```

Parse a BGP message from bytes:

```rust
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};

let raw: & [u8] = & [ /* BGP message bytes */ ];
let span = Span::new(raw);
let mut ctx = BgpParsingContext::default ();
let (_remaining, message) = BgpMessage::from_wire(span, & mut ctx).unwrap();
```

## Design Principles

NetGauze follows a consistent architecture across all protocol crates, documented in [
`docs/pdu_serde.md`](docs/pdu_serde.md):

- **Immutable PDUs** — packets are immutable once constructed
- **Enum-driven correctness** — protocol constants are represented as enums so invalid values are caught at compile time
- **Separated concerns** — packet representation (`*-pkt`) is independent of wire format parsing (`wire/`) and service
  integration (`*-service`)
- **Fuzz-tested** — all protocol parsers are continuously fuzzed via `cargo-fuzz`

# Development Documentation

## Running Tests

NetGauze uses macro tests from the [trybuild](https://crates.io/crates/trybuild) crate and PCAP-based regression tests.

```bash
# Standard test run
cargo test --features=codec

# Regenerate expected macro test output
TRYBUILD=overwrite cargo test

# Regenerate expected PCAP test output
OVERWRITE=true cargo test
```

## Code Formatting and Linting

```bash
cargo +nightly fmt
cargo +nightly clippy --tests -- -Dclippy::all
```

## Running Examples

```bash
# List available examples
ls crates/*/examples

# Run the IPFIX/NetFlow printer
cargo run -p netgauze-flow-service --example print-flow
```

## Fuzz Testing

```bash
cargo install cargo-fuzz

cargo +nightly fuzz run fuzz-bgp-pkt
cargo +nightly fuzz run fuzz-bgp-pkt-serialize
cargo +nightly fuzz run fuzz-bgp-peer
cargo +nightly fuzz run fuzz-bmp-pkt
cargo +nightly fuzz run fuzz-bmp-pkt-serialize
cargo +nightly fuzz run fuzz-ipfix-pkt
cargo +nightly fuzz run fuzz-netflow-v9-pkt
```

## Building RPMs

```bash
cargo install cargo-generate-rpm
cargo build --release -p netgauze-collector
strip target/release/netgauze-collector
cargo generate-rpm -p crates/collector
# Package output: target/generate-rpm/
```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
