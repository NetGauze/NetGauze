# NetGauze YANG-Push crate

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netgauze-yang-push.svg

[crates-url]: https://crates.io/crates/netgauze-yang-push

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/NetGauze/NetGauze/blob/main/LICENSE

[docs-badge]: https://docs.rs/netgauze-yang-push/badge.svg

[docs-url]: https://docs.rs/netgauze-yang-push


YANG-Push support for the NetGauze ecosystem,
including [IETF Telemetry Message](https://datatracker.ietf.org/doc/html/draft-netana-nmop-message-broker-telemetry-message)
model, a persistent YANG library cache, and actor-based validation for
UDP-Notif packets.

## What this crate provides

- **Telemetry model** for the IETF telemetry message payload
- **YANG library cache** with disk persistence and subscription indexing
- **NETCONF/SSH fetcher** for retrieving YANG libraries and schemas
- **Validation actor** that validates incoming YANG-Push notifications using
  cached schemas
- **OpenTelemetry metrics** for cache and validation behavior

## Module overview

- `model`: Telemetry message data structures (serde-friendly)
- `cache`: YANG library cache, fetchers, and actor-based access
- `validation`: Actor that validates UDP-Notif YANG-Push packets

## Quick start (actor pipeline)

This crate is typically wired between a UDP-Notif receiver and your downstream
processor. The flow is:

1. Receive UDP-Notif packets
2. Cache actor retrieves or fetches YANG libraries
3. Validation actor validates packets (or forwards unvalidated when schemas
   are not available)

## YANG library cache

The cache stores YANG libraries by content ID and associates them with
subscription metadata. It persists to disk with the following layout:

```text
<cache_root_path>/
  <content-id>/
    yang-lib.xml
    subscriptions-info.json
    modules/
      <module>.yang
```

Use `cache::storage::YangLibraryCache` for direct access or
`cache::actor::CacheActorHandle` for concurrent access and fetch deduplication.

## NETCONF fetcher

`cache::fetcher::NetconfYangLibraryFetcher` retrieves YANG libraries and schema
modules from devices over NETCONF/SSH. It implements the
`cache::fetcher::YangLibraryFetcher` trait and is used by the cache actor on
cache misses.

## Validation actor

`validation::ValidationActorHandle` validates UDP-Notif payloads when schemas
are available. It:

- Caches packets while schemas are loading
- Enforces per-peer and per-subscription cache limits
- Forwards unvalidated packets when schemas are unavailable

## Telemetry model

`model::telemetry` defines the telemetry message wrapper and metadata types for
serialization and deserialization using `serde`.

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
