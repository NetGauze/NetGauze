# UDP-Notif Packet Library

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netgauze-udp-notif-pkt.svg
[crates-url]: https://crates.io/crates/netgauze-udp-notif-pkt
[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg
[apache-url]: https://github.com/NetGauze/NetGauze/blob/main/LICENSE
[docs-badge]: https://docs.rs/netgauze-udp-notif-pkt/badge.svg
[docs-url]: https://docs.rs/netgauze-udp-notif-pkt


A complete Rust implementation of [draft-ietf-netconf-udp-notif](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-udp-notif) for UDP-based transport of YANG Push streaming telemetry notifications.

## Features

- **Multi-layer API**: Raw wire format, decoded notifications, and YANG data structures
- **Zero-copy parsing**: Efficient `Bytes`-based for raw payload handling
- **Media type support**: JSON (`application/yang-data+json`) and CBOR (`application/yang-data+cbor`)
- **Protocol options**: Segmentation and private encoding extensions
- **Dual notification formats**: Standard NETCONF notification (RFC 8639/RFC 8641) and YANG-based notification envelope [draft-ietf-netconf-notif-envelope](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-notif-envelope)
- **Async codec**: Tokio-based UDP framing for stream processing
- **Type-safe**: Strongly typed YANG Push notification structures from RFC 8639 and RFC 8641

## Architecture

The library provides three levels of abstraction:

### `raw` - Wire Format Layer
Direct access to UDP-Notif packet structure with unparsed payload bytes. Use for maximum performance, custom processing, or protocol-level inspection.

```rust,ignore
use udp_notif_pkt::raw::UdpNotifPacket;

// Access packet metadata and raw payload
let version = packet.version();
let publisher_id = packet.publisher_id();
let payload_bytes = packet.payload();
```

### `decoded` - Parsed Notification Layer
Automatic JSON/CBOR deserialization into structured Rust types. Use for type-safe access to notification contents.

```rust,ignore
use udp_notif_pkt::decoded::{UdpNotifPacketDecoded, UdpNotifPayload};

let decoded: UdpNotifPacketDecoded = (&raw_packet).try_into()?;
match decoded.payload() {
    UdpNotifPayload::NotificationEnvelope(envelope) => {
        // Handle modern format
    }
    UdpNotifPayload::NotificationLegacy(legacy) => {
        // Handle legacy format
    }
}
```

### `notification` - YANG Data Structures
Complete YANG Push notification types (subscriptions, updates, lifecycle events).

```rust,ignore
use udp_notif_pkt::notification::NotificationVariant;

match variant {
    NotificationVariant::YangPushUpdate(update) => {
        println!("Update for subscription {}", update.id());
    }
    NotificationVariant::SubscriptionStarted(sub) => {
        println!("Subscription started with encoding {:?}", sub.encoding());
    }
    // ... handle other notification types
}
```
