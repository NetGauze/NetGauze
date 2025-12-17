// Copyright (C) 2024-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # UDP-Notif Packet Library
//!
//! This crate provides a complete implementation of
//! [draft-ietf-netconf-udp-notif](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-udp-notif),
//! supporting both low-level packet manipulation and high-level decoded
//! notification handling for YANG-Push telemetry.
//!
//! ## Module Overview
//!
//! The library is organized into three main layers, each serving a specific
//! purpose:
//!
//! ### [`raw`] - Wire Format Layer
//!
//! The foundational layer providing direct access to UDP-Notif packet structure
//! with unparsed payload bytes. Use this when you need:
//! - Maximum performance with zero-copy operations
//! - Custom payload processing
//! - Protocol-level inspection or manipulation
//! - Building custom transport layers
//!
//! Key types: [`raw::UdpNotifPacket`], [`raw::MediaType`],
//! [`raw::UdpNotifOption`]
//!
//! ### [`decoded`] - Parsed Notification Layer
//!
//! Higher-level layer that deserializes JSON/CBOR payloads into structured Rust
//! types. Use this when you want:
//! - Type-safe access to notification contents
//! - Automatic format handling (JSON/CBOR)
//! - Direct access to subscription metadata
//!
//! Key types: [`decoded::UdpNotifPacketDecoded`], [`decoded::UdpNotifPayload`]
//!
//! ### [`notification`] - YANG Data Structures
//!
//! Domain model layer containing all YANG Push notification types as defined
//! in:
//! - [RFC 8639 - Subscription to YANG Notifications](https://datatracker.ietf.org/doc/html/rfc8639)
//! - [RFC 8641 - Subscription to YANG Notifications for Datastore Updates](https://datatracker.ietf.org/doc/html/rfc8641)
//!
//! Key types: [`notification::NotificationEnvelope`],
//! [`notification::NotificationVariant`], [`notification::YangPushUpdate`]
//!
//! ### Optional Features
//!
//! - [`codec`] - Tokio codec for async stream processing (requires `codec`
//!   feature)
//! - [`wire`] - Serialization/deserialization for UDP-Notif packets from the
//!   wire (requires `serde` feature)
//!
//! ## Performance Considerations
//!
//! - [`raw::UdpNotifPacket`] uses `Bytes` for zero-copy payload handling
//! - Payload deserialization is lazy - only performed when converting to
//!   [`decoded::UdpNotifPacketDecoded`]
//! - For high-throughput scenarios, consider processing at the `raw` layer and
//!   only decoding packets that match your subscription interests

#[cfg(feature = "codec")]
pub mod codec;
pub mod decoded;
pub mod notification;
pub mod raw;
#[cfg(feature = "serde")]
pub mod wire;

#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_bytes(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<bytes::Bytes> {
    let value: Vec<u8> = u.arbitrary()?;
    Ok(bytes::Bytes::from(value))
}
