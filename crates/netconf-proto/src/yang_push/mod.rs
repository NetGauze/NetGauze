// Copyright (C) 2026-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! YANG-Push subscription model ([RFC 8641]) and Subscribed Notifications
//! ([RFC 8639]).
//!
//! This module implements the data types, XML serialization/deserialization,
//! and helper utilities for YANG-Push and Subscribed Notifications as defined
//! in the following RFCs:
//!
//! * [RFC 8639 – Subscription to YANG Notifications](https://datatracker.ietf.org/doc/html/rfc8639)
//! * [RFC 8641 – Subscription to YANG Notifications for Datastore Updates](https://datatracker.ietf.org/doc/html/rfc8641)
//!
//! # Sub-modules
//!
//! | Module | Contents |
//! |---|---|
//! | [`filters`] | Filter types for stream and datastore subscriptions |
//! | [`identities`] | YANG identity enumerations (transport, encoding, etc.) |
//! | [`subscription`] | The core [`Subscription`](subscription::Subscription) type and targets |
//! | [`types`] | Primitive newtypes (`CentiSeconds`, `SubscriptionId`) |

use quick_xml::name::Namespace;

pub mod filters;
pub mod identities;
pub mod subscription;
#[cfg(test)]
mod tests;
pub mod types;

pub const YANG_PUSH_NS: Namespace<'static> =
    Namespace(b"urn:ietf:params:xml:ns:yang:ietf-yang-push");
pub const SUBSCRIBED_NOTIFICATIONS_NS: Namespace<'static> =
    Namespace(b"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications");
pub const DISTRIBUTED_NOTIF_NS: Namespace<'static> =
    Namespace(b"urn:ietf:params:xml:ns:yang:ietf-distributed-notif");
