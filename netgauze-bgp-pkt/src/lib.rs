// Copyright (C) 2022-present The NetGauze Authors.
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

#![allow(clippy::upper_case_acronyms)]
#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(unreachable_pub)]
#![deny(unused_allocation)]
#![deny(unused_assignments)]
#![deny(unused_comparisons)]
#![deny(clippy::clone_on_ref_ptr)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::missing_const_for_fn)]

use crate::{
    notification::BGPNotificationMessage, open::BGPOpenMessage,
    route_refresh::BGPRouteRefreshMessage, update::BGPUpdateMessage,
};

pub mod capabilities;
pub mod iana;
pub mod nlri;
pub mod notification;
pub mod open;
pub mod path_attribute;
pub mod route_refresh;
#[cfg(feature = "serde")]
pub mod serde;
pub mod update;

/// BGP message wire format as defined by [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.1)
/// Here we don't keep the length and type in memory. The type is inferred by
/// the enum value, while the length is computed a serialization time.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                           Marker                              |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Length               |      Type     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BGPMessage {
    Open(BGPOpenMessage),
    Update(BGPUpdateMessage),
    Notification(BGPNotificationMessage),
    KeepAlive,
    RouteRefresh(BGPRouteRefreshMessage),
}
