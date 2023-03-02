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

//! BGP PDU data representation

use crate::{
    iana::BgpMessageType, notification::BgpNotificationMessage, open::BgpOpenMessage,
    route_refresh::BgpRouteRefreshMessage, update::BgpUpdateMessage,
};
use ::serde::{Deserialize, Serialize};

pub mod capabilities;
pub mod community;
pub mod iana;
pub mod nlri;
pub mod notification;
pub mod open;
pub mod path_attribute;
pub mod route_refresh;
pub mod update;
#[cfg(feature = "serde")]
pub mod wire;

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpMessage {
    Open(BgpOpenMessage),
    Update(BgpUpdateMessage),
    Notification(BgpNotificationMessage),
    KeepAlive,
    RouteRefresh(BgpRouteRefreshMessage),
}

impl BgpMessage {
    /// Get the BGP message IANA type
    pub const fn get_type(&self) -> BgpMessageType {
        match self {
            Self::Open(_) => BgpMessageType::Open,
            Self::Update(_) => BgpMessageType::Update,
            Self::Notification(_) => BgpMessageType::Notification,
            Self::KeepAlive => BgpMessageType::KeepAlive,
            Self::RouteRefresh(_) => BgpMessageType::RouteRefresh,
        }
    }
}
