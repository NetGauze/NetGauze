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
pub mod bgp_ls;

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

// Custom function to generate arbitrary ipv4 addresses
#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_ipv4(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<std::net::Ipv4Addr> {
    let value = u.int_in_range(0..=u32::MAX)?;
    Ok(std::net::Ipv4Addr::from(value))
}

// Custom function to generate arbitrary ipv4 network address
#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_ipv4net(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<ipnet::Ipv4Net> {
    loop {
        let value = u.int_in_range(0..=u32::MAX)?;
        let mask = u.int_in_range(0..=u8::MAX)?;
        let addr = std::net::Ipv4Addr::from(value);
        if let Ok(net) = ipnet::Ipv4Net::new(addr, mask) {
            return Ok(net);
        }
    }
}

// Custom function to generate arbitrary ipv6 addresses
#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_ipv6(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<std::net::Ipv6Addr> {
    let value = u.int_in_range(0..=u128::MAX)?;
    Ok(std::net::Ipv6Addr::from(value))
}

// Custom function to generate arbitrary ipv6 network address
#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_ipv6net(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<ipnet::Ipv6Net> {
    loop {
        let value = u.int_in_range(0..=u128::MAX)?;
        let mask = u.int_in_range(0..=u8::MAX)?;
        let addr = std::net::Ipv6Addr::from(value);
        if let Ok(net) = ipnet::Ipv6Net::new(addr, mask) {
            return Ok(net);
        }
    }
}

// Custom function to generate arbitrary IPv4 and IPv6 addresses
#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_ip(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<std::net::IpAddr> {
    let ipv4 = arbitrary_ipv4(u)?;
    let ipv6 = arbitrary_ipv6(u)?;
    let choices = [std::net::IpAddr::V4(ipv4), std::net::IpAddr::V6(ipv6)];
    let addr = u.choose(&choices)?;
    Ok(*addr)
}
