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

#[cfg(feature = "fuzz")]
use chrono::TimeZone;
use chrono::{DateTime, Utc};
use std::{
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
};

use netgauze_bgp_pkt::{iana::BgpMessageType, nlri::RouteDistinguisher, BgpMessage};
use netgauze_iana::address_family::AddressType;

use crate::iana::{BmpMessageType, BmpPeerTypeCode, BmpVersion};

use crate::{
    v3::{
        BmpV3MessageValue, InitiationMessage, PeerDownNotificationMessage,
        PeerUpNotificationMessage, RouteMirroringMessage, RouteMonitoringMessage,
        StatisticsReportMessage, TerminationMessage,
    },
    v4::BmpV4MessageValue,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "codec")]
pub mod codec;
pub mod iana;
pub mod v3;
pub mod v4;
#[cfg(feature = "serde")]
pub mod wire;

/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |    Version    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Message Length                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Msg. Type   |
/// +---------------+
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpMessage {
    V3(BmpV3MessageValue),
    V4(BmpV4MessageValue),
}

impl BmpMessage {
    /// Returns the BMP Version from the BMP Common Header
    /// as [BmpVersion] because there is no IANA registry for BMP Versions
    pub fn get_version(&self) -> BmpVersion {
        match self {
            BmpMessage::V3(_) => BmpVersion::Version3,
            BmpMessage::V4(_) => BmpVersion::Version4,
        }
    }

    /// Returns the BMP Message Type ([BmpMessageType]) from the BMP Common
    /// Header
    pub fn get_type(&self) -> BmpMessageType {
        match &self {
            BmpMessage::V3(value) => value.get_type(),
            BmpMessage::V4(value) => value.get_type(),
        }
    }
}

///  The per-peer header follows the common header for most BMP messages.
///  The rest of the data in a BMP message is dependent on the Message
///  Type field in the common header.
///
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |   Peer Type   |  Peer Flags   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |         Peer Distinguisher (present based on peer type)       |
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                 Peer Address (16 bytes)                       |
///  ~                                                               ~
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                           Peer AS                             |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         Peer BGP ID                           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                    Timestamp (seconds)                        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                  Timestamp (microseconds)                     |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PeerHeader {
    peer_type: BmpPeerType,
    rd: Option<RouteDistinguisher>,
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ip)))]
    address: Option<IpAddr>,
    peer_as: u32,
    bgp_id: Ipv4Addr,
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_datetime)))]
    timestamp: Option<DateTime<Utc>>,
}

impl PeerHeader {
    pub const fn new(
        peer_type: BmpPeerType,
        rd: Option<RouteDistinguisher>,
        address: Option<IpAddr>,
        peer_as: u32,
        bgp_id: Ipv4Addr,
        timestamp: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            peer_type,
            rd,
            address,
            peer_as,
            bgp_id,
            timestamp,
        }
    }

    pub const fn peer_type(&self) -> BmpPeerType {
        self.peer_type
    }

    pub const fn rd(&self) -> Option<RouteDistinguisher> {
        self.rd
    }

    pub const fn address(&self) -> Option<IpAddr> {
        self.address
    }

    pub const fn peer_as(&self) -> u32 {
        self.peer_as
    }

    pub const fn bgp_id(&self) -> Ipv4Addr {
        self.bgp_id
    }

    pub const fn timestamp(&self) -> Option<&DateTime<Utc>> {
        self.timestamp.as_ref()
    }

    pub const fn is_asn4(&self) -> bool {
        match self.peer_type {
            BmpPeerType::GlobalInstancePeer { asn2, .. } => !asn2,
            BmpPeerType::RdInstancePeer { asn2, .. } => !asn2,
            BmpPeerType::LocalInstancePeer { asn2, .. } => !asn2,
            BmpPeerType::LocRibInstancePeer { .. } => true,
            BmpPeerType::Experimental251 { .. } => true,
            BmpPeerType::Experimental252 { .. } => true,
            BmpPeerType::Experimental253 { .. } => true,
            BmpPeerType::Experimental254 { .. } => true,
        }
    }
}

/// Identifies the type of peer, along with the type specific flags
/// Flags:
///  - ipv6: The V flag indicates that the Peer address is an IPv6 address. For
///    IPv4 peers, this is set to `false`.
///  - `post_policy`: The L flag, if set to `true`, indicates that the message
///    reflects the post-policy Adj-RIB-In (i.e., its path attributes reflect
///    the application of inbound policy). It is set to `false` if the message
///    reflects the pre-policy Adj-RIB-In. Locally sourced routes also carry an
///    L flag of `true`. This flag has no significance when used with route
///    mirroring messages.
///  - asn2: The A flag, if set to `true`, indicates that the message is
///    formatted using the legacy 2-byte `AS_PATH` format. If set to `false`,
///    the message is formatted using the 4-byte `AS_PATH` format
///    [RFC6793](https://datatracker.ietf.org/doc/html/rfc6793).
///    A BMP speaker MAY choose to propagate the `AS_PATH`
///    information as received from its peer, or it MAY choose to
///    reformat all `AS_PATH` information into a 4-byte format
///    regardless of how it was received from the peer. In the latter
///    case, `AS4_PATH` or `AS4_AGGREGATOR` path attributes SHOULD NOT be
///    sent in the BMP UPDATE message. This flag has no significance
///    when used with route mirroring messages.
///  - filtered: The F flag indicates that the Loc-RIB is filtered. This MUST be
///    set when a filter is applied to Loc-RIB routes sent to the BMP collector.
#[derive(Debug, Hash, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpPeerType {
    GlobalInstancePeer {
        ipv6: bool,
        post_policy: bool,
        asn2: bool,
        adj_rib_out: bool,
    },
    RdInstancePeer {
        ipv6: bool,
        post_policy: bool,
        asn2: bool,
        adj_rib_out: bool,
    },
    LocalInstancePeer {
        ipv6: bool,
        post_policy: bool,
        asn2: bool,
        adj_rib_out: bool,
    },
    LocRibInstancePeer {
        filtered: bool,
    },
    Experimental251 {
        flags: u8,
    },
    Experimental252 {
        flags: u8,
    },
    Experimental253 {
        flags: u8,
    },
    Experimental254 {
        flags: u8,
    },
}

impl BmpPeerType {
    /// Get the IANA Code for the peer type
    pub const fn get_type(&self) -> BmpPeerTypeCode {
        match self {
            Self::GlobalInstancePeer { .. } => BmpPeerTypeCode::GlobalInstancePeer,
            Self::RdInstancePeer { .. } => BmpPeerTypeCode::RdInstancePeer,
            Self::LocalInstancePeer { .. } => BmpPeerTypeCode::LocalInstancePeer,
            Self::LocRibInstancePeer { .. } => BmpPeerTypeCode::LocRibInstancePeer,
            Self::Experimental251 { .. } => BmpPeerTypeCode::Experimental251,
            Self::Experimental252 { .. } => BmpPeerTypeCode::Experimental252,
            Self::Experimental253 { .. } => BmpPeerTypeCode::Experimental253,
            Self::Experimental254 { .. } => BmpPeerTypeCode::Experimental254,
        }
    }
}

/// A non-negative integer that monotonically increases
/// until it reaches a maximum value, when it wraps around and starts
/// increasing again from 0.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct CounterU32(u32);

impl CounterU32 {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

impl Deref for CounterU32 {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Non-negative integer that may increase or decrease,
/// but shall never exceed a maximum value, nor fall below a minimum one.
/// The maximum value cannot be greater than 2^64-1 (18446744073709551615
/// decimal), and the minimum value cannot be smaller than 0. The value
/// has its maximum value whenever the information being modeled is
/// greater than or equal to its maximum value, and has its minimum value
/// whenever the information being modeled is smaller than or equal to
/// its minimum value. If the information being modeled subsequently
/// decreases below the maximum value (or increases above the minimum
/// value), the 64-bit Gauge also decreases (or increases).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct GaugeU64(u64);

impl GaugeU64 {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }
}

impl Deref for GaugeU64 {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Custom function to generate arbitrary ipv4 addresses
#[cfg(feature = "fuzz")]
fn arbitrary_ipv4(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Ipv4Addr> {
    let value = u.int_in_range(0..=u32::MAX)?;
    Ok(Ipv4Addr::from(value))
}

/// PeerKey is used to identify a BMP peer. This key is unique only
/// to the BMP session.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PeerKey {
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ip)))]
    peer_address: Option<IpAddr>,
    peer_type: BmpPeerType,
    rd: Option<RouteDistinguisher>,
    asn: u32,
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
    bgp_id: Ipv4Addr,
}

impl Hash for PeerKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.peer_address.hash(state);
        self.peer_type.get_type().hash(state);
        self.rd.hash(state);
        self.asn.hash(state);
        self.bgp_id.hash(state);
    }
}
impl PartialEq<Self> for PeerKey {
    fn eq(&self, other: &Self) -> bool {
        self.peer_address.eq(&other.peer_address)
            && std::mem::discriminant(&self.peer_type) == std::mem::discriminant(&other.peer_type)
            && self.rd == other.rd
            && self.asn == other.asn
            && self.bgp_id == other.bgp_id
    }
}

impl Eq for PeerKey {}

impl PeerKey {
    pub const fn new(
        peer_address: Option<IpAddr>,
        peer_type: BmpPeerType,
        rd: Option<RouteDistinguisher>,
        asn: u32,
        bgp_id: Ipv4Addr,
    ) -> Self {
        Self {
            peer_address,
            peer_type,
            rd,
            asn,
            bgp_id,
        }
    }

    pub const fn from_peer_header(header: &PeerHeader) -> Self {
        Self::new(
            header.address,
            header.peer_type,
            header.rd,
            header.peer_as,
            header.bgp_id,
        )
    }

    pub const fn peer_address(&self) -> Option<IpAddr> {
        self.peer_address
    }
    pub const fn peer_type(&self) -> BmpPeerType {
        self.peer_type
    }
    pub const fn rd(&self) -> Option<RouteDistinguisher> {
        self.rd
    }
    pub const fn asn(&self) -> u32 {
        self.asn
    }
    pub const fn bgp_id(&self) -> Ipv4Addr {
        self.bgp_id
    }
}

// Custom function to generate arbitrary ipv6 addresses
#[cfg(feature = "fuzz")]
fn arbitrary_ipv6(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<std::net::Ipv6Addr> {
    let value = u.int_in_range(0..=u128::MAX)?;
    Ok(std::net::Ipv6Addr::from(value))
}

// Custom function to generate arbitrary IPv4 and IPv6 addresses
#[cfg(feature = "fuzz")]
fn arbitrary_ip(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<IpAddr> {
    let ipv4 = arbitrary_ipv4(u)?;
    let ipv6 = arbitrary_ipv6(u)?;
    let choices = [IpAddr::V4(ipv4), IpAddr::V6(ipv6)];
    let addr = u.choose(&choices)?;
    Ok(*addr)
}

#[cfg(feature = "fuzz")]
fn arbitrary_datetime(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<DateTime<Utc>> {
    loop {
        let seconds = u.int_in_range(0..=i64::MAX)?;
        if let chrono::LocalResult::Single(tt) = Utc.timestamp_opt(seconds, 0) {
            return Ok(tt);
        }
    }
}
