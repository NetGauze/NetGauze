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

#![deny(clippy::upper_case_acronyms)]
#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(unreachable_pub)]
#![deny(unused_allocation)]
#![deny(unused_assignments)]
#![deny(unused_comparisons)]
#![deny(clippy::clone_on_ref_ptr)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::missing_const_for_fn)]

use crate::iana::{BmpPeerTypeCode, PeerTerminationCode};
use chrono::{DateTime, Utc};
use netgauze_bgp_pkt::{update::BGPUpdateMessage, BGPMessage};
use std::net::{IpAddr, Ipv4Addr};

pub mod iana;
#[cfg(feature = "serde")]
pub mod serde;

/// ```text
/// 0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |    Version    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Message Length                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Msg. Type   |
/// +---------------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BmpMessage {
    RouteMonitoring(RouteMonitoringMessage),
    StatisticsReport,
    PeerDownNotification,
    PeerUpNotification,
    Initiation(InitiationMessage),
    Termination(TerminationMessage),
    RouteMirroring(RouteMirroringMessage),
    Experimental251(Vec<u8>),
    Experimental252(Vec<u8>),
    Experimental253(Vec<u8>),
    Experimental254(Vec<u8>),
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PeerHeader {
    peer_type: BmpPeerType,
    distinguisher: Option<u64>,
    address: Option<IpAddr>,
    peer_as: u32,
    bgp_id: Ipv4Addr,
    timestamp: Option<DateTime<Utc>>,
}

impl PeerHeader {
    pub const fn new(
        peer_type: BmpPeerType,
        distinguisher: Option<u64>,
        address: Option<IpAddr>,
        peer_as: u32,
        bgp_id: Ipv4Addr,
        timestamp: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            peer_type,
            distinguisher,
            address,
            peer_as,
            bgp_id,
            timestamp,
        }
    }

    pub const fn peer_type(&self) -> &BmpPeerType {
        &self.peer_type
    }

    pub const fn distinguisher(&self) -> &Option<u64> {
        &self.distinguisher
    }

    pub const fn address(&self) -> &Option<IpAddr> {
        &self.address
    }

    pub const fn peer_as(&self) -> &u32 {
        &self.peer_as
    }

    pub const fn bgp_id(&self) -> &Ipv4Addr {
        &self.bgp_id
    }

    pub const fn timestamp(&self) -> &Option<DateTime<Utc>> {
        &self.timestamp
    }
}

/// Identifies the type of peer, along with the type specific flags
/// Flags:
///  - ipv6: The V flag indicates that the Peer address is an IPv6 address. For
///    IPv4 peers, this is set to `false`.
///  - post_policy: The L flag, if set to `true`, indicates that the message
///    reflects the post-policy Adj-RIB-In (i.e., its path attributes reflect
///    the application of inbound policy). It is set to `false` if the message
///    reflects the pre-policy Adj-RIB-In. Locally sourced routes also carry an
///    L flag of `true`. This flag has no significance when used with route
///    mirroring messages.
///  - asn2: The A flag, if set to `true`, indicates that the message is
///    formatted using the legacy 2-byte AS_PATH format. If set to `false`,
///    the message is formatted using the 4-byte AS_PATH format
///    [RFC6793](https://datatracker.ietf.org/doc/html/rfc6793).
///    A BMP speaker MAY choose to propagate the AS_PATH
///    information as received from its peer, or it MAY choose to
///    reformat all AS_PATH information into a 4-byte format
///    regardless of how it was received from the peer. In the latter
///    case, AS4_PATH or AS4_AGGREGATOR path attributes SHOULD NOT be
///    sent in the BMP UPDATE message. This flag has no significance
///    when used with route mirroring messages.
///  - filtered: The F flag indicates that the Loc-RIB is filtered. This MUST be
///    set when a filter is applied to Loc-RIB routes sent to the BMP collector.
#[derive(Debug, Clone, Eq, PartialEq)]
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

/// The initiation message provides a means for the monitored router to
/// inform the monitoring station of its vendor, software version, and so on.
///
/// The initiation message consists of the common BMP header followed by
/// two or more Information TLVs [InitiationInformation].
///
/// The [InitiationInformation::SystemDescription] and
/// [InitiationInformation::SystemName] Information TLVs MUST be sent, any
/// others are optional. The string TLV MAY be included multiple times.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InitiationMessage {
    information: Vec<InitiationInformation>,
}

impl InitiationMessage {
    pub const fn new(information: Vec<InitiationInformation>) -> Self {
        Self { information }
    }

    pub const fn information(&self) -> &Vec<InitiationInformation> {
        &self.information
    }
}

///  The Information TLV is used by the [InitiationMessage] and [PeerUpMessage]
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Information Type     |       Information Length      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Information (variable)                        |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InitiationInformation {
    /// The Information field contains a free-form UTF-8 string whose length is
    /// given by the Information Length field.
    String(String),

    /// The Information field contains an ASCII string whose value MUST be set
    /// to be equal to the value of the sysDescr MIB-II [RFC1213](https://datatracker.ietf.org/doc/html/rfc1213).
    SystemDescription(String),

    /// The Information field contains an ASCII string whose value MUST be set
    /// to be equal to the value of the sysName MIB-II [RFC1213](https://datatracker.ietf.org/doc/html/rfc1213).
    SystemName(String),

    /// The Information field contains a UTF-8 string whose value MUST be
    /// equal to the value of the VRF or table name (e.g., RD instance name)
    /// being conveyed. The string size MUST be within the range of 1 to 255
    /// bytes.
    ///
    /// See [RFC9069](https://datatracker.ietf.org/doc/html/rfc9069)
    VrfTableName(String),

    /// The Information field contains a free-form UTF-8 string whose byte
    /// length is given by the Information Length field. The value is
    /// administratively assigned.
    ///
    /// Multiple Admin Labels can be included in the Peer Up Notification.
    /// When multiple Admin Labels are included, the BMP receiver MUST preserve
    /// their order.
    ///
    /// See [RFC8671](https://datatracker.ietf.org/doc/html/rfc8671)
    AdminLabel(String),

    Experimental65531(Vec<u8>),
    Experimental65532(Vec<u8>),
    Experimental65533(Vec<u8>),
    Experimental65534(Vec<u8>),
}

/// The termination message provides a way for a monitored router to indicate
/// why it is terminating a session.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TerminationMessage {
    peer_header: PeerHeader,
    information: Vec<TerminationInformation>,
}

impl TerminationMessage {
    pub const fn new(peer_header: PeerHeader, information: Vec<TerminationInformation>) -> Self {
        Self {
            peer_header,
            information,
        }
    }
}

///  The Information TLV is used by the [TerminationMessage]
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Information Type     |       Information Length      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Information (variable)                        |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TerminationInformation {
    String(String),
    Reason(PeerTerminationCode),
    Experimental65531(Vec<u8>),
    Experimental65532(Vec<u8>),
    Experimental65533(Vec<u8>),
    Experimental65534(Vec<u8>),
}

/// Route Monitoring messages are used for initial synchronization of the
/// ADJ-RIBs-In.  They are also used for ongoing monitoring of the
/// ADJ-RIB-In state.  Route monitoring messages are state-compressed.
/// This is all discussed in more detail in Section 5.
//
/// Following the common BMP header and per-peer header is a BGP Update
/// PDU.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RouteMonitoringMessage {
    peer_header: PeerHeader,
    updates: Vec<BGPUpdateMessage>,
}

impl RouteMonitoringMessage {
    pub const fn new(peer_header: PeerHeader, updates: Vec<BGPUpdateMessage>) -> Self {
        Self {
            peer_header,
            updates,
        }
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn updates(&self) -> &Vec<BGPUpdateMessage> {
        &self.updates
    }
}

/// Route Mirroring messages are used for verbatim duplication of messages as
/// received.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RouteMirroringMessage {
    peer_header: PeerHeader,
    mirrored: Vec<RouteMirroringValue>,
}

impl RouteMirroringMessage {
    pub const fn new(peer_header: PeerHeader, mirrored: Vec<RouteMirroringValue>) -> Self {
        Self {
            peer_header,
            mirrored,
        }
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn mirrored(&self) -> &Vec<RouteMirroringValue> {
        &self.mirrored
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RouteMirroringValue {
    /// A BGP PDU.  This PDU may or may not be an Update message.
    /// If the BGP Message TLV occurs in the Route Mirroring message,
    /// it MUST occur last in the list of TLVs.
    BgpMessage(BGPMessage),

    /// A 2-byte code that provides information about the mirrored message or
    /// message stream.
    Information(RouteMirroringInformation),
}

/// A 2-byte code that provides information about the mirrored message or
/// message stream.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RouteMirroringInformation {
    /// The contained message was found to have some error that made it
    /// unusable, causing it to be treated-as- withdraw [RFC7606](https://datatracker.ietf.org/doc/html/rfc7606).
    /// A BGP Message TLV MUST also occur in the TLV list.
    ErroredPdu,

    /// One or more messages may have been lost. This could occur, for example,
    /// if an implementation runs out of available buffer space to queue
    /// mirroring messages.
    MessagesLost,
}
