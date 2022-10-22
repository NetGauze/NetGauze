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

use std::{
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
};

use chrono::{DateTime, Utc};

use netgauze_bgp_pkt::{iana::BGPMessageType, nlri::RouteDistinguisher, BGPMessage};
use netgauze_iana::address_family::AddressType;

use crate::iana::{
    BmpMessageType, BmpPeerTypeCode, BmpStatisticsType, InitiationInformationTlvType,
    PeerDownReasonCode, PeerTerminationCode, RouteMirroringInformation, RouteMirroringTlvType,
    TerminationInformationTlvType,
};


use serde::{Deserialize, Serialize};

pub mod iana;
#[cfg(feature = "serde")]
pub mod wire;

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BmpMessage {
    V3(BmpMessageValue),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BmpMessageValue {
    RouteMonitoring(RouteMonitoringMessage),
    StatisticsReport(StatisticsReportMessage),
    PeerDownNotification(PeerDownNotificationMessage),
    PeerUpNotification(PeerUpNotificationMessage),
    Initiation(InitiationMessage),
    Termination(TerminationMessage),
    RouteMirroring(RouteMirroringMessage),
    Experimental251(Vec<u8>),
    Experimental252(Vec<u8>),
    Experimental253(Vec<u8>),
    Experimental254(Vec<u8>),
}

impl BmpMessageValue {
    /// Get IANA type
    pub const fn get_type(&self) -> BmpMessageType {
        match self {
            Self::RouteMonitoring(_) => BmpMessageType::RouteMonitoring,
            Self::StatisticsReport(_) => BmpMessageType::StatisticsReport,
            Self::PeerDownNotification(_) => BmpMessageType::PeerDownNotification,
            Self::PeerUpNotification(_) => BmpMessageType::PeerUpNotification,
            Self::Initiation(_) => BmpMessageType::Initiation,
            Self::Termination(_) => BmpMessageType::Termination,
            Self::RouteMirroring(_) => BmpMessageType::RouteMirroring,
            Self::Experimental251(_) => BmpMessageType::Experimental251,
            Self::Experimental252(_) => BmpMessageType::Experimental252,
            Self::Experimental253(_) => BmpMessageType::Experimental253,
            Self::Experimental254(_) => BmpMessageType::Experimental254,
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
pub struct PeerHeader {
    peer_type: BmpPeerType,
    rd: Option<RouteDistinguisher>,
    address: Option<IpAddr>,
    peer_as: u32,
    bgp_id: Ipv4Addr,
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

    pub const fn peer_type(&self) -> &BmpPeerType {
        &self.peer_type
    }

    pub const fn rd(&self) -> &Option<RouteDistinguisher> {
        &self.rd
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

/// The initiation message provides a means for the monitored router to
/// inform the monitoring station of its vendor, software version, and so on.
///
/// The initiation message consists of the common BMP header followed by
/// two or more Information TLVs [InitiationInformation].
///
/// The [InitiationInformation::SystemDescription] and
/// [InitiationInformation::SystemName] Information TLVs MUST be sent, any
/// others are optional. The string TLV MAY be included multiple times.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

///  The Information TLV is used by the [InitiationMessage] and
/// [PeerUpNotificationMessage]
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

impl InitiationInformation {
    /// Get the IANA type
    pub const fn get_type(&self) -> InitiationInformationTlvType {
        match self {
            InitiationInformation::String(_) => InitiationInformationTlvType::String,
            InitiationInformation::SystemDescription(_) => {
                InitiationInformationTlvType::SystemDescription
            }
            InitiationInformation::SystemName(_) => InitiationInformationTlvType::SystemName,
            InitiationInformation::VrfTableName(_) => InitiationInformationTlvType::VrfTableName,
            InitiationInformation::AdminLabel(_) => InitiationInformationTlvType::AdminLabel,
            InitiationInformation::Experimental65531(_) => {
                InitiationInformationTlvType::Experimental65531
            }
            InitiationInformation::Experimental65532(_) => {
                InitiationInformationTlvType::Experimental65532
            }
            InitiationInformation::Experimental65533(_) => {
                InitiationInformationTlvType::Experimental65533
            }
            InitiationInformation::Experimental65534(_) => {
                InitiationInformationTlvType::Experimental65534
            }
        }
    }
}

/// The termination message provides a way for a monitored router to indicate
/// why it is terminating a session.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn information(&self) -> &Vec<TerminationInformation> {
        &self.information
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum TerminationInformation {
    String(String),
    Reason(PeerTerminationCode),
    Experimental65531(Vec<u8>),
    Experimental65532(Vec<u8>),
    Experimental65533(Vec<u8>),
    Experimental65534(Vec<u8>),
}

impl TerminationInformation {
    /// Get IANA code type
    pub const fn get_type(&self) -> TerminationInformationTlvType {
        match self {
            Self::String(_) => TerminationInformationTlvType::String,
            Self::Reason(_) => TerminationInformationTlvType::Reason,
            Self::Experimental65531(_) => TerminationInformationTlvType::Experimental65531,
            Self::Experimental65532(_) => TerminationInformationTlvType::Experimental65532,
            Self::Experimental65533(_) => TerminationInformationTlvType::Experimental65533,
            Self::Experimental65534(_) => TerminationInformationTlvType::Experimental65534,
        }
    }
}

/// Runtime errors when constructing a [RouteMonitoringMessage]
/// Peer Up BGP messages should only carry
/// [netgauze_bgp_pkt::BGPMessage::Update], anything else is an error
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum RouteMonitoringMessageError {
    UnexpectedMessageType(BGPMessageType),
}

/// Route Monitoring messages are used for initial synchronization of the
/// ADJ-RIBs-In.  They are also used for ongoing monitoring of the
/// ADJ-RIB-In state.  Route monitoring messages are state-compressed.
/// This is all discussed in more detail in Section 5.
//
/// Following the common BMP header and per-peer header is a BGP Update
/// PDU.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteMonitoringMessage {
    peer_header: PeerHeader,
    updates: Vec<BGPMessage>,
}

impl RouteMonitoringMessage {
    pub fn build(
        peer_header: PeerHeader,
        updates: Vec<BGPMessage>,
    ) -> Result<Self, RouteMonitoringMessageError> {
        for update in &updates {
            if update.get_type() != BGPMessageType::Update {
                return Err(RouteMonitoringMessageError::UnexpectedMessageType(
                    update.get_type(),
                ));
            }
        }
        Ok(Self {
            peer_header,
            updates,
        })
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn updates(&self) -> &Vec<BGPMessage> {
        &self.updates
    }
}

/// Route Mirroring messages are used for verbatim duplication of messages as
/// received.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum RouteMirroringValue {
    /// A BGP PDU.  This PDU may or may not be an Update message.
    /// If the BGP Message TLV occurs in the Route Mirroring message,
    /// it MUST occur last in the list of TLVs.
    BgpMessage(BGPMessage),

    /// A 2-byte code that provides information about the mirrored message or
    /// message stream.
    Information(RouteMirroringInformation),
    Experimental65531(Vec<u8>),
    Experimental65532(Vec<u8>),
    Experimental65533(Vec<u8>),
    Experimental65534(Vec<u8>),
}

impl RouteMirroringValue {
    /// Get IANA type
    pub const fn get_type(&self) -> RouteMirroringTlvType {
        match self {
            Self::BgpMessage(_) => RouteMirroringTlvType::BgpMessage,
            Self::Information(_) => RouteMirroringTlvType::Information,
            Self::Experimental65531(_) => RouteMirroringTlvType::Experimental65531,
            Self::Experimental65532(_) => RouteMirroringTlvType::Experimental65532,
            Self::Experimental65533(_) => RouteMirroringTlvType::Experimental65533,
            Self::Experimental65534(_) => RouteMirroringTlvType::Experimental65534,
        }
    }
}

/// The Peer Up message is used to indicate that a peering session has
/// come up (i.e., has transitioned into the Established state).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Local Address (16 bytes)                      |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Local Port            |        Remote Port            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Sent OPEN Message                          |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Received OPEN Message                        |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Information (variable)                        |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerUpNotificationMessage {
    peer_header: PeerHeader,
    local_address: IpAddr,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    sent_message: BGPMessage,
    received_message: BGPMessage,
    information: Vec<InitiationInformation>,
}

/// Runtime errors when constructing a [PeerUpNotificationMessage]
/// Peer Up BGP messages should only carry [netgauze_bgp_pkt::BGPMessage::Open],
/// anything else is an error
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PeerUpNotificationMessageError {
    UnexpectedSentMessageType(BGPMessageType),
    UnexpectedReceivedMessageType(BGPMessageType),
}

impl PeerUpNotificationMessage {
    pub fn build(
        peer_header: PeerHeader,
        local_address: IpAddr,
        local_port: Option<u16>,
        remote_port: Option<u16>,
        sent_message: BGPMessage,
        received_message: BGPMessage,
        information: Vec<InitiationInformation>,
    ) -> Result<Self, PeerUpNotificationMessageError> {
        if sent_message.get_type() != BGPMessageType::Open {
            return Err(PeerUpNotificationMessageError::UnexpectedSentMessageType(
                sent_message.get_type(),
            ));
        }
        if received_message.get_type() != BGPMessageType::Open {
            return Err(
                PeerUpNotificationMessageError::UnexpectedReceivedMessageType(
                    sent_message.get_type(),
                ),
            );
        }
        Ok(Self {
            peer_header,
            local_address,
            local_port,
            remote_port,
            sent_message,
            received_message,
            information,
        })
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn local_address(&self) -> &IpAddr {
        &self.local_address
    }

    pub const fn local_port(&self) -> &Option<u16> {
        &self.local_port
    }

    pub const fn remote_port(&self) -> &Option<u16> {
        &self.remote_port
    }

    pub const fn sent_message(&self) -> &BGPMessage {
        &self.sent_message
    }

    pub const fn received_message(&self) -> &BGPMessage {
        &self.received_message
    }

    pub const fn information(&self) -> &Vec<InitiationInformation> {
        &self.information
    }
}

/// Runtime errors when constructing a [PeerDownNotificationMessage]
/// Peer Up BGP messages should only carry
/// [netgauze_bgp_pkt::BGPMessage::Notification], anything else is an error
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PeerDownNotificationMessageError {
    UnexpectedBgpMessageType(BGPMessageType),
    UnexpectedInitiationInformationTlvType(InitiationInformationTlvType),
}

/// This message is used to indicate that a peering session was terminated.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |    Reason     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Data (present if Reason = 1, 2 or 3)               |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerDownNotificationMessage {
    peer_header: PeerHeader,
    reason: PeerDownNotificationReason,
}

impl PeerDownNotificationMessage {
    pub fn build(
        peer_header: PeerHeader,
        reason: PeerDownNotificationReason,
    ) -> Result<Self, PeerDownNotificationMessageError> {
        match &reason {
            PeerDownNotificationReason::LocalSystemClosedNotificationPduFollows(msg)
            | PeerDownNotificationReason::RemoteSystemClosedNotificationPduFollows(msg) => {
                if msg.get_type() != BGPMessageType::Notification {
                    return Err(PeerDownNotificationMessageError::UnexpectedBgpMessageType(
                        msg.get_type(),
                    ));
                }
            }
            PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(_) => {}
            PeerDownNotificationReason::RemoteSystemClosedNoData => {}
            PeerDownNotificationReason::PeerDeConfigured => {}
            PeerDownNotificationReason::LocalSystemClosedTlvDataFollows(information) => {
                if information.get_type() != InitiationInformationTlvType::VrfTableName {
                    return Err(
                        PeerDownNotificationMessageError::UnexpectedInitiationInformationTlvType(
                            information.get_type(),
                        ),
                    );
                }
            }
            PeerDownNotificationReason::Experimental251(_) => {}
            PeerDownNotificationReason::Experimental252(_) => {}
            PeerDownNotificationReason::Experimental253(_) => {}
            PeerDownNotificationReason::Experimental254(_) => {}
        }

        Ok(Self {
            peer_header,
            reason,
        })
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn reason(&self) -> &PeerDownNotificationReason {
        &self.reason
    }
}

/// Reason indicates why the session was closed and
/// [PeerDownNotificationMessage] is sent.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PeerDownNotificationReason {
    /// The local system closed the session.  Following the
    /// Reason is a BGP PDU containing a BGP NOTIFICATION message that
    /// would have been sent to the peer.
    LocalSystemClosedNotificationPduFollows(BGPMessage),

    /// The local system closed the session. No notification
    /// message was sent. Following the reason code is a 2-byte field
    /// containing the code corresponding to the Finite State Machine
    /// (FSM) Event that caused the system to close the session (see
    /// Section 8.1 of [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)).
    /// Two bytes both set to 0 are used to indicate that no relevant Event code
    /// is defined.
    LocalSystemClosedFsmEventFollows(u16),

    /// The remote system closed the session with a notification
    /// message. Following the Reason is a BGP PDU containing the BGP
    /// NOTIFICATION message as received from the peer.
    RemoteSystemClosedNotificationPduFollows(BGPMessage),

    /// The remote system closed the session without a
    /// notification message. This includes any unexpected termination of
    /// the transport session, so in some cases both the local and remote
    /// systems might consider this to apply.
    RemoteSystemClosedNoData,

    /// Information for this peer will no longer be sent to the
    /// monitoring station for configuration reasons.  This does not,
    /// strictly speaking, indicate that the peer has gone down, but it
    /// does indicate that the monitoring station will not receive updates
    /// for the peer.
    PeerDeConfigured,

    /// Type = 3: VRF/Table Name. The Information field contains a UTF-8 string
    /// whose value MUST be equal to the value of the VRF or table name (e.g.,
    /// RD instance name) being conveyed. The string size MUST be within the
    /// range of 1 to 255 bytes. The VRF/Table Name informational TLV MUST be
    /// included if it was in the Peer Up.
    LocalSystemClosedTlvDataFollows(InitiationInformation),

    Experimental251(Vec<u8>),
    Experimental252(Vec<u8>),
    Experimental253(Vec<u8>),
    Experimental254(Vec<u8>),
}

impl PeerDownNotificationReason {
    pub const fn get_type(&self) -> PeerDownReasonCode {
        match self {
            Self::LocalSystemClosedNotificationPduFollows(_) => {
                PeerDownReasonCode::LocalSystemClosedNotificationPduFollows
            }
            Self::LocalSystemClosedFsmEventFollows(_) => {
                PeerDownReasonCode::LocalSystemClosedFsmEventFollows
            }
            Self::RemoteSystemClosedNotificationPduFollows(_) => {
                PeerDownReasonCode::RemoteSystemClosedNotificationPduFollows
            }
            Self::RemoteSystemClosedNoData => PeerDownReasonCode::RemoteSystemClosedNoData,
            Self::PeerDeConfigured => PeerDownReasonCode::PeerDeConfigured,
            Self::LocalSystemClosedTlvDataFollows(_) => {
                PeerDownReasonCode::LocalSystemClosedTlvDataFollows
            }
            Self::Experimental251(_) => PeerDownReasonCode::Experimental251,
            Self::Experimental252(_) => PeerDownReasonCode::Experimental252,
            Self::Experimental253(_) => PeerDownReasonCode::Experimental253,
            Self::Experimental254(_) => PeerDownReasonCode::Experimental254,
        }
    }
}

/// These messages contain information that could be used by the
/// monitoring station to observe interesting events that occur on the router.
///
/// ```text
/// 0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Stats Count                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// followed by
///```text
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatisticsReportMessage {
    peer_header: PeerHeader,
    counters: Vec<StatisticsCounter>,
}

impl StatisticsReportMessage {
    pub const fn new(peer_header: PeerHeader, counters: Vec<StatisticsCounter>) -> Self {
        Self {
            peer_header,
            counters,
        }
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn counters(&self) -> &Vec<StatisticsCounter> {
        &self.counters
    }
}

/// [StatisticsReportMessage] value
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Stat Type             |          Stat Len             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Stat Data                              |
/// ~                                                               ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum StatisticsCounter {
    NumberOfPrefixesRejectedByInboundPolicy(CounterU32),
    NumberOfDuplicatePrefixAdvertisements(CounterU32),
    NumberOfDuplicateWithdraws(CounterU32),
    NumberOfUpdatesInvalidatedDueToClusterListLoop(CounterU32),
    NumberOfUpdatesInvalidatedDueToAsPathLoop(CounterU32),
    NumberOfUpdatesInvalidatedDueToOriginatorId(CounterU32),
    NumberOfUpdatesInvalidatedDueToAsConfederationLoop(CounterU32),
    NumberOfRoutesInAdjRibIn(GaugeU64),
    NumberOfRoutesInLocRib(GaugeU64),
    NumberOfRoutesInPerAfiSafiAdjRibIn(AddressType, CounterU32),
    NumberOfRoutesInPerAfiSafiLocRib(AddressType, CounterU32),
    NumberOfUpdatesSubjectedToTreatAsWithdraw(CounterU32),
    NumberOfPrefixesSubjectedToTreatAsWithdraw(CounterU32),
    NumberOfDuplicateUpdateMessagesReceived(CounterU32),
    NumberOfRoutesInPrePolicyAdjRibOut(GaugeU64),
    NumberOfRoutesInPostPolicyAdjRibOut(GaugeU64),
    NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(AddressType, GaugeU64),
    NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(AddressType, GaugeU64),
    Experimental65531(Vec<u8>),
    Experimental65532(Vec<u8>),
    Experimental65533(Vec<u8>),
    Experimental65534(Vec<u8>),
    Unknown(u16, Vec<u8>),
}

impl StatisticsCounter {
    pub const fn get_type(&self) -> Result<BmpStatisticsType, u16> {
        match self {
            Self::NumberOfPrefixesRejectedByInboundPolicy(_) => {
                Ok(BmpStatisticsType::NumberOfPrefixesRejectedByInboundPolicy)
            }
            Self::NumberOfDuplicatePrefixAdvertisements(_) => {
                Ok(BmpStatisticsType::NumberOfDuplicatePrefixAdvertisements)
            }
            Self::NumberOfDuplicateWithdraws(_) => {
                Ok(BmpStatisticsType::NumberOfDuplicateWithdraws)
            }
            Self::NumberOfUpdatesInvalidatedDueToClusterListLoop(_) => {
                Ok(BmpStatisticsType::NumberOfUpdatesInvalidatedDueToClusterListLoop)
            }
            Self::NumberOfUpdatesInvalidatedDueToAsPathLoop(_) => {
                Ok(BmpStatisticsType::NumberOfUpdatesInvalidatedDueToAsPathLoop)
            }
            Self::NumberOfUpdatesInvalidatedDueToOriginatorId(_) => {
                Ok(BmpStatisticsType::NumberOfUpdatesInvalidatedDueToOriginatorId)
            }
            Self::NumberOfUpdatesInvalidatedDueToAsConfederationLoop(_) => {
                Ok(BmpStatisticsType::NumberOfUpdatesInvalidatedDueToAsConfederationLoop)
            }
            Self::NumberOfRoutesInAdjRibIn(_) => Ok(BmpStatisticsType::NumberOfRoutesInAdjRibIn),
            Self::NumberOfRoutesInLocRib(_) => Ok(BmpStatisticsType::NumberOfRoutesInLocRib),
            Self::NumberOfRoutesInPerAfiSafiAdjRibIn(_, _) => {
                Ok(BmpStatisticsType::NumberOfRoutesInPerAfiSafiAdjRibIn)
            }
            Self::NumberOfRoutesInPerAfiSafiLocRib(_, _) => {
                Ok(BmpStatisticsType::NumberOfRoutesInPerAfiSafiLocRib)
            }
            Self::NumberOfUpdatesSubjectedToTreatAsWithdraw(_) => {
                Ok(BmpStatisticsType::NumberOfUpdatesSubjectedToTreatAsWithdraw)
            }
            Self::NumberOfPrefixesSubjectedToTreatAsWithdraw(_) => {
                Ok(BmpStatisticsType::NumberOfPrefixesSubjectedToTreatAsWithdraw)
            }
            Self::NumberOfDuplicateUpdateMessagesReceived(_) => {
                Ok(BmpStatisticsType::NumberOfDuplicateUpdateMessagesReceived)
            }
            Self::NumberOfRoutesInPrePolicyAdjRibOut(_) => {
                Ok(BmpStatisticsType::NumberOfRoutesInPrePolicyAdjRibOut)
            }
            Self::NumberOfRoutesInPostPolicyAdjRibOut(_) => {
                Ok(BmpStatisticsType::NumberOfRoutesInPostPolicyAdjRibOut)
            }
            Self::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(_, _) => {
                Ok(BmpStatisticsType::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut)
            }
            Self::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(_, _) => {
                Ok(BmpStatisticsType::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut)
            }
            Self::Experimental65531(_) => Ok(BmpStatisticsType::Experimental65531),
            Self::Experimental65532(_) => Ok(BmpStatisticsType::Experimental65532),
            Self::Experimental65533(_) => Ok(BmpStatisticsType::Experimental65533),
            Self::Experimental65534(_) => Ok(BmpStatisticsType::Experimental65534),
            Self::Unknown(code, _) => Err(*code),
        }
    }
}

/// A non-negative integer that monotonically increases
/// until it reaches a maximum value, when it wraps around and starts
/// increasing again from 0.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
