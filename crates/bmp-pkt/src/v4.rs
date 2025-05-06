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

use crate::{
    iana::BmpMessageType,
    v4::BmpV4RouteMonitoringTlvError::{
        BadBgpMessageType, BadGroupTlvIndex, VrfTableNameStringIsTooLong,
    },
    InitiationMessage, PeerDownNotificationMessage, PeerHeader, PeerUpNotificationMessage,
    RouteMirroringMessage, StatisticsReportMessage, TerminationMessage,
};
use either::Either;
use netgauze_bgp_pkt::{capabilities::BgpCapability, iana::BgpMessageType, BgpMessage};
use serde::{Deserialize, Serialize};
use std::ops::BitOr;
use strum_macros::{Display, FromRepr};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4MessageValue {
    RouteMonitoring(BmpV4RouteMonitoringMessage),
    StatisticsReport(StatisticsReportMessage),
    PeerDownNotification {
        v3_notif: PeerDownNotificationMessage,
        tlvs: Vec<BmpV4PeerDownTlv>,
    },
    PeerUpNotification(PeerUpNotificationMessage),
    Initiation(InitiationMessage),
    Termination(TerminationMessage),
    RouteMirroring(RouteMirroringMessage),
    Experimental251(Vec<u8>),
    Experimental252(Vec<u8>),
    Experimental253(Vec<u8>),
    Experimental254(Vec<u8>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4PeerDownTlv {
    Unknown { code: u16, value: Vec<u8> },
}

impl BmpV4PeerDownTlv {
    pub fn code(&self) -> u16 {
        match self {
            BmpV4PeerDownTlv::Unknown { code, .. } => *code,
        }
    }
}

impl BmpV4MessageValue {
    pub fn get_type(&self) -> BmpMessageType {
        match self {
            BmpV4MessageValue::RouteMonitoring(_) => BmpMessageType::RouteMonitoring,
            BmpV4MessageValue::StatisticsReport(_) => BmpMessageType::StatisticsReport,
            BmpV4MessageValue::PeerDownNotification { .. } => BmpMessageType::PeerDownNotification,
            BmpV4MessageValue::PeerUpNotification(_) => BmpMessageType::PeerUpNotification,
            BmpV4MessageValue::Initiation(_) => BmpMessageType::Initiation,
            BmpV4MessageValue::Termination(_) => BmpMessageType::Termination,
            BmpV4MessageValue::RouteMirroring(_) => BmpMessageType::RouteMirroring,
            BmpV4MessageValue::Experimental251(_) => BmpMessageType::Experimental251,
            BmpV4MessageValue::Experimental252(_) => BmpMessageType::Experimental252,
            BmpV4MessageValue::Experimental253(_) => BmpMessageType::Experimental253,
            BmpV4MessageValue::Experimental254(_) => BmpMessageType::Experimental254,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BmpV4RouteMonitoringTlv {
    index: u16,
    value: BmpV4RouteMonitoringTlvValue,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4RouteMonitoringTlvError {
    BadGroupTlvIndex(u16),
    BadBgpMessageType(BgpMessageType),
    VrfTableNameStringIsTooLong(usize),
}

impl BmpV4RouteMonitoringTlv {
    pub fn build(
        index: u16,
        value: BmpV4RouteMonitoringTlvValue,
    ) -> Result<Self, BmpV4RouteMonitoringTlvError> {
        match &value {
            BmpV4RouteMonitoringTlvValue::GroupTlv(_) => {
                if index.leading_ones() == 0 {
                    // First bit has to be one (G flag)
                    return Err(BadGroupTlvIndex(index));
                }
            }
            BmpV4RouteMonitoringTlvValue::VrfTableName(str) => {
                let len = str.len();
                if len > 255 {
                    return Err(VrfTableNameStringIsTooLong(len));
                }
            }
            BmpV4RouteMonitoringTlvValue::BgpUpdatePdu(update_pdu) => {
                if update_pdu.get_type() != BgpMessageType::Update {
                    return Err(BadBgpMessageType(update_pdu.get_type()));
                }
            }
            _ => {}
        };

        Ok(Self { index, value })
    }

    pub fn get_type(&self) -> Either<BmpV4RouteMonitoringTlvType, u16> {
        match self.value {
            BmpV4RouteMonitoringTlvValue::BgpUpdatePdu(_) => {
                Either::Left(BmpV4RouteMonitoringTlvType::BgpUpdatePdu)
            }
            BmpV4RouteMonitoringTlvValue::VrfTableName(_) => {
                Either::Left(BmpV4RouteMonitoringTlvType::VrfTableName)
            }
            BmpV4RouteMonitoringTlvValue::GroupTlv(_) => {
                Either::Left(BmpV4RouteMonitoringTlvType::GroupTlv)
            }
            BmpV4RouteMonitoringTlvValue::StatelessParsing { .. } => {
                Either::Left(BmpV4RouteMonitoringTlvType::StatelessParsing)
            }
            BmpV4RouteMonitoringTlvValue::PathMarking(..) => {
                Either::Left(BmpV4RouteMonitoringTlvType::PathMarking)
            }
            BmpV4RouteMonitoringTlvValue::Unknown { code, .. } => Either::Right(code),
        }
    }
    pub fn index(&self) -> u16 {
        self.index
    }

    pub fn value(&self) -> &BmpV4RouteMonitoringTlvValue {
        &self.value
    }
}

// TODO assign real codes and move to IANA when draft becomes RFC
#[repr(u16)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, FromRepr, Display)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4RouteMonitoringTlvType {
    GroupTlv = 0,
    StatelessParsing = 1,
    BgpUpdatePdu = 2,
    VrfTableName = 3,
    PathMarking = 4,
}

pub const BMPV4_TLV_GROUP_GBIT: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4RouteMonitoringTlvValue {
    BgpUpdatePdu(BgpMessage),
    VrfTableName(String),
    GroupTlv(Vec<u16>),
    StatelessParsing(BgpCapability),
    PathMarking(PathMarking),
    Unknown { code: u16, value: Vec<u8> },
}

/// Path Status TLV
/// ```text
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-------------------------------+-------------------------------+
/// |E|       Type (15 bits)        |       Length (2 octets)       |
/// +---------------------------------------------------------------+
/// |        Index (2 octets)       |
/// +-------------------------------+-------------------------------+
/// |                      Path Status (4 octets)                   |
/// +---------------------------------------------------------------+
/// |                 Reason Code (2 octets, optional)              |
/// +---------------------------------------------------------------+
/// ```
#[derive(Debug, Hash, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PathMarking {
    /// Represented as u32 instead of [PathStatus] since it is a bitflag
    /// [PathStatus] is just a collection of all possible flags in this bitflag
    pub path_status: u32,
    pub reason_code: Option<PathMarkingReason>,
}

// TODO assign real codes and move to IANA when draft becomes RFC
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, FromRepr, Display)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PathStatus {
    Invalid = 0x00000001,
    Best = 0x00000002,
    NonSelected = 0x00000004,
    Primary = 0x00000008,
    Backup = 0x00000010,
    NonInstalled = 0x00000020,
    BestExternal = 0x00000040,
    AddPath = 0x00000080,
    FilteredInInboundPolicy = 0x00000100,
    FilteredInOutboundPolicy = 0x00000200,
    InvalidRov = 0x00000400,
    Stale = 0x00000800,
    Suppressed = 0x00001000,
}

impl BitOr for PathStatus {
    type Output = u32;

    fn bitor(self, rhs: Self) -> Self::Output {
        self as u32 | rhs as u32
    }
}

impl BitOr<PathStatus> for u32 {
    type Output = u32;

    fn bitor(self, rhs: PathStatus) -> Self::Output {
        self | rhs as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, FromRepr)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum PathMarkingReason {
    InvalidAsLoop = 0x0001,
    InvalidUnresolvableNexthop = 0x0002,
    NotPreferredLocalPref = 0x0003,
    NotPreferredAsPathLength = 0x0004,
    NotPreferredOrigin = 0x0005,
    NotPreferredMed = 0x0006,
    NotPreferredPeerType = 0x0007,
    NotPreferredIgpCost = 0x0008,
    NotPreferredRouterId = 0x0009,
    NotPreferredPeerAddress = 0x000A,
    NotPreferredAigp = 0x000B,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4RouteMonitoringError {
    TlvError(BmpV4RouteMonitoringTlvError),
}

impl From<BmpV4RouteMonitoringTlvError> for BmpV4RouteMonitoringError {
    fn from(value: BmpV4RouteMonitoringTlvError) -> Self {
        Self::TlvError(value)
    }
}

/// Route Monitoring messages are used for initial synchronization of the
/// RIBs. They are also used for incremental updates of the RIB state.
/// Route monitoring messages are state-compressed.
/// This is all discussed in more detail in Section 5.
///
/// Following the common BMP header and per-peer header is a BGP Update
/// PDU.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BmpV4RouteMonitoringMessage {
    pub peer_header: PeerHeader,
    update_pdu: BmpV4RouteMonitoringTlv,
    tlvs: Vec<BmpV4RouteMonitoringTlv>,
}

impl BmpV4RouteMonitoringMessage {
    pub fn build(
        peer_header: PeerHeader,
        update_pdu: BgpMessage,
        tlvs: Vec<BmpV4RouteMonitoringTlv>,
    ) -> Result<Self, BmpV4RouteMonitoringError> {
        let update_pdu = BmpV4RouteMonitoringTlv::build(
            0,
            BmpV4RouteMonitoringTlvValue::BgpUpdatePdu(update_pdu),
        )?;

        Ok(Self {
            peer_header,
            update_pdu,
            tlvs,
        })
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub fn update_message_tlv(&self) -> &BmpV4RouteMonitoringTlv {
        &self.update_pdu
    }

    pub fn update_message(&self) -> &BgpMessage {
        match &self.update_pdu.value {
            BmpV4RouteMonitoringTlvValue::BgpUpdatePdu(update) => update,
            _ => {
                unreachable!("This TLV has to be BgpUpdatePdu (enforced by builder)");
            }
        }
    }

    pub const fn tlvs(&self) -> &Vec<BmpV4RouteMonitoringTlv> {
        &self.tlvs
    }
}
