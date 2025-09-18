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
    iana::{BmpMessageType, InitiationInformationTlvType},
    v3, PeerHeader,
};
use either::Either;
use netgauze_bgp_pkt::{capabilities::BgpCapability, iana::BgpMessageType, BgpMessage};
use serde::{Deserialize, Serialize};
use std::ops::BitOr;
use strum_macros::{Display, FromRepr};

pub const BMPV4_TLV_GROUP_GBIT: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpMessageValue {
    RouteMonitoring(RouteMonitoringMessage),
    StatisticsReport(v3::StatisticsReportMessage),
    PeerDownNotification(PeerDownNotificationMessage),
    PeerUpNotification(v3::PeerUpNotificationMessage),
    Initiation(v3::InitiationMessage),
    Termination(v3::TerminationMessage),
    RouteMirroring(v3::RouteMirroringMessage),
    Experimental251(Vec<u8>),
    Experimental252(Vec<u8>),
    Experimental253(Vec<u8>),
    Experimental254(Vec<u8>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PeerDownTlv {
    Unknown { code: u16, value: Vec<u8> },
}

impl PeerDownTlv {
    pub const fn code(&self) -> u16 {
        match self {
            PeerDownTlv::Unknown { code, .. } => *code,
        }
    }
}

impl BmpMessageValue {
    pub const fn get_type(&self) -> BmpMessageType {
        match self {
            BmpMessageValue::RouteMonitoring(_) => BmpMessageType::RouteMonitoring,
            BmpMessageValue::StatisticsReport(_) => BmpMessageType::StatisticsReport,
            BmpMessageValue::PeerDownNotification { .. } => BmpMessageType::PeerDownNotification,
            BmpMessageValue::PeerUpNotification(_) => BmpMessageType::PeerUpNotification,
            BmpMessageValue::Initiation(_) => BmpMessageType::Initiation,
            BmpMessageValue::Termination(_) => BmpMessageType::Termination,
            BmpMessageValue::RouteMirroring(_) => BmpMessageType::RouteMirroring,
            BmpMessageValue::Experimental251(_) => BmpMessageType::Experimental251,
            BmpMessageValue::Experimental252(_) => BmpMessageType::Experimental252,
            BmpMessageValue::Experimental253(_) => BmpMessageType::Experimental253,
            BmpMessageValue::Experimental254(_) => BmpMessageType::Experimental254,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct RouteMonitoringTlv {
    index: u16,
    value: RouteMonitoringTlvValue,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteMonitoringTlvError {
    BadGroupTlvIndex(u16),
    BadBgpMessageType(BgpMessageType),
    VrfTableNameStringIsTooLong(usize),
}

impl RouteMonitoringTlv {
    pub fn build(
        index: u16,
        value: RouteMonitoringTlvValue,
    ) -> Result<Self, RouteMonitoringTlvError> {
        match &value {
            RouteMonitoringTlvValue::GroupTlv(_) => {
                if index & BMPV4_TLV_GROUP_GBIT != BMPV4_TLV_GROUP_GBIT {
                    // First bit has to be one (G flag)
                    return Err(RouteMonitoringTlvError::BadGroupTlvIndex(index));
                }
            }
            RouteMonitoringTlvValue::VrfTableName(str) => {
                let len = str.len();
                if len > 255 {
                    return Err(RouteMonitoringTlvError::VrfTableNameStringIsTooLong(len));
                }
            }
            RouteMonitoringTlvValue::BgpUpdate(update_pdu) => {
                if update_pdu.get_type() != BgpMessageType::Update {
                    return Err(RouteMonitoringTlvError::BadBgpMessageType(
                        update_pdu.get_type(),
                    ));
                }
            }
            _ => {}
        };

        Ok(Self { index, value })
    }

    pub const fn get_type(&self) -> Either<RouteMonitoringTlvType, u16> {
        match self.value {
            RouteMonitoringTlvValue::BgpUpdate(_) => {
                Either::Left(RouteMonitoringTlvType::BgpUpdatePdu)
            }
            RouteMonitoringTlvValue::VrfTableName(_) => {
                Either::Left(RouteMonitoringTlvType::VrfTableName)
            }
            RouteMonitoringTlvValue::GroupTlv(_) => Either::Left(RouteMonitoringTlvType::GroupTlv),
            RouteMonitoringTlvValue::StatelessParsing { .. } => {
                Either::Left(RouteMonitoringTlvType::StatelessParsing)
            }
            RouteMonitoringTlvValue::PathMarking(..) => {
                Either::Left(RouteMonitoringTlvType::PathMarking)
            }
            RouteMonitoringTlvValue::Unknown { code, .. } => Either::Right(code),
        }
    }
    pub const fn index(&self) -> u16 {
        self.index
    }

    pub const fn value(&self) -> &RouteMonitoringTlvValue {
        &self.value
    }
}

// TODO assign real codes and move to IANA when draft becomes RFC
#[repr(u16)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, FromRepr, Display)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteMonitoringTlvType {
    BgpUpdatePdu = 1,
    GroupTlv = 2,
    VrfTableName = 3,
    StatelessParsing = 4,
    PathMarking = 5,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteMonitoringTlvValue {
    BgpUpdate(BgpMessage),
    VrfTableName(String),
    GroupTlv(Vec<u16>),
    StatelessParsing(BgpCapability),
    PathMarking(PathMarking),
    Unknown { code: u16, value: Vec<u8> },
}

/// Path Status TLV [draft-ietf-grow-bmp-path-marking-tlv](https://datatracker.ietf.org/doc/html/draft-ietf-grow-bmp-path-marking-tlv)
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
    path_status: u32,
    /// Represented as u16 instead of [PathMarkingReason] to accept
    /// non-IANA-defined reason codes Well-known reason codes are defined in
    /// [PathMarkingReason] Reason codes are used (Some(_)) with
    /// [PathStatus::Invalid] and [PathStatus::NonSelected]
    reason: Option<PathMarkingReason>,
}

impl PathMarking {
    pub fn new(path_status: u32, reason_code: Option<PathMarkingReason>) -> PathMarking {
        Self {
            path_status,
            reason: reason_code,
        }
    }

    pub const fn path_status(&self) -> u32 {
        self.path_status
    }

    pub const fn reason(&self) -> Option<PathMarkingReason> {
        self.reason
    }
    pub fn reason_code(&self) -> Option<u16> {
        self.reason.map(|x| x.code())
    }
}

// TODO assign real codes and move to IANA when draft becomes RFC
//  (https://datatracker.ietf.org/doc/html/draft-ietf-grow-bmp-path-marking-tlv)
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
    Stale = 0x00000400,
    Suppressed = 0x00000800,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PathMarkingReason {
    WellKnown(WellKnownPathMarkingReasonCode),
    Unknown(u16),
}

impl PathMarkingReason {
    pub const fn code(&self) -> u16 {
        match self {
            PathMarkingReason::WellKnown(x) => *x as u16,
            PathMarkingReason::Unknown(x) => *x,
        }
    }

    pub const fn is_well_known(&self) -> bool {
        matches!(self, PathMarkingReason::WellKnown(..))
    }

    pub const fn from_code(code: u16) -> Self {
        match WellKnownPathMarkingReasonCode::from_repr(code) {
            Some(code) => PathMarkingReason::WellKnown(code),
            None => PathMarkingReason::Unknown(code),
        }
    }
}

impl From<WellKnownPathMarkingReasonCode> for PathMarkingReason {
    fn from(value: WellKnownPathMarkingReasonCode) -> Self {
        PathMarkingReason::WellKnown(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, FromRepr)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum WellKnownPathMarkingReasonCode {
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
pub enum RouteMonitoringError {
    TlvError(RouteMonitoringTlvError),
}

impl From<RouteMonitoringTlvError> for RouteMonitoringError {
    fn from(value: RouteMonitoringTlvError) -> Self {
        Self::TlvError(value)
    }
}

/// Route Monitoring messages are used for initial synchronization of the
/// RIBs. They are also used for incremental updates of the RIB state.
/// Route monitoring messages are state-compressed.
/// This is all discussed in more detail in Section 5 [RFC7854 Section 5](https://www.rfc-editor.org/rfc/rfc7854#section-5).
///
/// Following the common BMP header and per-peer header is a BGP Update
/// PDU.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct RouteMonitoringMessage {
    peer_header: PeerHeader,
    update_pdu: RouteMonitoringTlv,
    tlvs: Vec<RouteMonitoringTlv>,
}

impl RouteMonitoringMessage {
    pub fn build(
        peer_header: PeerHeader,
        update_pdu: BgpMessage,
        tlvs: Vec<RouteMonitoringTlv>,
    ) -> Result<Self, RouteMonitoringError> {
        let update_pdu =
            RouteMonitoringTlv::build(0, RouteMonitoringTlvValue::BgpUpdate(update_pdu))?;

        Ok(Self {
            peer_header,
            update_pdu,
            tlvs,
        })
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn update_message_tlv(&self) -> &RouteMonitoringTlv {
        &self.update_pdu
    }

    pub fn update_message(&self) -> &BgpMessage {
        match &self.update_pdu.value {
            RouteMonitoringTlvValue::BgpUpdate(update) => update,
            _ => {
                unreachable!("This TLV has to be BgpUpdatePdu (enforced by builder)");
            }
        }
    }

    pub const fn tlvs(&self) -> &Vec<RouteMonitoringTlv> {
        &self.tlvs
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PeerDownNotificationMessage {
    peer_header: PeerHeader,
    reason: v3::PeerDownNotificationReason,
    tlvs: Vec<PeerDownTlv>,
}

impl PeerDownNotificationMessage {
    pub fn build(
        peer_header: PeerHeader,
        reason: v3::PeerDownNotificationReason,
        tlvs: Vec<PeerDownTlv>,
    ) -> Result<Self, v3::PeerDownNotificationMessageError> {
        match &reason {
            v3::PeerDownNotificationReason::LocalSystemClosedNotificationPduFollows(msg)
            | v3::PeerDownNotificationReason::RemoteSystemClosedNotificationPduFollows(msg) => {
                if msg.get_type() != BgpMessageType::Notification {
                    return Err(
                        v3::PeerDownNotificationMessageError::UnexpectedBgpMessageType(
                            msg.get_type(),
                        ),
                    );
                }
            }
            v3::PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(_) => {}
            v3::PeerDownNotificationReason::RemoteSystemClosedNoData => {}
            v3::PeerDownNotificationReason::PeerDeConfigured => {}
            v3::PeerDownNotificationReason::LocalSystemClosedTlvDataFollows(information) => {
                if information.get_type() != InitiationInformationTlvType::VrfTableName {
                    return Err(
                        v3::PeerDownNotificationMessageError::UnexpectedInitiationInformationTlvType(
                            information.get_type(),
                        ),
                    );
                }
            }
            v3::PeerDownNotificationReason::Experimental251(_) => {}
            v3::PeerDownNotificationReason::Experimental252(_) => {}
            v3::PeerDownNotificationReason::Experimental253(_) => {}
            v3::PeerDownNotificationReason::Experimental254(_) => {}
        }

        Ok(Self {
            peer_header,
            reason,
            tlvs,
        })
    }

    pub const fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub const fn reason(&self) -> &v3::PeerDownNotificationReason {
        &self.reason
    }

    pub const fn tlvs(&self) -> &Vec<PeerDownTlv> {
        &self.tlvs
    }
}
