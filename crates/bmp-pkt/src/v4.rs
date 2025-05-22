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
use strum_macros::{Display, FromRepr};

pub const BMPV4_TLV_GROUP_GBIT: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4MessageValue {
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

impl BmpV4MessageValue {
    pub const fn get_type(&self) -> BmpMessageType {
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
    GroupTlv = 0,
    StatelessParsing = 1,
    BgpUpdatePdu = 2,
    VrfTableName = 3,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteMonitoringTlvValue {
    BgpUpdate(BgpMessage),
    VrfTableName(String),
    GroupTlv(Vec<u16>),
    StatelessParsing(BgpCapability),
    Unknown { code: u16, value: Vec<u8> },
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
