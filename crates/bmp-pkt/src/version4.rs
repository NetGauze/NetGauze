use crate::{
    iana::BmpMessageType,
    version4::BmpV4RouteMonitoringTlvError::{
        BadBgpMessageType, BadGroupTlvIndex, VrfTableNameStringIsTooLong,
    },
    InitiationMessage, PeerDownNotificationMessage, PeerHeader, PeerUpNotificationMessage,
    RouteMirroringMessage, StatisticsReportMessage, TerminationMessage,
};
use either::Either;
use netgauze_bgp_pkt::{iana::BgpMessageType, BgpMessage};
use netgauze_iana::address_family::AddressType;
use serde::{Deserialize, Serialize};
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpV4RouteMonitoringTlvValue {
    BgpUpdatePdu(BgpMessage),
    VrfTableName(String),
    GroupTlv(Vec<u16>),
    StatelessParsing(StatelessParsingTlv),
    Unknown { code: u16, value: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct StatelessParsingTlv {
    pub address_type: AddressType,
    pub capability: BmpStatelessParsingCapability,
    pub enabled: bool,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Display, FromRepr)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpStatelessParsingCapability {
    AddPath = 0,
    MultipleLabels = 1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UnknownBmpStatelessParsingCapability(u16);

impl TryFrom<u16> for BmpStatelessParsingCapability {
    type Error = UnknownBmpStatelessParsingCapability;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            None => Err(UnknownBmpStatelessParsingCapability(value)),
            Some(ok) => Ok(ok),
        }
    }
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
