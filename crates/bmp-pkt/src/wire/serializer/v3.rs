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
    iana::{
        PEER_FLAGS_IS_ADJ_RIB_OUT, PEER_FLAGS_IS_ASN2, PEER_FLAGS_IS_FILTERED, PEER_FLAGS_IS_IPV6,
        PEER_FLAGS_IS_POST_POLICY,
    },
    v3::{
        BmpMessageValue, InitiationInformation, InitiationMessage, MirroredBgpMessage,
        PeerDownNotificationMessage, PeerDownNotificationReason, PeerUpNotificationMessage,
        RouteMirroringMessage, RouteMirroringValue, RouteMonitoringMessage, StatisticsCounter,
        StatisticsReportMessage, TerminationInformation, TerminationMessage,
    },
    BmpPeerType, PeerHeader,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_bgp_pkt::wire::serializer::{
    nlri::RouteDistinguisherWritingError, BgpMessageWritingError,
};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use std::{io::Write, net::IpAddr};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageValueWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteMonitoringMessageError(#[from] RouteMonitoringMessageWritingError),
    RouteMirroringMessageError(#[from] RouteMirroringMessageWritingError),
    InitiationMessageError(#[from] InitiationMessageWritingError),
    PeerUpNotificationMessageError(#[from] PeerUpNotificationMessageWritingError),
    PeerDownNotificationMessageError(#[from] PeerDownNotificationMessageWritingError),
    TerminationMessageError(#[from] TerminationMessageWritingError),
    StatisticsReportMessageError(#[from] StatisticsReportMessageWritingError),
}

impl WritablePdu<BmpMessageValueWritingError> for BmpMessageValue {
    /// 1-octet msg type,
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let len = match self {
            Self::RouteMonitoring(value) => value.len(),
            Self::StatisticsReport(value) => value.len(),
            Self::PeerDownNotification(value) => value.len(),
            Self::PeerUpNotification(value) => value.len(),
            Self::Initiation(value) => value.len(),
            Self::Termination(value) => value.len(),
            Self::RouteMirroring(value) => value.len(),
            Self::Experimental251(value) => value.len(),
            Self::Experimental252(value) => value.len(),
            Self::Experimental253(value) => value.len(),
            Self::Experimental254(value) => value.len(),
        };
        Self::BASE_LENGTH + len
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BmpMessageValueWritingError> {
        writer.write_u8(self.get_type().into())?;
        match self {
            Self::RouteMonitoring(value) => value.write(writer)?,
            Self::StatisticsReport(value) => value.write(writer)?,
            Self::PeerDownNotification(value) => value.write(writer)?,
            Self::PeerUpNotification(value) => value.write(writer)?,
            Self::Initiation(value) => value.write(writer)?,
            Self::Termination(value) => value.write(writer)?,
            Self::RouteMirroring(value) => value.write(writer)?,
            Self::Experimental251(value) => writer.write_all(value)?,
            Self::Experimental252(value) => writer.write_all(value)?,
            Self::Experimental253(value) => writer.write_all(value)?,
            Self::Experimental254(value) => writer.write_all(value)?,
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMirroringMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    RouteMirroringValueError(#[from] RouteMirroringValueWritingError),
}

impl WritablePdu<RouteMirroringMessageWritingError> for RouteMirroringMessage {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.peer_header().len()
            + self.mirrored().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteMirroringMessageWritingError> {
        self.peer_header().write(writer)?;
        for mirrored in self.mirrored() {
            mirrored.write(writer)?;
        }
        Ok(())
    }
}

#[inline]
const fn compute_peer_flags_value(
    ipv6: bool,
    post_policy: bool,
    asn2: bool,
    adj_rib_out: bool,
) -> u8 {
    let mut flags = 0;
    if ipv6 {
        flags |= PEER_FLAGS_IS_IPV6;
    }
    if post_policy {
        flags |= PEER_FLAGS_IS_POST_POLICY;
    }
    if asn2 {
        flags |= PEER_FLAGS_IS_ASN2
    }
    if adj_rib_out {
        flags |= PEER_FLAGS_IS_ADJ_RIB_OUT
    }
    flags
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BmpPeerTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl BmpPeerType {
    pub fn get_flags_value(&self) -> u8 {
        match self {
            Self::GlobalInstancePeer {
                ipv6,
                post_policy,
                asn2,
                adj_rib_out,
            }
            | Self::RdInstancePeer {
                ipv6,
                post_policy,
                asn2,
                adj_rib_out,
            }
            | Self::LocalInstancePeer {
                ipv6,
                post_policy,
                asn2,
                adj_rib_out,
            } => compute_peer_flags_value(*ipv6, *post_policy, *asn2, *adj_rib_out),
            Self::LocRibInstancePeer { filtered } => {
                if *filtered {
                    PEER_FLAGS_IS_FILTERED
                } else {
                    0
                }
            }
            Self::Experimental251 { flags }
            | Self::Experimental252 { flags }
            | Self::Experimental253 { flags }
            | Self::Experimental254 { flags } => *flags,
        }
    }
}

impl WritablePdu<BmpPeerTypeWritingError> for BmpPeerType {
    /// 1-octet type and 1-octet flags
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BmpPeerTypeWritingError> {
        writer.write_u8(self.get_type().into())?;
        writer.write_u8(self.get_flags_value())?;
        Ok(())
    }
}
#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum PeerHeaderWritingError {
    StdIOError(#[from_std_io_error] String),
    BmpPeerTypeError(#[from] BmpPeerTypeWritingError),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
}

impl WritablePdu<PeerHeaderWritingError> for PeerHeader {
    ///  1-octet peer type
    ///  1-octet peer flags
    ///  8-octets peer Distinguisher
    /// 16-octets peer address
    ///  4-octets peer AS
    ///  4-octets peer BGP ID
    ///  4-octets Timestamp (Seconds)
    ///  4-octets Timestamp (Microseconds)
    const BASE_LENGTH: usize = 42;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), PeerHeaderWritingError> {
        self.peer_type.write(writer)?;
        match self.rd() {
            None => writer.write_u64::<NetworkEndian>(0)?,
            Some(value) => value.write(writer)?,
        }
        match self.address() {
            Some(IpAddr::V4(ipv4)) => {
                writer.write_u64::<NetworkEndian>(0)?;
                writer.write_u32::<NetworkEndian>(0)?;
                writer.write_all(&ipv4.octets())?;
            }
            Some(IpAddr::V6(ipv6)) => {
                writer.write_all(&ipv6.octets())?;
            }
            None => writer.write_u128::<NetworkEndian>(0)?,
        }
        writer.write_u32::<NetworkEndian>(self.peer_as())?;
        writer.write_all(&self.bgp_id().octets())?;
        match self.timestamp() {
            None => writer.write_u64::<NetworkEndian>(0)?,
            Some(time) => {
                writer.write_u32::<NetworkEndian>(time.timestamp() as u32)?;
                writer.write_u32::<NetworkEndian>(time.timestamp_subsec_micros())?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMirroringValueWritingError {
    StdIOError(#[from_std_io_error] String),
    BgpMessageError(#[from] BgpMessageWritingError),
}

impl WritablePdu<RouteMirroringValueWritingError> for RouteMirroringValue {
    /// 2-octet type and 2-octet length
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::BgpMessage(msg) => match msg {
                    MirroredBgpMessage::Parsed(msg) => msg.len(),
                    MirroredBgpMessage::Raw(msg) => msg.len(),
                },
                Self::Information(_) => 2, // Information are always 2-octets
                Self::Experimental65531(value) => value.len(),
                Self::Experimental65532(value) => value.len(),
                Self::Experimental65533(value) => value.len(),
                Self::Experimental65534(value) => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteMirroringValueWritingError> {
        writer.write_u16::<NetworkEndian>(self.get_type().into())?;
        writer.write_u16::<NetworkEndian>((self.len() - Self::BASE_LENGTH) as u16)?;
        match self {
            Self::BgpMessage(msg) => match msg {
                MirroredBgpMessage::Parsed(msg) => msg.write(writer)?,
                MirroredBgpMessage::Raw(raw) => writer.write_all(raw)?,
            },
            Self::Information(info) => writer.write_u16::<NetworkEndian>((*info).into())?,
            Self::Experimental65531(value) => writer.write_all(value)?,
            Self::Experimental65532(value) => writer.write_all(value)?,
            Self::Experimental65533(value) => writer.write_all(value)?,
            Self::Experimental65534(value) => writer.write_all(value)?,
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    BgpMessageError(#[from] BgpMessageWritingError),
}

impl WritablePdu<RouteMonitoringMessageWritingError> for RouteMonitoringMessage {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.peer_header().len() + self.update_message().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteMonitoringMessageWritingError> {
        self.peer_header().write(writer)?;
        self.update_message().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum InitiationMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    InitiationInformationError(#[from] InitiationInformationWritingError),
}

impl WritablePdu<InitiationMessageWritingError> for InitiationMessage {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.information().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), InitiationMessageWritingError> {
        for info in self.information() {
            info.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum InitiationInformationWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<InitiationInformationWritingError> for InitiationInformation {
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::String(value) => value.len(),
                Self::SystemDescription(value) => value.len(),
                Self::SystemName(value) => value.len(),
                Self::VrfTableName(value) => value.len(),
                Self::AdminLabel(value) => value.len(),
                Self::Experimental65531(value) => value.len(),
                Self::Experimental65532(value) => value.len(),
                Self::Experimental65533(value) => value.len(),
                Self::Experimental65534(value) => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), InitiationInformationWritingError> {
        writer.write_u16::<NetworkEndian>(self.get_type().into())?;
        match self {
            Self::String(value) => {
                let bytes = value.as_bytes();
                writer.write_u16::<NetworkEndian>(bytes.len() as u16)?;
                writer.write_all(bytes)?;
            }
            Self::SystemDescription(value) => {
                let bytes = value.as_bytes();
                writer.write_u16::<NetworkEndian>(bytes.len() as u16)?;
                writer.write_all(bytes)?;
            }
            Self::SystemName(value) => {
                let bytes = value.as_bytes();
                writer.write_u16::<NetworkEndian>(bytes.len() as u16)?;
                writer.write_all(bytes)?;
            }
            Self::VrfTableName(value) => {
                let bytes = value.as_bytes();
                writer.write_u16::<NetworkEndian>(bytes.len() as u16)?;
                writer.write_all(bytes)?;
            }
            Self::AdminLabel(value) => {
                let bytes = value.as_bytes();
                writer.write_u16::<NetworkEndian>(bytes.len() as u16)?;
                writer.write_all(bytes)?;
            }
            Self::Experimental65531(value) => {
                writer.write_u16::<NetworkEndian>(value.len() as u16)?;
                writer.write_all(value)?;
            }
            Self::Experimental65532(value) => {
                writer.write_u16::<NetworkEndian>(value.len() as u16)?;
                writer.write_all(value)?;
            }
            Self::Experimental65533(value) => {
                writer.write_u16::<NetworkEndian>(value.len() as u16)?;
                writer.write_all(value)?;
            }
            Self::Experimental65534(value) => {
                writer.write_u16::<NetworkEndian>(value.len() as u16)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum PeerUpNotificationMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    BgpMessageError(#[from] BgpMessageWritingError),
    InitiationInformationError(#[from] InitiationInformationWritingError),
}

impl WritablePdu<PeerUpNotificationMessageWritingError> for PeerUpNotificationMessage {
    // 16 local addr + 2 local port + 2 remote port
    const BASE_LENGTH: usize = 20;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.peer_header().len()
            + self.sent_message().len()
            + self.received_message().len()
            + self.information().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), PeerUpNotificationMessageWritingError> {
        self.peer_header().write(writer)?;
        match self.local_address() {
            Some(IpAddr::V4(addr)) => {
                writer.write_u64::<NetworkEndian>(0)?;
                writer.write_u32::<NetworkEndian>(0)?;
                writer.write_all(&addr.octets())?;
            }
            Some(IpAddr::V6(addr)) => writer.write_all(&addr.octets())?,
            None => {
                writer.write_all(&[0x00; 16])?;
            }
        }
        writer.write_u16::<NetworkEndian>(self.local_port().unwrap_or_default())?;
        writer.write_u16::<NetworkEndian>(self.remote_port().unwrap_or_default())?;

        self.sent_message().write(writer)?;
        self.received_message().write(writer)?;
        for info in self.information() {
            info.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum PeerDownNotificationMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    InitiationInformationError(#[from] InitiationInformationWritingError),
    PeerDownNotificationReasonError(#[from] PeerDownNotificationReasonWritingError),
}

impl WritablePdu<PeerDownNotificationMessageWritingError> for PeerDownNotificationMessage {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.peer_header().len() + self.reason().len()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), PeerDownNotificationMessageWritingError> {
        self.peer_header().write(writer)?;
        self.reason().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum PeerDownNotificationReasonWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    BgpMessageError(#[from] BgpMessageWritingError),
    InitiationInformationError(#[from] InitiationInformationWritingError),
}

impl WritablePdu<PeerDownNotificationReasonWritingError> for PeerDownNotificationReason {
    // 1 reason
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::LocalSystemClosedNotificationPduFollows(msg) => msg.len(),
                Self::LocalSystemClosedFsmEventFollows(_) => 2,
                Self::RemoteSystemClosedNotificationPduFollows(msg) => msg.len(),
                Self::RemoteSystemClosedNoData => 0,
                Self::PeerDeConfigured => 0,
                Self::LocalSystemClosedTlvDataFollows(info) => info.len(),
                Self::Experimental251(data) => data.len(),
                Self::Experimental252(data) => data.len(),
                Self::Experimental253(data) => data.len(),
                Self::Experimental254(data) => data.len(),
            }
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), PeerDownNotificationReasonWritingError> {
        writer.write_u8(self.get_type().into())?;
        match self {
            Self::LocalSystemClosedNotificationPduFollows(msg) => msg.write(writer)?,
            Self::LocalSystemClosedFsmEventFollows(value) => {
                writer.write_u16::<NetworkEndian>(*value)?
            }
            Self::RemoteSystemClosedNotificationPduFollows(msg) => msg.write(writer)?,
            Self::RemoteSystemClosedNoData => {}
            Self::PeerDeConfigured => {}
            Self::LocalSystemClosedTlvDataFollows(info) => info.write(writer)?,
            Self::Experimental251(data) => writer.write_all(&data[0..])?,
            Self::Experimental252(data) => writer.write_all(&data[0..])?,
            Self::Experimental253(data) => writer.write_all(&data[0..])?,
            Self::Experimental254(data) => writer.write_all(&data[0..])?,
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TerminationMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    TerminationInformationError(#[from] TerminationInformationWritingError),
}

impl WritablePdu<TerminationMessageWritingError> for TerminationMessage {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.information().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), TerminationMessageWritingError> {
        for info in self.information() {
            info.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TerminationInformationWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<TerminationInformationWritingError> for TerminationInformation {
    /// 2-octet information type + 2-octet information length
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::String(str) => str.len(),
                Self::Reason(_) => 2, // reasons are 2-octet
                Self::Experimental65531(value) => value.len(),
                Self::Experimental65532(value) => value.len(),
                Self::Experimental65533(value) => value.len(),
                Self::Experimental65534(value) => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), TerminationInformationWritingError> {
        writer.write_u16::<NetworkEndian>(self.get_type().into())?;
        writer.write_u16::<NetworkEndian>((self.len() - Self::BASE_LENGTH) as u16)?;
        match self {
            Self::String(str) => writer.write_all(str.as_bytes())?,
            Self::Reason(reason) => writer.write_u16::<NetworkEndian>((*reason).into())?,
            Self::Experimental65531(value) => writer.write_all(value)?,
            Self::Experimental65532(value) => writer.write_all(value)?,
            Self::Experimental65533(value) => writer.write_all(value)?,
            Self::Experimental65534(value) => writer.write_all(value)?,
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum StatisticsReportMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    StatisticsCounterMessageError(#[from] StatisticsCounterMessageWritingError),
}

impl WritablePdu<StatisticsReportMessageWritingError> for StatisticsReportMessage {
    /// 4-octets Number of counters
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.peer_header().len()
            + self.counters().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), StatisticsReportMessageWritingError> {
        self.peer_header().write(writer)?;
        writer.write_u32::<NetworkEndian>(self.counters().len() as u32)?;
        for counter in self.counters() {
            counter.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum StatisticsCounterMessageWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<StatisticsCounterMessageWritingError> for StatisticsCounter {
    /// 2-octets type and 2-octets length
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::NumberOfPrefixesRejectedByInboundPolicy(_) => 4,
                Self::NumberOfDuplicatePrefixAdvertisements(_) => 4,
                Self::NumberOfDuplicateWithdraws(_) => 4,
                Self::NumberOfUpdatesInvalidatedDueToClusterListLoop(_) => 4,
                Self::NumberOfUpdatesInvalidatedDueToAsPathLoop(_) => 4,
                Self::NumberOfUpdatesInvalidatedDueToOriginatorId(_) => 4,
                Self::NumberOfUpdatesInvalidatedDueToAsConfederationLoop(_) => 4,
                Self::NumberOfRoutesInAdjRibIn(_) => 8,
                Self::NumberOfRoutesInLocRib(_) => 8,
                Self::NumberOfRoutesInPerAfiSafiAdjRibIn(_, _) => 11,
                Self::NumberOfRoutesInPerAfiSafiLocRib(_, _) => 11,
                Self::NumberOfUpdatesSubjectedToTreatAsWithdraw(_) => 4,
                Self::NumberOfPrefixesSubjectedToTreatAsWithdraw(_) => 4,
                Self::NumberOfDuplicateUpdateMessagesReceived(_) => 4,
                Self::NumberOfRoutesInPrePolicyAdjRibOut(_) => 8,
                Self::NumberOfRoutesInPostPolicyAdjRibOut(_) => 8,
                Self::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(_, _) => 11,
                Self::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(_, _) => 11,
                Self::Experimental65531(value) => value.len(),
                Self::Experimental65532(value) => value.len(),
                Self::Experimental65533(value) => value.len(),
                Self::Experimental65534(value) => value.len(),
                Self::Unknown(_, value) => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), StatisticsCounterMessageWritingError> {
        match self.get_type() {
            Ok(code) => writer.write_u16::<NetworkEndian>(code.into())?,
            Err(code) => writer.write_u16::<NetworkEndian>(code)?,
        }
        writer.write_u16::<NetworkEndian>((self.len() - Self::BASE_LENGTH) as u16)?;
        match self {
            Self::NumberOfPrefixesRejectedByInboundPolicy(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfDuplicatePrefixAdvertisements(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfDuplicateWithdraws(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfUpdatesInvalidatedDueToClusterListLoop(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfUpdatesInvalidatedDueToAsPathLoop(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfUpdatesInvalidatedDueToOriginatorId(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfUpdatesInvalidatedDueToAsConfederationLoop(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfRoutesInAdjRibIn(value) => writer.write_u64::<NetworkEndian>(value.0)?,
            Self::NumberOfRoutesInLocRib(value) => writer.write_u64::<NetworkEndian>(value.0)?,
            Self::NumberOfRoutesInPerAfiSafiAdjRibIn(address_type, value) => {
                writer.write_u16::<NetworkEndian>(address_type.address_family().into())?;
                writer.write_u8(address_type.subsequent_address_family().into())?;
                writer.write_u64::<NetworkEndian>(value.0)?;
            }
            Self::NumberOfRoutesInPerAfiSafiLocRib(address_type, value) => {
                writer.write_u16::<NetworkEndian>(address_type.address_family().into())?;
                writer.write_u8(address_type.subsequent_address_family().into())?;
                writer.write_u64::<NetworkEndian>(value.0)?;
            }
            Self::NumberOfUpdatesSubjectedToTreatAsWithdraw(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfPrefixesSubjectedToTreatAsWithdraw(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfDuplicateUpdateMessagesReceived(value) => {
                writer.write_u32::<NetworkEndian>(value.0)?
            }
            Self::NumberOfRoutesInPrePolicyAdjRibOut(value) => {
                writer.write_u64::<NetworkEndian>(value.0)?
            }
            Self::NumberOfRoutesInPostPolicyAdjRibOut(value) => {
                writer.write_u64::<NetworkEndian>(value.0)?
            }
            Self::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(address_type, value) => {
                writer.write_u16::<NetworkEndian>(address_type.address_family().into())?;
                writer.write_u8(address_type.subsequent_address_family().into())?;
                writer.write_u64::<NetworkEndian>(value.0)?;
            }
            Self::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(address_type, value) => {
                writer.write_u16::<NetworkEndian>(address_type.address_family().into())?;
                writer.write_u8(address_type.subsequent_address_family().into())?;
                writer.write_u64::<NetworkEndian>(value.0)?;
            }
            Self::Experimental65531(value) => writer.write_all(value)?,
            Self::Experimental65532(value) => writer.write_all(value)?,
            Self::Experimental65533(value) => writer.write_all(value)?,
            Self::Experimental65534(value) => writer.write_all(value)?,
            Self::Unknown(_, value) => writer.write_all(value)?,
        }
        Ok(())
    }
}
