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
    v4::{
        BmpMessageValue, PeerDownNotificationMessage, PeerDownTlv, RouteMonitoringMessage,
        RouteMonitoringTlv, RouteMonitoringTlvValue,
    },
    wire::serializer::v3::{
        InitiationInformationWritingError, InitiationMessageWritingError,
        PeerDownNotificationReasonWritingError, PeerHeaderWritingError,
        PeerUpNotificationMessageWritingError, RouteMirroringMessageWritingError,
        StatisticsReportMessageWritingError, TerminationMessageWritingError,
    },
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_bgp_pkt::wire::serializer::{
    capabilities::BGPCapabilityWritingError, write_tlv_header_t16_l16, BgpMessageWritingError,
};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use std::{convert::identity, io::Write};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageValueWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteMonitoringMessage(#[from] RouteMonitoringMessageWritingError),
    RouteMirroringMessage(#[from] RouteMirroringMessageWritingError),
    InitiationMessage(#[from] InitiationMessageWritingError),
    PeerUpNotificationMessage(#[from] PeerUpNotificationMessageWritingError),
    PeerDownNotificationMessage(#[from] PeerDownNotificationMessageWritingError),
    PeerDownTlvMessage(#[from] PeerDownTlvWritingError),
    TerminationMessage(#[from] TerminationMessageWritingError),
    StatisticsReportMessage(#[from] StatisticsReportMessageWritingError),
}

impl WritablePdu<BmpMessageValueWritingError> for BmpMessageValue {
    /// 1-octet msg type,
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let len = match self {
            Self::RouteMonitoring(value) => value.len(),
            Self::StatisticsReport(value) => value.len(),
            Self::PeerDownNotification(notif) => notif.len(),
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
pub enum PeerDownNotificationMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeaderError(#[from] PeerHeaderWritingError),
    InitiationInformationError(#[from] InitiationInformationWritingError),
    PeerDownNotificationReasonError(#[from] PeerDownNotificationReasonWritingError),
    PeerDownTlvError(#[from] PeerDownTlvWritingError),
}

impl WritablePdu<PeerDownNotificationMessageWritingError> for PeerDownNotificationMessage {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.peer_header().len()
            + self.reason().len()
            + self.tlvs().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), PeerDownNotificationMessageWritingError> {
        self.peer_header().write(writer)?;
        self.reason().write(writer)?;
        for tlv in self.tlvs() {
            tlv.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum PeerDownTlvWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<PeerDownTlvWritingError> for PeerDownTlv {
    const BASE_LENGTH: usize = 2 + 2; /* type + length */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                PeerDownTlv::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), PeerDownTlvWritingError>
    where
        Self: Sized,
    {
        write_tlv_header_t16_l16(writer, self.code(), self.len() as u16)?;

        match self {
            PeerDownTlv::Unknown { value, .. } => writer.write_all(value)?,
        }

        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    PeerHeader(#[from] PeerHeaderWritingError),
    TlvV4(#[from] RouteMonitoringTlvWritingError),
}

impl WritablePdu<RouteMonitoringMessageWritingError> for RouteMonitoringMessage {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.peer_header().len()
            + self.update_message_tlv().len()
            + self.tlvs().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteMonitoringMessageWritingError> {
        self.peer_header().write(writer)?;
        for tlv in self.tlvs() {
            tlv.write(writer)?;
        }

        self.update_message_tlv().write(writer)?;

        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringTlvWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteMonitoringTlvValueError(#[from] RouteMonitoringTlvValueWritingError),
}

impl WritablePdu<RouteMonitoringTlvWritingError> for RouteMonitoringTlv {
    const BASE_LENGTH: usize = 2 + 2 + 2; /* type + length + index */

    fn len(&self) -> usize {
        let mut x = Self::BASE_LENGTH;
        x += self.value().len();
        x
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteMonitoringTlvWritingError>
    where
        Self: Sized,
    {
        // Length - 2 to exclude the Index field from the TLV Length
        write_tlv_header_t16_l16(
            writer,
            self.get_type().either(|x| x as u16, identity),
            (self.len() - 2) as u16,
        )?;
        writer.write_u16::<NetworkEndian>(self.index())?;
        self.value().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringTlvValueWritingError {
    StdIOError(#[from_std_io_error] String),
    BgpMessageWritingError(#[from] BgpMessageWritingError),
    BgpCapability(#[from] BGPCapabilityWritingError),
}

impl WritablePdu<RouteMonitoringTlvValueWritingError> for RouteMonitoringTlvValue {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        match self {
            RouteMonitoringTlvValue::BgpUpdate(update) => update.len(),
            RouteMonitoringTlvValue::VrfTableName(str) => str.len(),
            RouteMonitoringTlvValue::GroupTlv(values) => 2 * values.len(),
            /* afi + safi + bool */
            RouteMonitoringTlvValue::StatelessParsing(capability) => capability.len(),
            RouteMonitoringTlvValue::Unknown { value, .. } => value.len(),
            RouteMonitoringTlvValue::PathMarking(path_marking) => {
                4 + path_marking.reason_code.map(|_| 2).unwrap_or(0)
            }
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteMonitoringTlvValueWritingError>
    where
        Self: Sized,
    {
        match self {
            RouteMonitoringTlvValue::BgpUpdate(update) => update.write(writer)?,
            RouteMonitoringTlvValue::VrfTableName(str) => writer.write_all(str.as_bytes())?,
            RouteMonitoringTlvValue::GroupTlv(values) => {
                for value in values {
                    writer.write_u16::<NetworkEndian>(*value)?
                }
            }
            RouteMonitoringTlvValue::StatelessParsing(capability) => capability.write(writer)?,
            RouteMonitoringTlvValue::Unknown { value, .. } => writer.write_all(value)?,
            RouteMonitoringTlvValue::PathMarking(path_marking) => {
                writer.write_u32::<NetworkEndian>(path_marking.path_status)?;
                if let Some(reason_code) = path_marking.reason_code {
                    writer.write_u16::<NetworkEndian>(reason_code as u16)?
                }
            }
        }

        Ok(())
    }
}
