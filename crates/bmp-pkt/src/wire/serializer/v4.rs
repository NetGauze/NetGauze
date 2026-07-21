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

use crate::v4::{
    BmpMessageValue, PeerDownNotificationMessage, PeerDownTlv, RouteMonitoringMessage,
    RouteMonitoringTlv, RouteMonitoringTlvValue,
};
use crate::wire::serializer::v3::{
    InitiationInformationWritingError, InitiationMessageWritingError,
    PeerDownNotificationReasonWritingError, PeerHeaderWritingError,
    PeerUpNotificationMessageWritingError, RouteMirroringMessageWritingError,
    StatisticsReportMessageWritingError, TerminationMessageWritingError,
};
use netgauze_bgp_pkt::wire::serializer::capabilities::BGPCapabilityWritingError;
use netgauze_bgp_pkt::wire::serializer::{BgpMessageWritingError, write_tlv_header_t16_l16};
use netgauze_parse_utils::{WritablePdu, impl_from_io_error};
use std::convert::identity;
use std::io::Write;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageValueWritingError {
    #[error("IO error while writing BMP message: {0}")]
    StdIOError(Box<str>),

    #[error("in route monitoring message: {0}")]
    RouteMonitoringMessage(#[from] RouteMonitoringMessageWritingError),

    #[error("in route mirroring message: {0}")]
    RouteMirroringMessage(#[from] RouteMirroringMessageWritingError),

    #[error("in initiation message: {0}")]
    InitiationMessage(#[from] InitiationMessageWritingError),

    #[error("in peer up notification message: {0}")]
    PeerUpNotificationMessage(#[from] PeerUpNotificationMessageWritingError),

    #[error("in peer down notification message: {0}")]
    PeerDownNotificationMessage(#[from] PeerDownNotificationMessageWritingError),

    #[error("in peer down TLV message: {0}")]
    PeerDownTlvMessage(#[from] PeerDownTlvWritingError),

    #[error("in termination message: {0}")]
    TerminationMessage(#[from] TerminationMessageWritingError),

    #[error("in statistics report message: {0}")]
    StatisticsReportMessage(#[from] StatisticsReportMessageWritingError),
}
impl_from_io_error!(BmpMessageValueWritingError);

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
        writer.write_all(&[self.get_type().into()])?;
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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum PeerDownNotificationMessageWritingError {
    #[error("IO error while writing peer down notification message: {0}")]
    StdIOError(Box<str>),

    #[error("in peer header: {0}")]
    PeerHeaderError(#[from] PeerHeaderWritingError),

    #[error("in initiation information: {0}")]
    InitiationInformationError(#[from] InitiationInformationWritingError),

    #[error("in peer down notification reason: {0}")]
    PeerDownNotificationReasonError(#[from] PeerDownNotificationReasonWritingError),

    #[error("in peer down TLV: {0}")]
    PeerDownTlvError(#[from] PeerDownTlvWritingError),
}
impl_from_io_error!(PeerDownNotificationMessageWritingError);

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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum PeerDownTlvWritingError {
    #[error("IO error while writing peer down TLV: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(PeerDownTlvWritingError);

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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringMessageWritingError {
    #[error("IO error while writing route monitoring message: {0}")]
    StdIOError(Box<str>),

    #[error("in peer header: {0}")]
    PeerHeader(#[from] PeerHeaderWritingError),

    #[error("in TLV v4: {0}")]
    TlvV4(#[from] RouteMonitoringTlvWritingError),
}
impl_from_io_error!(RouteMonitoringMessageWritingError);

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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringTlvWritingError {
    #[error("IO error while writing route monitoring TLV: {0}")]
    StdIOError(Box<str>),

    #[error("in route monitoring TLV value: {0}")]
    RouteMonitoringTlvValueError(#[from] RouteMonitoringTlvValueWritingError),
}
impl_from_io_error!(RouteMonitoringTlvWritingError);

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
        writer.write_all(&self.index().to_be_bytes())?;
        self.value().write(writer)?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringTlvValueWritingError {
    #[error("IO error while writing route monitoring TLV value: {0}")]
    StdIOError(Box<str>),

    #[error("in BGP message: {0}")]
    BgpMessageWritingError(#[from] BgpMessageWritingError),

    #[error("in BGP capability: {0}")]
    BgpCapability(#[from] BGPCapabilityWritingError),
}
impl_from_io_error!(RouteMonitoringTlvValueWritingError);

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
                4 + path_marking.reason_code().map(|_| 2).unwrap_or(0)
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
                    writer.write_all(&(*value).to_be_bytes())?
                }
            }
            RouteMonitoringTlvValue::StatelessParsing(capability) => capability.write(writer)?,
            RouteMonitoringTlvValue::Unknown { value, .. } => writer.write_all(value)?,
            RouteMonitoringTlvValue::PathMarking(path_marking) => {
                writer.write_all(&(*path_marking.path_status()).bits().to_be_bytes())?;
                if let Some(reason_code) = path_marking.reason_code() {
                    writer.write_all(&reason_code.to_be_bytes())?
                }
            }
        }

        Ok(())
    }
}
