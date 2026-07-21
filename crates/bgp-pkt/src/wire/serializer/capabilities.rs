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

use crate::capabilities::*;
use crate::wire::{
    BGP_ROLE_CAPABILITY_LENGTH, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH,
    EXTENDED_MESSAGE_CAPABILITY_LENGTH, EXTENDED_NEXT_HOP_ENCODING_LENGTH,
    FOUR_OCTET_AS_CAPABILITY_LENGTH, MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH,
    ROUTE_REFRESH_CAPABILITY_LENGTH,
};
use netgauze_parse_utils::{WritablePdu, impl_from_io_error};
use std::io::Write;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum BGPCapabilityWritingError {
    #[error("IO error while writing b g p capability: {0}")]
    StdIOError(Box<str>),

    #[error("in four-octet AS capability: {0}")]
    FourOctetAsCapabilityError(#[from] FourOctetAsCapabilityWritingError),

    #[error("in multi protocol extensions capability: {0}")]
    MultiProtocolExtensionsCapabilityError(#[from] MultiProtocolExtensionsCapabilityWritingError),

    #[error("in graceful restart capability: {0}")]
    GracefulRestartCapabilityError(#[from] GracefulRestartCapabilityWritingError),

    #[error("in add path capability: {0}")]
    AddPathCapabilityError(#[from] AddPathCapabilityWritingError),

    #[error("in extended next hop encoding capability: {0}")]
    ExtendedNextHopEncodingCapabilityError(#[from] ExtendedNextHopEncodingCapabilityWritingError),

    #[error("in multiple label: {0}")]
    MultipleLabelError(#[from] MultipleLabelWritingError),

    #[error("in BGP role capability: {0}")]
    BgpRoleCapabilityError(#[from] BgpRoleCapabilityWritingError),
}
impl_from_io_error!(BGPCapabilityWritingError);

impl WritablePdu<BGPCapabilityWritingError> for BgpCapability {
    // 1-octet length and 1-octet capability type
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::MultiProtocolExtensions(_) => {
                MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH as usize
            }
            Self::RouteRefresh => ROUTE_REFRESH_CAPABILITY_LENGTH as usize,
            Self::EnhancedRouteRefresh => ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH as usize,
            Self::CiscoRouteRefresh => ROUTE_REFRESH_CAPABILITY_LENGTH as usize,
            Self::FourOctetAs(value) => value.len(),
            // GracefulRestartCapability carries n length field, so need to account for it here
            Self::GracefulRestartCapability(value) => value.len() - 2,
            Self::AddPath(value) => value.len(),
            // ExtendedNextHopEncoding carries n length field, so need to account for it here
            Self::ExtendedNextHopEncoding(value) => value.len() - 1,
            Self::ExtendedMessage => EXTENDED_MESSAGE_CAPABILITY_LENGTH as usize,
            Self::MultipleLabels(value) => value.iter().map(|x| x.len()).sum(),
            Self::BgpRole(value) => value.len(),
            Self::Experimental(value) => value.value().len(),
            Self::Unrecognized(value) => value.value().len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BGPCapabilityWritingError> {
        let len = (self.len() - Self::BASE_LENGTH) as u8;
        match self {
            Self::MultiProtocolExtensions(value) => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[value.len() as u8])?;
                value.write(writer)?;
            }
            Self::RouteRefresh => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[len])?;
            }
            Self::EnhancedRouteRefresh => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[len])?;
            }
            Self::CiscoRouteRefresh => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[len])?;
            }
            Self::ExtendedMessage => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[len])?;
            }
            Self::MultipleLabels(value) => {
                writer.write_all(&[self.code().unwrap().into()])?;
                for addr in value {
                    addr.write(writer)?;
                }
            }
            Self::BgpRole(value) => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[len])?;
                value.write(writer)?;
            }
            Self::GracefulRestartCapability(value) => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[len])?;
                value.write(writer)?;
            }
            Self::AddPath(value) => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[len])?;
                value.write(writer)?;
            }
            Self::FourOctetAs(value) => {
                writer.write_all(&[self.code().unwrap().into()])?;
                writer.write_all(&[value.len() as u8])?;
                value.write(writer)?;
            }
            Self::ExtendedNextHopEncoding(value) => {
                writer.write_all(&[self.code().unwrap().into()])?;
                value.write(writer)?;
            }
            Self::Experimental(value) => {
                writer.write_all(&[value.code() as u8])?;
                writer.write_all(&[len])?;
                writer.write_all(value.value())?;
            }
            Self::Unrecognized(value) => {
                writer.write_all(&[*value.code()])?;
                writer.write_all(&[len])?;
                writer.write_all(value.value())?;
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum FourOctetAsCapabilityWritingError {
    #[error("IO error while writing four-octet AS capability: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(FourOctetAsCapabilityWritingError);

impl WritablePdu<FourOctetAsCapabilityWritingError> for FourOctetAsCapability {
    const BASE_LENGTH: usize = FOUR_OCTET_AS_CAPABILITY_LENGTH as usize;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), FourOctetAsCapabilityWritingError> {
        writer.write_all(&self.asn4().to_be_bytes())?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum MultiProtocolExtensionsCapabilityWritingError {
    #[error("IO error while writing multi protocol extensions capability: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(MultiProtocolExtensionsCapabilityWritingError);

impl WritablePdu<MultiProtocolExtensionsCapabilityWritingError>
    for MultiProtocolExtensionsCapability
{
    const BASE_LENGTH: usize = MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH as usize;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), MultiProtocolExtensionsCapabilityWritingError> {
        writer.write_all(&u16::from(self.address_type().address_family()).to_be_bytes())?;
        writer.write_all(&[0])?;
        writer.write_all(&[self.address_type().subsequent_address_family().into()])?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum GracefulRestartCapabilityWritingError {
    #[error("IO error while writing graceful restart capability: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(GracefulRestartCapabilityWritingError);

impl WritablePdu<GracefulRestartCapabilityWritingError> for GracefulRestartCapability {
    /// 4-octet time and flags
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self
                .address_families()
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), GracefulRestartCapabilityWritingError> {
        let mut flags: u16 = 0;
        flags |= if self.restart() { 0x8000 } else { 0x0000 };
        flags |= if self.graceful_notification() {
            0x4000
        } else {
            0x0000
        };
        flags |= self.time();
        writer.write_all(&flags.to_be_bytes())?;
        for value in self.address_families() {
            value.write(writer)?;
        }
        Ok(())
    }
}

impl WritablePdu<GracefulRestartCapabilityWritingError> for GracefulRestartAddressFamily {
    // 2 octet AFI, 1 reserved, and 1 SAFI
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), GracefulRestartCapabilityWritingError> {
        writer.write_all(&u16::from(self.address_type().address_family()).to_be_bytes())?;
        writer.write_all(&[self.address_type().subsequent_address_family().into()])?;
        writer.write_all(&[if self.forwarding_state() { 0x80 } else { 0x00 }])?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum AddPathCapabilityWritingError {
    #[error("IO error while writing add path capability: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(AddPathCapabilityWritingError);

impl WritablePdu<AddPathCapabilityWritingError> for AddPathCapability {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self
                .address_families()
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), AddPathCapabilityWritingError> {
        for value in self.address_families() {
            value.write(writer)?;
        }
        Ok(())
    }
}

impl WritablePdu<AddPathCapabilityWritingError> for AddPathAddressFamily {
    // 2 octet AFI, 1 reserved, and 1 SAFI
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), AddPathCapabilityWritingError> {
        writer.write_all(&u16::from(self.address_type().address_family()).to_be_bytes())?;
        writer.write_all(&[self.address_type().subsequent_address_family().into()])?;
        // Flip second bit if send is enabled
        let send = u8::from(self.send()) * 2;
        // Flip first bit if send is enabled
        let receive = u8::from(self.receive());
        writer.write_all(&[send | receive])?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum ExtendedNextHopEncodingCapabilityWritingError {
    #[error("IO error while writing extended next hop encoding capability: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(ExtendedNextHopEncodingCapabilityWritingError);

impl WritablePdu<ExtendedNextHopEncodingCapabilityWritingError> for ExtendedNextHopEncoding {
    const BASE_LENGTH: usize = EXTENDED_NEXT_HOP_ENCODING_LENGTH as usize;
    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExtendedNextHopEncodingCapabilityWritingError> {
        writer.write_all(&u16::from(self.address_type().address_family()).to_be_bytes())?;
        writer
            .write_all(&(self.address_type().subsequent_address_family() as u16).to_be_bytes())?;
        writer.write_all(&u16::from(self.next_hop_afi()).to_be_bytes())?;
        Ok(())
    }
}

impl WritablePdu<ExtendedNextHopEncodingCapabilityWritingError>
    for ExtendedNextHopEncodingCapability
{
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.encodings().iter().map(|x| x.len()).sum::<usize>()
    }
    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExtendedNextHopEncodingCapabilityWritingError> {
        writer.write_all(&[self.len() as u8 - 1])?;
        for encoding in self.encodings() {
            encoding.write(writer)?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum MultipleLabelWritingError {
    #[error("IO error while writing multiple label: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(MultipleLabelWritingError);

impl WritablePdu<MultipleLabelWritingError> for MultipleLabel {
    // 2 octets afi  + 1 octet safi + 1 octet count
    const BASE_LENGTH: usize = 4;
    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), MultipleLabelWritingError> {
        writer.write_all(&u16::from(self.address_type().address_family()).to_be_bytes())?;
        writer.write_all(&[self.address_type().subsequent_address_family().into()])?;
        writer.write_all(&[self.count()])?;
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum BgpRoleCapabilityWritingError {
    #[error("IO error while writing BGP role capability: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(BgpRoleCapabilityWritingError);

impl WritablePdu<BgpRoleCapabilityWritingError> for BgpRoleCapability {
    // 1 octet as defined by RFC9234
    const BASE_LENGTH: usize = BGP_ROLE_CAPABILITY_LENGTH as usize;
    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpRoleCapabilityWritingError> {
        writer.write_all(&[self.role().into()])?;
        Ok(())
    }
}
