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
    capabilities::{
        AddPathCapability, AddPathCapabilityAddressFamily, BGPCapability, ExtendedNextHopEncoding,
        ExtendedNextHopEncodingCapability, FourOctetASCapability,
        MultiProtocolExtensionsCapability, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH,
        EXTENDED_MESSAGE_CAPABILITY_LENGTH, EXTENDED_NEXT_HOP_ENCODING_LENGTH,
        FOUR_OCTET_AS_CAPABILITY_LENGTH, MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH,
        ROUTE_REFRESH_CAPABILITY_LENGTH,
    },
    iana::BGPCapabilityCode,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BGPCapabilityWritingError {
    StdIOError(#[from_std_io_error] String),
    FourOctetASCapabilityError(#[from] FourOctetASCapabilityWritingError),
    MultiProtocolExtensionsCapabilityError(#[from] MultiProtocolExtensionsCapabilityWritingError),
    AddPathCapabilityError(#[from] AddPathCapabilityWritingError),
    ExtendedNextHopEncodingCapabilityError(#[from] ExtendedNextHopEncodingCapabilityWritingError),
}

impl WritablePDU<BGPCapabilityWritingError> for BGPCapability {
    // 1-octet length and 1-octet capability type
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        let value_len = match self {
            Self::MultiProtocolExtensions(_) => {
                MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH as usize
            }
            Self::RouteRefresh => ROUTE_REFRESH_CAPABILITY_LENGTH as usize,
            Self::EnhancedRouteRefresh => ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH as usize,
            Self::FourOctetAS(value) => value.len(),
            Self::AddPath(value) => value.len(),
            // ExtendedNextHopEncoding carries an length field, so need to account for it here
            Self::ExtendedNextHopEncoding(value) => value.len() - 1,
            Self::ExtendedMessage => EXTENDED_MESSAGE_CAPABILITY_LENGTH as usize,
            Self::Experimental(value) => value.value().len(),
            Self::Unrecognized(value) => value.value().len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BGPCapabilityWritingError> {
        let len = (self.len() - Self::BASE_LENGTH) as u8;
        match self {
            Self::MultiProtocolExtensions(value) => {
                writer.write_u8(BGPCapabilityCode::MultiProtocolExtensions.into())?;
                writer.write_u8(value.len() as u8)?;
                value.write(writer)?;
            }
            Self::RouteRefresh => {
                writer.write_u8(BGPCapabilityCode::RouteRefreshCapability.into())?;
                writer.write_u8(len)?;
            }
            Self::EnhancedRouteRefresh => {
                writer.write_u8(BGPCapabilityCode::EnhancedRouteRefresh.into())?;
                writer.write_u8(len)?;
            }
            Self::ExtendedMessage => {
                writer.write_u8(BGPCapabilityCode::BGPExtendedMessage.into())?;
                writer.write_u8(len)?;
            }
            Self::AddPath(value) => {
                writer.write_u8(BGPCapabilityCode::ADDPathCapability.into())?;
                writer.write_u8(len)?;
                value.write(writer)?;
            }
            Self::FourOctetAS(value) => {
                writer.write_u8(BGPCapabilityCode::FourOctetAS.into())?;
                writer.write_u8(value.len() as u8)?;
                value.write(writer)?;
            }
            Self::ExtendedNextHopEncoding(value) => {
                writer.write_u8(BGPCapabilityCode::ExtendedNextHopEncoding.into())?;
                value.write(writer)?;
            }
            Self::Experimental(value) => {
                writer.write_u8(value.code() as u8)?;
                writer.write_u8(len)?;
                writer.write_all(value.value())?;
            }
            Self::Unrecognized(value) => {
                writer.write_u8(*value.code())?;
                writer.write_u8(len)?;
                writer.write_all(value.value())?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FourOctetASCapabilityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<FourOctetASCapabilityWritingError> for FourOctetASCapability {
    const BASE_LENGTH: usize = FOUR_OCTET_AS_CAPABILITY_LENGTH as usize;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), FourOctetASCapabilityWritingError> {
        writer.write_u32::<NetworkEndian>(self.asn4())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MultiProtocolExtensionsCapabilityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<MultiProtocolExtensionsCapabilityWritingError>
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
        writer.write_u16::<NetworkEndian>(self.address_type().address_family().into())?;
        writer.write_u8(0)?;
        writer.write_u8(self.address_type().subsequent_address_family().into())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum AddPathCapabilityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<AddPathCapabilityWritingError> for AddPathCapability {
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

impl WritablePDU<AddPathCapabilityWritingError> for AddPathCapabilityAddressFamily {
    // 2 octet AFI, 1 reserved, and 1 SAFI
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(&self, writer: &mut T) -> Result<(), AddPathCapabilityWritingError> {
        writer.write_u16::<NetworkEndian>(self.address_type().address_family().into())?;
        writer.write_u8(self.address_type().subsequent_address_family().into())?;
        // Flip second bit if send is enabled
        let send = u8::from(self.send()) * 2;
        // Flip first bit if send is enabled
        let receive = u8::from(self.receive());
        writer.write_u8(send | receive)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ExtendedNextHopEncodingCapabilityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<ExtendedNextHopEncodingCapabilityWritingError> for ExtendedNextHopEncoding {
    const BASE_LENGTH: usize = EXTENDED_NEXT_HOP_ENCODING_LENGTH as usize;
    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }
    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExtendedNextHopEncodingCapabilityWritingError> {
        writer.write_u16::<NetworkEndian>(self.address_type().address_family().into())?;
        writer.write_u16::<NetworkEndian>(self.address_type().subsequent_address_family() as u16)?;
        writer.write_u16::<NetworkEndian>(self.next_hop_afi().into())?;
        Ok(())
    }
}

impl WritablePDU<ExtendedNextHopEncodingCapabilityWritingError>
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
        writer.write_u8(self.len() as u8 - 1)?;
        for encoding in self.encodings() {
            encoding.write(writer)?;
        }
        Ok(())
    }
}
