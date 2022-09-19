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
        BGPCapability, FourOctetASCapability, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH,
        EXTENDED_MESSAGE_CAPABILITY_LENGTH, FOUR_OCTET_AS_CAPABILITY_LENGTH,
        MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH, ROUTE_REFRESH_CAPABILITY_LENGTH,
    },
    iana::BGPCapabilityCode,
    serde::serializer::open::BGPOpenMessageWritingError,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePDU;
use std::io::Write;

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPCapabilityWritingError {
    StdIOError(String),
    FourOctetASCapabilityError(FourOctetASCapabilityWritingError),
}

impl From<std::io::Error> for BGPCapabilityWritingError {
    fn from(err: std::io::Error) -> Self {
        BGPCapabilityWritingError::StdIOError(err.to_string())
    }
}

impl From<BGPCapabilityWritingError> for BGPOpenMessageWritingError {
    fn from(value: BGPCapabilityWritingError) -> Self {
        BGPOpenMessageWritingError::CapabilityError(value)
    }
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
            Self::ExtendedMessage => EXTENDED_MESSAGE_CAPABILITY_LENGTH as usize,
            Self::FourOctetAS(value) => value.len(),
            Self::Experimental(value) => value.value().len(),
            Self::Unrecognized(value) => value.value().len(),
        };
        Self::BASE_LENGTH + value_len
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BGPCapabilityWritingError> {
        let len = (self.len() - Self::BASE_LENGTH) as u8;
        match self {
            Self::MultiProtocolExtensions(_) => todo!(),
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
            Self::FourOctetAS(value) => {
                writer.write_u8(BGPCapabilityCode::FourOctetAS.into())?;
                writer.write_u8(value.len() as u8)?;
                writer.write_u32::<NetworkEndian>(value.asn4())?;
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

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum FourOctetASCapabilityWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for FourOctetASCapabilityWritingError {
    fn from(err: std::io::Error) -> Self {
        FourOctetASCapabilityWritingError::StdIOError(err.to_string())
    }
}

impl From<FourOctetASCapabilityWritingError> for BGPCapabilityWritingError {
    fn from(value: FourOctetASCapabilityWritingError) -> Self {
        BGPCapabilityWritingError::FourOctetASCapabilityError(value)
    }
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
