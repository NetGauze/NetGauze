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
        BGPCapability, ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH,
        MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH, ROUTE_REFRESH_CAPABILITY_LENGTH,
    },
    iana::BGPCapabilityCode,
    serde::serializer::open::BGPOpenMessageWritingError,
};
use byteorder::WriteBytesExt;
use netgauze_parse_utils::WritablePDU;
use std::io::Write;

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPCapabilityWritingError {
    StdIOError(String),
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
            Self::Unrecognized(value) => {
                writer.write_u8(*value.code())?;
                writer.write_u8(len)?;
                writer.write_all(value.value())?;
            }
        }
        Ok(())
    }
}
