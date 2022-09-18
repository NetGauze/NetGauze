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

//! Serializer for BGP Route Refresh message

use crate::{serde::serializer::BGPMessageWritingError, BGPRouteRefreshMessage};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePDU;

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPRouteRefreshMessageWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for BGPRouteRefreshMessageWritingError {
    fn from(err: std::io::Error) -> Self {
        BGPRouteRefreshMessageWritingError::StdIOError(err.to_string())
    }
}

impl From<BGPRouteRefreshMessageWritingError> for BGPMessageWritingError {
    fn from(value: BGPRouteRefreshMessageWritingError) -> Self {
        BGPMessageWritingError::RouteRefreshError(value)
    }
}

impl WritablePDU<BGPRouteRefreshMessageWritingError> for BGPRouteRefreshMessage {
    // 4 octet = 2 afi + 1 op + + 1 safi
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), BGPRouteRefreshMessageWritingError> {
        writer.write_u16::<NetworkEndian>(self.address_type().address_family().into())?;
        writer.write_u8(self.operation_type().into())?;
        writer.write_u8(self.address_type().subsequent_address_family().into())?;
        Ok(())
    }
}
