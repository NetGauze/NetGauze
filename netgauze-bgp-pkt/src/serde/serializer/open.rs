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

use std::io::Write;

use byteorder::{NetworkEndian, WriteBytesExt};

use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;

use crate::{
    capabilities::BGPCapability, iana::BGPOpenMessageParameterType, open::BGPOpenMessageParameter,
    serde::serializer::capabilities::BGPCapabilityWritingError, BGPOpenMessage,
};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BGPOpenMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    CapabilityError(#[from] BGPCapabilityWritingError),
}

impl WritablePDU<BGPOpenMessageWritingError> for BGPOpenMessage {
    /// Base length is 10 = 1 (bgp ver) + 2 (my as) + 2 (hold time) + 4 (bgp-id)
    /// + 1 (params len)
    const BASE_LENGTH: usize = 10;
    fn len(&self) -> usize {
        let params_length: usize = self.params().iter().map(BGPOpenMessageParameter::len).sum();
        Self::BASE_LENGTH + params_length
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BGPOpenMessageWritingError> {
        writer.write_u8(self.version())?;
        writer.write_u16::<NetworkEndian>(self.my_as())?;
        writer.write_u16::<NetworkEndian>(self.hold_time())?;
        writer.write_u32::<NetworkEndian>(self.bgp_id().into())?;
        let params_length: usize = self.params().iter().map(BGPOpenMessageParameter::len).sum();
        writer.write_u8(params_length as u8)?;
        for param in self.params().iter() {
            param.write(writer)?;
        }
        Ok(())
    }
}

impl WritablePDU<BGPOpenMessageWritingError> for BGPOpenMessageParameter {
    /// 1 octet for the length value and a second for the parameter type
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        match self {
            BGPOpenMessageParameter::Capabilities(capabilities) => {
                let capability_len: usize = capabilities.iter().map(BGPCapability::len).sum();
                Self::BASE_LENGTH + capability_len
            }
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BGPOpenMessageWritingError> {
        let length = self.len() - 2;
        match self {
            BGPOpenMessageParameter::Capabilities(capabilities) => {
                writer.write_u8(BGPOpenMessageParameterType::Capability.into())?;
                writer.write_u8(length as u8)?;
                for capability in capabilities.iter() {
                    capability.write(writer)?;
                }
                Ok(())
            }
        }
    }
}
