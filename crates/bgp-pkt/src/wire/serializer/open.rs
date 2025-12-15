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

use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;

use crate::BgpOpenMessage;
use crate::capabilities::BgpCapability;
use crate::iana::BgpOpenMessageParameterType;
use crate::open::BgpOpenMessageParameter;
use crate::wire::serializer::capabilities::BGPCapabilityWritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpOpenMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    CapabilityError(#[from] BGPCapabilityWritingError),
}

impl WritablePdu<BgpOpenMessageWritingError> for BgpOpenMessage {
    /// Base length is 10 = 1 (bgp ver) + 2 (my as) + 2 (hold time) + 4 (bgp-id)
    /// + 1 (params len)
    const BASE_LENGTH: usize = 10;
    fn len(&self) -> usize {
        let params_length: usize = self.params().iter().map(BgpOpenMessageParameter::len).sum();
        Self::BASE_LENGTH + params_length
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpOpenMessageWritingError> {
        writer.write_u8(self.version())?;
        writer.write_u16::<NetworkEndian>(self.my_as())?;
        writer.write_u16::<NetworkEndian>(self.hold_time())?;
        writer.write_u32::<NetworkEndian>(self.bgp_id().into())?;
        let params_length: usize = self.params().iter().map(BgpOpenMessageParameter::len).sum();
        writer.write_u8(params_length as u8)?;
        for param in self.params() {
            param.write(writer)?;
        }
        Ok(())
    }
}

impl WritablePdu<BgpOpenMessageWritingError> for BgpOpenMessageParameter {
    /// 1 octet for the length value and a second for the parameter type
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        match self {
            BgpOpenMessageParameter::Capabilities(capabilities) => {
                let capability_len: usize = capabilities.iter().map(BgpCapability::len).sum();
                Self::BASE_LENGTH + capability_len
            }
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpOpenMessageWritingError> {
        let length = self.len() - 2;
        match self {
            BgpOpenMessageParameter::Capabilities(capabilities) => {
                writer.write_u8(BgpOpenMessageParameterType::Capability.into())?;
                writer.write_u8(length as u8)?;
                for capability in capabilities {
                    capability.write(writer)?;
                }
                Ok(())
            }
        }
    }
}
