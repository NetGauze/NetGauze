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

//! Serializer for BGP Update message

use crate::{
    update::{NetworkLayerReachabilityInformation, WithdrawRoute},
    wire::serializer::{path_attribute::PathAttributeWritingError, round_len},
    BGPUpdateMessage,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BGPUpdateMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    WithdrawRouteError(#[from] WithdrawRouteWritingError),
    NLRIError(#[from] NetworkLayerReachabilityInformationWritingError),
    PathAttributeError(#[from] PathAttributeWritingError),
}

impl WritablePDU<BGPUpdateMessageWritingError> for BGPUpdateMessage {
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        let withdrawn_len = self
            .withdraw_routes()
            .iter()
            .map(|w| w.len())
            .sum::<usize>();
        let path_attrs_len = self
            .path_attributes()
            .iter()
            .map(|w| w.len())
            .sum::<usize>();
        let nlri = self
            .network_layer_reachability_information()
            .iter()
            .map(|w| w.len())
            .sum::<usize>();
        Self::BASE_LENGTH + withdrawn_len + path_attrs_len + nlri
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), BGPUpdateMessageWritingError> {
        let withdrawn_len = self
            .withdraw_routes()
            .iter()
            .map(|w| w.len())
            .sum::<usize>();
        writer.write_u16::<NetworkEndian>(withdrawn_len as u16)?;
        for withdrawn in self.withdraw_routes() {
            withdrawn.write(writer)?;
        }
        let attrs_len = self
            .path_attributes()
            .iter()
            .map(|attr| attr.len())
            .sum::<usize>();
        writer.write_u16::<NetworkEndian>(attrs_len as u16)?;
        for attr in self.path_attributes() {
            attr.write(writer)?;
        }
        for nlri in self.network_layer_reachability_information() {
            nlri.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum WithdrawRouteWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<WithdrawRouteWritingError> for WithdrawRoute {
    /// One octet for prefix length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        // Divide by 8 since we count the octets
        Self::BASE_LENGTH + self.prefix().prefix_len() as usize / 8
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), WithdrawRouteWritingError> {
        writer.write_u8(self.prefix().prefix_len())?;
        for octet in self
            .prefix()
            .network()
            .octets()
            .iter()
            .take(self.prefix().prefix_len() as usize / 8)
        {
            writer.write_u8(*octet)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NetworkLayerReachabilityInformationWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<NetworkLayerReachabilityInformationWritingError>
    for NetworkLayerReachabilityInformation
{
    /// one octet length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        let sum_len: u32 = self
            .networks()
            .iter()
            .map(|x| round_len(x.prefix_len()) as u32)
            .sum();
        1 + sum_len as usize
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), NetworkLayerReachabilityInformationWritingError> {
        for network in self.networks() {
            let len = round_len(network.prefix_len());
            writer.write_u8(network.prefix_len())?;
            writer.write_all(&network.network().octets()[..len as usize])?;
        }
        Ok(())
    }
}
