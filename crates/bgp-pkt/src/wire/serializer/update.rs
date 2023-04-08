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
    wire::serializer::{
        nlri::Ipv4UnicastAddressWritingError, path_attribute::PathAttributeWritingError,
    },
    BgpUpdateMessage,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpUpdateMessageWritingError {
    StdIOError(#[from_std_io_error] String),
    Ipv4UnicastAddressError(#[from] Ipv4UnicastAddressWritingError),
    PathAttributeError(#[from] PathAttributeWritingError),
}

impl WritablePdu<BgpUpdateMessageWritingError> for BgpUpdateMessage {
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
            .map(|x| x.len())
            .sum::<usize>();
        Self::BASE_LENGTH + withdrawn_len + path_attrs_len + nlri
    }

    fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<(), BgpUpdateMessageWritingError> {
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
        for address in self.network_layer_reachability_information() {
            address.write(writer)?;
        }
        Ok(())
    }
}
