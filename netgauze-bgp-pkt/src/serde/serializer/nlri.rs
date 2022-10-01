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
    nlri::{Ipv4Multicast, Ipv4Unicast, Ipv6Multicast, Ipv6Unicast},
    serde::serializer::round_len,
};
use byteorder::WriteBytesExt;
use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv6UnicastWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<Ipv6UnicastWritingError> for Ipv6Unicast {
    // 1-octet for the prefix length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + round_len(self.address().prefix_len()) as usize
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv6UnicastWritingError> {
        let len = self.len() - Self::BASE_LENGTH;
        writer.write_u8(self.address().prefix_len())?;
        writer.write_all(&self.address().network().octets()[..len])?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv6MulticastWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<Ipv6MulticastWritingError> for Ipv6Multicast {
    // 1-octet for the prefix length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + round_len(self.address().prefix_len()) as usize
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv6MulticastWritingError> {
        let len = self.len() - Self::BASE_LENGTH;
        writer.write_u8(self.address().prefix_len())?;
        writer.write_all(&self.address().network().octets()[..len])?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4UnicastWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<Ipv4UnicastWritingError> for Ipv4Unicast {
    // 1-octet for the prefix length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + round_len(self.address().prefix_len()) as usize
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv4UnicastWritingError> {
        let len = self.len() - Self::BASE_LENGTH;
        writer.write_u8(self.address().prefix_len())?;
        writer.write_all(&self.address().network().octets()[..len])?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4MulticastWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<Ipv4MulticastWritingError> for Ipv4Multicast {
    // 1-octet for the prefix length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + round_len(self.address().prefix_len()) as usize
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv4MulticastWritingError> {
        let len = self.len() - Self::BASE_LENGTH;
        writer.write_u8(self.address().prefix_len())?;
        writer.write_all(&self.address().network().octets()[..len])?;
        Ok(())
    }
}
