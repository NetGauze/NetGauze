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
    nlri::{
        Ipv4MplsVpnUnicast, Ipv4Multicast, Ipv4Unicast, Ipv6MplsVpnUnicast, Ipv6Multicast,
        Ipv6Unicast, LabeledIpv4NextHop, LabeledIpv6NextHop, LabeledNextHop, MplsLabel,
        RouteDistinguisher,
    },
    wire::serializer::round_len,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use std::{convert::Into, io::Write};

/// Length for Route Distinguisher
pub(crate) const RD_LEN: u8 = 8;
pub(crate) const IPV4_LEN: u8 = 4;
pub(crate) const LABELED_IPV4_LEN: u8 = RD_LEN + IPV4_LEN;
pub(crate) const IPV6_LEN: u8 = 16;
pub(crate) const LABELED_IPV6_LEN: u8 = RD_LEN + IPV6_LEN;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteDistinguisherWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<RouteDistinguisherWritingError> for RouteDistinguisher {
    const BASE_LENGTH: usize = RD_LEN as usize;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteDistinguisherWritingError> {
        writer.write_u16::<NetworkEndian>(self.get_type().into())?;
        match self {
            RouteDistinguisher::As2Administrator { asn2, number } => {
                writer.write_u16::<NetworkEndian>(*asn2)?;
                writer.write_u32::<NetworkEndian>(*number)?;
            }
            RouteDistinguisher::Ipv4Administrator { ip, number } => {
                writer.write_all(&ip.octets())?;
                writer.write_u16::<NetworkEndian>(*number)?;
            }
            RouteDistinguisher::As4Administrator { asn4, number } => {
                writer.write_u32::<NetworkEndian>(*asn4)?;
                writer.write_u16::<NetworkEndian>(*number)?;
            }
            RouteDistinguisher::LeafAdRoutes => {
                writer.write_u16::<NetworkEndian>(u16::MAX)?;
                writer.write_u32::<NetworkEndian>(u32::MAX)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MplsLabelWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<MplsLabelWritingError> for MplsLabel {
    // We don't include the TTL here
    const BASE_LENGTH: usize = 3;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), MplsLabelWritingError> {
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum LabeledIpv4NextHopWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
}

impl WritablePdu<LabeledIpv4NextHopWritingError> for LabeledIpv4NextHop {
    const BASE_LENGTH: usize = LABELED_IPV4_LEN as usize;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), LabeledIpv4NextHopWritingError> {
        self.rd().write(writer)?;
        writer.write_all(&self.next_hop().octets())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum LabeledIpv6NextHopWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
}

impl WritablePdu<LabeledIpv6NextHopWritingError> for LabeledIpv6NextHop {
    const BASE_LENGTH: usize = LABELED_IPV6_LEN as usize;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), LabeledIpv6NextHopWritingError> {
        self.rd().write(writer)?;
        writer.write_all(&self.next_hop().octets())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum LabeledNextHopWritingError {
    StdIOError(#[from_std_io_error] String),
    LabeledIpv4NextHopError(#[from] LabeledIpv4NextHopWritingError),
    LabeledIpv6NextHopError(#[from] LabeledIpv6NextHopWritingError),
}

impl WritablePdu<LabeledNextHopWritingError> for LabeledNextHop {
    // 1-octet for length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::Ipv4(value) => value.len(),
                Self::Ipv6(value) => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), LabeledNextHopWritingError> {
        writer.write_u8((self.len() - Self::BASE_LENGTH) as u8)?;
        match self {
            Self::Ipv4(value) => value.write(writer)?,
            Self::Ipv6(value) => value.write(writer)?,
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv6UnicastWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<Ipv6UnicastWritingError> for Ipv6Unicast {
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

impl WritablePdu<Ipv6MulticastWritingError> for Ipv6Multicast {
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
pub enum Ipv6MplsVpnUnicastWritingError {
    StdIOError(#[from_std_io_error] String),
    MplsLabelError(#[from] MplsLabelWritingError),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    Ipv6UnicastError(#[from] Ipv6UnicastWritingError),
}

impl WritablePdu<Ipv6MplsVpnUnicastWritingError> for Ipv6MplsVpnUnicast {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.rd().len()
            + self.network().len()
            + self.label_stack().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv6MplsVpnUnicastWritingError> {
        let prefix_len = self.rd().len() * 8
            + self.label_stack().len() * 3 * 8
            + self.network().address().prefix_len() as usize;
        writer.write_u8(prefix_len as u8)?;
        for label in self.label_stack() {
            label.write(writer)?;
        }
        self.rd().write(writer)?;
        let network_octets = &self.network().address().network().octets();
        let prefix_len = self.network().len() - 1;
        writer.write_all(&network_octets[0..prefix_len])?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4UnicastWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<Ipv4UnicastWritingError> for Ipv4Unicast {
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

impl WritablePdu<Ipv4MulticastWritingError> for Ipv4Multicast {
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

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4MplsVpnUnicastWritingError {
    StdIOError(#[from_std_io_error] String),
    MplsLabelError(#[from] MplsLabelWritingError),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    Ipv4UnicastError(#[from] Ipv4UnicastWritingError),
}

impl WritablePdu<Ipv4MplsVpnUnicastWritingError> for Ipv4MplsVpnUnicast {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.rd().len()
            + self.network().len()
            + self.label_stack().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv4MplsVpnUnicastWritingError> {
        let prefix_len = self.rd().len() * 8
            + self.label_stack().len() * 3 * 8
            + self.network().address().prefix_len() as usize;
        writer.write_u8(prefix_len as u8)?;
        for label in self.label_stack() {
            label.write(writer)?;
        }
        self.rd().write(writer)?;
        let network_octets = &self.network().address().network().octets();
        let prefix_len = self.network().len() - 1;
        writer.write_all(&network_octets[0..prefix_len])?;
        Ok(())
    }
}
