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

use crate::{nlri::*, wire::serializer::round_len};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use std::{io::Write, net::IpAddr};

/// Length for Route Distinguisher
pub(crate) const RD_LEN: u8 = 8;
pub(crate) const IPV4_LEN: u8 = 4;
pub(crate) const IPV4_LEN_BITS: u8 = 32;
pub(crate) const LABELED_IPV4_LEN: u8 = RD_LEN + IPV4_LEN;
pub(crate) const IPV6_LEN: u8 = 16;
pub(crate) const IPV6_LEN_BITS: u8 = 128;
pub(crate) const LABELED_IPV6_LEN: u8 = RD_LEN + IPV6_LEN;
pub(crate) const MPLS_LABEL_LEN_BITS: u8 = 24;
pub(crate) const MAC_ADDRESS_LEN_BITS: u8 = 48;

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
pub enum Ipv6UnicastAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    Ipv6UnicastError(#[from] Ipv6UnicastWritingError),
}

impl WritablePdu<Ipv6UnicastAddressWritingError> for Ipv6UnicastAddress {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.network().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv6UnicastAddressWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
        self.network().write(writer)?;
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
pub enum Ipv6MulticastAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    Ipv6MulticastError(#[from] Ipv6MulticastWritingError),
}

impl WritablePdu<Ipv6MulticastAddressWritingError> for Ipv6MulticastAddress {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.network().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv6MulticastAddressWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
        self.network().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv6MplsVpnUnicastAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    MplsLabelError(#[from] MplsLabelWritingError),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    Ipv6UnicastError(#[from] Ipv6UnicastAddressWritingError),
}

impl WritablePdu<Ipv6MplsVpnUnicastAddressWritingError> for Ipv6MplsVpnUnicastAddress {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.rd().len()
            + self.network().len()
            + self.label_stack().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv6MplsVpnUnicastAddressWritingError> {
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
pub enum Ipv4UnicastAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    Ipv4UnicastError(#[from] Ipv4UnicastWritingError),
}

impl WritablePdu<Ipv4UnicastAddressWritingError> for Ipv4UnicastAddress {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.network().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv4UnicastAddressWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
        self.network().write(writer)?;
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
pub enum Ipv4MulticastAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    Ipv4MulticastError(#[from] Ipv4MulticastWritingError),
}

impl WritablePdu<Ipv4MulticastAddressWritingError> for Ipv4MulticastAddress {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.network().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv4MulticastAddressWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
        self.network().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4MplsVpnUnicastAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    MplsLabelError(#[from] MplsLabelWritingError),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    Ipv4UnicastError(#[from] Ipv4UnicastWritingError),
}

impl WritablePdu<Ipv4MplsVpnUnicastAddressWritingError> for Ipv4MplsVpnUnicastAddress {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.path_id().map_or(0, |_| 4)
            + self.rd().len()
            + self.network().len()
            + self.label_stack().iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv4MplsVpnUnicastAddressWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
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
pub enum MacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<MacAddressWritingError> for MacAddress {
    const BASE_LENGTH: usize = 6;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), MacAddressWritingError> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum EthernetTagWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<EthernetTagWritingError> for EthernetTag {
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), EthernetTagWritingError> {
        writer.write_u32::<NetworkEndian>(self.0)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum EthernetSegmentIdentifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<EthernetSegmentIdentifierWritingError> for EthernetSegmentIdentifier {
    const BASE_LENGTH: usize = 10;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), EthernetSegmentIdentifierWritingError> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum EthernetAutoDiscoveryWritingError {
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierWritingError),
    EthernetTagError(#[from] EthernetTagWritingError),
    MplsLabelError(#[from] MplsLabelWritingError),
}

impl WritablePdu<EthernetAutoDiscoveryWritingError> for EthernetAutoDiscovery {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.rd().len()
            + self.segment_id().len()
            + self.tag().len()
            + self.mpls_label().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), EthernetAutoDiscoveryWritingError> {
        self.rd().write(writer)?;
        self.segment_id().write(writer)?;
        self.tag().write(writer)?;
        self.mpls_label().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum MacIpAdvertisementWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierWritingError),
    EthernetTagError(#[from] EthernetTagWritingError),
    MacAddressError(#[from] MacAddressWritingError),
    MplsLabelError(#[from] MplsLabelWritingError),
}

impl WritablePdu<MacIpAdvertisementWritingError> for MacIpAdvertisement {
    // 1-mac address len + 1 ip address len
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.rd().len()
            + self.segment_id().len()
            + self.tag().len()
            + self.mac().len()
            + self.ip().map_or(0, |x| {
                if x.is_ipv4() {
                    IPV4_LEN as usize
                } else {
                    IPV6_LEN as usize
                }
            })
            + self.mpls_label1().len()
            + self.mpls_label2().map_or(0, |x| x.len())
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), MacIpAdvertisementWritingError> {
        self.rd().write(writer)?;
        self.segment_id().write(writer)?;
        self.tag().write(writer)?;
        writer.write_u8(MAC_ADDRESS_LEN_BITS)?;
        self.mac().write(writer)?;
        match self.ip() {
            None => writer.write_u8(0)?,
            Some(IpAddr::V4(addr)) => {
                writer.write_u8(IPV4_LEN_BITS)?;
                writer.write_all(&addr.octets())?;
            }
            Some(IpAddr::V6(addr)) => {
                writer.write_u8(IPV6_LEN_BITS)?;
                writer.write_all(&addr.octets())?;
            }
        }
        self.mpls_label1().write(writer)?;
        if let Some(label) = self.mpls_label2() {
            label.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum InclusiveMulticastEthernetTagRouteWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    EthernetTagError(#[from] EthernetTagWritingError),
}

impl WritablePdu<InclusiveMulticastEthernetTagRouteWritingError>
    for InclusiveMulticastEthernetTagRoute
{
    // 1-octet for ip length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.rd().len()
            + self.tag().len()
            + if self.ip().is_ipv4() {
                IPV4_LEN as usize
            } else {
                IPV6_LEN as usize
            }
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), InclusiveMulticastEthernetTagRouteWritingError> {
        self.rd().write(writer)?;
        self.tag().write(writer)?;
        match self.ip() {
            IpAddr::V4(addr) => {
                writer.write_u8(IPV4_LEN_BITS)?;
                writer.write_all(&addr.octets())?;
            }
            IpAddr::V6(addr) => {
                writer.write_u8(IPV6_LEN_BITS)?;
                writer.write_all(&addr.octets())?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum EthernetSegmentRouteWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierWritingError),
}

impl WritablePdu<EthernetSegmentRouteWritingError> for EthernetSegmentRoute {
    // 1-octet for ip length
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.rd().len()
            + self.segment_id().len()
            + if self.ip().is_ipv4() {
                IPV4_LEN as usize
            } else {
                IPV6_LEN as usize
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), EthernetSegmentRouteWritingError> {
        self.rd().write(writer)?;
        self.segment_id().write(writer)?;
        match self.ip() {
            IpAddr::V4(addr) => {
                writer.write_u8(IPV4_LEN_BITS)?;
                writer.write_all(&addr.octets())?;
            }
            IpAddr::V6(addr) => {
                writer.write_u8(IPV6_LEN_BITS)?;
                writer.write_all(&addr.octets())?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum L2EvpnRouteWritingError {
    StdIOError(#[from_std_io_error] String),
    EthernetAutoDiscoveryError(#[from] EthernetAutoDiscoveryWritingError),
    MacIpAdvertisementError(#[from] MacIpAdvertisementWritingError),
    InclusiveMulticastEthernetTagWritingError(
        #[from] InclusiveMulticastEthernetTagRouteWritingError,
    ),
    EthernetSegmentRouteError(#[from] EthernetSegmentRouteWritingError),
    L2EvpnIpPrefixRouteError(#[from] L2EvpnIpPrefixRouteWritingError),
}

impl WritablePdu<L2EvpnRouteWritingError> for L2EvpnRoute {
    // 1-octet type + 1-octet length
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::EthernetAutoDiscovery(value) => value.len(),
                Self::MacIpAdvertisement(value) => value.len(),
                Self::InclusiveMulticastEthernetTagRoute(value) => value.len(),
                Self::EthernetSegmentRoute(value) => value.len(),
                Self::IpPrefixRoute(value) => value.len(),
                Self::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), L2EvpnRouteWritingError> {
        match self.route_type() {
            Ok(code) => writer.write_u8(code as u8)?,
            Err(code) => writer.write_u8(code)?,
        }
        writer.write_u8((self.len() - Self::BASE_LENGTH) as u8)?;
        match self {
            Self::EthernetAutoDiscovery(value) => value.write(writer)?,
            Self::MacIpAdvertisement(value) => value.write(writer)?,
            Self::InclusiveMulticastEthernetTagRoute(value) => value.write(writer)?,
            Self::EthernetSegmentRoute(value) => value.write(writer)?,
            Self::IpPrefixRoute(value) => value.write(writer)?,
            Self::Unknown { value, .. } => {
                writer.write_u8((value.len() + 1) as u8)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum L2EvpnAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    L2EvpnRouteError(#[from] L2EvpnRouteWritingError),
}

impl WritablePdu<L2EvpnAddressWritingError> for L2EvpnAddress {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.route().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), L2EvpnAddressWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(*path_id)?;
        }
        self.route().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum L2EvpnIpv4PrefixRouteWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierWritingError),
    EthernetTagError(#[from] EthernetTagWritingError),
    MplsLabelError(#[from] MplsLabelWritingError),
}

impl WritablePdu<L2EvpnIpv4PrefixRouteWritingError> for L2EvpnIpv4PrefixRoute {
    // 1-octet prefix len + 2 * 4 prefix & gateway + 3 MPLS Label
    const BASE_LENGTH: usize = 12;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.rd().len() + self.segment_id().len() + self.tag().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), L2EvpnIpv4PrefixRouteWritingError> {
        self.rd().write(writer)?;
        self.segment_id().write(writer)?;
        self.tag().write(writer)?;
        writer.write_u8(self.prefix().prefix_len())?;
        writer.write_all(&self.prefix().network().octets())?;
        writer.write_all(&self.gateway().octets())?;
        self.label().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum L2EvpnIpv6PrefixRouteWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteDistinguisherError(#[from] RouteDistinguisherWritingError),
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierWritingError),
    EthernetTagError(#[from] EthernetTagWritingError),
    MplsLabelError(#[from] MplsLabelWritingError),
}

impl WritablePdu<L2EvpnIpv6PrefixRouteWritingError> for L2EvpnIpv6PrefixRoute {
    // 1-octet prefix len + 2 * 16 prefix & gateway + 3 MPLS Label
    const BASE_LENGTH: usize = 36;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.rd().len() + self.segment_id().len() + self.tag().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), L2EvpnIpv6PrefixRouteWritingError> {
        self.rd().write(writer)?;
        self.segment_id().write(writer)?;
        self.tag().write(writer)?;
        writer.write_u8(self.prefix().prefix_len())?;
        writer.write_all(&self.prefix().network().octets())?;
        writer.write_all(&self.gateway().octets())?;
        self.label().write(writer)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum L2EvpnIpPrefixRouteWritingError {
    L2EvpnIpv4PrefixRouteError(#[from] L2EvpnIpv4PrefixRouteWritingError),
    L2EvpnIpv6PrefixRouteError(#[from] L2EvpnIpv6PrefixRouteWritingError),
}

impl WritablePdu<L2EvpnIpPrefixRouteWritingError> for L2EvpnIpPrefixRoute {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                Self::V4(value) => value.len(),
                Self::V6(value) => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), L2EvpnIpPrefixRouteWritingError> {
        match self {
            Self::V4(value) => value.write(writer)?,
            Self::V6(value) => value.write(writer)?,
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteTargetMembershipAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    RouteTargetMembershipWritingError(#[from] RouteTargetMembershipWritingError),
}

impl WritablePdu<RouteTargetMembershipAddressWritingError> for RouteTargetMembershipAddress {
    // 1-octet prefix len
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.path_id().map_or(0, |_| 4)
            + self.membership().map_or(0, |x| x.len())
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), RouteTargetMembershipAddressWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
        if let Some(membership) = self.membership() {
            let prefix_len = membership.len() * 8;
            writer.write_u8(prefix_len as u8)?;
            membership.write(writer)?;
        } else {
            // Default route with zero prefix length
            writer.write_u8(0)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum RouteTargetMembershipWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<RouteTargetMembershipWritingError> for RouteTargetMembership {
    // 4-octet origin AS
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.route_target().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), RouteTargetMembershipWritingError> {
        writer.write_u32::<NetworkEndian>(self.origin_as())?;
        writer.write_all(self.route_target())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv4NlriMplsLabelsAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    MplsLabelError(#[from] MplsLabelWritingError),
}

impl WritablePdu<Ipv4NlriMplsLabelsAddressWritingError> for Ipv4NlriMplsLabelsAddress {
    // 1-octet len
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.labels().iter().map(|x| x.len()).sum::<usize>()
            + round_len(self.prefix().prefix_len()) as usize
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv4NlriMplsLabelsAddressWritingError> {
        let len = (self.len() - 1) * 8;
        writer.write_u8((len - 1) as u8)?;
        for label in self.labels() {
            label.write(writer)?;
        }
        let prefix_len = round_len(self.prefix().prefix_len()) as usize;
        writer.write_all(&self.prefix().network().octets()[..prefix_len])?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum Ipv6NlriMplsLabelsAddressWritingError {
    StdIOError(#[from_std_io_error] String),
    MplsLabelError(#[from] MplsLabelWritingError),
}

impl WritablePdu<Ipv6NlriMplsLabelsAddressWritingError> for Ipv6NlriMplsLabelsAddress {
    // 1 octet prefix len
    const BASE_LENGTH: usize = 1;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.labels().iter().map(|x| x.len()).sum::<usize>()
            + round_len(self.prefix().prefix_len()) as usize
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), Ipv6NlriMplsLabelsAddressWritingError> {
        let len = (self.len() - 1) * 8;
        writer.write_u8(len as u8)?;
        for label in self.labels() {
            label.write(writer)?;
        }
        let prefix_len = round_len(self.prefix().prefix_len()) as usize;
        writer.write_all(&self.prefix().network().octets()[..prefix_len])?;
        Ok(())
    }
}
