// Copyright (C) 2023-present The NetGauze Authors.
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
    iana::BgpLsNodeDescriptorType,
    nlri::{
        BgpLsLinkDescriptor, BgpLsLocalNodeDescriptors, BgpLsNlri, BgpLsNlriIpPrefix,
        BgpLsNlriLink, BgpLsNlriNode, BgpLsNlriValue, BgpLsNodeDescriptorSubTlv,
        BgpLsNodeDescriptors, BgpLsPrefixDescriptor, BgpLsRemoteNodeDescriptors, BgpLsVpnNlri,
        IpReachabilityInformationData,
    },
    wire::serializer::{
        MultiTopologyIdWritingError, nlri::nlri::RouteDistinguisherWritingError,
        write_tlv_header_t16_l16,
    },
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;
use std::{io::Write, net::IpAddr};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpLsNlriWritingError {
    StdIoError(#[from_std_io_error] String),
    MultiTopologyIdWritingError(#[from] MultiTopologyIdWritingError),
    RouteDistinguisherWritingError(#[from] RouteDistinguisherWritingError),
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlri {
    const BASE_LENGTH: usize = 4; // nlri type u16 + total nlri length u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.nlri().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
        let nlri = self.nlri();

        // do not count add_path length since it is before the tlv
        let tlv_len = self.len() as u16 - self.path_id.map_or(0, |_| 4);
        write_tlv_header_t16_l16(writer, nlri.raw_code(), tlv_len)?;

        nlri.write(writer)?;

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsVpnNlri {
    const BASE_LENGTH: usize = 12; // nlri type u16 + total nlri length u16 + rd 8 bytes

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.value.len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }

        // do not count add_path length since it is before the tlv
        let tlv_len = self.len() as u16 - self.path_id.map_or(0, |_| 4);
        write_tlv_header_t16_l16(writer, self.value.raw_code(), tlv_len)?;

        self.rd.write(writer)?;
        self.value.write(writer)?;

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriValue {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        match self {
            BgpLsNlriValue::Node(data) => data.len(),
            BgpLsNlriValue::Link(data) => data.len(),
            BgpLsNlriValue::Ipv4Prefix(data) => data.len(),
            BgpLsNlriValue::Ipv6Prefix(data) => data.len(),
            BgpLsNlriValue::Unknown { value, .. } => value.len(),
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        match self {
            BgpLsNlriValue::Node(data) => data.write(writer),
            BgpLsNlriValue::Link(data) => data.write(writer),
            BgpLsNlriValue::Ipv4Prefix(data) => data.write(writer),
            BgpLsNlriValue::Ipv6Prefix(data) => data.write(writer),
            BgpLsNlriValue::Unknown { value, .. } => Ok(writer.write_all(value)?),
        }
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriIpPrefix {
    const BASE_LENGTH: usize = 1 + 8; // protocol_id + identifier;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors.len()
            + self
                .prefix_descriptors
                .iter()
                .map(|tlv| tlv.len())
                .sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        self.local_node_descriptors.write(writer)?;

        for tlv in &self.prefix_descriptors {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for IpReachabilityInformationData {
    const BASE_LENGTH: usize = 1; // Prefix Length (1 byte)

    fn len(&self) -> usize {
        Self::BASE_LENGTH + Self::most_significant_bytes(self.address().prefix_len())
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        writer.write_u8(self.address().prefix_len())?;

        match self.address().network() {
            IpAddr::V4(ipv4) => {
                writer.write_all(
                    &ipv4.octets()[..Self::most_significant_bytes(self.address().prefix_len())],
                )?;
            }
            IpAddr::V6(ipv6) => {
                writer.write_all(
                    &ipv6.octets()[..Self::most_significant_bytes(self.address().prefix_len())],
                )?;
            }
        };

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsPrefixDescriptor {
    const BASE_LENGTH: usize = 4; // tlv type u16 + tlv length u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(data) => data.len(),
                BgpLsPrefixDescriptor::OspfRouteType(_) => {
                    1 // OSPF Route Type
                }
                BgpLsPrefixDescriptor::IpReachabilityInformation(ip_reachability) => {
                    ip_reachability.len()
                }
                BgpLsPrefixDescriptor::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        write_tlv_header_t16_l16(writer, self.raw_code(), self.len() as u16)?;
        match self {
            BgpLsPrefixDescriptor::MultiTopologyIdentifier(data) => data.write(writer)?,
            BgpLsPrefixDescriptor::OspfRouteType(data) => writer.write_u8(*data as u8)?,
            BgpLsPrefixDescriptor::IpReachabilityInformation(data) => data.write(writer)?,
            BgpLsPrefixDescriptor::Unknown { value, .. } => writer.write_all(value)?,
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriNode {
    const BASE_LENGTH: usize = 1 + 8; // protocol_id + identifier

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.local_node_descriptors.len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        self.local_node_descriptors.write(writer)?;

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsLocalNodeDescriptors {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        self.0.len(BgpLsNodeDescriptorType::LocalNodeDescriptor)
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        self.0
            .write(writer, BgpLsNodeDescriptorType::LocalNodeDescriptor)
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsRemoteNodeDescriptors {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        self.0.len(BgpLsNodeDescriptorType::RemoteNodeDescriptor)
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        self.0
            .write(writer, BgpLsNodeDescriptorType::RemoteNodeDescriptor)
    }
}

impl WritablePduWithOneInput<BgpLsNodeDescriptorType, BgpLsNlriWritingError>
    for BgpLsNodeDescriptors
{
    const BASE_LENGTH: usize = 4; // tlv type 16bits + tlv length 16bits

    fn len(&self, _input: BgpLsNodeDescriptorType) -> usize {
        Self::BASE_LENGTH + self.subtlvs_len()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        input: BgpLsNodeDescriptorType,
    ) -> Result<(), BgpLsNlriWritingError> {
        write_tlv_header_t16_l16(writer, input as u16, self.len(input) as u16)?;
        for tlv in self.subtlvs() {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsLinkDescriptor {
    const BASE_LENGTH: usize = 4; // tlv type u16 + tlv length u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsLinkDescriptor::LinkLocalRemoteIdentifiers { .. } => 8,
                BgpLsLinkDescriptor::IPv4InterfaceAddress(..) => 4,
                BgpLsLinkDescriptor::IPv4NeighborAddress(..) => 4,
                BgpLsLinkDescriptor::IPv6InterfaceAddress(..) => 16,
                BgpLsLinkDescriptor::IPv6NeighborAddress(..) => 16,
                BgpLsLinkDescriptor::MultiTopologyIdentifier(data) => data.len(),
                BgpLsLinkDescriptor::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        write_tlv_header_t16_l16(writer, self.raw_code(), self.len() as u16)?;

        match self {
            BgpLsLinkDescriptor::LinkLocalRemoteIdentifiers {
                link_local_identifier,
                link_remote_identifier,
            } => {
                writer.write_u32::<NetworkEndian>(*link_local_identifier)?;
                writer.write_u32::<NetworkEndian>(*link_remote_identifier)?;
            }
            BgpLsLinkDescriptor::IPv4InterfaceAddress(ipv4) => {
                writer.write_u32::<NetworkEndian>((*ipv4).into())?
            }
            BgpLsLinkDescriptor::IPv4NeighborAddress(ipv4) => {
                writer.write_u32::<NetworkEndian>((*ipv4).into())?
            }
            BgpLsLinkDescriptor::IPv6InterfaceAddress(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsLinkDescriptor::IPv6NeighborAddress(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsLinkDescriptor::MultiTopologyIdentifier(data) => data.write(writer)?,
            BgpLsLinkDescriptor::Unknown { value, .. } => writer.write_all(value)?,
        };

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNodeDescriptorSubTlv {
    const BASE_LENGTH: usize = 4; // tlv type u16 + tlv length u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsNodeDescriptorSubTlv::AutonomousSystem(_) => 4,
                BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(_) => 4,
                BgpLsNodeDescriptorSubTlv::OspfAreaId(_) => 4,
                BgpLsNodeDescriptorSubTlv::IgpRouterId(inner) => inner.len(),
                BgpLsNodeDescriptorSubTlv::BgpRouterIdentifier(_) => 4,
                BgpLsNodeDescriptorSubTlv::MemberAsNumber(_) => 4,
                BgpLsNodeDescriptorSubTlv::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        write_tlv_header_t16_l16(writer, self.raw_code(), self.len() as u16)?;

        match self {
            BgpLsNodeDescriptorSubTlv::AutonomousSystem(data) => {
                writer.write_u32::<NetworkEndian>(*data)?
            }
            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(data) => {
                writer.write_u32::<NetworkEndian>(*data)?
            }
            BgpLsNodeDescriptorSubTlv::OspfAreaId(data) => {
                writer.write_u32::<NetworkEndian>(*data)?
            }
            BgpLsNodeDescriptorSubTlv::IgpRouterId(data) => writer.write_all(data)?,
            BgpLsNodeDescriptorSubTlv::BgpRouterIdentifier(data) => {
                writer.write_u32::<NetworkEndian>(*data)?
            }
            BgpLsNodeDescriptorSubTlv::MemberAsNumber(data) => {
                writer.write_u32::<NetworkEndian>(*data)?
            }
            BgpLsNodeDescriptorSubTlv::Unknown { value, .. } => writer.write_all(value)?,
        };

        Ok(())
    }
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriLink {
    const BASE_LENGTH: usize = 1 + 8; // protocol_id + identifier

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors.len()
            + self.remote_node_descriptors.len()
            + self
                .link_descriptors
                .iter()
                .map(|tlv| tlv.len())
                .sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        self.local_node_descriptors.write(writer)?;
        self.remote_node_descriptors.write(writer)?;

        for tlv in &self.link_descriptors {
            tlv.write(writer)?;
        }

        Ok(())
    }
}
