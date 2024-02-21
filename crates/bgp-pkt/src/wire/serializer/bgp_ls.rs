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
    iana::BgpLsNodeFlagsBits,
    nlri::{
        BgpLsLinkDescriptor, BgpLsNlri, BgpLsNlriIpPrefix, BgpLsNlriLink, BgpLsNlriNode,
        BgpLsNlriValue, BgpLsNodeDescriptorSubTlv, BgpLsNodeDescriptor,
        BgpLsPrefixDescriptor, BgpLsVpnNlri, IgpFlags, IpReachabilityInformationData,
        MplsProtocolMask, MultiTopologyId, MultiTopologyIdData,
    },
    path_attribute::{BgpLsAttribute, BgpLsAttributeValue, BgpLsPeerSid},
    wire::serializer::{
        nlri::{MplsLabelWritingError, RouteDistinguisherWritingError},
        path_attribute::write_length,
        IpAddrWritingError,
    },
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;
use std::{io::Write, net::IpAddr};
use crate::path_attribute::LinkProtectionType;

#[inline]
/// Write a TLV header.
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              Type             |             Length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// `tlv_type` : tlv code point
///
/// `tlv_length` : total tlv length on the wire
/// (as reported by the writer <=> including type and length fields)
///
/// Written length field will be `tlv_length - 4` since "Length" must not
/// include the length of the "Type" and "Length" field
fn write_tlv_header<T: Write>(
    writer: &mut T,
    tlv_type: u16,
    tlv_length: u16,
) -> Result<(), BgpLsWritingError> {
    // do not account for the tlv type u16 and tlv length u16
    let effective_length = tlv_length - 4;

    writer.write_u16::<NetworkEndian>(tlv_type)?;
    writer.write_u16::<NetworkEndian>(effective_length)?;

    Ok(())
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpLsWritingError {
    StdIoError(#[from_std_io_error] String),
    NodeNameTlvStringTooLong,
    IpAddrWritingError(#[from] IpAddrWritingError),
    RouteDistinguisherWritingError(#[from] RouteDistinguisherWritingError),
    MplsLabelWritingError(#[from] MplsLabelWritingError),
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlri {
    const BASE_LENGTH: usize = 4; // nlri type u16 + total nlri length u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.nlri().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }
        let nlri = self.nlri();

        // do not count add_path length since it is before the tlv
        let tlv_len = self.len() as u16 - self.path_id.map_or(0, |_| 4);
        write_tlv_header(writer, nlri.get_type() as u16, tlv_len)?;

        nlri.write(writer)?;

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsVpnNlri {
    const BASE_LENGTH: usize = 12; // nlri type u16 + total nlri length u16 + rd 8 bytes

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.path_id().map_or(0, |_| 4) + self.value.len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        if let Some(path_id) = self.path_id() {
            writer.write_u32::<NetworkEndian>(path_id)?;
        }

        // do not count add_path length since it is before the tlv
        let tlv_len = self.len() as u16 - self.path_id.map_or(0, |_| 4);
        write_tlv_header(writer, self.value.get_type() as u16, tlv_len)?;

        self.rd.write(writer)?;
        self.value.write(writer)?;

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriValue {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        match self {
            BgpLsNlriValue::Node(data) => data.len(),
            BgpLsNlriValue::Link(data) => data.len(),
            BgpLsNlriValue::Ipv4Prefix(data) => data.len(),
            BgpLsNlriValue::Ipv6Prefix(data) => data.len(),
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        match self {
            BgpLsNlriValue::Node(data) => data.write(writer),
            BgpLsNlriValue::Link(data) => data.write(writer),
            BgpLsNlriValue::Ipv4Prefix(data) => data.write(writer),
            BgpLsNlriValue::Ipv6Prefix(data) => data.write(writer),
        }
    }
}

impl WritablePduWithOneInput<bool, BgpLsWritingError> for BgpLsAttribute {
    const BASE_LENGTH: usize = 1; // 1 byte for attribute length

    fn len(&self, extended_length: bool) -> usize {
        let len = Self::BASE_LENGTH;

        len + usize::from(extended_length) + self.attributes.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_length(self, extended_length, writer)?;

        for tlv in &self.attributes {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriIpPrefix {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        self.local_node_descriptors.write(writer)?;

        for tlv in &self.prefix_descriptors {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for IpReachabilityInformationData {
    const BASE_LENGTH: usize = 1; // Prefix Length (1 byte)

    fn len(&self) -> usize {
        Self::BASE_LENGTH + Self::most_significant_bytes(self.address().prefix_len())
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
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

impl WritablePdu<BgpLsWritingError> for BgpLsPrefixDescriptor {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.raw_code(), self.len() as u16)?;
        match self {
            BgpLsPrefixDescriptor::MultiTopologyIdentifier(data) => data.write(writer)?,
            BgpLsPrefixDescriptor::OspfRouteType(data) => writer.write_u8(*data as u8)?,
            BgpLsPrefixDescriptor::IpReachabilityInformation(data) => data.write(writer)?,
            BgpLsPrefixDescriptor::Unknown { value, .. } => writer.write_all(value)?,
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsAttributeValue {
    const BASE_LENGTH: usize = 4; // tlv type u16 + tlv length u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsAttributeValue::LocalNodeIpv4RouterId(_) => 4,
                BgpLsAttributeValue::LocalNodeIpv6RouterId(_) => 16,
                BgpLsAttributeValue::RemoteNodeIpv4RouterId(_) => 4,
                BgpLsAttributeValue::RemoteNodeIpv6RouterId(_) => 16,
                BgpLsAttributeValue::RemoteNodeAdministrativeGroupColor(_) => 4,
                BgpLsAttributeValue::MaximumLinkBandwidth(_) => 4,
                BgpLsAttributeValue::MaximumReservableLinkBandwidth(_) => 4,
                BgpLsAttributeValue::UnreservedBandwidth(_) => 4 * 8,
                BgpLsAttributeValue::TeDefaultMetric(_) => 4,
                BgpLsAttributeValue::LinkProtectionType { .. } => 2,
                BgpLsAttributeValue::MplsProtocolMask { .. } => 1,
                BgpLsAttributeValue::IgpMetric(metric) => metric.len(),
                BgpLsAttributeValue::SharedRiskLinkGroup(groups) => 4 * groups.len(),
                BgpLsAttributeValue::OpaqueLinkAttribute(attr) => attr.len(),
                BgpLsAttributeValue::LinkName(name) => name.len(),
                BgpLsAttributeValue::IgpFlags { .. } => 1,
                BgpLsAttributeValue::IgpRouteTag(tags) => 4 * tags.len(),
                BgpLsAttributeValue::IgpExtendedRouteTag(tags) => 8 * tags.len(),
                BgpLsAttributeValue::PrefixMetric(_) => 4,
                BgpLsAttributeValue::OspfForwardingAddress(addr) => addr.len(),
                BgpLsAttributeValue::OpaquePrefixAttribute(attr) => attr.len(),
                BgpLsAttributeValue::MultiTopologyIdentifier(data) => data.len(),
                BgpLsAttributeValue::NodeFlagBits { .. } => 1,
                BgpLsAttributeValue::OpaqueNodeAttribute(bytes) => bytes.len(),
                BgpLsAttributeValue::NodeNameTlv(ascii) => ascii.len(),
                BgpLsAttributeValue::IsIsArea(area) => area.len(),
                BgpLsAttributeValue::PeerNodeSid(value) => value.len(),
                BgpLsAttributeValue::PeerAdjSid(value) => value.len(),
                BgpLsAttributeValue::PeerSetSid(value) => value.len(),
                BgpLsAttributeValue::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.raw_code(), self.len() as u16)?;

        match self {
            BgpLsAttributeValue::LocalNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsAttributeValue::LocalNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsAttributeValue::RemoteNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsAttributeValue::RemoteNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsAttributeValue::RemoteNodeAdministrativeGroupColor(color) => {
                writer.write_u32::<NetworkEndian>(*color)?
            }
            BgpLsAttributeValue::MaximumLinkBandwidth(bandwidth) => {
                writer.write_f32::<NetworkEndian>(*bandwidth)?
            }
            BgpLsAttributeValue::MaximumReservableLinkBandwidth(bandwidth) => {
                writer.write_f32::<NetworkEndian>(*bandwidth)?
            }
            BgpLsAttributeValue::UnreservedBandwidth(bandwidths) => {
                for bandwidth in bandwidths {
                    writer.write_f32::<NetworkEndian>(*bandwidth)?;
                }
            }
            BgpLsAttributeValue::TeDefaultMetric(metric) => {
                writer.write_u32::<NetworkEndian>(*metric)?
            }
            BgpLsAttributeValue::LinkProtectionType {
                extra_traffic,
                unprotected,
                shared,
                dedicated1c1,
                dedicated1p1,
                enhanced,
            } => {
                let mut protection_cap = 0;

                if *extra_traffic {
                    protection_cap |= LinkProtectionType::ExtraTraffic as u8
                }

                if *unprotected {
                    protection_cap |= LinkProtectionType::Unprotected as u8
                }

                if *shared {
                    protection_cap |= LinkProtectionType::Shared as u8
                }

                if *dedicated1c1 {
                    protection_cap |= LinkProtectionType::Dedicated1c1 as u8
                }

                if *dedicated1p1 {
                    protection_cap |= LinkProtectionType::Dedicated1p1 as u8
                }

                if *enhanced {
                    protection_cap |= LinkProtectionType::Enhanced as u8
                }

                writer.write_u8(protection_cap)?
            }
            BgpLsAttributeValue::MplsProtocolMask { ldp, rsvp_te } => {
                let mut flags = 0;

                if *ldp {
                    flags |= MplsProtocolMask::LabelDistributionProtocol as u8
                }

                if *rsvp_te {
                    flags |= MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8
                }

                writer.write_u8(flags)?
            }
            BgpLsAttributeValue::IgpMetric(metric) => writer.write_all(metric)?,
            BgpLsAttributeValue::SharedRiskLinkGroup(groups) => {
                for group in groups {
                    writer.write_u32::<NetworkEndian>(group.value())?;
                }
            }
            BgpLsAttributeValue::OpaqueLinkAttribute(attr) => writer.write_all(attr)?,
            BgpLsAttributeValue::LinkName(ascii) => writer.write_all(ascii.as_bytes())?,
            BgpLsAttributeValue::IgpFlags {
                isis_up_down,
                ospf_no_unicast,
                ospf_local_address,
                ospf_propagate_nssa,
            } => {
                let mut igp_flags = 0;

                if *isis_up_down {
                    igp_flags |= IgpFlags::IsIsUp as u8
                }

                if *ospf_no_unicast {
                    igp_flags |= IgpFlags::OspfNoUnicast as u8
                }

                if *ospf_local_address {
                    igp_flags |= IgpFlags::OspfLocalAddress as u8
                }

                if *ospf_propagate_nssa {
                    igp_flags |= IgpFlags::OspfPropagateNssa as u8
                }

                writer.write_u8(igp_flags)?
            }
            BgpLsAttributeValue::IgpRouteTag(tags) => {
                for tag in tags {
                    writer.write_u32::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsAttributeValue::IgpExtendedRouteTag(tags) => {
                for tag in tags {
                    writer.write_u64::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsAttributeValue::PrefixMetric(metric) => {
                writer.write_u32::<NetworkEndian>(*metric)?
            }
            BgpLsAttributeValue::OspfForwardingAddress(addr) => addr.write(writer)?,
            BgpLsAttributeValue::OpaquePrefixAttribute(attr) => writer.write_all(attr)?,
            BgpLsAttributeValue::MultiTopologyIdentifier(data) => data.write(writer)?,
            // TODO make macro for bitfields because come on look at this
            BgpLsAttributeValue::NodeFlagBits {
                overload,
                attached,
                external,
                abr,
                router,
                v6,
            } => {
                let mut flags: u8 = 0x00u8;
                if *overload {
                    flags |= BgpLsNodeFlagsBits::Overload as u8;
                }

                if *attached {
                    flags |= BgpLsNodeFlagsBits::Attached as u8;
                }

                if *external {
                    flags |= BgpLsNodeFlagsBits::External as u8;
                }

                if *abr {
                    flags |= BgpLsNodeFlagsBits::Abr as u8;
                }

                if *router {
                    flags |= BgpLsNodeFlagsBits::Router as u8;
                }

                if *v6 {
                    flags |= BgpLsNodeFlagsBits::V6 as u8;
                }

                writer.write_u8(flags)?;
            }
            BgpLsAttributeValue::OpaqueNodeAttribute(bytes) => writer.write_all(bytes)?,
            BgpLsAttributeValue::NodeNameTlv(ascii) => {
                if self.len() > BgpLsAttributeValue::NODE_NAME_TLV_MAX_LEN as usize {
                    return Err(BgpLsWritingError::NodeNameTlvStringTooLong);
                } else {
                    writer.write_all(ascii.as_bytes())?;
                }
            }
            BgpLsAttributeValue::IsIsArea(area) => writer.write_all(area)?,
            BgpLsAttributeValue::PeerNodeSid(value) => value.write(writer)?,
            BgpLsAttributeValue::PeerAdjSid(value) => value.write(writer)?,
            BgpLsAttributeValue::PeerSetSid(value) => value.write(writer)?,
            BgpLsAttributeValue::Unknown { value, .. } => writer.write_all(value)?,
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriNode {
    const BASE_LENGTH: usize = 1 + 8; // protocol_id + identifier

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.local_node_descriptors.len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        self.local_node_descriptors.write(writer)?;

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNodeDescriptor {
    const BASE_LENGTH: usize = 4; // tlv type 16bits + tlv length 16bits

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.subtlvs_len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;
        for tlv in self.subtlvs() {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsLinkDescriptor {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.raw_code(), self.len() as u16)?;

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
            BgpLsLinkDescriptor::IPv6InterfaceAddress(ipv6) => {
                writer.write_all(&ipv6.octets())?
            }
            BgpLsLinkDescriptor::IPv6NeighborAddress(ipv6) => {
                writer.write_all(&ipv6.octets())?
            }
            BgpLsLinkDescriptor::MultiTopologyIdentifier(data) => data.write(writer)?,
            BgpLsLinkDescriptor::Unknown { value, .. } => writer.write_all(value)?,
        };

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNodeDescriptorSubTlv {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.raw_code(), self.len() as u16)?;

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

impl WritablePdu<BgpLsWritingError> for BgpLsNlriLink {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
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

impl WritablePdu<BgpLsWritingError> for MultiTopologyIdData {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        2 * self.id_count()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        for id in &self.0 {
            id.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for MultiTopologyId {
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        writer.write_u16::<NetworkEndian>(self.value())?;

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsPeerSid {
    const BASE_LENGTH: usize = 4; // flags u8 + weight u8 + reserved u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsPeerSid::LabelValue { .. } => 3,
                BgpLsPeerSid::IndexValue { .. } => 4,
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        // tlv header is already written in BgpLsAttributeTlv

        writer.write_u8(self.flags())?;
        writer.write_u8(self.weight())?;
        writer.write_u16::<NetworkEndian>(0)?;

        match self {
            BgpLsPeerSid::LabelValue { label, .. } => label.write(writer)?,
            BgpLsPeerSid::IndexValue { index, .. } => writer.write_u32::<NetworkEndian>(*index)?,
        }

        Ok(())
    }
}
