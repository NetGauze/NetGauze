use crate::bgp_ls::{
    BgpLsAttribute, BgpLsAttributeTlv, BgpLsLinkDescriptorTlv, BgpLsNlri, BgpLsNlriIpPrefix,
    BgpLsNlriLink, BgpLsNlriNode, BgpLsNlriValue, BgpLsNodeDescriptorSubTlv,
    BgpLsNodeDescriptorTlv, BgpLsPrefixDescriptorTlv, BgpLsVpnNlri, IgpFlags,
    IpReachabilityInformationData, LinkProtectionType, MplsProtocolMask, MultiTopologyId,
    MultiTopologyIdData, NodeFlagsBits,
};
use crate::wire::serializer::nlri::RouteDistinguisherWritingError;
use crate::wire::serializer::path_attribute::write_length;
use crate::wire::serializer::IpAddrWritingError;
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;
use std::io::Write;
use std::net::IpAddr;

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
/// `tlv_length` : tlv length on the wire (as reported by the writer <=> including type and length fields)
///
/// Written length field will be `tlv_length - 4`
fn write_tlv_header<T: Write>(
    writer: &mut T,
    tlv_type: u16,
    tlv_length: u16,
) -> Result<(), BgpLsWritingError> {
    /* do not account for the tlv type u16 and tlv length u16 */
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
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlri {
    const BASE_LENGTH: usize = 4; /* nlri type u16 + total nlri length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.nlri().len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        let nlri = self.nlri();
        write_tlv_header(writer, nlri.get_type() as u16, self.len() as u16)?;

        nlri.write(writer)?;

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsVpnNlri {
    const BASE_LENGTH: usize = 12; /* nlri type u16 + total nlri length u16 + rd 8 bytes */

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.nlri.len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.nlri.get_type() as u16, self.len() as u16)?;

        self.rd.write(writer)?;

        self.nlri.write(writer)?;

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
    const BASE_LENGTH: usize = 1; /* 1 byte for attribute length */

    fn len(&self, extended_length: bool) -> usize {
        let len = Self::BASE_LENGTH;

        len + usize::from(extended_length) + self.tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
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

        for tlv in &self.tlvs {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriIpPrefix {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors.len()
            + self
                .prefix_descriptor_tlvs
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

        for tlv in &self.prefix_descriptor_tlvs {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for IpReachabilityInformationData {
    const BASE_LENGTH: usize = 1; /* Prefix Length (1 byte) */

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

impl WritablePdu<BgpLsWritingError> for BgpLsPrefixDescriptorTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(data) => data.len(),
                BgpLsPrefixDescriptorTlv::OspfRouteType(_) => {
                    1 /* OSPF Route Type */
                }
                BgpLsPrefixDescriptorTlv::IpReachabilityInformation(ip_reachability) => {
                    ip_reachability.len()
                }
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;
        match self {
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(data) => data.write(writer)?,
            BgpLsPrefixDescriptorTlv::OspfRouteType(data) => writer.write_u8(*data as u8)?,
            BgpLsPrefixDescriptorTlv::IpReachabilityInformation(data) => data.write(writer)?,
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsAttributeTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsAttributeTlv::LocalNodeIpv4RouterId(_) => 4,
                BgpLsAttributeTlv::LocalNodeIpv6RouterId(_) => 16,
                BgpLsAttributeTlv::RemoteNodeIpv4RouterId(_) => 4,
                BgpLsAttributeTlv::RemoteNodeIpv6RouterId(_) => 16,
                BgpLsAttributeTlv::RemoteNodeAdministrativeGroupColor(_) => 4,
                BgpLsAttributeTlv::MaximumLinkBandwidth(_) => 4,
                BgpLsAttributeTlv::MaximumReservableLinkBandwidth(_) => 4,
                BgpLsAttributeTlv::UnreservedBandwidth(_) => 4 * 8,
                BgpLsAttributeTlv::TeDefaultMetric(_) => 4,
                BgpLsAttributeTlv::LinkProtectionType { .. } => 2,
                BgpLsAttributeTlv::MplsProtocolMask { .. } => 1,
                BgpLsAttributeTlv::IgpMetric(metric) => metric.len(),
                BgpLsAttributeTlv::SharedRiskLinkGroup(groups) => 4 * groups.len(),
                BgpLsAttributeTlv::OpaqueLinkAttribute(attr) => attr.len(),
                BgpLsAttributeTlv::LinkName(name) => name.len(),
                BgpLsAttributeTlv::IgpFlags { .. } => 1,
                BgpLsAttributeTlv::IgpRouteTag(tags) => 4 * tags.len(),
                BgpLsAttributeTlv::IgpExtendedRouteTag(tags) => 8 * tags.len(),
                BgpLsAttributeTlv::PrefixMetric(_) => 4,
                BgpLsAttributeTlv::OspfForwardingAddress(addr) => addr.len(),
                BgpLsAttributeTlv::OpaquePrefixAttribute(attr) => attr.len(),
                BgpLsAttributeTlv::MultiTopologyIdentifier(data) => data.len(),
                BgpLsAttributeTlv::NodeFlagBits { .. } => 1,
                BgpLsAttributeTlv::OpaqueNodeAttribute(bytes) => bytes.len(),
                BgpLsAttributeTlv::NodeNameTlv(ascii) => ascii.len(),
                BgpLsAttributeTlv::IsIsArea(area) => area.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;

        match self {
            BgpLsAttributeTlv::LocalNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsAttributeTlv::LocalNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsAttributeTlv::RemoteNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsAttributeTlv::RemoteNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsAttributeTlv::RemoteNodeAdministrativeGroupColor(color) => {
                writer.write_u32::<NetworkEndian>(*color)?
            }
            BgpLsAttributeTlv::MaximumLinkBandwidth(bandwidth) => {
                writer.write_f32::<NetworkEndian>(*bandwidth)?
            }
            BgpLsAttributeTlv::MaximumReservableLinkBandwidth(bandwidth) => {
                writer.write_f32::<NetworkEndian>(*bandwidth)?
            }
            BgpLsAttributeTlv::UnreservedBandwidth(bandwidths) => {
                for bandwidth in bandwidths {
                    writer.write_f32::<NetworkEndian>(*bandwidth)?;
                }
            }
            BgpLsAttributeTlv::TeDefaultMetric(metric) => {
                writer.write_u32::<NetworkEndian>(*metric)?
            }
            BgpLsAttributeTlv::LinkProtectionType {
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
            BgpLsAttributeTlv::MplsProtocolMask { ldp, rsvp_te } => {
                let mut flags = 0;

                if *ldp {
                    flags |= MplsProtocolMask::LabelDistributionProtocol as u8
                }

                if *rsvp_te {
                    flags |= MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8
                }

                writer.write_u8(flags)?
            }
            BgpLsAttributeTlv::IgpMetric(metric) => writer.write_all(metric)?,
            BgpLsAttributeTlv::SharedRiskLinkGroup(groups) => {
                for group in groups {
                    writer.write_u32::<NetworkEndian>(group.value())?;
                }
            }
            BgpLsAttributeTlv::OpaqueLinkAttribute(attr) => writer.write_all(attr)?,
            BgpLsAttributeTlv::LinkName(ascii) => writer.write_all(ascii.as_bytes())?,
            BgpLsAttributeTlv::IgpFlags {
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
            BgpLsAttributeTlv::IgpRouteTag(tags) => {
                for tag in tags {
                    writer.write_u32::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsAttributeTlv::IgpExtendedRouteTag(tags) => {
                for tag in tags {
                    writer.write_u64::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsAttributeTlv::PrefixMetric(metric) => {
                writer.write_u32::<NetworkEndian>(*metric)?
            }
            BgpLsAttributeTlv::OspfForwardingAddress(addr) => addr.write(writer)?,
            BgpLsAttributeTlv::OpaquePrefixAttribute(attr) => writer.write_all(attr)?,
            BgpLsAttributeTlv::MultiTopologyIdentifier(data) => data.write(writer)?,
            // TODO make macro for bitfields because come on look at this
            BgpLsAttributeTlv::NodeFlagBits {
                overload,
                attached,
                external,
                abr,
                router,
                v6,
            } => {
                let mut flags: u8 = 0x00u8;
                if *overload {
                    flags |= NodeFlagsBits::Overload as u8;
                }

                if *attached {
                    flags |= NodeFlagsBits::Attached as u8;
                }

                if *external {
                    flags |= NodeFlagsBits::External as u8;
                }

                if *abr {
                    flags |= NodeFlagsBits::Abr as u8;
                }

                if *router {
                    flags |= NodeFlagsBits::Router as u8;
                }

                if *v6 {
                    flags |= NodeFlagsBits::V6 as u8;
                }

                writer.write_u8(flags)?;
            }
            BgpLsAttributeTlv::OpaqueNodeAttribute(bytes) => writer.write_all(bytes)?,
            BgpLsAttributeTlv::NodeNameTlv(ascii) => {
                if self.len() > BgpLsAttributeTlv::NODE_NAME_TLV_MAX_LEN as usize {
                    return Err(BgpLsWritingError::NodeNameTlvStringTooLong);
                } else {
                    writer.write_all(ascii.as_bytes())?;
                }
            }
            BgpLsAttributeTlv::IsIsArea(area) => writer.write_all(area)?,
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriNode {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

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

impl WritablePdu<BgpLsWritingError> for BgpLsNodeDescriptorTlv {
    const BASE_LENGTH: usize = 4; /* tlv type 16bits + tlv length 16bits */

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

impl WritablePdu<BgpLsWritingError> for BgpLsLinkDescriptorTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers { .. } => 8,
                BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(..) => 4,
                BgpLsLinkDescriptorTlv::IPv4NeighborAddress(..) => 4,
                BgpLsLinkDescriptorTlv::IPv6InterfaceAddress(..) => 16,
                BgpLsLinkDescriptorTlv::IPv6NeighborAddress(..) => 16,
                BgpLsLinkDescriptorTlv::MultiTopologyIdentifier(data) => data.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;

        match self {
            BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers {
                link_local_identifier,
                link_remote_identifier,
            } => {
                writer.write_u32::<NetworkEndian>(*link_local_identifier)?;
                writer.write_u32::<NetworkEndian>(*link_remote_identifier)?;
            }
            BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(ipv4) => {
                writer.write_u32::<NetworkEndian>((*ipv4).into())?
            }
            BgpLsLinkDescriptorTlv::IPv4NeighborAddress(ipv4) => {
                writer.write_u32::<NetworkEndian>((*ipv4).into())?
            }
            BgpLsLinkDescriptorTlv::IPv6InterfaceAddress(ipv6) => {
                writer.write_all(&ipv6.octets())?
            }
            BgpLsLinkDescriptorTlv::IPv6NeighborAddress(ipv6) => {
                writer.write_all(&ipv6.octets())?
            }
            BgpLsLinkDescriptorTlv::MultiTopologyIdentifier(data) => data.write(writer)?,
        };

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNodeDescriptorSubTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsNodeDescriptorSubTlv::AutonomousSystem(_) => 4,
                BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(_) => 4,
                BgpLsNodeDescriptorSubTlv::OspfAreaId(_) => 4,
                BgpLsNodeDescriptorSubTlv::IgpRouterId(inner) => inner.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;
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
        };

        Ok(())
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriLink {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors.len()
            + self.remote_node_descriptors.len()
            + self
                .link_descriptor_tlvs
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

        for tlv in &self.link_descriptor_tlvs {
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
