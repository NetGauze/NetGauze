use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use byteorder::{NetworkEndian, WriteBytesExt};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, FromRepr};
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;
use crate::bgp_ls::BgpLsMtIdError::{IsIsMtIdInvalidValue, OspfMtIdInvalidValue};
use crate::iana;
use crate::iana::BgpLsDescriptorTlvs::{LocalNodeDescriptor, RemoteNodeDescriptor};
use crate::iana::{BgpLsDescriptorTlvs, BgpLsProtocolId};
use crate::path_attribute::PathAttributeValueProperties;
use crate::wire::serializer::IpAddrWritingError;
use crate::wire::serializer::path_attribute::write_length;

#[derive(Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BgpLs {
    Node(Vec<BgpLsNodeAttributeTlv>),
    Link(Vec<BgpLsLinkAttributeTlv>),
    Prefix(Vec<BgpLsPrefixAttributeTlv>),
}

impl PathAttributeValueProperties for BgpLs {
    /// see [RFC7752 Section 3.3]https://www.rfc-editor.org/rfc/rfc7752#section-3.3
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    /// see [RFC7752 Section 3.3]https://www.rfc-editor.org/rfc/rfc7752#section-3.3
    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    /// optional non-transitive attributes can't be partial
    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

#[derive(Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BgpLsLinkAttributeTlv {
    LocalNodeIpv4RouterId(Ipv4Addr),
    LocalNodeIpv6RouterId(Ipv6Addr),
    /// must be global
    RemoteNodeIpv4RouterId(Ipv4Addr),
    /// must be global
    RemoteNodeIpv6RouterId(Ipv6Addr),
    RemoteNodeAdministrativeGroupColor(u32),
    MaximumLinkBandwidth(f32),
    MaximumReservableLinkBandwidth(f32),
    UnreservedBandwidth([f32; 8]),
    TeDefaultMetric(u32),

    ///        0                   1
    ///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       |Protection Cap |    Reserved   |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       0x01  Extra Traffic
    ///
    ///       0x02  Unprotected
    ///
    ///       0x04  Shared
    ///
    ///       0x08  Dedicated 1:1
    ///
    ///       0x10  Dedicated 1+1
    ///
    ///       0x20  Enhanced
    ///
    ///       0x40  Reserved
    ///
    ///       0x80  Reserved
    LinkProtectionType {
        extra_traffic: bool,
        unprotected: bool,
        shared: bool,
        dedicated1c1: bool,
        dedicated1p1: bool,
        enhanced: bool,
    },
    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |L|R|  Reserved |
    ///      +-+-+-+-+-+-+-+-+
    ///
    ///    +------------+------------------------------------------+-----------+
    ///    |    Bit     | Description                              | Reference |
    ///    +------------+------------------------------------------+-----------+
    ///    |    'L'     | Label Distribution Protocol (LDP)        | [RFC5036] |
    ///    |    'R'     | Extension to RSVP for LSP Tunnels        | [RFC3209] |
    ///    |            | (RSVP-TE)                                |           |
    ///    | 'Reserved' | Reserved for future use                  |           |
    ///    +------------+------------------------------------------+-----------+
    MplsProtocolMask {
        ldp: bool,
        rsvp_te: bool,
    },

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //      IGP Link Metric (variable length)      //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    IgpMetric(Vec<u8>),

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                  Shared Risk Link Group Value                 |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                         ............                        //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                  Shared Risk Link Group Value                 |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    SharedRiskLinkGroup(Vec<SharedRiskLinkGroupValue>),

    ///      0                   1                   2                   3
    ///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     |              Type             |             Length            |
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     //                Opaque link attributes (variable)            //
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    OpaqueLinkAttribute(Vec<u8>),

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                     Link Name (variable)                    //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    LinkName(String),
}

impl BgpLsLinkAttributeTlv {
    pub fn get_type(&self) -> iana::BgpLsLinkAttribute {
        match self {
            BgpLsLinkAttributeTlv::LocalNodeIpv4RouterId(_) => iana::BgpLsLinkAttribute::LocalNodeIpv4RouterId,
            BgpLsLinkAttributeTlv::LocalNodeIpv6RouterId(_) => iana::BgpLsLinkAttribute::LocalNodeIpv6RouterId,
            BgpLsLinkAttributeTlv::RemoteNodeIpv4RouterId(_) => iana::BgpLsLinkAttribute::RemoteNodeIpv4RouterId,
            BgpLsLinkAttributeTlv::RemoteNodeIpv6RouterId(_) => iana::BgpLsLinkAttribute::RemoteNodeIpv6RouterId,
            BgpLsLinkAttributeTlv::RemoteNodeAdministrativeGroupColor(_) => iana::BgpLsLinkAttribute::RemoteNodeAdministrativeGroupColor,
            BgpLsLinkAttributeTlv::MaximumLinkBandwidth(_) => iana::BgpLsLinkAttribute::MaximumLinkBandwidth,
            BgpLsLinkAttributeTlv::MaximumReservableLinkBandwidth(_) => iana::BgpLsLinkAttribute::MaximumReservableLinkBandwidth,
            BgpLsLinkAttributeTlv::UnreservedBandwidth(_) => iana::BgpLsLinkAttribute::UnreservedBandwidth,
            BgpLsLinkAttributeTlv::TeDefaultMetric(_) => iana::BgpLsLinkAttribute::TeDefaultMetric,
            BgpLsLinkAttributeTlv::LinkProtectionType { .. } => iana::BgpLsLinkAttribute::LinkProtectionType,
            BgpLsLinkAttributeTlv::MplsProtocolMask { .. } => iana::BgpLsLinkAttribute::MplsProtocolMask,
            BgpLsLinkAttributeTlv::IgpMetric(..) => iana::BgpLsLinkAttribute::IgpMetric,
            BgpLsLinkAttributeTlv::SharedRiskLinkGroup(..) => iana::BgpLsLinkAttribute::SharedRiskLinkGroup,
            BgpLsLinkAttributeTlv::OpaqueLinkAttribute(..) => iana::BgpLsLinkAttribute::OpaqueLinkAttribute,
            BgpLsLinkAttributeTlv::LinkName(..) => iana::BgpLsLinkAttribute::LinkName,
        }
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsLinkAttributeTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH +
            match self {
                BgpLsLinkAttributeTlv::LocalNodeIpv4RouterId(_) => 4,
                BgpLsLinkAttributeTlv::LocalNodeIpv6RouterId(_) => 16,
                BgpLsLinkAttributeTlv::RemoteNodeIpv4RouterId(_) => 4,
                BgpLsLinkAttributeTlv::RemoteNodeIpv6RouterId(_) => 16,
                BgpLsLinkAttributeTlv::RemoteNodeAdministrativeGroupColor(_) => 4,
                BgpLsLinkAttributeTlv::MaximumLinkBandwidth(_) => 4,
                BgpLsLinkAttributeTlv::MaximumReservableLinkBandwidth(_) => 4,
                BgpLsLinkAttributeTlv::UnreservedBandwidth(_) => 4 * 8,
                BgpLsLinkAttributeTlv::TeDefaultMetric(_) => 4,
                BgpLsLinkAttributeTlv::LinkProtectionType { .. } => 2,
                BgpLsLinkAttributeTlv::MplsProtocolMask { .. } => 1,
                BgpLsLinkAttributeTlv::IgpMetric(metric) => metric.len(),
                BgpLsLinkAttributeTlv::SharedRiskLinkGroup(groups) => 4 * groups.len(),
                BgpLsLinkAttributeTlv::OpaqueLinkAttribute(attr) => attr.len(),
                BgpLsLinkAttributeTlv::LinkName(name) => name.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;

        match self {
            BgpLsLinkAttributeTlv::LocalNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsLinkAttributeTlv::LocalNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsLinkAttributeTlv::RemoteNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsLinkAttributeTlv::RemoteNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsLinkAttributeTlv::RemoteNodeAdministrativeGroupColor(color) => writer.write_u32::<NetworkEndian>(*color)?,
            BgpLsLinkAttributeTlv::MaximumLinkBandwidth(bandwidth) => writer.write_f32::<NetworkEndian>(*bandwidth)?,
            BgpLsLinkAttributeTlv::MaximumReservableLinkBandwidth(bandwidth) => writer.write_f32::<NetworkEndian>(*bandwidth)?,
            BgpLsLinkAttributeTlv::UnreservedBandwidth(bandwidths) => {
                for bandwidth in bandwidths {
                    writer.write_f32::<NetworkEndian>(*bandwidth)?;
                }
            }
            BgpLsLinkAttributeTlv::TeDefaultMetric(metric) => writer.write_u32::<NetworkEndian>(*metric)?,
            BgpLsLinkAttributeTlv::LinkProtectionType { extra_traffic, unprotected, shared, dedicated1c1, dedicated1p1, enhanced } => {
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
            BgpLsLinkAttributeTlv::MplsProtocolMask { ldp, rsvp_te } => {
                let mut flags = 0;

                if *ldp {
                    flags |= MplsProtocolMask::LabelDistributionProtocol as u8
                }

                if *rsvp_te {
                    flags |= MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8
                }

                writer.write_u8(flags)?
            }
            BgpLsLinkAttributeTlv::IgpMetric(metric) => writer.write_all(metric)?,
            BgpLsLinkAttributeTlv::SharedRiskLinkGroup(groups) => {
                for group in groups {
                    writer.write_u32::<NetworkEndian>(group.value())?;
                }
            },
            BgpLsLinkAttributeTlv::OpaqueLinkAttribute(attr) => writer.write_all(attr)?,
            BgpLsLinkAttributeTlv::LinkName(ascii) => writer.write_all(ascii.as_bytes())?,
        }

        Ok(())
    }
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsPrefixAttributeTlv {
    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |D|N|L|P| Resvd.|
    ///      +-+-+-+-+-+-+-+-+
    ///
    ///    The Value field contains bits defined according to the table below:
    ///
    ///            +----------+---------------------------+-----------+
    ///            |   Bit    | Description               | Reference |
    ///            +----------+---------------------------+-----------+
    ///            |   'D'    | IS-IS Up/Down Bit         | [RFC5305] |
    ///            |   'N'    | OSPF "no unicast" Bit     | [RFC5340] |
    ///            |   'L'    | OSPF "local address" Bit  | [RFC5340] |
    ///            |   'P'    | OSPF "propagate NSSA" Bit | [RFC5340] |
    ///            | Reserved | Reserved for future use.  |           |
    ///            +----------+---------------------------+-----------+
    IgpFlags {
        isis_up_down: bool,
        ospf_no_unicast: bool,
        ospf_local_address: bool,
        ospf_propagate_nssa: bool,
    },

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                    Route Tags (one or more)                 //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is a multiple of 4.
    IgpRouteTag(Vec<u32>),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                Extended Route Tag (one or more)             //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is a multiple of 8.
    IgpExtendedRouteTag(Vec<u64>),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                            Metric                             |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is 4.
    PrefixMetric(u32),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                Forwarding Address (variable)                //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is 4 for an IPv4 forwarding address, and 16 for an IPv6
    ///    forwarding address.
    OspfForwardingAddress(IpAddr),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //              Opaque Prefix Attributes  (variable)           //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    OpaquePrefixAttribute(Vec<u8>),
}

impl BgpLsPrefixAttributeTlv {
    pub fn get_type(&self) -> iana::BgpLsPrefixAttribute {
        match self {
            BgpLsPrefixAttributeTlv::IgpFlags { .. } => iana::BgpLsPrefixAttribute::IgpFlags,
            BgpLsPrefixAttributeTlv::IgpRouteTag(_) => iana::BgpLsPrefixAttribute::IgpRouteTag,
            BgpLsPrefixAttributeTlv::IgpExtendedRouteTag(_) => iana::BgpLsPrefixAttribute::IgpExtendedRouteTag,
            BgpLsPrefixAttributeTlv::PrefixMetric(_) => iana::BgpLsPrefixAttribute::PrefixMetric,
            BgpLsPrefixAttributeTlv::OspfForwardingAddress(_) => iana::BgpLsPrefixAttribute::OspfForwardingAddress,
            BgpLsPrefixAttributeTlv::OpaquePrefixAttribute(_) => iana::BgpLsPrefixAttribute::OpaquePrefixAttribute,
        }
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsPrefixAttributeTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        match self {
            BgpLsPrefixAttributeTlv::IgpFlags { .. } => 1,
            BgpLsPrefixAttributeTlv::IgpRouteTag(tags) => 4 * tags.len(),
            BgpLsPrefixAttributeTlv::IgpExtendedRouteTag(tags) => 8 * tags.len(),
            BgpLsPrefixAttributeTlv::PrefixMetric(_) => 4,
            BgpLsPrefixAttributeTlv::OspfForwardingAddress(addr) => addr.len(),
            BgpLsPrefixAttributeTlv::OpaquePrefixAttribute(attr) => attr.len(),
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;

        match self {
            BgpLsPrefixAttributeTlv::IgpFlags { isis_up_down, ospf_no_unicast, ospf_local_address, ospf_propagate_nssa } => {
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
            BgpLsPrefixAttributeTlv::IgpRouteTag(tags) => {
                for tag in tags {
                    writer.write_u32::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsPrefixAttributeTlv::IgpExtendedRouteTag(tags) => {
                for tag in tags {
                    writer.write_u64::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsPrefixAttributeTlv::PrefixMetric(metric) => writer.write_u32::<NetworkEndian>(*metric)?,
            BgpLsPrefixAttributeTlv::OspfForwardingAddress(addr) => addr.write(writer)?,
            BgpLsPrefixAttributeTlv::OpaquePrefixAttribute(attr) => writer.write_all(attr)?,
        }

        Ok(())
    }
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsNodeAttributeTlv {
    MultiTopologyIdentifier(MultiTopologyIdData),
    NodeFlagBits {
        overload: bool,
        attached: bool,
        external: bool,
        abr: bool,
        router: bool,
        v6: bool,
    },
    OpaqueNodeAttribute(Vec<u8>),
    NodeNameTlv(String),
    IsIsArea(Vec<u8>),
    LocalNodeIpv4RouterId(Ipv4Addr),
    LocalNodeIpv6RouterId(Ipv6Addr),
}

impl BgpLsNodeAttributeTlv {
    const NODE_NAME_TLV_MAX_LEN: u8 = 255;

    pub fn get_type(&self) -> iana::BgpLsNodeAttributeTlv {
        match self {
            BgpLsNodeAttributeTlv::MultiTopologyIdentifier(..) => iana::BgpLsNodeAttributeTlv::MultiTopologyIdentifier,
            BgpLsNodeAttributeTlv::NodeFlagBits { .. } => iana::BgpLsNodeAttributeTlv::NodeFlagBits,
            BgpLsNodeAttributeTlv::OpaqueNodeAttribute(..) => iana::BgpLsNodeAttributeTlv::OpaqueNodeAttribute,
            BgpLsNodeAttributeTlv::NodeNameTlv(..) => iana::BgpLsNodeAttributeTlv::NodeNameTlv,
            BgpLsNodeAttributeTlv::IsIsArea(..) => iana::BgpLsNodeAttributeTlv::IsIsArea,
            BgpLsNodeAttributeTlv::LocalNodeIpv4RouterId(..) => iana::BgpLsNodeAttributeTlv::LocalNodeIpv4RouterId,
            BgpLsNodeAttributeTlv::LocalNodeIpv6RouterId(..) => iana::BgpLsNodeAttributeTlv::LocalNodeIpv6RouterId,
        }
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNodeAttributeTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH +
            match self {
                BgpLsNodeAttributeTlv::MultiTopologyIdentifier(data) => data.len(),
                BgpLsNodeAttributeTlv::NodeFlagBits { .. } => 1,
                BgpLsNodeAttributeTlv::OpaqueNodeAttribute(bytes) => bytes.len(),
                BgpLsNodeAttributeTlv::NodeNameTlv(ascii) => ascii.len(),
                BgpLsNodeAttributeTlv::IsIsArea(area) => area.len(),
                BgpLsNodeAttributeTlv::LocalNodeIpv4RouterId(_) => 4,
                BgpLsNodeAttributeTlv::LocalNodeIpv6RouterId(_) => 16,
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;

        match self {
            BgpLsNodeAttributeTlv::MultiTopologyIdentifier(data) => data.write(writer)?,
            // TODO make macro for bitfields because come on look at this
            BgpLsNodeAttributeTlv::NodeFlagBits { overload, attached, external, abr, router, v6 } => {
                let mut flags: u8 = 0x00u8;
                if *overload {
                    flags |= 0b_1000_0000;
                }

                if *attached {
                    flags |= 0b_0100_0000;
                }

                if *external {
                    flags |= 0b_0010_0000;
                }

                if *abr {
                    flags |= 0b_0001_0000;
                }

                if *router {
                    flags |= 0b_0000_1000;
                }

                if *v6 {
                    flags |= 0b_0000_0100;
                }

                writer.write_u8(flags)?;
            }
            BgpLsNodeAttributeTlv::OpaqueNodeAttribute(bytes) => writer.write_all(bytes)?,
            BgpLsNodeAttributeTlv::NodeNameTlv(ascii) => {
                if self.len() > BgpLsNodeAttributeTlv::NODE_NAME_TLV_MAX_LEN as usize {
                    return Err(BgpLsWritingError::NodeNameTlvStringTooLongError);
                } else {
                    writer.write_all(ascii.as_bytes())?;
                }
            }
            BgpLsNodeAttributeTlv::IsIsArea(area) => writer.write_all(area)?,
            BgpLsNodeAttributeTlv::LocalNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsNodeAttributeTlv::LocalNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
        }

        Ok(())
    }
}

impl WritablePduWithOneInput<bool, BgpLsWritingError> for BgpLs {
    const BASE_LENGTH: usize = 0;

    fn len(&self, extended_length: bool) -> usize {
        let len = Self::BASE_LENGTH;

        len + usize::from(extended_length)
    }

    fn write<T: Write>(&self, writer: &mut T, extended_length: bool) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_length(self, extended_length, writer)?;

        /* rust does not let us have a &Vec<impl WritablePdu<BgpLsWritingError>> */
        match self {
            BgpLs::Node(tlvs) => {
                for tlv in tlvs {
                    tlv.write(writer)?;
                }
            }
            BgpLs::Link(tlvs) => {
                for tlv in tlvs {
                    tlv.write(writer)?;
                }
            }
            BgpLs::Prefix(tlvs) => {
                for tlv in tlvs {
                    tlv.write(writer)?;
                }
            }
        };

        Ok(())
    }
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsNlri {
    Node(BgpLsNlriNode),
    Link(BgpLsNlriLink),
    Ipv4Prefix(BgpLsNlriIpPrefix),
    Ipv6Prefix(BgpLsNlriIpPrefix),
}

impl BgpLsNlri {
    pub fn get_type(&self) -> iana::BgpLsNlriType {
        match self {
            BgpLsNlri::Node(_) => iana::BgpLsNlriType::Node,
            BgpLsNlri::Link(_) => iana::BgpLsNlriType::Link,
            BgpLsNlri::Ipv4Prefix(_) => iana::BgpLsNlriType::Ipv4TopologyPrefix,
            BgpLsNlri::Ipv6Prefix(_) => iana::BgpLsNlriType::Ipv6TopologyPrefix,
        }
    }
}


#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpLsWritingError {
    StdIoError(#[from_std_io_error] String),
    NodeNameTlvStringTooLongError,
    AddrWritingError(#[from] IpAddrWritingError),
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlri {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        match self {
            BgpLsNlri::Node(data) => data.len(),
            BgpLsNlri::Link(data) => data.len(),
            BgpLsNlri::Ipv4Prefix(data) => data.len(),
            BgpLsNlri::Ipv6Prefix(data) => data.len(),
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        match self {
            BgpLsNlri::Node(data) => data.write(writer),
            BgpLsNlri::Link(data) => data.write(writer),
            BgpLsNlri::Ipv4Prefix(data) => data.write(writer),
            BgpLsNlri::Ipv6Prefix(data) => data.write(writer),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpLsNlriIpPrefix {
    protocol_id: BgpLsProtocolId,
    identifier: u64,
    local_node_descriptors: Vec<BgpLsNodeDescriptorTlv>,
    prefix_descriptors: Vec<BgpLsPrefixDescriptorTlv>,
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriIpPrefix {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.prefix_descriptors.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        writer.write_u16::<NetworkEndian>(self.protocol_id as u16)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        for tlv in &self.local_node_descriptors {
            tlv.write(writer)?;
        }

        for tlv in &self.prefix_descriptors {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

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
fn write_tlv_header<T: Write>(writer: &mut T, tlv_type: u16, tlv_length: u16) -> Result<(), BgpLsWritingError> {
    /* do not account for the tlv type u16 and tlv length u16 */
    let effective_length = tlv_length - 4;

    writer.write_u16::<NetworkEndian>(tlv_type)?;
    writer.write_u16::<NetworkEndian>(effective_length)?;

    Ok(())
}

// TODO does this go into IANA?
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum OspfRouteType {
    IntraArea = 1,
    InterArea = 2,
    External1 = 3,
    External2 = 4,
    Nssa1 = 5,
    Nssa2 = 6,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MplsProtocolMask {
    LabelDistributionProtocol = 0b10000000,
    ExtensionToRsvpForLspTunnels = 0b01000000,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LinkProtectionType {
    ExtraTraffic = 0x01,
    Unprotected = 0x02,
    Shared = 0x04,
    Dedicated1c1 = 0x08,
    Dedicated1p1 = 0x10,
    Enhanced = 0x20,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum IgpFlags {
    IsIsUp = 0b10000000,
    OspfNoUnicast = 0b01000000,
    OspfLocalAddress = 0b00100000,
    OspfPropagateNssa = 0b00010000,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpLsIpReachabilityInformationData(IpNet);


impl BgpLsIpReachabilityInformationData {
    /// Count of most significant bytes of the Prefix to send
    /// as described in [RFC7752 Section-3.2.3.2](https://datatracker.ietf.org/doc/html/rfc7752#section-3.2.3.2)
    pub fn most_significant_bytes(prefix_len: u8) -> usize {
        /*
         1-8    -> 1
         9-16   -> 2
         17-24 -> 3
         ...
        */
        if prefix_len == 0 {
            0
        } else {
            1 + (prefix_len as usize - 1) / 8
        }
    }

    pub fn address(&self) -> &IpNet {
        &self.0
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsIpReachabilityInformationData {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::most_significant_bytes(self.address().prefix_len())
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        writer.write_u8(self.address().prefix_len())?;

        // FIXME no way this works, check if significant bytes are at the beginning or not
        match self.address().network() {
            IpAddr::V4(ipv4) => {
                writer.write_all(&ipv4.octets()[..Self::most_significant_bytes(self.address().prefix_len())])?;
            }
            IpAddr::V6(ipv6) => {
                writer.write_all(&ipv6.octets()[..Self::most_significant_bytes(self.address().prefix_len())])?;
            }
        };

        Ok(())
    }
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsPrefixDescriptorTlv {
    MultiTopologyIdentifier(MultiTopologyIdData),
    OspfRouteType(OspfRouteType),
    IpReachabilityInformation(BgpLsIpReachabilityInformationData),
}

impl BgpLsPrefixDescriptorTlv {
    pub fn get_type(&self) -> iana::BgpLsPrefixDescriptorTlv {
        match self {
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(..) => iana::BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier,
            BgpLsPrefixDescriptorTlv::OspfRouteType(_) => iana::BgpLsPrefixDescriptorTlv::OspfRouteType,
            BgpLsPrefixDescriptorTlv::IpReachabilityInformation(_) => iana::BgpLsPrefixDescriptorTlv::IpReachabilityInformation,
        }
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsPrefixDescriptorTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(data) => { data.len() }
            BgpLsPrefixDescriptorTlv::OspfRouteType(_) => {
                1 /* OSPF Route Type */
            }
            BgpLsPrefixDescriptorTlv::IpReachabilityInformation(ip_reachability) => {
                1 /* Prefix Length */
                    + ip_reachability.len()
            }
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;
        match self {
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(data) => data.write(writer)?,
            BgpLsPrefixDescriptorTlv::OspfRouteType(data) => writer.write_u8(*data as u8)?,
            BgpLsPrefixDescriptorTlv::IpReachabilityInformation(data) => data.write(writer)?,
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpLsNlriNode {
    protocol_id: BgpLsProtocolId,
    identifier: u64,
    local_node_descriptors_tlvs: Vec<BgpLsNodeDescriptorTlv>,
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriNode {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        for tlv in &self.local_node_descriptors_tlvs {
            tlv.write(writer)?
        }

        Ok(())
    }
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsNodeDescriptorTlv {
    Local(Vec<BgpLsNodeDescriptorSubTlv>),
    Remote(Vec<BgpLsNodeDescriptorSubTlv>),
}

impl BgpLsNodeDescriptorTlv {
    pub fn get_type(&self) -> BgpLsDescriptorTlvs {
        match self {
            BgpLsNodeDescriptorTlv::Local(_) => LocalNodeDescriptor,
            BgpLsNodeDescriptorTlv::Remote(_) => RemoteNodeDescriptor
        }
    }

    pub fn subtlvs(&self) -> &[BgpLsNodeDescriptorSubTlv] {
        match self {
            BgpLsNodeDescriptorTlv::Local(subtlvs)
            | BgpLsNodeDescriptorTlv::Remote(subtlvs) => subtlvs
        }
    }

    pub fn subtlvs_len(&self) -> usize {
        self.subtlvs().iter().map(|tlv| tlv.len()).sum()
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNodeDescriptorTlv {
    const BASE_LENGTH: usize = 4; /* tlv type 16bits + tlv length 16bits */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.subtlvs_len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;
        for tlv in self.subtlvs() {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsLinkDescriptorTlv {
    LinkLocalRemoteIdentifiers {
        link_local_identifier: u32,
        link_remote_identifier: u32,
    },
    IPv4InterfaceAddress(Ipv4Addr),
    IPv4NeighborAddress(Ipv4Addr),

    /// MUST NOT be local-link
    IPv6InterfaceAddress(Ipv6Addr),

    /// MUST NOT be local-link
    IPv6NeighborAddress(Ipv6Addr),
    MultiTopologyIdentifier(MultiTopologyIdData),
}

impl BgpLsLinkDescriptorTlv {
    pub fn get_type(&self) -> iana::BgpLsLinkDescriptorTlv {
        match self {
            BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers { .. } => iana::BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers,
            BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(..) => iana::BgpLsLinkDescriptorTlv::IPv4InterfaceAddress,
            BgpLsLinkDescriptorTlv::IPv4NeighborAddress(..) => iana::BgpLsLinkDescriptorTlv::IPv4NeighborAddress,
            BgpLsLinkDescriptorTlv::IPv6InterfaceAddress(..) => iana::BgpLsLinkDescriptorTlv::IPv6InterfaceAddress,
            BgpLsLinkDescriptorTlv::IPv6NeighborAddress(..) => iana::BgpLsLinkDescriptorTlv::IPv6NeighborAddress,
            BgpLsLinkDescriptorTlv::MultiTopologyIdentifier(..) => iana::BgpLsLinkDescriptorTlv::MultiTopologyIdentifier,
        }
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsLinkDescriptorTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH +
            match self {
                BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers { .. } => 8,
                BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(..) => 4,
                BgpLsLinkDescriptorTlv::IPv4NeighborAddress(..) => 4,
                BgpLsLinkDescriptorTlv::IPv6InterfaceAddress(..) => 16,
                BgpLsLinkDescriptorTlv::IPv6NeighborAddress(..) => 16,
                BgpLsLinkDescriptorTlv::MultiTopologyIdentifier(data) => data.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;

        match self {
            BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers { link_local_identifier, link_remote_identifier } => {
                writer.write_u32::<NetworkEndian>(*link_local_identifier)?;
                writer.write_u32::<NetworkEndian>(*link_remote_identifier)?;
            }
            BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(ipv4) => writer.write_u32::<NetworkEndian>((*ipv4).into())?,
            BgpLsLinkDescriptorTlv::IPv4NeighborAddress(ipv4) => writer.write_u32::<NetworkEndian>((*ipv4).into())?,
            BgpLsLinkDescriptorTlv::IPv6InterfaceAddress(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsLinkDescriptorTlv::IPv6NeighborAddress(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsLinkDescriptorTlv::MultiTopologyIdentifier(data) => data.write(writer)?
        };

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsNodeDescriptorSubTlv {
    AutonomousSystem(u32),
    BgpLsIdentifier(u32),
    OspfAreaId(u32),
    IgpRouterId(Vec<u8>), // TODO add types for all possible cases (https://datatracker.ietf.org/doc/html/rfc7752)
}

impl BgpLsNodeDescriptorSubTlv {
    fn get_type(&self) -> iana::BgpLsNodeDescriptorSubTlv {
        match self {
            BgpLsNodeDescriptorSubTlv::AutonomousSystem(_) => iana::BgpLsNodeDescriptorSubTlv::AutonomousSystem,
            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(_) => iana::BgpLsNodeDescriptorSubTlv::BgpLsIdentifier,
            BgpLsNodeDescriptorSubTlv::OspfAreaId(_) => iana::BgpLsNodeDescriptorSubTlv::OspfAreaId,
            BgpLsNodeDescriptorSubTlv::IgpRouterId(_) => iana::BgpLsNodeDescriptorSubTlv::IgpRouterId,
        }
    }
}

impl WritablePdu<BgpLsWritingError> for BgpLsNodeDescriptorSubTlv {
    const BASE_LENGTH: usize = 4; /* tlv type u16 + tlv length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH +
            match self {
                BgpLsNodeDescriptorSubTlv::AutonomousSystem(_) => 4,
                BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(_) => 4,
                BgpLsNodeDescriptorSubTlv::OspfAreaId(_) => 4,
                BgpLsNodeDescriptorSubTlv::IgpRouterId(inner) => inner.len()
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        write_tlv_header(writer, self.get_type() as u16, self.len() as u16)?;
        match self {
            BgpLsNodeDescriptorSubTlv::AutonomousSystem(data) => writer.write_u32::<NetworkEndian>(*data)?,
            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(data) => writer.write_u32::<NetworkEndian>(*data)?,
            BgpLsNodeDescriptorSubTlv::OspfAreaId(data) => writer.write_u32::<NetworkEndian>(*data)?,
            BgpLsNodeDescriptorSubTlv::IgpRouterId(data) => writer.write_all(data)?,
        };

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpLsNlriLink {
    protocol_id: BgpLsProtocolId,
    identifier: u64,
    local_node_descriptor_tlvs: Vec<BgpLsNodeDescriptorTlv>,
    remote_node_descriptor_tlvs: Vec<BgpLsNodeDescriptorTlv>,
    link_descriptor_tlvs: Vec<BgpLsLinkDescriptorTlv>,
}

impl WritablePdu<BgpLsWritingError> for BgpLsNlriLink {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptor_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.remote_node_descriptor_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.link_descriptor_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        writer.write_u16::<NetworkEndian>(self.protocol_id as u16)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        for tlv in &self.local_node_descriptor_tlvs {
            tlv.write(writer)?;
        }

        for tlv in &self.remote_node_descriptor_tlvs {
            tlv.write(writer)?;
        }

        for tlv in &self.link_descriptor_tlvs {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultiTopologyIdData(Vec<MultiTopologyId>);

impl From<Vec<MultiTopologyId>> for MultiTopologyIdData {
    fn from(value: Vec<MultiTopologyId>) -> Self {
        Self(value)
    }
}

impl MultiTopologyIdData {
    pub fn id_count(&self) -> usize {
        self.0.len()
    }
}

impl WritablePdu<BgpLsWritingError> for MultiTopologyIdData {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        2 * self.id_count()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        for id in &self.0 {
            id.write(writer)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum MultiTopologyId {
    Ospf(OspfMtId),
    IsIs(IsIsMtId),
}

impl MultiTopologyId {
    pub fn value(&self) -> u16 {
        match self {
            MultiTopologyId::Ospf(mtid) => mtid.0 as u16,
            MultiTopologyId::IsIs(mtid) => mtid.0,
        }
    }
}

#[derive(Debug, Display)]
pub enum BgpLsMtIdError {
    OspfMtIdInvalidValue(OspfMtId),
    IsIsMtIdInvalidValue(IsIsMtId),
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OspfMtId(u8);

impl OspfMtId {
    const OSPF_MTID_MAX: u8 = 127;
    pub fn new(mtid: u8) -> Result<Self, BgpLsMtIdError> {
        if mtid > Self::OSPF_MTID_MAX {
            Err(OspfMtIdInvalidValue(Self(mtid)))
        } else {
            Ok(Self(mtid))
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IsIsMtId(u16);

impl IsIsMtId {
    const ISIS_MTID_MAX: u16 = 4095;
    const ISIS_MTID_RESERVED: u16 = 0;

    pub fn new(mtid: u16) -> Result<Self, BgpLsMtIdError> {
        if mtid == Self::ISIS_MTID_RESERVED || mtid > Self::ISIS_MTID_MAX {
            Err(IsIsMtIdInvalidValue(Self(mtid)))
        } else {
            Ok(Self(mtid))
        }
    }
}

impl WritablePdu<BgpLsWritingError> for MultiTopologyId {
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsWritingError> where Self: Sized {
        writer.write_u16::<NetworkEndian>(self.value())?;

        Ok(())
    }
}

/// TODO unimplemented: figure out what
///  "In Link-State NLRI, both IPv4 and IPv6 SRLG information are carried in a single TLV."
///  means (https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.5)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SharedRiskLinkGroupValue(u32);

impl SharedRiskLinkGroupValue {
    fn value(&self) -> u32 {
        self.0
    }
}

#[test]
fn test_bgp_ls() {}