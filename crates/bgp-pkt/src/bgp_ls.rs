// TODO BGP-LS Attribute
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use byteorder::{NetworkEndian, WriteBytesExt};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, FromRepr};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use crate::bgp_ls::BgpLsMtIdError::{IsIsMtIdInvalidValue, OspfMtIdInvalidValue};
use crate::iana;
use crate::iana::BgpLsDescriptorTlvs::{LocalNodeDescriptor, RemoteNodeDescriptor};
use crate::iana::{BgpLsDescriptorTlvs, BgpLsProtocolId};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
pub enum BgpLsNlriWritingError {
    StdIoError(#[from_std_io_error] String)
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlri {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        match self {
            BgpLsNlri::Node(data) => data.len(),
            BgpLsNlri::Link(data) => data.len(),
            BgpLsNlri::Ipv4Prefix(data) => data.len(),
            BgpLsNlri::Ipv6Prefix(data) => data.len(),
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriIpPrefix {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.prefix_descriptors.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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
/// `tlv_length` : tlv length on the wire (as reported by the writer <=> including type and length fields)
///
/// Written length field will be `tlv_length - 4`
fn write_tlv_header<T: Write>(writer: &mut T, tlv_type: u16, tlv_length: u16) -> Result<(), BgpLsNlriWritingError> {
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsIpReachabilityInformationData {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        Self::most_significant_bytes(self.address().prefix_len())
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsPrefixDescriptorTlv {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriNode {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptors_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        for tlv in &self.local_node_descriptors_tlvs {
            tlv.write(writer)?
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNodeDescriptorTlv {
    const BASE_LENGTH: usize = 4; /* tlv type 16bits + tlv length 16bits */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.subtlvs_len()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsLinkDescriptorTlv {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNodeDescriptorSubTlv {
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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriLink {
    const BASE_LENGTH: usize = 1 /* protocol_id */ + 8 /* identifier */;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self.local_node_descriptor_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.remote_node_descriptor_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.link_descriptor_tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

impl WritablePdu<BgpLsNlriWritingError> for MultiTopologyIdData {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        2 * self.id_count()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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

impl WritablePdu<BgpLsNlriWritingError> for MultiTopologyId {
    const BASE_LENGTH: usize = 2;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
        writer.write_u16::<NetworkEndian>(self.value())?;

        Ok(())
    }
}


#[test]
fn test_bgp_ls() {}