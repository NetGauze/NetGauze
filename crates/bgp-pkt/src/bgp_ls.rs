// TODO do not forget MT-ID TLV

use std::io::Write;
use std::net::IpAddr;
use byteorder::{NetworkEndian, WriteBytesExt};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, FromRepr};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
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
    // TODO find the use of BASE_LENGTH
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        1 /* protocol_id */
            + 8 /* identifier */
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
/// tlv_type : tlv code point
/// tlv_length : tlv length on the wire (as reported by the writer <=> including type and length fields)
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
    MultiTopologyIdentifier(),
    OspfRouteType(OspfRouteType),
    IpReachabilityInformation(BgpLsIpReachabilityInformationData),
}

impl BgpLsPrefixDescriptorTlv {
    pub fn get_type(&self) -> iana::BgpLsPrefixDescriptorTlv {
        match self {
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier() => iana::BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier,
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
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier() => { unimplemented!() }
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
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier() => unimplemented!(),
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
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        1 /* protocol_id */
            + 8 /* identifier */
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
pub enum BgpLsLinkDescriptor {
    // TODO
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsLinkDescriptor {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        unimplemented!()
    }

    fn write<T: Write>(&self, _writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
        unimplemented!()
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
    local_descriptors_tlv: Vec<BgpLsNodeDescriptorTlv>,
    remote_descriptors_tlv: Vec<BgpLsNodeDescriptorTlv>,
    link_descriptors_tlv: Vec<BgpLsLinkDescriptor>,
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNlriLink {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        1 /* protocol_id */
            + 8 /* identifier */
            + self.local_descriptors_tlv.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.remote_descriptors_tlv.iter().map(|tlv| tlv.len()).sum::<usize>()
            + self.link_descriptors_tlv.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
        writer.write_u16::<NetworkEndian>(self.protocol_id as u16)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;

        for tlv in &self.local_descriptors_tlv {
            tlv.write(writer)?;
        }

        for tlv in &self.remote_descriptors_tlv {
            tlv.write(writer)?;
        }

        for tlv in &self.link_descriptors_tlv {
            tlv.write(writer)?;
        }

        Ok(())
    }
}


#[test]
fn test_bgp_ls() {}