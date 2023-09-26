// TODO do not forget MT-ID TLV

use std::io::Write;
use std::net::IpAddr;
use byteorder::{NetworkEndian, WriteBytesExt};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, FromRepr};
use netgauze_parse_utils::WritablePdu;
use netgauze_serde_macros::WritingError;
use crate::iana::BgpLsProtocolId;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsNlri {
    Node(BgpLsNodeNlriData),
    Link(BgpLsLinkNlriData),
    Ipv4Prefix(BgpLsIpPrefixData),
    Ipv6Prefix(BgpLsIpPrefixData),
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
pub struct BgpLsIpPrefixData {
    protocol_id: BgpLsProtocolId,
    identifier: u64,
    local_node_descriptors: Vec<BgpLsNodeDescriptor>,
    prefix_descriptors: Vec<BgpLsPrefixDescriptor>,
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsIpPrefixData {
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


// TODO does this go into IANA?
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum OspfRouteType {
    IntraArea = 1,
    InterArea = 2,
    External1 = 3,
    External2 = 4,
    NSSA1 = 5,
    NSSA2 = 6,
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
pub enum BgpLsPrefixDescriptor {
    MultiTopologyIdentifier(),
    OspfRouteType(OspfRouteType),
    IpReachabilityInformation(BgpLsIpReachabilityInformationData),
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsPrefixDescriptor {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        match self {
            BgpLsPrefixDescriptor::MultiTopologyIdentifier() => { unimplemented!() }
            BgpLsPrefixDescriptor::OspfRouteType(_) => {
                1 /* OSPF Route Type */
            }
            BgpLsPrefixDescriptor::IpReachabilityInformation(ip_reachability) => {
                1 /* Prefix Length */
                    + ip_reachability.len()
            }
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
        match self {
            BgpLsPrefixDescriptor::MultiTopologyIdentifier() => unimplemented!(),
            BgpLsPrefixDescriptor::OspfRouteType(data) => writer.write_u8(*data as u8)?,
            BgpLsPrefixDescriptor::IpReachabilityInformation(data) => data.write(writer)?,
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpLsNodeNlriData {
    protocol_id: BgpLsProtocolId,
    identifier: u64,
    local_descriptors_tlv: Vec<BgpLsNodeDescriptor>,
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNodeNlriData {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        1 /* protocol_id */
            + 8 /* identifier */
            + self.local_descriptors_tlv.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
        writer.write_u8(self.protocol_id as u8)?;
        writer.write_u64::<NetworkEndian>(self.identifier)?;
        for tlv in &self.local_descriptors_tlv {
            tlv.write(writer)?
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpLsNodeDescriptor {
    node_descriptor_subtlvs: Vec<BgpLsNodeDescriptorSubTlv>,
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNodeDescriptor {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        self.node_descriptor_subtlvs.iter().map(|tlv| tlv.len()).sum()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
        for tlv in &self.node_descriptor_subtlvs {
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

impl WritablePdu<BgpLsNlriWritingError> for BgpLsNodeDescriptorSubTlv {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        match self {
            BgpLsNodeDescriptorSubTlv::AutonomousSystem(_) => 4,
            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(_) => 4,
            BgpLsNodeDescriptorSubTlv::OspfAreaId(_) => 4,
            BgpLsNodeDescriptorSubTlv::IgpRouterId(inner) => inner.len()
        }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsNlriWritingError> where Self: Sized {
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
pub struct BgpLsLinkNlriData {
    protocol_id: BgpLsProtocolId,
    identifier: u64,
    local_descriptors_tlv: Vec<BgpLsNodeDescriptor>,
    remote_descriptors_tlv: Vec<BgpLsNodeDescriptor>,
    link_descriptors_tlv: Vec<BgpLsLinkDescriptor>,
}

impl WritablePdu<BgpLsNlriWritingError> for BgpLsLinkNlriData {
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