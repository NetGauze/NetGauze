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

use crate::iana;
use crate::iana::{
    BgpLsLinkDescriptorType, BgpLsNlriType, BgpLsNodeDescriptorSubType, BgpLsNodeDescriptorType,
    BgpLsNodeDescriptorTypeError, BgpLsPrefixDescriptorType, BgpLsProtocolIdError, IanaValueError,
    LinkDescriptorTypeError, NodeDescriptorSubTypeError, PrefixDescriptorTypeError,
};
use crate::nlri::{
    BgpLsLinkDescriptor, BgpLsLocalNodeDescriptors, BgpLsNlri, BgpLsNlriIpPrefix, BgpLsNlriLink,
    BgpLsNlriNode, BgpLsNlriValue, BgpLsNodeDescriptorSubTlv, BgpLsNodeDescriptors,
    BgpLsPrefixDescriptor, BgpLsRemoteNodeDescriptors, BgpLsVpnNlri, IpReachabilityInformationData,
    MultiTopologyId, MultiTopologyIdData, OspfRouteType, RouteDistinguisher,
};
use crate::wire::deserializer::nlri::RouteDistinguisherParsingError;
use crate::wire::deserializer::read_tlv_header_t16_l16;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use netgauze_parse_utils::common::{Ipv4PrefixParsingError, Ipv6PrefixParsingError};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};

/// BGP Link-State NLRI Parsing Errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpLsNlriParsingError {
    #[error("BGP-LS NLRI parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("BGP-LS unknown NLRI type {code} at {offset}")]
    UnknownNlriType { offset: usize, code: u16 },
    #[error("BGP-LS NLRI error {0}")]
    RouteDistinguisherParsingError(#[from] RouteDistinguisherParsingError),
    #[error("BGP-LS NLRI unknown protocol ID {error} at offset {offset}")]
    UnknownProtocolId {
        offset: usize,
        error: BgpLsProtocolIdError,
    },
    #[error("BGP-LS NLRI unknown descriptor TLV type {error} at offset {offset}")]
    UnknownDescriptorTlvType {
        offset: usize,
        error: BgpLsNodeDescriptorTypeError,
    },
    #[error("BGP-LS NLRI unknown node descriptor sub-TLV type {error} at offset {offset}")]
    UnknownNodeDescriptorSubTlvType {
        offset: usize,
        error: NodeDescriptorSubTypeError,
    },
    #[error("BGP-LS NLRI unknown node descriptor TLV type {error} at offset {offset}")]
    UnknownPrefixDescriptorTlvType {
        offset: usize,
        error: PrefixDescriptorTypeError,
    },
    #[error("BGP-LS NLRI unknown OSPF route type {code} at offset {offset}")]
    UnknownOspfRouteType { offset: usize, code: u8 },
    #[error("BGP-LS NLRI bad node descriptor TLV type {code} at offset {offset}")]
    BadNodeDescriptorTlvType {
        offset: usize,
        code: BgpLsNodeDescriptorType,
    },
    #[error("BGP-LS NLRI error unknown link descriptor TLV type {error} at offset {offset}")]
    UnknownLinkDescriptorTlvType {
        offset: usize,
        error: LinkDescriptorTypeError,
    },
    #[error("BGP-LS NLRI error bad TLV type {code} offset {offset}")]
    BadTlvTypeInNlri { offset: usize, code: BgpLsNlriType },
    #[error("BGP-LS NLRI error: {0}")]
    Ipv4PrefixError(#[from] Ipv4PrefixParsingError),
    #[error("BGP-LS NLRI error: {0}")]
    Ipv6PrefixError(#[from] Ipv6PrefixParsingError),
    #[error("BGP-LS NLRI error: {0}")]
    MultiTopologyIdDataError(#[from] MultiTopologyIdDataParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for BgpLsNlri {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let nlri_type = cur.read_u16_be()?;
        let nlri_type = BgpLsNlriType::try_from(nlri_type).map_err(|code| {
            BgpLsNlriParsingError::UnknownNlriType {
                offset: cur.offset() - 4,
                code: code.0,
            }
        })?;
        let nlri_len = cur.read_u16_be()?;
        let mut data = cur.take_slice(nlri_len as usize)?;
        let value = BgpLsNlriValue::parse(&mut data, nlri_type)?;
        Ok(BgpLsNlri { path_id, value })
    }
}

impl<'a> ParseFromWithOneInput<'a, bool> for BgpLsVpnNlri {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };

        let nlri_type = cur.read_u16_be()?;
        let nlri_type = BgpLsNlriType::try_from(nlri_type).map_err(|code| {
            BgpLsNlriParsingError::UnknownNlriType {
                offset: cur.offset() - 4,
                code: code.0,
            }
        })?;
        let nlri_len = cur.read_u16_be()?;
        let mut data = cur.take_slice(nlri_len as usize)?;
        let rd = RouteDistinguisher::parse(&mut data)?;
        let value = BgpLsNlriValue::parse(&mut data, nlri_type)?;
        Ok(BgpLsVpnNlri { path_id, rd, value })
    }
}

impl<'a> ParseFromWithOneInput<'a, BgpLsNlriType> for BgpLsNlriValue {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>, nlri_type: BgpLsNlriType) -> Result<Self, Self::Error> {
        let result = match nlri_type {
            BgpLsNlriType::Node => {
                let nlri_value = BgpLsNlriNode::parse(cur)?;
                BgpLsNlriValue::Node(nlri_value)
            }
            BgpLsNlriType::Link => {
                let nlri_value = BgpLsNlriLink::parse(cur)?;
                BgpLsNlriValue::Link(nlri_value)
            }
            BgpLsNlriType::Ipv4TopologyPrefix => {
                let nlri_value = BgpLsNlriIpPrefix::parse(cur, BgpLsNlriType::Ipv4TopologyPrefix)?;
                BgpLsNlriValue::Ipv4Prefix(nlri_value)
            }
            BgpLsNlriType::Ipv6TopologyPrefix => {
                let nlri_value = BgpLsNlriIpPrefix::parse(cur, BgpLsNlriType::Ipv6TopologyPrefix)?;
                BgpLsNlriValue::Ipv6Prefix(nlri_value)
            }
            BgpLsNlriType::TePolicy | BgpLsNlriType::Srv6Sid => {
                let value = cur.read_bytes(cur.remaining())?;
                BgpLsNlriValue::Unknown {
                    code: nlri_type.into(),
                    value: value.to_vec(),
                }
            }
        };

        Ok(result)
    }
}

impl<'a> ParseFrom<'a> for BgpLsNlriLink {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let protocol_id = cur.read_u8()?;
        let protocol_id = iana::BgpLsProtocolId::try_from(protocol_id).map_err(|error| {
            BgpLsNlriParsingError::UnknownProtocolId {
                offset: cur.offset() - 1,
                error,
            }
        })?;

        let identifier = cur.read_u64_be()?;
        let local_node_descriptors = BgpLsLocalNodeDescriptors::parse(cur)?;
        let remote_node_descriptors = BgpLsRemoteNodeDescriptors::parse(cur)?;
        let mut link_descriptors = Vec::new();
        while cur.remaining() > 0 {
            let link_descriptor = BgpLsLinkDescriptor::parse(cur)?;
            link_descriptors.push(link_descriptor);
        }

        Ok(BgpLsNlriLink {
            protocol_id,
            identifier,
            local_node_descriptors,
            remote_node_descriptors,
            link_descriptors,
        })
    }
}

impl<'a> ParseFrom<'a> for BgpLsLinkDescriptor {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (tlv_type, _tlv_length, mut data) =
            read_tlv_header_t16_l16::<BgpLsNlriParsingError>(cur)?;
        let tlv_type = match BgpLsLinkDescriptorType::try_from(tlv_type) {
            Ok(value) => value,
            Err(LinkDescriptorTypeError(IanaValueError::Unknown(value))) => {
                return Ok(BgpLsLinkDescriptor::Unknown {
                    code: value,
                    value: data.read_bytes(data.remaining())?.to_vec(),
                });
            }
            Err(error) => {
                return Err(BgpLsNlriParsingError::UnknownLinkDescriptorTlvType { offset, error });
            }
        };
        let tlv = match tlv_type {
            BgpLsLinkDescriptorType::LinkLocalRemoteIdentifiers => {
                let link_local_identifier = data.read_u32_be()?;
                let link_remote_identifier = data.read_u32_be()?;
                BgpLsLinkDescriptor::LinkLocalRemoteIdentifiers {
                    link_local_identifier,
                    link_remote_identifier,
                }
            }
            BgpLsLinkDescriptorType::IPv4InterfaceAddress => {
                let ipv4 = data.read_u32_be()?;
                BgpLsLinkDescriptor::IPv4InterfaceAddress(Ipv4Addr::from(ipv4))
            }
            BgpLsLinkDescriptorType::IPv4NeighborAddress => {
                let ipv4 = data.read_u32_be()?;
                BgpLsLinkDescriptor::IPv4NeighborAddress(Ipv4Addr::from(ipv4))
            }
            BgpLsLinkDescriptorType::IPv6InterfaceAddress => {
                let ipv6 = data.read_u128_be()?;
                // TODO CHECK NOT LOCAL-LINK
                BgpLsLinkDescriptor::IPv6InterfaceAddress(Ipv6Addr::from(ipv6))
            }
            BgpLsLinkDescriptorType::IPv6NeighborAddress => {
                let ipv6 = data.read_u128_be()?;
                // TODO CHECK NOT LOCAL-LINK
                BgpLsLinkDescriptor::IPv6NeighborAddress(Ipv6Addr::from(ipv6))
            }
            BgpLsLinkDescriptorType::MultiTopologyIdentifier => {
                let mtid = MultiTopologyIdData::parse(&mut data)?;
                BgpLsLinkDescriptor::MultiTopologyIdentifier(mtid)
            }
        };
        Ok(tlv)
    }
}

impl<'a> ParseFrom<'a> for BgpLsNlriNode {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let protocol_id = iana::BgpLsProtocolId::try_from(cur.read_u8()?)
            .map_err(|error| BgpLsNlriParsingError::UnknownProtocolId { offset, error })?;
        let identifier = cur.read_u64_be()?;
        let local_node_descriptors = BgpLsLocalNodeDescriptors::parse(cur)?;

        Ok(BgpLsNlriNode {
            protocol_id,
            identifier,
            local_node_descriptors,
        })
    }
}

impl<'a> ParseFrom<'a> for BgpLsLocalNodeDescriptors {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let value = BgpLsNodeDescriptors::parse(cur, BgpLsNodeDescriptorType::LocalNodeDescriptor)?;
        Ok(BgpLsLocalNodeDescriptors(value))
    }
}

impl<'a> ParseFrom<'a> for BgpLsRemoteNodeDescriptors {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let value =
            BgpLsNodeDescriptors::parse(cur, BgpLsNodeDescriptorType::RemoteNodeDescriptor)?;
        Ok(BgpLsRemoteNodeDescriptors(value))
    }
}

impl<'a> ParseFromWithOneInput<'a, BgpLsNodeDescriptorType> for BgpLsNodeDescriptors {
    type Error = BgpLsNlriParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        input: BgpLsNodeDescriptorType,
    ) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let tlv_type = BgpLsNodeDescriptorType::try_from(cur.read_u16_be()?)
            .map_err(|error| BgpLsNlriParsingError::UnknownDescriptorTlvType { offset, error })?;

        if tlv_type != input {
            return Err(BgpLsNlriParsingError::BadNodeDescriptorTlvType {
                offset,
                code: tlv_type,
            });
        }

        let tlv_length = cur.read_u16_be()?;
        let mut data = cur.take_slice(tlv_length as usize)?;

        let mut subtlvs = Vec::new();
        while !data.is_empty() {
            let subtlv = BgpLsNodeDescriptorSubTlv::parse(&mut data)?;
            subtlvs.push(subtlv);
        }

        Ok(BgpLsNodeDescriptors(subtlvs))
    }
}

impl<'a> ParseFrom<'a> for BgpLsNodeDescriptorSubTlv {
    type Error = BgpLsNlriParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (tlv_type, _tlv_length, mut data) =
            read_tlv_header_t16_l16::<BgpLsNlriParsingError>(cur)?;
        let tlv_type = match BgpLsNodeDescriptorSubType::try_from(tlv_type) {
            Ok(value) => value,
            Err(NodeDescriptorSubTypeError(IanaValueError::Unknown(value))) => {
                return Ok(BgpLsNodeDescriptorSubTlv::Unknown {
                    code: value,
                    value: data.read_bytes(data.remaining())?.to_vec(),
                });
            }
            Err(error) => {
                return Err(BgpLsNlriParsingError::UnknownNodeDescriptorSubTlvType {
                    offset,
                    error,
                });
            }
        };

        let result = match tlv_type {
            BgpLsNodeDescriptorSubType::AutonomousSystem => {
                let value = data.read_u32_be()?;
                BgpLsNodeDescriptorSubTlv::AutonomousSystem(value)
            }
            BgpLsNodeDescriptorSubType::BgpLsIdentifier => {
                let value = data.read_u32_be()?;
                BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(value)
            }
            BgpLsNodeDescriptorSubType::OspfAreaId => {
                let value = data.read_u32_be()?;
                BgpLsNodeDescriptorSubTlv::OspfAreaId(value)
            }
            BgpLsNodeDescriptorSubType::IgpRouterId => {
                BgpLsNodeDescriptorSubTlv::IgpRouterId(data.read_bytes(data.remaining())?.to_vec())
            }
            BgpLsNodeDescriptorSubType::BgpRouterIdentifier => {
                let value = data.read_u32_be()?;
                BgpLsNodeDescriptorSubTlv::BgpRouterIdentifier(value)
            }
            BgpLsNodeDescriptorSubType::MemberAsNumber => {
                let value = data.read_u32_be()?;
                BgpLsNodeDescriptorSubTlv::MemberAsNumber(value)
            }
        };

        Ok(result)
    }
}

impl<'a> ParseFromWithOneInput<'a, BgpLsNlriType> for BgpLsNlriIpPrefix {
    type Error = BgpLsNlriParsingError;

    fn parse(cur: &mut SliceReader<'a>, nlri_type: BgpLsNlriType) -> Result<Self, Self::Error> {
        let protocol_id = iana::BgpLsProtocolId::try_from(cur.read_u8()?).map_err(|error| {
            BgpLsNlriParsingError::UnknownProtocolId {
                offset: cur.offset() - 1,
                error,
            }
        })?;
        let identifier = cur.read_u64_be()?;
        let local_node_descriptors = BgpLsLocalNodeDescriptors::parse(cur)?;
        let mut prefix_descriptors = Vec::new();
        while cur.remaining() > 0 {
            let descriptor = BgpLsPrefixDescriptor::parse(cur, nlri_type)?;
            prefix_descriptors.push(descriptor);
        }

        Ok(BgpLsNlriIpPrefix {
            protocol_id,
            identifier,
            local_node_descriptors,
            prefix_descriptors,
        })
    }
}

impl<'a> ParseFromWithOneInput<'a, BgpLsNlriType> for BgpLsPrefixDescriptor {
    type Error = BgpLsNlriParsingError;

    fn parse(cur: &mut SliceReader<'a>, nlri_type: BgpLsNlriType) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (tlv_type, _tlv_length, mut data) =
            read_tlv_header_t16_l16::<BgpLsNlriParsingError>(cur)?;

        let tlv_type = match BgpLsPrefixDescriptorType::try_from(tlv_type) {
            Ok(value) => value,
            Err(PrefixDescriptorTypeError(IanaValueError::Unknown(value))) => {
                return Ok(BgpLsPrefixDescriptor::Unknown {
                    code: value,
                    value: data.read_bytes(data.remaining())?.to_vec(),
                });
            }
            Err(error) => {
                return Err(BgpLsNlriParsingError::UnknownPrefixDescriptorTlvType {
                    offset,
                    error,
                });
            }
        };

        let tlv = match tlv_type {
            BgpLsPrefixDescriptorType::MultiTopologyIdentifier => {
                let mtid = MultiTopologyIdData::parse(&mut data)?;
                BgpLsPrefixDescriptor::MultiTopologyIdentifier(mtid)
            }
            BgpLsPrefixDescriptorType::OspfRouteType => {
                let ospf_route_type = OspfRouteType::parse(&mut data)?;
                BgpLsPrefixDescriptor::OspfRouteType(ospf_route_type)
            }
            BgpLsPrefixDescriptorType::IpReachabilityInformation => {
                let ip_reachability_info =
                    IpReachabilityInformationData::parse(&mut data, nlri_type)?;
                BgpLsPrefixDescriptor::IpReachabilityInformation(ip_reachability_info)
            }
        };

        Ok(tlv)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MultiTopologyIdDataParsingError {
    #[error("Multi-Topology ID data parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for MultiTopologyIdData {
    type Error = MultiTopologyIdDataParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let mut ids = Vec::new();
        while !cur.is_empty() {
            let id = MultiTopologyId::from(cur.read_u16_be()?);
            ids.push(id);
        }
        Ok(MultiTopologyIdData(ids))
    }
}

impl<'a> ParseFrom<'a> for MultiTopologyId {
    type Error = BgpLsNlriParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let id = MultiTopologyId::from(cur.read_u16_be()?);
        Ok(id)
    }
}

impl<'a> ParseFrom<'a> for OspfRouteType {
    type Error = BgpLsNlriParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let code = cur.read_u8()?;
        OspfRouteType::try_from(code).map_err(|error| BgpLsNlriParsingError::UnknownOspfRouteType {
            offset,
            code: error.0,
        })
    }
}

impl<'a> ParseFromWithOneInput<'a, BgpLsNlriType> for IpReachabilityInformationData {
    type Error = BgpLsNlriParsingError;

    fn parse(cur: &mut SliceReader<'a>, nlri_type: BgpLsNlriType) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        match nlri_type {
            BgpLsNlriType::Ipv4TopologyPrefix => {
                let ipv4 = <Ipv4Net as ParseFrom>::parse(cur)?;
                Ok(IpReachabilityInformationData(IpNet::V4(ipv4)))
            }
            BgpLsNlriType::Ipv6TopologyPrefix => {
                let ipv6 = <Ipv6Net as ParseFrom>::parse(cur)?;
                Ok(IpReachabilityInformationData(IpNet::V6(ipv6)))
            }
            BgpLsNlriType::Node
            | BgpLsNlriType::Link
            | BgpLsNlriType::TePolicy
            | BgpLsNlriType::Srv6Sid => Err(BgpLsNlriParsingError::BadTlvTypeInNlri {
                offset,
                code: nlri_type,
            }),
        }
    }
}
