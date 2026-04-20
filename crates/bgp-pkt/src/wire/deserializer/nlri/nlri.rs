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

use crate::iana::{L2EvpnRouteTypeCode, RouteDistinguisherTypeCode};
use crate::nlri::*;
use crate::wire::serializer::nlri::{
    IPV4_LEN_BITS, IPV6_LEN, IPV6_LEN_BITS, LABELED_IPV4_LEN, LABELED_IPV6_LEN,
    MAC_ADDRESS_LEN_BITS, MPLS_LABEL_LEN_BITS, RD_LEN,
};
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_parse_utils::common::{Ipv4PrefixParsingError, Ipv6PrefixParsingError};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::BytesReader;
use netgauze_parse_utils::traits::{
    ParseFrom, ParseFromWithOneInput, ParseFromWithThreeInputs, ParseFromWithTwoInputs,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP Prefix route type for IPv4 has the Length field set to 34
/// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
pub(crate) const L2_EVPN_IPV4_PREFIX_ROUTE_LEN: usize = 34;
/// An IP Prefix route type for IPv6 has the Length field set to 58
/// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
pub(crate) const L2_EVPN_IPV6_PREFIX_ROUTE_LEN: usize = 58;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MplsLabelParsingError {
    #[error("MPLS Label address parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for MplsLabel {
    type Error = MplsLabelParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let label: [u8; 3] = cur.read_array()?;
        Ok(MplsLabel::new(label))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteDistinguisherParsingError {
    #[error("Route Distinguisher parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Invalid Route Distinguisher `{code}` at offset {offset}")]
    UndefinedRouteDistinguisherTypeCode { offset: usize, code: u16 },

    #[error(
        "Invalid LeafAdRoutes at offset {offset}: {num1}:{num2}, LeafAdRoutes is expected to be all `1`"
    )]
    InvalidLeafAdRoutes { offset: usize, num1: u16, num2: u32 },
}

impl<'a> ParseFrom<'a> for RouteDistinguisher {
    type Error = RouteDistinguisherParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let rd_type = cur.read_u16_be()?;
        let rd_type = RouteDistinguisherTypeCode::try_from(rd_type).map_err(|error| {
            RouteDistinguisherParsingError::UndefinedRouteDistinguisherTypeCode {
                offset,
                code: error.0,
            }
        })?;

        match rd_type {
            RouteDistinguisherTypeCode::As2Administrator => {
                let asn2 = cur.read_u16_be()?;
                let number = cur.read_u32_be()?;
                Ok(RouteDistinguisher::As2Administrator { asn2, number })
            }
            RouteDistinguisherTypeCode::Ipv4Administrator => {
                let ip = cur.read_u32_be()?;
                let ip = Ipv4Addr::from(ip);
                let number = cur.read_u16_be()?;
                Ok(RouteDistinguisher::Ipv4Administrator { ip, number })
            }
            RouteDistinguisherTypeCode::As4Administrator => {
                let asn4 = cur.read_u32_be()?;
                let number = cur.read_u16_be()?;
                Ok(RouteDistinguisher::As4Administrator { asn4, number })
            }
            RouteDistinguisherTypeCode::LeafAdRoutes => {
                let num1 = cur.read_u16_be()?;
                let num2 = cur.read_u32_be()?;
                if num1 != u16::MAX || num2 != u32::MAX {
                    Err(RouteDistinguisherParsingError::InvalidLeafAdRoutes { offset, num1, num2 })
                } else {
                    Ok(RouteDistinguisher::LeafAdRoutes)
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LabeledIpv4NextHopParsingError {
    #[error("Labeled IPv4 parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Invalid Labeled IPv4 Next Hop: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
}

impl<'a> ParseFrom<'a> for LabeledIpv4NextHop {
    type Error = LabeledIpv4NextHopParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let ip = cur.read_u32_be()?;
        let ip = Ipv4Addr::from(ip);
        Ok(LabeledIpv4NextHop::new(rd, ip))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LabeledIpv6NextHopParsingError {
    #[error("Labeled IPv6 Next Hop parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Invalid Labeled IPv6 Next Hop: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
}

impl<'a> ParseFrom<'a> for LabeledIpv6NextHop {
    type Error = LabeledIpv6NextHopParsingError;

    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let ip = cur.read_u128_be()?;
        let next_hop = Ipv6Addr::from(ip);
        let local = if cur.remaining() == IPV6_LEN as usize {
            let ip = cur.read_u128_be()?;
            Some(Ipv6Addr::from(ip))
        } else {
            None
        };
        Ok(LabeledIpv6NextHop::new(rd, next_hop, local))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LabeledNextHopParsingError {
    #[error("Labeled Next Hop parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Label next hop invalid length {len} at offset {offset}")]
    InvalidLength { offset: usize, len: u8 },

    #[error("Invalid Labeled Next Hop: {0}")]
    LabeledIpv4NextHopError(#[from] LabeledIpv4NextHopParsingError),

    #[error("Invalid Labeled Next Hop: {0}")]
    LabeledIpv6NextHopError(#[from] LabeledIpv6NextHopParsingError),
}

impl<'a> ParseFrom<'a> for LabeledNextHop {
    type Error = LabeledNextHopParsingError;

    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        let mut address_buf = cur.take_slice(prefix_len as usize)?;
        if prefix_len == LABELED_IPV4_LEN {
            let labeled_ipv4 = LabeledIpv4NextHop::parse(&mut address_buf)?;
            Ok(LabeledNextHop::Ipv4(labeled_ipv4))
        } else if prefix_len == LABELED_IPV6_LEN {
            let labeled_ipv6 = LabeledIpv6NextHop::parse(&mut address_buf)?;
            Ok(LabeledNextHop::Ipv6(labeled_ipv6))
        } else {
            Err(LabeledNextHopParsingError::InvalidLength {
                offset,
                len: prefix_len,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4MplsVpnUnicastAddressParsingError {
    #[error("IPv4 MPLS VPN Unicast address parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Invalid IPv4 MPLS VPN Unicast address prefix length: {len} at offset {offset}")]
    InvalidLength { offset: usize, len: u8 },

    #[error("Invalid IPv4 MPLS VPN Unicast address: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),

    #[error("Invalid IPv4 MPLS VPN Unicast address: {0}")]
    Ipv4UnicastError(#[from] Ipv4UnicastParsingError),

    #[error("Invalid IPv4 MPLS VPN Unicast address: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),
}

impl<'a> ParseFromWithThreeInputs<'a, bool, bool, u8> for Ipv4MplsVpnUnicastAddress {
    type Error = Ipv4MplsVpnUnicastAddressParsingError;
    fn parse(
        cur: &mut BytesReader,
        add_path: bool,
        is_unreach: bool,
        multiple_labels_limit: u8,
    ) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        let prefix_bytes = if prefix_len > u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        // consuming only the bytes specified by the prefix length field, since MPLS
        // stack is read until the last bit is set.
        let mut prefix_buf = cur.take_slice(prefix_bytes as usize)?;
        let label_stack =
            parse_mpls_label_stack(&mut prefix_buf, is_unreach, multiple_labels_limit)?;
        let rd = RouteDistinguisher::parse(&mut prefix_buf)?;
        let read_prefix = RD_LEN * 8 + label_stack.len() as u8 * MPLS_LABEL_LEN_BITS;
        // Check subtraction operation is safe first
        let remainder_prefix_len = match prefix_len.checked_sub(read_prefix) {
            None => {
                return Err(Ipv4MplsVpnUnicastAddressParsingError::InvalidLength {
                    offset,
                    len: prefix_len,
                });
            }
            Some(val) => val,
        };
        let network = <Ipv4Unicast as ParseFromWithTwoInputs<'_, _, _>>::parse(
            &mut prefix_buf,
            remainder_prefix_len,
            offset,
        )?;
        // Check all the bytes specified by the prefix length are consumed
        if !prefix_buf.is_empty() {
            return Err(Ipv4MplsVpnUnicastAddressParsingError::InvalidLength {
                offset,
                len: prefix_len,
            });
        }
        Ok(Ipv4MplsVpnUnicastAddress::new(
            path_id,
            rd,
            label_stack,
            network,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6MplsVpnUnicastAddressParsingError {
    #[error("IPv6 MPLS VPN Unicast address parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Invalid IPv6 MPLS VPN Unicast address: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),

    #[error("Invalid IPv6 MPLS VPN Unicast address: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),

    #[error("Invalid IPv6 MPLS VPN Unicast address prefix length: {len} at offset {offset}")]
    InvalidLength { offset: usize, len: u8 },

    #[error("Invalid IPv6 MPLS VPN Unicast address: {0}")]
    Ipv6UnicastError(#[from] Ipv6UnicastParsingError),
}

impl<'a> ParseFromWithThreeInputs<'a, bool, bool, u8> for Ipv6MplsVpnUnicastAddress {
    type Error = Ipv6MplsVpnUnicastAddressParsingError;

    fn parse(
        cur: &mut BytesReader,
        add_path: bool,
        is_unreach: bool,
        multiple_labels_limit: u8,
    ) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        let prefix_bytes = if prefix_len > u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        // consuming only the bytes specified by the prefix length field, since MPLS
        // stack is read until the last bit is set.
        let mut prefix_buf = cur.take_slice(prefix_bytes as usize)?;
        let label_stack =
            parse_mpls_label_stack(&mut prefix_buf, is_unreach, multiple_labels_limit)?;
        let rd = RouteDistinguisher::parse(&mut prefix_buf)?;
        let read_prefix = RD_LEN * 8 + label_stack.len() as u8 * MPLS_LABEL_LEN_BITS;
        // Check subtraction operation is safe first
        let remainder_prefix_len = match prefix_len.checked_sub(read_prefix) {
            None => {
                return Err(Ipv6MplsVpnUnicastAddressParsingError::InvalidLength {
                    offset,
                    len: prefix_len,
                });
            }
            Some(val) => val,
        };
        let network = <Ipv6Unicast as ParseFromWithTwoInputs<'a, _, _>>::parse(
            &mut prefix_buf,
            remainder_prefix_len,
            offset,
        )?;
        // Check all the bytes specified by the prefix length are consumed
        if !prefix_buf.is_empty() {
            return Err(Ipv6MplsVpnUnicastAddressParsingError::InvalidLength {
                offset,
                len: prefix_len,
            });
        }
        Ok(Ipv6MplsVpnUnicastAddress::new(
            path_id,
            rd,
            label_stack,
            network,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6UnicastParsingError {
    #[error("Invalid IPv6 Unicast Address: {0}")]
    Parse(#[from] ParseError),

    #[error("Invalid IPv6 Unicast: {0}")]
    Ipv6PrefixError(#[from] Ipv6PrefixParsingError),

    #[error("Invalid IPv6 Unicast network {network:?} at offset {offset}")]
    InvalidUnicastNetwork { offset: usize, network: Ipv6Net },
}

impl<'a> ParseFrom<'a> for Ipv6Unicast {
    type Error = Ipv6UnicastParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let net = <Ipv6Net as ParseFrom>::parse(cur)?;
        let unicast_net = Ipv6Unicast::from_net(net).map_err(|_| {
            Ipv6UnicastParsingError::InvalidUnicastNetwork {
                offset,
                network: net,
            }
        })?;
        Ok(unicast_net)
    }
}

impl<'a> ParseFromWithTwoInputs<'a, u8, usize> for Ipv6Unicast {
    type Error = Ipv6UnicastParsingError;
    fn parse(cur: &mut BytesReader, prefix_len: u8, offset: usize) -> Result<Self, Self::Error> {
        let net = <Ipv6Net as ParseFromWithTwoInputs<'a, _, _>>::parse(cur, prefix_len, offset)?;
        let unicast_net = Ipv6Unicast::from_net(net).map_err(|_| {
            Ipv6UnicastParsingError::InvalidUnicastNetwork {
                offset,
                network: net,
            }
        })?;
        Ok(unicast_net)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6UnicastAddressParsingError {
    #[error("IPv6 Unicast Address parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("IPv6 Unicast Address error: {0}")]
    Ipv6UnicastError(#[from] Ipv6UnicastParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for Ipv6UnicastAddress {
    type Error = Ipv6UnicastAddressParsingError;
    fn parse(cur: &mut BytesReader, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let net = <Ipv6Unicast as ParseFrom>::parse(cur)?;
        Ok(Ipv6UnicastAddress::new(path_id, net))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6MulticastParsingError {
    #[error("Invalid IPv6 Multicast: {0}")]
    Ipv6PrefixError(#[from] Ipv6PrefixParsingError),
    #[error("Invalid IPv6 Multicast network {network} at offset {offset}")]
    InvalidMulticastNetwork { offset: usize, network: Ipv6Net },
}

impl<'a> ParseFrom<'a> for Ipv6Multicast {
    type Error = Ipv6MulticastParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let network = <Ipv6Net as ParseFrom<'_>>::parse(cur)?;
        let net = Ipv6Multicast::from_net(network)
            .map_err(|_| Ipv6MulticastParsingError::InvalidMulticastNetwork { offset, network })?;
        Ok(net)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6MulticastAddressParsingError {
    #[error("IPv6 Multicast Address parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("IPv6 Multicast Address error: {0}")]
    Ipv6MulticastError(#[from] Ipv6MulticastParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for Ipv6MulticastAddress {
    type Error = Ipv6MulticastAddressParsingError;
    fn parse(cur: &mut BytesReader, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let net = Ipv6Multicast::parse(cur)?;
        Ok(Ipv6MulticastAddress::new(path_id, net))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4UnicastParsingError {
    #[error("Invalid IPv4 Unicast: {0}")]
    Ipv4PrefixError(#[from] Ipv4PrefixParsingError),

    #[error("Invalid IPv4 unicast network {network} at offset {offset}")]
    InvalidUnicastNetwork { offset: usize, network: Ipv4Net },
}

impl<'a> ParseFrom<'a> for Ipv4Unicast {
    type Error = Ipv4UnicastParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let network = <Ipv4Net as ParseFrom>::parse(cur)?;
        let unicast = Self::from_net(network)
            .map_err(|_| Ipv4UnicastParsingError::InvalidUnicastNetwork { offset, network })?;
        Ok(unicast)
    }
}

impl<'a> ParseFromWithTwoInputs<'a, u8, usize> for Ipv4Unicast {
    type Error = Ipv4UnicastParsingError;
    fn parse(cur: &mut BytesReader, prefix_len: u8, offset: usize) -> Result<Self, Self::Error> {
        let ipv4_net =
            <Ipv4Net as ParseFromWithTwoInputs<'_, _, _>>::parse(cur, prefix_len, offset)?;
        let net = Self::from_net(ipv4_net).map_err(|_| {
            Ipv4UnicastParsingError::InvalidUnicastNetwork {
                offset,
                network: ipv4_net,
            }
        })?;
        Ok(net)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4UnicastAddressParsingError {
    #[error("IPv4 Unicast Address parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("IPv4 Unicast Address error: {0}")]
    Ipv4UnicastError(#[from] Ipv4UnicastParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for Ipv4UnicastAddress {
    type Error = Ipv4UnicastAddressParsingError;
    fn parse(cur: &mut BytesReader, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let net = <Ipv4Unicast as ParseFrom<'_>>::parse(cur)?;
        Ok(Ipv4UnicastAddress::new(path_id, net))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4MulticastParsingError {
    #[error("Invalid IPv4 Multicast: {0}")]
    Ipv4PrefixError(#[from] Ipv4PrefixParsingError),

    #[error("Invalid IPv4 Multicast network {network} at offset {offset}")]
    InvalidMulticastNetwork { offset: usize, network: Ipv4Net },
}

impl<'a> ParseFrom<'a> for Ipv4Multicast {
    type Error = Ipv4MulticastParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let net = <Ipv4Net as ParseFrom<'_>>::parse(cur)?;
        let net = Ipv4Multicast::from_net(net).map_err(|_| {
            Ipv4MulticastParsingError::InvalidMulticastNetwork {
                offset,
                network: net,
            }
        })?;
        Ok(net)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4MulticastAddressParsingError {
    #[error("IPv4 Multicast Address parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("IPv4 Multicast Address error: {0}")]
    Ipv4MulticastError(#[from] Ipv4MulticastParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for Ipv4MulticastAddress {
    type Error = Ipv4MulticastAddressParsingError;
    fn parse(cur: &mut BytesReader, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let multicast = Ipv4Multicast::parse(cur)?;
        Ok(Ipv4MulticastAddress::new(path_id, multicast))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MacAddressParsingError {
    #[error("Mac Address parsing error: {0}")]
    Parse(#[from] ParseError),
}
impl<'a> ParseFrom<'a> for MacAddress {
    type Error = MacAddressParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let mac_address: [u8; 6] = cur.read_array()?;
        Ok(MacAddress(mac_address))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum EthernetSegmentIdentifierParsingError {
    #[error("Ethernet Segment Identifier parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for EthernetSegmentIdentifier {
    type Error = EthernetSegmentIdentifierParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let segment = cur.read_array()?;
        Ok(EthernetSegmentIdentifier(segment))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum EthernetTagParsingError {
    #[error("Ethernet Tag parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFrom<'a> for EthernetTag {
    type Error = EthernetTagParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let tag = cur.read_u32_be()?;
        Ok(EthernetTag(tag))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum EthernetAutoDiscoveryParsingError {
    #[error("Ethernet Auto Discovery parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Ethernet Auto Discovery error: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
    #[error("Ethernet Auto Discovery error: {0}")]
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierParsingError),
    #[error("Ethernet Auto Discovery error: {0}")]
    EthernetTagError(#[from] EthernetTagParsingError),
    #[error("Ethernet Auto Discovery error: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),
}

impl<'a> ParseFrom<'a> for EthernetAutoDiscovery {
    type Error = EthernetAutoDiscoveryParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let segment_id = EthernetSegmentIdentifier::parse(cur)?;
        let tag = EthernetTag::parse(cur)?;
        let mpls_label = MplsLabel::parse(cur)?;
        Ok(EthernetAutoDiscovery::new(rd, segment_id, tag, mpls_label))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MacIpAdvertisementParsingError {
    #[error("Mac IP Advertisement parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Mac IP Advertisement error invalid address length {length} at offset {offset}")]
    InvalidMacAddressLength { offset: usize, length: u8 },
    #[error("Mac IP Advertisement error invalid ip address length {length} at offset {offset}")]
    InvalidIpAddressAddressLength { offset: usize, length: u8 },
    #[error("Mac IP Advertisement error: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
    #[error("Mac IP Advertisement error: {0}")]
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierParsingError),
    #[error("Mac IP Advertisement error: {0}")]
    EthernetTagError(#[from] EthernetTagParsingError),
    #[error("Mac IP Advertisement error: {0}")]
    MacAddressError(#[from] MacAddressParsingError),
    #[error("Mac IP Advertisement error: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),
}

impl<'a> ParseFrom<'a> for MacIpAdvertisement {
    type Error = MacIpAdvertisementParsingError;

    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let segment_id = EthernetSegmentIdentifier::parse(cur)?;
        let tag = EthernetTag::parse(cur)?;
        let offset = cur.offset();
        let mac_len = cur.read_u8()?;
        if mac_len != MAC_ADDRESS_LEN_BITS {
            return Err(MacIpAdvertisementParsingError::InvalidMacAddressLength {
                offset,
                length: mac_len,
            });
        }
        let mac = MacAddress::parse(cur)?;
        let offset = cur.offset();
        let ip_len = cur.read_u8()?;
        let ip = match ip_len {
            0 => None,
            IPV4_LEN_BITS => {
                let ip = cur.read_u32_be()?;
                Some(IpAddr::V4(Ipv4Addr::from(ip)))
            }
            IPV6_LEN_BITS => {
                let ip = cur.read_u128_be()?;
                Some(IpAddr::V6(Ipv6Addr::from(ip)))
            }
            _ => {
                return Err(
                    MacIpAdvertisementParsingError::InvalidIpAddressAddressLength {
                        offset,
                        length: ip_len,
                    },
                );
            }
        };

        let mpls_label = MplsLabel::parse(cur)?;
        let mpls_label2 = if !cur.is_empty() {
            Some(MplsLabel::parse(cur)?)
        } else {
            None
        };
        Ok(MacIpAdvertisement::new(
            rd,
            segment_id,
            tag,
            mac,
            ip,
            mpls_label,
            mpls_label2,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum InclusiveMulticastEthernetTagRouteParsingError {
    #[error("Inclusive Multicast EthernetTag route parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error(
        "Invalid address length {length} in Inclusive Multicast EthernetTag route at offset {offset}"
    )]
    InvalidIpAddressAddressLength { offset: usize, length: u8 },
    #[error("Inclusive Multicast EthernetTag route parsing error: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
    #[error("Inclusive Multicast EthernetTag route parsing error: {0}")]
    EthernetTagError(#[from] EthernetTagParsingError),
}

impl<'a> ParseFrom<'a> for InclusiveMulticastEthernetTagRoute {
    type Error = InclusiveMulticastEthernetTagRouteParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let tag = EthernetTag::parse(cur)?;
        let offset = cur.offset();
        let ip_len = cur.read_u8()?;
        let ip = match ip_len {
            IPV4_LEN_BITS => {
                let ip = cur.read_u32_be()?;
                IpAddr::V4(Ipv4Addr::from(ip))
            }
            IPV6_LEN_BITS => {
                let ip = cur.read_u128_be()?;
                IpAddr::V6(Ipv6Addr::from(ip))
            }
            _ => {
                return Err(
                    InclusiveMulticastEthernetTagRouteParsingError::InvalidIpAddressAddressLength {
                        offset,
                        length: ip_len,
                    },
                );
            }
        };
        Ok(InclusiveMulticastEthernetTagRoute::new(rd, tag, ip))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum EthernetSegmentRouteParsingError {
    #[error("Invalid Ethernet Segment route parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Invalid address length {length} in Ethernet Segment route at offset {offset}")]
    InvalidIpAddressAddressLength { offset: usize, length: u8 },
    #[error("Invalid Ethernet Segment route parsing error: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
    #[error("Invalid Ethernet Segment route parsing error: {0}")]
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierParsingError),
}

impl<'a> ParseFrom<'a> for EthernetSegmentRoute {
    type Error = EthernetSegmentRouteParsingError;

    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let segment_id = EthernetSegmentIdentifier::parse(cur)?;
        let offset = cur.offset();
        let ip_len = cur.read_u8()?;
        let ip = match ip_len {
            IPV4_LEN_BITS => {
                let ip = cur.read_u32_be()?;
                IpAddr::V4(Ipv4Addr::from(ip))
            }
            IPV6_LEN_BITS => {
                let ip = cur.read_u128_be()?;
                IpAddr::V6(Ipv6Addr::from(ip))
            }
            _ => {
                return Err(
                    EthernetSegmentRouteParsingError::InvalidIpAddressAddressLength {
                        offset,
                        length: ip_len,
                    },
                );
            }
        };
        Ok(EthernetSegmentRoute::new(rd, segment_id, ip))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum L2EvpnRouteParsingError {
    #[error("Invalid L2 EVPN route parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("L2 EvPN route error: {0}")]
    EthernetAutoDiscoveryError(#[from] EthernetAutoDiscoveryParsingError),
    #[error("L2 EvPN route error: {0}")]
    MacIpAdvertisementError(#[from] MacIpAdvertisementParsingError),
    #[error("L2 EvPN route error: {0}")]
    InclusiveMulticastEthernetTagRouteError(#[from] InclusiveMulticastEthernetTagRouteParsingError),
    #[error("L2 EvPN route error: {0}")]
    EthernetSegmentRouteError(#[from] EthernetSegmentRouteParsingError),
    #[error("L2 EvPN route error: {0}")]
    L2EvpnIpPrefixRouteError(#[from] L2EvpnIpPrefixRouteParsingError),
}

impl<'a> ParseFrom<'a> for L2EvpnRoute {
    type Error = L2EvpnRouteParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let typ_code = cur.read_u8()?;
        let len = cur.read_u8()?;
        let mut route_buf = cur.take_slice(len as usize)?;
        let typ = L2EvpnRouteTypeCode::try_from(typ_code);
        let value = match typ {
            Ok(L2EvpnRouteTypeCode::EthernetAutoDiscovery) => {
                let value = EthernetAutoDiscovery::parse(&mut route_buf)?;
                L2EvpnRoute::EthernetAutoDiscovery(value)
            }
            Ok(L2EvpnRouteTypeCode::MacIpAdvertisement) => {
                let value = MacIpAdvertisement::parse(&mut route_buf)?;
                L2EvpnRoute::MacIpAdvertisement(value)
            }
            Ok(L2EvpnRouteTypeCode::InclusiveMulticastEthernetTagRoute) => {
                let value = InclusiveMulticastEthernetTagRoute::parse(&mut route_buf)?;
                L2EvpnRoute::InclusiveMulticastEthernetTagRoute(value)
            }
            Ok(L2EvpnRouteTypeCode::EthernetSegmentRoute) => {
                let value = EthernetSegmentRoute::parse(&mut route_buf)?;
                L2EvpnRoute::EthernetSegmentRoute(value)
            }
            Ok(L2EvpnRouteTypeCode::IpPrefix) => {
                let value = L2EvpnIpPrefixRoute::parse(&mut route_buf)?;
                L2EvpnRoute::IpPrefixRoute(value)
            }
            Ok(_) | Err(_) => {
                let len = cur.read_u8()?;
                let value = cur.read_bytes(len as usize)?;
                L2EvpnRoute::Unknown {
                    code: typ_code,
                    value: value.to_vec(),
                }
            }
        };
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum L2EvpnAddressParsingError {
    #[error("Invalid L2 EVPN address")]
    Parse(#[from] ParseError),
    #[error("L2 EvPN address error: {0}")]
    L2EvpnRouteError(#[from] L2EvpnRouteParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for L2EvpnAddress {
    type Error = L2EvpnAddressParsingError;
    fn parse(cur: &mut BytesReader, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let route = L2EvpnRoute::parse(cur)?;
        Ok(L2EvpnAddress::new(path_id, route))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum L2EvpnIpv4PrefixRouteParsingError {
    #[error("L2 EVPN IPv4 prefix route parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("EVPN IPv4 prefix route error: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
    #[error("EVPN IPv4 prefix route error: {0}")]
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierParsingError),
    #[error("EVPN IPv4 prefix route error: {0}")]
    EthernetTagError(#[from] EthernetTagParsingError),
    #[error("EVPN IPv4 prefix route error: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),
    #[error("EVPN IPv4 prefix route error: {0}")]
    Ipv4PrefixError(#[from] Ipv4PrefixParsingError),
}

impl<'a> ParseFrom<'a> for L2EvpnIpv4PrefixRoute {
    type Error = L2EvpnIpv4PrefixRouteParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let segment_id = EthernetSegmentIdentifier::parse(cur)?;
        let tag = EthernetTag::parse(cur)?;
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        let network = cur.read_u32_be()?;
        let prefix = match Ipv4Net::new(Ipv4Addr::from(network), prefix_len) {
            Ok(prefix) => prefix,
            Err(_) => {
                return Err(L2EvpnIpv4PrefixRouteParsingError::Ipv4PrefixError(
                    Ipv4PrefixParsingError::InvalidIpv4PrefixLen { offset, prefix_len },
                ));
            }
        };
        let gateway = cur.read_u32_be()?;
        let gateway = Ipv4Addr::from(gateway);
        let mpls_label = MplsLabel::parse(cur)?;
        Ok(L2EvpnIpv4PrefixRoute::new(
            rd, segment_id, tag, prefix, gateway, mpls_label,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum L2EvpnIpv6PrefixRouteParsingError {
    #[error("L2 EVPN IPv6 prefix route parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("EVPN IPv6 prefix route error: {0}")]
    RouteDistinguisherError(#[from] RouteDistinguisherParsingError),
    #[error("EVPN IPv6 prefix route error: {0}")]
    EthernetSegmentIdentifierError(#[from] EthernetSegmentIdentifierParsingError),
    #[error("EVPN IPv6 prefix route error: {0}")]
    EthernetTagError(#[from] EthernetTagParsingError),
    #[error("EVPN IPv6 prefix route error: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),
    #[error("EVPN IPv6 prefix route error: {0}")]
    Ipv6PrefixError(#[from] Ipv6PrefixParsingError),
}

impl<'a> ParseFrom<'a> for L2EvpnIpv6PrefixRoute {
    type Error = L2EvpnIpv6PrefixRouteParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let rd = RouteDistinguisher::parse(cur)?;
        let segment_id = EthernetSegmentIdentifier::parse(cur)?;
        let tag = EthernetTag::parse(cur)?;
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        let network = cur.read_u128_be()?;
        let prefix = match Ipv6Net::new(Ipv6Addr::from(network), prefix_len) {
            Ok(prefix) => prefix,
            Err(_) => {
                return Err(L2EvpnIpv6PrefixRouteParsingError::Ipv6PrefixError(
                    Ipv6PrefixParsingError::InvalidIpv6PrefixLen { offset, prefix_len },
                ));
            }
        };
        let gateway = cur.read_u128_be()?;
        let gateway = Ipv6Addr::from(gateway);
        let mpls_label = MplsLabel::parse(cur)?;
        Ok(L2EvpnIpv6PrefixRoute::new(
            rd, segment_id, tag, prefix, gateway, mpls_label,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum L2EvpnIpPrefixRouteParsingError {
    #[error("L2 EVPN IP Prefix Route invalid buffer length {length} at offset {offset}")]
    InvalidBufferLength { offset: usize, length: usize },
    #[error("Invalid L2 EVPN IP Prefix Route {0}")]
    L2EvpnIpv4PrefixRouteError(#[from] L2EvpnIpv4PrefixRouteParsingError),
    #[error("Invalid L2 EVPN IP Prefix Route {0}")]
    L2EvpnIpv6PrefixRouteError(#[from] L2EvpnIpv6PrefixRouteParsingError),
}

impl<'a> ParseFrom<'a> for L2EvpnIpPrefixRoute {
    type Error = L2EvpnIpPrefixRouteParsingError;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        match cur.remaining() {
            L2_EVPN_IPV4_PREFIX_ROUTE_LEN => {
                let value = L2EvpnIpv4PrefixRoute::parse(cur)?;
                Ok(L2EvpnIpPrefixRoute::V4(value))
            }
            L2_EVPN_IPV6_PREFIX_ROUTE_LEN => {
                let value = L2EvpnIpv6PrefixRoute::parse(cur)?;
                Ok(L2EvpnIpPrefixRoute::V6(value))
            }
            _ => Err(L2EvpnIpPrefixRouteParsingError::InvalidBufferLength {
                offset,
                length: cur.remaining(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteTargetMembershipAddressParsingError {
    #[error("Route Target membership address parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("Invalid route target membership prefix length {length} at offset {offset}")]
    InvalidPrefixLen { offset: usize, length: u8 },
    #[error("Invalid Route Target membership address: {0}")]
    RouteTargetMembershipParsingError(#[from] RouteTargetMembershipParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for RouteTargetMembershipAddress {
    type Error = RouteTargetMembershipAddressParsingError;
    fn parse(cur: &mut BytesReader, add_path: bool) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let offset = cur.offset();
        let prefix_len = cur.read_u8()?;
        let membership = if prefix_len == 0 {
            None
        } else if !(32..=96).contains(&prefix_len) {
            return Err(RouteTargetMembershipAddressParsingError::InvalidPrefixLen {
                offset,
                length: prefix_len,
            });
        } else {
            let membership = RouteTargetMembership::parse(cur, prefix_len)?;
            Some(membership)
        };
        Ok(RouteTargetMembershipAddress::new(path_id, membership))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RouteTargetMembershipParsingError {
    #[error("Route Target membership address parsing error: {0}")]
    Parse(#[from] ParseError),
}

impl<'a> ParseFromWithOneInput<'a, u8> for RouteTargetMembership {
    type Error = RouteTargetMembershipParsingError;
    fn parse(cur: &mut BytesReader, prefix_len: u8) -> Result<Self, Self::Error> {
        let origin_as = cur.read_u32_be()?;
        let route_target = cur.read_bytes(((prefix_len - 32) / 8) as usize)?;
        Ok(RouteTargetMembership::new(origin_as, route_target.to_vec()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv4NlriMplsLabelsAddressParsingError {
    #[error("IPv4 NLRI MPLS Labels Address parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("IPv4 NLRI MPLS Labels Address error: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),
    #[error("IPv4 NLRI MPLS Labels Address error: {0}")]
    Ipv4PrefixError(#[from] Ipv4PrefixParsingError),
    #[error("Invalid IPv4 NLRI MPLS Labels Address {error} at offset {offset}")]
    InvalidIpv4NlriMplsLabelsAddress {
        offset: usize,
        error: InvalidIpv4NlriMplsLabelsAddress,
    },
    #[error("Invalid IPv4 NLRI MPLS Labels Address length {len} at offset {offset}")]
    InvalidLength { offset: usize, len: u8 },
}

impl<'a> ParseFromWithThreeInputs<'a, bool, bool, u8> for Ipv4NlriMplsLabelsAddress {
    type Error = Ipv4NlriMplsLabelsAddressParsingError;
    fn parse(
        cur: &mut BytesReader,
        add_path: bool,
        is_unreach: bool,
        multiple_labels_limit: u8,
    ) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let offset = cur.offset();
        let mut prefix_len = cur.read_u8()?;
        let prefix_bytes = if prefix_len > u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        let mut nlri_buf = cur.take_slice(prefix_bytes as usize)?;
        let label_stack = parse_mpls_label_stack(&mut nlri_buf, is_unreach, multiple_labels_limit)?;
        if prefix_len < MPLS_LABEL_LEN_BITS * label_stack.len() as u8 {
            return Err(Ipv4NlriMplsLabelsAddressParsingError::InvalidLength {
                offset,
                len: prefix_len,
            });
        }
        prefix_len -= MPLS_LABEL_LEN_BITS * label_stack.len() as u8;
        let offset = cur.offset();
        let prefix = <Ipv4Net as ParseFromWithTwoInputs<'_, _, _>>::parse(
            &mut nlri_buf,
            prefix_len,
            offset,
        )?;
        match Ipv4NlriMplsLabelsAddress::from(path_id, label_stack, prefix) {
            Ok(address) => Ok(address),
            Err(error) => Err(
                Ipv4NlriMplsLabelsAddressParsingError::InvalidIpv4NlriMplsLabelsAddress {
                    offset,
                    error,
                },
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Ipv6NlriMplsLabelsAddressParsingError {
    #[error("IPv6 NLRI MPLS Labels Address parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("IPv6 NLRI MPLS Labels Address error: {0}")]
    MplsLabelError(#[from] MplsLabelParsingError),
    #[error("IPv6 NLRI MPLS Labels Address error: {0}")]
    Ipv6PrefixError(#[from] Ipv6PrefixParsingError),
    #[error("IPv6 NLRI MPLS Labels Address error {error} at offset {offset}")]
    InvalidIpv6NlriMplsLabelsAddress {
        offset: usize,
        error: InvalidIpv6NlriMplsLabelsAddress,
    },
    #[error("IPv6 NLRI MPLS Labels Address length {len} at offset {offset}")]
    InvalidLength { offset: usize, len: u8 },
}

impl<'a> ParseFromWithThreeInputs<'a, bool, bool, u8> for Ipv6NlriMplsLabelsAddress {
    type Error = Ipv6NlriMplsLabelsAddressParsingError;

    fn parse(
        cur: &mut BytesReader,
        add_path: bool,
        is_unreach: bool,
        multiple_labels_limit: u8,
    ) -> Result<Self, Self::Error> {
        let path_id = if add_path {
            Some(cur.read_u32_be()?)
        } else {
            None
        };
        let offset = cur.offset();
        let mut prefix_len = cur.read_u8()?;
        let prefix_bytes = if prefix_len > u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        let mut nlri_buf = cur.take_slice(prefix_bytes as usize)?;
        let label_stack = parse_mpls_label_stack(&mut nlri_buf, is_unreach, multiple_labels_limit)?;
        if prefix_len < MPLS_LABEL_LEN_BITS * label_stack.len() as u8 {
            return Err(Ipv6NlriMplsLabelsAddressParsingError::InvalidLength {
                offset,
                len: prefix_len,
            });
        }
        prefix_len -= MPLS_LABEL_LEN_BITS * label_stack.len() as u8;
        let prefix = <Ipv6Net as ParseFromWithTwoInputs<'_, _, _>>::parse(
            &mut nlri_buf,
            prefix_len,
            offset,
        )?;
        match Ipv6NlriMplsLabelsAddress::from(path_id, label_stack, prefix) {
            Ok(address) => Ok(address),
            Err(error) => Err(
                Ipv6NlriMplsLabelsAddressParsingError::InvalidIpv6NlriMplsLabelsAddress {
                    offset,
                    error,
                },
            ),
        }
    }
}

#[inline]
fn parse_mpls_label_stack(
    cur: &mut BytesReader,
    is_unreach: bool,
    mut multiple_labels_limit: u8,
) -> Result<Vec<MplsLabel>, MplsLabelParsingError> {
    let mut label_stack = Vec::<MplsLabel>::new();
    let mut is_bottom = false;
    while !is_bottom && multiple_labels_limit > 0 {
        let label = MplsLabel::parse(cur)?;
        if multiple_labels_limit != u8::MAX {
            multiple_labels_limit -= 1;
        }
        is_bottom = label.is_bottom() || is_unreach && label.is_unreach_compatibility();
        label_stack.push(label);
    }
    Ok(label_stack)
}
