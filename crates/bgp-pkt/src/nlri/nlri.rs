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

//! Data types to represent various Network Layer Reachability Information
//! (`NLRI`)

use crate::iana::{L2EvpnRouteTypeCode, RouteDistinguisherTypeCode};
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_iana::address_family::AddressType;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Get the [`AddressType`] of a given NLRI
pub trait NlriAddressType {
    fn address_type() -> AddressType;
}

/// Temporary representation of MPLS Labels
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MplsLabel([u8; 3]);

impl MplsLabel {
    pub const fn new(label: [u8; 3]) -> Self {
        Self(label)
    }

    pub const fn value(&self) -> &[u8; 3] {
        &self.0
    }

    pub const fn is_bottom(&self) -> bool {
        self.0[2] & 0x01 == 0x01
    }
    pub const fn is_unreach_compatibility(&self) -> bool {
        self.0[0] == 0x80 && self.0[1] == 0x00 && self.0[2] == 0x00
    }
}

/// Route Distinguisher (RD) is a 8-byte value and encoded as follows:
///     - Type Field: 2 bytes
///     - Value Field: 6 bytes
#[derive(Hash, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteDistinguisher {
    /// The Value field consists of two subfields:
    ///     - Administrator subfield: ASN2
    ///     - Assigned Number subfield: 4 bytes
    As2Administrator { asn2: u16, number: u32 },

    /// The Value field consists of two subfields:
    ///     - Administrator subfield: Ipv4 address
    ///     - Assigned Number subfield: 2 bytes
    Ipv4Administrator {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4))]
        ip: Ipv4Addr,
        number: u16,
    },

    /// The Value field consists of two subfields:
    ///     - Administrator subfield: ASN4
    ///     - Assigned Number subfield: 2 bytes
    As4Administrator { asn4: u32, number: u16 },

    /// [RFC7524](https://datatracker.ietf.org/doc/html/rfc7524) defines this value
    /// to be always ones, so we don't keep its value in memory
    LeafAdRoutes,
}

impl RouteDistinguisher {
    pub const fn get_type(&self) -> RouteDistinguisherTypeCode {
        match self {
            Self::As2Administrator { .. } => RouteDistinguisherTypeCode::As2Administrator,
            Self::Ipv4Administrator { .. } => RouteDistinguisherTypeCode::Ipv4Administrator,
            Self::As4Administrator { .. } => RouteDistinguisherTypeCode::As4Administrator,
            Self::LeafAdRoutes => RouteDistinguisherTypeCode::LeafAdRoutes,
        }
    }
}

impl std::fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::As2Administrator { asn2, number } => write!(f, "{asn2}:{number}"),
            Self::Ipv4Administrator { ip, number } => write!(f, "{ip}:{number}"),
            Self::As4Administrator { asn4, number } => write!(f, "{asn4}:{number}"),
            Self::LeafAdRoutes => write!(f, "leaf-A-D-route"),
        }
    }
}

impl From<RouteDistinguisher> for u64 {
    fn from(value: RouteDistinguisher) -> Self {
        match value {
            RouteDistinguisher::As2Administrator { asn2, number } => {
                let t: u16 = RouteDistinguisherTypeCode::As2Administrator.into();
                (t as u64) << (u64::BITS - u16::BITS)
                    | (asn2 as u64) << (u64::BITS - u16::BITS - u16::BITS)
                    | (number as u64)
            }
            RouteDistinguisher::Ipv4Administrator { ip, number } => {
                let t: u16 = RouteDistinguisherTypeCode::Ipv4Administrator.into();
                let ip: u32 = ip.into();
                (t as u64) << (u64::BITS - u16::BITS)
                    | (ip as u64) << (u64::BITS - u16::BITS - u32::BITS)
                    | (number as u64)
            }
            RouteDistinguisher::As4Administrator { asn4, number } => {
                let t: u16 = RouteDistinguisherTypeCode::As4Administrator.into();
                (t as u64) << (u64::BITS - u16::BITS)
                    | (asn4 as u64) << (u64::BITS - u16::BITS - u32::BITS)
                    | (number as u64)
            }
            RouteDistinguisher::LeafAdRoutes => u64::MAX,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct LabeledIpv4NextHop {
    rd: RouteDistinguisher,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4))]
    next_hop: Ipv4Addr,
}

impl LabeledIpv4NextHop {
    pub const fn new(rd: RouteDistinguisher, next_hop: Ipv4Addr) -> Self {
        Self { rd, next_hop }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn next_hop(&self) -> Ipv4Addr {
        self.next_hop
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct LabeledIpv6NextHop {
    rd: RouteDistinguisher,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6))]
    next_hop: Ipv6Addr,
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ipv6)))]
    next_hop_local: Option<Ipv6Addr>,
}

impl LabeledIpv6NextHop {
    pub const fn new(
        rd: RouteDistinguisher,
        next_hop: Ipv6Addr,
        next_hop_local: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            rd,
            next_hop,
            next_hop_local,
        }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn next_hop(&self) -> Ipv6Addr {
        self.next_hop
    }

    pub const fn next_hop_local(&self) -> Option<Ipv6Addr> {
        self.next_hop_local
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum LabeledNextHop {
    Ipv4(LabeledIpv4NextHop),
    Ipv6(LabeledIpv6NextHop),
}

impl LabeledNextHop {
    pub fn next_hop(&self) -> IpAddr {
        match self {
            LabeledNextHop::Ipv4(nh) => IpAddr::V4(nh.next_hop()),
            LabeledNextHop::Ipv6(nh) => IpAddr::V6(nh.next_hop()),
        }
    }

    pub fn rd(&self) -> RouteDistinguisher {
        match self {
            LabeledNextHop::Ipv4(nh) => nh.rd(),
            LabeledNextHop::Ipv6(nh) => nh.rd(),
        }
    }
}

/// A more restricted version of [`Ipv4Net`] that allows only unicast
/// networks
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv4Unicast(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4net))] Ipv4Net,
);

/// Raised when the network is not a unicast range
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]

pub struct InvalidIpv4UnicastNetwork(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4net))] pub Ipv4Net,
);

impl Ipv4Unicast {
    pub fn from_net(net: Ipv4Net) -> Result<Self, InvalidIpv4UnicastNetwork> {
        if net.addr().is_broadcast() || net.addr().is_multicast() {
            return Err(InvalidIpv4UnicastNetwork(net));
        }
        if let Some(addr) = net.hosts().last() {
            if addr.is_broadcast() || addr.is_multicast() {
                return Err(InvalidIpv4UnicastNetwork(net));
            }
        }
        Ok(Self(net))
    }

    pub const fn address(&self) -> Ipv4Net {
        self.0
    }
}

impl TryFrom<Ipv4Net> for Ipv4Unicast {
    type Error = InvalidIpv4UnicastNetwork;

    fn try_from(net: Ipv4Net) -> Result<Self, Self::Error> {
        Self::from_net(net)
    }
}

/// Ipv4 Network address in NLRI
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv4UnicastAddress {
    path_id: Option<u32>,
    network: Ipv4Unicast,
}

impl Ipv4UnicastAddress {
    pub const fn new(path_id: Option<u32>, network: Ipv4Unicast) -> Self {
        Self { path_id, network }
    }

    pub const fn new_no_path_id(network: Ipv4Unicast) -> Self {
        Self {
            path_id: None,
            network,
        }
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn network(&self) -> Ipv4Unicast {
        self.network
    }
}

impl NlriAddressType for Ipv4UnicastAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv4Unicast
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv4MplsVpnUnicastAddress {
    path_id: Option<u32>,
    rd: RouteDistinguisher,
    label_stack: Vec<MplsLabel>,
    network: Ipv4Unicast,
}

impl Ipv4MplsVpnUnicastAddress {
    pub const fn new(
        path_id: Option<u32>,
        rd: RouteDistinguisher,
        label_stack: Vec<MplsLabel>,
        network: Ipv4Unicast,
    ) -> Self {
        Self {
            path_id,
            rd,
            label_stack,
            network,
        }
    }

    pub const fn new_no_path_id(
        rd: RouteDistinguisher,
        label_stack: Vec<MplsLabel>,
        network: Ipv4Unicast,
    ) -> Self {
        Self {
            path_id: None,
            rd,
            label_stack,
            network,
        }
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn label_stack(&self) -> &Vec<MplsLabel> {
        &self.label_stack
    }

    pub const fn network(&self) -> Ipv4Unicast {
        self.network
    }
}

impl NlriAddressType for Ipv4MplsVpnUnicastAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv4MplsLabeledVpn
    }
}

/// A more restricted version of [`Ipv4Net`] that allows only multicast
/// networks
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv4Multicast(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4net))] Ipv4Net,
);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct InvalidIpv4MulticastNetwork(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4net))] pub Ipv4Net,
);

impl Ipv4Multicast {
    pub fn from_net(net: Ipv4Net) -> Result<Self, InvalidIpv4MulticastNetwork> {
        if !net.addr().is_multicast() || net.hosts().last().map(|x| x.is_multicast()) == Some(false)
        {
            return Err(InvalidIpv4MulticastNetwork(net));
        }
        Ok(Self(net))
    }

    pub const fn address(&self) -> Ipv4Net {
        self.0
    }
}

impl TryFrom<Ipv4Net> for Ipv4Multicast {
    type Error = InvalidIpv4MulticastNetwork;

    fn try_from(net: Ipv4Net) -> Result<Self, Self::Error> {
        Self::from_net(net)
    }
}

/// Ipv4 Multicast Network address in NLRI
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv4MulticastAddress {
    path_id: Option<u32>,
    network: Ipv4Multicast,
}

impl Ipv4MulticastAddress {
    pub const fn new(path_id: Option<u32>, network: Ipv4Multicast) -> Self {
        Self { path_id, network }
    }

    pub const fn new_no_path_id(network: Ipv4Multicast) -> Self {
        Self {
            path_id: None,
            network,
        }
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn network(&self) -> Ipv4Multicast {
        self.network
    }
}

impl NlriAddressType for Ipv4MulticastAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv4Multicast
    }
}

/// A more restricted version of [`Ipv6Net`] that allows only unicast
/// networks
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv6Unicast(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6net))] Ipv6Net,
);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct InvalidIpv6UnicastNetwork(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6net))] pub Ipv6Net,
);

impl Ipv6Unicast {
    pub fn from_net(net: Ipv6Net) -> Result<Self, InvalidIpv6UnicastNetwork> {
        if net.addr().is_multicast() || net.hosts().last().map(|x| x.is_multicast()) == Some(true) {
            return Err(InvalidIpv6UnicastNetwork(net));
        }
        Ok(Self(net))
    }

    pub const fn address(&self) -> Ipv6Net {
        self.0
    }
}

impl TryFrom<Ipv6Net> for Ipv6Unicast {
    type Error = InvalidIpv6UnicastNetwork;

    fn try_from(net: Ipv6Net) -> Result<Self, Self::Error> {
        Self::from_net(net)
    }
}

/// Ipv6 Network address in NLRI
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv6UnicastAddress {
    path_id: Option<u32>,
    network: Ipv6Unicast,
}

impl Ipv6UnicastAddress {
    pub const fn new(path_id: Option<u32>, network: Ipv6Unicast) -> Self {
        Self { path_id, network }
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn network(&self) -> Ipv6Unicast {
        self.network
    }
}

impl NlriAddressType for Ipv6UnicastAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv6Unicast
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv6MplsVpnUnicastAddress {
    path_id: Option<u32>,
    rd: RouteDistinguisher,
    label_stack: Vec<MplsLabel>,
    network: Ipv6Unicast,
}

impl Ipv6MplsVpnUnicastAddress {
    pub const fn new(
        path_id: Option<u32>,
        rd: RouteDistinguisher,
        label_stack: Vec<MplsLabel>,
        network: Ipv6Unicast,
    ) -> Self {
        Self {
            path_id,
            rd,
            label_stack,
            network,
        }
    }

    pub const fn new_no_path_id(
        rd: RouteDistinguisher,
        label_stack: Vec<MplsLabel>,
        network: Ipv6Unicast,
    ) -> Self {
        Self {
            path_id: None,
            rd,
            label_stack,
            network,
        }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn label_stack(&self) -> &Vec<MplsLabel> {
        &self.label_stack
    }

    pub const fn network(&self) -> Ipv6Unicast {
        self.network
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }
}

impl NlriAddressType for Ipv6MplsVpnUnicastAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv6MplsLabeledVpn
    }
}

/// A more restricted version of [`Ipv6Net`] that allows only multicast
/// networks
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv6Multicast(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6net))] Ipv6Net,
);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct InvalidIpv6MulticastNetwork(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6net))] pub Ipv6Net,
);

impl Ipv6Multicast {
    pub fn from_net(net: Ipv6Net) -> Result<Self, InvalidIpv6MulticastNetwork> {
        if !net.addr().is_multicast() {
            return Err(InvalidIpv6MulticastNetwork(net));
        }
        if let Some(addr) = net.hosts().last() {
            if !addr.is_multicast() {
                return Err(InvalidIpv6MulticastNetwork(net));
            }
        }
        Ok(Self(net))
    }

    pub const fn address(&self) -> Ipv6Net {
        self.0
    }
}

impl TryFrom<Ipv6Net> for Ipv6Multicast {
    type Error = InvalidIpv6MulticastNetwork;

    fn try_from(net: Ipv6Net) -> Result<Self, Self::Error> {
        Self::from_net(net)
    }
}

/// Ipv4 Multicast Network address in NLRI
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv6MulticastAddress {
    path_id: Option<u32>,
    network: Ipv6Multicast,
}

impl Ipv6MulticastAddress {
    pub const fn new(path_id: Option<u32>, network: Ipv6Multicast) -> Self {
        Self { path_id, network }
    }

    pub const fn new_no_path_id(network: Ipv6Multicast) -> Self {
        Self {
            path_id: None,
            network,
        }
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn network(&self) -> Ipv6Multicast {
        self.network
    }
}

impl NlriAddressType for Ipv6MulticastAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv6Multicast
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct EthernetSegmentIdentifier(pub [u8; 10]);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct EthernetTag(pub u32);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MacAddress(pub [u8; 6]);

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct L2EvpnAddress {
    path_id: Option<u32>,
    route: L2EvpnRoute,
}

impl L2EvpnAddress {
    pub const fn new(path_id: Option<u32>, route: L2EvpnRoute) -> Self {
        Self { path_id, route }
    }

    pub const fn path_id(&self) -> Option<&u32> {
        self.path_id.as_ref()
    }

    pub const fn route(&self) -> &L2EvpnRoute {
        &self.route
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum L2EvpnRoute {
    EthernetAutoDiscovery(EthernetAutoDiscovery),
    MacIpAdvertisement(MacIpAdvertisement),
    InclusiveMulticastEthernetTagRoute(InclusiveMulticastEthernetTagRoute),
    EthernetSegmentRoute(EthernetSegmentRoute),
    IpPrefixRoute(L2EvpnIpPrefixRoute),
    Unknown { code: u8, value: Vec<u8> },
}

impl L2EvpnRoute {
    pub const fn route_type(&self) -> Result<L2EvpnRouteTypeCode, u8> {
        match self {
            Self::EthernetAutoDiscovery(_) => Ok(L2EvpnRouteTypeCode::EthernetAutoDiscovery),
            Self::MacIpAdvertisement(_) => Ok(L2EvpnRouteTypeCode::MacIpAdvertisement),
            Self::InclusiveMulticastEthernetTagRoute(_) => {
                Ok(L2EvpnRouteTypeCode::InclusiveMulticastEthernetTagRoute)
            }
            Self::EthernetSegmentRoute(_) => Ok(L2EvpnRouteTypeCode::EthernetSegmentRoute),
            Self::IpPrefixRoute(_) => Ok(L2EvpnRouteTypeCode::IpPrefix),
            Self::Unknown { code, .. } => Err(*code),
        }
    }
}

impl NlriAddressType for L2EvpnAddress {
    fn address_type() -> AddressType {
        AddressType::L2VpnBgpEvpn
    }
}

/// An Ethernet A-D route type specific EVPN NLRI [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
/// ```text
/// +---------------------------------------+
/// |  Route Distinguisher (RD) (8 octets)  |
/// +---------------------------------------+
/// |Ethernet Segment Identifier (10 octets)|
/// +---------------------------------------+
/// |  Ethernet Tag ID (4 octets)           |
/// +---------------------------------------+
/// |  MPLS Label (3 octets)                |
/// +---------------------------------------+
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct EthernetAutoDiscovery {
    rd: RouteDistinguisher,
    segment_id: EthernetSegmentIdentifier,
    tag: EthernetTag,
    mpls_label: MplsLabel,
}

impl EthernetAutoDiscovery {
    pub const fn new(
        rd: RouteDistinguisher,
        segment_id: EthernetSegmentIdentifier,
        tag: EthernetTag,
        mpls_label: MplsLabel,
    ) -> Self {
        Self {
            rd,
            segment_id,
            tag,
            mpls_label,
        }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn segment_id(&self) -> &EthernetSegmentIdentifier {
        &self.segment_id
    }

    pub const fn tag(&self) -> &EthernetTag {
        &self.tag
    }
    pub const fn mpls_label(&self) -> &MplsLabel {
        &self.mpls_label
    }
}

/// A MAC/IP Advertisement route type specific EVPN NLRI
/// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
///
/// ```text
/// +---------------------------------------+
/// |  RD (8 octets)                        |
/// +---------------------------------------+
/// |Ethernet Segment Identifier (10 octets)|
/// +---------------------------------------+
/// |  Ethernet Tag ID (4 octets)           |
/// +---------------------------------------+
/// |  MAC Address Length (1 octet)         |
/// +---------------------------------------+
/// |  MAC Address (6 octets)               |
/// +---------------------------------------+
/// |  IP Address Length (1 octet)          |
/// +---------------------------------------+
/// |  IP Address (0, 4, or 16 octets)      |
/// +---------------------------------------+
/// |  MPLS Label1 (3 octets)               |
/// +---------------------------------------+
/// |  MPLS Label2 (0 or 3 octets)          |
/// +---------------------------------------+
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MacIpAdvertisement {
    rd: RouteDistinguisher,
    segment_id: EthernetSegmentIdentifier,
    tag: EthernetTag,
    mac: MacAddress,
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ip)))]
    ip: Option<IpAddr>,
    mpls_label1: MplsLabel,
    mpls_label2: Option<MplsLabel>,
}

impl MacIpAdvertisement {
    pub const fn new(
        rd: RouteDistinguisher,
        segment_id: EthernetSegmentIdentifier,
        tag: EthernetTag,
        mac: MacAddress,
        ip: Option<IpAddr>,
        mpls_label1: MplsLabel,
        mpls_label2: Option<MplsLabel>,
    ) -> Self {
        Self {
            rd,
            segment_id,
            tag,
            mac,
            ip,
            mpls_label1,
            mpls_label2,
        }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn segment_id(&self) -> &EthernetSegmentIdentifier {
        &self.segment_id
    }

    pub const fn tag(&self) -> &EthernetTag {
        &self.tag
    }

    pub const fn mac(&self) -> &MacAddress {
        &self.mac
    }

    pub const fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    pub const fn mpls_label1(&self) -> &MplsLabel {
        &self.mpls_label1
    }

    pub const fn mpls_label2(&self) -> Option<&MplsLabel> {
        self.mpls_label2.as_ref()
    }
}

/// An Inclusive Multicast Ethernet Tag route type specific EVPN NLRI
/// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
///
/// ```text
/// +---------------------------------------+
/// |  RD (8 octets)                        |
/// +---------------------------------------+
/// |  Ethernet Tag ID (4 octets)           |
/// +---------------------------------------+
/// |  IP Address Length (1 octet)          |
/// +---------------------------------------+
/// |  Originating Router's IP Address      |
/// |          (4 or 16 octets)             |
/// +---------------------------------------+
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct InclusiveMulticastEthernetTagRoute {
    rd: RouteDistinguisher,
    tag: EthernetTag,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
    ip: IpAddr,
}

impl InclusiveMulticastEthernetTagRoute {
    pub const fn new(rd: RouteDistinguisher, tag: EthernetTag, ip: IpAddr) -> Self {
        Self { rd, tag, ip }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn tag(&self) -> &EthernetTag {
        &self.tag
    }

    pub const fn ip(&self) -> IpAddr {
        self.ip
    }
}

/// An Ethernet Segment route type specific EVPN NLRI
/// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
///
/// ```text
/// +---------------------------------------+
/// |  RD (8 octets)                        |
/// +---------------------------------------+
/// |Ethernet Segment Identifier (10 octets)|
/// +---------------------------------------+
/// |  IP Address Length (1 octet)          |
/// +---------------------------------------+
/// |  Originating Router's IP Address      |
/// |          (4 or 16 octets)             |
/// +---------------------------------------+
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct EthernetSegmentRoute {
    rd: RouteDistinguisher,
    segment_id: EthernetSegmentIdentifier,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
    ip: IpAddr,
}

impl EthernetSegmentRoute {
    pub const fn new(
        rd: RouteDistinguisher,
        segment_id: EthernetSegmentIdentifier,
        ip: IpAddr,
    ) -> Self {
        Self { rd, segment_id, ip }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn segment_id(&self) -> &EthernetSegmentIdentifier {
        &self.segment_id
    }

    pub const fn ip(&self) -> IpAddr {
        self.ip
    }
}

/// The BGP EVPN IPv4 or IPv6 Prefix Route
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum L2EvpnIpPrefixRoute {
    V4(L2EvpnIpv4PrefixRoute),
    V6(L2EvpnIpv6PrefixRoute),
}

/// The BGP EVPN IPv4 Prefix Route
/// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
/// ```text
///  +---------------------------------------+
/// |      RD (8 octets)                    |
/// +---------------------------------------+
/// |Ethernet Segment Identifier (10 octets)|
/// +---------------------------------------+
/// |  Ethernet Tag ID (4 octets)           |
/// +---------------------------------------+
/// |  IP Prefix Length (1 octet, 0 to 32)  |
/// +---------------------------------------+
/// |  IP Prefix (4 octets)                 |
/// +---------------------------------------+
/// |  GW IP Address (4 octets)             |
/// +---------------------------------------+
/// |  MPLS Label (3 octets)                |
/// +---------------------------------------+
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct L2EvpnIpv4PrefixRoute {
    rd: RouteDistinguisher,
    segment_id: EthernetSegmentIdentifier,
    tag: EthernetTag,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4net))]
    prefix: Ipv4Net,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4))]
    gateway: Ipv4Addr,
    label: MplsLabel,
}

impl L2EvpnIpv4PrefixRoute {
    pub const fn new(
        rd: RouteDistinguisher,
        segment_id: EthernetSegmentIdentifier,
        tag: EthernetTag,
        prefix: Ipv4Net,
        gateway: Ipv4Addr,
        label: MplsLabel,
    ) -> Self {
        Self {
            rd,
            segment_id,
            tag,
            prefix,
            gateway,
            label,
        }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn segment_id(&self) -> &EthernetSegmentIdentifier {
        &self.segment_id
    }

    pub const fn tag(&self) -> &EthernetTag {
        &self.tag
    }
    pub const fn prefix(&self) -> Ipv4Net {
        self.prefix
    }
    pub const fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    pub const fn label(&self) -> &MplsLabel {
        &self.label
    }
}

/// The BGP EVPN IPv4 Prefix Route
/// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
/// ```text
///  +---------------------------------------+
/// |      RD (8 octets)                    |
/// +---------------------------------------+
/// |Ethernet Segment Identifier (10 octets)|
/// +---------------------------------------+
/// |  Ethernet Tag ID (4 octets)           |
/// +---------------------------------------+
/// |  IP Prefix Length (1 octet, 0 to 32)  |
/// +---------------------------------------+
/// |  IP Prefix (4 octets)                 |
/// +---------------------------------------+
/// |  GW IP Address (4 octets)             |
/// +---------------------------------------+
/// |  MPLS Label (3 octets)                |
/// +---------------------------------------+
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct L2EvpnIpv6PrefixRoute {
    rd: RouteDistinguisher,
    segment_id: EthernetSegmentIdentifier,
    tag: EthernetTag,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6net))]
    prefix: Ipv6Net,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6))]
    gateway: Ipv6Addr,
    label: MplsLabel,
}

impl L2EvpnIpv6PrefixRoute {
    pub const fn new(
        rd: RouteDistinguisher,
        segment_id: EthernetSegmentIdentifier,
        tag: EthernetTag,
        prefix: Ipv6Net,
        gateway: Ipv6Addr,
        label: MplsLabel,
    ) -> Self {
        Self {
            rd,
            segment_id,
            tag,
            prefix,
            gateway,
            label,
        }
    }

    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }

    pub const fn segment_id(&self) -> &EthernetSegmentIdentifier {
        &self.segment_id
    }

    pub const fn tag(&self) -> &EthernetTag {
        &self.tag
    }
    pub const fn prefix(&self) -> Ipv6Net {
        self.prefix
    }
    pub const fn gateway(&self) -> Ipv6Addr {
        self.gateway
    }

    pub const fn label(&self) -> &MplsLabel {
        &self.label
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct RouteTargetMembershipAddress {
    path_id: Option<u32>,
    membership: Option<RouteTargetMembership>,
}

impl RouteTargetMembershipAddress {
    pub const fn new(path_id: Option<u32>, membership: Option<RouteTargetMembership>) -> Self {
        Self {
            path_id,
            membership,
        }
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn membership(&self) -> Option<&RouteTargetMembership> {
        self.membership.as_ref()
    }
}

/// Route Target Membership NLRI
/// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
/// ```text
/// +-------------------------------+
/// | origin as        (4 octets)   |
/// +-------------------------------+
/// | route target     (8 octets)   |
/// +                               +
/// |                               |
/// +-------------------------------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct RouteTargetMembership {
    origin_as: u32,
    /// Route targets can then be expressed as prefixes, where, for instance,
    /// a prefix would encompass all route target extended communities
    /// assigned by a given Global Administrator
    route_target: Vec<u8>,
}

impl RouteTargetMembership {
    pub const fn new(origin_as: u32, route_target: Vec<u8>) -> Self {
        Self {
            origin_as,
            route_target,
        }
    }

    pub const fn origin_as(&self) -> u32 {
        self.origin_as
    }

    pub const fn route_target(&self) -> &Vec<u8> {
        &self.route_target
    }
}

impl NlriAddressType for RouteTargetMembershipAddress {
    fn address_type() -> AddressType {
        AddressType::RouteTargetConstrains
    }
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum InvalidIpv4NlriMplsLabelsAddress {
    /// Total length should not exceed 255, each MPLS Label is 24 bit and
    /// account for up to 32 bit IPv4 prefix length
    InvalidLabelsLength(usize),
}

/// Binding IPv4 addresses to one or more MPLS labels
///
/// [RFC8277](https://datatracker.ietf.org/doc/html/rfc8277) defines two wire format based on
/// if the Multiple Label capability is used or not.
///
/// When Multiple Label capability IS NOT used
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Length     |                 Label                 |Rsrv |S|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Prefix                               ~
/// ~                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// When Multiple Label capability IS used
/// ```text
/// 0                   1                   2                     3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |    Length     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Label                 |Rsrv |S~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ~                 Label                 |Rsrv |S|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Prefix                               ~
/// ~                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv4NlriMplsLabelsAddress {
    path_id: Option<u32>,
    labels: Vec<MplsLabel>,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4net))]
    prefix: Ipv4Net,
}

impl Ipv4NlriMplsLabelsAddress {
    pub fn from(
        path_id: Option<u32>,
        labels: Vec<MplsLabel>,
        prefix: Ipv4Net,
    ) -> Result<Self, InvalidIpv4NlriMplsLabelsAddress> {
        // Total length should not exceed 255, each MPLS Label is 24 bit and account for
        // 32 bit IP prefix length
        if labels.len() * 24 + prefix.prefix_len() as usize > u8::MAX as usize {
            Err(InvalidIpv4NlriMplsLabelsAddress::InvalidLabelsLength(
                labels.len(),
            ))
        } else {
            Ok(Self {
                path_id,
                labels,
                prefix,
            })
        }
    }

    pub fn new_no_path_id(
        labels: Vec<MplsLabel>,
        prefix: Ipv4Net,
    ) -> Result<Self, InvalidIpv4NlriMplsLabelsAddress> {
        Self::from(None, labels, prefix)
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn labels(&self) -> &Vec<MplsLabel> {
        &self.labels
    }

    pub const fn prefix(&self) -> Ipv4Net {
        self.prefix
    }
}

impl NlriAddressType for Ipv4NlriMplsLabelsAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv4NlriMplsLabels
    }
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum InvalidIpv6NlriMplsLabelsAddress {
    /// Total length should not exceed 255, each MPLS Label is 24 bit and
    /// account for up to 128 bit IPv6 prefix length
    InvalidLabelsLength(usize),
}

/// Binding IPv6 addresses to one or more MPLS labels
///
/// [RFC8277](https://datatracker.ietf.org/doc/html/rfc8277) defines two wire format based on
/// if the Multiple Label capability is used or not.
///
/// When Multiple Label capability IS NOT used
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Length     |                 Label                 |Rsrv |S|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Prefix                               ~
/// ~                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// When Multiple Label capability IS used
/// ```text
/// 0                   1                   2                     3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |    Length     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Label                 |Rsrv |S~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ~                 Label                 |Rsrv |S|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Prefix                               ~
/// ~                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Ipv6NlriMplsLabelsAddress {
    path_id: Option<u32>,
    labels: Vec<MplsLabel>,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6net))]
    prefix: Ipv6Net,
}

impl Ipv6NlriMplsLabelsAddress {
    pub fn from(
        path_id: Option<u32>,
        labels: Vec<MplsLabel>,
        prefix: Ipv6Net,
    ) -> Result<Self, InvalidIpv6NlriMplsLabelsAddress> {
        // Total length should not exceed 255, each MPLS Label is 24 bit and account for
        // 32 bit IP prefix length
        if labels.len() * 24 + prefix.prefix_len() as usize > u8::MAX as usize {
            Err(InvalidIpv6NlriMplsLabelsAddress::InvalidLabelsLength(
                labels.len(),
            ))
        } else {
            Ok(Self {
                path_id,
                labels,
                prefix,
            })
        }
    }

    pub fn new_no_path_id(
        labels: Vec<MplsLabel>,
        prefix: Ipv6Net,
    ) -> Result<Self, InvalidIpv6NlriMplsLabelsAddress> {
        Self::from(None, labels, prefix)
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn labels(&self) -> &Vec<MplsLabel> {
        &self.labels
    }

    pub const fn prefix(&self) -> Ipv6Net {
        self.prefix
    }
}

impl NlriAddressType for Ipv6NlriMplsLabelsAddress {
    fn address_type() -> AddressType {
        AddressType::Ipv6NlriMplsLabels
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv4_unicast() {
        let unicast_addr = Ipv4Net::new(Ipv4Addr::new(192, 168, 56, 1), 4).unwrap();
        let multicast_addr = Ipv4Net::new(Ipv4Addr::new(224, 0, 0, 13), 4).unwrap();

        let unicast = Ipv4Unicast::try_from(unicast_addr);
        let multicast = Ipv4Unicast::try_from(multicast_addr);

        assert!(unicast.is_ok());
        assert!(unicast.is_ok());
        assert_eq!(unicast.unwrap().address(), unicast_addr);
        assert_eq!(Ipv4UnicastAddress::address_type(), AddressType::Ipv4Unicast);
        assert_eq!(multicast, Err(InvalidIpv4UnicastNetwork(multicast_addr)));
    }

    #[test]
    fn test_ipv4_multicast() {
        let unicast_addr = Ipv4Net::new(Ipv4Addr::new(192, 168, 56, 1), 4).unwrap();
        let multicast_addr = Ipv4Net::new(Ipv4Addr::new(224, 0, 0, 13), 4).unwrap();

        let unicast = Ipv4Multicast::try_from(unicast_addr);
        let multicast = Ipv4Multicast::try_from(multicast_addr);

        assert!(multicast.is_ok());
        assert!(multicast.is_ok());
        assert_eq!(multicast.unwrap().address(), multicast_addr);
        assert_eq!(
            Ipv4MulticastAddress::address_type(),
            AddressType::Ipv4Multicast
        );
        assert_eq!(unicast, Err(InvalidIpv4MulticastNetwork(unicast_addr)));
    }

    #[test]
    fn test_ipv6_unicast() {
        let unicast_addr = Ipv6Net::new(Ipv6Addr::LOCALHOST, 64).unwrap();
        let multicast_addr = Ipv6Net::from_str("ff00::/8").unwrap();

        let unicast = Ipv6Unicast::try_from(unicast_addr);
        let multicast = Ipv6Unicast::try_from(multicast_addr);

        assert!(unicast.is_ok());
        assert_eq!(unicast.unwrap().address(), unicast_addr);
        assert_eq!(Ipv6UnicastAddress::address_type(), AddressType::Ipv6Unicast);
        assert_eq!(multicast, Err(InvalidIpv6UnicastNetwork(multicast_addr)));
    }

    #[test]
    fn test_ipv6_multicast() {
        let unicast_addr = Ipv6Net::new(Ipv6Addr::LOCALHOST, 64).unwrap();
        let multicast_addr = Ipv6Net::from_str("ff00::/8").unwrap();

        let unicast = Ipv6Multicast::try_from(unicast_addr);
        let multicast = Ipv6Multicast::try_from(multicast_addr);

        assert!(multicast.is_ok());
        assert_eq!(multicast.unwrap().address(), multicast_addr);
        assert_eq!(
            Ipv6MulticastAddress::address_type(),
            AddressType::Ipv6Multicast
        );
        assert_eq!(unicast, Err(InvalidIpv6MulticastNetwork(unicast_addr)));
    }
}
