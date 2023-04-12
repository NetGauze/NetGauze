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

use crate::iana::RouteDistinguisherTypeCode;
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_iana::address_family::AddressType;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Get the [`AddressType`] of a given NLRI
pub trait NlriAddressType {
    fn address_type() -> AddressType;
}

/// Temporary representation of MPLS Labels
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
    Ipv4Administrator { ip: Ipv4Addr, number: u16 },

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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LabeledIpv4NextHop {
    rd: RouteDistinguisher,
    next_hop: Ipv4Addr,
}

impl LabeledIpv4NextHop {
    pub const fn new(rd: RouteDistinguisher, next_hop: Ipv4Addr) -> Self {
        Self { rd, next_hop }
    }

    pub const fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }

    pub const fn next_hop(&self) -> &Ipv4Addr {
        &self.next_hop
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LabeledIpv6NextHop {
    rd: RouteDistinguisher,
    next_hop: Ipv6Addr,
}

impl LabeledIpv6NextHop {
    pub const fn new(rd: RouteDistinguisher, next_hop: Ipv6Addr) -> Self {
        Self { rd, next_hop }
    }

    pub const fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }

    pub const fn next_hop(&self) -> &Ipv6Addr {
        &self.next_hop
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum LabeledNextHop {
    Ipv4(LabeledIpv4NextHop),
    Ipv6(LabeledIpv6NextHop),
}

/// A more restricted version of [`Ipv4Net`] that allows only unicast
/// networks
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv4Unicast(Ipv4Net);

/// Raised when the network is not a unicast range
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InvalidIpv4UnicastNetwork(pub Ipv4Net);

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

    pub const fn address(&self) -> &Ipv4Net {
        &self.0
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

    pub const fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }

    pub const fn label_stack(&self) -> &Vec<MplsLabel> {
        &self.label_stack
    }

    pub const fn network(&self) -> &Ipv4Unicast {
        &self.network
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
pub struct Ipv4Multicast(Ipv4Net);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InvalidIpv4MulticastNetwork(pub Ipv4Net);

impl Ipv4Multicast {
    pub fn from_net(net: Ipv4Net) -> Result<Self, InvalidIpv4MulticastNetwork> {
        if !net.addr().is_multicast() || net.hosts().last().map(|x| x.is_multicast()) == Some(false)
        {
            return Err(InvalidIpv4MulticastNetwork(net));
        }
        Ok(Self(net))
    }

    pub const fn address(&self) -> &Ipv4Net {
        &self.0
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
pub struct Ipv6Unicast(Ipv6Net);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InvalidIpv6UnicastNetwork(pub Ipv6Net);

impl Ipv6Unicast {
    pub fn from_net(net: Ipv6Net) -> Result<Self, InvalidIpv6UnicastNetwork> {
        if net.addr().is_multicast() || net.hosts().last().map(|x| x.is_multicast()) == Some(true) {
            return Err(InvalidIpv6UnicastNetwork(net));
        }
        Ok(Self(net))
    }

    pub const fn address(&self) -> &Ipv6Net {
        &self.0
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

    pub const fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }

    pub const fn label_stack(&self) -> &Vec<MplsLabel> {
        &self.label_stack
    }

    pub const fn network(&self) -> &Ipv6Unicast {
        &self.network
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
pub struct Ipv6Multicast(Ipv6Net);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InvalidIpv6MulticastNetwork(pub Ipv6Net);

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

    pub const fn address(&self) -> &Ipv6Net {
        &self.0
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

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_iana::address_family::AddressType;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    #[test]
    fn test_ipv4_unicast() {
        let unicast_addr = Ipv4Net::new(Ipv4Addr::new(192, 168, 56, 1), 4).unwrap();
        let multicast_addr = Ipv4Net::new(Ipv4Addr::new(224, 0, 0, 13), 4).unwrap();

        let unicast = Ipv4Unicast::try_from(unicast_addr);
        let multicast = Ipv4Unicast::try_from(multicast_addr);

        assert!(unicast.is_ok());
        assert!(unicast.is_ok());
        assert_eq!(unicast.unwrap().address(), &unicast_addr);
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
        assert_eq!(multicast.unwrap().address(), &multicast_addr);
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
        assert_eq!(unicast.unwrap().address(), &unicast_addr);
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
        assert_eq!(multicast.unwrap().address(), &multicast_addr);
        assert_eq!(
            Ipv6MulticastAddress::address_type(),
            AddressType::Ipv6Multicast
        );
        assert_eq!(unicast, Err(InvalidIpv6MulticastNetwork(unicast_addr)));
    }
}
