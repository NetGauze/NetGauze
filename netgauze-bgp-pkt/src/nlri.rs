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

use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_iana::address_family::AddressType;

/// Get the [netgauze_iana::address_family::AddressType] of a given NLRI
pub trait NlriAddressType {
    fn address_type() -> AddressType;
}

/// A more restricted version of [ipnet::Ipv4Net] that allows only unicast
/// networks
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv4Unicast(Ipv4Net);

/// Raised when the network is not a unicast range
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

impl NlriAddressType for Ipv4Unicast {
    fn address_type() -> AddressType {
        AddressType::Ipv4Unicast
    }
}

/// A more restricted version of `ipnet::Ipv4Net` that allows only multicast
/// networks
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv4Multicast(Ipv4Net);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

impl NlriAddressType for Ipv4Multicast {
    fn address_type() -> AddressType {
        AddressType::Ipv4Multicast
    }
}

/// A more restricted version of `ipnet::Ipv6Net` that allows only unicast
/// networks
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv6Unicast(Ipv6Net);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

impl NlriAddressType for Ipv6Unicast {
    fn address_type() -> AddressType {
        AddressType::Ipv6Unicast
    }
}

/// A more restricted version of `ipnet::Ipv6Net` that allows only multicast
/// networks
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv6Multicast(Ipv6Net);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

impl NlriAddressType for Ipv6Multicast {
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
        assert_eq!(Ipv4Unicast::address_type(), AddressType::Ipv4Unicast);
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
        assert_eq!(Ipv4Multicast::address_type(), AddressType::Ipv4Multicast);
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
        assert_eq!(Ipv6Unicast::address_type(), AddressType::Ipv6Unicast);
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
        assert_eq!(Ipv6Multicast::address_type(), AddressType::Ipv6Multicast);
        assert_eq!(unicast, Err(InvalidIpv6MulticastNetwork(unicast_addr)));
    }
}
