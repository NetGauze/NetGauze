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

//! Handling [AddressFamily] (SAFI) and [SubsequentAddressFamily] (SAFI).
//! Also introduces a new `enum` [AddressType] to make sure we can only
//! construct valid AFI/SAFI combinations
//!
//! ```rust
//! use netgauze_iana::address_family::*;
//!
//! let ipv4_unicast = AddressType::Ipv4Unicast;
//! let ipv6_unicast =
//!     AddressType::from_afi_safi(AddressFamily::IPv6, SubsequentAddressFamily::Unicast);
//! let invalid =
//!     AddressType::from_afi_safi(AddressFamily::AppleTalk, SubsequentAddressFamily::BgpEvpn);
//!
//! assert_eq!(ipv4_unicast.address_family(), AddressFamily::IPv4);
//! assert_eq!(
//!     ipv4_unicast.subsequent_address_family(),
//!     SubsequentAddressFamily::Unicast
//! );
//! assert_eq!(ipv6_unicast, Ok(AddressType::Ipv6Unicast));
//! assert_eq!(
//!     invalid,
//!     Err(InvalidAddressType::new(
//!         AddressFamily::AppleTalk,
//!         SubsequentAddressFamily::BgpEvpn
//!     ))
//! );
//! ```

use strum_macros::{Display, FromRepr};

/// Address families identifiers (AFI) registered at IANA [Address Family Number](https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml)
///
/// ```rust
/// use netgauze_iana::address_family::{AddressFamily, UndefinedAddressFamily};
///
/// let afi = AddressFamily::IPv6;
/// println!("IPv6 AFI is: {}", afi);
///
/// let undefined = AddressFamily::try_from(65000);
/// assert_eq!(undefined, Err(UndefinedAddressFamily(65000)));
/// ```
#[repr(u16)]
#[derive(FromRepr, Display, Copy, Clone, PartialEq, Eq, Debug)]
pub enum AddressFamily {
    IPv4 = 1,
    IPv6 = 2,
    Nsap = 3,
    Hdlc = 4,
    BBN1822 = 5,
    /// 802 (includes all 802 media plus Ethernet "canonical format")
    IEEE802 = 6,

    E163 = 7,

    /// SMDS, Frame Relay, ATM
    E164 = 8,

    /// F.69 (Telex)
    F69 = 9,

    /// X.121 (X.25, Frame Relay)
    FrameRelay = 10,

    IPX = 11,
    AppleTalk = 12,
    DecnetIv = 13,
    BanyanVines = 14,
    /// E.164 with NSAP format subaddress
    E164Nsap = 15,

    /// DNS (Domain Name System)
    DNS = 16,

    DistinguishedName = 17,
    ASNumber = 18,

    /// XTP over IP version 4
    XtpIpv4 = 19,

    /// XTP over IP version 6
    XtpIpv6 = 20,

    /// XTP native mode XTP
    XTPNative = 21,

    /// Fibre Channel World-Wide Port Name
    FiberPortName = 22,

    /// Fibre Channel World-Wide Node Name
    FiberNodeName = 23,

    Gwid = 24,

    /// [RFC4761](https://datatracker.ietf.org/doc/html/RFC4761)
    /// [RFC6074](https://datatracker.ietf.org/doc/html/RFC6074) AFI for L2VPN information
    L2vpn = 25,

    /// [RFC7212](https://datatracker.ietf.org/doc/html/RFC7212) MPLS-TP Section Endpoint Identifier
    MplsTpSectionEndpointId = 26,

    /// [RFC7212](https://datatracker.ietf.org/doc/html/RFC7212)  MPLS-TP LSP Endpoint Identifier
    MplsTpLspEndpointId = 27,

    /// [RFC7212](https://datatracker.ietf.org/doc/html/RFC7212) MPLS-TP Pseudowire Endpoint Identifier
    MplsTpPseudowireEndpointId = 28,

    /// [RFC7307](https://datatracker.ietf.org/doc/html/RFC7307) MT IP: Multi-Topology IP version 4
    MpIpv4 = 29,

    /// [RFC7307](https://datatracker.ietf.org/doc/html/RFC7307) MT IPv6: Multi-Topology IP version 6
    MpIpv6 = 30,

    /// [RFC9015](https://datatracker.ietf.org/doc/html/RFC9015) BGP SFC
    BgpSfc = 31,

    /// EIGRP Common Service Family
    EigrpCommonServiceFamily = 16384,

    /// EIGRP IPv4 Service Family
    EigrpIpv4 = 16385,

    /// EIGRP IPv6 Service Family
    EigrpIpv6 = 16386,

    /// LISP Canonical Address Format (LCAF)
    LispCanonicalAddressFormat = 16387,

    /// [RFC7752](https://datatracker.ietf.org/doc/html/RFC7752) BGP-LS
    BgpLs = 16388,

    /// [RFC7042](https://datatracker.ietf.org/doc/html/RFC7042) 48-bit MAC
    Mac48Bit = 16389,

    /// [RFC7042](https://datatracker.ietf.org/doc/html/RFC7042) 64-bit MAC
    Mac64Bit = 16390,

    /// [RFC7961](https://datatracker.ietf.org/doc/html/RFC7961) OUI
    OUI = 16391,

    /// [RFC7961](https://datatracker.ietf.org/doc/html/RFC7961) MAC/24
    MacSlash24 = 16392,

    /// [RFC7961](https://datatracker.ietf.org/doc/html/RFC7961) MAC/40
    MacSlash40 = 16393,

    /// [RFC7961](https://datatracker.ietf.org/doc/html/RFC7961) IPv6/64
    Ipv6Slash64 = 16394,

    /// [RFC7961](https://datatracker.ietf.org/doc/html/RFC7961) RBridge Port ID
    RBridgePortID = 16395,

    /// [RFC7455](https://datatracker.ietf.org/doc/html/RFC7455) TRILL Nickname
    TrillNickname = 16396,

    /// Universally Unique Identifier (UUID)
    Uuid = 16397,

    /// Routing Policy AFI [draft-ietf-idr-rpd-15](https://datatracker.ietf.org/doc/html/draft-ietf-idr-rpd)
    RoutingPolicyAfi = 16398,

    /// [draft-kaliraj-bess-bgp-sig-private-mpls-labels](https://datatracker.ietf.org/doc/draft-kaliraj-bess-bgp-sig-private-mpls-labels/)
    MplsNamespaces = 16399,
}

/// Error type used in `[TryFrom] for [AddressFamily].
/// The value carried is the undefined value being parsed
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct UndefinedAddressFamily(pub u16);

impl From<AddressFamily> for u16 {
    fn from(afi: AddressFamily) -> Self {
        afi as u16
    }
}

impl TryFrom<u16> for AddressFamily {
    type Error = UndefinedAddressFamily;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedAddressFamily(value)),
        }
    }
}

/// Subsequent Address families identifiers (SAFI) registered at IANA [Subsequent Address Family Identifiers (SAFI) Parameters](https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml)
///
/// ```rust
/// use netgauze_iana::address_family::{
///     SubsequentAddressFamily, UndefinedSubsequentAddressFamily,
/// };
///
/// let safi = SubsequentAddressFamily::Unicast;
/// println!("Unicast SAFI is: {}", safi);
///
/// let undefined = SubsequentAddressFamily::try_from(0);
/// assert_eq!(undefined, Err(UndefinedSubsequentAddressFamily(0)));
/// ```
#[repr(u8)]
#[derive(FromRepr, Display, Copy, Clone, PartialEq, Eq, Debug)]
pub enum SubsequentAddressFamily {
    /// Network Layer Reachability Information used for unicast forwarding
    /// [RFC4760](https://datatracker.ietf.org/doc/html/RFC4760)
    Unicast = 1,

    /// Network Layer Reachability Information used for multicast forwarding
    /// [RFC4760](https://datatracker.ietf.org/doc/html/RFC4760)
    Multicast = 2,

    /// Network Layer Reachability Information (NLRI) with MPLS Labels
    /// [RFC8277](https://datatracker.ietf.org/doc/html/RFC8277)
    NlriMplsLabels = 4,

    /// MCAST-VPN [RFC6514](https://datatracker.ietf.org/doc/html/RFC6514)
    McastVpn = 5,

    /// Network Layer Reachability Information used for
    /// Dynamic Placement of Multi-Segment Pseudowires
    /// [RFC7267](https://datatracker.ietf.org/doc/html/RFC7267)
    NlriMsp = 6,

    /// Encapsulation SAFI (OBSOLETE) [RFC9012](https://datatracker.ietf.org/doc/html/RFC9012) = 7,
    /// MCAST-VPLS [RFC7117](https://datatracker.ietf.org/doc/html/RFC7117)
    McastVpls = 8,

    /// BGP SFC [RFC9015](https://datatracker.ietf.org/doc/html/RFC9015)
    BgpSfc = 9,

    /// Tunnel SAFI
    /// [draft-nalawade-kapoor-tunnel-safi](https://datatracker.ietf.org/doc/html/draft-nalawade-kapoor-tunnel-safi)
    Tunnel = 64,

    /// Virtual Private LAN Service (VPLS)
    /// [RFC4761](https://datatracker.ietf.org/doc/html/RFC4761)
    /// [RFC6074](https://datatracker.ietf.org/doc/html/RFC6074)
    VPLS = 65,

    /// BGP MDT SAFI [RFC6037](https://datatracker.ietf.org/doc/html/RFC6037)
    BgpMdtSafi = 66,

    /// BGP 4over6 SAFI [RFC5747](https://datatracker.ietf.org/doc/html/RFC5747)
    Bgp4over6 = 67,

    /// BGP 6over4 SAFI
    Bgp6over4 = 68,

    /// Layer-1 VPN auto-discovery information [RFC5195](https://datatracker.ietf.org/doc/html/RFC5195)
    Layer1Vpn = 69,

    /// BGP EVPNs [RFC7432](https://datatracker.ietf.org/doc/html/RFC7432)
    BgpEvpn = 70,

    /// BGP-LS [RFC7752](https://datatracker.ietf.org/doc/html/RFC7752)
    BgpLs = 71,

    /// BGP-LS-VPN [RFC7752](https://datatracker.ietf.org/doc/html/RFC7752)
    BgpLsVpn = 72,

    /// SR TE Policy SAFI
    /// [draft-previdi-idr-segment-routing-te-policy](https://datatracker.ietf.org/doc/html/draft-previdi-idr-segment-routing-te-policy)
    SrTePolicy = 73,

    /// SD-WAN Capabilities
    /// [draft-dunbar-idr-sdwan-port-safi](https://datatracker.ietf.org/doc/html/draft-dunbar-idr-sdwan-port-safi)
    SdnWan = 74,

    /// Routing Policy SAFI
    /// [draft-ietf-idr-rpd](https://datatracker.ietf.org/doc/html/draft-ietf-idr-rpd)
    RoutingPolicy = 75,

    /// Classful-Transport SAFI
    /// [draft-kaliraj-idr-bgp-classful-transport-planes](https://datatracker.ietf.org/doc/html/draft-kaliraj-idr-bgp-classful-transport-planes)
    ClassfulTransport = 76,

    /// Tunneled Traffic Flowspec
    /// [draft-ietf-idr-flowspec-nvo3](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-nvo3)
    TunneledTrafficFlowSpec = 77,

    /// MCAST-TREE
    /// [draft-ietf-bess-bgp-multicast](https://datatracker.ietf.org/doc/html/draft-ietf-bess-bgp-multicast)
    McastTree = 78,

    /// BGP-DPS (Dynamic Path Selection)
    /// [dps-vpn-scaling-using-bgp](https://eos.arista.com/eos-4-26-2f/dps-vpn-scaling-using-bgp)
    BgpDps = 79,

    /// MPLS-labeled VPN address
    /// [RFC4364](https://datatracker.ietf.org/doc/html/RFC4364)
    /// [RFC8277](https://datatracker.ietf.org/doc/html/RFC8277)
    MplsVpn = 128,

    /// Multicast for BGP/MPLS IP Virtual Private Networks (VPNs)
    /// [RFC6513](https://datatracker.ietf.org/doc/html/RFC6513)
    /// [RFC6514](https://datatracker.ietf.org/doc/html/RFC6514)
    MulticastBgpMplsVpn = 129,

    /// Route Target constrains [RFC4684](https://datatracker.ietf.org/doc/html/RFC4684)
    RouteTargetConstrains = 132,

    /// Dissemination of Flow Specification rules
    /// [RFC8955](https://datatracker.ietf.org/doc/html/RFC8955)
    FlowSPecFilter = 133,

    /// L3VPN Dissemination of Flow Specification rules
    /// [RFC8955](https://datatracker.ietf.org/doc/html/RFC8955)
    FlowSPecFilterL3Vpn = 134,

    /// [draft-ietf-l3vpn-bgpvpn-auto](https://datatracker.ietf.org/doc/html/draft-ietf-l3vpn-bgpvpn-auto)
    VpnAutoDiscovery = 140,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse241 = 241,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse242 = 242,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse243 = 243,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse244 = 244,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse245 = 245,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse246 = 246,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse247 = 247,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse248 = 248,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse249 = 249,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse250 = 250,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse251 = 251,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse252 = 252,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse253 = 253,

    /// Reserved for Private Use [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    PrivateUse254 = 254,
}

/// Error type used in `[TryFrom] for [SubsequentAddressFamily].
/// The value carried is the undefined value being parsed
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct UndefinedSubsequentAddressFamily(pub u8);

impl From<SubsequentAddressFamily> for u8 {
    fn from(safi: SubsequentAddressFamily) -> Self {
        safi as u8
    }
}

impl TryFrom<u8> for SubsequentAddressFamily {
    type Error = UndefinedSubsequentAddressFamily;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedSubsequentAddressFamily(value)),
        }
    }
}

/// Since not all [AddressFamily] and [SubsequentAddressFamily] are valid
/// combinations, this enum defines a set of valid combination to ensure only
/// valid AFI/SAFI are used at compile time.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AddressType {
    Ipv4Unicast,
    Ipv4Multicast,
    IpPv4MplsLabeledVpn,
    Ipv4MulticastBgpMplsVpn,
    Ipv4Bgp4over6,
    Ipv6Unicast,
    Ipv6Multicast,
    Ipv6MPLSLabeledVpn,
    Ipv6MulticastBgpMplsVpn,
    Ipv6Bgp6over4,
    L2VpnBgpEvpn,
}

/// Error type used in `[TryFrom] for [AddressType].
/// The value carried is the undefined value being parsed
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct InvalidAddressType {
    address_family: AddressFamily,
    subsequent_address_family: SubsequentAddressFamily,
}

impl InvalidAddressType {
    pub const fn new(
        address_family: AddressFamily,
        subsequent_address_family: SubsequentAddressFamily,
    ) -> Self {
        Self {
            address_family,
            subsequent_address_family,
        }
    }

    pub const fn address_family(&self) -> AddressFamily {
        self.address_family
    }

    pub const fn subsequent_address_family(&self) -> SubsequentAddressFamily {
        self.subsequent_address_family
    }
}

impl AddressType {
    pub const fn address_family(&self) -> AddressFamily {
        match self {
            Self::Ipv4Unicast => AddressFamily::IPv4,
            Self::Ipv4Multicast => AddressFamily::IPv4,
            Self::IpPv4MplsLabeledVpn => AddressFamily::IPv4,
            Self::Ipv4MulticastBgpMplsVpn => AddressFamily::IPv4,
            Self::Ipv4Bgp4over6 => AddressFamily::IPv4,

            Self::Ipv6Unicast => AddressFamily::IPv6,
            Self::Ipv6Multicast => AddressFamily::IPv6,
            Self::Ipv6MPLSLabeledVpn => AddressFamily::IPv6,
            Self::Ipv6MulticastBgpMplsVpn => AddressFamily::IPv6,
            Self::Ipv6Bgp6over4 => AddressFamily::IPv6,

            Self::L2VpnBgpEvpn => AddressFamily::L2vpn,
        }
    }

    pub const fn subsequent_address_family(&self) -> SubsequentAddressFamily {
        match self {
            Self::Ipv4Unicast => SubsequentAddressFamily::Unicast,
            Self::Ipv4Multicast => SubsequentAddressFamily::Multicast,
            Self::IpPv4MplsLabeledVpn => SubsequentAddressFamily::MplsVpn,
            Self::Ipv4MulticastBgpMplsVpn => SubsequentAddressFamily::MulticastBgpMplsVpn,
            Self::Ipv4Bgp4over6 => SubsequentAddressFamily::Bgp4over6,

            Self::Ipv6Unicast => SubsequentAddressFamily::Unicast,
            Self::Ipv6Multicast => SubsequentAddressFamily::Multicast,
            Self::Ipv6MPLSLabeledVpn => SubsequentAddressFamily::MplsVpn,
            Self::Ipv6MulticastBgpMplsVpn => SubsequentAddressFamily::MulticastBgpMplsVpn,
            Self::Ipv6Bgp6over4 => SubsequentAddressFamily::Bgp6over4,

            Self::L2VpnBgpEvpn => SubsequentAddressFamily::BgpEvpn,
        }
    }

    pub const fn from_afi_safi(
        afi: AddressFamily,
        safi: SubsequentAddressFamily,
    ) -> Result<Self, InvalidAddressType> {
        match (afi, safi) {
            (AddressFamily::IPv4, SubsequentAddressFamily::Unicast) => Ok(Self::Ipv4Unicast),
            (AddressFamily::IPv4, SubsequentAddressFamily::Multicast) => Ok(Self::Ipv4Multicast),
            (AddressFamily::IPv4, SubsequentAddressFamily::MplsVpn) => {
                Ok(Self::IpPv4MplsLabeledVpn)
            }
            (AddressFamily::IPv4, SubsequentAddressFamily::MulticastBgpMplsVpn) => {
                Ok(Self::Ipv4MulticastBgpMplsVpn)
            }
            (AddressFamily::IPv4, SubsequentAddressFamily::Bgp4over6) => Ok(Self::Ipv4Bgp4over6),

            (AddressFamily::IPv6, SubsequentAddressFamily::Unicast) => Ok(Self::Ipv6Unicast),
            (AddressFamily::IPv6, SubsequentAddressFamily::Multicast) => Ok(Self::Ipv6Multicast),
            (AddressFamily::IPv6, SubsequentAddressFamily::MplsVpn) => Ok(Self::Ipv6MPLSLabeledVpn),
            (AddressFamily::IPv6, SubsequentAddressFamily::MulticastBgpMplsVpn) => {
                Ok(Self::Ipv6MulticastBgpMplsVpn)
            }
            (AddressFamily::IPv6, SubsequentAddressFamily::Bgp6over4) => Ok(Self::Ipv6Bgp6over4),

            (AddressFamily::L2vpn, SubsequentAddressFamily::BgpEvpn) => Ok(Self::L2VpnBgpEvpn),
            _ => Err(InvalidAddressType::new(afi, safi)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamily, AddressType, InvalidAddressType, SubsequentAddressFamily,
        UndefinedAddressFamily, UndefinedSubsequentAddressFamily,
    };

    #[test]
    fn test_afi_try_from() {
        let undefined_val = 65000;
        let afi_ipv6 = AddressFamily::try_from(2);
        let afi_undefined = AddressFamily::try_from(undefined_val);
        assert_eq!(afi_ipv6, Ok(AddressFamily::IPv6));
        assert_eq!(afi_undefined, Err(UndefinedAddressFamily(undefined_val)));
    }

    #[test]
    fn test_afi_into() {
        let afi_ipv6 = AddressFamily::IPv6;
        let ipv6_u16: u16 = afi_ipv6.into();
        assert_eq!(ipv6_u16, 2);
    }

    #[test]
    fn test_safi_try_from() {
        let undefined_val = 100;
        let safi_multicast = SubsequentAddressFamily::try_from(2);
        let safi_undefined = SubsequentAddressFamily::try_from(undefined_val);
        assert_eq!(safi_multicast, Ok(SubsequentAddressFamily::Multicast));
        assert_eq!(
            safi_undefined,
            Err(UndefinedSubsequentAddressFamily(undefined_val))
        );
    }

    #[test]
    fn test_safi_into() {
        let safi_multicast = SubsequentAddressFamily::Multicast;
        let multicast_u8: u8 = safi_multicast.into();
        assert_eq!(multicast_u8, 2);
    }

    #[test]
    fn test_address_type_check_ret_afi_safi() {
        let ipv4_unicast = AddressType::Ipv4Unicast;
        let ipv4_multicast = AddressType::Ipv4Multicast;
        let ipv4_mpls_vpn = AddressType::IpPv4MplsLabeledVpn;
        let ipv4_multicast_mpls_vpn = AddressType::Ipv4MulticastBgpMplsVpn;
        let ipv4_bgp_4_over_6 = AddressType::Ipv4Bgp4over6;

        let ipv6_unicast = AddressType::Ipv6Unicast;
        let ipv6_multicast = AddressType::Ipv6Multicast;
        let ipv6_mpls_vpn = AddressType::Ipv6MPLSLabeledVpn;
        let ipv6_multicast_mpls_vpn = AddressType::Ipv6MulticastBgpMplsVpn;
        let ipv6_bgp_6_over_4 = AddressType::Ipv6Bgp6over4;

        let l2vpn_bgp = AddressType::L2VpnBgpEvpn;

        assert_eq!(ipv4_unicast.address_family(), AddressFamily::IPv4);
        assert_eq!(ipv4_multicast.address_family(), AddressFamily::IPv4);
        assert_eq!(ipv4_mpls_vpn.address_family(), AddressFamily::IPv4);
        assert_eq!(
            ipv4_multicast_mpls_vpn.address_family(),
            AddressFamily::IPv4
        );
        assert_eq!(ipv4_bgp_4_over_6.address_family(), AddressFamily::IPv4);

        assert_eq!(
            ipv4_unicast.subsequent_address_family(),
            SubsequentAddressFamily::Unicast
        );
        assert_eq!(
            ipv4_multicast.subsequent_address_family(),
            SubsequentAddressFamily::Multicast
        );
        assert_eq!(
            ipv4_mpls_vpn.subsequent_address_family(),
            SubsequentAddressFamily::MplsVpn
        );
        assert_eq!(
            ipv4_multicast_mpls_vpn.subsequent_address_family(),
            SubsequentAddressFamily::MulticastBgpMplsVpn
        );
        assert_eq!(
            ipv4_bgp_4_over_6.subsequent_address_family(),
            SubsequentAddressFamily::Bgp4over6
        );

        assert_eq!(ipv6_unicast.address_family(), AddressFamily::IPv6);
        assert_eq!(ipv6_multicast.address_family(), AddressFamily::IPv6);
        assert_eq!(ipv6_mpls_vpn.address_family(), AddressFamily::IPv6);
        assert_eq!(
            ipv6_multicast_mpls_vpn.address_family(),
            AddressFamily::IPv6
        );
        assert_eq!(ipv6_bgp_6_over_4.address_family(), AddressFamily::IPv6);

        assert_eq!(
            ipv6_unicast.subsequent_address_family(),
            SubsequentAddressFamily::Unicast
        );
        assert_eq!(
            ipv6_multicast.subsequent_address_family(),
            SubsequentAddressFamily::Multicast
        );
        assert_eq!(
            ipv6_mpls_vpn.subsequent_address_family(),
            SubsequentAddressFamily::MplsVpn
        );
        assert_eq!(
            ipv6_multicast_mpls_vpn.subsequent_address_family(),
            SubsequentAddressFamily::MulticastBgpMplsVpn
        );
        assert_eq!(
            ipv6_bgp_6_over_4.subsequent_address_family(),
            SubsequentAddressFamily::Bgp6over4
        );

        assert_eq!(l2vpn_bgp.address_family(), AddressFamily::L2vpn);
        assert_eq!(
            l2vpn_bgp.subsequent_address_family(),
            SubsequentAddressFamily::BgpEvpn
        );
    }
    #[test]
    fn test_address_type_try_from() {
        let invalid = AddressType::from_afi_safi(
            AddressFamily::AppleTalk,
            SubsequentAddressFamily::Bgp6over4,
        );
        let ipv4_unicast = AddressType::Ipv4Unicast;
        let ipv4_multicast = AddressType::Ipv4Multicast;
        let ipv4_mpls_vpn = AddressType::IpPv4MplsLabeledVpn;
        let ipv4_multicast_mpls_vpn = AddressType::Ipv4MulticastBgpMplsVpn;
        let ipv4_bgp_4_over_6 = AddressType::Ipv4Bgp4over6;

        let ipv6_unicast = AddressType::Ipv6Unicast;
        let ipv6_multicast = AddressType::Ipv6Multicast;
        let ipv6_mpls_vpn = AddressType::Ipv6MPLSLabeledVpn;
        let ipv6_multicast_mpls_vpn = AddressType::Ipv6MulticastBgpMplsVpn;
        let ipv6_bgp_6_over_4 = AddressType::Ipv6Bgp6over4;

        let l2vpn_bgp = AddressType::L2VpnBgpEvpn;

        assert_eq!(
            invalid,
            Err(InvalidAddressType::new(
                AddressFamily::AppleTalk,
                SubsequentAddressFamily::Bgp6over4
            ))
        );
        assert_eq!(
            invalid.err().unwrap().address_family(),
            AddressFamily::AppleTalk
        );
        assert_eq!(
            invalid.err().unwrap().subsequent_address_family(),
            SubsequentAddressFamily::Bgp6over4
        );
        assert_eq!(
            Ok(ipv4_unicast),
            AddressType::from_afi_safi(
                ipv4_unicast.address_family(),
                ipv4_unicast.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv4_multicast),
            AddressType::from_afi_safi(
                ipv4_multicast.address_family(),
                ipv4_multicast.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv4_mpls_vpn),
            AddressType::from_afi_safi(
                ipv4_mpls_vpn.address_family(),
                ipv4_mpls_vpn.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv4_multicast_mpls_vpn),
            AddressType::from_afi_safi(
                ipv4_multicast_mpls_vpn.address_family(),
                ipv4_multicast_mpls_vpn.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv4_bgp_4_over_6),
            AddressType::from_afi_safi(
                ipv4_bgp_4_over_6.address_family(),
                ipv4_bgp_4_over_6.subsequent_address_family()
            )
        );

        assert_eq!(
            Ok(ipv6_unicast),
            AddressType::from_afi_safi(
                ipv6_unicast.address_family(),
                ipv6_unicast.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv6_multicast),
            AddressType::from_afi_safi(
                ipv6_multicast.address_family(),
                ipv6_multicast.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv6_mpls_vpn),
            AddressType::from_afi_safi(
                ipv6_mpls_vpn.address_family(),
                ipv6_mpls_vpn.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv6_multicast_mpls_vpn),
            AddressType::from_afi_safi(
                ipv6_multicast_mpls_vpn.address_family(),
                ipv6_multicast_mpls_vpn.subsequent_address_family()
            )
        );
        assert_eq!(
            Ok(ipv6_bgp_6_over_4),
            AddressType::from_afi_safi(
                ipv6_bgp_6_over_4.address_family(),
                ipv6_bgp_6_over_4.subsequent_address_family()
            )
        );

        assert_eq!(
            Ok(l2vpn_bgp),
            AddressType::from_afi_safi(
                l2vpn_bgp.address_family(),
                l2vpn_bgp.subsequent_address_family()
            )
        );
    }
}
