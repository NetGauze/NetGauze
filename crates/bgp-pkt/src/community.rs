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

//! Representations for normal, extended, and large BGP Communities.

use crate::iana::WellKnownCommunity;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Four octet values to specify a community.
///
/// See [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Community(u32);

impl Community {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
    /// Parse the community numerical value into a [`WellKnownCommunity`].
    /// If the value is not well-known, then will return None.
    pub const fn into_well_known(&self) -> Option<WellKnownCommunity> {
        WellKnownCommunity::from_repr(self.0)
    }

    /// Getting the ASN number part according to [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    pub const fn collection_asn(&self) -> u16 {
        (self.0 >> 16 & 0xffff) as u16
    }

    /// Getting the value part according to [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    pub const fn collection_value(&self) -> u16 {
        (self.0 & 0x0000ffff) as u16
    }
}

/// As defined in [RFC8092](https://www.rfc-editor.org/rfc/rfc8092)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Global Administrator                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Local Data Part 1                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Local Data Part 2                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Global Administrator:  A four-octet namespace identifier.
/// Local Data Part 1:  A four-octet operator-defined value.
/// Local Data Part 2:  A four-octet operator-defined value.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LargeCommunity {
    global_admin: u32,
    local_data1: u32,
    local_data2: u32,
}

impl LargeCommunity {
    pub const fn new(global_admin: u32, local_data1: u32, local_data2: u32) -> Self {
        Self {
            global_admin,
            local_data1,
            local_data2,
        }
    }

    pub const fn global_admin(&self) -> u32 {
        self.global_admin
    }

    pub const fn local_data1(&self) -> u32 {
        self.local_data1
    }

    pub const fn local_data2(&self) -> u32 {
        self.local_data2
    }
}
pub trait ExtendedCommunityProperties {
    fn iana_defined(&self) -> bool;
    fn transitive(&self) -> bool;
}

/// The Extended Communities Attribute is a transitive optional BGP
/// attribute, with the Type Code 16.  The attribute consists of a set of
/// "extended communities".  All routes with the Extended Communities
/// attribute belong to the communities listed in the attribute.
///
/// Each Extended Community is encoded as an 8-octet quantity, as
/// follows:
///    - Type Field  : 1 or 2 octets
///    - Value Field : Remaining octets
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |  Type high    |  Type low(*)  |                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          Value                |
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// See [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunity {
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    TransitiveTwoOctet(TransitiveTwoOctetExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    NonTransitiveTwoOctet(NonTransitiveTwoOctetExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    TransitiveIpv4(TransitiveIpv4ExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    NonTransitiveIpv4(NonTransitiveIpv4ExtendedCommunity),

    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    TransitiveFourOctet(TransitiveFourOctetExtendedCommunity),

    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    NonTransitiveFourOctet(NonTransitiveFourOctetExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    TransitiveOpaque(TransitiveOpaqueExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    NonTransitiveOpaque(NonTransitiveOpaqueExtendedCommunity),

    Experimental(ExperimentalExtendedCommunity),

    Unknown(UnknownExtendedCommunity),
}

impl ExtendedCommunityProperties for ExtendedCommunity {
    fn iana_defined(&self) -> bool {
        match self {
            Self::TransitiveTwoOctet(value) => value.iana_defined(),
            Self::NonTransitiveTwoOctet(value) => value.iana_defined(),
            Self::TransitiveIpv4(value) => value.iana_defined(),
            Self::NonTransitiveIpv4(value) => value.iana_defined(),
            Self::TransitiveFourOctet(value) => value.iana_defined(),
            Self::NonTransitiveFourOctet(value) => value.iana_defined(),
            Self::TransitiveOpaque(value) => value.iana_defined(),
            Self::NonTransitiveOpaque(value) => value.iana_defined(),
            Self::Experimental(value) => value.iana_defined(),
            Self::Unknown(value) => value.iana_defined(),
        }
    }

    fn transitive(&self) -> bool {
        match self {
            Self::TransitiveTwoOctet(value) => value.transitive(),
            Self::NonTransitiveTwoOctet(value) => value.transitive(),
            Self::TransitiveIpv4(value) => value.transitive(),
            Self::NonTransitiveIpv4(value) => value.transitive(),
            Self::TransitiveFourOctet(value) => value.transitive(),
            Self::NonTransitiveFourOctet(value) => value.transitive(),
            Self::TransitiveOpaque(value) => value.transitive(),
            Self::NonTransitiveOpaque(value) => value.transitive(),
            Self::Experimental(value) => value.transitive(),
            Self::Unknown(value) => value.transitive(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TransitiveTwoOctetExtendedCommunity {
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteTarget {
        global_admin: u16,
        local_admin: u32,
    },

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteOrigin {
        global_admin: u16,
        local_admin: u32,
    },

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfDomainIdentifier {
        global_admin: u16,
        local_admin: u32,
    },

    /// [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    BgpDataCollection {
        global_admin: u16,
        local_admin: u32,
    },

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    SourceAs {
        global_admin: u16,
        local_admin: u32,
    },

    /// [RFC6074](https://datatracker.ietf.org/doc/html/rfc6074)
    L2VpnIdentifier {
        global_admin: u16,
        local_admin: u32,
    },

    CiscoVpnDistinguisher {
        global_admin: u16,
        local_admin: u32,
    },

    /// [draft-ietf-bess-service-chaining](https://datatracker.ietf.org/doc/draft-ietf-bess-service-chaining/)
    RouteTargetRecord {
        global_admin: u16,
        local_admin: u32,
    },

    /// [draft-zzhang-idr-rt-derived-community](https://datatracker.ietf.org/doc/draft-zzhang-idr-rt-derived-community/)
    RtDerivedEc {
        global_admin: u16,
        local_admin: u32,
    },

    VirtualNetworkIdentifier {
        global_admin: u16,
        local_admin: u32,
    },

    Unassigned {
        sub_type: u8,
        global_admin: u16,
        local_admin: u32,
    },
}

impl ExtendedCommunityProperties for TransitiveTwoOctetExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        true
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NonTransitiveTwoOctetExtendedCommunity {
    LinkBandwidth {
        global_admin: u16,
        local_admin: u32,
    },
    VirtualNetworkIdentifier {
        global_admin: u16,
        local_admin: u32,
    },
    Unassigned {
        sub_type: u8,
        global_admin: u16,
        local_admin: u32,
    },
}

impl ExtendedCommunityProperties for NonTransitiveTwoOctetExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        false
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TransitiveFourOctetExtendedCommunity {
    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    RouteTarget {
        global_admin: u32,
        local_admin: u16,
    },

    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    RouteOrigin {
        global_admin: u32,
        local_admin: u16,
    },

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfDomainIdentifier {
        global_admin: u32,
        local_admin: u16,
    },

    /// [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    BgpDataCollection {
        global_admin: u32,
        local_admin: u16,
    },

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    SourceAs {
        global_admin: u32,
        local_admin: u16,
    },

    CiscoVpnDistinguisher {
        global_admin: u32,
        local_admin: u16,
    },

    /// [draft-ietf-bess-service-chaining](https://datatracker.ietf.org/doc/draft-ietf-bess-service-chaining/)
    RouteTargetRecord {
        global_admin: u32,
        local_admin: u16,
    },

    /// [draft-zzhang-idr-rt-derived-community](https://datatracker.ietf.org/doc/draft-zzhang-idr-rt-derived-community/)
    RtDerivedEc {
        global_admin: u32,
        local_admin: u16,
    },

    Unassigned {
        sub_type: u8,
        global_admin: u32,
        local_admin: u16,
    },
}

impl ExtendedCommunityProperties for TransitiveFourOctetExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        true
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NonTransitiveFourOctetExtendedCommunity {
    Unassigned {
        sub_type: u8,
        global_admin: u32,
        local_admin: u16,
    },
}

impl ExtendedCommunityProperties for NonTransitiveFourOctetExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        true
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TransitiveIpv4ExtendedCommunity {
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteTarget {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteOrigin {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-bgp-ifit-capabilities](https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ifit-capabilities)
    Ipv4Ifit {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfDomainIdentifier {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfRouteID {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-dong-idr-node-target-ext-comm](https://datatracker.ietf.org/doc/draft-dong-idr-node-target-ext-comm)
    NodeTarget {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC6074](https://datatracker.ietf.org/doc/html/rfc6074)
    L2VpnIdentifier {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    VrfRouteImport {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-flowspec-redirect](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect)
    FlowSpecRedirectToIpv4 {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    CiscoVpnDistinguisher {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC7524](https://datatracker.ietf.org/doc/rfc7524)
    InterAreaP2MpSegmentedNextHop {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-ietf-bess-service-chaining](https://datatracker.ietf.org/doc/draft-ietf-bess-service-chaining/)
    RouteTargetRecord {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    VrfRecursiveNextHop {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-zzhang-idr-rt-derived-community](https://datatracker.ietf.org/doc/draft-zzhang-idr-rt-derived-community/)
    RtDerivedEc {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC9081](https://datatracker.ietf.org/doc/rfc9081)
    MulticastVpnRpAddress {
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    Unassigned {
        sub_type: u8,
        global_admin: Ipv4Addr,
        local_admin: u16,
    },
}

impl ExtendedCommunityProperties for TransitiveIpv4ExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        true
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NonTransitiveIpv4ExtendedCommunity {
    Unassigned {
        sub_type: u8,
        global_admin: Ipv4Addr,
        local_admin: u16,
    },
}

impl ExtendedCommunityProperties for NonTransitiveIpv4ExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        false
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TransitiveOpaqueExtendedCommunity {
    Unassigned { sub_type: u8, value: [u8; 6] },
}

impl ExtendedCommunityProperties for TransitiveOpaqueExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        false
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NonTransitiveOpaqueExtendedCommunity {
    Unassigned { sub_type: u8, value: [u8; 6] },
}

impl ExtendedCommunityProperties for NonTransitiveOpaqueExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        false
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ExperimentalExtendedCommunity {
    code: u8,
    sub_type: u8,
    value: [u8; 6],
}

impl ExperimentalExtendedCommunity {
    pub const fn new(code: u8, sub_type: u8, value: [u8; 6]) -> Self {
        Self {
            code,
            sub_type,
            value,
        }
    }

    pub const fn code(&self) -> u8 {
        self.code
    }

    pub const fn sub_type(&self) -> u8 {
        self.sub_type
    }

    pub const fn value(&self) -> &[u8; 6] {
        &self.value
    }
}

impl ExtendedCommunityProperties for ExperimentalExtendedCommunity {
    fn iana_defined(&self) -> bool {
        self.code & 0x80 != 0
    }

    fn transitive(&self) -> bool {
        self.code & 0x40 == 0
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnknownExtendedCommunity {
    code: u8,
    sub_type: u8,
    value: [u8; 6],
}

impl UnknownExtendedCommunity {
    pub const fn new(code: u8, sub_type: u8, value: [u8; 6]) -> Self {
        Self {
            code,
            sub_type,
            value,
        }
    }

    pub const fn code(&self) -> u8 {
        self.code
    }

    pub const fn sub_type(&self) -> u8 {
        self.sub_type
    }

    pub const fn value(&self) -> &[u8; 6] {
        &self.value
    }
}

impl ExtendedCommunityProperties for UnknownExtendedCommunity {
    fn iana_defined(&self) -> bool {
        self.code & 0x80 != 0
    }

    fn transitive(&self) -> bool {
        self.code & 0x40 == 0
    }
}

/// Similar to [`ExtendedCommunity`] but for IPv6
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | 0x00 or 0x40  |    Sub-Type   |    Global Administrator       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Global Administrator (cont.)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Global Administrator (cont.)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Global Administrator (cont.)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Global Administrator (cont.)  |    Local Administrator        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// See [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ExtendedCommunityIpv6 {
    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    TransitiveIpv6(TransitiveIpv6ExtendedCommunity),

    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    NonTransitiveIpv6(NonTransitiveIpv6ExtendedCommunity),

    Unknown(UnknownExtendedCommunityIpv6),
}

impl ExtendedCommunityProperties for ExtendedCommunityIpv6 {
    fn iana_defined(&self) -> bool {
        match self {
            Self::TransitiveIpv6(value) => value.iana_defined(),
            Self::NonTransitiveIpv6(value) => value.iana_defined(),
            Self::Unknown(value) => value.iana_defined(),
        }
    }

    fn transitive(&self) -> bool {
        match self {
            Self::TransitiveIpv6(value) => value.transitive(),
            Self::NonTransitiveIpv6(value) => value.transitive(),
            Self::Unknown(value) => value.transitive(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TransitiveIpv6ExtendedCommunity {
    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    RouteTarget {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    RouteOrigin {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-bgp-ifit-capabilities](https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ifit-capabilities)
    Ipv6Ifit {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC6515](https://datatracker.ietf.org/doc/html/rfc6515) and
    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    VrfRouteImport {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-flowspec-redirect](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect)
    FlowSpecRedirectToIpv6 {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC8956](https://datatracker.ietf.org/doc/html/rfc8956)
    FlowSpecRtRedirectToIpv6 {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    CiscoVpnDistinguisher {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC7524](https://datatracker.ietf.org/doc/rfc7524)
    InterAreaP2MpSegmentedNextHop {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [draft-zzhang-idr-rt-derived-community](https://datatracker.ietf.org/doc/draft-zzhang-idr-rt-derived-community/)
    RtDerivedEc {
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    Unassigned {
        sub_type: u8,
        global_admin: Ipv6Addr,
        local_admin: u16,
    },
}

impl ExtendedCommunityProperties for TransitiveIpv6ExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        true
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NonTransitiveIpv6ExtendedCommunity {
    Unassigned {
        sub_type: u8,
        global_admin: Ipv6Addr,
        local_admin: u16,
    },
}

impl ExtendedCommunityProperties for NonTransitiveIpv6ExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        false
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnknownExtendedCommunityIpv6 {
    code: u8,
    sub_type: u8,
    value: [u8; 18],
}

impl UnknownExtendedCommunityIpv6 {
    pub const fn new(code: u8, sub_type: u8, value: [u8; 18]) -> Self {
        Self {
            code,
            sub_type,
            value,
        }
    }

    pub const fn code(&self) -> u8 {
        self.code
    }

    pub const fn sub_type(&self) -> u8 {
        self.sub_type
    }

    pub const fn value(&self) -> &[u8; 18] {
        &self.value
    }
}

impl ExtendedCommunityProperties for UnknownExtendedCommunityIpv6 {
    fn iana_defined(&self) -> bool {
        self.code & 0x80 != 0
    }

    fn transitive(&self) -> bool {
        self.code & 0x40 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_into_well_known() {
        let well_known = Community::new(0xFFFFFF04);
        let not_well_known = Community::new(0x00FF0F04);
        assert_eq!(
            well_known.into_well_known(),
            Some(WellKnownCommunity::NoPeer)
        );
        assert_eq!(not_well_known.into_well_known(), None);
    }
    #[test]
    fn test_community_val() {
        let comm = Community::new(0x10012003);
        assert_eq!(comm.collection_asn(), 0x1001);
        assert_eq!(comm.collection_value(), 0x2003);
    }
}
