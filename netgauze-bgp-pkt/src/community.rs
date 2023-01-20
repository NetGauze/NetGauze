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

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

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
    TransitiveTwoOctetExtendedCommunity(TransitiveTwoOctetExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    NonTransitiveTwoOctetExtendedCommunity(NonTransitiveTwoOctetExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    TransitiveIpv4ExtendedCommunity(TransitiveIpv4ExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    NonTransitiveIpv4ExtendedCommunity(NonTransitiveIpv4ExtendedCommunity),

    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    TransitiveFourOctetExtendedCommunity(TransitiveFourOctetExtendedCommunity),

    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    NonTransitiveFourOctetExtendedCommunity(NonTransitiveFourOctetExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    TransitiveOpaqueExtendedCommunity(TransitiveOpaqueExtendedCommunity),

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    NonTransitiveOpaqueExtendedCommunity(NonTransitiveOpaqueExtendedCommunity),

    Experimental(ExperimentalExtendedCommunity),

    Unknown(UnknownExtendedCommunity),
}

impl ExtendedCommunityProperties for ExtendedCommunity {
    fn iana_defined(&self) -> bool {
        match self {
            Self::TransitiveTwoOctetExtendedCommunity(value) => value.iana_defined(),
            Self::NonTransitiveTwoOctetExtendedCommunity(value) => value.iana_defined(),
            Self::TransitiveIpv4ExtendedCommunity(value) => value.iana_defined(),
            Self::NonTransitiveIpv4ExtendedCommunity(value) => value.iana_defined(),
            Self::TransitiveFourOctetExtendedCommunity(value) => value.iana_defined(),
            Self::NonTransitiveFourOctetExtendedCommunity(value) => value.iana_defined(),
            Self::TransitiveOpaqueExtendedCommunity(value) => value.iana_defined(),
            Self::NonTransitiveOpaqueExtendedCommunity(value) => value.iana_defined(),
            Self::Experimental(value) => value.iana_defined(),
            Self::Unknown(value) => value.iana_defined(),
        }
    }

    fn transitive(&self) -> bool {
        match self {
            Self::TransitiveTwoOctetExtendedCommunity(value) => value.transitive(),
            Self::NonTransitiveTwoOctetExtendedCommunity(value) => value.transitive(),
            Self::TransitiveIpv4ExtendedCommunity(value) => value.transitive(),
            Self::NonTransitiveIpv4ExtendedCommunity(value) => value.transitive(),
            Self::TransitiveFourOctetExtendedCommunity(value) => value.transitive(),
            Self::NonTransitiveFourOctetExtendedCommunity(value) => value.transitive(),
            Self::TransitiveOpaqueExtendedCommunity(value) => value.transitive(),
            Self::NonTransitiveOpaqueExtendedCommunity(value) => value.transitive(),
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
