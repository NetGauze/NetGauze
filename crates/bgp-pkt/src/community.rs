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
use crate::nlri::MacAddress;
#[cfg(feature = "fuzz")]
use crate::{arbitrary_ipv4, arbitrary_ipv6};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Four octet values to specify a community.
///
/// See [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
        ((self.0 >> 16) & 0xffff) as u16
    }

    /// Getting the value part according to [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    pub const fn collection_value(&self) -> u16 {
        (self.0 & 0x0000ffff) as u16
    }
}

impl std::fmt::Display for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.into_well_known() {
            Some(w) => write!(f, "{w}"),
            None => {
                // Extract high 16 bits (AS number)
                let as_number = (self.0 >> 16) & 0xFFFF;
                // Extract low 16 bits (community value)
                let value = self.0 & 0xFFFF;
                write!(f, "{as_number}:{value}")
            }
        }
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];

        bytes[0..4].copy_from_slice(&self.global_admin.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.local_data1.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.local_data2.to_be_bytes());

        bytes
    }
}

impl std::fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.global_admin, self.local_data1, self.local_data2
        )
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

    ///EVPN [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Evpn(EvpnExtendedCommunity),

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
            Self::Evpn(value) => value.iana_defined(),
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
            Self::Evpn(value) => value.transitive(),
            Self::Unknown(value) => value.transitive(),
        }
    }
}

impl std::fmt::Display for ExtendedCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransitiveTwoOctet(value) => match value {
                TransitiveTwoOctetExtendedCommunity::RouteTarget {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::RouteOrigin {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ro:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::OspfDomainIdentifier {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ospf-domain:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::BgpDataCollection {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "bgp-data:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::SourceAs {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "source-as:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::L2VpnIdentifier {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "l2vpn:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::CiscoVpnDistinguisher {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "cisco-vpn:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::RouteTargetRecord {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt-record:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::RtDerivedEc {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt-derived:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::VirtualNetworkIdentifier {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "vni:{global_admin}:{local_admin}")
                }
                TransitiveTwoOctetExtendedCommunity::Unassigned {
                    sub_type,
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "unassigned-{sub_type}:{global_admin}:{local_admin}")
                }
            },
            Self::NonTransitiveTwoOctet(value) => match value {
                NonTransitiveTwoOctetExtendedCommunity::LinkBandwidth {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "link-bw:{global_admin}:{local_admin}")
                }
                NonTransitiveTwoOctetExtendedCommunity::VirtualNetworkIdentifier {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "vni:{global_admin}:{local_admin}")
                }
                NonTransitiveTwoOctetExtendedCommunity::Unassigned {
                    sub_type,
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "unassigned-{sub_type}:{global_admin}:{local_admin}")
                }
            },
            Self::TransitiveIpv4(value) => match value {
                TransitiveIpv4ExtendedCommunity::RouteTarget {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::RouteOrigin {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ro:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::OspfDomainIdentifier {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ospf-domain:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::OspfRouteID {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ospf-rid:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::L2VpnIdentifier {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "l2vpn:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::VrfRouteImport {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "vrf-import:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::FlowSpecRedirectToIpv4 {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "flowspec-redirect:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::CiscoVpnDistinguisher {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "cisco-vpn:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::InterAreaP2MpSegmentedNextHop {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "p2mp-nexthop:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::RouteTargetRecord {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt-record:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::VrfRecursiveNextHop {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "vrf-nexthop:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::RtDerivedEc {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt-derived:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::MulticastVpnRpAddress {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "mvpn-rp:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::Unassigned {
                    sub_type,
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "unassigned-{sub_type}:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::NodeTarget {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "node-target:{global_admin}:{local_admin}")
                }
                TransitiveIpv4ExtendedCommunity::Ipv4Ifit {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ifit:{global_admin}:{local_admin}")
                }
            },
            Self::NonTransitiveIpv4(value) => match value {
                NonTransitiveIpv4ExtendedCommunity::Unassigned {
                    sub_type,
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "unassigned-{sub_type}:{global_admin}:{local_admin}")
                }
            },
            Self::TransitiveFourOctet(value) => match value {
                TransitiveFourOctetExtendedCommunity::RouteTarget {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::RouteOrigin {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ro:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::OspfDomainIdentifier {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "ospf-domain:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::BgpDataCollection {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "bgp-data:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::SourceAs {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "source-as:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::CiscoVpnDistinguisher {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "cisco-vpn:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::RouteTargetRecord {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt-record:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::RtDerivedEc {
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "rt-derived:{global_admin}:{local_admin}")
                }
                TransitiveFourOctetExtendedCommunity::Unassigned {
                    sub_type,
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "unassigned-{sub_type}:{global_admin}:{local_admin}")
                }
            },
            Self::NonTransitiveFourOctet(value) => match value {
                NonTransitiveFourOctetExtendedCommunity::Unassigned {
                    sub_type,
                    global_admin,
                    local_admin,
                } => {
                    write!(f, "unassigned-{sub_type}:{global_admin}:{local_admin}")
                }
            },
            Self::TransitiveOpaque(value) => match value {
                TransitiveOpaqueExtendedCommunity::DefaultGateway => write!(f, "default-gateway"),
                TransitiveOpaqueExtendedCommunity::Unassigned { sub_type, value } => {
                    write!(f, "unassigned-{sub_type}:{value:x?}")
                }
            },
            Self::NonTransitiveOpaque(value) => match value {
                NonTransitiveOpaqueExtendedCommunity::Unassigned { sub_type, value } => {
                    write!(f, "unassigned-{sub_type}:{value:x?}")
                }
            },
            Self::Evpn(value) => match value {
                EvpnExtendedCommunity::MacMobility { flags, seq_no } => {
                    write!(f, "mac-mobility:flags={flags:x}:seq={seq_no}")
                }
                EvpnExtendedCommunity::EsiLabel { flags, esi_label } => {
                    write!(f, "esi-label:flags={flags:x}:label={esi_label:x?}")
                }
                EvpnExtendedCommunity::EsImportRouteTarget { route_target } => {
                    write!(f, "es-import:{route_target:?}",)
                }
                EvpnExtendedCommunity::EvpnRoutersMac { mac } => {
                    write!(f, "router-mac:{mac}",)
                }
                EvpnExtendedCommunity::EvpnL2Attribute {
                    control_flags,
                    l2_mtu,
                } => {
                    write!(f, "l2-attr:flags={control_flags:x}:mtu={l2_mtu}")
                }
                EvpnExtendedCommunity::Unassigned { sub_type, value } => {
                    write!(f, "unassigned-{sub_type}:{value:x?}")
                }
            },
            Self::Experimental(value) => {
                write!(
                    f,
                    "experimental:{}:{}:{:x?}",
                    value.code, value.sub_type, value.value
                )
            }
            Self::Unknown(value) => {
                write!(
                    f,
                    "unknown:{}:{}:{:x?}",
                    value.code, value.sub_type, value.value
                )
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveIpv4ExtendedCommunity {
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteTarget {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteOrigin {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-bgp-ifit-capabilities](https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ifit-capabilities)
    Ipv4Ifit {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfDomainIdentifier {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfRouteID {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-dong-idr-node-target-ext-comm](https://datatracker.ietf.org/doc/draft-dong-idr-node-target-ext-comm)
    NodeTarget {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC6074](https://datatracker.ietf.org/doc/html/rfc6074)
    L2VpnIdentifier {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    VrfRouteImport {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-flowspec-redirect](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect)
    FlowSpecRedirectToIpv4 {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    CiscoVpnDistinguisher {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC7524](https://datatracker.ietf.org/doc/rfc7524)
    InterAreaP2MpSegmentedNextHop {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-ietf-bess-service-chaining](https://datatracker.ietf.org/doc/draft-ietf-bess-service-chaining/)
    RouteTargetRecord {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    VrfRecursiveNextHop {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [draft-zzhang-idr-rt-derived-community](https://datatracker.ietf.org/doc/draft-zzhang-idr-rt-derived-community/)
    RtDerivedEc {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    /// [RFC9081](https://datatracker.ietf.org/doc/rfc9081)
    MulticastVpnRpAddress {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
        global_admin: Ipv4Addr,
        local_admin: u16,
    },

    Unassigned {
        sub_type: u8,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum NonTransitiveIpv4ExtendedCommunity {
    Unassigned {
        sub_type: u8,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveOpaqueExtendedCommunity {
    /// The Default Gateway community  It is a transitive community,
    /// which means that the first octet is 0x03.  The value of the second
    /// octet (Sub-Type) is 0x0d (Default Gateway) as assigned by IANA.  The
    /// Value field of this community is reserved (set to 0 by the senders,
    /// ignored by the receivers).
    DefaultGateway,

    Unassigned {
        sub_type: u8,
        value: [u8; 6],
    },
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveIpv6ExtendedCommunity {
    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    RouteTarget {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    RouteOrigin {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-bgp-ifit-capabilities](https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ifit-capabilities)
    Ipv6Ifit {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC6515](https://datatracker.ietf.org/doc/html/rfc6515) and
    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    VrfRouteImport {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [draft-ietf-idr-flowspec-redirect](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect)
    FlowSpecRedirectToIpv6 {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC8956](https://datatracker.ietf.org/doc/html/rfc8956)
    FlowSpecRtRedirectToIpv6 {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    CiscoVpnDistinguisher {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [RFC7524](https://datatracker.ietf.org/doc/rfc7524)
    InterAreaP2MpSegmentedNextHop {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    /// [draft-zzhang-idr-rt-derived-community](https://datatracker.ietf.org/doc/draft-zzhang-idr-rt-derived-community/)
    RtDerivedEc {
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
        global_admin: Ipv6Addr,
        local_admin: u16,
    },

    Unassigned {
        sub_type: u8,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum NonTransitiveIpv6ExtendedCommunity {
    Unassigned {
        sub_type: u8,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum EvpnExtendedCommunity {
    /// MAC Mobility extended community
    /// ```text
    ///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  | Type=0x06     | Sub-Type=0x00 |Flags(1 octet)|  Reserved=0    |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                       Sequence Number                         |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// The low-order bit of the Flags octet is defined as the
    /// "Sticky/static" flag and may be set to 1.  A value of 1 means that
    /// the MAC address is static and cannot move.  The sequence number is
    /// used to ensure that PEs retain the correct MAC/IP Advertisement route
    /// when multiple updates occur for the same MAC address.
    MacMobility {
        flags: u8,
        seq_no: u32,
    },

    /// Each ESI Label extended community
    /// ```text
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  | Type=0x06     | Sub-Type=0x01 | Flags(1 octet)|  Reserved=0   |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |  Reserved=0   |          ESI Label                            |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    EsiLabel {
        flags: u8,
        esi_label: [u8; 3],
    },

    /// ```text
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Type=0x06     | Sub-Type=0x02 |          ES-Import            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                     ES-Import Cont'd                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    EsImportRouteTarget {
        route_target: [u8; 6],
    },

    /// EVPN Router's MAC Extended Community
    /// ```text
    ///   0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Type=0x06     | Sub-Type=0x03 |        EVPN Router's MAC      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                    EVPN Router's MAC Cont'd                   |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    EvpnRoutersMac {
        mac: MacAddress,
    },

    /// EVPN Layer 2 Attributes Extended Community
    /// [RFC8214](https://datatracker.ietf.org/doc/rfc8214)
    ///
    /// ```text
    /// +-------------------------------------------+
    /// |  Type (0x06) / Sub-type (0x04) (2 octets) |
    /// +-------------------------------------------+
    /// |  Control Flags  (2 octets)                |
    /// +-------------------------------------------+
    /// |  L2 MTU (2 octets)                        |
    /// +-------------------------------------------+
    /// |  Reserved (2 octets)                      |
    /// +-------------------------------------------+
    /// ```
    EvpnL2Attribute {
        /// EVPN Layer 2 Attributes Control Flags
        /// ```text
        /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |   MBZ                   |C|P|B|  (MBZ = MUST Be Zero)
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// Name     Meaning
        /// ---------------------------------------------------------------
        /// P        If set to 1 in multihoming Single-Active scenarios,
        ///          this flag indicates that the advertising PE is the
        ///          primary PE.  MUST be set to 1 for multihoming
        ///         All-Active scenarios by all active PE(s).
        ///
        /// B       If set to 1 in multihoming Single-Active scenarios,
        ///         this flag indicates that the advertising PE is the
        ///         backup PE.
        ///
        /// C       If set to 1, a control word [RFC4448](https://datatracker.ietf.org/doc/rfc4448)
        ///         MUST be present when sending EVPN packets to this PE.
        ///         It is recommended that the control word be included in the
        ///         absence of an entropy label
        ///         [RFC6790](https://datatracker.ietf.org/doc/rfc6790).
        control_flags: u16,

        /// L2 MTU is a 2-octet value indicating the MTU in bytes.
        l2_mtu: u16,
    },

    Unassigned {
        sub_type: u8,
        value: [u8; 6],
    },
}

impl ExtendedCommunityProperties for EvpnExtendedCommunity {
    fn iana_defined(&self) -> bool {
        true
    }

    fn transitive(&self) -> bool {
        true
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

    #[test]
    pub fn test_large_community_to_bytes() {
        let input = LargeCommunity::new(123456789, 987654321, 159734628);
        let expected_output = [
            0x07, 0x5b, 0xcd, 0x15, 0x3a, 0xde, 0x68, 0xb1, 0x9, 0x85, 0x5b, 0x64,
        ];
        let to_bytes_output = input.to_bytes();
        assert_eq!(to_bytes_output, expected_output);
    }
}
