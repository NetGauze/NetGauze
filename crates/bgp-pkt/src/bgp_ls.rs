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

use crate::{
    bgp_ls::BgpLsMtIdError::{IsIsMtIdInvalidValue, OspfMtIdInvalidValue},
    iana,
    iana::{
        BgpLsNodeDescriptorTlvType,
        BgpLsNodeDescriptorTlvType::{LocalNodeDescriptor, RemoteNodeDescriptor},
        BgpLsProtocolId, BgpLsSidAttributeFlags,
    },
    nlri::{MplsLabel, RouteDistinguisher},
    path_attribute::PathAttributeValueProperties,
};
use ipnet::IpNet;
use netgauze_parse_utils::WritablePdu;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, BitOr},
};
use strum_macros::{Display, FromRepr};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// The BGP Link-State Attribute. see [RFC7752 Section 3.3](https://www.rfc-editor.org/rfc/rfc7752#section-3.3)
pub struct BgpLsAttribute {
    pub tlvs: Vec<BgpLsAttributeTlv>,
}

impl PathAttributeValueProperties for BgpLsAttribute {
    /// see [RFC7752 Section 3.3](https://www.rfc-editor.org/rfc/rfc7752#section-3.3)
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    /// see [RFC7752 Section 3.3](https://www.rfc-editor.org/rfc/rfc7752#section-3.3)
    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    /// optional non-transitive attributes can't be partial
    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

#[derive(Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpLsAttributeTlv {
    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
    LocalNodeIpv4RouterId(Ipv4Addr),

    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
    LocalNodeIpv6RouterId(Ipv6Addr),

    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
    RemoteNodeIpv4RouterId(
        /// must be global
        Ipv4Addr,
    ),

    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
    RemoteNodeIpv6RouterId(
        /// must be global
        Ipv6Addr,
    ),

    /// see [RFC5305 Section 3.1](https://www.rfc-editor.org/rfc/rfc5305#section-3.1)
    RemoteNodeAdministrativeGroupColor(u32),

    /// see [RFC5305 Section 3.4](https://www.rfc-editor.org/rfc/rfc5305#section-3.4)
    MaximumLinkBandwidth(f32),

    /// see [RFC5305 Section 3.5](https://www.rfc-editor.org/rfc/rfc5305#section-3.5)
    MaximumReservableLinkBandwidth(f32),

    /// see [RFC5305 Section 3.6](https://www.rfc-editor.org/rfc/rfc5305#section-3.6)
    UnreservedBandwidth([f32; 8]),

    /// see [RFC5305 Section 3.7](https://www.rfc-editor.org/rfc/rfc5305#section-3.7)
    TeDefaultMetric(u32),

    /// ```text
    ///  0                   1
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Protection Cap |    Reserved   |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// 0x01  Extra Traffic
    /// 0x02  Unprotected
    /// 0x04  Shared
    /// 0x08  Dedicated 1:1
    /// 0x10  Dedicated 1+1
    /// ```
    /// see [RFC5307 Section 1.2](https://www.rfc-editor.org/rfc/rfc5307#section-1.2)
    LinkProtectionType {
        extra_traffic: bool,
        unprotected: bool,
        shared: bool,
        dedicated1c1: bool,
        dedicated1p1: bool,
        enhanced: bool,
    },
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |L|R|  Reserved |
    /// +-+-+-+-+-+-+-+-+
    ///
    /// +------------+------------------------------------------+-----------+
    /// |    Bit     | Description                              | Reference |
    /// +------------+------------------------------------------+-----------+
    /// |    'L'     | Label Distribution Protocol (LDP)        | [RFC5036] |
    /// |    'R'     | Extension to RSVP for LSP Tunnels        | [RFC3209] |
    /// |            | (RSVP-TE)                                |           |
    /// | 'Reserved' | Reserved for future use                  |           |
    /// +------------+------------------------------------------+-----------+
    /// ```
    /// see [RFC7752 Section 3.3.2.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.2)
    MplsProtocolMask { ldp: bool, rsvp_te: bool },

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //      IGP Link Metric (variable length)      //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.2.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.4)
    IgpMetric(Vec<u8>),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  Shared Risk Link Group Value                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                         ............                        //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  Shared Risk Link Group Value                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.2.5](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.5)
    SharedRiskLinkGroup(Vec<SharedRiskLinkGroupValue>),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                Opaque link attributes (variable)            //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.2.6](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.6)
    OpaqueLinkAttribute(Vec<u8>),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                     Link Name (variable)                    //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.2.7](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.7)
    LinkName(String),

    /* Prefix Attribute TLV */
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |D|N|L|P| Resvd.|
    /// +-+-+-+-+-+-+-+-+
    /// ```
    ///    The Value field contains bits defined according to the table below:
    /// ```text
    /// +----------+---------------------------+-----------+
    /// |   Bit    | Description               | Reference |
    /// +----------+---------------------------+-----------+
    /// |   'D'    | IS-IS Up/Down Bit         | [RFC5305] |
    /// |   'N'    | OSPF "no unicast" Bit     | [RFC5340] |
    /// |   'L'    | OSPF "local address" Bit  | [RFC5340] |
    /// |   'P'    | OSPF "propagate NSSA" Bit | [RFC5340] |
    /// | Reserved | Reserved for future use.  |           |
    /// +----------+---------------------------+-----------+
    /// ```
    /// see [RFC7752 Section 3.3.3.1](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.3.1)
    IgpFlags {
        isis_up_down: bool,
        ospf_no_unicast: bool,
        ospf_local_address: bool,
        ospf_propagate_nssa: bool,
    },

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                    Route Tags (one or more)                 //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// Length is a multiple of 4.
    /// ```
    /// see [RFC7752 Section 3.3.3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.3.2)
    IgpRouteTag(Vec<u32>),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                Extended Route Tag (one or more)             //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// Length is a multiple of 8.
    /// ```
    /// see [RFC7752 Section 3.3.3.3](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.3.3)
    IgpExtendedRouteTag(Vec<u64>),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                            Metric                             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// Length is 4.
    /// ```
    /// see [RFC7752 Section 3.3.3.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.3.4)
    PrefixMetric(u32),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                Forwarding Address (variable)                //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// Length is 4 for an IPv4 forwarding address, and 16 for an IPv6
    /// forwarding address.
    /// ```
    /// see [RFC7752 Section 3.3.3.5](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.3.5)
    OspfForwardingAddress(
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))] IpAddr,
    ),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //              Opaque Prefix Attributes  (variable)           //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.3.6](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.3.6)
    OpaquePrefixAttribute(Vec<u8>),

    /* Node Attribute TLV */
    /// ```text
    /// The format of the MT-ID TLV is shown in the following figure.
    ///
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |          Length=2*n           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |R R R R|  Multi-Topology ID 1  |             ....             //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //             ....             |R R R R|  Multi-Topology ID n  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// where Type is 263, Length is 2*n, and n is the number of MT-IDs
    /// carried in the TLV.
    /// ```
    /// see [RFC7752 Section 3.2.1.5](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.1.5)
    MultiTopologyIdentifier(MultiTopologyIdData),

    ///  ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |O|T|E|B|R|V| Rsvd|
    /// +-+-+-+-+-+-+-+-+-+
    /// ```
    /// The bits are defined as follows:
    /// ```text
    /// +-----------------+-------------------------+------------+
    /// |       Bit       | Description             | Reference  |
    /// +-----------------+-------------------------+------------+
    /// |       'O'       | Overload Bit            | [ISO10589] |
    /// |       'T'       | Attached Bit            | [ISO10589] |
    /// |       'E'       | External Bit            | [RFC2328]  |
    /// |       'B'       | ABR Bit                 | [RFC2328]  |
    /// |       'R'       | Router Bit              | [RFC5340]  |
    /// |       'V'       | V6 Bit                  | [RFC5340]  |
    /// | Reserved (Rsvd) | Reserved for future use |            |
    /// +-----------------+-------------------------+------------+
    /// ```
    /// see [RFC7752 Section 3.2.3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.3.2)
    NodeFlagBits {
        overload: bool,
        attached: bool,
        external: bool,
        abr: bool,
        router: bool,
        v6: bool,
    },

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //               Opaque node attributes (variable)             //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.1.5](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.5)
    OpaqueNodeAttribute(Vec<u8>),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                     Node Name (variable)                    //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.2.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.4)
    NodeNameTlv(String),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                 Area Identifier (variable)                  //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.1.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.2)
    IsIsArea(Vec<u8>),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |               Type            |              Length           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Flags         |     Weight    |             Reserved          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                   SID/Label/Index (variable)                  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// see [RFC9086](https://datatracker.ietf.org/doc/html/rfc9086#section-5)
    PeerNodeSid(BgpLsPeerSid),
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |               Type            |              Length           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Flags         |     Weight    |             Reserved          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                   SID/Label/Index (variable)                  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// see [RFC9086](https://datatracker.ietf.org/doc/html/rfc9086#section-5)
    PeerAdjSid(BgpLsPeerSid),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |               Type            |              Length           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Flags         |     Weight    |             Reserved          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                   SID/Label/Index (variable)                  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// see [RFC9086](https://datatracker.ietf.org/doc/html/rfc9086#section-5)
    PeerSetSid(BgpLsPeerSid),
}

#[derive(Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Type            |              Length           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Flags         |     Weight    |             Reserved          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   SID/Label/Index (variable)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// see [RFC9086](https://datatracker.ietf.org/doc/html/rfc9086#section-5)
pub enum BgpLsPeerSid {
    LabelValue {
        flags: u8,
        weight: u8,
        label: MplsLabel,
    },
    IndexValue {
        flags: u8,
        weight: u8,
        index: u32,
    },
}

impl BgpLsPeerSid {
    pub fn new_label_value(flags: u8, weight: u8, label: MplsLabel) -> Self {
        Self::LabelValue {
            // force the value flag to set
            flags: flags.bitor(BgpLsSidAttributeFlags::ValueFlag as u8),
            weight,
            label,
        }
    }
    pub fn new_index_value(flags: u8, weight: u8, index: u32) -> Self {
        Self::IndexValue {
            // force the value flag to unset
            flags: flags.bitand(!(BgpLsSidAttributeFlags::ValueFlag as u8)),
            weight,
            index,
        }
    }

    pub fn flags(&self) -> u8 {
        match self {
            BgpLsPeerSid::LabelValue { flags, .. } => *flags,
            BgpLsPeerSid::IndexValue { flags, .. } => *flags,
        }
    }
    pub fn weight(&self) -> u8 {
        match self {
            BgpLsPeerSid::LabelValue { weight, .. } => *weight,
            BgpLsPeerSid::IndexValue { weight, .. } => *weight,
        }
    }

    pub fn v_flag(&self) -> bool {
        Self::flags_have_v_flag(self.flags())
    }
    pub fn flags_have_v_flag(flags: u8) -> bool {
        let flag = BgpLsSidAttributeFlags::ValueFlag as u8;
        (flags & flag) == flag
    }
    pub fn l_flag(&self) -> bool {
        Self::flags_have_l_flag(self.flags())
    }
    pub fn flags_have_l_flag(flags: u8) -> bool {
        let flag = BgpLsSidAttributeFlags::LocalFlag as u8;
        (flags & flag) == flag
    }
    pub fn b_flag(&self) -> bool {
        Self::flags_have_b_flag(self.flags())
    }
    pub fn flags_have_b_flag(flags: u8) -> bool {
        let flag = BgpLsSidAttributeFlags::BackupFlag as u8;
        (flags & flag) == flag
    }
    pub fn p_flag(&self) -> bool {
        Self::flags_have_p_flag(self.flags())
    }
    pub fn flags_have_p_flag(flags: u8) -> bool {
        let flag = BgpLsSidAttributeFlags::PersistentFlag as u8;
        (flags & flag) == flag
    }
}

impl BgpLsAttributeTlv {
    pub const NODE_NAME_TLV_MAX_LEN: u8 = 255;

    pub fn get_type(&self) -> iana::BgpLsAttributeTlv {
        match self {
            BgpLsAttributeTlv::LocalNodeIpv4RouterId(_) => {
                iana::BgpLsAttributeTlv::LocalNodeIpv4RouterId
            }
            BgpLsAttributeTlv::LocalNodeIpv6RouterId(_) => {
                iana::BgpLsAttributeTlv::LocalNodeIpv6RouterId
            }
            BgpLsAttributeTlv::RemoteNodeIpv4RouterId(_) => {
                iana::BgpLsAttributeTlv::RemoteNodeIpv4RouterId
            }
            BgpLsAttributeTlv::RemoteNodeIpv6RouterId(_) => {
                iana::BgpLsAttributeTlv::RemoteNodeIpv6RouterId
            }
            BgpLsAttributeTlv::RemoteNodeAdministrativeGroupColor(_) => {
                iana::BgpLsAttributeTlv::RemoteNodeAdministrativeGroupColor
            }
            BgpLsAttributeTlv::MaximumLinkBandwidth(_) => {
                iana::BgpLsAttributeTlv::MaximumLinkBandwidth
            }
            BgpLsAttributeTlv::MaximumReservableLinkBandwidth(_) => {
                iana::BgpLsAttributeTlv::MaximumReservableLinkBandwidth
            }
            BgpLsAttributeTlv::UnreservedBandwidth(_) => {
                iana::BgpLsAttributeTlv::UnreservedBandwidth
            }
            BgpLsAttributeTlv::TeDefaultMetric(_) => iana::BgpLsAttributeTlv::TeDefaultMetric,
            BgpLsAttributeTlv::LinkProtectionType { .. } => {
                iana::BgpLsAttributeTlv::LinkProtectionType
            }
            BgpLsAttributeTlv::MplsProtocolMask { .. } => iana::BgpLsAttributeTlv::MplsProtocolMask,
            BgpLsAttributeTlv::IgpMetric(..) => iana::BgpLsAttributeTlv::IgpMetric,
            BgpLsAttributeTlv::SharedRiskLinkGroup(..) => {
                iana::BgpLsAttributeTlv::SharedRiskLinkGroup
            }
            BgpLsAttributeTlv::OpaqueLinkAttribute(..) => {
                iana::BgpLsAttributeTlv::OpaqueLinkAttribute
            }
            BgpLsAttributeTlv::LinkName(..) => iana::BgpLsAttributeTlv::LinkName,
            BgpLsAttributeTlv::IgpFlags { .. } => iana::BgpLsAttributeTlv::IgpFlags,
            BgpLsAttributeTlv::IgpRouteTag(_) => iana::BgpLsAttributeTlv::IgpRouteTag,
            BgpLsAttributeTlv::IgpExtendedRouteTag(_) => {
                iana::BgpLsAttributeTlv::IgpExtendedRouteTag
            }
            BgpLsAttributeTlv::PrefixMetric(_) => iana::BgpLsAttributeTlv::PrefixMetric,
            BgpLsAttributeTlv::OspfForwardingAddress(_) => {
                iana::BgpLsAttributeTlv::OspfForwardingAddress
            }
            BgpLsAttributeTlv::OpaquePrefixAttribute(_) => {
                iana::BgpLsAttributeTlv::OpaquePrefixAttribute
            }
            BgpLsAttributeTlv::MultiTopologyIdentifier(..) => {
                iana::BgpLsAttributeTlv::MultiTopologyIdentifier
            }
            BgpLsAttributeTlv::NodeFlagBits { .. } => iana::BgpLsAttributeTlv::NodeFlagBits,
            BgpLsAttributeTlv::OpaqueNodeAttribute(..) => {
                iana::BgpLsAttributeTlv::OpaqueNodeAttribute
            }
            BgpLsAttributeTlv::NodeNameTlv(..) => iana::BgpLsAttributeTlv::NodeNameTlv,
            BgpLsAttributeTlv::IsIsArea(..) => iana::BgpLsAttributeTlv::IsIsArea,
            BgpLsAttributeTlv::PeerNodeSid(..) => iana::BgpLsAttributeTlv::PeerNodeSid,
            BgpLsAttributeTlv::PeerAdjSid(..) => iana::BgpLsAttributeTlv::PeerAdjSid,
            BgpLsAttributeTlv::PeerSetSid(..) => iana::BgpLsAttributeTlv::PeerSetSid,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            NLRI Type          |     Total NLRI Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// //                  Link-State NLRI (variable)                 //
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
pub struct BgpLsNlri {
    pub path_id: Option<u32>,
    pub value: BgpLsNlriValue,
}

impl BgpLsNlri {
    pub fn nlri(&self) -> &BgpLsNlriValue {
        &self.value
    }
    pub fn path_id(&self) -> &Option<u32> {
        &self.path_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            NLRI Type          |     Total NLRI Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                       Route Distinguisher                     +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// //                  Link-State NLRI (variable)                 //
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
pub struct BgpLsVpnNlri {
    pub path_id: Option<u32>,
    pub rd: RouteDistinguisher,
    pub value: BgpLsNlriValue,
}

impl BgpLsVpnNlri {
    pub fn nlri(&self) -> &BgpLsNlriValue {
        &self.value
    }
    pub fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }
    pub fn path_id(&self) -> &Option<u32> {
        &self.path_id
    }
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
/// +------+---------------------------+
/// | Type | NLRI Type                 |
/// +------+---------------------------+
/// |  1   | Node NLRI                 |
/// |  2   | Link NLRI                 |
/// |  3   | IPv4 Topology Prefix NLRI |
/// |  4   | IPv6 Topology Prefix NLRI |
/// +------+---------------------------+
/// ```
/// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
pub enum BgpLsNlriValue {
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+
    /// |  Protocol-ID  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Identifier                          |
    /// |                            (64 bits)                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                Local Node Descriptors (variable)            //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
    Node(BgpLsNlriNode),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+
    /// |  Protocol-ID  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Identifier                          |
    /// |                            (64 bits)                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //               Local Node Descriptors (variable)             //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //               Remote Node Descriptors (variable)            //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                  Link Descriptors (variable)                //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
    Link(BgpLsNlriLink),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+
    /// |  Protocol-ID  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Identifier                          |
    /// |                            (64 bits)                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //              Local Node Descriptors (variable)              //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                Prefix Descriptors (variable)                //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
    Ipv4Prefix(BgpLsNlriIpPrefix),

    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+
    /// |  Protocol-ID  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Identifier                          |
    /// |                            (64 bits)                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //              Local Node Descriptors (variable)              //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //                Prefix Descriptors (variable)                //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
    Ipv6Prefix(BgpLsNlriIpPrefix),
}

impl BgpLsNlriValue {
    pub fn get_type(&self) -> iana::BgpLsNlriType {
        match self {
            BgpLsNlriValue::Node(_) => iana::BgpLsNlriType::Node,
            BgpLsNlriValue::Link(_) => iana::BgpLsNlriType::Link,
            BgpLsNlriValue::Ipv4Prefix(_) => iana::BgpLsNlriType::Ipv4TopologyPrefix,
            BgpLsNlriValue::Ipv6Prefix(_) => iana::BgpLsNlriType::Ipv6TopologyPrefix,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |  Protocol-ID  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Identifier                          |
/// |                            (64 bits)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //              Local Node Descriptors (variable)              //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //                Prefix Descriptors (variable)                //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
pub struct BgpLsNlriIpPrefix {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsNodeDescriptorTlv,
    pub prefix_descriptor_tlvs: Vec<BgpLsPrefixDescriptorTlv>,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum OspfRouteType {
    IntraArea = 1,
    InterArea = 2,
    External1 = 3,
    External2 = 4,
    Nssa1 = 5,
    Nssa2 = 6,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnknownOspfRouteType(pub u8);

impl From<OspfRouteType> for u8 {
    fn from(value: OspfRouteType) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for OspfRouteType {
    type Error = UnknownOspfRouteType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UnknownOspfRouteType(value)),
        }
    }
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// ```text
/// +------------+------------------------------------------+-----------+
/// |    Bit     | Description                              | Reference |
/// +------------+------------------------------------------+-----------+
/// |    'L'     | Label Distribution Protocol (LDP)        | [RFC5036](https://rfc-editor.org/rfc/rfc5036) |
/// |    'R'     | Extension to RSVP for LSP Tunnels        | [RFC3209](https://rfc-editor.org/rfc/rfc3209) |
/// |            | (RSVP-TE)                                |           |
/// | 'Reserved' | Reserved for future use                  |           |
/// +------------+------------------------------------------+-----------+
/// ```
/// see [RFC7752 Section 3.3.2.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.2.2)
pub enum MplsProtocolMask {
    LabelDistributionProtocol = 0b_1000_0000,
    ExtensionToRsvpForLspTunnels = 0b_0100_0000,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// ```text
///  0                   1
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Protection Cap |    Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// Protection Cap:
/// 0x01  Extra Traffic
/// 0x02  Unprotected
/// 0x04  Shared
/// 0x08  Dedicated 1:1
/// 0x10  Dedicated 1+1
/// ```
///
/// see [RFC5307 Section 1.2](https://www.rfc-editor.org/rfc/rfc5307#section-1.2)
pub enum LinkProtectionType {
    ExtraTraffic = 0x01,
    Unprotected = 0x02,
    Shared = 0x04,
    Dedicated1c1 = 0x08,
    Dedicated1p1 = 0x10,
    Enhanced = 0x20,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// ```text
/// +----------+---------------------------+-----------+
/// |   Bit    | Description               | Reference |
/// +----------+---------------------------+-----------+
/// |   'D'    | IS-IS Up/Down Bit         | [RFC5305] |
/// |   'N'    | OSPF "no unicast" Bit     | [RFC5340] |
/// |   'L'    | OSPF "local address" Bit  | [RFC5340] |
/// |   'P'    | OSPF "propagate NSSA" Bit | [RFC5340] |
/// | Reserved | Reserved for future use.  |           |
/// +----------+---------------------------+-----------+
/// ```
/// see [RFC7752 Section 3.3.3.1](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.3.1)
pub enum IgpFlags {
    IsIsUp = 0b_1000_0000,
    OspfNoUnicast = 0b_0100_0000,
    OspfLocalAddress = 0b_0010_0000,
    OspfPropagateNssa = 0b_0001_0000,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              Type             |             Length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Prefix Length | IP Prefix (variable)                         //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// see [RFC7752 Section 3.3.2.3](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.3.2)
pub struct IpReachabilityInformationData(
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipnet))] pub IpNet,
);

impl IpReachabilityInformationData {
    /// Count of most significant bytes of the Prefix to send
    /// as described in [RFC7752 Section-3.2.3.2](https://datatracker.ietf.org/doc/html/rfc7752#section-3.2.3.2)
    pub fn most_significant_bytes(prefix_len: u8) -> usize {
        /*
         pfx            pfx
         length (bits)  length (bytes)
         1-8        ->  1
         9-16       ->  2
         17-24      ->  3
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

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpLsPrefixDescriptorTlv {
    /// The format of the MT-ID TLV is shown in the following figure.
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |          Length=2*n           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |R R R R|  Multi-Topology ID 1  |             ....             //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// //             ....             |R R R R|  Multi-Topology ID n  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// where Type is 263, Length is 2*n, and n is the number of MT-IDs
    /// carried in the TLV.
    /// ```
    /// see [RFC7752 Section 3.2.1.5](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.1.5)
    MultiTopologyIdentifier(MultiTopologyIdData),
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Route Type   |
    /// +-+-+-+-+-+-+-+-+
    /// Route Type:
    /// Intra-Area (0x1)
    /// Inter-Area (0x2)
    /// External 1 (0x3)
    /// External 2 (0x4)
    /// NSSA 1 (0x5)
    /// NSSA 2 (0x6)
    /// ```
    OspfRouteType(OspfRouteType),
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |              Type             |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Prefix Length | IP Prefix (variable)                         //
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 3.3.2.3](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.3.2)
    IpReachabilityInformation(IpReachabilityInformationData),
}

impl BgpLsPrefixDescriptorTlv {
    pub fn get_type(&self) -> iana::BgpLsPrefixDescriptorTlvType {
        match self {
            BgpLsPrefixDescriptorTlv::MultiTopologyIdentifier(..) => {
                iana::BgpLsPrefixDescriptorTlvType::MultiTopologyIdentifier
            }
            BgpLsPrefixDescriptorTlv::OspfRouteType(_) => {
                iana::BgpLsPrefixDescriptorTlvType::OspfRouteType
            }
            BgpLsPrefixDescriptorTlv::IpReachabilityInformation(_) => {
                iana::BgpLsPrefixDescriptorTlvType::IpReachabilityInformation
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |  Protocol-ID  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Identifier                          |
/// |                            (64 bits)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //                Local Node Descriptors (variable)            //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
pub struct BgpLsNlriNode {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsNodeDescriptorTlv,
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              Type             |             Length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// //              Node Descriptor Sub-TLVs (variable)            //
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub enum BgpLsNodeDescriptorTlv {
    Local(Vec<BgpLsNodeDescriptorSubTlv>),
    Remote(Vec<BgpLsNodeDescriptorSubTlv>),
}

impl BgpLsNodeDescriptorTlv {
    pub fn get_type(&self) -> BgpLsNodeDescriptorTlvType {
        match self {
            BgpLsNodeDescriptorTlv::Local(_) => LocalNodeDescriptor,
            BgpLsNodeDescriptorTlv::Remote(_) => RemoteNodeDescriptor,
        }
    }

    pub fn subtlvs(&self) -> &[BgpLsNodeDescriptorSubTlv] {
        match self {
            BgpLsNodeDescriptorTlv::Local(subtlvs) | BgpLsNodeDescriptorTlv::Remote(subtlvs) => {
                subtlvs
            }
        }
    }

    pub fn subtlvs_len(&self) -> usize {
        self.subtlvs().iter().map(|tlv| tlv.len()).sum()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// see [RFC7752 Section 3.2.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.2)
pub enum BgpLsLinkDescriptorTlv {
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  Link Local Identifier                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  Link Remote Identifier                       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// see [RFC7752 Section 1.1](https://www.rfc-editor.org/rfc/rfc5307#section-1.1)
    LinkLocalRemoteIdentifiers {
        link_local_identifier: u32,
        link_remote_identifier: u32,
    },

    IPv4InterfaceAddress(Ipv4Addr),
    IPv4NeighborAddress(Ipv4Addr),

    /// MUST NOT be local-link
    IPv6InterfaceAddress(Ipv6Addr),

    /// MUST NOT be local-link
    IPv6NeighborAddress(Ipv6Addr),
    MultiTopologyIdentifier(MultiTopologyIdData),
}

impl BgpLsLinkDescriptorTlv {
    pub fn get_type(&self) -> iana::BgpLsLinkDescriptorTlvType {
        match self {
            BgpLsLinkDescriptorTlv::LinkLocalRemoteIdentifiers { .. } => {
                iana::BgpLsLinkDescriptorTlvType::LinkLocalRemoteIdentifiers
            }
            BgpLsLinkDescriptorTlv::IPv4InterfaceAddress(..) => {
                iana::BgpLsLinkDescriptorTlvType::IPv4InterfaceAddress
            }
            BgpLsLinkDescriptorTlv::IPv4NeighborAddress(..) => {
                iana::BgpLsLinkDescriptorTlvType::IPv4NeighborAddress
            }
            BgpLsLinkDescriptorTlv::IPv6InterfaceAddress(..) => {
                iana::BgpLsLinkDescriptorTlvType::IPv6InterfaceAddress
            }
            BgpLsLinkDescriptorTlv::IPv6NeighborAddress(..) => {
                iana::BgpLsLinkDescriptorTlvType::IPv6NeighborAddress
            }
            BgpLsLinkDescriptorTlv::MultiTopologyIdentifier(..) => {
                iana::BgpLsLinkDescriptorTlvType::MultiTopologyIdentifier
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
/// +--------------------+-------------------+----------+
/// | Sub-TLV Code Point | Description       |   Length |
/// +--------------------+-------------------+----------+
/// |        512         | Autonomous System |        4 |
/// |        513         | BGP-LS Identifier |        4 |
/// |        514         | OSPF Area-ID      |        4 |
/// |        515         | IGP Router-ID     | Variable |
/// |        516         | BGP Router-ID     |        4 |
/// |        517         | Member-AS Number  |        4 |
/// +--------------------+-------------------+----------+
/// ```
/// see [RFC7752 Section 3.2.1](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.1)
pub enum BgpLsNodeDescriptorSubTlv {
    AutonomousSystem(u32),
    BgpLsIdentifier(u32),
    OspfAreaId(u32),
    IgpRouterId(Vec<u8>),
    BgpRouterIdentifier(u32),
    MemberAsNumber(u32),
}

impl BgpLsNodeDescriptorSubTlv {
    pub fn get_type(&self) -> iana::BgpLsNodeDescriptorSubTlv {
        match self {
            BgpLsNodeDescriptorSubTlv::AutonomousSystem(_) => {
                iana::BgpLsNodeDescriptorSubTlv::AutonomousSystem
            }
            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(_) => {
                iana::BgpLsNodeDescriptorSubTlv::BgpLsIdentifier
            }
            BgpLsNodeDescriptorSubTlv::OspfAreaId(_) => iana::BgpLsNodeDescriptorSubTlv::OspfAreaId,
            BgpLsNodeDescriptorSubTlv::IgpRouterId(_) => {
                iana::BgpLsNodeDescriptorSubTlv::IgpRouterId
            }
            BgpLsNodeDescriptorSubTlv::BgpRouterIdentifier(_) => {
                iana::BgpLsNodeDescriptorSubTlv::BgpRouterIdentifier
            }
            BgpLsNodeDescriptorSubTlv::MemberAsNumber(_) => {
                iana::BgpLsNodeDescriptorSubTlv::MemberAsNumber
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
///  ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |  Protocol-ID  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Identifier                          |
/// |                            (64 bits)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //               Local Node Descriptors (variable)             //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //               Remote Node Descriptors (variable)            //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //                  Link Descriptors (variable)                //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// see [RFC7752 Section 3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2)
pub struct BgpLsNlriLink {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsNodeDescriptorTlv,
    pub remote_node_descriptors: BgpLsNodeDescriptorTlv,
    pub link_descriptor_tlvs: Vec<BgpLsLinkDescriptorTlv>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// ```text
/// The format of the MT-ID TLV is shown in the following figure.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              Type             |          Length=2*n           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R R R R|  Multi-Topology ID 1  |             ....             //
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// //             ....             |R R R R|  Multi-Topology ID n  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// where Type is 263, Length is 2*n, and n is the number of MT-IDs
/// carried in the TLV.
/// ```
/// see [RFC7752 Section 3.2.1.5](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.1.5)
pub struct MultiTopologyIdData(pub Vec<MultiTopologyId>);

impl From<Vec<MultiTopologyId>> for MultiTopologyIdData {
    fn from(value: Vec<MultiTopologyId>) -> Self {
        Self(value)
    }
}

impl MultiTopologyIdData {
    pub fn id_count(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
/// Multi-Topology ID for IS-IS [RFC5120 Section 7.2](https://www.rfc-editor.org/rfc/rfc5120#section-7.2)
/// MT ID is a 12-bit field containing the non-zero MT ID of the
/// topology being announced.  The TLV MUST be ignored if the ID is
/// zero.  This is to ensure the consistent view of the standard
/// unicast topology.
///
/// Multi-Topology ID for OSPF [RFC4915 Section 3.7](https://www.rfc-editor.org/rfc/rfc4915#section-3.7)
///  Since AS-External-LSAs use the high-order bit in the MT-ID field
/// (E-bit) for the external metric-type, only MT-IDs in the 0 to 127
/// range are valid.  The following MT-ID values are reserved:
///
/// ```text
///  0      - Reserved for advertising the metric associated
///           with the default topology (see Section 4.2)
///  1      - Reserved for advertising the metric associated
///           with the default multicast topology
///  2      - Reserved for IPv4 in-band management purposes
/// 3-31    - Reserved for assignments by IANA
/// 32-127  - Reserved for development, experimental and
///           proprietary features [RFC3692]
/// 128-255 - Invalid and SHOULD be ignored
/// ```
pub struct MultiTopologyId(pub u16);

impl MultiTopologyId {
    pub fn value(&self) -> u16 {
        self.0
    }
}

#[derive(Debug, Display)]
pub enum BgpLsMtIdError {
    OspfMtIdInvalidValue(MultiTopologyId),
    IsIsMtIdInvalidValue(MultiTopologyId),
}

impl MultiTopologyId {
    const OSPF_MTID_MAX: u8 = 127;
    pub fn new_ospf(mtid: u8) -> Result<Self, BgpLsMtIdError> {
        if mtid > Self::OSPF_MTID_MAX {
            Err(OspfMtIdInvalidValue(Self(mtid as u16)))
        } else {
            Ok(Self(mtid as u16))
        }
    }

    const ISIS_MTID_MAX: u16 = 4095;
    const ISIS_MTID_RESERVED: u16 = 0;

    pub fn new_isis(mtid: u16) -> Result<Self, BgpLsMtIdError> {
        if mtid == Self::ISIS_MTID_RESERVED || mtid > Self::ISIS_MTID_MAX {
            Err(IsIsMtIdInvalidValue(Self(mtid)))
        } else {
            Ok(Self(mtid))
        }
    }
}

impl From<u16> for MultiTopologyId {
    fn from(value: u16) -> Self {
        // ignore 4 first reserved bits
        Self(value.bitand(!(0b1111u16 << 12)))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct SharedRiskLinkGroupValue(pub u32);

impl SharedRiskLinkGroupValue {
    pub fn value(&self) -> u32 {
        self.0
    }
}
