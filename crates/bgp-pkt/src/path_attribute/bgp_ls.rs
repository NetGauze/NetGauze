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
    iana::{BgpLsAttributeType, BgpLsSidAttributeFlags},
    nlri::{MplsLabel, MultiTopologyIdData, SharedRiskLinkGroupValue},
    path_attribute::PathAttributeValueProperties,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, BitOr},
};
use strum_macros::{Display, FromRepr};

/// The BGP Link-State Attribute. see [RFC7752 Section 3.3](https://www.rfc-editor.org/rfc/rfc7752#section-3.3)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsAttribute {
    pub attributes: Vec<BgpLsAttributeValue>,
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
pub enum BgpLsAttributeValue {
    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    LocalNodeIpv4RouterId(
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4))] Ipv4Addr,
    ),

    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    LocalNodeIpv6RouterId(
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6))] Ipv6Addr,
    ),

    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    RemoteNodeIpv4RouterId(
        /// must be global
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv4))]
        Ipv4Addr,
    ),

    /// see [RFC7752 Section 3.3.1.4](https://www.rfc-editor.org/rfc/rfc7752#section-3.3.1.4)
    RemoteNodeIpv6RouterId(
        /// must be global
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6))]
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

    /// Unrecognized types MUST be preserved and propagated. [RFC7752 Section 3.1](https://datatracker.ietf.org/doc/html/rfc7752#section-3.1)
    Unknown { code: u16, value: Vec<u8> },
}

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
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LinkProtectionType {
    ExtraTraffic = 0x01,
    Unprotected = 0x02,
    Shared = 0x04,
    Dedicated1c1 = 0x08,
    Dedicated1p1 = 0x10,
    Enhanced = 0x20,
}

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

#[derive(Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

impl BgpLsAttributeValue {
    pub const NODE_NAME_TLV_MAX_LEN: u8 = 255;

    pub const fn code(&self) -> Result<BgpLsAttributeType, u16> {
        match self {
            BgpLsAttributeValue::LocalNodeIpv4RouterId(_) => {
                Ok(BgpLsAttributeType::LocalNodeIpv4RouterId)
            }
            BgpLsAttributeValue::LocalNodeIpv6RouterId(_) => {
                Ok(BgpLsAttributeType::LocalNodeIpv6RouterId)
            }
            BgpLsAttributeValue::RemoteNodeIpv4RouterId(_) => {
                Ok(BgpLsAttributeType::RemoteNodeIpv4RouterId)
            }
            BgpLsAttributeValue::RemoteNodeIpv6RouterId(_) => {
                Ok(BgpLsAttributeType::RemoteNodeIpv6RouterId)
            }
            BgpLsAttributeValue::RemoteNodeAdministrativeGroupColor(_) => {
                Ok(BgpLsAttributeType::RemoteNodeAdministrativeGroupColor)
            }
            BgpLsAttributeValue::MaximumLinkBandwidth(_) => {
                Ok(BgpLsAttributeType::MaximumLinkBandwidth)
            }
            BgpLsAttributeValue::MaximumReservableLinkBandwidth(_) => {
                Ok(BgpLsAttributeType::MaximumReservableLinkBandwidth)
            }
            BgpLsAttributeValue::UnreservedBandwidth(_) => {
                Ok(BgpLsAttributeType::UnreservedBandwidth)
            }
            BgpLsAttributeValue::TeDefaultMetric(_) => Ok(BgpLsAttributeType::TeDefaultMetric),
            BgpLsAttributeValue::LinkProtectionType { .. } => {
                Ok(BgpLsAttributeType::LinkProtectionType)
            }
            BgpLsAttributeValue::MplsProtocolMask { .. } => {
                Ok(BgpLsAttributeType::MplsProtocolMask)
            }
            BgpLsAttributeValue::IgpMetric(..) => Ok(BgpLsAttributeType::IgpMetric),
            BgpLsAttributeValue::SharedRiskLinkGroup(..) => {
                Ok(BgpLsAttributeType::SharedRiskLinkGroup)
            }
            BgpLsAttributeValue::OpaqueLinkAttribute(..) => {
                Ok(BgpLsAttributeType::OpaqueLinkAttribute)
            }
            BgpLsAttributeValue::LinkName(..) => Ok(BgpLsAttributeType::LinkName),
            BgpLsAttributeValue::IgpFlags { .. } => Ok(BgpLsAttributeType::IgpFlags),
            BgpLsAttributeValue::IgpRouteTag(_) => Ok(BgpLsAttributeType::IgpRouteTag),
            BgpLsAttributeValue::IgpExtendedRouteTag(_) => {
                Ok(BgpLsAttributeType::IgpExtendedRouteTag)
            }
            BgpLsAttributeValue::PrefixMetric(_) => Ok(BgpLsAttributeType::PrefixMetric),
            BgpLsAttributeValue::OspfForwardingAddress(_) => {
                Ok(BgpLsAttributeType::OspfForwardingAddress)
            }
            BgpLsAttributeValue::OpaquePrefixAttribute(_) => {
                Ok(BgpLsAttributeType::OpaquePrefixAttribute)
            }
            BgpLsAttributeValue::MultiTopologyIdentifier(..) => {
                Ok(BgpLsAttributeType::MultiTopologyIdentifier)
            }
            BgpLsAttributeValue::NodeFlagBits { .. } => Ok(BgpLsAttributeType::NodeFlagBits),
            BgpLsAttributeValue::OpaqueNodeAttribute(..) => {
                Ok(BgpLsAttributeType::OpaqueNodeAttribute)
            }
            BgpLsAttributeValue::NodeNameTlv(..) => Ok(BgpLsAttributeType::NodeNameTlv),
            BgpLsAttributeValue::IsIsArea(..) => Ok(BgpLsAttributeType::IsIsArea),
            BgpLsAttributeValue::PeerNodeSid(..) => Ok(BgpLsAttributeType::PeerNodeSid),
            BgpLsAttributeValue::PeerAdjSid(..) => Ok(BgpLsAttributeType::PeerAdjSid),
            BgpLsAttributeValue::PeerSetSid(..) => Ok(BgpLsAttributeType::PeerSetSid),
            BgpLsAttributeValue::Unknown { code, .. } => Err(*code),
        }
    }

    pub const fn raw_code(&self) -> u16 {
        match self.code() {
            Ok(value) => value as u16,
            Err(value) => value,
        }
    }
}
