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

use crate::iana::{
    BgpLsLinkDescriptorType, BgpLsNlriType, BgpLsNodeDescriptorSubType, BgpLsPrefixDescriptorType,
    BgpLsProtocolId,
};
use crate::nlri::RouteDistinguisher;
use ipnet::IpNet;
use netgauze_parse_utils::WritablePdu;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::BitAnd;
use strum_macros::{Display, FromRepr};

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsNlri {
    pub path_id: Option<u32>,
    pub value: BgpLsNlriValue,
}

impl BgpLsNlri {
    pub fn nlri(&self) -> &BgpLsNlriValue {
        &self.value
    }
    pub fn path_id(&self) -> Option<u32> {
        self.path_id
    }
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsVpnNlri {
    pub path_id: Option<u32>,
    pub rd: RouteDistinguisher,
    pub value: BgpLsNlriValue,
}

impl BgpLsVpnNlri {
    pub fn nlri(&self) -> &BgpLsNlriValue {
        &self.value
    }
    pub const fn rd(&self) -> RouteDistinguisher {
        self.rd
    }
    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }
}

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
#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

    Unknown {
        code: u16,
        value: Vec<u8>,
    },
}

impl BgpLsNlriValue {
    pub fn code(&self) -> Result<BgpLsNlriType, u16> {
        match self {
            BgpLsNlriValue::Node(_) => Ok(BgpLsNlriType::Node),
            BgpLsNlriValue::Link(_) => Ok(BgpLsNlriType::Link),
            BgpLsNlriValue::Ipv4Prefix(_) => Ok(BgpLsNlriType::Ipv4TopologyPrefix),
            BgpLsNlriValue::Ipv6Prefix(_) => Ok(BgpLsNlriType::Ipv6TopologyPrefix),
            BgpLsNlriValue::Unknown { code, .. } => Err(*code),
        }
    }

    pub fn raw_code(&self) -> u16 {
        match self.code() {
            Ok(type_) => type_ as u16,
            Err(code) => code,
        }
    }
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsNlriIpPrefix {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsLocalNodeDescriptors,
    pub prefix_descriptors: Vec<BgpLsPrefixDescriptor>,
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

/// ```text
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
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MplsProtocolMask {
    LabelDistributionProtocol = 0b_1000_0000,
    ExtensionToRsvpForLspTunnels = 0b_0100_0000,
}

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
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum IgpFlags {
    IsIsUp = 0b_1000_0000,
    OspfNoUnicast = 0b_0100_0000,
    OspfLocalAddress = 0b_0010_0000,
    OspfPropagateNssa = 0b_0001_0000,
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
pub enum BgpLsPrefixDescriptor {
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
    Unknown {
        code: u16,
        value: Vec<u8>,
    },
}

impl BgpLsPrefixDescriptor {
    pub const fn code(&self) -> Result<BgpLsPrefixDescriptorType, u16> {
        match self {
            BgpLsPrefixDescriptor::MultiTopologyIdentifier(..) => {
                Ok(BgpLsPrefixDescriptorType::MultiTopologyIdentifier)
            }
            BgpLsPrefixDescriptor::OspfRouteType(_) => Ok(BgpLsPrefixDescriptorType::OspfRouteType),
            BgpLsPrefixDescriptor::IpReachabilityInformation(_) => {
                Ok(BgpLsPrefixDescriptorType::IpReachabilityInformation)
            }
            BgpLsPrefixDescriptor::Unknown { code, .. } => Err(*code),
        }
    }

    pub const fn raw_code(&self) -> u16 {
        match self.code() {
            Ok(value) => value as u16,
            Err(value) => value,
        }
    }
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsNlriNode {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsLocalNodeDescriptors,
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsNodeDescriptors(pub Vec<BgpLsNodeDescriptorSubTlv>);

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsLocalNodeDescriptors(pub BgpLsNodeDescriptors);
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsRemoteNodeDescriptors(pub BgpLsNodeDescriptors);

impl BgpLsNodeDescriptors {
    pub fn subtlvs(&self) -> &[BgpLsNodeDescriptorSubTlv] {
        &self.0
    }

    pub fn subtlvs_len(&self) -> usize {
        self.subtlvs().iter().map(|tlv| tlv.len()).sum()
    }
}

/// see [RFC7752 Section 3.2.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.2)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpLsLinkDescriptor {
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
    Unknown {
        code: u16,
        value: Vec<u8>,
    },
}

impl BgpLsLinkDescriptor {
    pub const fn code(&self) -> Result<BgpLsLinkDescriptorType, u16> {
        match self {
            BgpLsLinkDescriptor::LinkLocalRemoteIdentifiers { .. } => {
                Ok(BgpLsLinkDescriptorType::LinkLocalRemoteIdentifiers)
            }
            BgpLsLinkDescriptor::IPv4InterfaceAddress(..) => {
                Ok(BgpLsLinkDescriptorType::IPv4InterfaceAddress)
            }
            BgpLsLinkDescriptor::IPv4NeighborAddress(..) => {
                Ok(BgpLsLinkDescriptorType::IPv4NeighborAddress)
            }
            BgpLsLinkDescriptor::IPv6InterfaceAddress(..) => {
                Ok(BgpLsLinkDescriptorType::IPv6InterfaceAddress)
            }
            BgpLsLinkDescriptor::IPv6NeighborAddress(..) => {
                Ok(BgpLsLinkDescriptorType::IPv6NeighborAddress)
            }
            BgpLsLinkDescriptor::MultiTopologyIdentifier(..) => {
                Ok(BgpLsLinkDescriptorType::MultiTopologyIdentifier)
            }
            BgpLsLinkDescriptor::Unknown { code, .. } => Err(*code),
        }
    }

    pub const fn raw_code(&self) -> u16 {
        match self.code() {
            Ok(value) => value as u16,
            Err(value) => value,
        }
    }
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpLsNodeDescriptorSubTlv {
    AutonomousSystem(u32),
    BgpLsIdentifier(u32),
    OspfAreaId(u32),
    IgpRouterId(Vec<u8>),
    BgpRouterIdentifier(u32),
    MemberAsNumber(u32),
    Unknown { code: u16, value: Vec<u8> },
}

impl BgpLsNodeDescriptorSubTlv {
    pub const fn code(&self) -> Result<BgpLsNodeDescriptorSubType, u16> {
        match self {
            BgpLsNodeDescriptorSubTlv::AutonomousSystem(_) => {
                Ok(BgpLsNodeDescriptorSubType::AutonomousSystem)
            }
            BgpLsNodeDescriptorSubTlv::BgpLsIdentifier(_) => {
                Ok(BgpLsNodeDescriptorSubType::BgpLsIdentifier)
            }
            BgpLsNodeDescriptorSubTlv::OspfAreaId(_) => Ok(BgpLsNodeDescriptorSubType::OspfAreaId),
            BgpLsNodeDescriptorSubTlv::IgpRouterId(_) => {
                Ok(BgpLsNodeDescriptorSubType::IgpRouterId)
            }
            BgpLsNodeDescriptorSubTlv::BgpRouterIdentifier(_) => {
                Ok(BgpLsNodeDescriptorSubType::BgpRouterIdentifier)
            }
            BgpLsNodeDescriptorSubTlv::MemberAsNumber(_) => {
                Ok(BgpLsNodeDescriptorSubType::MemberAsNumber)
            }
            BgpLsNodeDescriptorSubTlv::Unknown { code, .. } => Err(*code),
        }
    }

    pub const fn raw_code(&self) -> u16 {
        match self.code() {
            Ok(value) => value as u16,
            Err(value) => value,
        }
    }
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsNlriLink {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsLocalNodeDescriptors,
    pub remote_node_descriptors: BgpLsRemoteNodeDescriptors,
    pub link_descriptors: Vec<BgpLsLinkDescriptor>,
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MultiTopologyId(pub u16);

impl MultiTopologyId {
    pub fn value(&self) -> u16 {
        self.0
    }
}

#[derive(Debug, Display, Eq, PartialEq, Serialize, Deserialize)]
pub enum BgpLsMtIdError {
    OspfMtIdInvalidValue(MultiTopologyId),
    IsIsMtIdInvalidValue(MultiTopologyId),
}

impl MultiTopologyId {
    const OSPF_MTID_MAX: u8 = 127;
    pub fn new_ospf(mtid: u8) -> Result<Self, BgpLsMtIdError> {
        if mtid > Self::OSPF_MTID_MAX {
            Err(BgpLsMtIdError::OspfMtIdInvalidValue(Self(mtid as u16)))
        } else {
            Ok(Self(mtid as u16))
        }
    }

    const ISIS_MTID_MAX: u16 = 4095;
    const ISIS_MTID_RESERVED: u16 = 0;

    pub fn new_isis(mtid: u16) -> Result<Self, BgpLsMtIdError> {
        if mtid == Self::ISIS_MTID_RESERVED || mtid > Self::ISIS_MTID_MAX {
            Err(BgpLsMtIdError::IsIsMtIdInvalidValue(Self(mtid)))
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
