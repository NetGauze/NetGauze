use crate::bgp_ls::BgpLsMtIdError::{IsIsMtIdInvalidValue, OspfMtIdInvalidValue};
use crate::iana;
use crate::iana::BgpLsNodeDescriptorTlvType::{LocalNodeDescriptor, RemoteNodeDescriptor};
use crate::iana::{BgpLsNodeDescriptorTlvType, BgpLsProtocolId};
use crate::nlri::RouteDistinguisher;
use crate::path_attribute::PathAttributeValueProperties;
use ipnet::IpNet;
use netgauze_parse_utils::WritablePdu;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::BitAnd;
use strum_macros::{Display, FromRepr};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsAttribute {
    pub tlvs: Vec<BgpLsAttributeTlv>,
}

impl PathAttributeValueProperties for BgpLsAttribute {
    /// see [RFC7752 Section 3.3]https://www.rfc-editor.org/rfc/rfc7752#section-3.3
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    /// see [RFC7752 Section 3.3]https://www.rfc-editor.org/rfc/rfc7752#section-3.3
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
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
    LocalNodeIpv4RouterId(Ipv4Addr),
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
    LocalNodeIpv6RouterId(Ipv6Addr),
    /// must be global
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv4))]
    RemoteNodeIpv4RouterId(Ipv4Addr),
    /// must be global
    #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ipv6))]
    RemoteNodeIpv6RouterId(Ipv6Addr),
    RemoteNodeAdministrativeGroupColor(u32),
    MaximumLinkBandwidth(f32),
    MaximumReservableLinkBandwidth(f32),
    UnreservedBandwidth([f32; 8]),
    TeDefaultMetric(u32),

    ///        0                   1
    ///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       |Protection Cap |    Reserved   |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       0x01  Extra Traffic
    ///
    ///       0x02  Unprotected
    ///
    ///       0x04  Shared
    ///
    ///       0x08  Dedicated 1:1
    ///
    ///       0x10  Dedicated 1+1
    ///
    ///       0x20  Enhanced
    ///
    ///       0x40  Reserved
    ///
    ///       0x80  Reserved
    LinkProtectionType {
        extra_traffic: bool,
        unprotected: bool,
        shared: bool,
        dedicated1c1: bool,
        dedicated1p1: bool,
        enhanced: bool,
    },
    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |L|R|  Reserved |
    ///      +-+-+-+-+-+-+-+-+
    ///
    ///    +------------+------------------------------------------+-----------+
    ///    |    Bit     | Description                              | Reference |
    ///    +------------+------------------------------------------+-----------+
    ///    |    'L'     | Label Distribution Protocol (LDP)        | [RFC5036] |
    ///    |    'R'     | Extension to RSVP for LSP Tunnels        | [RFC3209] |
    ///    |            | (RSVP-TE)                                |           |
    ///    | 'Reserved' | Reserved for future use                  |           |
    ///    +------------+------------------------------------------+-----------+
    MplsProtocolMask {
        ldp: bool,
        rsvp_te: bool,
    },

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //      IGP Link Metric (variable length)      //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    IgpMetric(Vec<u8>),

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                  Shared Risk Link Group Value                 |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                         ............                        //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                  Shared Risk Link Group Value                 |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    SharedRiskLinkGroup(Vec<SharedRiskLinkGroupValue>),

    ///      0                   1                   2                   3
    ///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     |              Type             |             Length            |
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     //                Opaque link attributes (variable)            //
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    OpaqueLinkAttribute(Vec<u8>),

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                     Link Name (variable)                    //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    LinkName(String),

    /* Prefix Attribute TLV */
    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |D|N|L|P| Resvd.|
    ///      +-+-+-+-+-+-+-+-+
    ///
    ///    The Value field contains bits defined according to the table below:
    ///
    ///            +----------+---------------------------+-----------+
    ///            |   Bit    | Description               | Reference |
    ///            +----------+---------------------------+-----------+
    ///            |   'D'    | IS-IS Up/Down Bit         | [RFC5305] |
    ///            |   'N'    | OSPF "no unicast" Bit     | [RFC5340] |
    ///            |   'L'    | OSPF "local address" Bit  | [RFC5340] |
    ///            |   'P'    | OSPF "propagate NSSA" Bit | [RFC5340] |
    ///            | Reserved | Reserved for future use.  |           |
    ///            +----------+---------------------------+-----------+
    IgpFlags {
        isis_up_down: bool,
        ospf_no_unicast: bool,
        ospf_local_address: bool,
        ospf_propagate_nssa: bool,
    },

    ///      0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                    Route Tags (one or more)                 //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is a multiple of 4.
    IgpRouteTag(Vec<u32>),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                Extended Route Tag (one or more)             //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is a multiple of 8.
    IgpExtendedRouteTag(Vec<u64>),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                            Metric                             |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is 4.
    PrefixMetric(u32),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //                Forwarding Address (variable)                //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///    Length is 4 for an IPv4 forwarding address, and 16 for an IPv6
    ///    forwarding address.
    OspfForwardingAddress(
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))] IpAddr,
    ),

    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |              Type             |             Length            |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      //              Opaque Prefix Attributes  (variable)           //
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    OpaquePrefixAttribute(Vec<u8>),

    /* Node Attribute TLV */
    MultiTopologyIdentifier(MultiTopologyIdData),
    NodeFlagBits {
        overload: bool,
        attached: bool,
        external: bool,
        abr: bool,
        router: bool,
        v6: bool,
    },
    OpaqueNodeAttribute(Vec<u8>),
    NodeNameTlv(String),
    IsIsArea(Vec<u8>),
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
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsNlri(pub BgpLsNlriValue);

impl BgpLsNlri {
    pub fn nlri(&self) -> &BgpLsNlriValue {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsVpnNlri {
    pub rd: RouteDistinguisher,
    pub nlri: BgpLsNlriValue,
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpLsNlriValue {
    Node(BgpLsNlriNode),
    Link(BgpLsNlriLink),
    Ipv4Prefix(BgpLsNlriIpPrefix),
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
pub struct BgpLsNlriIpPrefix {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsNodeDescriptorTlv,
    pub prefix_descriptor_tlvs: Vec<BgpLsPrefixDescriptorTlv>,
}

// TODO does this go into IANA?
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
pub enum MplsProtocolMask {
    LabelDistributionProtocol = 0b10000000,
    ExtensionToRsvpForLspTunnels = 0b01000000,
}

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

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum IgpFlags {
    IsIsUp = 0b10000000,
    OspfNoUnicast = 0b01000000,
    OspfLocalAddress = 0b00100000,
    OspfPropagateNssa = 0b00010000,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NodeFlagsBits {
    Overload = 0b_1000_0000,
    Attached = 0b_0100_0000,
    External = 0b_0010_0000,
    Abr = 0b_0001_0000,
    Router = 0b_0000_1000,
    V6 = 0b_0000_0100,
}

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
         1-8    -> 1
         9-16   -> 2
         17-24 -> 3
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
    MultiTopologyIdentifier(MultiTopologyIdData),
    OspfRouteType(OspfRouteType),
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
pub struct BgpLsNlriNode {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsNodeDescriptorTlv,
}

#[derive(Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
pub enum BgpLsLinkDescriptorTlv {
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
pub enum BgpLsNodeDescriptorSubTlv {
    AutonomousSystem(u32),
    BgpLsIdentifier(u32),
    OspfAreaId(u32),
    IgpRouterId(Vec<u8>),
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
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpLsNlriLink {
    pub protocol_id: BgpLsProtocolId,
    pub identifier: u64,
    pub local_node_descriptors: BgpLsNodeDescriptorTlv,
    pub remote_node_descriptors: BgpLsNodeDescriptorTlv,
    pub link_descriptor_tlvs: Vec<BgpLsLinkDescriptorTlv>,
}

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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IsIsMtId(u16);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct SharedRiskLinkGroupValue(pub u32);

impl SharedRiskLinkGroupValue {
    pub fn value(&self) -> u32 {
        self.0
    }
}
