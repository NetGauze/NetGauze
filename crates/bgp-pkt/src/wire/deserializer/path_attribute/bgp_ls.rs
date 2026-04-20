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
    BgpLsAttributeType, BgpLsAttributeTypeError, BgpLsNodeFlagsBits, IanaValueError,
};
use crate::nlri::{
    IgpFlags, MplsLabel, MplsProtocolMask, MultiTopologyIdData, SharedRiskLinkGroupValue,
};
use crate::path_attribute::{
    BgpLsAttribute, BgpLsAttributeValue, BgpLsPeerSid, LinkProtectionType,
};
use crate::wire::deserializer::nlri::{MplsLabelParsingError, MultiTopologyIdDataParsingError};
use crate::wire::deserializer::read_tlv_header_t16_l16;
use crate::wire::serializer::nlri::{IPV4_LEN, IPV6_LEN};

use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::BitAnd;

/// BGP Link-State Attribute Parsing Errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpLsAttributeParsingError {
    #[error("BGP-LS attribute parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("BGP-LS attribute unknown TLV type {error} at offset {offset}")]
    UnknownTlvType {
        offset: usize,
        error: BgpLsAttributeTypeError,
    },
    #[error("BGP-LS attribute UTF-8 error {error} at offset {offset}")]
    Utf8Error { offset: usize, error: String },
    #[error("BGP-LS attribute IP invalid address length {length} at offset {offset}")]
    WrongIpAddrLength { offset: usize, length: usize },
    #[error("BGP-LS attribute error: {0}")]
    MplsLabelParsingError(#[from] MplsLabelParsingError),
    #[error("BGP-LS bad SID value {value} at offset {offset}")]
    BadSidValue { offset: usize, value: u8 },
    #[error("BGP-LS attribute error: {0}")]
    MultiTopologyIdDataError(#[from] MultiTopologyIdDataParsingError),
}

impl<'a> ParseFromWithOneInput<'a, bool> for BgpLsAttribute {
    type Error = BgpLsAttributeParsingError;
    fn parse(cur: &mut SliceReader<'a>, extended_length: bool) -> Result<Self, Self::Error> {
        let mut ls_buf = if extended_length {
            let len = cur.read_u16_be()?;
            cur.take_slice(len as usize)?
        } else {
            let len = cur.read_u8()?;
            cur.take_slice(len as usize)?
        };

        let mut attributes = Vec::new();
        while !ls_buf.is_empty() {
            let attribute = BgpLsAttributeValue::parse(&mut ls_buf)?;
            attributes.push(attribute);
        }
        Ok(BgpLsAttribute { attributes })
    }
}

impl<'a> ParseFrom<'a> for BgpLsAttributeValue {
    type Error = BgpLsAttributeParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (tlv_type, tlv_length, mut data) =
            read_tlv_header_t16_l16::<BgpLsAttributeParsingError>(cur)?;

        let tlv_type = match BgpLsAttributeType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpLsAttributeTypeError(IanaValueError::Unknown(value))) => {
                return Ok(BgpLsAttributeValue::Unknown {
                    code: value,
                    value: data.read_bytes(data.remaining())?.to_vec(),
                });
            }
            Err(error) => {
                return Err(BgpLsAttributeParsingError::UnknownTlvType { offset, error });
            }
        };

        let tlv = match tlv_type {
            BgpLsAttributeType::MultiTopologyIdentifier => {
                let mtid = MultiTopologyIdData::parse(&mut data)?;
                BgpLsAttributeValue::MultiTopologyIdentifier(mtid)
            }
            BgpLsAttributeType::NodeFlagBits => {
                let flags = data.read_u8()?;
                BgpLsAttributeValue::NodeFlagBits {
                    overload: flags.bitand(BgpLsNodeFlagsBits::Overload as u8)
                        == BgpLsNodeFlagsBits::Overload as u8,
                    attached: flags.bitand(BgpLsNodeFlagsBits::Attached as u8)
                        == BgpLsNodeFlagsBits::Attached as u8,
                    external: flags.bitand(BgpLsNodeFlagsBits::External as u8)
                        == BgpLsNodeFlagsBits::External as u8,
                    abr: flags.bitand(BgpLsNodeFlagsBits::Abr as u8)
                        == BgpLsNodeFlagsBits::Abr as u8,
                    router: flags.bitand(BgpLsNodeFlagsBits::Router as u8)
                        == BgpLsNodeFlagsBits::Router as u8,
                    v6: flags.bitand(BgpLsNodeFlagsBits::V6 as u8) == BgpLsNodeFlagsBits::V6 as u8,
                }
            }
            BgpLsAttributeType::OpaqueNodeAttribute => BgpLsAttributeValue::OpaqueNodeAttribute(
                data.read_bytes(data.remaining())?.to_vec(),
            ),
            BgpLsAttributeType::NodeNameTlv => {
                let offset = data.offset();
                let str_buf = data.read_bytes(tlv_length as usize)?;
                let str = String::from_utf8(str_buf.to_vec()).map_err(|e| {
                    BgpLsAttributeParsingError::Utf8Error {
                        offset,
                        error: e.to_string(),
                    }
                })?;
                BgpLsAttributeValue::NodeNameTlv(str)
            }
            BgpLsAttributeType::IsIsArea => {
                BgpLsAttributeValue::IsIsArea(data.read_bytes(data.remaining())?.to_vec())
            }
            BgpLsAttributeType::LocalNodeIpv4RouterId => {
                let address = data.read_u32_be()?;
                BgpLsAttributeValue::LocalNodeIpv4RouterId(Ipv4Addr::from(address))
            }
            BgpLsAttributeType::LocalNodeIpv6RouterId => {
                let address = data.read_u128_be()?;
                BgpLsAttributeValue::LocalNodeIpv6RouterId(Ipv6Addr::from(address))
            }
            BgpLsAttributeType::RemoteNodeIpv4RouterId => {
                let address = data.read_u32_be()?;
                BgpLsAttributeValue::RemoteNodeIpv4RouterId(Ipv4Addr::from(address))
            }
            BgpLsAttributeType::RemoteNodeIpv6RouterId => {
                let address = data.read_u128_be()?;
                BgpLsAttributeValue::RemoteNodeIpv6RouterId(Ipv6Addr::from(address))
            }
            BgpLsAttributeType::RemoteNodeAdministrativeGroupColor => {
                let color = data.read_u32_be()?;
                BgpLsAttributeValue::RemoteNodeAdministrativeGroupColor(color)
            }
            BgpLsAttributeType::MaximumLinkBandwidth => {
                let bandwidth = data.read_f32_be()?;
                BgpLsAttributeValue::MaximumLinkBandwidth(bandwidth)
            }
            BgpLsAttributeType::MaximumReservableLinkBandwidth => {
                let bandwidth = data.read_f32_be()?;
                BgpLsAttributeValue::MaximumReservableLinkBandwidth(bandwidth)
            }
            BgpLsAttributeType::UnreservedBandwidth => {
                let mut value: [f32; 8] = [0.0; 8];
                for v in &mut value {
                    *v = data.read_f32_be()?;
                }
                BgpLsAttributeValue::UnreservedBandwidth(value)
            }
            BgpLsAttributeType::TeDefaultMetric => {
                let metric = data.read_u32_be()?;
                BgpLsAttributeValue::TeDefaultMetric(metric)
            }
            BgpLsAttributeType::LinkProtectionType => {
                let flags = data.read_u16_be()?;
                BgpLsAttributeValue::LinkProtectionType {
                    extra_traffic: flags.bitand(LinkProtectionType::ExtraTraffic as u16)
                        == LinkProtectionType::ExtraTraffic as u16,
                    unprotected: flags.bitand(LinkProtectionType::Unprotected as u16)
                        == LinkProtectionType::Unprotected as u16,
                    shared: flags.bitand(LinkProtectionType::Shared as u16)
                        == LinkProtectionType::Shared as u16,
                    dedicated1c1: flags.bitand(LinkProtectionType::Dedicated1c1 as u16)
                        == LinkProtectionType::Dedicated1c1 as u16,
                    dedicated1p1: flags.bitand(LinkProtectionType::Dedicated1p1 as u16)
                        == LinkProtectionType::Dedicated1p1 as u16,
                    enhanced: flags.bitand(LinkProtectionType::Enhanced as u16)
                        == LinkProtectionType::Enhanced as u16,
                }
            }
            BgpLsAttributeType::MplsProtocolMask => {
                let flags = data.read_u8()?;
                BgpLsAttributeValue::MplsProtocolMask {
                    ldp: flags.bitand(MplsProtocolMask::LabelDistributionProtocol as u8)
                        == MplsProtocolMask::LabelDistributionProtocol as u8,
                    rsvp_te: flags.bitand(MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8)
                        == MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8,
                }
            }
            BgpLsAttributeType::IgpMetric => {
                BgpLsAttributeValue::IgpMetric(data.read_bytes(data.remaining())?.to_vec())
            }
            BgpLsAttributeType::SharedRiskLinkGroup => {
                let mut values = Vec::new();
                while !data.is_empty() {
                    let v = SharedRiskLinkGroupValue::parse(&mut data)?;
                    values.push(v);
                }
                BgpLsAttributeValue::SharedRiskLinkGroup(values)
            }
            BgpLsAttributeType::OpaqueLinkAttribute => BgpLsAttributeValue::OpaqueLinkAttribute(
                data.read_bytes(data.remaining())?.to_vec(),
            ),
            BgpLsAttributeType::LinkName => {
                let offset = data.offset();
                let str_buf = data.read_bytes(tlv_length as usize)?;
                let str = String::from_utf8(str_buf.to_vec()).map_err(|e| {
                    BgpLsAttributeParsingError::Utf8Error {
                        offset,
                        error: e.to_string(),
                    }
                })?;
                BgpLsAttributeValue::LinkName(str)
            }
            BgpLsAttributeType::IgpFlags => {
                let flags = data.read_u8()?;
                BgpLsAttributeValue::IgpFlags {
                    isis_up_down: flags.bitand(IgpFlags::IsIsUp as u8) == IgpFlags::IsIsUp as u8,
                    ospf_no_unicast: flags.bitand(IgpFlags::OspfNoUnicast as u8)
                        == IgpFlags::OspfNoUnicast as u8,
                    ospf_local_address: flags.bitand(IgpFlags::OspfLocalAddress as u8)
                        == IgpFlags::OspfLocalAddress as u8,
                    ospf_propagate_nssa: flags.bitand(IgpFlags::OspfPropagateNssa as u8)
                        == IgpFlags::OspfPropagateNssa as u8,
                }
            }
            BgpLsAttributeType::IgpRouteTag => {
                let mut vec = Vec::new();
                while !data.is_empty() {
                    let v = cur.read_u32_be()?;
                    vec.push(v);
                }
                BgpLsAttributeValue::IgpRouteTag(vec)
            }
            BgpLsAttributeType::IgpExtendedRouteTag => {
                let mut vec = Vec::new();
                while !data.is_empty() {
                    let v = cur.read_u64_be()?;
                    vec.push(v);
                }
                BgpLsAttributeValue::IgpExtendedRouteTag(vec)
            }
            BgpLsAttributeType::PrefixMetric => {
                let metric = data.read_u32_be()?;
                BgpLsAttributeValue::PrefixMetric(metric)
            }
            BgpLsAttributeType::OspfForwardingAddress => {
                let address = if tlv_length == IPV4_LEN as u16 {
                    let ip = data.read_u32_be()?;
                    IpAddr::V4(Ipv4Addr::from(ip))
                } else if tlv_length == IPV6_LEN as u16 {
                    let ip = data.read_u128_be()?;
                    IpAddr::V6(Ipv6Addr::from(ip))
                } else {
                    return Err(BgpLsAttributeParsingError::WrongIpAddrLength {
                        offset,
                        length: tlv_length as usize,
                    });
                };

                BgpLsAttributeValue::OspfForwardingAddress(address)
            }
            BgpLsAttributeType::OpaquePrefixAttribute => {
                BgpLsAttributeValue::OpaquePrefixAttribute(
                    data.read_bytes(data.remaining())?.to_vec(),
                )
            }
            BgpLsAttributeType::PeerNodeSid => {
                let value = BgpLsPeerSid::parse(&mut data, tlv_length)?;
                BgpLsAttributeValue::PeerNodeSid(value)
            }
            BgpLsAttributeType::PeerAdjSid => {
                let value = BgpLsPeerSid::parse(&mut data, tlv_length)?;
                BgpLsAttributeValue::PeerAdjSid(value)
            }
            BgpLsAttributeType::PeerSetSid => {
                let value = BgpLsPeerSid::parse(&mut data, tlv_length)?;
                BgpLsAttributeValue::PeerSetSid(value)
            }
        };
        Ok(tlv)
    }
}

impl<'a> ParseFrom<'a> for SharedRiskLinkGroupValue {
    type Error = BgpLsAttributeParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let value = cur.read_u32_be()?;
        Ok(SharedRiskLinkGroupValue(value))
    }
}

impl<'a> ParseFromWithOneInput<'a, u16> for BgpLsPeerSid {
    type Error = BgpLsAttributeParsingError;
    fn parse(cur: &mut SliceReader<'a>, length: u16) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let flags = cur.read_u8()?;
        let weight = cur.read_u8()?;
        let _reserved = cur.read_u16_be()?;

        if length == 7 && Self::flags_have_v_flag(flags) {
            let label = MplsLabel::parse(cur)?;
            // TODO check if max 20 rightmost bits are set
            Ok(BgpLsPeerSid::LabelValue {
                flags,
                weight,
                label,
            })
        } else if length == 8 && !Self::flags_have_v_flag(flags) {
            let index = cur.read_u32_be()?;
            Ok(BgpLsPeerSid::IndexValue {
                flags,
                weight,
                index,
            })
        } else {
            Err(BgpLsAttributeParsingError::BadSidValue {
                offset,
                value: flags,
            })
        }
    }
}
