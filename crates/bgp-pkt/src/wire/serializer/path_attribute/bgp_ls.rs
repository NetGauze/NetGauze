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
    iana::BgpLsNodeFlagsBits,
    nlri::{IgpFlags, MplsProtocolMask},
    path_attribute::{BgpLsAttribute, BgpLsAttributeValue, BgpLsPeerSid, LinkProtectionType},
    wire::serializer::{
        nlri::MplsLabelWritingError, path_attribute::write_length, write_tlv_header,
        IpAddrWritingError, MultiTopologyIdWritingError,
    },
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpLsAttributeWritingError {
    StdIoError(#[from_std_io_error] String),
    IpAddrWritingError(#[from] IpAddrWritingError),
    MultiTopologyIdWritingError(#[from] MultiTopologyIdWritingError),
    BgpLsPeerSidWritingError(#[from] BgpLsPeerSidWritingError),
    NodeNameTlvStringTooLong(usize),
}
impl WritablePduWithOneInput<bool, BgpLsAttributeWritingError> for BgpLsAttribute {
    const BASE_LENGTH: usize = 1; // 1 byte for attribute length

    fn len(&self, extended_length: bool) -> usize {
        let len = Self::BASE_LENGTH;

        len + usize::from(extended_length)
            + self.attributes.iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), BgpLsAttributeWritingError>
    where
        Self: Sized,
    {
        write_length(self, extended_length, writer)?;

        for tlv in &self.attributes {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

impl WritablePdu<BgpLsAttributeWritingError> for BgpLsAttributeValue {
    const BASE_LENGTH: usize = 4; // tlv type u16 + tlv length u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsAttributeValue::LocalNodeIpv4RouterId(_) => 4,
                BgpLsAttributeValue::LocalNodeIpv6RouterId(_) => 16,
                BgpLsAttributeValue::RemoteNodeIpv4RouterId(_) => 4,
                BgpLsAttributeValue::RemoteNodeIpv6RouterId(_) => 16,
                BgpLsAttributeValue::RemoteNodeAdministrativeGroupColor(_) => 4,
                BgpLsAttributeValue::MaximumLinkBandwidth(_) => 4,
                BgpLsAttributeValue::MaximumReservableLinkBandwidth(_) => 4,
                BgpLsAttributeValue::UnreservedBandwidth(_) => 4 * 8,
                BgpLsAttributeValue::TeDefaultMetric(_) => 4,
                BgpLsAttributeValue::LinkProtectionType { .. } => 2,
                BgpLsAttributeValue::MplsProtocolMask { .. } => 1,
                BgpLsAttributeValue::IgpMetric(metric) => metric.len(),
                BgpLsAttributeValue::SharedRiskLinkGroup(groups) => 4 * groups.len(),
                BgpLsAttributeValue::OpaqueLinkAttribute(attr) => attr.len(),
                BgpLsAttributeValue::LinkName(name) => name.len(),
                BgpLsAttributeValue::IgpFlags { .. } => 1,
                BgpLsAttributeValue::IgpRouteTag(tags) => 4 * tags.len(),
                BgpLsAttributeValue::IgpExtendedRouteTag(tags) => 8 * tags.len(),
                BgpLsAttributeValue::PrefixMetric(_) => 4,
                BgpLsAttributeValue::OspfForwardingAddress(addr) => addr.len(),
                BgpLsAttributeValue::OpaquePrefixAttribute(attr) => attr.len(),
                BgpLsAttributeValue::MultiTopologyIdentifier(data) => data.len(),
                BgpLsAttributeValue::NodeFlagBits { .. } => 1,
                BgpLsAttributeValue::OpaqueNodeAttribute(bytes) => bytes.len(),
                BgpLsAttributeValue::NodeNameTlv(ascii) => ascii.len(),
                BgpLsAttributeValue::IsIsArea(area) => area.len(),
                BgpLsAttributeValue::PeerNodeSid(value) => value.len(),
                BgpLsAttributeValue::PeerAdjSid(value) => value.len(),
                BgpLsAttributeValue::PeerSetSid(value) => value.len(),
                BgpLsAttributeValue::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsAttributeWritingError>
    where
        Self: Sized,
    {
        write_tlv_header(writer, self.raw_code(), self.len() as u16)?;

        match self {
            BgpLsAttributeValue::LocalNodeIpv4RouterId(ipv4) => writer.write_all(&ipv4.octets())?,
            BgpLsAttributeValue::LocalNodeIpv6RouterId(ipv6) => writer.write_all(&ipv6.octets())?,
            BgpLsAttributeValue::RemoteNodeIpv4RouterId(ipv4) => {
                writer.write_all(&ipv4.octets())?
            }
            BgpLsAttributeValue::RemoteNodeIpv6RouterId(ipv6) => {
                writer.write_all(&ipv6.octets())?
            }
            BgpLsAttributeValue::RemoteNodeAdministrativeGroupColor(color) => {
                writer.write_u32::<NetworkEndian>(*color)?
            }
            BgpLsAttributeValue::MaximumLinkBandwidth(bandwidth) => {
                writer.write_f32::<NetworkEndian>(*bandwidth)?
            }
            BgpLsAttributeValue::MaximumReservableLinkBandwidth(bandwidth) => {
                writer.write_f32::<NetworkEndian>(*bandwidth)?
            }
            BgpLsAttributeValue::UnreservedBandwidth(bandwidths) => {
                for bandwidth in bandwidths {
                    writer.write_f32::<NetworkEndian>(*bandwidth)?;
                }
            }
            BgpLsAttributeValue::TeDefaultMetric(metric) => {
                writer.write_u32::<NetworkEndian>(*metric)?
            }
            BgpLsAttributeValue::LinkProtectionType {
                extra_traffic,
                unprotected,
                shared,
                dedicated1c1,
                dedicated1p1,
                enhanced,
            } => {
                let mut protection_cap = 0;

                if *extra_traffic {
                    protection_cap |= LinkProtectionType::ExtraTraffic as u8
                }

                if *unprotected {
                    protection_cap |= LinkProtectionType::Unprotected as u8
                }

                if *shared {
                    protection_cap |= LinkProtectionType::Shared as u8
                }

                if *dedicated1c1 {
                    protection_cap |= LinkProtectionType::Dedicated1c1 as u8
                }

                if *dedicated1p1 {
                    protection_cap |= LinkProtectionType::Dedicated1p1 as u8
                }

                if *enhanced {
                    protection_cap |= LinkProtectionType::Enhanced as u8
                }

                writer.write_u8(protection_cap)?
            }
            BgpLsAttributeValue::MplsProtocolMask { ldp, rsvp_te } => {
                let mut flags = 0;

                if *ldp {
                    flags |= MplsProtocolMask::LabelDistributionProtocol as u8
                }

                if *rsvp_te {
                    flags |= MplsProtocolMask::ExtensionToRsvpForLspTunnels as u8
                }

                writer.write_u8(flags)?
            }
            BgpLsAttributeValue::IgpMetric(metric) => writer.write_all(metric)?,
            BgpLsAttributeValue::SharedRiskLinkGroup(groups) => {
                for group in groups {
                    writer.write_u32::<NetworkEndian>(group.value())?;
                }
            }
            BgpLsAttributeValue::OpaqueLinkAttribute(attr) => writer.write_all(attr)?,
            BgpLsAttributeValue::LinkName(ascii) => writer.write_all(ascii.as_bytes())?,
            BgpLsAttributeValue::IgpFlags {
                isis_up_down,
                ospf_no_unicast,
                ospf_local_address,
                ospf_propagate_nssa,
            } => {
                let mut igp_flags = 0;

                if *isis_up_down {
                    igp_flags |= IgpFlags::IsIsUp as u8
                }

                if *ospf_no_unicast {
                    igp_flags |= IgpFlags::OspfNoUnicast as u8
                }

                if *ospf_local_address {
                    igp_flags |= IgpFlags::OspfLocalAddress as u8
                }

                if *ospf_propagate_nssa {
                    igp_flags |= IgpFlags::OspfPropagateNssa as u8
                }

                writer.write_u8(igp_flags)?
            }
            BgpLsAttributeValue::IgpRouteTag(tags) => {
                for tag in tags {
                    writer.write_u32::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsAttributeValue::IgpExtendedRouteTag(tags) => {
                for tag in tags {
                    writer.write_u64::<NetworkEndian>(*tag)?;
                }
            }
            BgpLsAttributeValue::PrefixMetric(metric) => {
                writer.write_u32::<NetworkEndian>(*metric)?
            }
            BgpLsAttributeValue::OspfForwardingAddress(addr) => addr.write(writer)?,
            BgpLsAttributeValue::OpaquePrefixAttribute(attr) => writer.write_all(attr)?,
            BgpLsAttributeValue::MultiTopologyIdentifier(data) => data.write(writer)?,
            // TODO make macro for bitfields because come on look at this
            BgpLsAttributeValue::NodeFlagBits {
                overload,
                attached,
                external,
                abr,
                router,
                v6,
            } => {
                let mut flags: u8 = 0x00u8;
                if *overload {
                    flags |= BgpLsNodeFlagsBits::Overload as u8;
                }

                if *attached {
                    flags |= BgpLsNodeFlagsBits::Attached as u8;
                }

                if *external {
                    flags |= BgpLsNodeFlagsBits::External as u8;
                }

                if *abr {
                    flags |= BgpLsNodeFlagsBits::Abr as u8;
                }

                if *router {
                    flags |= BgpLsNodeFlagsBits::Router as u8;
                }

                if *v6 {
                    flags |= BgpLsNodeFlagsBits::V6 as u8;
                }

                writer.write_u8(flags)?;
            }
            BgpLsAttributeValue::OpaqueNodeAttribute(bytes) => writer.write_all(bytes)?,
            BgpLsAttributeValue::NodeNameTlv(ascii) => {
                let len = ascii.len();
                if len > BgpLsAttributeValue::NODE_NAME_TLV_MAX_LEN as usize {
                    return Err(BgpLsAttributeWritingError::NodeNameTlvStringTooLong(len));
                } else {
                    writer.write_all(ascii.as_bytes())?;
                }
            }
            BgpLsAttributeValue::IsIsArea(area) => writer.write_all(area)?,
            BgpLsAttributeValue::PeerNodeSid(value) => value.write(writer)?,
            BgpLsAttributeValue::PeerAdjSid(value) => value.write(writer)?,
            BgpLsAttributeValue::PeerSetSid(value) => value.write(writer)?,
            BgpLsAttributeValue::Unknown { value, .. } => writer.write_all(value)?,
        }

        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpLsPeerSidWritingError {
    StdIoError(#[from_std_io_error] String),
    MplsLabelWritingError(#[from] MplsLabelWritingError),
}

impl WritablePdu<BgpLsPeerSidWritingError> for BgpLsPeerSid {
    const BASE_LENGTH: usize = 4; // flags u8 + weight u8 + reserved u16

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpLsPeerSid::LabelValue { .. } => 3,
                BgpLsPeerSid::IndexValue { .. } => 4,
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpLsPeerSidWritingError>
    where
        Self: Sized,
    {
        // tlv header is already written in BgpLsAttributeTlv

        writer.write_u8(self.flags())?;
        writer.write_u8(self.weight())?;
        writer.write_u16::<NetworkEndian>(0)?;

        match self {
            BgpLsPeerSid::LabelValue { label, .. } => label.write(writer)?,
            BgpLsPeerSid::IndexValue { index, .. } => writer.write_u32::<NetworkEndian>(*index)?,
        }

        Ok(())
    }
}
