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

//! Representations for BGP Update message

use crate::nlri::Ipv4UnicastAddress;
use netgauze_iana::address_family::AddressType;
use serde::{Deserialize, Serialize};

use crate::path_attribute::{MpUnreach, PathAttribute, PathAttributeValue};

/// UPDATE messages are used to transfer routing information between BGP peers
/// as defined by [RFC4271](https://datatracker.ietf.org/doc/html/RFC4271).
///
/// ```text
/// +-----------------------------------------------------+
/// |   Withdrawn Routes Length (2 octets)                |
/// +-----------------------------------------------------+
/// |   Withdrawn Routes (variable)                       |
/// +-----------------------------------------------------+
/// |   Total Path Attribute Length (2 octets)            |
/// +-----------------------------------------------------+
/// |   Path Attributes (variable)                        |
/// +-----------------------------------------------------+
/// |   Network Layer Reachability Information (variable) |
/// +-----------------------------------------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BgpUpdateMessage {
    withdrawn_routes: Vec<Ipv4UnicastAddress>,
    path_attributes: Vec<PathAttribute>,
    nlri: Vec<Ipv4UnicastAddress>,
}

impl BgpUpdateMessage {
    #[inline]
    pub fn new(
        withdrawn_routes: Vec<Ipv4UnicastAddress>,
        path_attributes: Vec<PathAttribute>,
        nlri: Vec<Ipv4UnicastAddress>,
    ) -> Self {
        BgpUpdateMessage {
            withdrawn_routes,
            path_attributes,
            nlri,
        }
    }
    pub const fn withdraw_routes(&self) -> &Vec<Ipv4UnicastAddress> {
        &self.withdrawn_routes
    }

    pub const fn path_attributes(&self) -> &Vec<PathAttribute> {
        &self.path_attributes
    }

    #[inline]
    pub const fn nlri(&self) -> &Vec<Ipv4UnicastAddress> {
        &self.nlri
    }

    /// Return address family of End-Of-RIB (EoR) messages or `None` if the
    /// update message is not EoR
    ///
    /// RFC4724: An UPDATE message with no reachable Network Layer Reachability
    /// Information (NLRI) and empty withdrawn NLRI is specified as the End-
    /// of-RIB marker that can be used by a BGP speaker to indicate to its
    /// peer the completion of the initial routing update after the session
    /// is established. For the IPv4 unicast address family, the End-of-RIB
    /// marker is an UPDATE message with the minimum length [RFC4271](https://datatracker.ietf.org/doc/html/RFC4271).
    /// For any other address family, it is an UPDATE message that contains only
    /// the MP_UNREACH_NLRI attribute [RFC4760](https://datatracker.ietf.org/doc/html/RFC4760)
    /// with no withdrawn routes for that <AFI, SAFI>.
    pub fn end_of_rib(&self) -> Option<AddressType> {
        if !self.nlri.is_empty() || !self.withdrawn_routes.is_empty() {
            return None;
        }
        if self.path_attributes.is_empty() {
            return Some(AddressType::Ipv4Unicast);
        }
        let mut current = None;
        let mut mp_unreach_count = 0;
        for attr in &self.path_attributes {
            if let PathAttributeValue::MpReach(_) = attr.value() {
                return None;
            }
            if let PathAttributeValue::MpUnreach(unreach) = attr.value() {
                mp_unreach_count += 1;
                if mp_unreach_count > 1 {
                    // Only one MpUnreach is used to indicate End-of-RIB (EoR), more than one
                    // MpUnreach attribute doesn't define EoR.
                    return None;
                }
                match unreach {
                    MpUnreach::Ipv4Unicast { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv4Unicast);
                        }
                    }
                    MpUnreach::Ipv4Multicast { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv4Multicast);
                        }
                    }
                    MpUnreach::Ipv4NlriMplsLabels { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv4NlriMplsLabels);
                        }
                    }
                    MpUnreach::Ipv4MplsVpnUnicast { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv4MplsLabeledVpn);
                        }
                    }
                    MpUnreach::Ipv6Unicast { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv6Unicast);
                        }
                    }
                    MpUnreach::Ipv6Multicast { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv6Multicast);
                        }
                    }
                    MpUnreach::Ipv6NlriMplsLabels { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv6NlriMplsLabels);
                        }
                    }
                    MpUnreach::Ipv6MplsVpnUnicast { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::Ipv6MplsLabeledVpn);
                        }
                    }
                    MpUnreach::L2Evpn { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::L2VpnBgpEvpn);
                        }
                    }
                    MpUnreach::RouteTargetMembership { nlri } => {
                        if nlri.is_empty() {
                            current = Some(AddressType::RouteTargetConstrains);
                        }
                    }
                    MpUnreach::Unknown { .. } => {
                        // For unknown address families we assume it's not EoR, as they might have
                        // different semantics defined.
                        current = None;
                    }
                }
            }
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        nlri::{
            Ipv4MplsVpnUnicastAddress, Ipv4Unicast, LabeledIpv6NextHop, LabeledNextHop, MplsLabel,
            RouteDistinguisher,
        },
        path_attribute::MpReach,
    };

    #[test]
    fn test_end_of_rib() {
        let ipv4_eor = BgpUpdateMessage::new(vec![], vec![], vec![]);
        let ipv4_unicast_eor = BgpUpdateMessage::new(
            vec![],
            vec![PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::MpUnreach(MpUnreach::Ipv4Unicast { nlri: vec![] }),
            )
            .unwrap()],
            vec![],
        );
        let ipv6_eor = BgpUpdateMessage::new(
            vec![],
            vec![PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::MpUnreach(MpUnreach::Ipv6Unicast { nlri: vec![] }),
            )
            .unwrap()],
            vec![],
        );
        let ipv4_multicast_eor = BgpUpdateMessage::new(
            vec![],
            vec![PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::MpUnreach(MpUnreach::Ipv4Multicast { nlri: vec![] }),
            )
            .unwrap()],
            vec![],
        );
        let ipv6_multicast_eor = BgpUpdateMessage::new(
            vec![],
            vec![PathAttribute::from(
                true,
                false,
                false,
                false,
                PathAttributeValue::MpUnreach(MpUnreach::Ipv6Multicast { nlri: vec![] }),
            )
            .unwrap()],
            vec![],
        );

        let with_nlri = BgpUpdateMessage::new(
            vec![],
            vec![],
            vec![Ipv4UnicastAddress::new_no_path_id(
                Ipv4Unicast::from_net("192.168.0.0/24".parse().unwrap()).unwrap(),
            )],
        );
        let with_withdraw = BgpUpdateMessage::new(
            vec![Ipv4UnicastAddress::new_no_path_id(
                Ipv4Unicast::from_net("192.168.0.0/24".parse().unwrap()).unwrap(),
            )],
            vec![],
            vec![],
        );
        let with_mp_reach = BgpUpdateMessage::new(
            vec![],
            vec![PathAttribute::from(
                true,
                false,
                false,
                true,
                PathAttributeValue::MpReach(MpReach::Ipv4MplsVpnUnicast {
                    next_hop: LabeledNextHop::Ipv6(LabeledIpv6NextHop::new(
                        RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
                        "fc00::1".parse().unwrap(),
                        None,
                    )),
                    nlri: vec![Ipv4MplsVpnUnicastAddress::new_no_path_id(
                        RouteDistinguisher::As2Administrator { asn2: 1, number: 1 },
                        vec![MplsLabel::new([0, 65, 0]), MplsLabel::new([0, 65, 1])],
                        Ipv4Unicast::from_net("192.168.1.0/24".parse().unwrap()).unwrap(),
                    )],
                }),
            )
            .unwrap()],
            vec![],
        );

        let with_more_than_one_mp_unreach = BgpUpdateMessage::new(
            vec![],
            vec![
                PathAttribute::from(
                    true,
                    false,
                    false,
                    false,
                    PathAttributeValue::MpUnreach(MpUnreach::Ipv4Unicast { nlri: vec![] }),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    false,
                    false,
                    false,
                    PathAttributeValue::MpUnreach(MpUnreach::Ipv6Multicast { nlri: vec![] }),
                )
                .unwrap(),
            ],
            vec![],
        );

        assert_eq!(with_nlri.end_of_rib(), None);
        assert_eq!(with_withdraw.end_of_rib(), None);
        assert_eq!(with_mp_reach.end_of_rib(), None);
        assert_eq!(with_more_than_one_mp_unreach.end_of_rib(), None);

        assert_eq!(ipv4_eor.end_of_rib(), Some(AddressType::Ipv4Unicast));
        assert_eq!(
            ipv4_unicast_eor.end_of_rib(),
            Some(AddressType::Ipv4Unicast)
        );
        assert_eq!(ipv6_eor.end_of_rib(), Some(AddressType::Ipv6Unicast));
        assert_eq!(
            ipv4_multicast_eor.end_of_rib(),
            Some(AddressType::Ipv4Multicast)
        );
        assert_eq!(
            ipv6_multicast_eor.end_of_rib(),
            Some(AddressType::Ipv6Multicast)
        );
    }
}
