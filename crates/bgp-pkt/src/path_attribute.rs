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

//! Contains the extensible definitions for various [`PathAttribute`] that can
//! be used in [`crate::update::BgpUpdateMessage`].

use crate::{
    community::{Community, ExtendedCommunity, ExtendedCommunityIpv6, LargeCommunity},
    nlri::*,
};
use netgauze_iana::address_family::{AddressFamily, SubsequentAddressFamily};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use strum_macros::{Display, FromRepr};
use crate::bgp_ls::BgpLsNlri;

/// General properties to check the validity of a given path attribute value
pub trait PathAttributeValueProperties {
    /// Check the validity of the `optional` bit in the [`PathAttribute`]:
    ///  - `Some(true)` optional must be set to `true`.
    ///  - `Some(false)` optional must be set to `false`.
    ///  - `None` optional can be set to either `true` or `false`.
    fn can_be_optional() -> Option<bool>;

    /// Check the validity of the `transitive` bit in the [`PathAttribute`]:
    ///  - `Some(true)` transitive must be set to `true`.
    ///  - `Some(false)` transitive must be set to `false`.
    ///  - `None` transitive can be set to either `true` or `false`.
    fn can_be_transitive() -> Option<bool>;

    /// Check the validity of the `partial` bit in the [`PathAttribute`]:
    ///  - `Some(true)` partial must be set to `true`.
    ///  - `Some(false)` partial must be set to `false`.
    ///  - `None` partial can be set to either `true` or `false`.
    fn can_be_partial() -> Option<bool>;
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum InvalidPathAttribute {
    InvalidOptionalFlagValue(bool),
    InvalidTransitiveFlagValue(bool),
    InvalidPartialFlagValue(bool),
}

/// Path Attribute
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Attr. Flags  |Attr. Type Code| Path value (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PathAttribute {
    /// Optional bit defines whether the attribute is optional (if set to
    /// `true`) or well-known (if set to `false`).
    optional: bool,

    /// Transitive bit defines whether an optional attribute is transitive (if
    /// set to `true`) or non-transitive (if set to `false`). For well-known
    /// attributes, the Transitive bit MUST be set to `true`.
    transitive: bool,
    partial: bool,
    extended_length: bool,
    value: PathAttributeValue,
}

impl PathAttribute {
    pub fn from(
        optional: bool,
        transitive: bool,
        partial: bool,
        extended_length: bool,
        value: PathAttributeValue,
    ) -> Result<PathAttribute, (PathAttributeValue, InvalidPathAttribute)> {
        if value
            .can_be_optional()
            .map(|x| x != optional)
            .unwrap_or(false)
        {
            return Err((
                value,
                InvalidPathAttribute::InvalidOptionalFlagValue(optional),
            ));
        }
        if value
            .can_be_transitive()
            .map(|x| x != transitive)
            .unwrap_or(false)
        {
            return Err((
                value,
                InvalidPathAttribute::InvalidTransitiveFlagValue(transitive),
            ));
        }
        if value
            .can_be_partial()
            .map(|x| x != partial)
            .unwrap_or(false)
        {
            return Err((
                value,
                InvalidPathAttribute::InvalidPartialFlagValue(partial),
            ));
        }

        Ok(PathAttribute {
            optional,
            transitive,
            partial,
            extended_length,
            value,
        })
    }

    pub const fn value(&self) -> &PathAttributeValue {
        &self.value
    }

    pub const fn optional(&self) -> bool {
        self.optional
    }

    /// Partial bit defines whether the information contained in the optional
    /// transitive attribute is partial (if set to `true`) or complete (if
    /// set to `false`).
    ///
    /// For well-known attributes and for optional non-transitive attributes,
    /// the Partial bit MUST be set to `false`.
    pub const fn partial(&self) -> bool {
        self.partial
    }

    pub const fn transitive(&self) -> bool {
        self.transitive
    }

    ///// Extended Length bit defines whether the Attribute Length is one octet
    ///// (if set to `false`) or two octets (if set to `true`).
    pub const fn extended_length(&self) -> bool {
        self.extended_length
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PathAttributeValue {
    Origin(Origin),
    AsPath(AsPath),
    As4Path(As4Path),
    NextHop(NextHop),
    MultiExitDiscriminator(MultiExitDiscriminator),
    LocalPreference(LocalPreference),
    AtomicAggregate(AtomicAggregate),
    Aggregator(Aggregator),
    Communities(Communities),
    ExtendedCommunities(ExtendedCommunities),
    ExtendedCommunitiesIpv6(ExtendedCommunitiesIpv6),
    LargeCommunities(LargeCommunities),
    Originator(Originator),
    ClusterList(ClusterList),
    MpReach(MpReach),
    MpUnreach(MpUnreach),
    OnlyToCustomer(OnlyToCustomer),
    /// Accumulated IGP metric attribute
    Aigp(Aigp),
    UnknownAttribute(UnknownAttribute),
}

impl PathAttributeValue {
    pub fn can_be_optional(&self) -> Option<bool> {
        match self {
            Self::Origin(_) => Origin::can_be_optional(),
            Self::AsPath(_) => AsPath::can_be_optional(),
            Self::As4Path(_) => As4Path::can_be_optional(),
            Self::NextHop(_) => NextHop::can_be_optional(),
            Self::MultiExitDiscriminator(_) => MultiExitDiscriminator::can_be_optional(),
            Self::LocalPreference(_) => LocalPreference::can_be_optional(),
            Self::AtomicAggregate(_) => AtomicAggregate::can_be_optional(),
            Self::Aggregator(_) => Aggregator::can_be_optional(),
            Self::Communities(_) => Communities::can_be_optional(),
            Self::ExtendedCommunities(_) => ExtendedCommunities::can_be_optional(),
            Self::ExtendedCommunitiesIpv6(_) => ExtendedCommunitiesIpv6::can_be_optional(),
            Self::LargeCommunities(_) => LargeCommunities::can_be_optional(),
            Self::Originator(_) => Originator::can_be_optional(),
            Self::ClusterList(_) => ClusterList::can_be_optional(),
            Self::MpReach(_) => MpReach::can_be_optional(),
            Self::MpUnreach(_) => MpUnreach::can_be_optional(),
            Self::OnlyToCustomer(_) => OnlyToCustomer::can_be_optional(),
            Self::Aigp(_) => Aigp::can_be_optional(),
            Self::UnknownAttribute(_) => UnknownAttribute::can_be_partial(),
        }
    }

    pub fn can_be_transitive(&self) -> Option<bool> {
        match self {
            Self::Origin(_) => Origin::can_be_transitive(),
            Self::AsPath(_) => AsPath::can_be_transitive(),
            Self::As4Path(_) => As4Path::can_be_transitive(),
            Self::NextHop(_) => NextHop::can_be_transitive(),
            Self::MultiExitDiscriminator(_) => MultiExitDiscriminator::can_be_transitive(),
            Self::LocalPreference(_) => LocalPreference::can_be_transitive(),
            Self::AtomicAggregate(_) => AtomicAggregate::can_be_transitive(),
            Self::Aggregator(_) => Aggregator::can_be_transitive(),
            Self::Communities(_) => Communities::can_be_transitive(),
            Self::ExtendedCommunities(_) => ExtendedCommunities::can_be_transitive(),
            Self::ExtendedCommunitiesIpv6(_) => ExtendedCommunitiesIpv6::can_be_transitive(),
            Self::LargeCommunities(_) => LargeCommunities::can_be_transitive(),
            Self::Originator(_) => Originator::can_be_transitive(),
            Self::ClusterList(_) => ClusterList::can_be_transitive(),
            Self::MpReach(_) => MpReach::can_be_transitive(),
            Self::MpUnreach(_) => MpUnreach::can_be_transitive(),
            Self::OnlyToCustomer(_) => OnlyToCustomer::can_be_transitive(),
            Self::Aigp(_) => Aigp::can_be_transitive(),
            Self::UnknownAttribute(_) => UnknownAttribute::can_be_transitive(),
        }
    }

    pub fn can_be_partial(&self) -> Option<bool> {
        match self {
            Self::Origin(_) => Origin::can_be_partial(),
            Self::AsPath(_) => AsPath::can_be_partial(),
            Self::As4Path(_) => As4Path::can_be_partial(),
            Self::NextHop(_) => NextHop::can_be_partial(),
            Self::MultiExitDiscriminator(_) => MultiExitDiscriminator::can_be_partial(),
            Self::LocalPreference(_) => LocalPreference::can_be_partial(),
            Self::AtomicAggregate(_) => AtomicAggregate::can_be_partial(),
            Self::Aggregator(_) => Aggregator::can_be_partial(),
            Self::Communities(_) => Communities::can_be_partial(),
            Self::ExtendedCommunities(_) => ExtendedCommunities::can_be_partial(),
            Self::ExtendedCommunitiesIpv6(_) => ExtendedCommunitiesIpv6::can_be_partial(),
            Self::LargeCommunities(_) => LargeCommunities::can_be_partial(),
            Self::Originator(_) => Originator::can_be_partial(),
            Self::ClusterList(_) => ClusterList::can_be_partial(),
            Self::MpReach(_) => MpReach::can_be_partial(),
            Self::MpUnreach(_) => MpUnreach::can_be_partial(),
            Self::OnlyToCustomer(_) => OnlyToCustomer::can_be_partial(),
            Self::Aigp(_) => Aigp::can_be_partial(),
            Self::UnknownAttribute(_) => UnknownAttribute::can_be_partial(),
        }
    }
}

/// ORIGIN is a well-known mandatory attribute that defines the origin of the
/// path information.
///
/// ```text
/// 0                   1
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  len=1        | value         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Origin {
    IGP = 0,
    EGP = 1,
    Incomplete = 2,
}

impl PathAttributeValueProperties for Origin {
    fn can_be_optional() -> Option<bool> {
        Some(false)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

impl From<Origin> for u8 {
    fn from(value: Origin) -> Self {
        value as u8
    }
}

/// Error type used in [`TryFrom`] for [`Origin`].
/// The value carried is the undefined value being parsed
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedOrigin(pub u8);

impl TryFrom<u8> for Origin {
    type Error = UndefinedOrigin;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedOrigin(value)),
        }
    }
}

/// `AS_PATH` is a well-known mandatory attribute that is composed
/// of a sequence of AS path segments.  Each AS path segment is
/// represented by a triple <path segment type, path segment
/// length, path segment value>.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum AsPath {
    As2PathSegments(Vec<As2PathSegment>),
    As4PathSegments(Vec<As4PathSegment>),
}

impl PathAttributeValueProperties for AsPath {
    fn can_be_optional() -> Option<bool> {
        Some(false)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// AS Path Segment Type
///
/// ```text
/// 0
/// 0 1 2 3 4 5 6 7 8
/// +-+-+-+-+-+-+-+-+
/// | set=1 or seq=2|
/// +-+-+-+-+-+-+-+-+
/// ```
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

impl From<AsPathSegmentType> for u8 {
    fn from(value: AsPathSegmentType) -> Self {
        value as u8
    }
}

/// Error type used in [`TryFrom`] for [`AsPathSegmentType`].
/// The value carried is the undefined value being parsed
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedAsPathSegmentType(pub u8);

impl TryFrom<u8> for AsPathSegmentType {
    type Error = UndefinedAsPathSegmentType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedAsPathSegmentType(value)),
        }
    }
}

///  Each AS path segment is represented by a triple:
/// <path segment type, path segment length, path segment value>.
///
/// ```text
/// 0                   1
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  segment type | len           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | 1.  as number (2 octets)      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | .....                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | len.  as number (2 octets)    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct As2PathSegment {
    segment_type: AsPathSegmentType,
    as_numbers: Vec<u16>,
}

impl As2PathSegment {
    pub fn new(segment_type: AsPathSegmentType, as_numbers: Vec<u16>) -> Self {
        Self {
            segment_type,
            as_numbers,
        }
    }

    pub const fn segment_type(&self) -> AsPathSegmentType {
        self.segment_type
    }

    pub const fn as_numbers(&self) -> &Vec<u16> {
        &self.as_numbers
    }
}

///  Each AS path segment is represented by a triple:
/// <path segment type, path segment length, path segment value>.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct As4PathSegment {
    segment_type: AsPathSegmentType,
    as_numbers: Vec<u32>,
}

impl As4PathSegment {
    pub const fn new(segment_type: AsPathSegmentType, as_numbers: Vec<u32>) -> Self {
        Self {
            segment_type,
            as_numbers,
        }
    }

    pub const fn segment_type(&self) -> AsPathSegmentType {
        self.segment_type
    }

    pub const fn as_numbers(&self) -> &Vec<u32> {
        &self.as_numbers
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct As4Path {
    segments: Vec<As4PathSegment>,
}

/// This is an optional transitive attribute that
/// contains the AS path encoded with four-octet AS numbers. The
/// `AS4_PATH` attribute has the same semantics and the same encoding as
/// the [`AsPath`] attribute, except that it is "optional transitive", and
/// it carries four-octet AS numbers.
/// See [RFC6793](https://datatracker.ietf.org/doc/html/RFC6793)
impl As4Path {
    pub const fn new(segments: Vec<As4PathSegment>) -> Self {
        Self { segments }
    }

    pub const fn segments(&self) -> &Vec<As4PathSegment> {
        &self.segments
    }
}

impl PathAttributeValueProperties for As4Path {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        None
    }
}

/// This is a well-known mandatory attribute that defines the
/// (unicast) IP address of the router that SHOULD be used as
/// the next hop to the destinations listed in the Network Layer
/// Reachability Information field of the UPDATE message.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct NextHop {
    next_hop: Ipv4Addr,
}
impl NextHop {
    pub const fn new(next_hop: Ipv4Addr) -> Self {
        Self { next_hop }
    }

    pub const fn next_hop(&self) -> Ipv4Addr {
        self.next_hop
    }
}

impl PathAttributeValueProperties for NextHop {
    fn can_be_optional() -> Option<bool> {
        Some(false)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// This is an optional non-transitive attribute that is a
/// four-octet unsigned integer. The value of this attribute
/// MAY be used by a BGP speaker's Decision Process to
/// discriminate among multiple entry points to a neighboring
/// autonomous system.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MultiExitDiscriminator {
    metric: u32,
}

impl MultiExitDiscriminator {
    pub const fn new(metric: u32) -> Self {
        Self { metric }
    }

    pub const fn metric(&self) -> u32 {
        self.metric
    }
}

impl PathAttributeValueProperties for MultiExitDiscriminator {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// `LOCAL_PREF` is a well-known attribute that is a four-octet
/// unsigned integer. A BGP speaker uses it to inform its other
/// internal peers of the advertising speaker's degree of
/// preference for an advertised route.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct LocalPreference {
    metric: u32,
}

impl LocalPreference {
    pub const fn new(metric: u32) -> Self {
        Self { metric }
    }

    pub const fn metric(&self) -> u32 {
        self.metric
    }
}

impl PathAttributeValueProperties for LocalPreference {
    fn can_be_optional() -> Option<bool> {
        Some(false)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// `ATOMIC_AGGREGATE` is a well-known discretionary attribute of length 0.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct AtomicAggregate;

impl PathAttributeValueProperties for AtomicAggregate {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}
/// AGGREGATOR is an optional transitive attribute of length 6.
/// The attribute contains the last AS number that formed the
/// aggregate route (encoded as 2 octets), followed by the IP
/// address of the BGP speaker that formed the aggregate route
/// (encoded as 4 octets). This SHOULD be the same address as
/// the one used for the BGP Identifier of the speaker.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct As2Aggregator {
    asn: u16,
    origin: Ipv4Addr,
}

impl As2Aggregator {
    pub const fn new(asn: u16, origin: Ipv4Addr) -> Self {
        Self { asn, origin }
    }

    pub const fn asn(&self) -> &u16 {
        &self.asn
    }
    pub const fn origin(&self) -> Ipv4Addr {
        self.origin
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct As4Aggregator {
    asn: u32,
    origin: Ipv4Addr,
}

impl As4Aggregator {
    pub const fn new(asn: u32, origin: Ipv4Addr) -> Self {
        Self { asn, origin }
    }

    pub const fn asn(&self) -> &u32 {
        &self.asn
    }
    pub const fn origin(&self) -> Ipv4Addr {
        self.origin
    }
}

/// AGGREGATOR is an optional transitive attribute. The attribute contains the
/// last AS number that formed the aggregate route, followed by the IP
/// address of the BGP speaker that formed the aggregate route.
/// This SHOULD be the same address as the one used for the BGP Identifier of
/// the speaker.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Aggregator {
    As2Aggregator(As2Aggregator),
    As4Aggregator(As4Aggregator),
}

impl PathAttributeValueProperties for Aggregator {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        None
    }
}

/// Path attribute can be of size `u8` or `u16` based on `extended_length` bit.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PathAttributeLength {
    U8(u8),
    U16(u16),
}

impl From<PathAttributeLength> for u16 {
    fn from(path_attr_len: PathAttributeLength) -> Self {
        match path_attr_len {
            PathAttributeLength::U8(len) => len.into(),
            PathAttributeLength::U16(len) => len,
        }
    }
}

/// COMMUNITIES path attribute is an optional transitive attribute of variable
/// length. The attribute consists of a set of four octet values, each of which
/// specify a community. All routes with this attribute belong to the
/// communities listed in the attribute.
///
/// See [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Communities {
    communities: Vec<Community>,
}

impl Communities {
    pub const fn new(communities: Vec<Community>) -> Self {
        Self { communities }
    }

    pub const fn communities(&self) -> &Vec<Community> {
        &self.communities
    }
}

impl PathAttributeValueProperties for Communities {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        None
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ExtendedCommunities {
    communities: Vec<ExtendedCommunity>,
}

impl ExtendedCommunities {
    pub const fn new(communities: Vec<ExtendedCommunity>) -> Self {
        Self { communities }
    }

    pub const fn communities(&self) -> &Vec<ExtendedCommunity> {
        &self.communities
    }
}

impl PathAttributeValueProperties for ExtendedCommunities {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        None
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ExtendedCommunitiesIpv6 {
    communities: Vec<ExtendedCommunityIpv6>,
}

impl ExtendedCommunitiesIpv6 {
    pub const fn new(communities: Vec<ExtendedCommunityIpv6>) -> Self {
        Self { communities }
    }

    pub const fn communities(&self) -> &Vec<ExtendedCommunityIpv6> {
        &self.communities
    }
}

impl PathAttributeValueProperties for ExtendedCommunitiesIpv6 {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        None
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct LargeCommunities {
    communities: Vec<LargeCommunity>,
}

impl LargeCommunities {
    pub const fn new(communities: Vec<LargeCommunity>) -> Self {
        Self { communities }
    }

    pub const fn communities(&self) -> &Vec<LargeCommunity> {
        &self.communities
    }
}

impl PathAttributeValueProperties for LargeCommunities {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        None
    }
}

/// `ORIGINATOR_ID` is an optional, non-transitive BGP attribute. This
/// attribute is 4 bytes long and it will be created by an RR in reflecting a
/// route. This attribute carries the BGP Identifier of the originator of
/// the route in the local AS.  A BGP speaker SHOULD NOT create an
/// `ORIGINATOR_ID` attribute if one already exists.  A router that recognizes
/// the `ORIGINATOR_ID` attribute SHOULD ignore a route received with its BGP
/// Identifier as the `ORIGINATOR_ID`.
///
/// [RFC4456](https://datatracker.ietf.org/doc/html/rfc4456) defines this value
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Originator(Ipv4Addr);

impl Originator {
    pub const fn new(id: Ipv4Addr) -> Self {
        Self(id)
    }

    pub const fn id(&self) -> Ipv4Addr {
        self.0
    }
}

impl PathAttributeValueProperties for Originator {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// `CLUSTER_LIST` is a new, optional, non-transitive BGP attribute. It is a
/// sequence of `CLUSTER_ID` values representing the reflection path that the
/// route has passed.
///
/// [RFC4456](https://datatracker.ietf.org/doc/html/rfc4456) defines this value
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ClusterList(Vec<ClusterId>);

impl ClusterList {
    pub const fn new(cluster_list: Vec<ClusterId>) -> Self {
        Self(cluster_list)
    }

    pub const fn cluster_list(&self) -> &Vec<ClusterId> {
        &self.0
    }
}

impl PathAttributeValueProperties for ClusterList {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ClusterId(Ipv4Addr);

impl ClusterId {
    pub const fn new(id: Ipv4Addr) -> Self {
        Self(id)
    }

    pub const fn id(&self) -> Ipv4Addr {
        self.0
    }
}

/// Multi-protocol Reachable NLRI (`MP_REACH_NLRI`) is an optional
/// non-transitive attribute that can be used for the following purposes:
///
/// 1. to advertise a feasible route to a peer
/// 2. to permit a router to advertise the Network Layer address of the router
/// that should be used as the next hop to the destinations
/// listed in the Network Layer Reachability Information field of the `MP_NLRI`
/// attribute.
///
/// see [RFC4760](https://www.rfc-editor.org/rfc/rfc4760)
///
/// ```text
/// +---------------------------------------------------------+
/// | Address Family Identifier (2 octets)                    |
/// +---------------------------------------------------------+
/// | Subsequent Address Family Identifier (1 octet)          |
/// +---------------------------------------------------------+
/// | Length of Next Hop Network Address (1 octet)            |
/// +---------------------------------------------------------+
/// | Network Address of Next Hop (variable)                  |
/// +---------------------------------------------------------+
/// | Reserved (1 octet)                                      |
/// +---------------------------------------------------------+
/// | Network Layer Reachability Information (variable)       |
/// +---------------------------------------------------------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum MpReach {
    Ipv4Unicast {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
        next_hop: IpAddr,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ipv6)))]
        next_hop_local: Option<Ipv6Addr>,
        nlri: Vec<Ipv4UnicastAddress>,
    },
    Ipv4Multicast {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
        next_hop: IpAddr,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ipv6)))]
        next_hop_local: Option<Ipv6Addr>,
        nlri: Vec<Ipv4MulticastAddress>,
    },
    Ipv4NlriMplsLabels {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
        next_hop: IpAddr,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ipv6)))]
        next_hop_local: Option<Ipv6Addr>,
        nlri: Vec<Ipv4NlriMplsLabelsAddress>,
    },
    Ipv4MplsVpnUnicast {
        next_hop: LabeledNextHop,
        nlri: Vec<Ipv4MplsVpnUnicastAddress>,
    },
    Ipv6Unicast {
        next_hop_global: Ipv6Addr,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ipv6)))]
        next_hop_local: Option<Ipv6Addr>,
        nlri: Vec<Ipv6UnicastAddress>,
    },
    Ipv6Multicast {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ipv6))]
        next_hop_global: Ipv6Addr,
        #[cfg_attr(feature = "fuzz", arbitrary(with = arbitrary_ext::arbitrary_option(crate::arbitrary_ipv6)))]
        next_hop_local: Option<Ipv6Addr>,
        nlri: Vec<Ipv6MulticastAddress>,
    },
    Ipv6NlriMplsLabels {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
        next_hop: IpAddr,
        nlri: Vec<Ipv6NlriMplsLabelsAddress>,
    },
    Ipv6MplsVpnUnicast {
        next_hop: LabeledNextHop,
        nlri: Vec<Ipv6MplsVpnUnicastAddress>,
    },
    L2Evpn {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
        next_hop: IpAddr,
        nlri: Vec<L2EvpnAddress>,
    },
    RouteTargetMembership {
        #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_ip))]
        next_hop: IpAddr,
        nlri: Vec<RouteTargetMembershipAddress>,
    },

    ///
    ///    The format of the Link-State NLRI is shown in the following figures.
    ///
    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |            NLRI Type          |     Total NLRI Length         |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                                                               |
    ///      //                  Link-State NLRI (variable)                 //
    ///      |                                                               |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///            Figure 5: Link-State AFI 16388 / SAFI 71 NLRI Format
    ///
    ///    The Total NLRI Length field contains the cumulative length, in
    ///    octets, of the rest of the NLRI, not including the NLRI Type field or
    ///    itself
    /// 
    BgpLs {
        // TODO add nexthop
        nlri: BgpLsNlri
    },

    ///
    ///    The format of the Link-State VPN NLRI is shown in the following figures.
    ///
    ///       0                   1                   2                   3
    ///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |            NLRI Type          |     Total NLRI Length         |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                                                               |
    ///      +                       Route Distinguisher                     +
    ///      |                                                               |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///      |                                                               |
    ///      //                  Link-State NLRI (variable)                 //
    ///      |                                                               |
    ///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///            Figure 5: Link-State AFI 16388 / SAFI 71 NLRI Format
    ///
    ///    The Total NLRI Length field contains the cumulative length, in
    ///    octets, of the rest of the NLRI, not including the NLRI Type field or
    ///    itself. For VPN applications, it also includes the length of the
    ///    Route Distinguisher.
    ///
    BgpLsVpn {
        // TODO add nexthop
        rd: RouteDistinguisher,
        nlri: BgpLsNlri
    },
    Unknown {
        afi: AddressFamily,
        safi: SubsequentAddressFamily,
        value: Vec<u8>,
    },
}

impl PathAttributeValueProperties for MpReach {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// Multi-protocol Unreachable NLRI (`MP_UNREACH_NLRI`) is an optional
/// non-transitive attribute that can be used for the purpose of withdrawing
/// multiple unfeasible routes from service.
///
/// see [RFC4760](https://www.rfc-editor.org/rfc/rfc4760)
///
/// ```text
/// +---------------------------------------------------------+
/// | Address Family Identifier (2 octets)                    |
/// +---------------------------------------------------------+
/// | Subsequent Address Family Identifier (1 octet)          |
/// +---------------------------------------------------------+
/// | Withdrawn Routes (variable)                             |
/// +---------------------------------------------------------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum MpUnreach {
    Ipv4Unicast {
        nlri: Vec<Ipv4UnicastAddress>,
    },
    Ipv4Multicast {
        nlri: Vec<Ipv4MulticastAddress>,
    },
    Ipv4NlriMplsLabels {
        nlri: Vec<Ipv4NlriMplsLabelsAddress>,
    },
    Ipv4MplsVpnUnicast {
        nlri: Vec<Ipv4MplsVpnUnicastAddress>,
    },
    Ipv6Unicast {
        nlri: Vec<Ipv6UnicastAddress>,
    },
    Ipv6Multicast {
        nlri: Vec<Ipv6MulticastAddress>,
    },
    Ipv6NlriMplsLabels {
        nlri: Vec<Ipv4NlriMplsLabelsAddress>,
    },
    Ipv6MplsVpnUnicast {
        nlri: Vec<Ipv6MplsVpnUnicastAddress>,
    },
    L2Evpn {
        nlri: Vec<L2EvpnAddress>,
    },
    RouteTargetMembership {
        nlri: Vec<RouteTargetMembershipAddress>,
    },
    Unknown {
        afi: AddressFamily,
        safi: SubsequentAddressFamily,
        nlri: Vec<u8>,
    },
}

impl PathAttributeValueProperties for MpUnreach {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// Path Attribute that is not recognized.
/// BGP Allows parsing unrecognized attributes as is, and then only consider
/// the transitive and partial bits of the attribute.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UnknownAttribute {
    code: u8,
    value: Vec<u8>,
}

impl UnknownAttribute {
    pub const fn new(code: u8, value: Vec<u8>) -> Self {
        Self { code, value }
    }

    /// Attribute Type code
    pub const fn code(&self) -> u8 {
        self.code
    }

    /// Raw u8 vector of the value carried in the attribute
    pub const fn value(&self) -> &Vec<u8> {
        &self.value
    }
}

impl PathAttributeValueProperties for UnknownAttribute {
    fn can_be_optional() -> Option<bool> {
        None
    }

    fn can_be_transitive() -> Option<bool> {
        None
    }

    fn can_be_partial() -> Option<bool> {
        None
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct OnlyToCustomer(u32);

impl OnlyToCustomer {
    pub const fn new(asn: u32) -> Self {
        Self(asn)
    }

    pub const fn asn(&self) -> u32 {
        self.0
    }
}

impl PathAttributeValueProperties for OnlyToCustomer {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

/// Accumulated IGP Metric Attribute [RFC7311](https://datatracker.ietf.org/doc/html/rfc7311)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Aigp {
    AccumulatedIgpMetric(u64),
}

impl PathAttributeValueProperties for Aigp {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(false)
    }

    fn can_be_partial() -> Option<bool> {
        Some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin() {
        let undefined_code = 255;
        let defined_code = 0;
        let defined_ret = Origin::try_from(defined_code);
        let undefined_ret = Origin::try_from(undefined_code);
        let defined_u8: u8 = Origin::IGP.into();
        assert_eq!(defined_ret, Ok(Origin::IGP));
        assert_eq!(undefined_ret, Err(UndefinedOrigin(undefined_code)));
        assert_eq!(defined_u8, defined_code);
    }

    #[test]
    fn test_as_segment_type() {
        let undefined_code = 255;
        let defined_code = 1;
        let defined_ret = AsPathSegmentType::try_from(defined_code);
        let undefined_ret = AsPathSegmentType::try_from(undefined_code);
        let defined_u8: u8 = AsPathSegmentType::AsSet.into();
        assert_eq!(defined_ret, Ok(AsPathSegmentType::AsSet));
        assert_eq!(
            undefined_ret,
            Err(UndefinedAsPathSegmentType(undefined_code))
        );
        assert_eq!(defined_u8, defined_code);
    }

    #[test]
    fn test_path_attributes_well_known_mandatory() {
        assert!(!Origin::can_be_optional().unwrap_or(false));
        assert!(Origin::can_be_transitive().unwrap_or(false));
        assert!(!AsPath::can_be_optional().unwrap_or(false));
        assert!(AsPath::can_be_transitive().unwrap_or(false));
        assert!(!NextHop::can_be_optional().unwrap_or(false));
        assert!(NextHop::can_be_transitive().unwrap_or(false));
        assert!(!LocalPreference::can_be_optional().unwrap_or(false));
        assert!(LocalPreference::can_be_transitive().unwrap_or(false));
    }

    #[test]
    fn test_path_attributes_well_known_discretionary() {
        assert!(MultiExitDiscriminator::can_be_optional().unwrap_or(false));
        assert!(!MultiExitDiscriminator::can_be_transitive().unwrap_or(false));
    }

    #[test]
    fn test_path_attributes_optional() {
        assert!(As4Path::can_be_optional().unwrap_or(false));
        assert!(As4Path::can_be_transitive().unwrap_or(false));
        assert!(Aggregator::can_be_optional().unwrap_or(false));
        assert!(Aggregator::can_be_transitive().unwrap_or(false));
        assert!(MpReach::can_be_optional().unwrap_or(false));
        assert!(!MpReach::can_be_transitive().unwrap_or(false));
        assert!(OnlyToCustomer::can_be_optional().unwrap_or(false));
        assert!(OnlyToCustomer::can_be_transitive().unwrap_or(false));
    }
}
