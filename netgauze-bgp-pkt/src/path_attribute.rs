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

//! Contains the extensible definitions for various [PathAttribute] that can be
//! used in [crate::update::BGPUpdateMessage].

use crate::{
    iana::WellKnownCommunity,
    nlri::{Ipv4Multicast, Ipv4Unicast, Ipv6Multicast, Ipv6Unicast},
};
use std::net::{Ipv4Addr, Ipv6Addr};
use strum_macros::{Display, FromRepr};

/// PathAttribute
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Attr. Flags  |Attr. Type Code| Path value (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PathAttribute {
    Origin {
        extended_length: bool,
        value: Origin,
    },
    ASPath {
        extended_length: bool,
        value: ASPath,
    },
    AS4Path {
        partial: bool,
        extended_length: bool,
        value: AS4Path,
    },
    NextHop {
        extended_length: bool,
        value: NextHop,
    },
    MultiExitDiscriminator {
        extended_length: bool,
        value: MultiExitDiscriminator,
    },
    LocalPreference {
        extended_length: bool,
        value: LocalPreference,
    },
    AtomicAggregate {
        extended_length: bool,
        value: AtomicAggregate,
    },
    Aggregator {
        partial: bool,
        extended_length: bool,
        value: Aggregator,
    },
    Communities {
        partial: bool,
        extended_length: bool,
        value: Communities,
    },
    MpReach {
        extended_length: bool,
        value: MpReach,
    },
    UnknownAttribute {
        partial: bool,
        value: UnknownAttribute,
    },
}

impl PathAttribute {
    /// Optional bit defines whether the attribute is optional (if set to
    /// `true`) or well-known (if set to `false`).
    pub const fn optional(&self) -> bool {
        match self {
            Self::Origin {
                extended_length: _,
                value: _,
            } => Origin::optional(),
            Self::ASPath {
                extended_length: _,
                value: _,
            } => ASPath::optional(),
            Self::AS4Path {
                partial: _,
                extended_length: _,
                value: _,
            } => AS4Path::optional(),
            Self::NextHop {
                extended_length: _,
                value: _,
            } => NextHop::optional(),
            Self::MultiExitDiscriminator {
                extended_length: _,
                value: _,
            } => MultiExitDiscriminator::optional(),
            Self::LocalPreference {
                extended_length: _,
                value: _,
            } => LocalPreference::optional(),
            Self::AtomicAggregate {
                extended_length: _,
                value: _,
            } => AtomicAggregate::optional(),
            Self::Aggregator {
                partial: _,
                extended_length: _,
                value: _,
            } => Aggregator::optional(),
            Self::Communities {
                partial: _,
                extended_length: _,
                value: _,
            } => Communities::optional(),
            Self::MpReach {
                extended_length: _,
                value: _,
            } => MpReach::optional(),
            Self::UnknownAttribute { partial: _, value } => value.optional(),
        }
    }

    /// Transitive bit defines whether an optional attribute is transitive (if
    /// set to `true`) or non-transitive (if set to `false`). For well-known
    /// attributes, the Transitive bit MUST be set to `true`.
    pub const fn transitive(&self) -> bool {
        match self {
            Self::Origin {
                extended_length: _,
                value: _,
            } => Origin::transitive(),
            Self::ASPath {
                extended_length: _,
                value: _,
            } => ASPath::transitive(),
            Self::AS4Path {
                partial: _,
                extended_length: _,
                value: _,
            } => AS4Path::transitive(),
            Self::NextHop {
                extended_length: _,
                value: _,
            } => NextHop::transitive(),
            Self::MultiExitDiscriminator {
                extended_length: _,
                value: _,
            } => MultiExitDiscriminator::transitive(),
            Self::LocalPreference {
                extended_length: _,
                value: _,
            } => LocalPreference::transitive(),
            Self::AtomicAggregate {
                extended_length: _,
                value: _,
            } => AtomicAggregate::transitive(),
            Self::Aggregator {
                partial: _,
                extended_length: _,
                value: _,
            } => Aggregator::transitive(),
            Self::Communities {
                partial: _,
                extended_length: _,
                value: _,
            } => Communities::transitive(),
            Self::MpReach {
                extended_length: _,
                value: _,
            } => MpReach::transitive(),
            Self::UnknownAttribute { partial: _, value } => value.transitive(),
        }
    }

    /// Partial bit defines whether the information contained in the optional
    /// transitive attribute is partial (if set to `true`) or complete (if
    /// set to `false`).
    ///
    /// For well-known attributes and for optional non-transitive attributes,
    /// the Partial bit MUST be set to `false`.
    pub const fn partial(&self) -> bool {
        match self {
            Self::Origin {
                extended_length: _,
                value: _,
            } => Origin::partial(),
            Self::ASPath {
                extended_length: _,
                value: _,
            } => ASPath::partial(),
            Self::AS4Path {
                partial,
                extended_length: _,
                value: _,
            } => *partial,
            Self::NextHop {
                extended_length: _,
                value: _,
            } => NextHop::partial(),
            Self::MultiExitDiscriminator {
                extended_length: _,
                value: _,
            } => MultiExitDiscriminator::partial(),
            Self::LocalPreference {
                extended_length: _,
                value: _,
            } => LocalPreference::partial(),
            Self::AtomicAggregate {
                extended_length: _,
                value: _,
            } => AtomicAggregate::partial(),
            Self::Aggregator {
                partial,
                extended_length: _,
                value: _,
            } => *partial,
            Self::Communities {
                partial,
                extended_length: _,
                value: _,
            } => *partial,
            Self::MpReach {
                extended_length: _,
                value: _,
            } => MpReach::partial(),
            Self::UnknownAttribute { partial, value: _ } => *partial,
        }
    }

    /// Extended Length bit defines whether the Attribute Length is one octet
    /// (if set to `false`) or two octets (if set to `true`).
    pub const fn extended_length(&self) -> bool {
        match self {
            Self::Origin {
                extended_length,
                value: _,
            } => *extended_length,
            Self::ASPath {
                extended_length,
                value: _,
            } => *extended_length,
            Self::AS4Path {
                partial: _,
                extended_length,
                value: _,
            } => *extended_length,
            Self::NextHop {
                extended_length,
                value: _,
            } => *extended_length,
            Self::MultiExitDiscriminator {
                extended_length,
                value: _,
            } => *extended_length,
            Self::LocalPreference {
                extended_length,
                value: _,
            } => *extended_length,
            Self::AtomicAggregate {
                extended_length,
                value: _,
            } => *extended_length,
            Self::Aggregator {
                partial: _,
                extended_length,
                value: _,
            } => *extended_length,
            Self::Communities {
                partial: _,
                extended_length,
                value: _,
            } => *extended_length,
            Self::MpReach {
                extended_length,
                value: _,
            } => *extended_length,
            Self::UnknownAttribute { partial: _, value } => value.extended_length(),
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
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug)]
pub enum Origin {
    IGP = 0,
    EGP = 1,
    Incomplete = 2,
}

impl Origin {
    pub const fn optional() -> bool {
        false
    }

    pub const fn transitive() -> bool {
        true
    }

    pub const fn partial() -> bool {
        false
    }
}

impl From<Origin> for u8 {
    fn from(value: Origin) -> Self {
        value as u8
    }
}

/// Error type used in `[TryFrom] for [Origin].
/// The value carried is the undefined value being parsed
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

/// AS_PATH is a well-known mandatory attribute that is composed
/// of a sequence of AS path segments.  Each AS path segment is
/// represented by a triple <path segment type, path segment
/// length, path segment value>.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ASPath {
    As2PathSegments(Vec<As2PathSegment>),
    As4PathSegments(Vec<As4PathSegment>),
}

impl ASPath {
    pub const fn optional() -> bool {
        false
    }

    pub const fn transitive() -> bool {
        true
    }

    pub const fn partial() -> bool {
        false
    }
}

/// AsPathSegmentType
///
/// ```text
/// 0
/// 0 1 2 3 4 5 6 7 8
/// +-+-+-+-+-+-+-+-+
/// | set=1 or seq=2|
/// +-+-+-+-+-+-+-+-+
/// ```
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

impl From<AsPathSegmentType> for u8 {
    fn from(value: AsPathSegmentType) -> Self {
        value as u8
    }
}

/// Error type used in `[TryFrom] for [AsPathSegmentType].
/// The value carried is the undefined value being parsed
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
#[derive(Debug, Clone, Eq, PartialEq)]
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
#[derive(Debug, Clone, Eq, PartialEq)]
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AS4Path {
    segments: Vec<As4PathSegment>,
}

impl AS4Path {
    pub const fn new(segments: Vec<As4PathSegment>) -> Self {
        Self { segments }
    }

    pub const fn segments(&self) -> &Vec<As4PathSegment> {
        &self.segments
    }
}

impl AS4Path {
    pub const fn optional() -> bool {
        true
    }

    pub const fn transitive() -> bool {
        true
    }
}

/// This is a well-known mandatory attribute that defines the
/// (unicast) IP address of the router that SHOULD be used as
/// the next hop to the destinations listed in the Network Layer
/// Reachability Information field of the UPDATE message.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NextHop {
    next_hop: Ipv4Addr,
}
impl NextHop {
    pub const fn new(next_hop: Ipv4Addr) -> Self {
        Self { next_hop }
    }

    pub const fn next_hop(&self) -> &Ipv4Addr {
        &self.next_hop
    }
}

impl NextHop {
    pub const fn optional() -> bool {
        false
    }

    pub const fn transitive() -> bool {
        true
    }

    pub const fn partial() -> bool {
        false
    }
}

/// This is an optional non-transitive attribute that is a
/// four-octet unsigned integer. The value of this attribute
/// MAY be used by a BGP speaker's Decision Process to
/// discriminate among multiple entry points to a neighboring
/// autonomous system.
#[derive(Debug, Clone, Eq, PartialEq)]
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

    pub const fn optional() -> bool {
        true
    }

    pub const fn transitive() -> bool {
        false
    }

    pub const fn partial() -> bool {
        false
    }
}

/// LOCAL_PREF is a well-known attribute that is a four-octet
/// unsigned integer. A BGP speaker uses it to inform its other
/// internal peers of the advertising speaker's degree of
/// preference for an advertised route.
#[derive(Debug, Clone, Eq, PartialEq)]
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

impl LocalPreference {
    pub const fn optional() -> bool {
        false
    }

    pub const fn transitive() -> bool {
        true
    }

    pub const fn partial() -> bool {
        false
    }
}

/// ATOMIC_AGGREGATE is a well-known discretionary attribute of length 0.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AtomicAggregate;

impl AtomicAggregate {
    pub const fn optional() -> bool {
        true
    }

    pub const fn transitive() -> bool {
        true
    }

    pub const fn partial() -> bool {
        false
    }
}

/// AGGREGATOR is an optional transitive attribute of length 6.
/// The attribute contains the last AS number that formed the
/// aggregate route (encoded as 2 octets), followed by the IP
/// address of the BGP speaker that formed the aggregate route
/// (encoded as 4 octets). This SHOULD be the same address as
/// the one used for the BGP Identifier of the speaker.
#[derive(Debug, Clone, Eq, PartialEq)]
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
    pub const fn origin(&self) -> &Ipv4Addr {
        &self.origin
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
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
    pub const fn origin(&self) -> &Ipv4Addr {
        &self.origin
    }
}

/// AGGREGATOR is an optional transitive attribute. The attribute contains the
/// last AS number that formed the aggregate route, followed by the IP
/// address of the BGP speaker that formed the aggregate route.
/// This SHOULD be the same address as the one used for the BGP Identifier of
/// the speaker.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Aggregator {
    As2Aggregator(As2Aggregator),
    As4Aggregator(As4Aggregator),
}

impl Aggregator {
    pub const fn optional() -> bool {
        true
    }

    pub const fn transitive() -> bool {
        true
    }
}

/// Path attribute can be of size `u8` or `u16` based on `extended_length` bit.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
#[derive(Debug, Clone, Eq, PartialEq)]
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

impl Communities {
    pub const fn optional() -> bool {
        true
    }

    pub const fn transitive() -> bool {
        true
    }
}

/// Four octet values to specify a community.
///
/// See [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Community(u32);

impl Community {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
    /// Parse the community numerical value into a [WellKnownCommunity].
    /// If the value is not well-known, then will return None.
    pub const fn into_well_known(&self) -> Option<WellKnownCommunity> {
        WellKnownCommunity::from_repr(self.0)
    }

    /// Getting the ASN number part according to [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    pub const fn collection_asn(&self) -> u16 {
        (self.0 >> 16 & 0xffff) as u16
    }

    /// Getting the value part according to [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    pub const fn collection_value(&self) -> u16 {
        (self.0 & 0x0000ffff) as u16
    }
}

/// Multi-protocol Reachable NLRI (MP_REACH_NLRI) is an optional non-transitive
/// attribute that can be used for the following purposes:
///
/// 1. to advertise a feasible route to a peer
/// 2. to permit a router to advertise the Network Layer address of the router
/// that should be used as the next hop to the destinations
/// listed in the Network Layer Reachability Information field of the MP_NLRI
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MpReach {
    Ipv4Unicast {
        next_hop: Ipv4Addr,
        nlri: Vec<Ipv4Unicast>,
    },
    Ipv4Multicast {
        next_hop: Ipv4Addr,
        nlri: Vec<Ipv4Multicast>,
    },
    Ipv6Unicast {
        next_hop_global: Ipv6Addr,
        next_hop_local: Option<Ipv6Addr>,
        nlri: Vec<Ipv6Unicast>,
    },
    Ipv6Multicast {
        next_hop_global: Ipv6Addr,
        next_hop_local: Option<Ipv6Addr>,
        nlri: Vec<Ipv6Multicast>,
    },
}

impl MpReach {
    pub const fn optional() -> bool {
        true
    }

    pub const fn transitive() -> bool {
        false
    }

    pub const fn partial() -> bool {
        false
    }
}

/// Path Attribute that is not recognized.
/// BGP Allows parsing unrecognized attributes as is, and then only consider
/// the transitive and partial bits of the attribute.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnknownAttribute {
    optional: bool,
    transitive: bool,
    code: u8,
    length: PathAttributeLength,
    value: Vec<u8>,
}

impl UnknownAttribute {
    pub const fn new(
        optional: bool,
        transitive: bool,
        code: u8,
        len: PathAttributeLength,
        value: Vec<u8>,
    ) -> Self {
        Self {
            optional,
            transitive,
            code,
            length: len,
            value,
        }
    }

    /// Attribute Type code
    pub const fn code(&self) -> u8 {
        self.code
    }

    pub const fn length(&self) -> PathAttributeLength {
        self.length
    }

    /// Raw u8 vector of the value carried in the attribute
    pub const fn value(&self) -> &Vec<u8> {
        &self.value
    }

    pub const fn optional(&self) -> bool {
        self.optional
    }

    pub const fn transitive(&self) -> bool {
        self.transitive
    }

    pub const fn extended_length(&self) -> bool {
        match self.length {
            PathAttributeLength::U8(_) => false,
            PathAttributeLength::U16(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        iana::WellKnownCommunity,
        path_attribute::{
            AS4Path, ASPath, Aggregator, AsPathSegmentType, Community, LocalPreference, MpReach,
            MultiExitDiscriminator, NextHop, Origin, UndefinedAsPathSegmentType, UndefinedOrigin,
        },
    };

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
        assert!(!Origin::optional());
        assert!(Origin::transitive());
        assert!(!ASPath::optional());
        assert!(ASPath::transitive());
        assert!(!NextHop::optional());
        assert!(NextHop::transitive());
        assert!(!LocalPreference::optional());
        assert!(LocalPreference::transitive());
    }

    #[test]
    fn test_path_attributes_well_known_discretionary() {
        assert!(MultiExitDiscriminator::optional());
        assert!(!MultiExitDiscriminator::transitive());
    }

    #[test]
    fn test_path_attributes_optional() {
        assert!(AS4Path::optional());
        assert!(AS4Path::transitive());
        assert!(Aggregator::optional());
        assert!(Aggregator::transitive());
        assert!(MpReach::optional());
        assert!(!MpReach::transitive());
    }

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
}
