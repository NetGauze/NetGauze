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

use std::net::Ipv4Addr;
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
pub struct PathAttribute {
    /// Partial bit defines whether the information contained in the optional
    /// transitive attribute is partial (if set to `true`) or complete (if
    /// set to `false`).
    ///
    /// For well-known attributes and for optional non-transitive attributes,
    /// the Partial bit MUST be set to `false`.
    partial: bool,

    /// Extended Length bit defines whether the Attribute Length is one octet
    /// (if set to `false`) or two octets (if set to `true`).
    extended_length: bool,

    /// Attribute value and are interpreted according to the Attribute Flags and
    /// the Attribute Type Code.
    value: PathAttributeValue,
}

impl PathAttribute {
    pub const fn new(partial: bool, extended_length: bool, value: PathAttributeValue) -> Self {
        Self {
            partial,
            extended_length,
            value,
        }
    }

    /// Optional bit defines whether the attribute is optional (if set to
    /// `true`) or well-known (if set to `false`).
    pub fn optional(&self) -> bool {
        self.value.is_optional()
    }

    /// Transitive bit defines whether an optional attribute is transitive (if
    /// set to `true`) or non-transitive (if set to `false`). For well-known
    /// attributes, the Transitive bit MUST be set to `true`.
    pub fn transitive(&self) -> bool {
        self.value.is_transitive()
    }

    pub const fn partial(&self) -> bool {
        self.partial
    }

    pub const fn extended_length(&self) -> bool {
        self.extended_length
    }

    pub const fn value(&self) -> &PathAttributeValue {
        &self.value
    }
}

pub(crate) trait PathAttributeValueOptions {
    fn is_optional() -> bool;
    fn is_transitive() -> bool;
}

/// PathAttributeValue
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Attr. Code   | value (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PathAttributeValue {
    Origin(Origin),
    ASPath(AsPathSegments),
    AS4Path(As4PathSegments),
    NextHop(NextHop),
    MultiExitDiscriminator(MultiExitDiscriminator),
    LocalPreference(LocalPreference),
    AtomicAggregate(AtomicAggregate),
    Aggregator(Aggregator),
    UnknownAttribute(UnknownAttribute),
}

impl PathAttributeValue {
    fn is_optional(&self) -> bool {
        match self {
            Self::Origin(_) => Origin::is_optional(),
            Self::ASPath(_) => AsPathSegments::is_optional(),
            Self::AS4Path(_) => As4PathSegments::is_optional(),
            Self::NextHop(_) => NextHop::is_optional(),
            Self::MultiExitDiscriminator(_) => MultiExitDiscriminator::is_optional(),
            Self::LocalPreference(_) => LocalPreference::is_optional(),
            Self::AtomicAggregate(_) => AtomicAggregate::is_optional(),
            Self::Aggregator(_) => Aggregator::is_optional(),
            Self::UnknownAttribute(attr) => attr.optional(),
        }
    }

    fn is_transitive(&self) -> bool {
        match self {
            Self::Origin(_) => Origin::is_transitive(),
            Self::ASPath(_) => AsPathSegments::is_transitive(),
            Self::AS4Path(_) => As4PathSegments::is_transitive(),
            Self::NextHop(_) => NextHop::is_transitive(),
            Self::MultiExitDiscriminator(_) => MultiExitDiscriminator::is_transitive(),
            Self::LocalPreference(_) => LocalPreference::is_transitive(),
            Self::AtomicAggregate(_) => AtomicAggregate::is_transitive(),
            Self::Aggregator(_) => Aggregator::is_transitive(),
            Self::UnknownAttribute(attr) => attr.transitive(),
        }
    }
}

/// Origin
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

impl PathAttributeValueOptions for Origin {
    fn is_optional() -> bool {
        false
    }

    fn is_transitive() -> bool {
        true
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AsPathSegments {
    As2PathSegments(As2PathSegments),
    As4PathSegments(As4PathSegments),
}

impl PathAttributeValueOptions for AsPathSegments {
    fn is_optional() -> bool {
        false
    }

    fn is_transitive() -> bool {
        true
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

/// As2PathSegment
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct As2PathSegments {
    segments: Vec<As2PathSegment>,
}
impl As2PathSegments {
    pub const fn new(segments: Vec<As2PathSegment>) -> Self {
        Self { segments }
    }

    pub const fn segments(&self) -> &Vec<As2PathSegment> {
        &self.segments
    }
}

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

    pub const fn segment_type(&self) -> &AsPathSegmentType {
        &self.segment_type
    }

    pub const fn as_numbers(&self) -> &Vec<u32> {
        &self.as_numbers
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct As4PathSegments {
    segments: Vec<As4PathSegment>,
}

impl As4PathSegments {
    pub const fn new(segments: Vec<As4PathSegment>) -> Self {
        Self { segments }
    }

    pub const fn segments(&self) -> &Vec<As4PathSegment> {
        &self.segments
    }
}

impl PathAttributeValueOptions for As4PathSegments {
    fn is_optional() -> bool {
        true
    }

    fn is_transitive() -> bool {
        true
    }
}

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

impl PathAttributeValueOptions for NextHop {
    fn is_optional() -> bool {
        false
    }

    fn is_transitive() -> bool {
        true
    }
}

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
}

impl PathAttributeValueOptions for MultiExitDiscriminator {
    fn is_optional() -> bool {
        true
    }

    fn is_transitive() -> bool {
        false
    }
}

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

impl PathAttributeValueOptions for LocalPreference {
    fn is_optional() -> bool {
        false
    }

    fn is_transitive() -> bool {
        true
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AtomicAggregate;

impl PathAttributeValueOptions for AtomicAggregate {
    fn is_optional() -> bool {
        true
    }

    fn is_transitive() -> bool {
        true
    }
}

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Aggregator {
    As2Aggregator(As2Aggregator),
    As4Aggregator(As4Aggregator),
}

impl PathAttributeValueOptions for Aggregator {
    fn is_optional() -> bool {
        true
    }

    fn is_transitive() -> bool {
        true
    }
}

/// Path attribute can be of size `u8` or `u16` if the `extended_length` bit is
/// toggled.
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

    pub const fn code(&self) -> &u8 {
        &self.code
    }

    pub const fn length(&self) -> &PathAttributeLength {
        &self.length
    }

    pub const fn value(&self) -> &Vec<u8> {
        &self.value
    }

    pub const fn optional(&self) -> bool {
        self.optional
    }

    pub const fn transitive(&self) -> bool {
        self.transitive
    }
}

#[cfg(test)]
mod tests {
    use crate::path_attribute::{
        Aggregator, As4PathSegments, AsPathSegmentType, AsPathSegments, LocalPreference,
        MultiExitDiscriminator, NextHop, Origin, PathAttributeValueOptions,
        UndefinedAsPathSegmentType, UndefinedOrigin,
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
        assert!(!Origin::is_optional());
        assert!(Origin::is_transitive());
        assert!(!AsPathSegments::is_optional());
        assert!(AsPathSegments::is_transitive());
        assert!(!NextHop::is_optional());
        assert!(NextHop::is_transitive());
        assert!(!LocalPreference::is_optional());
        assert!(LocalPreference::is_transitive());
    }

    #[test]
    fn test_path_attributes_well_known_discretionary() {
        assert!(MultiExitDiscriminator::is_optional());
        assert!(!MultiExitDiscriminator::is_transitive());
    }

    #[test]
    fn test_path_attributes_optional() {
        assert!(As4PathSegments::is_optional());
        assert!(As4PathSegments::is_transitive());
        assert!(Aggregator::is_optional());
        assert!(Aggregator::is_transitive());
    }
}
