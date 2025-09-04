// Copyright (C) 2025-present The NetGauze Authors.
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

//! Flow reference types and utilities.
//!
//! This module provides types and functions for working with flow field
//! references, allowing efficient mapping and indexing of Information Elements
//! (IEs) within flow records. The primary type `FieldRef` combines an IE with
//! an index to handle cases where the same IE appears multiple times in a
//! template.
//!
//! Note: This module/functions may be relocated in the future.

use netgauze_flow_pkt::ie::{Field, HasIE, IE};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};

/// A reference to a specific field within a flow DataRecord (Box<[Field]>)
///
/// `FieldRef` uniquely identifies a field by combining an Information Element
/// (IE) with an index. The index is necessary because the same IE can appear
/// multiple times within a single record, and each occurrence needs to be
/// distinguished.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FieldRef {
    ie: IE,
    index: usize,
}
impl FieldRef {
    pub fn new(ie: IE, index: usize) -> Self {
        Self { ie, index }
    }
    pub fn ie(&self) -> IE {
        self.ie
    }
    pub fn index(&self) -> usize {
        self.index
    }

    /// Generic function that maps Field objects to FieldRef and collects into
    /// any collection.
    ///
    /// This function processes an array of fields, assigns sequential indices
    /// to fields with the same IE, and applies a custom mapping function to
    /// create the desired collection type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type of items in the resulting collection
    /// * `F` - The mapper function type
    /// * `C` - The collection type to create (must implement `FromIterator<T>`)
    ///
    /// # Arguments
    ///
    /// * `fields` - Slice of Field objects to process
    /// * `mapper_fn` - Function that transforms (FieldRef, &Field) into type T
    ///
    /// # Returns
    ///
    /// A collection of type C containing the mapped items
    pub fn map_fields<'a, T, F, C>(fields: &'a [Field], mut mapper_fn: F) -> C
    where
        F: FnMut(FieldRef, &'a Field) -> T,
        C: FromIterator<T>,
    {
        let mut ie_counters: FxHashMap<IE, usize> =
            FxHashMap::with_capacity_and_hasher(fields.len(), FxBuildHasher);

        fields
            .iter()
            .map(|field| {
                let ie = field.ie();
                let ie_count = ie_counters.entry(ie).or_insert(0);
                let field_ref = FieldRef::new(ie, *ie_count);
                *ie_count += 1;
                mapper_fn(field_ref, field)
            })
            .collect()
    }

    /// Maps fields into an FxHashMap with FieldRef keys and borrowed Field
    /// values.
    pub fn map_fields_into_fxhashmap(fields: &[Field]) -> FxHashMap<Self, &Field> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field))
    }

    /// Maps fields into an FxHashMap with FieldRef keys and owned Field values.
    pub fn map_fields_into_fxhashmap_owned(fields: &[Field]) -> FxHashMap<Self, Field> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field.clone()))
    }

    /// Maps fields into a Vec with FieldRef and borrowed Field pairs.
    pub fn map_fields_into_vec(fields: &[Field]) -> Vec<(Self, &Field)> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field))
    }

    /// Maps fields into a Vec with FieldRef and owned Field pairs.
    pub fn map_fields_into_vec_owned(fields: &[Field]) -> Vec<(Self, Field)> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field.clone()))
    }

    /// Maps fields into a boxed slice with FieldRef and borrowed Field pairs.
    pub fn map_fields_into_boxed_slice(fields: &[Field]) -> Box<[(Self, &Field)]> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field))
    }

    /// A boxed slice of (FieldRef, Field) tuples with owned Field objects
    pub fn map_fields_into_boxed_slice_owned(fields: &[Field]) -> Box<[(Self, Field)]> {
        Self::map_fields(fields, |field_ref, field| (field_ref, field.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use netgauze_flow_pkt::ie::{protocolIdentifier, Field, IE};
    use netgauze_iana::tcp::TCPHeaderFlags;
    use rustc_hash::{FxBuildHasher, FxHashMap};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_field_ref_equality_and_ordering() {
        let ref1 = FieldRef::new(IE::sourceIPv4Address, 0);
        let ref2 = FieldRef::new(IE::sourceIPv4Address, 0);
        let ref3 = FieldRef::new(IE::sourceIPv4Address, 1);
        let ref4 = FieldRef::new(IE::destinationIPv4Address, 0);

        // Test equality
        assert_eq!(ref1, ref2);
        assert_ne!(ref1, ref3);
        assert_ne!(ref1, ref4);

        // Test ordering
        assert!(ref1 < ref3);
        assert!(ref1 != ref4);
    }

    #[test]
    fn test_field_ref_hash() {
        use std::collections::HashMap;

        let ref1 = FieldRef::new(IE::sourceIPv4Address, 0);
        let ref2 = FieldRef::new(IE::sourceIPv4Address, 0);
        let ref3 = FieldRef::new(IE::sourceIPv4Address, 1);

        let mut map = HashMap::new();
        map.insert(ref1, "value1");
        map.insert(ref3, "value3");

        // Same FieldRef should retrieve same value
        assert_eq!(map.get(&ref2), Some(&"value1"));
        assert_eq!(map.get(&ref3), Some(&"value3"));
    }

    #[test]
    fn test_map_fields_simple() {
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
            Field::sourceTransportPort(80),
            Field::octetDeltaCount(1000),
        ];

        let result: Vec<(FieldRef, u32)> =
            FieldRef::map_fields(&fields, |field_ref, field| match field {
                Field::sourceTransportPort(port) => (field_ref, *port as u32),
                Field::octetDeltaCount(count) => (field_ref, *count as u32),
                _ => (field_ref, 0),
            });

        let expected = vec![
            (FieldRef::new(IE::sourceIPv4Address, 0), 0),
            (FieldRef::new(IE::destinationIPv4Address, 0), 0),
            (FieldRef::new(IE::sourceTransportPort, 0), 80),
            (FieldRef::new(IE::octetDeltaCount, 0), 1000),
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_map_fields_with_duplicate_ies() {
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::sourceIPv4Address(Ipv4Addr::new(192, 168, 1, 1)),
            Field::protocolIdentifier(protocolIdentifier::TCP),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
            Field::protocolIdentifier(protocolIdentifier::UDP),
            Field::protocolIdentifier(protocolIdentifier::ICMP),
        ];

        let result: Vec<FieldRef> = FieldRef::map_fields(&fields, |field_ref, _| field_ref);

        let expected = vec![
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::sourceIPv4Address, 1),
            FieldRef::new(IE::protocolIdentifier, 0),
            FieldRef::new(IE::destinationIPv4Address, 0),
            FieldRef::new(IE::protocolIdentifier, 1),
            FieldRef::new(IE::protocolIdentifier, 2),
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_map_fields_empty() {
        let fields: Vec<Field> = vec![];
        let result: Vec<FieldRef> = FieldRef::map_fields(&fields, |field_ref, _| field_ref);
        assert!(result.is_empty());
    }

    #[test]
    fn test_map_fields_into_fxhashmap() {
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
            Field::sourceTransportPort(80),
            Field::sourceTransportPort(443),
        ];

        let result = FieldRef::map_fields_into_fxhashmap(&fields);

        // Create expected fxhashmap
        let mut expected: FxHashMap<FieldRef, &Field> =
            FxHashMap::with_capacity_and_hasher(4, FxBuildHasher);
        expected.insert(FieldRef::new(IE::sourceIPv4Address, 0), &fields[0]);
        expected.insert(FieldRef::new(IE::destinationIPv4Address, 0), &fields[1]);
        expected.insert(FieldRef::new(IE::sourceTransportPort, 0), &fields[2]);
        expected.insert(FieldRef::new(IE::sourceTransportPort, 1), &fields[3]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_map_fields_into_fxhashmap_owned() {
        let fields = vec![
            Field::tcpControlBits(TCPHeaderFlags::new(
                true, false, false, false, false, false, false, false,
            )),
            Field::octetDeltaCount(2000),
        ];

        let result = FieldRef::map_fields_into_fxhashmap_owned(&fields);

        // Create expected fxhashmap
        let mut expected: FxHashMap<FieldRef, Field> =
            FxHashMap::with_capacity_and_hasher(2, FxBuildHasher);
        expected.insert(
            FieldRef::new(IE::tcpControlBits, 0),
            Field::tcpControlBits(TCPHeaderFlags::new(
                true, false, false, false, false, false, false, false,
            )),
        );
        expected.insert(
            FieldRef::new(IE::octetDeltaCount, 0),
            Field::octetDeltaCount(2000),
        );

        assert_eq!(result, expected);
    }

    #[test]
    fn test_map_fields_into_vec() {
        let fields = vec![
            Field::sourceIPv6Address(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            Field::destinationIPv6Address(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ];

        let result = FieldRef::map_fields_into_vec(&fields);

        // Create expected vec
        let source_field = Field::sourceIPv6Address(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let dest_field =
            Field::destinationIPv6Address(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let expected = vec![
            (FieldRef::new(IE::sourceIPv6Address, 0), &source_field),
            (FieldRef::new(IE::destinationIPv6Address, 0), &dest_field),
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_map_fields_into_vec_owned() {
        let fields = vec![
            Field::packetDeltaCount(10),
            Field::flowEndSeconds(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()),
        ];

        let result = FieldRef::map_fields_into_vec_owned(&fields);

        // Create expected vec
        let expected = vec![
            (
                FieldRef::new(IE::packetDeltaCount, 0),
                Field::packetDeltaCount(10),
            ),
            (
                FieldRef::new(IE::flowEndSeconds, 0),
                Field::flowEndSeconds(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()),
            ),
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_map_fields_into_boxed_slice() {
        let fields = vec![Field::minimumTTL(64), Field::maximumTTL(128)];

        let result = FieldRef::map_fields_into_boxed_slice(&fields);

        // Create expected boxed slice
        let expected: Box<[(FieldRef, &Field)]> = Box::new([
            (FieldRef::new(IE::minimumTTL, 0), &Field::minimumTTL(64)),
            (FieldRef::new(IE::maximumTTL, 0), &Field::maximumTTL(128)),
        ]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_map_fields_into_boxed_slice_owned() {
        let fields = vec![
            Field::flowStartSeconds(Utc.with_ymd_and_hms(2025, 1, 1, 16, 0, 0).unwrap()),
            Field::ingressInterface(1),
            Field::egressInterface(2),
        ];

        let result = FieldRef::map_fields_into_boxed_slice_owned(&fields);

        // Create expected boxed slice
        let expected: Box<[(FieldRef, Field)]> = Box::new([
            (
                FieldRef::new(IE::flowStartSeconds, 0),
                Field::flowStartSeconds(Utc.with_ymd_and_hms(2025, 1, 1, 16, 0, 0).unwrap()),
            ),
            (
                FieldRef::new(IE::ingressInterface, 0),
                Field::ingressInterface(1),
            ),
            (
                FieldRef::new(IE::egressInterface, 0),
                Field::egressInterface(2),
            ),
        ]);

        assert_eq!(result, expected);
    }
}
