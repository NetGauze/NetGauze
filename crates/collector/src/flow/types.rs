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

use netgauze_flow_pkt::{
    ie::{Field, HasIE, IE},
    ipfix,
};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};

const fn default_field_index() -> usize {
    0
}

/// A reference to a specific field within a flow DataRecord (Box<[Field]>)
///
/// `FieldRef` uniquely identifies a field by combining an Information Element
/// (IE) with an index. The index is necessary because the same IE can appear
/// multiple times within a single record, and each occurrence needs to be
/// distinguished.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FieldRef {
    ie: IE,

    #[serde(default = "default_field_index")]
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
    /// create the desired collection type. Calling collect() on the iterator
    /// will leverage size hints if the chosen collections supports it so it
    /// should not have allocation overhead.
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

/// Trait for efficient field lookups in flow data structures.
///
/// This trait provides a consistent interface for looking up fields by either
/// their exact `FieldRef` (IE + index) or just by their Information Element.
pub trait FieldRefLookup<V> {
    fn contains_field_ref(&self, field_ref: FieldRef) -> bool;
    fn contains_ie(&self, ie: IE) -> bool;
    fn get_by_field_ref(&self, field_ref: FieldRef) -> Option<&V>;
    fn get_by_ie(&self, ie: IE) -> Option<&V>;
}

impl<V> FieldRefLookup<V> for FxHashMap<FieldRef, V> {
    fn contains_field_ref(&self, field_ref: FieldRef) -> bool {
        self.contains_key(&field_ref)
    }

    fn contains_ie(&self, ie: IE) -> bool {
        // Try index 0 for O(1) lookup
        if self.contains_key(&FieldRef::new(ie, 0)) {
            return true;
        }

        // Fallback to check all indices
        self.keys().any(|field_ref| field_ref.ie() == ie)
    }

    fn get_by_field_ref(&self, field_ref: FieldRef) -> Option<&V> {
        self.get(&field_ref)
    }

    fn get_by_ie(&self, ie: IE) -> Option<&V> {
        // Try index 0 for O(1) lookup
        if let Some(value) = self.get(&FieldRef::new(ie, 0)) {
            return Some(value);
        }

        // Fallback to check all indices
        self.iter()
            .find(|(field_ref, _)| field_ref.ie() == ie)
            .map(|(_, value)| value)
    }
}

/// An indexed flow data record struct for efficient field access.
///
/// The record maintains separate collections for scope fields and regular
/// fields, matching the structure of IPFIX DataRecords.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedDataRecord {
    scope_fields: FxHashMap<FieldRef, Field>,
    fields: FxHashMap<FieldRef, Field>,
}

impl IndexedDataRecord {
    /// Create a new IndexedDataRecord from `Vec<Field>` for both scope fields
    /// and fields
    pub fn new(scope_fields: &[Field], fields: &[Field]) -> Self {
        Self {
            scope_fields: FieldRef::map_fields_into_fxhashmap_owned(scope_fields),
            fields: FieldRef::map_fields_into_fxhashmap_owned(fields),
        }
    }
    pub fn scope_fields(&self) -> &FxHashMap<FieldRef, Field> {
        &self.scope_fields
    }
    pub fn into_scope_fields(self) -> FxHashMap<FieldRef, Field> {
        self.scope_fields
    }
    pub fn fields(&self) -> &FxHashMap<FieldRef, Field> {
        &self.fields
    }
    pub fn into_fields(self) -> FxHashMap<FieldRef, Field> {
        self.fields
    }
    /// Destructure the record into its constituent parts
    pub fn into_parts(self) -> (FxHashMap<FieldRef, Field>, FxHashMap<FieldRef, Field>) {
        (self.scope_fields, self.fields)
    }
}

impl FieldRefLookup<Field> for IndexedDataRecord {
    fn contains_field_ref(&self, field_ref: FieldRef) -> bool {
        self.scope_fields.contains_key(&field_ref) || self.fields.contains_key(&field_ref)
    }

    fn contains_ie(&self, ie: IE) -> bool {
        self.scope_fields.contains_ie(ie) || self.fields.contains_ie(ie)
    }

    fn get_by_field_ref(&self, field_ref: FieldRef) -> Option<&Field> {
        self.scope_fields
            .get_by_field_ref(field_ref)
            .or_else(|| self.fields.get_by_field_ref(field_ref))
    }

    fn get_by_ie(&self, ie: IE) -> Option<&Field> {
        self.scope_fields
            .get_by_ie(ie)
            .or_else(|| self.fields.get_by_ie(ie))
    }
}

impl From<ipfix::DataRecord> for IndexedDataRecord {
    fn from(record: ipfix::DataRecord) -> Self {
        IndexedDataRecord {
            scope_fields: FieldRef::map_fields_into_fxhashmap_owned(record.scope_fields()),
            fields: FieldRef::map_fields_into_fxhashmap_owned(record.fields()),
        }
    }
}

impl From<IndexedDataRecord> for ipfix::DataRecord {
    fn from(record: IndexedDataRecord) -> Self {
        ipfix::DataRecord::new(
            record.scope_fields.into_values().collect(),
            record.fields.into_values().collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use netgauze_flow_pkt::ie::{Field, IE, protocolIdentifier};
    use netgauze_iana::tcp::TCPHeaderFlags;
    use rustc_hash::{FxBuildHasher, FxHashMap};
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
    };

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

    #[test]
    fn test_indexed_data_record_new() {
        let scope_fields = vec![
            Field::exportingProcessId(100),
            Field::ingressInterface(1),
            Field::egressInterface(2),
            Field::exportingProcessId(200),
            Field::exportingProcessId(300),
        ];
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::applicationGroupName("first".to_string().into()),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
            Field::applicationGroupName("second".to_string().into()),
            Field::sourceTransportPort(80),
            Field::applicationGroupName("third".to_string().into()),
            Field::applicationGroupName("fourth".to_string().into()),
        ];

        let record = IndexedDataRecord::new(&scope_fields, &fields);

        // Construct expected IndexedDataRecord
        let mut expected_scope_fields = HashMap::with_hasher(FxBuildHasher);
        expected_scope_fields.insert(
            FieldRef::new(IE::exportingProcessId, 0),
            Field::exportingProcessId(100),
        );
        expected_scope_fields.insert(
            FieldRef::new(IE::exportingProcessId, 1),
            Field::exportingProcessId(200),
        );
        expected_scope_fields.insert(
            FieldRef::new(IE::exportingProcessId, 2),
            Field::exportingProcessId(300),
        );
        expected_scope_fields.insert(
            FieldRef::new(IE::ingressInterface, 0),
            Field::ingressInterface(1),
        );
        expected_scope_fields.insert(
            FieldRef::new(IE::egressInterface, 0),
            Field::egressInterface(2),
        );
        let mut expected_fields = HashMap::with_hasher(FxBuildHasher);
        expected_fields.insert(
            FieldRef::new(IE::applicationGroupName, 0),
            Field::applicationGroupName("first".to_string().into()),
        );
        expected_fields.insert(
            FieldRef::new(IE::applicationGroupName, 1),
            Field::applicationGroupName("second".to_string().into()),
        );
        expected_fields.insert(
            FieldRef::new(IE::applicationGroupName, 2),
            Field::applicationGroupName("third".to_string().into()),
        );
        expected_fields.insert(
            FieldRef::new(IE::applicationGroupName, 3),
            Field::applicationGroupName("fourth".to_string().into()),
        );
        expected_fields.insert(
            FieldRef::new(IE::sourceIPv4Address, 0),
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        );
        expected_fields.insert(
            FieldRef::new(IE::destinationIPv4Address, 0),
            Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
        );
        expected_fields.insert(
            FieldRef::new(IE::sourceTransportPort, 0),
            Field::sourceTransportPort(80),
        );
        let expected_record = IndexedDataRecord {
            scope_fields: expected_scope_fields,
            fields: expected_fields,
        };

        assert_eq!(record, expected_record);
    }

    #[test]
    fn test_indexed_data_record_getters() {
        let scope_fields = vec![
            Field::exportingProcessId(100),
            Field::exportingProcessId(200),
            Field::exportingProcessId(300),
        ];
        let fields = vec![Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))];
        let record = IndexedDataRecord::new(&scope_fields, &fields);

        // Test IndexedDataRecord getter methods
        assert!(record.contains_field_ref(FieldRef::new(IE::exportingProcessId, 0)));
        assert!(record.contains_field_ref(FieldRef::new(IE::exportingProcessId, 1)));
        assert!(record.contains_field_ref(FieldRef::new(IE::exportingProcessId, 2)));
        assert!(record.contains_field_ref(FieldRef::new(IE::sourceIPv4Address, 0)));

        assert!(record.contains_ie(IE::exportingProcessId));
        assert!(record.contains_ie(IE::sourceIPv4Address));

        // Test FxHashMap<FieldRef, V> getter methods
        assert!(
            record
                .scope_fields()
                .contains_field_ref(FieldRef::new(IE::exportingProcessId, 0))
        );
        assert!(
            record
                .scope_fields()
                .contains_field_ref(FieldRef::new(IE::exportingProcessId, 1))
        );
        assert!(
            record
                .scope_fields()
                .contains_field_ref(FieldRef::new(IE::exportingProcessId, 2))
        );
        assert!(
            record
                .fields()
                .contains_field_ref(FieldRef::new(IE::sourceIPv4Address, 0))
        );

        assert!(record.scope_fields().contains_ie(IE::exportingProcessId));
        assert!(record.fields().contains_ie(IE::sourceIPv4Address));
    }
}
