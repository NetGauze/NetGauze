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

use crate::flow::enrichment::{cache::*, EnrichmentOperation, Scope, Weight};
use netgauze_flow_pkt::ie::{Field, IE};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[test]
fn test_enrichment_cache_upsert_new_entry() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(0, None); // Global scope
    let weight: Weight = 100;
    let fields = vec![
        Field::samplerName("test_sampler".to_string().into()),
        Field::observationPointId(42),
    ];

    // Upsert operation
    cache.upsert(ip, scope.clone(), weight, fields.clone());

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            weight,
            Field::samplerName("test_sampler".to_string().into()),
        ),
    );
    expected_fields.insert(
        FieldRef::new(IE::observationPointId, 0),
        WeightedField::new(weight, Field::observationPointId(42)),
    );
    let expected_peer_metadata = PeerMetadata::from_vec(vec![(scope.into(), expected_fields)]);
    let expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);

    // Compare cache after upsert with expected
    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_upsert_weight_replacement() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(1000, None);

    // Insert field with low weight
    let low_weight: Weight = 50;
    let fields1 = vec![Field::samplerName("low_priority".to_string().into())];
    cache.upsert(ip, scope.clone(), low_weight, fields1);

    // Insert field with higher weight - should replace
    let high_weight: Weight = 150;
    let fields2 = vec![Field::samplerName("high_priority".to_string().into())];
    cache.upsert(ip, scope.clone(), high_weight, fields2);

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            high_weight,
            Field::samplerName("high_priority".to_string().into()),
        ),
    );
    let expected_peer_metadata =
        PeerMetadata::from_vec(vec![(scope.clone().into(), expected_fields)]);
    let expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_upsert_weight_ignored() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope_fields = vec![Field::selectorId(1200)];
    let scope = Scope::new(2000, Some(scope_fields));

    // Insert field with high weight
    let high_weight: Weight = 200;
    let fields1 = vec![Field::samplerName("high_priority".to_string().into())];
    cache.upsert(ip, scope.clone(), high_weight, fields1);

    // Try to insert field with lower weight - should be ignored
    let low_weight: Weight = 100;
    let fields2 = vec![Field::samplerName("low_priority".to_string().into())];
    cache.upsert(ip, scope.clone(), low_weight, fields2);

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            high_weight,
            Field::samplerName("high_priority".to_string().into()),
        ),
    );
    let expected_peer_metadata =
        PeerMetadata::from_vec(vec![(scope.clone().into(), expected_fields)]);
    let expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_upsert_equal_weights() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(3000, None);
    let weight: Weight = 100;

    // Insert first field
    let fields1 = vec![Field::samplerName("first".to_string().into())];
    cache.upsert(ip, scope.clone(), weight, fields1);

    // Insert second field with equal weight - should replace
    let fields2 = vec![Field::samplerName("second".to_string().into())];
    cache.upsert(ip, scope.clone(), weight, fields2);

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(weight, Field::samplerName("second".to_string().into())),
    );
    let expected_peer_metadata =
        PeerMetadata::from_vec(vec![(scope.clone().into(), expected_fields)]);
    let expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_delete_by_weight() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(4000, None);

    // Insert fields with different weights
    let fields = vec![
        Field::samplerName("test1".to_string().into()),
        Field::observationPointId(1),
    ];
    cache.upsert(ip, scope.clone(), 50, fields);

    let fields2 = vec![Field::meteringProcessId(42)];
    cache.upsert(ip, scope.clone(), 150, fields2);

    let fields3 = vec![Field::observationDomainName("OBS_NAME".to_string().into())];
    cache.upsert(ip, scope.clone(), 80, fields3);

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(50, Field::samplerName("test1".to_string().into())),
    );
    expected_fields.insert(
        FieldRef::new(IE::observationPointId, 0),
        WeightedField::new(50, Field::observationPointId(1)),
    );
    expected_fields.insert(
        FieldRef::new(IE::meteringProcessId, 0),
        WeightedField::new(150, Field::meteringProcessId(42)),
    );
    expected_fields.insert(
        FieldRef::new(IE::observationDomainName, 0),
        WeightedField::new(
            80,
            Field::observationDomainName("OBS_NAME".to_string().into()),
        ),
    );
    let expected_peer_metadata =
        PeerMetadata::from_vec(vec![(scope.clone().into(), expected_fields)]);
    let expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);

    assert_eq!(cache, expected_cache);

    // Delete fields with weight < 100
    cache.delete(ip, scope.clone(), 100);

    // Create expected cache after delete
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::meteringProcessId, 0),
        WeightedField::new(150, Field::meteringProcessId(42)),
    );
    let expected_peer_metadata =
        PeerMetadata::from_vec(vec![(scope.clone().into(), expected_fields)]);
    let expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_delete_empty_scope_cleanup() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(5000, None);

    // Insert field with low weight
    let fields = vec![Field::samplerName("test".to_string().into())];
    cache.upsert(ip, scope.clone(), 50, fields);

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(50, Field::samplerName("test".to_string().into())),
    );
    let expected_peer_metadata =
        PeerMetadata::from_vec(vec![(scope.clone().into(), expected_fields)]);
    let expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);

    assert_eq!(cache, expected_cache);

    // Delete with higher weight - should remove all fields and cleanup scope
    cache.delete(ip, scope.clone(), 100);

    // Create expected cache after delete (empty)
    let expected_cache = EnrichmentCache::from_vec(vec![]);

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_delete_nonexistent() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(6000, None);

    // Delete from empty cache should not panic
    cache.delete(ip, scope, 100);
    let expected_cache = EnrichmentCache::from_vec(vec![]);
    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_apply_enrichment_operations() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(7000, None);
    let weight: Weight = 100;

    // Apply upsert operation
    let fields = vec![Field::samplerName("test_sampler".to_string().into())];
    let upsert_op = EnrichmentOperation::new_upsert(ip, scope.clone(), weight, fields.clone());
    cache.apply_enrichment(upsert_op);

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            weight,
            Field::samplerName("test_sampler".to_string().into()),
        ),
    );
    let expected_peer_metadata =
        PeerMetadata::from_vec(vec![(scope.clone().into(), expected_fields)]);
    let mut expected_cache = EnrichmentCache::from_vec(vec![(ip, expected_peer_metadata)]);
    assert_eq!(cache, expected_cache);

    // Apply delete operation
    let delete_op = EnrichmentOperation::new_delete(ip, scope, 200);
    cache.apply_enrichment(delete_op);

    // Create expected cache after delete operation (empty)
    expected_cache = EnrichmentCache::from_vec(vec![]);
    assert_eq!(cache, expected_cache);
}

#[test]
fn test_peer_metadata_scope_matches_global() {
    let scope = IndexedScope::new(0, vec![]); // Global/system scope

    let fields = [
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let incoming_fields = FieldRef::map_fields_into_fxhashmap(&fields);

    // Global scope should match any observation domain & incoming fields
    assert!(PeerMetadata::scope_matches(&scope, 1000, &incoming_fields));
    assert!(PeerMetadata::scope_matches(&scope, 2000, &incoming_fields));
    assert!(PeerMetadata::scope_matches(&scope, 0, &incoming_fields));
}

#[test]
fn test_peer_metadata_scope_matches_specific_domain() {
    let scope = IndexedScope::new(1000, vec![]);

    let empty_incoming_fields = FxHashMap::with_hasher(FxBuildHasher);

    let fields = [Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))];
    let incoming_fields = FieldRef::map_fields_into_fxhashmap(&fields);

    // Specific obs_id scope should only match its own observation domain
    // (however since scope_fields empty it should match any incoming fields)
    assert!(PeerMetadata::scope_matches(
        &scope,
        1000,
        &empty_incoming_fields
    ));
    assert!(PeerMetadata::scope_matches(&scope, 1000, &incoming_fields));
    assert!(!PeerMetadata::scope_matches(&scope, 2000, &incoming_fields));
    assert!(!PeerMetadata::scope_matches(&scope, 0, &incoming_fields));
}

#[test]
fn test_peer_metadata_scope_matches_with_scope_fields() {
    let scope = IndexedScope::new(
        1000,
        vec![
            (FieldRef::new(IE::selectorId, 0), Field::selectorId(42)),
            (
                FieldRef::new(IE::samplingAlgorithm, 0),
                Field::samplingAlgorithm(1),
            ),
        ],
    );

    let fields = [
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
        Field::selectorId(42),       // match
        Field::samplingAlgorithm(1), // match
        Field::octetDeltaCount(8000),
        Field::packetDeltaCount(100),
    ];
    let matching_fields = FieldRef::map_fields_into_fxhashmap(&fields);

    let fields = [
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::selectorId(43),       // no match (different value)
        Field::samplingAlgorithm(1), // match
        Field::octetDeltaCount(8000),
        Field::packetDeltaCount(100),
    ];
    let non_matching_fields = FieldRef::map_fields_into_fxhashmap(&fields);

    let fields = [
        Field::selectorId(42), // match
        // no match (missing samplingAlgorithm)
        Field::octetDeltaCount(8000),
        Field::packetDeltaCount(100),
    ];
    let missing_field = FieldRef::map_fields_into_fxhashmap(&fields);

    // Should match when all scope fields are present and have matching values
    assert!(PeerMetadata::scope_matches(&scope, 1000, &matching_fields));

    // Should not match when field values differ
    assert!(!PeerMetadata::scope_matches(
        &scope,
        1000,
        &non_matching_fields
    ));

    // Should not match when required scope fields are missing
    assert!(!PeerMetadata::scope_matches(&scope, 1000, &missing_field));
}

#[test]
fn test_peer_metadata_scope_global_obs_id_with_scope_fields() {
    let scope = IndexedScope::new(
        0,
        vec![
            (FieldRef::new(IE::selectorId, 0), Field::selectorId(42)),
            (
                FieldRef::new(IE::samplingAlgorithm, 0),
                Field::samplingAlgorithm(1),
            ),
        ],
    );

    let fields = [
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
        Field::selectorId(42),       // match
        Field::samplingAlgorithm(1), // match
        Field::octetDeltaCount(8000),
        Field::packetDeltaCount(100),
    ];
    let matching_fields = FieldRef::map_fields_into_fxhashmap(&fields);

    let fields = [
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::selectorId(43),       // no match (different value)
        Field::samplingAlgorithm(1), // match
        Field::octetDeltaCount(8000),
        Field::packetDeltaCount(100),
    ];
    let non_matching_fields = FieldRef::map_fields_into_fxhashmap(&fields);

    let fields = [
        Field::selectorId(42), // match
        // no match (missing samplingAlgorithm)
        Field::octetDeltaCount(8000),
        Field::packetDeltaCount(100),
    ];
    let missing_field = FieldRef::map_fields_into_fxhashmap(&fields);

    // Should match when all scope fields are present and have matching values
    // even with more specific incoming obs_domain_id (55)
    assert!(PeerMetadata::scope_matches(&scope, 0, &matching_fields));
    assert!(PeerMetadata::scope_matches(&scope, 55, &matching_fields));

    // Should not match when field values differ
    assert!(!PeerMetadata::scope_matches(
        &scope,
        0,
        &non_matching_fields
    ));
    assert!(!PeerMetadata::scope_matches(
        &scope,
        430,
        &non_matching_fields
    ));

    // Should not match when required scope fields are missing
    assert!(!PeerMetadata::scope_matches(&scope, 0, &missing_field));
    assert!(!PeerMetadata::scope_matches(&scope, 235, &missing_field));
}

#[test]
fn test_peer_metadata_get_enrichment_fields_simple() {
    let global_scope = IndexedScope::new(0, vec![]);

    let mut fields_map = FxHashMap::default();
    fields_map.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(100, Field::samplerName("global_sampler".to_string().into())),
    );

    let peer_metadata = PeerMetadata::from_vec(vec![(global_scope, fields_map)]);

    let incoming_fields = vec![
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
        Field::octetDeltaCount(1500),
        Field::packetDeltaCount(1),
    ];

    let enrichment_fields = peer_metadata.get_enrichment_fields(1000, &incoming_fields);

    // Create expected enrichment fields (scope matches since we something for
    // global scope)
    let expected_enrichment_fields = Some(vec![Field::samplerName(
        "global_sampler".to_string().into(),
    )]);

    assert_eq!(enrichment_fields, expected_enrichment_fields);
}

#[test]
fn test_peer_metadata_get_enrichment_fields_multiple_scopes_matching() {
    let global_scope = IndexedScope::new(0, vec![]);
    let mut global_fields = FxHashMap::default();
    global_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(50, Field::samplerName("global_sampler".to_string().into())),
    );

    let specific_scope = IndexedScope::new(1000, vec![]);
    let mut specific_fields = FxHashMap::default();
    specific_fields.insert(
        FieldRef::new(IE::observationPointId, 0),
        WeightedField::new(100, Field::observationPointId(123)),
    );

    let peer_metadata = PeerMetadata::from_vec(vec![
        (global_scope, global_fields),
        (specific_scope, specific_fields),
    ]);

    let incoming_fields = vec![Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))];

    let enrichment_fields = peer_metadata
        .get_enrichment_fields(1000, &incoming_fields)
        .unwrap_or_default();

    let expected_enrichment_fields = vec![
        Field::samplerName("global_sampler".to_string().into()),
        Field::observationPointId(123),
    ];

    // Compare using HashSet to handle ordering differences
    assert_eq!(
        enrichment_fields.into_iter().collect::<HashSet<Field>>(),
        expected_enrichment_fields
            .into_iter()
            .collect::<HashSet<Field>>()
    );
}

#[test]
fn test_peer_metadata_get_enrichment_fields_multiple_scopes_some_matching() {
    let global_scope = IndexedScope::new(0, vec![]);
    let mut global_fields_map = FxHashMap::default();
    global_fields_map.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(100, Field::samplerName("global_sampler".to_string().into())),
    );

    let specific_obs_id_scope = IndexedScope::new(1000, vec![]);
    let mut specific_obs_id_map = FxHashMap::default();
    specific_obs_id_map.insert(
        FieldRef::new(IE::dstTrafficIndex, 0),
        WeightedField::new(100, Field::dstTrafficIndex(33)),
    );

    let specific_obs_id_scope_nomatch = IndexedScope::new(20, vec![]);
    let mut specific_obs_id_nomatch_map = FxHashMap::default();
    specific_obs_id_nomatch_map.insert(
        FieldRef::new(IE::internalAddressRealm, 0),
        WeightedField::new(100, Field::internalAddressRealm(Box::new([13u8]))),
    );

    let specific_scope = IndexedScope::new(
        1000,
        vec![(
            FieldRef::new(IE::applicationId, 0),
            Field::applicationId(Box::new([244u8])),
        )],
    );
    let mut specific_fields_map = FxHashMap::default();
    specific_fields_map.insert(
        FieldRef::new(IE::udpExID, 0),
        WeightedField::new(100, Field::udpExID(29)),
    );

    let peer_metadata = PeerMetadata::from_vec(vec![
        (global_scope, global_fields_map),
        (specific_obs_id_scope, specific_obs_id_map),
        (specific_obs_id_scope_nomatch, specific_obs_id_nomatch_map),
        (specific_scope, specific_fields_map),
    ]);

    let incoming_fields = vec![
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2)),
        Field::octetDeltaCount(1500),
        Field::packetDeltaCount(1),
        Field::applicationId(Box::new([244u8])),
    ];

    let enrichment_fields = peer_metadata
        .get_enrichment_fields(1000, &incoming_fields)
        .unwrap_or_default();

    // Create expected enrichment fields
    let expected_enrichment_fields = vec![
        Field::samplerName("global_sampler".to_string().into()),
        Field::dstTrafficIndex(33),
        Field::udpExID(29),
    ];

    // Compare retrieved enrichment fields (ordering could change)
    assert_eq!(
        enrichment_fields.into_iter().collect::<HashSet<Field>>(),
        expected_enrichment_fields
            .into_iter()
            .collect::<HashSet<Field>>()
    );
}

#[test]
fn test_peer_metadata_get_enrichment_fields_weight_priority() {
    // Define globally scoped sampler
    let global_scope = IndexedScope::new(0, vec![]);
    let mut global_fields = FxHashMap::default();
    global_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(200, Field::samplerName("global_sampler".to_string().into())),
    );

    // Define specific_sampler scoped by obs ID 1000
    let specific_scope = IndexedScope::new(1000, vec![]);
    let mut specific_fields = FxHashMap::default();
    specific_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            150,
            Field::samplerName("specific_sampler".to_string().into()),
        ),
    );

    // Define more_specific_sampler scoped by obs ID 1000 and selectorId 1
    let more_specific_scope = IndexedScope::new(
        1000,
        vec![(FieldRef::new(IE::selectorId, 0), Field::selectorId(1))],
    );
    let mut more_specific_fields = FxHashMap::default();
    more_specific_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            100,
            Field::samplerName("more_specific_sampler".to_string().into()),
        ),
    );

    let peer_metadata = PeerMetadata::from_vec(vec![
        (global_scope.clone(), global_fields),
        (specific_scope.clone(), specific_fields),
        (more_specific_scope.clone(), more_specific_fields),
    ]);

    let incoming_fields = vec![
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::octetDeltaCount(1500),
        Field::packetDeltaCount(1),
        Field::selectorId(1),
    ];

    // Get enrichment fields and compare (global_sampler wins since has higher
    // weight)
    let enrichment_fields = peer_metadata.get_enrichment_fields(1000, &incoming_fields);
    let expected_enrichment_fields = Some(vec![Field::samplerName(
        "global_sampler".to_string().into(),
    )]);

    assert_eq!(enrichment_fields, expected_enrichment_fields);

    // Delete the global_sampler entry
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut cache = EnrichmentCache::from_vec(vec![(ip, peer_metadata)]);
    cache.delete(ip, (&global_scope).into(), 201); // weight 201 > 200 --> delete

    // Get enrichment fields and compare (specific_sampler wins since has higher
    // weight)
    let enrichment_fields = cache
        .get_or_create_peer_metadata(ip)
        .get_enrichment_fields(1000, &incoming_fields);
    let expected_enrichment_fields = Some(vec![Field::samplerName(
        "specific_sampler".to_string().into(),
    )]);
    assert_eq!(enrichment_fields, expected_enrichment_fields);

    // Delete the specific_sampler entry
    cache.delete(ip, (&specific_scope).into(), 151); // weight 151 > 150 --> delete

    // Get enrichment fields and compare (more_specific_sampler is now the only
    // matching scope left)
    let enrichment_fields = cache
        .get_or_create_peer_metadata(ip)
        .get_enrichment_fields(1000, &incoming_fields);
    let expected_enrichment_fields = Some(vec![Field::samplerName(
        "more_specific_sampler".to_string().into(),
    )]);
    assert_eq!(enrichment_fields, expected_enrichment_fields);
}

#[test]
fn test_peer_metadata_get_enrichment_fields_same_weight_specificity_tiebreaker() {
    // Define globally scoped fields with weight 100
    let global_scope = IndexedScope::new(0, vec![]);
    let mut global_fields = FxHashMap::default();
    global_fields.insert(
        FieldRef::new(IE::applicationName, 0),
        WeightedField::new(100, Field::applicationName("global_app".to_string().into())),
    );
    global_fields.insert(
        FieldRef::new(IE::observationPointId, 0),
        WeightedField::new(100, Field::observationPointId(1)),
    );

    // Define specific_sampler scoped by obs ID 1000 with weight 100
    let specific_scope = IndexedScope::new(1000, vec![]);
    let mut specific_fields = FxHashMap::default();
    specific_fields.insert(
        FieldRef::new(IE::applicationName, 0),
        WeightedField::new(
            100,
            Field::applicationName("specific_app".to_string().into()),
        ),
    );
    specific_fields.insert(
        FieldRef::new(IE::meteringProcessId, 0),
        WeightedField::new(100, Field::meteringProcessId(2000)),
    );

    // Define more_specific_sampler scoped by obs ID 1000 and selectorId 5 with
    // weight 100
    let more_specific_scope = IndexedScope::new(
        1000,
        vec![(FieldRef::new(IE::selectorId, 0), Field::selectorId(5))],
    );
    let mut more_specific_fields = FxHashMap::default();
    more_specific_fields.insert(
        FieldRef::new(IE::applicationName, 0),
        WeightedField::new(
            100,
            Field::applicationName("more_specific_app".to_string().into()),
        ),
    );
    more_specific_fields.insert(
        FieldRef::new(IE::observationDomainName, 0),
        WeightedField::new(
            100,
            Field::observationDomainName("specific_domain".to_string().into()),
        ),
    );

    let peer_metadata = PeerMetadata::from_vec(vec![
        (global_scope, global_fields),
        (specific_scope, specific_fields),
        (more_specific_scope, more_specific_fields),
    ]);

    let incoming_fields = vec![
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::octetDeltaCount(1500),
        Field::packetDeltaCount(1),
        Field::selectorId(5), // Matches more_specific_scope
    ];

    // Get enrichment fields - should prefer more specific scope as tie-breaker
    let enrichment_fields = peer_metadata
        .get_enrichment_fields(1000, &incoming_fields)
        .unwrap_or_default();

    // Create expected enrichment fields from all matching scopes
    let expected_enrichment_fields = vec![
        Field::applicationName("more_specific_app".to_string().into()), /* From more_specific_scope (wins tie) */
        Field::observationPointId(1),                                   /* From global_scope
                                                                         * (unique field) */
        Field::meteringProcessId(2000), // From specific_scope (unique field)
        Field::observationDomainName("specific_domain".to_string().into()), /* From more_specific_scope (unique field) */
    ];

    // Compare retrieved enrichment fields (ordering could change)
    assert_eq!(
        enrichment_fields.into_iter().collect::<HashSet<Field>>(),
        expected_enrichment_fields
            .into_iter()
            .collect::<HashSet<Field>>()
    );
}

#[test]
fn test_peer_metadata_get_enrichment_fields_no_matches() {
    let scope = IndexedScope::new(
        1000,
        vec![(FieldRef::new(IE::selectorId, 0), Field::selectorId(42))],
    );

    let mut fields_map = FxHashMap::default();
    fields_map.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(100, Field::samplerName("test_sampler".to_string().into())),
    );

    let peer_metadata = PeerMetadata::from_vec(vec![(scope, fields_map)]);

    let incoming_fields = vec![
        Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
        Field::selectorId(99), // Different value, won't match
    ];

    let enrichment_fields = peer_metadata.get_enrichment_fields(1000, &incoming_fields);

    assert_eq!(enrichment_fields, None);
}

#[test]
fn test_indexed_scope_from_scope_conversion() {
    let scope_fields = vec![Field::selectorId(42), Field::samplingAlgorithm(1)];
    let scope = Scope::new(1000, Some(scope_fields.clone()));

    let indexed_scope: IndexedScope = scope.clone().into();
    let converted_back: Scope = (&indexed_scope).into();

    assert_eq!(converted_back, scope);
}

#[test]
fn test_indexed_scope_empty_scope_fields() {
    let scope = Scope::new(500, None);

    let indexed_scope: IndexedScope = scope.clone().into();
    let converted_back: Scope = (&indexed_scope).into();

    assert_eq!(converted_back, scope);
}

#[test]
fn test_enrichment_cache_get_enrichment_fields() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let scope = Scope::new(0, None);
    let weight: Weight = 100;
    let fields = vec![Field::observationPointId(42)];

    cache.upsert(ip, scope, weight, fields);

    let incoming_fields = vec![Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))];
    let result = cache.get_enrichment_fields(&ip, 1000, &incoming_fields);

    let expected_result = Some(vec![Field::observationPointId(42)]);
    assert_eq!(result, expected_result);
}

#[test]
fn test_enrichment_cache_get_enrichment_fields_not_found() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let scope = Scope::new(150, None);
    let weight: Weight = 100;
    let fields = vec![Field::observationPointId(42)];

    cache.upsert(ip, scope, weight, fields);

    let incoming_fields = vec![Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))];

    let result = cache.get_enrichment_fields(&ip, 1000, &incoming_fields);

    assert_eq!(result, None);
}
