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

use crate::flow::enrichment::cache::*;
use crate::flow::enrichment::{EnrichmentOperation, Scope, Weight};
use netgauze_flow_pkt::ie::{Field, IE};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    cache.upsert(ip, scope.clone(), weight, Some(fields.clone()));

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

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .global
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

    // Compare cache after upsert with expected
    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_upsert_empty_fields() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(0, None);

    // Upsert with empty fields vector should not modify cache
    cache.upsert(ip, scope.clone(), 100, Some(vec![]));

    assert_eq!(cache.peer_count(), 0);
    assert!(cache.get(&ip).is_none());
}

#[test]
fn test_enrichment_cache_upsert_none_fields() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(0, None);

    // Upsert with None fields should not modify cache
    cache.upsert(ip, scope, 100, None);

    assert_eq!(cache.peer_count(), 0);
}

#[test]
fn test_enrichment_cache_upsert_weight_replacement() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(1000, None);

    // Insert field with low weight
    let low_weight: Weight = 50;
    let fields1 = vec![Field::samplerName("low_priority".to_string().into())];
    cache.upsert(ip, scope.clone(), low_weight, Some(fields1));

    // Insert field with higher weight - should replace
    let high_weight: Weight = 150;
    let fields2 = vec![Field::samplerName("high_priority".to_string().into())];
    cache.upsert(ip, scope.clone(), high_weight, Some(fields2));

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            high_weight,
            Field::samplerName("high_priority".to_string().into()),
        ),
    );

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(1000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

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
    cache.upsert(ip, scope.clone(), high_weight, Some(fields1));

    // Try to insert field with lower weight - should be ignored
    let low_weight: Weight = 100;
    let fields2 = vec![Field::samplerName("low_priority".to_string().into())];
    cache.upsert(ip, scope.clone(), low_weight, Some(fields2));

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            high_weight,
            Field::samplerName("high_priority".to_string().into()),
        ),
    );

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(2000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

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
    cache.upsert(ip, scope.clone(), weight, Some(fields1));

    // Insert second field with equal weight - should replace
    let fields2 = vec![Field::samplerName("second".to_string().into())];
    cache.upsert(ip, scope.clone(), weight, Some(fields2));

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(weight, Field::samplerName("second".to_string().into())),
    );

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(3000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_delete_empty_ies() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(0, None);

    cache.upsert(
        ip,
        scope.clone(),
        100,
        Some(vec![Field::observationPointId(42)]),
    );

    // Delete with empty IEs vector should not modify cache
    cache.delete(ip, scope, 100, Some(vec![]));

    assert!(cache.get(&ip).is_some());
}

#[test]
fn test_enrichment_cache_delete_partial_field_match() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(0, None);

    // Insert multiple fields with same weight
    cache.upsert(
        ip,
        scope.clone(),
        100,
        Some(vec![
            Field::samplerName("test".to_string().into()),
            Field::observationPointId(42),
            Field::meteringProcessId(100),
        ]),
    );

    // Delete only some fields by IE
    cache.delete(
        ip,
        scope.clone(),
        100,
        Some(vec![IE::samplerName, IE::observationPointId]),
    );

    // meteringProcessId should remain
    let peer = cache.get(&ip).unwrap();
    let enrichment = peer.get_enrichment_fields(0, &[]);
    assert_eq!(enrichment, Some(vec![Field::meteringProcessId(100)]));
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
    cache.upsert(ip, scope.clone(), 50, Some(fields));

    let fields2 = vec![Field::meteringProcessId(42)];
    cache.upsert(ip, scope.clone(), 150, Some(fields2));

    let fields3 = vec![Field::observationDomainName("OBS_NAME".to_string().into())];
    cache.upsert(ip, scope.clone(), 80, Some(fields3));

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

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(4000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

    assert_eq!(cache, expected_cache);

    // Delete fields with weight < 100
    cache.delete(ip, scope.clone(), 100, None);

    // Create expected cache after delete
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::meteringProcessId, 0),
        WeightedField::new(150, Field::meteringProcessId(42)),
    );

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(4000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_delete_empty_scope_cleanup() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(5000, None);

    // Insert field with low weight
    let fields = vec![Field::samplerName("test".to_string().into())];
    cache.upsert(ip, scope.clone(), 50, Some(fields));

    // Create expected cache
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(50, Field::samplerName("test".to_string().into())),
    );

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(5000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

    assert_eq!(cache, expected_cache);

    // Delete with higher weight - should remove all fields and cleanup scope
    cache.delete(ip, scope.clone(), 100, None);

    // Create expected cache after delete (empty)
    let expected_cache: EnrichmentCache = vec![].into();

    assert_eq!(cache, expected_cache);
}

#[test]
fn test_enrichment_cache_delete_nonexistent() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let scope = Scope::new(6000, None);

    // Delete from empty cache should not panic
    cache.delete(ip, scope, 100, None);
    let expected_cache: EnrichmentCache = vec![].into();
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
    let upsert_op = EnrichmentOperation::Upsert(UpsertPayload {
        ip,
        scope: scope.clone(),
        weight,
        fields: fields.clone(),
    });
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

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(7000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();
    assert_eq!(cache, expected_cache);

    // Apply delete operation
    let delete_op = EnrichmentOperation::DeleteAll(DeleteAllPayload {
        ip,
        scope,
        weight: 200,
    });
    cache.apply_enrichment(delete_op);

    // Create expected cache after delete operation (empty)
    let expected_cache: EnrichmentCache = vec![].into();
    assert_eq!(cache, expected_cache);
}

#[test]
fn test_peer_metadata_empty_metadata() {
    let peer_metadata = PeerMetadata::new();
    let incoming_fields = vec![Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))];

    let result = peer_metadata.get_enrichment_fields(1000, &incoming_fields);
    assert_eq!(result, None);
}

#[test]
fn test_peer_metadata_scope_matches_with_scope_fields() {
    let scope_fields = IndexedScopeFields::new(vec![
        (FieldRef::new(IE::selectorId, 0), Field::selectorId(42)),
        (
            FieldRef::new(IE::samplingAlgorithm, 0),
            Field::samplingAlgorithm(1),
        ),
    ]);

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
    let missing_fields = FieldRef::map_fields_into_fxhashmap(&fields);

    // Should match when all scope fields are present and have matching values
    assert!(scope_fields.matches(&matching_fields));

    // Should not match when field values differ
    assert!(!scope_fields.matches(&non_matching_fields));

    // Should not match when required scope fields are missing
    assert!(!scope_fields.matches(&missing_fields));
}

#[test]
fn test_peer_metadata_get_enrichment_fields_simple() {
    let mut fields_map = FxHashMap::default();
    fields_map.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(100, Field::samplerName("global_sampler".to_string().into())),
    );

    // Peer Metadata with globally scoped metadata fields only
    let mut peer_metadata = PeerMetadata::new();
    peer_metadata
        .global
        .insert(IndexedScopeFields::new(vec![]), fields_map);

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
    // Globally scoped fields (obs_domain_id = 0)
    let mut global_fields = FxHashMap::default();
    global_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(50, Field::samplerName("global_sampler".to_string().into())),
    );

    // Domain-specific scoped fields (obs_domain_id = 1000)
    let mut specific_fields = FxHashMap::default();
    specific_fields.insert(
        FieldRef::new(IE::observationPointId, 0),
        WeightedField::new(100, Field::observationPointId(123)),
    );

    let mut peer_metadata = PeerMetadata::new();
    peer_metadata
        .global
        .insert(IndexedScopeFields::new(vec![]), global_fields);
    peer_metadata
        .domain_scoped
        .entry(1000)
        .or_default()
        .insert(IndexedScopeFields::new(vec![]), specific_fields);

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
    // Globally scoped fields (obs_domain_id = 0, no scope fields)
    let mut global_fields_map = FxHashMap::default();
    global_fields_map.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(100, Field::samplerName("global_sampler".to_string().into())),
    );

    // Domain-specific scoped fields (obs_domain_id = 1000, no scope fields)
    let mut specific_obs_id_map = FxHashMap::default();
    specific_obs_id_map.insert(
        FieldRef::new(IE::dstTrafficIndex, 0),
        WeightedField::new(100, Field::dstTrafficIndex(33)),
    );

    // Domain-specific scoped fields (obs_domain_id = 1000, applicationId = 244)
    let mut specific_fields_map = FxHashMap::default();
    specific_fields_map.insert(
        FieldRef::new(IE::udpExID, 0),
        WeightedField::new(100, Field::udpExID(29)),
    );

    // Domain-specific scoped fields that won't match (obs_domain_id = 20, no scope
    // fields)
    let mut specific_obs_id_nomatch_map = FxHashMap::default();
    specific_obs_id_nomatch_map.insert(
        FieldRef::new(IE::internalAddressRealm, 0),
        WeightedField::new(100, Field::internalAddressRealm(Box::new([13u8]))),
    );

    let mut peer_metadata = PeerMetadata::new();
    peer_metadata
        .global
        .insert(IndexedScopeFields::new(vec![]), global_fields_map);
    peer_metadata
        .domain_scoped
        .entry(1000)
        .or_default()
        .insert(IndexedScopeFields::new(vec![]), specific_obs_id_map);
    peer_metadata.domain_scoped.entry(1000).or_default().insert(
        IndexedScopeFields::new(vec![(
            FieldRef::new(IE::applicationId, 0),
            Field::applicationId(Box::new([244u8])),
        )]),
        specific_fields_map,
    );
    peer_metadata
        .domain_scoped
        .entry(20)
        .or_default()
        .insert(IndexedScopeFields::new(vec![]), specific_obs_id_nomatch_map);

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
    // Global scope (obs_domain_id = 0)
    let mut global_fields = FxHashMap::default();
    global_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(200, Field::samplerName("global_sampler".to_string().into())),
    );

    // Domain-specific scope (obs_domain_id = 1000, no scope fields)
    let mut specific_fields = FxHashMap::default();
    specific_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            150,
            Field::samplerName("specific_sampler".to_string().into()),
        ),
    );

    // Domain-specific scope with scope fields (obs_domain_id = 1000, selectorId =
    // 1)
    let mut more_specific_fields = FxHashMap::default();
    more_specific_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(
            100,
            Field::samplerName("more_specific_sampler".to_string().into()),
        ),
    );

    let mut peer_metadata = PeerMetadata::new();
    peer_metadata
        .global
        .insert(IndexedScopeFields::new(vec![]).clone(), global_fields);
    peer_metadata
        .domain_scoped
        .entry(1000)
        .or_default()
        .insert(IndexedScopeFields::new(vec![]).clone(), specific_fields);
    peer_metadata.domain_scoped.entry(1000).or_default().insert(
        IndexedScopeFields::new(vec![(
            FieldRef::new(IE::selectorId, 0),
            Field::selectorId(1),
        )]),
        more_specific_fields,
    );

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
    let mut cache: EnrichmentCache = vec![(ip, peer_metadata)].into();
    let global_scope = Scope::new(0, None);
    cache.delete(ip, global_scope, 201, None); // weight 201 > 200 --> delete

    // Get enrichment fields and compare (specific_sampler wins since has higher
    // weight)
    let enrichment_fields = cache
        .get(&ip)
        .unwrap()
        .get_enrichment_fields(1000, &incoming_fields);
    let expected_enrichment_fields = Some(vec![Field::samplerName(
        "specific_sampler".to_string().into(),
    )]);
    assert_eq!(enrichment_fields, expected_enrichment_fields);

    // Delete the specific_sampler entry
    let specific_scope = Scope::new(1000, None);
    cache.delete(ip, specific_scope, 151, None); // weight 151 > 150 --> delete

    // Get enrichment fields and compare (more_specific_sampler is now the only
    // matching scope left)
    let enrichment_fields = cache
        .get(&ip)
        .unwrap()
        .get_enrichment_fields(1000, &incoming_fields);
    let expected_enrichment_fields = Some(vec![Field::samplerName(
        "more_specific_sampler".to_string().into(),
    )]);
    assert_eq!(enrichment_fields, expected_enrichment_fields);
}

#[test]
fn test_peer_metadata_get_enrichment_fields_same_weight_specificity_tiebreaker() {
    // Global scope (obs_domain_id = 0)
    let mut global_fields = FxHashMap::default();
    global_fields.insert(
        FieldRef::new(IE::applicationName, 0),
        WeightedField::new(100, Field::applicationName("global_app".to_string().into())),
    );
    global_fields.insert(
        FieldRef::new(IE::observationPointId, 0),
        WeightedField::new(100, Field::observationPointId(1)),
    );

    // Domain-specific scope (obs_domain_id = 1000, no scope fields)
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

    // Domain-specific scope with scope fields (obs_domain_id = 1000, selectorId =
    // 5)
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

    let mut peer_metadata = PeerMetadata::new();
    peer_metadata
        .global
        .insert(IndexedScopeFields::new(vec![]), global_fields);
    peer_metadata
        .domain_scoped
        .entry(1000)
        .or_default()
        .insert(IndexedScopeFields::new(vec![]), specific_fields);
    peer_metadata.domain_scoped.entry(1000).or_default().insert(
        IndexedScopeFields::new(vec![(
            FieldRef::new(IE::selectorId, 0),
            Field::selectorId(5),
        )]),
        more_specific_fields,
    );

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
    let mut fields_map = FxHashMap::default();
    fields_map.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(100, Field::samplerName("test_sampler".to_string().into())),
    );

    let mut peer_metadata = PeerMetadata::new();
    peer_metadata.domain_scoped.entry(1000).or_default().insert(
        IndexedScopeFields::new(vec![(
            FieldRef::new(IE::selectorId, 0),
            Field::selectorId(42),
        )]),
        fields_map,
    );

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

    let indexed_scope_fields: IndexedScopeFields = (&scope).into();

    let expected_indexed_scope_fields = IndexedScopeFields::new(vec![
        (FieldRef::new(IE::selectorId, 0), Field::selectorId(42)),
        (
            FieldRef::new(IE::samplingAlgorithm, 0),
            Field::samplingAlgorithm(1),
        ),
    ]);

    assert_eq!(expected_indexed_scope_fields, indexed_scope_fields);
}

#[test]
fn test_indexed_scope_empty_scope_fields() {
    let scope = Scope::new(500, None);

    let indexed_scope_fields: IndexedScopeFields = (&scope).into();

    assert!(indexed_scope_fields.is_empty());
}

#[test]
fn test_enrichment_cache_get_enrichment_fields() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let scope = Scope::new(0, None);
    let weight: Weight = 100;
    let fields = vec![Field::observationPointId(42)];

    cache.upsert(ip, scope, weight, Some(fields));

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

    cache.upsert(ip, scope, weight, Some(fields));

    let incoming_fields = vec![Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))];

    let result = cache.get_enrichment_fields(&ip, 1000, &incoming_fields);

    assert_eq!(result, None);
}

#[test]
fn test_enrichment_cache_delete_specific_fields_weight_check() {
    let mut cache = EnrichmentCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let scope = Scope::new(9000, None);

    // Insert fields with different weights
    cache.upsert(
        ip,
        scope.clone(),
        200,
        Some(vec![Field::samplerName("high_priority".to_string().into())]),
    );
    cache.upsert(
        ip,
        scope.clone(),
        80,
        Some(vec![Field::meteringProcessId(50)]),
    );

    // Try to delete specific fields (some with insufficient weight 150 < 200)
    let fields_to_delete = vec![IE::samplerName, IE::meteringProcessId];
    cache.delete(ip, scope.clone(), 150, Some(fields_to_delete));

    // Create expected cache after delete (only low-weight field removed)
    let mut expected_fields = FxHashMap::default();
    expected_fields.insert(
        FieldRef::new(IE::samplerName, 0),
        WeightedField::new(200, Field::samplerName("high_priority".to_string().into())),
    );

    let mut expected_peer_metadata = PeerMetadata::new();
    expected_peer_metadata
        .domain_scoped
        .entry(9000)
        .or_default()
        .insert(IndexedScopeFields::from(&scope), expected_fields);
    let expected_cache: EnrichmentCache = vec![(ip, expected_peer_metadata)].into();

    assert_eq!(cache, expected_cache);
}
