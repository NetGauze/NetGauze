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

//! Flow enrichment cache module for managing peer metadata and field
//! enrichment.
//!
//! This module provides the core caching infrastructure for flow enrichment:
//! - `EnrichmentCache` - Main cache storing peer metadata indexed by IP address
//! - `PeerMetadata` - Hierarchical metadata storage with scope-based field
//!   organization
//! - `IndexedScope` - Optimized scope representation for fast matching
//!   operations
//! - `WeightedField` - Field wrapper with priority weighting for conflict
//!   resolution
//!
//! The cache supports hierarchical scoping from global to more specific
//! contexts, with weight-based field precedence handling. It efficiently
//! matches incoming flow records against cached metadata to provide contextual
//! enrichment fields.
//!
//! ## Scope Matching
//!
//! Scopes are matched hierarchically using:
//! - **Observation Domain ID** - Must match if non-zero in scope
//! - **Scope Fields** - All scope fields must exactly match incoming data
//!
//! ## Weight Resolution
//!
//! When multiple scopes provide the same field type:
//! - Higher weight fields override lower weight fields
//! - Equal weights prefer more specific (later processed) scopes

use crate::flow::{
    enrichment::{EnrichmentOperation, Scope, Weight},
    types::FieldRef,
};
use netgauze_flow_pkt::ie::Field;
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map, hash_map, BTreeMap},
    net::IpAddr,
};
use tracing::debug;

mod debug_utils;

/// Main enrichment cache storing peer metadata indexed by IP address.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EnrichmentCache(FxHashMap<IpAddr, PeerMetadata>);

impl EnrichmentCache {
    pub(crate) fn new() -> Self {
        Self(FxHashMap::with_hasher(FxBuildHasher))
    }

    #[cfg(test)]
    pub(crate) fn from_vec(vec: Vec<(IpAddr, PeerMetadata)>) -> Self {
        let mut cache = Self::new();
        for (ip, metadata) in vec {
            cache.0.insert(ip, metadata);
        }
        cache
    }

    pub(crate) fn get(&self, ip: &IpAddr) -> Option<&PeerMetadata> {
        self.0.get(ip)
    }

    pub(crate) fn get_mut(&mut self, ip: &IpAddr) -> Option<&mut PeerMetadata> {
        self.0.get_mut(ip)
    }

    /// Get the number of peer IPs with cached metadata entries.
    pub(crate) fn peer_count(&self) -> usize {
        self.0.len()
    }

    /// Get or create peer metadata for the given IP address.
    ///
    /// Returns a mutable reference to the peer metadata, creating a new entry
    /// with an empty BTreeMap if one doesn't already exist.
    pub(crate) fn get_or_create_peer_metadata(&mut self, ip: IpAddr) -> &mut PeerMetadata {
        self.0.entry(ip).or_insert_with(|| {
            debug!("Creating new peer metadata cache entry for ip={}", ip);
            PeerMetadata::new()
        })
    }

    // Remove peer metadata from the cache for the given IP address.
    pub(crate) fn remove(&mut self, ip: &IpAddr) -> Option<PeerMetadata> {
        debug!("Deleting peer metadata cache entry for ip={}", ip);
        self.0.remove(ip)
    }

    /// Get enrichment fields for the given peer IP, observation ID and incoming
    /// fields.
    pub(crate) fn get_enrichment_fields(
        &self,
        peer_ip: &IpAddr,
        obs_domain_id: u32,
        record_fields: &[Field],
    ) -> Option<Vec<Field>> {
        self.get(peer_ip).and_then(|peer_metadata| {
            peer_metadata.get_enrichment_fields(obs_domain_id, record_fields)
        })
    }

    /// Apply an enrichment operation (upsert or delete) to the cache.
    pub(crate) fn apply_enrichment(&mut self, op: EnrichmentOperation) {
        match op {
            EnrichmentOperation::Upsert(ip, scope, weight, incoming_fields) => {
                debug!(
                    "Applying upsert operation for ip={}, scope={}, weight={}, incoming_fields={:?}",
                    ip, scope, weight, incoming_fields
                );
                self.upsert(ip, scope, weight, incoming_fields);
            }
            EnrichmentOperation::Delete(ip, scope, weight) => {
                debug!(
                    "Applying delete operation for ip={}, scope={}, weight={}",
                    ip, scope, weight
                );
                self.delete(ip, scope, weight);
            }
        }
    }

    /// Insert or update metadata for a peer IP with the given scope, weight,
    /// and fields.
    ///
    /// For existing entries, fields are compared by weight - higher weight
    /// fields replace lower weight ones. Equal weights favor the incoming
    /// field.
    fn upsert(&mut self, ip: IpAddr, scope: Scope, weight: Weight, incoming_fields: Vec<Field>) {
        let peer_metadata = self.get_or_create_peer_metadata(ip);

        // Index incoming fields with FieldRef and create WeightedField entries
        let indexed_incoming: FxHashMap<FieldRef, WeightedField> =
            FieldRef::map_fields_into_fxhashmap_owned(&incoming_fields)
                .into_iter()
                .map(|(field_ref, field)| (field_ref, WeightedField::new(weight, field)))
                .collect();

        match peer_metadata.map.entry(scope.clone().into()) {
            btree_map::Entry::Occupied(mut entry) => {
                let curr_fields = entry.get_mut();

                for (field_ref, weighted_field) in indexed_incoming {
                    // Check if field with same IE already exists
                    match curr_fields.entry(field_ref) {
                        hash_map::Entry::Occupied(mut occupied) => {
                            let curr_weight = occupied.get().weight;
                            if weight >= curr_weight {
                                debug!("Replacing field[{}] in metadata for ip={}, scope={}, weight {}->{}",
                                            field_ref.ie(),
                                            ip,
                                            scope,
                                            curr_weight,
                                            weight,
                                        );
                                occupied.insert(weighted_field);
                            } else {
                                debug!("Ignoring lower weight field[{}] in metadata for ip={}, scope={}, weight: {}<{}",
                                            field_ref.ie(),
                                            ip,
                                            scope,
                                            curr_weight,
                                            weight,
                                    );
                            }
                        }
                        hash_map::Entry::Vacant(vacant) => {
                            debug!(
                                "Adding new field[{}] in metadata for ip={}, scope={}, weight={}",
                                field_ref.ie(),
                                ip,
                                scope,
                                weight
                            );
                            vacant.insert(weighted_field);
                        }
                    }
                }
            }
            btree_map::Entry::Vacant(entry) => {
                debug!(
                    "Adding new metadata for ip={}, scope={}, weight={}",
                    ip, scope, weight,
                );

                entry.insert(indexed_incoming);
            }
        }

        debug!("Updated cache for {ip}: \n{}", peer_metadata)
    }

    /// Remove metadata entries matching the given scope and weight criteria.
    ///
    /// Removes all fields with weight less than the specified weight within
    /// the matching scope. Cleans up empty scopes and peer entries
    /// automatically.
    fn delete(&mut self, ip: IpAddr, scope: Scope, weight: Weight) {
        if let Some(peer_metadata) = self.get_mut(&ip) {
            match peer_metadata.map.entry(scope.clone().into()) {
                btree_map::Entry::Occupied(mut occupied) => {
                    let current_fields = occupied.get_mut();

                    current_fields.retain(|_ie, m_fld| {
                        if m_fld.weight < weight {
                            debug!(
                                "Removing field [{:?}] for ip={}, scope={}, weight: {}>{}",
                                m_fld.field, ip, scope, weight, m_fld.weight
                            );
                            false
                        } else {
                            true
                        }
                    });

                    if current_fields.is_empty() {
                        occupied.remove();
                        debug!(
                            "Scope {:?} now empty for ip={}, removing scope entry...",
                            scope, ip
                        );

                        if peer_metadata.map.is_empty() {
                            debug!("Cache now empty for ip={}, cleaning up...", ip);
                            self.remove(&ip);
                        } else {
                            debug!("Updated cache for {ip}: \n{}", peer_metadata)
                        }
                    }
                }
                btree_map::Entry::Vacant(_) => {
                    debug!(
                        "No entry matching ip={} and scope={}, nothing to delete",
                        ip, scope
                    );
                }
            }
        } else {
            debug!("No cache entry for ip={}, nothing to delete", ip);
        }
    }
}

/// Hierarchical metadata storage for a single peer, organized by scope.
///
/// Metadata is stored in a BTreeMap keyed by IndexedScope to ensure
/// consistent ordering from global to specific scopes during lookups.
/// Each scope contains a map of fields indexed by FieldRef for efficient
/// access.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PeerMetadata {
    map: BTreeMap<IndexedScope, FxHashMap<FieldRef, WeightedField>>,
}
impl PeerMetadata {
    pub(crate) fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_vec(vec: Vec<(IndexedScope, FxHashMap<FieldRef, WeightedField>)>) -> Self {
        let mut metadata = Self::new();
        for (scope, fields) in vec {
            metadata.map.insert(scope, fields);
        }
        metadata
    }

    pub(crate) fn map(&self) -> &BTreeMap<IndexedScope, FxHashMap<FieldRef, WeightedField>> {
        &self.map
    }

    /// Check if a scope matches the incoming observation domain ID and fields.
    ///
    /// A scope matches if:
    /// - The observation domain ID matches (or scope has ID 0 for
    ///   global/system)
    /// - All scope fields exactly match corresponding incoming fields
    #[inline]
    fn scope_matches(
        scope: &IndexedScope,
        incoming_obs_id: u32,
        incoming_fields: &FxHashMap<FieldRef, &Field>,
    ) -> bool {
        if scope.obs_domain_id != 0 && scope.obs_domain_id != incoming_obs_id {
            return false;
        }

        scope.scope_fields.iter().all(|(field_ref, field)| {
            incoming_fields
                .get(field_ref)
                .is_some_and(|incoming| field == *incoming)
        })
    }

    /// Extract enrichment fields for the given observation ID and incoming
    /// fields.
    ///
    /// Iterates through all scopes in order (global to specific) and collects
    /// matching fields. For duplicate field types across scopes, returns the
    /// highest weight field, with equal weights favoring more specific scopes.
    ///
    /// As an example, consider the following PeerMetadata entries:
    /// - Scope {obs_domain_id: 0, scope_fields: []} ->
    ///   \[samplerName("global_sampler")\], weight 64
    /// - Scope {obs_domain_id: 2000, scope_fields: \[selectorId(1)\]} -> ->
    ///   \[samplerName("specific_sampler")\], weight 16
    ///
    /// Given inputs incoming_obs_id: 2000, and incoming_fields: \[bytes(600),
    /// selectorId(1)\] => the return will be \[samplerName("global_sampler")\]
    /// even though a more specific scope would exist, due to the higher weight.
    pub(crate) fn get_enrichment_fields(
        &self,
        incoming_obs_id: u32,
        incoming_fields: &[Field],
    ) -> Option<Vec<Field>> {
        debug!(
            "Getting enrichment fields for obs_id={}, incoming_fields={:?}",
            incoming_obs_id, incoming_fields
        );

        if self.map.is_empty() {
            debug!("No scopes available for enrichment");
            return None;
        }

        // Store incoming fields indexed by FieldRef (IE, index)
        let fields_map = FieldRef::map_fields_into_fxhashmap(incoming_fields);

        // Map to temporarily store enrichment fields
        // (needed due to possible weight based field overwrites)
        let mut enrichment_fields: FxHashMap<FieldRef, &WeightedField> =
            FxHashMap::with_capacity_and_hasher(16, FxBuildHasher);

        // Iterating from global to more specific scopes (thanks to BTreeMap)
        for (scope, metadata) in self.map() {
            if Self::scope_matches(scope, incoming_obs_id, &fields_map) {
                debug!(
                    "Scope {} matches incoming data!",
                    Into::<Scope>::into(scope)
                );

                for (field_ref, field) in metadata {
                    match enrichment_fields.entry(*field_ref) {
                        hash_map::Entry::Occupied(mut best) => {
                            let curr_weight = best.get().weight();
                            if field.weight >= curr_weight {
                                debug!(
                                    "Overriding field {:?} with higher/equal weight: {} >= {}",
                                    field.field(),
                                    field.weight(),
                                    curr_weight,
                                );
                                best.insert(field);
                            }
                        }
                        hash_map::Entry::Vacant(best) => {
                            debug!(
                                "Selecting field {:?} with weight: {}",
                                field.field(),
                                field.weight(),
                            );
                            best.insert(field);
                        }
                    }
                }
            }
        }

        if enrichment_fields.is_empty() {
            debug!("No matching fields found for enrichment");
            return None;
        } else {
            debug!(
                "Enrichment fields retrieved based on scope matches:\n{}",
                debug_utils::format_fields_table(&enrichment_fields)
            );
        }

        Some(
            enrichment_fields
                .values()
                .map(|weighted_field| weighted_field.field().clone())
                .collect::<Vec<_>>(),
        )
    }
}

/// Optimized scope representation with indexed scope fields for fast matching.
///
/// Converts scope fields into a sorted slice of (FieldRef, Field) pairs
/// for efficient comparison during scope matching operations.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IndexedScope {
    obs_domain_id: u32,
    scope_fields: Box<[(FieldRef, Field)]>,
}

impl IndexedScope {
    #[cfg(test)]
    pub(crate) fn new(obs_domain_id: u32, scope_fields: Vec<(FieldRef, Field)>) -> Self {
        Self {
            obs_domain_id,
            scope_fields: scope_fields.into_boxed_slice(),
        }
    }
}

impl From<Scope> for IndexedScope {
    fn from(scope: Scope) -> Self {
        let scope_fields = scope
            .scope_fields()
            .as_ref()
            .map(|fields| FieldRef::map_fields_into_boxed_slice_owned(fields))
            .unwrap_or_default();

        Self {
            obs_domain_id: scope.obs_domain_id(),
            scope_fields,
        }
    }
}

impl From<&IndexedScope> for Scope {
    fn from(scope_key: &IndexedScope) -> Self {
        let scope_fields = if scope_key.scope_fields.is_empty() {
            None
        } else {
            Some(
                scope_key
                    .scope_fields
                    .iter()
                    .map(|(_, field)| field.clone())
                    .collect(),
            )
        };

        Scope::new(scope_key.obs_domain_id, scope_fields)
    }
}

/// Field wrapper that includes priority weight for conflict resolution.
///
/// Used to store enrichment fields with their associated weights,
/// enabling the cache to resolve conflicts when multiple sources
/// provide the same field type.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct WeightedField {
    weight: Weight,
    field: Field,
}
impl WeightedField {
    pub(crate) fn new(weight: Weight, field: Field) -> Self {
        Self { weight, field }
    }
    pub(crate) fn weight(&self) -> Weight {
        self.weight
    }
    pub(crate) fn field(&self) -> &Field {
        &self.field
    }
}

#[cfg(test)]
mod tests;
