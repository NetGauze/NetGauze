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
    enrichment::{DeletePayload, EnrichmentOperation, Scope, UpsertPayload, Weight},
    types::FieldRef,
};
use netgauze_flow_pkt::ie::{Field, IE};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map, hash_map, BTreeMap},
    net::IpAddr,
};
use tracing::debug;

/// Main enrichment cache storing peer metadata indexed by IP address.
#[derive(Debug, Eq, PartialEq)]
pub struct EnrichmentCache(FxHashMap<IpAddr, PeerMetadata>);

impl EnrichmentCache {
    pub fn new() -> Self {
        Self(FxHashMap::with_hasher(FxBuildHasher))
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&PeerMetadata> {
        self.0.get(ip)
    }

    pub fn get_mut(&mut self, ip: &IpAddr) -> Option<&mut PeerMetadata> {
        self.0.get_mut(ip)
    }

    /// Get the number of peer IPs with cached metadata entries.
    pub fn peer_count(&self) -> usize {
        self.0.len()
    }

    /// Get enrichment fields for the given peer IP, observation ID and incoming
    /// fields.
    pub fn get_enrichment_fields(
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
    pub fn apply_enrichment(&mut self, op: EnrichmentOperation) {
        debug!("Apply enrichment operation: {op}");

        match op {
            EnrichmentOperation::Upsert(UpsertPayload {
                ip,
                scope,
                weight,
                fields,
            }) => {
                self.upsert(ip, scope, weight, fields);
            }
            EnrichmentOperation::Delete(DeletePayload {
                ip,
                scope,
                weight,
                ies,
            }) => {
                self.delete(ip, scope, weight, ies);
            }
        }
    }

    /// Insert or update metadata for a peer IP with the given scope, weight,
    /// and fields.
    ///
    /// For existing entries, fields are compared by weight - higher weight
    /// fields replace lower weight ones. Equal weights favor the incoming
    /// field.
    fn upsert(
        &mut self,
        ip: IpAddr,
        scope: Scope,
        weight: Weight,
        incoming_fields: Option<Vec<Field>>,
    ) {
        // Early returns if no fields are provided
        let incoming_fields = match incoming_fields {
            None => {
                debug!("No fields provided for upsert operation for ip={}, scope={} - cache not modified", ip, scope);
                return;
            }
            Some(fields) if fields.is_empty() => {
                debug!("Empty fields vector provided for upsert operation for ip={}, scope={} - cache not modified", ip, scope);
                return;
            }
            Some(fields) => fields,
        };

        // Index incoming fields with FieldRef and store as WeightedField entries
        let indexed_incoming: FxHashMap<FieldRef, WeightedField> =
            FieldRef::map_fields(&incoming_fields, |field_ref, field| {
                (field_ref, WeightedField::new(weight, field.clone()))
            });

        // Get or create PeerMetadata instance
        let peer_metadata = self.0.entry(ip).or_insert_with(|| {
            debug!("Creating new peer metadata cache entry for ip={}", ip);
            PeerMetadata::new()
        });

        match peer_metadata.0.entry(scope.clone().into()) {
            btree_map::Entry::Occupied(mut scoped_enrichment_fields) => {
                let scoped_enrichment_fields = scoped_enrichment_fields.get_mut();

                for (field_ref, weighted_field) in indexed_incoming {
                    // Check if field already exists
                    match scoped_enrichment_fields.entry(field_ref) {
                        hash_map::Entry::Occupied(mut enrichment_fields) => {
                            let curr_weight = enrichment_fields.get().weight();
                            if weight >= curr_weight {
                                debug!(
                                    "Replacing field[{}] in metadata for ip={}, scope={}, weight {}->{}",
                                    field_ref.ie(),
                                    ip,
                                    scope,
                                    curr_weight,
                                    weight,
                                );
                                enrichment_fields.insert(weighted_field);
                            } else {
                                debug!(
                                    "Ignoring lower weight field[{}] in metadata for ip={}, scope={}, weight: {}<{}",
                                    field_ref.ie(),
                                    ip,
                                    scope,
                                    curr_weight,
                                    weight,
                                );
                            }
                        }
                        hash_map::Entry::Vacant(enrichment_fields) => {
                            debug!(
                                "Adding new field[{}] in metadata for ip={}, scope={}, weight={}",
                                field_ref.ie(),
                                ip,
                                scope,
                                weight
                            );
                            enrichment_fields.insert(weighted_field);
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
    fn delete(&mut self, ip: IpAddr, scope: Scope, weight: Weight, ies: Option<Vec<IE>>) {
        // Early returns if empty vec is provided, and handle Null fields case
        // as delete all for scope (given weight precedence)
        let (scope_delete_all, ies) = match ies {
            Some(ies) if ies.is_empty() => {
                debug!("Empty IEs vector provided for delete operation for ip={}, scope={} - cache not modified", ip, scope);
                return;
            }
            Some(ies) => (false, ies),
            None => (true, vec![]),
        };

        if let Some(peer_metadata) = self.get_mut(&ip) {
            match peer_metadata.0.entry(scope.clone().into()) {
                btree_map::Entry::Occupied(mut occupied) => {
                    let current_fields = occupied.get_mut();

                    current_fields.retain(|field_ref, m_fld| {
                        if m_fld.weight <= weight
                            && (scope_delete_all || ies.contains(&field_ref.ie()))
                        {
                            debug!(
                                "Removing field [{:?}] for ip={}, scope={}, weight: {}>={}",
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
                            "Scope {} now empty for ip={}, removing scope entry...",
                            scope, ip
                        );

                        if peer_metadata.0.is_empty() {
                            debug!("Cache now empty for ip={}, cleaning up...", ip);
                            self.0.remove(&ip);
                        } else {
                            debug!("Updated cache for {ip}: \n{}", peer_metadata)
                        }
                    } else {
                        debug!("Updated cache for {ip}: \n{}", peer_metadata)
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

impl From<Vec<(IpAddr, PeerMetadata)>> for EnrichmentCache {
    fn from(value: Vec<(IpAddr, PeerMetadata)>) -> Self {
        let mut cache = FxHashMap::with_capacity_and_hasher(value.len(), FxBuildHasher);
        for (ip, metadata) in value {
            cache.insert(ip, metadata);
        }
        Self(cache)
    }
}

/// Optimized scope representation with indexed scope fields for fast matching.
///
/// Converts scope fields into a sorted slice of (FieldRef, Field) pairs
/// for efficient comparison during scope matching operations.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct IndexedScope {
    obs_domain_id: u32,
    scope_fields: Box<[(FieldRef, Field)]>,
}

impl IndexedScope {
    #[cfg(test)]
    fn new(obs_domain_id: u32, scope_fields: Vec<(FieldRef, Field)>) -> Self {
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
struct WeightedField {
    weight: Weight,
    field: Field,
}
impl WeightedField {
    fn new(weight: Weight, field: Field) -> Self {
        Self { weight, field }
    }
    fn weight(&self) -> Weight {
        self.weight
    }
    fn field(&self) -> &Field {
        &self.field
    }
}

/// Hierarchical metadata storage for a single peer, organized by scope.
///
/// Metadata is stored in a BTreeMap keyed by IndexedScope to ensure
/// consistent ordering from global to specific scopes during lookups.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PeerMetadata(BTreeMap<IndexedScope, IndexedMetadata>);
impl PeerMetadata {
    fn new() -> Self {
        Self(BTreeMap::new())
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
    fn get_enrichment_fields(
        &self,
        incoming_obs_id: u32,
        incoming_fields: &[Field],
    ) -> Option<Vec<Field>> {
        debug!(
            "Getting enrichment fields for obs_id={}, incoming_fields={:?}",
            incoming_obs_id, incoming_fields
        );

        if self.0.is_empty() {
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
        for (scope, metadata) in self
            .0
            .iter()
            .filter(|(scope, _)| Self::scope_matches(scope, incoming_obs_id, &fields_map))
        {
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

        if enrichment_fields.is_empty() {
            debug!("No matching fields found for enrichment");
            return None;
        } else {
            debug!(
                "Enrichment fields retrieved based on scope matches:\n{}",
                format_indexed_metadata(&enrichment_fields)
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

impl AsRef<BTreeMap<IndexedScope, IndexedMetadata>> for PeerMetadata {
    fn as_ref(&self) -> &BTreeMap<IndexedScope, IndexedMetadata> {
        &self.0
    }
}

impl std::fmt::Display for PeerMetadata {
    /// Formats PeerMetadata as a markdown-style table for debug logging
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.as_ref().is_empty() {
            return writeln!(f, "No metadata");
        }

        // Calculate column widths
        let max_scope_width = self
            .as_ref()
            .keys()
            .map(|scope| Into::<Scope>::into(scope).to_string().len())
            .max()
            .unwrap_or(40)
            .max(40);
        let max_field_width = self
            .as_ref()
            .values()
            .flat_map(|field_map| {
                field_map.values().map(|w_fld| {
                    let field_display = format!("{:?}", w_fld.field());
                    field_display.len()
                })
            })
            .max()
            .unwrap_or(40)
            .max(40);
        let max_index_width = 6;
        let max_weight_width = 6;

        // Header
        writeln!(
            f,
            "| {:<width_scope$} | {:<width_field$} | {:<width_index$} | {:<width_weight$} |",
            "Scope",
            "Fields",
            "Index",
            "Weight",
            width_scope = max_scope_width,
            width_field = max_field_width,
            width_index = max_index_width,
            width_weight = max_weight_width
        )?;

        // Separator
        writeln!(
            f,
            "|{:-<width_scope$}|{:-<width_field$}|{:-<width_index$}|{:-<width_weight$}|",
            "",
            "",
            "",
            "",
            width_scope = max_scope_width + 2,
            width_field = max_field_width + 2,
            width_index = max_index_width + 2,
            width_weight = max_weight_width + 2
        )?;

        // Data rows grouped by scope
        let mut first_scope = true;
        for (scope, fields) in self.as_ref() {
            // Add separator between scopes (except before the first one)
            if !first_scope {
                writeln!(
                    f,
                    "|{:-<width_scope$}|{:-<width_field$}|{:-<width_index$}|{:-<width_weight$}|",
                    "",
                    "",
                    "",
                    "",
                    width_scope = max_scope_width + 2,
                    width_field = max_field_width + 2,
                    width_index = max_index_width + 2,
                    width_weight = max_weight_width + 2
                )?;
            }
            first_scope = false;

            if fields.is_empty() {
                writeln!(
                    f,
                    "| {:<width_scope$} | {:<width_field$} | {:<width_index$} | {:<width_weight$} |",
                    Into::<Scope>::into(scope).to_string(),
                    "No fields",
                    "--",
                    "--",
                    width_scope = max_scope_width,
                    width_field = max_field_width,
                    width_index = max_index_width,
                    width_weight = max_weight_width
                )?;
            } else {
                let mut first_field = true;
                for (field_ref, metadata_field) in fields {
                    let field_display = format!("{:?}", metadata_field.field());
                    let field_truncated = if field_display.len() > max_field_width {
                        format!("{}...", &field_display[..max_field_width - 3])
                    } else {
                        field_display
                    };

                    // Only show scope on the first row of each scope group
                    let scope_display = if first_field {
                        Into::<Scope>::into(scope).to_string()
                    } else {
                        "".to_string()
                    };

                    writeln!(f,
                        "| {:<width_scope$} | {:<width_field$} | {:<width_index$} | {:<width_weight$} |",
                        scope_display,
                        field_truncated,
                        field_ref.index(),
                        metadata_field.weight(),
                        width_scope = max_scope_width,
                        width_field = max_field_width,
                        width_index = max_index_width,
                        width_weight = max_weight_width
                    )?;

                    first_field = false;
                }
            }
        }

        Ok(())
    }
}

/// A hash map that indexes enrichment fields by their reference for fast
/// lookup.
type IndexedMetadata = FxHashMap<FieldRef, WeightedField>;

/// Formats IndexedMetadata as a markdown-style table for debug logging
fn format_indexed_metadata(enrichment_fields: &FxHashMap<FieldRef, &WeightedField>) -> String {
    if enrichment_fields.is_empty() {
        "No enrichment fields found".to_string()
    } else {
        // Calculate column widths
        let max_field_width = enrichment_fields
            .values()
            .map(|weighted_field| format!("{:?}", weighted_field.field()).len())
            .max()
            .unwrap_or(60)
            .max(60);
        let max_index_width = enrichment_fields
            .keys()
            .map(|field_ref| field_ref.index().to_string().len())
            .max()
            .unwrap_or(5)
            .max(5);
        let max_weight_width = enrichment_fields
            .values()
            .map(|weighted_field| weighted_field.weight().to_string().len())
            .max()
            .unwrap_or(6)
            .max(6);

        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "| {:<width_field$} | {:<width_index$} | {:<width_weight$} |\n",
            "Field",
            "Index",
            "Weight",
            width_field = max_field_width,
            width_index = max_index_width,
            width_weight = max_weight_width
        ));

        // Separator
        output.push_str(&format!(
            "|{:-<width_field$}|{:-<width_index$}|{:-<width_weight$}|\n",
            "",
            "",
            "",
            width_field = max_field_width + 2,
            width_index = max_index_width + 2,
            width_weight = max_weight_width + 2
        ));

        // Data rows
        for (field_ref, weighted_field) in enrichment_fields {
            output.push_str(&format!(
                "| {:<width_field$} | {:<width_index$} | {:<width_weight$} |\n",
                format!("{:?}", weighted_field.field()),
                field_ref.index(),
                weighted_field.weight(),
                width_field = max_field_width,
                width_index = max_index_width,
                width_weight = max_weight_width
            ));
        }

        output
    }
}

#[cfg(test)]
mod tests;
