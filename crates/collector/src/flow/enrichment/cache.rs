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
//! - `IndexedScopeFields` - Optimized scope fields representation for fast
//!   matching operations
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
//! - **Observation Domain ID**:
//!   - Global scopes (ID 0) are matched first.
//!   - Domain-specific scopes are matched next, based on the Observation Domain
//!     ID.
//! - **Scope Fields**:
//!   - All scope fields must exactly match incoming data.
//!
//! ## Weight Resolution
//!
//! When multiple scopes provide the same field type:
//! - Higher weight fields override lower weight fields
//! - Equal weights prefer more specific (later processed) scopes

use crate::flow::enrichment::{
    DeleteAllPayload, DeletePayload, EnrichmentOperation, Scope, UpsertPayload, Weight,
};
use crate::flow::types::FieldRef;
use netgauze_flow_pkt::ie::{Field, HasIE, IE};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, btree_map, hash_map};
use std::net::IpAddr;
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
                self.upsert(ip, scope, weight, Some(fields));
            }
            EnrichmentOperation::Delete(DeletePayload {
                ip,
                scope,
                weight,
                ies,
            }) => {
                self.delete(ip, scope, weight, Some(ies));
            }
            EnrichmentOperation::DeleteAll(DeleteAllPayload { ip, scope, weight }) => {
                self.delete(ip, scope, weight, None);
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
                debug!(
                    "No fields provided for upsert operation for ip={}, scope={} - cache not modified",
                    ip, scope
                );
                return;
            }
            Some(fields) if fields.is_empty() => {
                debug!(
                    "Empty fields vector provided for upsert operation for ip={}, scope={} - cache not modified",
                    ip, scope
                );
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

        let scope_fields = IndexedScopeFields::from(&scope);
        let obs_domain_id = scope.obs_domain_id();

        // Select the target map (global or obs-domain specific)
        let target_map = if obs_domain_id == 0 {
            &mut peer_metadata.global
        } else {
            peer_metadata
                .domain_scoped
                .entry(obs_domain_id)
                .or_default()
        };

        match target_map.entry(scope_fields) {
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
    /// Removes all fields with weight less or equal than the specified weight
    /// within the matching scope & ies. Cleans up empty scopes and peer
    /// entries automatically.
    fn delete(&mut self, ip: IpAddr, scope: Scope, weight: Weight, ies: Option<Vec<IE>>) {
        // Early returns if empty vec is provided, and handle Null fields case
        // as delete all for scope (given weight precedence)
        let (scope_delete_all, ies) = match ies {
            Some(ies) if ies.is_empty() => {
                debug!(
                    "Empty IEs vector provided for delete operation for ip={}, scope={} - cache not modified",
                    ip, scope
                );
                return;
            }
            Some(ies) => (false, ies),
            None => (true, vec![]), // None -> delete all
        };

        if let Some(peer_metadata) = self.get_mut(&ip) {
            let scope_fields = IndexedScopeFields::from(&scope);
            let obs_domain_id = scope.obs_domain_id();

            // Select the target map
            let target_map = if obs_domain_id == 0 {
                &mut peer_metadata.global
            } else {
                match peer_metadata.domain_scoped.get_mut(&obs_domain_id) {
                    Some(map) => map,
                    None => {
                        debug!(
                            "No entry matching ip={} and obs_domain_id={}, nothing to delete",
                            ip, obs_domain_id
                        );
                        return;
                    }
                }
            };

            match target_map.entry(scope_fields) {
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

                        // Clean up empty domain map
                        if obs_domain_id != 0 && target_map.is_empty() {
                            peer_metadata.domain_scoped.remove(&obs_domain_id);
                        }

                        if peer_metadata.global.is_empty() && peer_metadata.domain_scoped.is_empty()
                        {
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

/// Indexed scope fields for efficient matching operations.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct IndexedScopeFields(Box<[(FieldRef, Field)]>);

impl IndexedScopeFields {
    /// Check if all scope fields match with the incoming fields
    #[inline]
    fn matches(&self, incoming_fields: &FxHashMap<FieldRef, &Field>) -> bool {
        self.0.iter().all(|(field_ref, field)| {
            incoming_fields
                .get(field_ref)
                .is_some_and(|incoming| field == *incoming)
        })
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    fn new(scope_fields: Vec<(FieldRef, Field)>) -> Self {
        Self(scope_fields.into_boxed_slice())
    }
}

impl From<&Scope> for IndexedScopeFields {
    fn from(scope: &Scope) -> Self {
        let scope_fields = scope
            .scope_fields()
            .as_ref()
            .map(|fields| FieldRef::map_fields_into_boxed_slice_owned(fields))
            .unwrap_or_default();

        Self(scope_fields)
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

/// A hash map that indexes enrichment fields by their reference for fast
/// lookup.
type IndexedMetadata = FxHashMap<FieldRef, WeightedField>;

/// Hierarchical metadata storage for a single peer, organized by scope.
///
/// Metadata is partitioned by Observation Domain ID to optimize lookups:
/// - `global`: scoped to all domains (ID 0)
/// - `domain_scoped`: scoped specific to a domain, indexed by ID
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PeerMetadata {
    global: BTreeMap<IndexedScopeFields, IndexedMetadata>,
    domain_scoped: FxHashMap<u32, BTreeMap<IndexedScopeFields, IndexedMetadata>>,
}

impl PeerMetadata {
    fn new() -> Self {
        Self {
            global: BTreeMap::new(),
            domain_scoped: FxHashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Extract enrichment fields for the given observation ID and incoming
    /// fields.
    ///
    /// Iterates through global scopes first, then domain-specific scopes,
    /// collecting matching fields. For duplicate field types across scopes,
    /// returns the highest weight field, with equal weights favoring more
    /// specific scopes.
    ///
    /// As an example, consider the following PeerMetadata entries:
    /// - Global scope {scope_fields: []} -> \[samplerName("global_sampler")\],
    ///   weight 64
    /// - Domain scope {obs_domain_id: 2000, scope_fields: \[selectorId(1)\]} ->
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

        if self.global.is_empty() && self.domain_scoped.is_empty() {
            debug!("No scopes available for enrichment");
            return None;
        }

        // Store incoming fields indexed by FieldRef (IE, index)
        let fields_map = FieldRef::map_fields_into_fxhashmap(incoming_fields);

        // Map to temporarily store enrichment fields
        let mut enrichment_fields: FxHashMap<FieldRef, &WeightedField> =
            FxHashMap::with_capacity_and_hasher(16, FxBuildHasher);

        // Process global scopes first (obs_domain_id == 0)
        for (scope_fields, metadata) in &self.global {
            if scope_fields.matches(&fields_map) {
                debug!("Global scope matches incoming data!");
                Self::merge_fields(&mut enrichment_fields, metadata);
            }
        }

        // Process obs-domain-id specific scopes
        if let Some(domain_metadata) = self.domain_scoped.get(&incoming_obs_id) {
            for (scope_fields, metadata) in domain_metadata {
                if scope_fields.matches(&fields_map) {
                    debug!(
                        "Obs-id specific scope (obs_id={}) matches incoming data!",
                        incoming_obs_id
                    );
                    Self::merge_fields(&mut enrichment_fields, metadata);
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

    /// Helper to merge enrichment fields based on weights
    #[inline]
    fn merge_fields<'a>(
        enrichment_fields: &mut FxHashMap<FieldRef, &'a WeightedField>,
        metadata: &'a IndexedMetadata,
    ) {
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

impl std::fmt::Display for PeerMetadata {
    /// Formats PeerMetadata as a markdown-style table for debug logging
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.global.is_empty() && self.domain_scoped.is_empty() {
            return writeln!(f, "No metadata");
        }

        // Calculate column widths
        let calc_scope_width = |obs_id: u32, scope_fields: &IndexedScopeFields| -> usize {
            let scope = Scope::new(
                obs_id,
                if scope_fields.is_empty() {
                    None
                } else {
                    Some(scope_fields.0.iter().map(|(_, f)| f.clone()).collect())
                },
            );
            scope.to_string().len()
        };

        let max_scope_width =
            self.global
                .keys()
                .map(|sf| calc_scope_width(0, sf))
                .chain(self.domain_scoped.iter().flat_map(|(obs_id, map)| {
                    map.keys().map(move |sf| calc_scope_width(*obs_id, sf))
                }))
                .max()
                .unwrap_or(40)
                .max(40);

        let max_field_width = self
            .global
            .values()
            .chain(self.domain_scoped.values().flat_map(|m| m.values()))
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

        let mut first_scope = true;

        // Helper to format scope entries
        let format_scope_entries = |f: &mut std::fmt::Formatter<'_>,
                                    obs_id: u32,
                                    scope_fields: &IndexedScopeFields,
                                    fields: &IndexedMetadata,
                                    first_scope: &mut bool|
         -> std::fmt::Result {
            // Add separator between scopes
            if !*first_scope {
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
            *first_scope = false;

            let scope_str = Scope::new(
                obs_id,
                if scope_fields.is_empty() {
                    None
                } else {
                    Some(scope_fields.0.iter().map(|(_, f)| f.clone()).collect())
                },
            )
            .to_string();

            if fields.is_empty() {
                writeln!(
                    f,
                    "| {:<width_scope$} | {:<width_field$} | {:<width_index$} | {:<width_weight$} |",
                    scope_str,
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
                    let field_str = match std::convert::TryInto::<String>::try_into(
                        metadata_field.field().clone(),
                    ) {
                        Ok(s) => s,
                        Err(_) => metadata_field.field().to_string(),
                    };

                    let field_display = format!("{}({})", metadata_field.field().ie(), field_str);
                    let field_truncated = if field_display.len() > max_field_width {
                        format!("{}...", &field_display[..max_field_width - 3])
                    } else {
                        field_display
                    };

                    let scope_display = if first_field {
                        scope_str.clone()
                    } else {
                        "".to_string()
                    };

                    writeln!(
                        f,
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
            Ok(())
        };

        // Format global scopes
        for (scope_fields, fields) in &self.global {
            format_scope_entries(f, 0, scope_fields, fields, &mut first_scope)?;
        }

        // Format domain-specific scopes (sorted by obs_domain_id for consistency)
        let mut sorted_domains: Vec<_> = self.domain_scoped.iter().collect();
        sorted_domains.sort_by_key(|(obs_id, _)| *obs_id);

        for (obs_id, domain_map) in sorted_domains {
            for (scope_fields, fields) in domain_map {
                format_scope_entries(f, *obs_id, scope_fields, fields, &mut first_scope)?;
            }
        }

        Ok(())
    }
}

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
            let field_str =
                match std::convert::TryInto::<String>::try_into(weighted_field.field().clone()) {
                    Ok(s) => s,
                    Err(_) => weighted_field.field().to_string(),
                };

            let field_display = format!("{}({})", weighted_field.field().ie(), field_str);

            output.push_str(&format!(
                "| {:<width_field$} | {:<width_index$} | {:<width_weight$} |\n",
                field_display,
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
