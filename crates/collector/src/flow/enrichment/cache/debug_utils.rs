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

//! Debug utilities for flow enrichment cache components.
//!
//! This module provides Display trait implementations and formatting utilities
//! for debugging and logging enrichment cache operations:
//!
//! - `Display` implementations for core enrichment types
//! - Table-formatted output for field collections
//! - Human-readable representations of cache operations and metadata
//!
//! These utilities are primarily used for tracing and debugging cache behavior,
//! providing structured output that makes it easier to understand enrichment
//! operations and metadata organization.

use crate::flow::{
    enrichment::{
        cache::{PeerMetadata, WeightedField},
        EnrichmentOperation, Scope,
    },
    types::FieldRef,
};
use rustc_hash::FxHashMap;
use std::fmt::Display;

impl Display for EnrichmentOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upsert(ip, scope, weight, fields) => {
                write!(
                    f,
                    "Upsert(ip={ip}, scope={scope}, weight={weight}, fields={fields:?})"
                )
            }
            Self::Delete(ip, scope, weight) => {
                write!(f, "Delete(ip={ip}, scope={scope}, weight={weight})")
            }
        }
    }
}

impl Display for PeerMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.map().is_empty() {
            return writeln!(f, "No metadata");
        }

        // Calculate column widths
        let max_scope_width = self
            .map()
            .keys()
            .map(|scope| Into::<Scope>::into(scope).to_string().len())
            .max()
            .unwrap_or(5)
            .max(5);
        let max_field_ref_width = self
            .map()
            .values()
            .flat_map(|fields| fields.keys())
            .map(|field_ref| format!("{field_ref:?}").len())
            .max()
            .unwrap_or(8)
            .max(8);
        let max_weight_width = 6;
        let max_field_width = 60;

        // Header
        writeln!(
            f,
            "| {:<width_scope$} | {:<width_field_ref$} | {:<width_weight$} | {:<width_field$} |",
            "Scope",
            "FieldRef",
            "Weight",
            "Field",
            width_scope = max_scope_width,
            width_field_ref = max_field_ref_width,
            width_weight = max_weight_width,
            width_field = max_field_width
        )?;

        // Separator
        writeln!(
            f,
            "|{:-<width_scope$}|{:-<width_field_ref$}|{:-<width_weight$}|{:-<width_field$}|",
            "",
            "",
            "",
            "",
            width_scope = max_scope_width + 2,
            width_field_ref = max_field_ref_width + 2,
            width_weight = max_weight_width + 2,
            width_field = max_field_width + 2
        )?;

        // Data rows grouped by scope
        let mut first_scope = true;
        for (scope, fields) in self.map() {
            // Add separator between scopes (except before the first one)
            if !first_scope {
                writeln!(
                    f,
                    "|{:-<width_scope$}|{:-<width_field_ref$}|{:-<width_weight$}|{:-<width_field$}|",
                    "",
                    "",
                    "",
                    "",
                    width_scope = max_scope_width + 2,
                    width_field_ref = max_field_ref_width + 2,
                    width_weight = max_weight_width + 2,
                    width_field = max_field_width + 2
                )?;
            }
            first_scope = false;

            if fields.is_empty() {
                writeln!(
                    f,
                    "| {:<width_scope$} | {:<width_field_ref$} | {:<width_weight$} | {:<width_field$} |",
                    Into::<Scope>::into(scope).to_string(),
                    "--",
                    "--",
                    "No fields",
                    width_scope = max_scope_width,
                    width_field_ref = max_field_ref_width,
                    width_weight = max_weight_width,
                    width_field = max_field_width
                )?;
            } else {
                let mut first_field = true;
                for (ie, metadata_field) in fields {
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
                        "| {:<width_scope$} | {:<width_field_ref$} | {:<width_weight$} | {:<width_field$} |",
                        scope_display,
                        format!("{:?}", ie),
                        metadata_field.weight(),
                        field_truncated,
                        width_scope = max_scope_width,
                        width_field_ref = max_field_ref_width,
                        width_weight = max_weight_width,
                        width_field = max_field_width
                    )?;

                    first_field = false;
                }
            }
        }

        Ok(())
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_global() {
            write!(f, "[SYSTEM]")
        } else if let Some(ref fields) = self.scope_fields() {
            write!(f, "obs_id({})+{:?}", self.obs_domain_id(), fields)
        } else {
            write!(f, "[obs_id={}]", self.obs_domain_id())
        }
    }
}

/// Formats <FieldRef, WeightedField> maps as a markdown-style table for debug
/// logging
pub(crate) fn format_fields_table(
    enrichment_fields: &FxHashMap<FieldRef, &WeightedField>,
) -> String {
    if enrichment_fields.is_empty() {
        "No enrichment fields found".to_string()
    } else {
        // Calculate column widths
        let max_field_ref_width = enrichment_fields
            .keys()
            .map(|field_ref| format!("{field_ref:?}").len())
            .max()
            .unwrap_or(8)
            .max(8);
        let max_weight_width = enrichment_fields
            .values()
            .map(|weighted_field| weighted_field.weight().to_string().len())
            .max()
            .unwrap_or(6)
            .max(6);
        let max_field_width = enrichment_fields
            .values()
            .map(|weighted_field| format!("{:?}", weighted_field.field()).len())
            .max()
            .unwrap_or(5)
            .max(5);

        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "| {:<width_ref$} | {:<width_weight$} | {:<width_field$} |\n",
            "FieldRef",
            "Weight",
            "Field",
            width_ref = max_field_ref_width,
            width_weight = max_weight_width,
            width_field = max_field_width
        ));

        // Separator
        output.push_str(&format!(
            "|{:-<width_ref$}|{:-<width_weight$}|{:-<width_field$}|\n",
            "",
            "",
            "",
            width_ref = max_field_ref_width + 2,
            width_weight = max_weight_width + 2,
            width_field = max_field_width + 2
        ));

        // Data rows
        for (field_ref, weighted_field) in enrichment_fields {
            output.push_str(&format!(
                "| {:<width_ref$} | {:<width_weight$} | {:<width_field$} |\n",
                format!("{:?}", field_ref),
                weighted_field.weight(),
                format!("{:?}", weighted_field.field()),
                width_ref = max_field_ref_width,
                width_weight = max_weight_width,
                width_field = max_field_width
            ));
        }

        output
    }
}
