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

//! # Flow Enrichment Module
//!
//! This module provides functionality for enriching network flow data with
//! additional metadata. It supports operations to add, update, or remove
//! enrichment data associated with IP addresses within specific scopes and
//! observation domains.
//!
//! ## Key Concepts
//!
//! - **Enrichment Operations**: Actions to modify enrichment data (upsert or
//!   delete)
//! - **Scope**: Defines the context where enrichment applies (global,
//!   observation domain, or field-specific)
//! - **Weight**: Priority system for enrichment data resolution
//! - **Payload**: The actual enrichment data and metadata

mod actor;
mod cache;
mod config;

pub use actor::FlowEnrichmentActorHandle;
pub use config::EnrichmentConfig;

#[cfg(feature = "bench")]
pub use actor::{EnrichmentActor, EnrichmentStats};
#[cfg(feature = "bench")]
pub use cache::EnrichmentCache;

use netgauze_flow_pkt::ie::{Field, HasIE, IE};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum_macros::Display)]
pub enum EnrichmentOperationType {
    Upsert,
    Delete,
}

/// Operations to update or delete enrichment data.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, strum_macros::Display, Serialize, Deserialize,
)]
pub enum EnrichmentOperation {
    /// Upsert a list of fields for the matching scope
    #[strum(to_string = "Upsert({0})")]
    Upsert(UpsertPayload),

    /// Delete a list of fields for the matching scope
    #[strum(to_string = "Delete({0})")]
    Delete(DeletePayload),

    /// Delete all fields for the matching scope
    #[strum(to_string = "DeleteAll({0})")]
    DeleteAll(DeleteAllPayload),
}

impl EnrichmentOperation {
    pub fn ip(&self) -> IpAddr {
        match self {
            EnrichmentOperation::Upsert(payload) => payload.ip,
            EnrichmentOperation::Delete(payload) => payload.ip,
            EnrichmentOperation::DeleteAll(payload) => payload.ip,
        }
    }

    pub fn scope(&self) -> &Scope {
        match self {
            EnrichmentOperation::Upsert(payload) => &payload.scope,
            EnrichmentOperation::Delete(payload) => &payload.scope,
            EnrichmentOperation::DeleteAll(payload) => &payload.scope,
        }
    }

    pub fn weight(&self) -> Weight {
        match self {
            EnrichmentOperation::Upsert(payload) => payload.weight,
            EnrichmentOperation::Delete(payload) => payload.weight,
            EnrichmentOperation::DeleteAll(payload) => payload.weight,
        }
    }

    /// Validate that payload contains actual fields to upsert/delete
    /// (e.g. use drop useless operations)
    pub fn validate(&self) -> bool {
        match self {
            EnrichmentOperation::Upsert(payload) => payload.validate(),
            EnrichmentOperation::Delete(payload) => payload.validate(),
            EnrichmentOperation::DeleteAll(_) => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UpsertPayload {
    pub ip: IpAddr,
    pub scope: Scope,
    pub weight: Weight,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
}

impl UpsertPayload {
    pub fn validate(&self) -> bool {
        !self.fields.is_empty()
    }
}

impl std::fmt::Display for UpsertPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ip={}, scope={}, weight={}, fields={:?}",
            self.ip, self.scope, self.weight, self.fields
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeletePayload {
    pub ip: IpAddr,
    pub scope: Scope,
    pub weight: Weight,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ies: Vec<IE>,
}

impl DeletePayload {
    pub fn validate(&self) -> bool {
        !self.ies.is_empty()
    }
}

impl std::fmt::Display for DeletePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ip={}, scope={}, weight={}, ies={:?}",
            self.ip, self.scope, self.weight, self.ies
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeleteAllPayload {
    pub ip: IpAddr,
    pub scope: Scope,
    pub weight: Weight,
}

impl std::fmt::Display for DeleteAllPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ip={}, scope={}, weight={}, ies=ALL",
            self.ip, self.scope, self.weight
        )
    }
}

/// Convert (lossy) UpsertPayload to DeletePayload
impl From<UpsertPayload> for DeletePayload {
    fn from(upsert: UpsertPayload) -> Self {
        Self {
            ip: upsert.ip,
            scope: upsert.scope,
            weight: upsert.weight,
            ies: upsert.fields.into_iter().map(|field| field.ie()).collect(),
        }
    }
}

/// Weight helper type
pub type Weight = u8;

/// Scope helper struct
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Scope {
    obs_domain_id: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope_fields: Option<Vec<Field>>,
}

impl Scope {
    pub fn new(obs_domain_id: u32, scope_fields: Option<Vec<Field>>) -> Self {
        Self {
            obs_domain_id,
            scope_fields,
        }
    }
    pub fn is_global(&self) -> bool {
        self.obs_domain_id == 0 && self.scope_fields.is_none()
    }
    pub fn obs_domain_id(&self) -> u32 {
        self.obs_domain_id
    }
    pub fn scope_fields(&self) -> Option<&Vec<Field>> {
        self.scope_fields.as_ref()
    }
}

impl std::fmt::Display for Scope {
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

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_flow_pkt::ie::Field;
    use serde_json;

    #[test]
    fn test_enrichment_operation_serde_upsert() {
        let op = EnrichmentOperation::Upsert(UpsertPayload {
            ip: "192.0.2.1".parse().unwrap(),
            scope: Scope::new(42, Some(vec![Field::selectorId(100)])),
            weight: 5,
            fields: vec![
                Field::selectorName("test".to_string().into()),
                Field::samplingSize(1),
                Field::samplingPopulation(1000),
            ],
        });

        let json = serde_json::to_string(&op).unwrap();
        let expected = r#"{"Upsert":{"ip":"192.0.2.1","scope":{"obs_domain_id":42,"scope_fields":[{"selectorId":100}]},"weight":5,"fields":[{"selectorName":"test"},{"samplingSize":1},{"samplingPopulation":1000}]}}"#;

        println!("{json}");

        assert_eq!(json, expected);

        let de: EnrichmentOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(de, op);
    }

    #[test]
    fn test_enrichment_operation_serde_delete() {
        let op = EnrichmentOperation::DeleteAll(DeleteAllPayload {
            ip: "203.0.113.5".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 1,
        });

        let json = serde_json::to_string(&op).unwrap();
        let expected =
            r#"{"DeleteAll":{"ip":"203.0.113.5","scope":{"obs_domain_id":0},"weight":1}}"#;
        assert_eq!(json, expected);

        let de: EnrichmentOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(de, op);
    }

    #[test]
    fn test_enrichment_operation_delete_with_specific_fields() {
        let op = EnrichmentOperation::Delete(DeletePayload {
            ip: "198.51.100.10".parse().unwrap(),
            scope: Scope::new(100, Some(vec![Field::selectorId(200)])),
            weight: 3,
            ies: vec![IE::selectorName, IE::samplingSize],
        });

        let json = serde_json::to_string(&op).unwrap();
        let expected = r#"{"Delete":{"ip":"198.51.100.10","scope":{"obs_domain_id":100,"scope_fields":[{"selectorId":200}]},"weight":3,"ies":["selectorName","samplingSize"]}}"#;
        assert_eq!(json, expected);

        let de: EnrichmentOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(de, op);
    }
}
