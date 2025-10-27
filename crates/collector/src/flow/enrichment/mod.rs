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
mod inputs;

pub use actor::EnrichmentActorHandle;
pub use config::EnrichmentConfig;
pub use inputs::{FilesActorHandle, FlowOptionsActorHandle, KafkaConsumerActorHandle};

use netgauze_flow_pkt::ie::{Field, HasIE, IE};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum_macros::Display)]
pub enum EnrichmentOperationType {
    Upsert,
    Delete,
}

/// Operations to update or delete enrichment data.
///
/// ## Upsert Behavior:
/// - If `fields` is `None` or Some(vec![]): No operation is performed
/// - If `fields` is `Some(vec![field1, field2, ...])`: Adds or updates the
///   specified fields
///
/// ## Delete Behavior:
/// - If `ies` is `None`: Removes ALL enrichment data matching the IP and scope
/// - If `ies` is `Some(vec![])`: No operation is performed (safeguard)
/// - If `ies` is `Some(vec![IE1, IE2, ...])`: Removes all the fields matching
///   the specified IEs
///
/// The empty vector safeguard prevents accidental bulk operations when
/// malformed data is provided.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, strum_macros::Display, Serialize, Deserialize,
)]
pub enum EnrichmentOperation {
    #[strum(to_string = "Upsert({0})")]
    Upsert(UpsertPayload),

    #[strum(to_string = "Delete({0})")]
    Delete(DeletePayload),
}

impl EnrichmentOperation {
    pub fn ip(&self) -> IpAddr {
        match self {
            EnrichmentOperation::Upsert(payload) => payload.ip,
            EnrichmentOperation::Delete(payload) => payload.ip,
        }
    }

    pub fn scope(&self) -> &Scope {
        match self {
            EnrichmentOperation::Upsert(payload) => &payload.scope,
            EnrichmentOperation::Delete(payload) => &payload.scope,
        }
    }

    pub fn weight(&self) -> Weight {
        match self {
            EnrichmentOperation::Upsert(payload) => payload.weight,
            EnrichmentOperation::Delete(payload) => payload.weight,
        }
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
pub struct UpsertPayload {
    pub ip: IpAddr,
    pub scope: Scope,
    pub weight: Weight,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<Field>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeletePayload {
    pub ip: IpAddr,
    pub scope: Scope,
    pub weight: Weight,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ies: Option<Vec<IE>>,
}

/// Convert (lossy) UpsertPayload to DeletePayload
///
/// When `fields`=`None` we map to `ies`=`Some(vec![])` to avoid converting
/// an upsert-nothing to a delete-all operation (safeguard)
impl From<UpsertPayload> for DeletePayload {
    fn from(upsert: UpsertPayload) -> Self {
        Self {
            ip: upsert.ip,
            scope: upsert.scope,
            weight: upsert.weight,
            ies: match upsert.fields {
                Some(fields) => Some(fields.into_iter().map(|field| field.ie()).collect()),
                None => Some(vec![]),
            },
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
            fields: Some(vec![
                Field::selectorName("test".to_string().into()),
                Field::samplingSize(1),
                Field::samplingPopulation(1000),
            ]),
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
        let op = EnrichmentOperation::Delete(DeletePayload {
            ip: "203.0.113.5".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 1,
            ies: None,
        });

        let json = serde_json::to_string(&op).unwrap();
        let expected = r#"{"Delete":{"ip":"203.0.113.5","scope":{"obs_domain_id":0},"weight":1}}"#;
        assert_eq!(json, expected);

        let de: EnrichmentOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(de, op);

        // Test deserialization of same op with null fields specific that should also
        // result in same op
        let del1 = r#"{"Delete":{"ip":"203.0.113.5","scope":{"obs_domain_id":0,"scope_fields":null},"weight":1,"ies":null}}"#;
        let del2 = r#"{"Delete":{"ip":"203.0.113.5","scope":{"obs_domain_id":0,"scope_fields":null},"weight":1}}"#;

        let de1: EnrichmentOperation = serde_json::from_str(del1).unwrap();
        let de2: EnrichmentOperation = serde_json::from_str(del2).unwrap();

        assert_eq!(de1, op);
        assert_eq!(de2, op);
    }
    #[test]
    fn test_enrichment_operation_delete_with_specific_fields() {
        let op = EnrichmentOperation::Delete(DeletePayload {
            ip: "198.51.100.10".parse().unwrap(),
            scope: Scope::new(100, Some(vec![Field::selectorId(200)])),
            weight: 3,
            ies: Some(vec![IE::selectorName, IE::samplingSize]),
        });

        let json = serde_json::to_string(&op).unwrap();
        let expected = r#"{"Delete":{"ip":"198.51.100.10","scope":{"obs_domain_id":100,"scope_fields":[{"selectorId":200}]},"weight":3,"ies":["selectorName","samplingSize"]}}"#;
        assert_eq!(json, expected);

        let de: EnrichmentOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(de, op);
    }
}
