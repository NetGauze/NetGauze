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

use netgauze_yang_push::model::telemetry::Label;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub mod config;
pub mod enrichment;

/// Weight helper type
pub type Weight = u8;

/// Operations to update or delete enrichment data.
#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpsertPayload {
    pub ip: IpAddr,
    pub weight: Weight,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<Label>,
}

impl UpsertPayload {
    pub fn validate(&self) -> bool {
        !self.labels.is_empty()
    }
}

impl std::fmt::Display for UpsertPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ip={}, weight={}, labels={:?}",
            self.ip, self.weight, self.labels
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeletePayload {
    pub ip: IpAddr,
    pub weight: Weight,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub label_names: Vec<String>,
}

impl DeletePayload {
    pub fn validate(&self) -> bool {
        !self.label_names.is_empty()
    }
}

impl std::fmt::Display for DeletePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ip={}, weight={}, labels={:?}",
            self.ip, self.weight, self.label_names
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeleteAllPayload {
    pub ip: IpAddr,
    pub weight: Weight,
}

impl std::fmt::Display for DeleteAllPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ip={}, weight={}, label=ALL", self.ip, self.weight)
    }
}

/// Convert (lossy) UpsertPayload to DeletePayload
impl From<UpsertPayload> for DeletePayload {
    fn from(upsert: UpsertPayload) -> Self {
        Self {
            ip: upsert.ip,
            weight: upsert.weight,
            label_names: upsert
                .labels
                .into_iter()
                .map(|label| label.name().to_string())
                .collect(),
        }
    }
}
