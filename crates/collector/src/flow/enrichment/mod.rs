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

mod actor;
mod cache;
mod inputs;

pub use actor::EnrichmentActorHandle;
pub use inputs::FlowOptionsActorHandle;

use netgauze_flow_pkt::ie::Field;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Operations to update or delete enrichment data
#[derive(Debug, Clone, strum_macros::Display)]
pub enum EnrichmentOperation {
    #[strum(to_string = "Upsert(ip={ip}, scope={scope}, weight={weight}, fields={fields:?})")]
    Upsert {
        ip: IpAddr,
        scope: Scope,
        weight: Weight,
        fields: Vec<Field>,
    },
    #[strum(to_string = "Delete(ip={ip}, scope={scope}, weight={weight})")]
    Delete {
        ip: IpAddr,
        scope: Scope,
        weight: Weight,
    },
}

/// Weight helper type
pub type Weight = u8;

/// Scope helper struct
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Scope {
    obs_domain_id: u32,
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
