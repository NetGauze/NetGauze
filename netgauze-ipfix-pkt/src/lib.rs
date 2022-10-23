// Copyright (C) 2022-present The NetGauze Authors.
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

pub mod ie;
#[cfg(feature = "serde")]
pub mod wire;

use crate::ie::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Field {
    element_id: InformationElementId,
    length: u16,
}

impl Field {
    pub const fn new(element_id: InformationElementId, length: u16) -> Self {
        Self { element_id, length }
    }

    pub const fn element_id(&self) -> InformationElementId {
        self.element_id
    }

    pub const fn length(&self) -> u16 {
        self.length
    }
}
