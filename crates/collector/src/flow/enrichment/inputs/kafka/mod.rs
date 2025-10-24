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
mod handlers;

pub use actor::KafkaConsumerActorHandle;

use crate::flow::enrichment::EnrichmentOperation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub(crate) const fn default_weight() -> u8 {
    64
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KafkaConfig {
    pub consumers: Vec<KafkaConsumerConfig>,
}

/// Kafka consumer config
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KafkaConsumerConfig {
    pub topic: String,

    pub message_format: MessageFormat,

    pub consumer_config: HashMap<String, String>,
}

#[derive(strum_macros::Display, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageFormat {
    /// JSON-serialized [`EnrichmentOperation`] upsert/delete messages
    #[strum(to_string = "JSON EnrichmentOperation message")]
    JsonOps,

    /// Swisscom custom SonataDB insert/update/delete messages
    #[strum(to_string = "Swisscom custom SonataDB message")]
    Sonata(SonataConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SonataConfig {
    #[serde(default = "default_weight")]
    pub weight: u8,
}

/// Trait for handling different message formats from Kafka
pub trait MessageHandler: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Parse the raw message into an [`EnrichmentOperation`]
    fn handle_message(
        &mut self,
        payload: &[u8],
        partition: i32,
        offset: i64,
    ) -> Result<Vec<EnrichmentOperation>, Self::Error>;
}
