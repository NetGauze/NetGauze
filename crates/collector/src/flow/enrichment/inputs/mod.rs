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

use crate::flow::enrichment::inputs::{
    files::FilesConfig, flow_options::FlowOptionsConfig, kafka::KafkaConfig,
};

use serde::{Deserialize, Serialize};

mod files;
mod flow_options;
mod kafka;

pub use files::FilesActorHandle;
pub use flow_options::FlowOptionsActorHandle;
pub use kafka::KafkaConsumerActorHandle;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct InputsConfig {
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub files: Option<FilesConfig>,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub flow_options: Option<FlowOptionsConfig>,

    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub kafka: Option<KafkaConfig>,
}
