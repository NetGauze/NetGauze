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
use netgauze_flow_pkt::ie::IE;
use serde::{Deserialize, Serialize};

mod actor;
mod formats;
mod handlers;
mod processor;

pub use actor::FilesActorHandle;

fn default_weight() -> u8 {
    128
}

fn default_poll_interval() -> u64 {
    30
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesConfig {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,

    pub paths: Vec<InputFile>,
}

impl FilesConfig {
    pub fn paths(&self) -> &[InputFile] {
        self.paths.as_ref()
    }
    pub fn poll_interval_seconds(&self) -> u64 {
        self.poll_interval_seconds
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputFile {
    pub path: String,
    pub format: InputFileFormat,
}

impl InputFile {
    pub fn path(&self) -> &str {
        self.path.as_ref()
    }
    pub fn format(&self) -> &InputFileFormat {
        &self.format
    }
}

#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub enum InputFileFormat {
    /// Pmacct custom maps format
    PmacctMaps {
        id: IE,

        #[serde(default = "default_weight")]
        weight: u8,
    },

    /// JSON-serialized upsert messages
    JSONUpserts,
}

pub enum LineChangeType {
    Added,
    Removed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_flow_pkt::ie::IE;
    use serde_yaml;

    #[test]
    fn test_filesconfig_serialize_to_yaml() {
        let config = FilesConfig {
            poll_interval_seconds: 45,
            paths: vec![
                InputFile {
                    path: "/tmp/file1.map".to_string(),
                    format: InputFileFormat::PmacctMaps {
                        id: IE::mplsVpnRouteDistinguisher,
                        weight: 42,
                    },
                },
                InputFile {
                    path: "/tmp/file2.map".to_string(),
                    format: InputFileFormat::PmacctMaps {
                        id: IE::samplerRandomInterval,
                        weight: 200,
                    },
                },
                InputFile {
                    path: "/tmp/file3.map".to_string(),
                    format: InputFileFormat::PmacctMaps {
                        id: IE::samplerRandomInterval,
                        weight: default_weight(),
                    },
                },
                InputFile {
                    path: "/tmp/file4.jsonl".to_string(),
                    format: InputFileFormat::JSONUpserts,
                },
            ],
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        let expected = r#"poll_interval_seconds: 45
paths:
- path: /tmp/file1.map
  format: !PmacctMaps
    id: mplsVpnRouteDistinguisher
    weight: 42
- path: /tmp/file2.map
  format: !PmacctMaps
    id: samplerRandomInterval
    weight: 200
- path: /tmp/file3.map
  format: !PmacctMaps
    id: samplerRandomInterval
    weight: 128
- path: /tmp/file4.jsonl
  format: JSONUpserts
"#;
        assert_eq!(yaml, expected);
    }

    #[test]
    fn test_filesconfig_deserialize_from_yaml() {
        let yaml = r#"paths:
- path: /tmp/file1.map
  format: !PmacctMaps
    id: mplsVpnRouteDistinguisher
- path: /tmp/file2.map
  format: !PmacctMaps
    id: samplerRandomInterval
    weight: 200
- path: /tmp/file3.map
  format: !PmacctMaps
    id: samplerRandomInterval
    weight: 32
- path: /tmp/file4.jsonl
  format: !JSONUpserts
"#;

        let config: FilesConfig = serde_yaml::from_str(yaml).unwrap();

        let expected = FilesConfig {
            poll_interval_seconds: 30,
            paths: vec![
                InputFile {
                    path: "/tmp/file1.map".to_string(),
                    format: InputFileFormat::PmacctMaps {
                        id: IE::mplsVpnRouteDistinguisher,
                        weight: 128,
                    },
                },
                InputFile {
                    path: "/tmp/file2.map".to_string(),
                    format: InputFileFormat::PmacctMaps {
                        id: IE::samplerRandomInterval,
                        weight: 200,
                    },
                },
                InputFile {
                    path: "/tmp/file3.map".to_string(),
                    format: InputFileFormat::PmacctMaps {
                        id: IE::samplerRandomInterval,
                        weight: 32,
                    },
                },
                InputFile {
                    path: "/tmp/file4.jsonl".to_string(),
                    format: InputFileFormat::JSONUpserts,
                },
            ],
        };

        assert_eq!(config, expected);
    }
}
