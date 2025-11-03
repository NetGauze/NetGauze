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
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// *** Sonata Data Modeling *** //

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SonataOperation {
    #[serde(rename = "insert")]
    Insert,
    #[serde(rename = "update")]
    Update,
    #[serde(rename = "delete")]
    Delete,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SonataData {
    pub operation: SonataOperation,
    pub id_node: u32,
    pub node: Option<SonataNode>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SonataNode {
    pub hostname: String,
    #[serde(rename = "loopbackAddress")]
    pub loopback_address: IpAddr,
    pub platform: SonataPlatform,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SonataPlatform {
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_sonata_json_serialization() {
        let insert = r#"{"operation": "insert", "id_node": 13244, "node": {"hostname": "test-node", "loopbackAddress": "1.1.1.1", "managementAddress": "1.1.1.1", "function": null, "serviceId": null, "customField": null, "nameDaisyServiceTemplate": "migr_bgp_flow2rd_md5", "idNode": "dsy-nod-13244", "idPlatform": "dsy-plt-115", "isDeployed": false, "lastUpdate": "2025-02-20T16:00:53", "platform": {"name": "DAISY-PE", "contactEmail": "Daisy.Telemetry@swisscom.com", "agileOrgUrl": "https://agileorg.scapp.swisscom.com/organisation/10069/overview", "idPlatform": "dsy-plt-115"}}}"#;
        let update = r#"{"operation": "update", "id_node": 13244, "node": {"hostname": "test-node", "loopbackAddress": "1.1.1.2", "managementAddress": "1.1.1.1", "function": null, "serviceId": null, "customField": null, "nameDaisyServiceTemplate": "migr_bgp_flow2rd_md5", "idNode": "dsy-nod-13244", "idPlatform": "dsy-plt-115", "isDeployed": false, "lastUpdate": "2025-02-20T16:03:14", "platform": {"name": "DAISY-PE", "contactEmail": "Daisy.Telemetry@swisscom.com", "agileOrgUrl": "https://agileorg.scapp.swisscom.com/organisation/10069/overview", "idPlatform": "dsy-plt-115"}}}"#;
        let delete = r#"{"operation": "delete", "id_node": 13244, "node": null}"#;

        let insert_data = serde_json::from_str::<SonataData>(insert).unwrap();
        let update_data = serde_json::from_str::<SonataData>(update).unwrap();
        let delete_data = serde_json::from_str::<SonataData>(delete).unwrap();

        let expected_insert = SonataData {
            operation: SonataOperation::Insert,
            id_node: 13244,
            node: Some(SonataNode {
                hostname: "test-node".to_string(),
                loopback_address: IpAddr::from_str("1.1.1.1").unwrap(),
                platform: SonataPlatform {
                    name: "DAISY-PE".to_string(),
                },
            }),
        };
        let expected_update = SonataData {
            operation: SonataOperation::Update,
            id_node: 13244,
            node: Some(SonataNode {
                hostname: "test-node".to_string(),
                loopback_address: IpAddr::from_str("1.1.1.2").unwrap(),
                platform: SonataPlatform {
                    name: "DAISY-PE".to_string(),
                },
            }),
        };
        let expected_delete = SonataData {
            operation: SonataOperation::Delete,
            id_node: 13244,
            node: None,
        };

        assert_eq!(insert_data, expected_insert);
        assert_eq!(update_data, expected_update);
        assert_eq!(delete_data, expected_delete);
    }
}
