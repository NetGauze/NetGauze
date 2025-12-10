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
use crate::inputs::{
    InputProcessingError,
    files::{
        LineChangeType,
        formats::pmacct_maps::{PmacctMapEntry, PmacctMapEntryScope, PmacctMapError},
    },
};
use netgauze_flow_pkt::ie::{Field, HasIE, IE, netgauze};
use std::{net::IpAddr, path::Path};

/// **Generic Files Line Handler Trait**
///
/// Trait for handling files with different formats
pub trait FilesLineHandler<T>: Send + Sync + 'static {
    /// Parse a raw line into a vector of output type `T`
    fn handle_line(
        &mut self,
        line: &str,
        change_type: LineChangeType,
        path: &Path,
    ) -> Result<Vec<T>, InputProcessingError>;
}

/// **Flow Upserts Handler**
///
/// Handler for json-line input files with
/// [`crate::flow::enrichment::UpsertPayload`] format, such as:
///
/// ```jsonl
/// {"ip":"::ffff:192.168.100.6","scope":{"obs_domain_id":1999104,"scope_fields":[{"selectorId":27}]},"weight":200,"fields":[{"virtualStationName":"STATION-NAME"}]}
/// {"ip":"::ffff:192.168.100.6","scope":{"obs_domain_id":1999104,"scope_fields":[{"selectorId":27}]},"weight":210,"fields":[{"applicationName":"APP-NAME"}]}
/// {"ip":"::ffff:192.168.100.6","scope":{"obs_domain_id":1999104,"scope_fields":[{"ingressInterface":7000}]},"weight":254,"fields":[{"observationPointType":"Portchannel"}]}
/// ```
#[derive(Debug, Clone)]
pub struct FlowUpsertsHandler;

impl FlowUpsertsHandler {
    pub fn new() -> Self {
        Self
    }
}

impl FilesLineHandler<crate::flow::enrichment::EnrichmentOperation> for FlowUpsertsHandler {
    fn handle_line(
        &mut self,
        line: &str,
        change_type: LineChangeType,
        _path: &Path,
    ) -> Result<Vec<crate::flow::enrichment::EnrichmentOperation>, InputProcessingError> {
        // Parse JSON into UpsertPayload
        let upsert: crate::flow::enrichment::UpsertPayload =
            serde_json::from_str(line).map_err(|e| InputProcessingError::JsonError {
                context: format!("FlowUpsertsHandler (line '{line}')"),
                reason: e.to_string(),
            })?;

        if !upsert.validate() {
            return Ok(vec![]); // drop useless no-field op
        }

        match change_type {
            LineChangeType::Added => {
                Ok(vec![crate::flow::enrichment::EnrichmentOperation::Upsert(
                    upsert,
                )])
            }
            LineChangeType::Removed => {
                // If line was removed: generate delete payload from upsert payload (one-way
                // conversion)
                let delete: crate::flow::enrichment::DeletePayload = upsert.into();
                Ok(vec![crate::flow::enrichment::EnrichmentOperation::Delete(
                    delete,
                )])
            }
        }
    }
}

impl FilesLineHandler<crate::yang_push::EnrichmentOperation> for FlowUpsertsHandler {
    fn handle_line(
        &mut self,
        _line: &str,
        _change_type: LineChangeType,
        _path: &Path,
    ) -> Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> {
        Err(InputProcessingError::UnsupportedOperation {
            handler: "FlowUpsertsHandler".to_string(),
            reason: "This handler only supports flow::enrichment::EnrichmentOperation".to_string(),
        })
    }
}

/// **Yang-Push Upserts Handler**
///
/// Handler for json-line input files with [`crate::yang_push::UpsertPayload`]
/// format, such as:
///
/// ```jsonl
/// {"ip":"1.1.1.1","weight":29, "labels":[{"name":"node_id","string-value":"n1"},{"name":"platform_id","string-value":"p1"}]}
/// ```
pub struct YangPushUpsertsHandler;

impl YangPushUpsertsHandler {
    pub fn new() -> Self {
        Self
    }
}
impl FilesLineHandler<crate::yang_push::EnrichmentOperation> for YangPushUpsertsHandler {
    fn handle_line(
        &mut self,
        line: &str,
        change_type: LineChangeType,
        _path: &Path,
    ) -> Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> {
        // Parse JSON into UpsertPayload
        let upsert: crate::yang_push::UpsertPayload =
            serde_json::from_str(line).map_err(|e| InputProcessingError::JsonError {
                context: format!("YangPushUpsertsHandler (line '{line}')"),
                reason: e.to_string(),
            })?;

        if !upsert.validate() {
            return Ok(vec![]); // drop useless no-field op
        }

        match change_type {
            LineChangeType::Added => {
                Ok(vec![crate::yang_push::EnrichmentOperation::Upsert(upsert)])
            }
            LineChangeType::Removed => {
                // If line was removed: generate delete payload from upsert payload (one-way
                // conversion)
                let delete: crate::yang_push::DeletePayload = upsert.into();
                Ok(vec![crate::yang_push::EnrichmentOperation::Delete(delete)])
            }
        }
    }
}

impl FilesLineHandler<crate::flow::enrichment::EnrichmentOperation> for YangPushUpsertsHandler {
    fn handle_line(
        &mut self,
        _line: &str,
        _change_type: LineChangeType,
        _path: &Path,
    ) -> Result<Vec<crate::flow::enrichment::EnrichmentOperation>, InputProcessingError> {
        Err(InputProcessingError::UnsupportedOperation {
            handler: "YangPushUpsertsHandler".to_string(),
            reason: "This handler only supports yang_push::EnrichmentOperation".to_string(),
        })
    }
}

/// **Pmacct Maps Handler**
///
/// Handler for line input files with [`PmacctMapEntry`] format, such as:
///
/// ```txt
/// ! Example flow2rd map
/// id=0:6837:1054 ip=::ffff:192.168.100.6 mpls_vpn_id=18
/// id=2:4200137808:1003 ip=::ffff:192.168.100.6 in=537
/// id=2:4200137808:1002 ip=::ffff:192.168.100.6 out=537
/// ```
#[derive(Debug, Clone)]
pub struct PmacctMapsHandler {
    ie: IE,
    weight: u8,
}

impl PmacctMapsHandler {
    pub fn new(id: IE, weight: u8) -> Self {
        Self { ie: id, weight }
    }
    pub fn ie(&self) -> &IE {
        &self.ie
    }
    pub fn weight(&self) -> u8 {
        self.weight
    }
}

impl FilesLineHandler<crate::flow::enrichment::EnrichmentOperation> for PmacctMapsHandler {
    fn handle_line(
        &mut self,
        line: &str,
        change_type: LineChangeType,
        _path: &Path,
    ) -> Result<Vec<crate::flow::enrichment::EnrichmentOperation>, InputProcessingError> {
        match PmacctMapEntry::parse_line(line) {
            Ok(Some(entry)) => {
                let op_type = match change_type {
                    LineChangeType::Added => {
                        crate::flow::enrichment::EnrichmentOperationType::Upsert
                    }
                    LineChangeType::Removed => {
                        crate::flow::enrichment::EnrichmentOperationType::Delete
                    }
                };

                let ops = entry
                    .try_into_enrichment_operations(self.ie(), op_type, self.weight())
                    .map_err(|e| InputProcessingError::ConversionError {
                        context: format!("PmacctMapsHandler (line '{line}')"),
                        reason: e.to_string(),
                    })?
                    .into_iter()
                    .filter(|op| op.validate()) // drop useless no-field ops
                    .collect();

                Ok(ops)
            }
            Ok(None) => Ok(vec![]), // comment or empty line
            Err(e) => Err(InputProcessingError::InvalidFormat {
                context: format!("PmacctMapsHandler (line '{line}')"),
                reason: e.to_string(),
            }),
        }
    }
}

impl FilesLineHandler<crate::yang_push::EnrichmentOperation> for PmacctMapsHandler {
    fn handle_line(
        &mut self,
        _line: &str,
        _change_type: LineChangeType,
        _path: &Path,
    ) -> Result<Vec<crate::yang_push::EnrichmentOperation>, InputProcessingError> {
        Err(InputProcessingError::UnsupportedOperation {
            handler: "PmacctMapsHandler".to_string(),
            reason: "This handler only supports flow::enrichment::EnrichmentOperation".to_string(),
        })
    }
}

/// Helper function to create an EnrichmentOperation for a single field
/// based on Scope, Weight, and EnrichmentOperationType
fn create_operation(
    ip: IpAddr,
    scope: crate::flow::enrichment::Scope,
    weight: crate::flow::enrichment::Weight,
    field: Field,
    op_type: crate::flow::enrichment::EnrichmentOperationType,
) -> crate::flow::enrichment::EnrichmentOperation {
    match op_type {
        crate::flow::enrichment::EnrichmentOperationType::Upsert => {
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip,
                    scope,
                    weight,
                    fields: vec![field],
                },
            )
        }
        crate::flow::enrichment::EnrichmentOperationType::Delete => {
            crate::flow::enrichment::EnrichmentOperation::Delete(
                crate::flow::enrichment::DeletePayload {
                    ip,
                    scope,
                    weight,
                    ies: vec![field.ie()],
                },
            )
        }
    }
}

impl PmacctMapEntry {
    /// Convert PmacctMapEntry to EnrichmentOperation(s)
    pub fn try_into_enrichment_operations(
        self,
        ie: &IE,
        op_type: crate::flow::enrichment::EnrichmentOperationType,
        weight: crate::flow::enrichment::Weight,
    ) -> Result<Vec<crate::flow::enrichment::EnrichmentOperation>, PmacctMapError> {
        let ip = self.ip();
        let id_field = Self::parse_field_from_string(ie, self.id())?;

        let operations = match self.into_scope() {
            Some(PmacctMapEntryScope::In(in_iface)) => {
                let ingress_field = if let Field::mplsVpnRouteDistinguisher(rd) = id_field {
                    Field::NetGauze(netgauze::Field::ingressMplsVpnRouteDistinguisher(rd))
                } else {
                    id_field
                };

                vec![create_operation(
                    ip,
                    crate::flow::enrichment::Scope::new(
                        0,
                        Some(vec![Field::ingressInterface(in_iface)]),
                    ),
                    weight,
                    ingress_field,
                    op_type,
                )]
            }
            Some(PmacctMapEntryScope::Out(out_iface)) => {
                let egress_field = if let Field::mplsVpnRouteDistinguisher(rd) = id_field {
                    Field::NetGauze(netgauze::Field::egressMplsVpnRouteDistinguisher(rd))
                } else {
                    id_field
                };

                vec![create_operation(
                    ip,
                    crate::flow::enrichment::Scope::new(
                        0,
                        Some(vec![Field::egressInterface(out_iface)]),
                    ),
                    weight,
                    egress_field,
                    op_type,
                )]
            }
            Some(PmacctMapEntryScope::MplsVpnId(vrfid)) => {
                let (ingress_field, egress_field) =
                    if let Field::mplsVpnRouteDistinguisher(rd) = id_field {
                        (
                            Field::NetGauze(netgauze::Field::ingressMplsVpnRouteDistinguisher(
                                rd.clone(),
                            )),
                            Field::NetGauze(netgauze::Field::egressMplsVpnRouteDistinguisher(rd)),
                        )
                    } else {
                        (id_field.clone(), id_field)
                    };

                vec![
                    create_operation(
                        ip,
                        crate::flow::enrichment::Scope::new(
                            0,
                            Some(vec![Field::ingressVRFID(vrfid)]),
                        ),
                        weight,
                        ingress_field,
                        op_type,
                    ),
                    create_operation(
                        ip,
                        crate::flow::enrichment::Scope::new(
                            0,
                            Some(vec![Field::egressVRFID(vrfid)]),
                        ),
                        weight,
                        egress_field,
                        op_type,
                    ),
                ]
            }
            None => {
                vec![create_operation(
                    ip,
                    crate::flow::enrichment::Scope::new(0, None),
                    weight,
                    id_field,
                    op_type,
                )]
            }
        };

        Ok(operations)
    }
}

#[cfg(test)]
mod tests {
    use crate::inputs::files::{
        handlers::{FlowUpsertsHandler, PmacctMapsHandler, YangPushUpsertsHandler},
        processor::{FileProcessor, FileProcessorCallback},
    };
    use netgauze_flow_pkt::ie::{Field, IE, netgauze};
    use netgauze_yang_push::model::telemetry::{Label, LabelValue};
    use std::cell::RefCell;
    use tempfile::NamedTempFile;
    use tokio::fs;

    // ** Tests with crate::flow::enrichment::EnrichmentOperation for Flow ** //

    #[tokio::test]
    async fn test_first_time_processing_json_upserts() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test-app"}]}
{"ip":"192.168.1.2","scope":{"obs_domain_id":42},"weight":10,"fields":[{"samplerRandomInterval":100}]}"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = FlowUpsertsHandler::new();
        let mut result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result.sort();

        let mut expected = vec![
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.1.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(0, None),
                    weight: 5,
                    fields: vec![Field::applicationName("test-app".to_string().into())],
                },
            ),
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.1.2".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(42, None),
                    weight: 10,
                    fields: vec![Field::samplerRandomInterval(100)],
                },
            ),
        ];
        expected.sort();

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_incremental_processing_json_upserts() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        let mut handler = FlowUpsertsHandler::new();

        // First processing - initial content
        let content1 = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test-app"}]}"#;
        fs::write(&path, content1).await.unwrap();

        let expected1 = vec![crate::flow::enrichment::EnrichmentOperation::Upsert(
            crate::flow::enrichment::UpsertPayload {
                ip: "192.168.1.1".parse().unwrap(),
                scope: crate::flow::enrichment::Scope::new(0, None),
                weight: 5,
                fields: vec![Field::applicationName("test-app".to_string().into())],
            },
        )];
        let result1 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        assert_eq!(expected1, result1);

        // Second processing - add one line, remove one line
        let content2 = r#"{"ip":"192.168.1.2","scope":{"obs_domain_id":42},"weight":10,"fields":[{"samplerRandomInterval":100}]}"#;
        fs::write(&path, content2).await.unwrap();

        let mut result2 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result2.sort();

        let mut expected2 = vec![
            crate::flow::enrichment::EnrichmentOperation::Delete(
                crate::flow::enrichment::DeletePayload {
                    ip: "192.168.1.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(0, None),
                    weight: 5,
                    ies: vec![IE::applicationName],
                },
            ),
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.1.2".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(42, None),
                    weight: 10,
                    fields: vec![Field::samplerRandomInterval(100)],
                },
            ),
        ];
        expected2.sort();

        assert_eq!(expected2, result2);
    }

    #[tokio::test]
    async fn test_pmacct_maps_format_iface_scope() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"id=0:6837:1054 ip=192.168.100.1 in=537
id=2:4200137808:1003 ip=192.168.100.1 out=127"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = PmacctMapsHandler::new(IE::mplsVpnRouteDistinguisher, 32);
        let mut result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        result.sort();

        let mut expected = vec![
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.100.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(
                        0,
                        Some(vec![Field::ingressInterface(537)]),
                    ),
                    weight: 32,
                    fields: vec![Field::NetGauze(
                        netgauze::Field::ingressMplsVpnRouteDistinguisher(
                            [0, 0, 26, 181, 0, 0, 4, 30].into(),
                        ),
                    )],
                },
            ),
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.100.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(
                        0,
                        Some(vec![Field::egressInterface(127)]),
                    ),
                    weight: 32,
                    fields: vec![Field::NetGauze(
                        netgauze::Field::egressMplsVpnRouteDistinguisher(
                            [0, 2, 250, 89, 4, 80, 3, 235].into(),
                        ),
                    )],
                },
            ),
        ];
        expected.sort();

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_pmacct_maps_format_mpls_vpn_id_scope() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = "id=0:6837:1054 ip=192.168.100.1 mpls_vpn_id=18";
        fs::write(&path, content).await.unwrap();

        let mut handler = PmacctMapsHandler::new(IE::mplsVpnRouteDistinguisher, 32);
        let mut result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result.sort();

        // Should generate two operations: one for ingress VRF, one for egress VRF
        assert_eq!(result.len(), 2);

        let mut expected = vec![
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.100.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(
                        0,
                        Some(vec![Field::ingressVRFID(18)]),
                    ),
                    weight: 32,
                    fields: vec![Field::NetGauze(
                        netgauze::Field::ingressMplsVpnRouteDistinguisher(
                            [0, 0, 26, 181, 0, 0, 4, 30].into(),
                        ),
                    )],
                },
            ),
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.100.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(
                        0,
                        Some(vec![Field::egressVRFID(18)]),
                    ),
                    weight: 32,
                    fields: vec![Field::NetGauze(
                        netgauze::Field::egressMplsVpnRouteDistinguisher(
                            [0, 0, 26, 181, 0, 0, 4, 30].into(),
                        ),
                    )],
                },
            ),
        ];
        expected.sort();

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_comment_filtering() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"# This is a comment
{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test-app"}]}
// Another comment
! Yet another comment
{"ip":"192.168.1.2","scope":{"obs_domain_id":42},"weight":10,"fields":[{"samplerRandomInterval":100}]}"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = FlowUpsertsHandler::new();
        let mut result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result.sort();

        let mut expected = vec![
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.1.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(0, None),
                    weight: 5,
                    fields: vec![Field::applicationName("test-app".to_string().into())],
                },
            ),
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.1.2".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(42, None),
                    weight: 10,
                    fields: vec![Field::samplerRandomInterval(100)],
                },
            ),
        ];
        expected.sort();

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_malformed_json_handling() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test-app"}]}
{invalid json line}
{"ip":"192.168.1.2","scope":{"obs_domain_id":42},"weight":10,"fields":[{"samplerRandomInterval":100}]}"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = FlowUpsertsHandler::new();
        let mut result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result.sort();

        // Should only process valid JSON lines, skipping malformed ones
        let mut expected = vec![
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.1.1".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(0, None),
                    weight: 5,
                    fields: vec![Field::applicationName("test-app".to_string().into())],
                },
            ),
            crate::flow::enrichment::EnrichmentOperation::Upsert(
                crate::flow::enrichment::UpsertPayload {
                    ip: "192.168.1.2".parse().unwrap(),
                    scope: crate::flow::enrichment::Scope::new(42, None),
                    weight: 10,
                    fields: vec![Field::samplerRandomInterval(100)],
                },
            ),
        ];
        expected.sort();

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_no_changes_processing() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test-app"}]}"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = FlowUpsertsHandler::new();

        // First processing
        let result1 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        let expected1 = vec![crate::flow::enrichment::EnrichmentOperation::Upsert(
            crate::flow::enrichment::UpsertPayload {
                ip: "192.168.1.1".parse().unwrap(),
                scope: crate::flow::enrichment::Scope::new(0, None),
                weight: 5,
                fields: vec![Field::applicationName("test-app".to_string().into())],
            },
        )];
        assert_eq!(expected1, result1);

        // Second processing with same content
        let result2 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        // Should return empty vec since no changes
        let expected2: Vec<crate::flow::enrichment::EnrichmentOperation> = vec![];
        assert_eq!(expected2, result2);
    }

    #[tokio::test]
    async fn test_error_callback_with_invalid_lines() {
        let mut processor = FileProcessor::<crate::flow::enrichment::EnrichmentOperation>::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"missing": "required_fields"}
{invalid json}"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = FlowUpsertsHandler::new();

        // Use RefCell for interior mutability of callback closure
        let captured_errors = RefCell::new(Vec::new());
        let error_callback = |error: &str| {
            captured_errors.borrow_mut().push(error.to_string());
        };
        let result = processor
            .process_file_changes(&path, &mut handler, Some(error_callback))
            .await
            .unwrap();

        // Should return no operations due to all invalid lines
        assert!(result.is_empty());

        // Should capture exactly 2 errors
        let errors = captured_errors.borrow();
        assert_eq!(errors.len(), 2);

        // Verify specific error content
        assert!(errors[0].contains("missing field `ip` at line"));
        assert!(errors[1].contains("key must be a string at line"));
    }

    // ** Tests with crate::yang_push::EnrichmentOperation for Yang-Push ** //

    #[tokio::test]
    async fn test_yang_push_first_time_processing() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"1.1.1.1","weight":29,"labels":[{"name":"node_id","string-value":"n1"},{"name":"platform_id","string-value":"p1"}]}
{"ip":"2.2.2.2","weight":30,"labels":[{"name":"node_id","string-value":"n2"}]}"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = YangPushUpsertsHandler::new();
        let result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        let expected = vec![
            crate::yang_push::EnrichmentOperation::Upsert(crate::yang_push::UpsertPayload {
                ip: "1.1.1.1".parse().unwrap(),
                weight: 29,
                labels: vec![
                    Label::new(
                        "node_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "n1".to_string(),
                        },
                    ),
                    Label::new(
                        "platform_id".to_string(),
                        LabelValue::StringValue {
                            string_value: "p1".to_string(),
                        },
                    ),
                ],
            }),
            crate::yang_push::EnrichmentOperation::Upsert(crate::yang_push::UpsertPayload {
                ip: "2.2.2.2".parse().unwrap(),
                weight: 30,
                labels: vec![Label::new(
                    "node_id".to_string(),
                    LabelValue::StringValue {
                        string_value: "n2".to_string(),
                    },
                )],
            }),
        ];

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_yang_push_incremental_processing() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        let mut handler = YangPushUpsertsHandler::new();

        // First processing - initial content
        let content1 =
            r#"{"ip":"1.1.1.1","weight":29,"labels":[{"name":"node_id","string-value":"n1"}]}"#;
        fs::write(&path, content1).await.unwrap();

        let expected1 = vec![crate::yang_push::EnrichmentOperation::Upsert(
            crate::yang_push::UpsertPayload {
                ip: "1.1.1.1".parse().unwrap(),
                weight: 29,
                labels: vec![Label::new(
                    "node_id".to_string(),
                    LabelValue::StringValue {
                        string_value: "n1".to_string(),
                    },
                )],
            },
        )];
        let result1 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        assert_eq!(expected1, result1);

        // Second processing - add one line, remove one line
        let content2 =
            r#"{"ip":"2.2.2.2","weight":30,"labels":[{"name":"platform_id","string-value":"p2"}]}"#;
        fs::write(&path, content2).await.unwrap();

        let result2 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        let expected2 = vec![
            crate::yang_push::EnrichmentOperation::Delete(crate::yang_push::DeletePayload {
                ip: "1.1.1.1".parse().unwrap(),
                weight: 29,
                label_names: vec!["node_id".to_string()],
            }),
            crate::yang_push::EnrichmentOperation::Upsert(crate::yang_push::UpsertPayload {
                ip: "2.2.2.2".parse().unwrap(),
                weight: 30,
                labels: vec![Label::new(
                    "platform_id".to_string(),
                    LabelValue::StringValue {
                        string_value: "p2".to_string(),
                    },
                )],
            }),
        ];

        assert_eq!(expected2, result2);
    }

    #[tokio::test]
    async fn test_yang_push_no_changes_processing() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content =
            r#"{"ip":"1.1.1.1","weight":29,"labels":[{"name":"node_id","string-value":"n1"}]}"#;
        fs::write(&path, content).await.unwrap();

        let mut handler = YangPushUpsertsHandler::new();

        // First processing
        let result1 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();
        let expected1 = vec![crate::yang_push::EnrichmentOperation::Upsert(
            crate::yang_push::UpsertPayload {
                ip: "1.1.1.1".parse().unwrap(),
                weight: 29,
                labels: vec![Label::new(
                    "node_id".to_string(),
                    LabelValue::StringValue {
                        string_value: "n1".to_string(),
                    },
                )],
            },
        )];
        assert_eq!(expected1, result1);

        // Second processing with same content
        let result2 = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        let expected2: Vec<crate::yang_push::EnrichmentOperation> = vec![];
        assert_eq!(expected2, result2);
    }

    #[tokio::test]
    async fn test_yang_push_anydata_value_labels() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"1.1.1.1","weight":29,"labels":[{"name":"metadata","anydata-values":{"key1":"value1","key2":42}}]}"#;
        fs::write(&path, content).await.unwrap();

        let mut handler = YangPushUpsertsHandler::new();
        let result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        let expected = vec![crate::yang_push::EnrichmentOperation::Upsert(
            crate::yang_push::UpsertPayload {
                ip: "1.1.1.1".parse().unwrap(),
                weight: 29,
                labels: vec![Label::new(
                    "metadata".to_string(),
                    LabelValue::AnydataValue {
                        anydata_values: serde_json::json!({"key1": "value1", "key2": 42}),
                    },
                )],
            },
        )];

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_yang_push_empty_labels_filtering() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        // Line with empty labels array should be filtered out
        let content = r#"{"ip":"1.1.1.1","weight":29,"labels":[]}
{"ip":"2.2.2.2","weight":30,"labels":[{"name":"node_id","string-value":"n2"}]}"#;

        fs::write(&path, content).await.unwrap();

        let mut handler = YangPushUpsertsHandler::new();
        let result = processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        let expected = vec![crate::yang_push::EnrichmentOperation::Upsert(
            crate::yang_push::UpsertPayload {
                ip: "2.2.2.2".parse().unwrap(),
                weight: 30,
                labels: vec![Label::new(
                    "node_id".to_string(),
                    LabelValue::StringValue {
                        string_value: "n2".to_string(),
                    },
                )],
            },
        )];

        assert_eq!(expected, result);
    }
}
