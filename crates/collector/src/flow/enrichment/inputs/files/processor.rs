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

//! File processing module
//!
//! This module provides functionality to monitor and process files containing
//! enrichment data, tracking line changes and generating appropriate
//! enrichment operations.
use crate::flow::enrichment::{
    inputs::files::{formats::PmacctMapEntry, InputFileFormat},
    EnrichmentOperation, EnrichmentOperationType, EnrichmentPayload,
};
use rustc_hash::{FxBuildHasher, FxHashSet};
use std::path::PathBuf;
use tokio::fs;
use tracing::debug;

/// Line processing error callback type
pub type FileProcessorCallback = fn(&str, &str);

/// `FileProcessor` maintains an internal cache of previously processed file
/// content to efficiently detect additions, modifications, and deletions. It
/// uses a line-based diffing algorithm to identify changes and generates
/// corresponding enrichment operations.
///
/// # Features
/// - Incremental processing with change detection
/// - Extensible support for multiple file formats (PmacctMaps, JSONUpserts)
/// - Comment filtering (lines starting with `#`, `//`, or `!`)
/// - Memory-efficient hash-based line storage
pub struct FileProcessor {
    hashed_lines: rustc_hash::FxHashMap<PathBuf, FxHashSet<Box<str>>>,
}

impl FileProcessor {
    pub fn new() -> Self {
        Self {
            hashed_lines: rustc_hash::FxHashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Converts lines of text into EnrichmentOperations based on the specified
    /// format. Filters out operations with empty or null fields to maintain
    /// declarative state consistency.
    fn process_lines_into_ops<F>(
        &self,
        lines: &[&str],
        format: &InputFileFormat,
        path: &PathBuf,
        op_type: EnrichmentOperationType,
        line_error_callback: Option<F>,
    ) -> Vec<EnrichmentOperation>
    where
        F: Fn(&str, &str) + Clone, // (line, err)
    {
        let mut ops = Vec::new();

        match format {
            InputFileFormat::PmacctMaps { id, weight } => {
                debug!(
                    "Processing PmacctMaps(id={id}, weight={weight}) file (path: {path:?}) for {op_type} operations"
                );

                for &line in lines {
                    match PmacctMapEntry::parse_line(line) {
                        Ok(Some(entry)) => {
                            match entry.try_into_enrichment_operations(id, op_type, *weight) {
                                Ok(line_ops) => ops.extend(line_ops),
                                Err(e) => {
                                    if let Some(ref callback) = line_error_callback {
                                        callback(line, &e.to_string());
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            // Empty line or comment, skip silently
                        }
                        Err(e) => {
                            if let Some(ref callback) = line_error_callback {
                                callback(line, &e.to_string());
                            }
                        }
                    }
                }
            }
            InputFileFormat::JSONUpserts => {
                debug!("Processing JSONUpserts file (path: {path:?}) for {op_type} operations");

                for &line in lines {
                    match serde_json::from_str::<EnrichmentPayload>(line) {
                        Ok(payload) => {
                            ops.push((payload, op_type).into());
                        }
                        Err(e) => {
                            if let Some(ref callback) = line_error_callback {
                                callback(line, &e.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Clean up - remove ops with payload having None or empty fields
        ops.retain(|op| match &op.payload().fields {
            Some(fields) => !fields.is_empty(),
            None => false,
        });

        ops
    }

    /// Processes a file comparing with cached content to detect added/removed
    /// lines, and generates corresponding upsert/delete operations.
    pub async fn process_file_changes<F>(
        &mut self,
        path: &PathBuf,
        format: &InputFileFormat,
        line_error_callback: Option<F>,
    ) -> anyhow::Result<Vec<EnrichmentOperation>>
    where
        F: Fn(&str, &str) + Clone,
    {
        let mut ops = Vec::new();

        let content = fs::read_to_string(path).await?;
        let lines: FxHashSet<Box<str>> = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.starts_with("#") && !l.starts_with("//") && !l.starts_with("!"))
            .map(|l| l.into())
            .collect();

        let (added, removed) = if let Some(previous_lines) = self.hashed_lines.get(path) {
            let added: Vec<&str> = lines
                .difference(previous_lines)
                .map(|l| l.as_ref())
                .collect();

            let removed: Vec<&str> = previous_lines
                .difference(&lines)
                .map(|l| l.as_ref())
                .collect();

            (added, removed)
        } else {
            // First time processing this file - all lines are added
            let added: Vec<&str> = lines.iter().map(|l| l.as_ref()).collect();
            (added, Vec::new())
        };

        // Create delete operations from removed lines
        ops.extend(self.process_lines_into_ops(
            &removed,
            format,
            path,
            EnrichmentOperationType::Delete,
            line_error_callback.clone(),
        ));

        // Create upsert operations from added lines
        ops.extend(self.process_lines_into_ops(
            &added,
            format,
            path,
            EnrichmentOperationType::Upsert,
            line_error_callback,
        ));

        // Update the stored hash set for future comparisons
        self.hashed_lines.insert(path.clone(), lines);
        Ok(ops)
    }

    /// Purges all cached entries for a file and returns delete operations.
    /// This removes the file from internal cache and generates delete
    /// operations for all previously cached lines.
    pub fn purge_file<F>(
        &mut self,
        path: &PathBuf,
        format: &InputFileFormat,
        line_error_callback: Option<F>,
    ) -> Vec<EnrichmentOperation>
    where
        F: Fn(&str, &str) + Clone,
    {
        let delete_ops = if let Some(cached_lines) = self.hashed_lines.get(path) {
            let lines: Vec<&str> = cached_lines.iter().map(|l| l.as_ref()).collect();
            self.process_lines_into_ops(
                &lines,
                format,
                path,
                EnrichmentOperationType::Delete,
                line_error_callback,
            )
        } else {
            vec![]
        };

        self.hashed_lines.remove(path);
        delete_ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::enrichment::{EnrichmentOperation, EnrichmentPayload, Scope};
    use netgauze_flow_pkt::ie::{netgauze, Field, IE};
    use std::cell::RefCell;
    use tempfile::NamedTempFile;
    use tokio::fs;

    #[tokio::test]
    async fn test_first_time_processing_json_upserts() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test-app"}]}
{"ip":"192.168.1.2","scope":{"obs_domain_id":42},"weight":10,"fields":[{"samplerRandomInterval":100}]}"#;

        fs::write(&path, content).await.unwrap();

        let format = InputFileFormat::JSONUpserts;
        let mut result = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result.sort();

        let mut expected = vec![
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.1.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 5,
                fields: Some(vec![Field::applicationName("test-app".to_string().into())]),
            }),
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.1.2".parse().unwrap(),
                scope: Scope::new(42, None),
                weight: 10,
                fields: Some(vec![Field::samplerRandomInterval(100)]),
            }),
        ];
        expected.sort();

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_incremental_processing_json_upserts() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        let format = InputFileFormat::JSONUpserts;

        // First processing - initial content
        let content1 = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test-app"}]}"#;
        fs::write(&path, content1).await.unwrap();

        let expected1 = vec![EnrichmentOperation::Upsert(EnrichmentPayload {
            ip: "192.168.1.1".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 5,
            fields: Some(vec![Field::applicationName("test-app".to_string().into())]),
        })];
        let result1 = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();
        assert_eq!(expected1, result1);

        // Second processing - add one line, remove one line
        let content2 = r#"{"ip":"192.168.1.2","scope":{"obs_domain_id":42},"weight":10,"fields":[{"samplerRandomInterval":100}]}"#;
        fs::write(&path, content2).await.unwrap();

        let mut result2 = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result2.sort();

        let mut expected2 = vec![
            EnrichmentOperation::Delete(EnrichmentPayload {
                ip: "192.168.1.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 5,
                fields: Some(vec![Field::applicationName("test-app".to_string().into())]),
            }),
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.1.2".parse().unwrap(),
                scope: Scope::new(42, None),
                weight: 10,
                fields: Some(vec![Field::samplerRandomInterval(100)]),
            }),
        ];
        expected2.sort();

        assert_eq!(expected2, result2);
    }

    #[tokio::test]
    async fn test_pmacct_maps_format() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"id=0:6837:1054 ip=192.168.100.1 in=537
id=2:4200137808:1003 ip=192.168.100.1 out=127"#;

        fs::write(&path, content).await.unwrap();

        let format = InputFileFormat::PmacctMaps {
            id: IE::mplsVpnRouteDistinguisher,
            weight: 32,
        };
        let mut result = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();

        result.sort();

        let mut expected = vec![
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.100.1".parse().unwrap(),
                scope: Scope::new(0, Some(vec![Field::ingressInterface(537)])),
                weight: 32,
                fields: Some(vec![Field::NetGauze(
                    netgauze::Field::ingressMplsVpnRouteDistinguisher(
                        [0, 0, 26, 181, 0, 0, 4, 30].into(),
                    ),
                )]),
            }),
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.100.1".parse().unwrap(),
                scope: Scope::new(0, Some(vec![Field::egressInterface(127)])),
                weight: 32,
                fields: Some(vec![Field::NetGauze(
                    netgauze::Field::egressMplsVpnRouteDistinguisher(
                        [0, 2, 250, 89, 4, 80, 3, 235].into(),
                    ),
                )]),
            }),
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

        let format = InputFileFormat::JSONUpserts;
        let mut result = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result.sort();

        let mut expected = vec![
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.1.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 5,
                fields: Some(vec![Field::applicationName("test-app".to_string().into())]),
            }),
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.1.2".parse().unwrap(),
                scope: Scope::new(42, None),
                weight: 10,
                fields: Some(vec![Field::samplerRandomInterval(100)]),
            }),
        ];
        expected.sort();

        assert_eq!(expected, result);
    }

    #[tokio::test]
    async fn test_empty_fields_filtering() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[]}
{"ip":"192.168.1.2","scope":{"obs_domain_id":42},"weight":10}
{"ip":"192.168.1.3","scope":{"obs_domain_id":0},"weight":15,"fields":[{"applicationName":"valid-app"}]}"#;

        fs::write(&path, content).await.unwrap();

        let format = InputFileFormat::JSONUpserts;
        let result = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();

        let expected = vec![EnrichmentOperation::Upsert(EnrichmentPayload {
            ip: "192.168.1.3".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 15,
            fields: Some(vec![Field::applicationName("valid-app".to_string().into())]),
        })];

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

        let format = InputFileFormat::JSONUpserts;
        let mut result = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();
        result.sort();

        // Should only process valid JSON lines, skipping malformed ones
        let mut expected = vec![
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.1.1".parse().unwrap(),
                scope: Scope::new(0, None),
                weight: 5,
                fields: Some(vec![Field::applicationName("test-app".to_string().into())]),
            }),
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "192.168.1.2".parse().unwrap(),
                scope: Scope::new(42, None),
                weight: 10,
                fields: Some(vec![Field::samplerRandomInterval(100)]),
            }),
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

        let format = InputFileFormat::JSONUpserts;

        // First processing
        let result1 = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();
        let expected1 = vec![EnrichmentOperation::Upsert(EnrichmentPayload {
            ip: "192.168.1.1".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 5,
            fields: Some(vec![Field::applicationName("test-app".to_string().into())]),
        })];
        assert_eq!(expected1, result1);

        // Second processing with same content
        let result2 = processor
            .process_file_changes(&path, &format, None::<FileProcessorCallback>)
            .await
            .unwrap();

        // Should return empty vec since no changes
        let expected2: Vec<EnrichmentOperation> = vec![];
        assert_eq!(expected2, result2);
    }

    #[tokio::test]
    async fn test_error_callback_with_invalid_lines() {
        let mut processor = FileProcessor::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"missing": "required_fields"}
{invalid json}"#;

        fs::write(&path, content).await.unwrap();

        let format = InputFileFormat::JSONUpserts;

        // Use RefCell for interior mutability of callback closure
        let captured_errors = RefCell::new(Vec::new());
        let error_callback = |line: &str, error: &str| {
            captured_errors
                .borrow_mut()
                .push((line.to_string(), error.to_string()));
        };
        let result = processor
            .process_file_changes(&path, &format, Some(error_callback))
            .await
            .unwrap();

        // Should return no operations due to all invalid lines
        assert!(result.is_empty());

        // Should capture exactly 2 errors
        let errors = captured_errors.borrow();
        assert_eq!(errors.len(), 2);

        // Verify specific error content
        assert_eq!(errors[0].0, r#"{"missing": "required_fields"}"#);
        assert!(errors[0].1.contains("missing field `ip` at line"));

        assert_eq!(errors[1].0, r#"{invalid json}"#);
        assert!(errors[1].1.contains("key must be a string at line"));
    }
}
