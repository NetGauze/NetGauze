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
use crate::inputs::{
    files::{handlers::FilesLineHandler, LineChangeType},
    InputProcessingError,
};
use rustc_hash::{FxBuildHasher, FxHashSet};
use std::path::PathBuf;
use tokio::fs;

/// Line processing error callback type
pub type FileProcessorCallback = fn(&str);

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
pub struct FileProcessor<T>
where
    T: Clone + Send + Sync + 'static,
{
    hashed_lines: rustc_hash::FxHashMap<PathBuf, FxHashSet<Box<str>>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> FileProcessor<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            hashed_lines: rustc_hash::FxHashMap::with_hasher(FxBuildHasher),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Processes a file comparing with cached content to detect added/removed
    /// lines, and generates corresponding upsert/delete operations.
    pub async fn process_file_changes<F, H>(
        &mut self,
        path: &PathBuf,
        handler: &mut H,
        line_error_callback: Option<F>,
    ) -> Result<Vec<T>, InputProcessingError>
    where
        F: Fn(&str) + Clone,
        H: FilesLineHandler<T> + ?Sized,
    {
        let mut ops = Vec::new();

        let content =
            fs::read_to_string(path)
                .await
                .map_err(|e| InputProcessingError::IoError {
                    context: format!("reading file '{}'", path.display()),
                    reason: e.to_string(),
                })?;
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

        // Handle removed lines
        for &line in &removed {
            match handler.handle_line(line, LineChangeType::Removed, path) {
                Ok(mut v) => ops.append(&mut v),
                Err(e) => {
                    if let Some(ref callback) = line_error_callback {
                        callback(&e.to_string());
                    }
                }
            }
        }

        // Handle added lines
        for &line in &added {
            match handler.handle_line(line, LineChangeType::Added, path) {
                Ok(mut v) => ops.append(&mut v),
                Err(e) => {
                    if let Some(ref callback) = line_error_callback {
                        callback(&e.to_string());
                    }
                }
            }
        }

        // Update the stored hash set for future comparisons
        self.hashed_lines.insert(path.clone(), lines);

        Ok(ops)
    }

    /// Purges all cached entries for a file and returns delete operations.
    /// This removes the file from internal cache and generates delete
    /// operations for all previously cached lines.
    pub fn purge_file<F, H>(
        &mut self,
        path: &PathBuf,
        handler: &mut H,
        line_error_callback: Option<F>,
    ) -> Vec<T>
    where
        F: Fn(&str) + Clone,
        H: FilesLineHandler<T> + ?Sized,
    {
        let mut delete_ops = Vec::new();
        if let Some(cached_lines) = self.hashed_lines.get(path) {
            for line in cached_lines.iter().map(|l| l.as_ref()) {
                match handler.handle_line(line, LineChangeType::Removed, path) {
                    Ok(mut v) => delete_ops.append(&mut v),
                    Err(e) => {
                        if let Some(ref callback) = line_error_callback {
                            callback(&e.to_string());
                        }
                    }
                }
            }
        }

        self.hashed_lines.remove(path);
        delete_ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        flow::enrichment::{DeletePayload, EnrichmentOperation, Scope},
        inputs::files::handlers::FlowUpsertsHandler,
    };
    use netgauze_flow_pkt::ie::IE;
    use std::{net::IpAddr, str::FromStr};
    use tempfile::NamedTempFile;
    use tokio::fs;

    #[tokio::test]
    async fn test_purge_file() {
        let mut processor = FileProcessor::<EnrichmentOperation>::new();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let content = r#"{"ip":"192.168.1.1","scope":{"obs_domain_id":0},"weight":5,"fields":[{"applicationName":"test"}]}"#;
        fs::write(&path, content).await.unwrap();

        let mut handler = FlowUpsertsHandler::new();

        // First process to populate cache
        processor
            .process_file_changes(&path, &mut handler, None::<FileProcessorCallback>)
            .await
            .unwrap();

        // Purge should generate delete operations
        let delete_ops = processor.purge_file(&path, &mut handler, None::<FileProcessorCallback>);

        let expected = vec![EnrichmentOperation::Delete(DeletePayload {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            scope: Scope::new(0, None),
            weight: 5,
            ies: vec![IE::applicationName],
        })];

        assert_eq!(expected, delete_ops);

        // Cache should be empty
        assert!(!processor.hashed_lines.contains_key(&path));
    }
}
