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

//! File-based enrichment input actor module for monitoring and processing
//! external enrichment data.
//!
//! This module provides the core actor implementation for file-based enrichment
//! input:
//! - `FilesActor` - Main actor that monitors files and processes enrichment
//!   data
//! - `FilesActorHandle` - Handle for controlling and communicating with the
//!   actor
//! - `FilesActorStats` - Comprehensive metrics collection for file processing
//!   operations
//!
//! The actor monitors configured file paths for changes and processes
//! enrichment data from various formats, converting them into enrichment
//! operations that are sent to enrichment actors for cache updates.
//!
//! ## File Processing Flow
//!
//! For each file change event:
//! 1. Detect file system changes using a poll-based watcher
//! 2. Parse file contents based on configured format
//! 3. Generate enrichment operations from parsed data
//! 4. Send operations to all registered enrichment actors
//! 5. Handle send errors with exponential backoff and retry logic
//!
//! ## Supported File Formats
//!
//! - **PmacctMaps** - Pmacct-style map files with configurable Information
//!   Element mapping
//! - **JSONUpserts** - Line-delimited JSON objects with direct field mapping
//!
//! - Additional formats can be added via the `InputFileFormat` enum
//! - All formats support comment filtering (lines starting with `#`, `//`, or
//!   `!`)
//! - All formats support incremental change detection with line-based diffing
use crate::inputs::{
    files::{
        handlers::{
            FilesLineHandler, FlowUpsertsHandler, PmacctMapsHandler, YangPushUpsertsHandler,
        },
        processor::{FileProcessor, FileProcessorCallback},
        FilesConfig, InputFileFormat,
    },
    EnrichmentHandle,
};
use notify::{Config, Event, PollWatcher, RecursiveMode, Watcher};
use rustc_hash::{FxBuildHasher, FxHashMap, FxHashSet};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    string::ToString,
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

const MAX_BACKOFF_TIME: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
enum FilesActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct FilesActorStats {
    files_watched: opentelemetry::metrics::Gauge<u64>,
    files_failing: opentelemetry::metrics::Gauge<u64>,
    file_changes_detected: opentelemetry::metrics::Counter<u64>,
    file_processing_errors: opentelemetry::metrics::Counter<u64>,
    operations_generated: opentelemetry::metrics::Counter<u64>,
    send_error: opentelemetry::metrics::Counter<u64>,
}

impl FilesActorStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let files_watched = meter
            .u64_gauge("netgauze.collector.flows.enrichment.input.files.watched")
            .with_description("Number of files being watched")
            .build();
        let files_failing = meter
            .u64_gauge("netgauze.collector.flows.enrichment.input.files.failing")
            .with_description("Number of files where currently parsing is completely failing")
            .build();
        let file_changes_detected = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.files.changes.detected")
            .with_description("Number of file changes detected")
            .build();
        let file_processing_errors = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.files.processing.errors")
            .with_description("Errors during file processing")
            .build();
        let operations_generated = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.files.ops.generated")
            .with_description("Number of enrichment operations generated from files")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.enrichment.input.files.send_error")
            .with_description("Error sending enrichment operations to enrichment actors")
            .build();
        Self {
            files_watched,
            files_failing,
            file_changes_detected,
            file_processing_errors,
            operations_generated,
            send_error,
        }
    }
}

/// Core files actor that monitors configured files and processes enrichment
/// data.
struct FilesActor<T, E>
where
    T: std::fmt::Display + Clone + Send + Sync + 'static,
    E: EnrichmentHandle<T>,
{
    config: FilesConfig,
    cmd_rx: mpsc::Receiver<FilesActorCommand>,
    file_event_tx: mpsc::Sender<notify::Result<Event>>,
    file_event_rx: mpsc::Receiver<notify::Result<Event>>,
    enrichment_handles: Vec<E>,
    stats: FilesActorStats,
    watcher: Option<PollWatcher>,
    watched_files: FxHashMap<PathBuf, InputFileFormat>,
    watched_directories: FxHashSet<PathBuf>,
    failing_files: FxHashSet<PathBuf>,
    processor: FileProcessor<T>,
    handlers: HashMap<InputFileFormat, Box<dyn FilesLineHandler<T>>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, E> FilesActor<T, E>
where
    T: std::fmt::Display + Clone + Send + Sync + 'static,
    E: EnrichmentHandle<T>,
{
    fn new(
        config: FilesConfig,
        cmd_rx: mpsc::Receiver<FilesActorCommand>,
        file_event_tx: mpsc::Sender<notify::Result<Event>>,
        file_event_rx: mpsc::Receiver<notify::Result<Event>>,
        enrichment_handles: Vec<E>,
        stats: FilesActorStats,
        handlers: HashMap<InputFileFormat, Box<dyn FilesLineHandler<T>>>,
    ) -> Self {
        Self {
            config,
            cmd_rx,
            file_event_tx,
            file_event_rx,
            enrichment_handles,
            stats,
            watcher: None,
            watched_files: FxHashMap::with_hasher(FxBuildHasher),
            watched_directories: FxHashSet::with_hasher(FxBuildHasher),
            failing_files: FxHashSet::with_hasher(FxBuildHasher),
            processor: FileProcessor::new(),
            handlers,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Update all gauge metrics for current file states$
    fn update_state_metrics(&self) {
        self.stats
            .files_watched
            .record(self.watched_files.len() as u64, &[]);
        self.stats
            .files_failing
            .record(self.failing_files.len() as u64, &[]);
    }

    /// Check if a file path matches the configured paths.
    fn is_configured(&self, path: &Path) -> bool {
        self.config
            .paths
            .iter()
            .any(|input| path.to_str() == Some(input.path()))
    }

    /// Add a file to the watcher
    ///
    /// Watches the parent directory instead of the file directly
    /// to detect file creation events.
    async fn add_file_to_watcher(
        &mut self,
        path: PathBuf,
        format: InputFileFormat,
    ) -> anyhow::Result<()> {
        if !path.exists() {
            return Err(anyhow::anyhow!("Path does not exist"));
        }

        if let Some(ref mut watcher) = self.watcher {
            if let Some(parent_dir) = path.parent() {
                if !self.watched_directories.contains(parent_dir) {
                    watcher.watch(parent_dir, RecursiveMode::NonRecursive)?;
                    self.watched_directories.insert(parent_dir.to_path_buf());
                    debug!("Now watching directory: {:?}", parent_dir);
                }
            } else {
                watcher.watch(&path, RecursiveMode::NonRecursive)?;
            }

            self.watched_files.insert(path.clone(), format);

            self.update_state_metrics();

            info!("Now watching file: {:?}", path);

            // Process the file initially
            if let Err(e) = self.handle_file_change(path).await {
                error!("Failed to process file initially: {}", e);
            }
        }

        Ok(())
    }

    /// Initialize file watcher for the configured paths.
    ///
    /// Creates a poll-based watcher with the configured interval
    /// and sets up monitoring for all configured file paths.
    /// Parent directories are watched to detect file creation.
    async fn setup_file_watcher(&mut self) -> anyhow::Result<()> {
        let file_event_tx = self.file_event_tx.clone();

        // Create PollWatcher with configured poll interval
        let config = Config::default()
            .with_poll_interval(Duration::from_secs(self.config.poll_interval_seconds()));
        let watcher = PollWatcher::new(
            move |res: notify::Result<Event>| {
                match file_event_tx.try_send(res) {
                    Ok(_) => {
                        // Successfully sent
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("File event channel is full (receiver may be stuck), dropping event");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        error!("File event channel is closed, cannot send file events");
                    }
                }
            },
            config,
        )?;

        self.watcher = Some(watcher);

        let paths: Vec<(String, PathBuf, InputFileFormat)> = self
            .config
            .paths()
            .iter()
            .map(|input| {
                (
                    input.path().to_string(),
                    PathBuf::from(input.path()),
                    input.format().clone(),
                )
            })
            .collect();

        // Watch all configured paths
        for (path_str, path, format) in paths {
            if let Err(e) = self.add_file_to_watcher(path, format).await {
                error!("Failed to watch configured path {}: {}", path_str, e);
            } else {
                debug!("File watcher initialized for path {}", path_str);
            }
        }

        info!(
            "File watcher initialized for {}/{} paths, watching {} directories",
            self.watched_files.len(),
            self.config.paths.len(),
            self.watched_directories.len()
        );
        Ok(())
    }

    /// Send enrichment operations to all registered enrichment actors.
    ///
    /// Implements exponential backoff up to MAX_BACKOFF_TIME upon send failures
    /// to handle temporary congestion in enrichment actor channels. Each
    /// operation is sent to all enrichment handles with independent retry
    /// logic.
    async fn send_enrichment_operations(&mut self, ops: Vec<T>, path: &Path) {
        let file_tags = [opentelemetry::KeyValue::new(
            "path",
            path.to_string_lossy().to_string(),
        )];

        for op in ops {
            debug!("Sending File-based Enrichment Operation: {}", op);
            for handle in &self.enrichment_handles {
                let mut backoff_time = Duration::from_micros(10); // initial backoff time 10us

                loop {
                    match handle.update_enrichment(op.clone()).await {
                        Ok(_) => break, // successfully sent, exit backoff loop
                        Err(e) => {
                            if backoff_time >= MAX_BACKOFF_TIME {
                                warn!(
                                    "Failed to send enrichment operation after {:?}: {}",
                                    MAX_BACKOFF_TIME, e
                                );
                                self.stats.send_error.add(1, &file_tags);
                                break;
                            }

                            // Exponential Backoff
                            debug!(
                                "Failed to send enrichment operation, sleeping for {:?}: {}",
                                backoff_time, e
                            );

                            tokio::time::sleep(backoff_time).await;
                            backoff_time *= 2;
                        }
                    }
                }
            }
        }
    }

    /// Process a file change event by parsing and generating enrichment
    /// operations.
    ///
    /// Reads and parses the file content based on its configured format,
    /// generates enrichment operations from the parsed data using incremental
    /// change detection, and sends them to all enrichment actors. Handles
    /// parsing errors gracefully and maintains failure state for metrics.
    async fn handle_file_change(&mut self, path: PathBuf) -> anyhow::Result<()> {
        let file_tags = [opentelemetry::KeyValue::new(
            "path",
            path.to_string_lossy().to_string(),
        )];
        self.stats.file_changes_detected.add(1, &file_tags);

        // Error callback to update processing error stats and log
        let error_callback = |error: &str| {
            self.stats.file_processing_errors.add(1, &file_tags);
            warn!("Failed to process entry in file {:?}: {}", path, error);
        };

        info!("Processing file change: {:?}", path);

        let format = self.watched_files.get(&path).cloned();
        if let Some(format) = format {
            if let Some(handler) = self.handlers.get_mut(&format) {
                match self
                    .processor
                    .process_file_changes(&path, handler.as_mut(), Some(error_callback))
                    .await
                {
                    Ok(ops) => {
                        debug!(
                            "Generated {} enrichment operations from file {:?}",
                            ops.len(),
                            path
                        );

                        // Mark file as successfully processed for stats
                        self.failing_files.remove(&path);
                        self.stats
                            .operations_generated
                            .add(ops.len() as u64, &file_tags);

                        // Send generated ops
                        self.send_enrichment_operations(ops, &path).await;
                    }
                    Err(e) => {
                        error!("Failed to read file {:?}: {}", path, e);

                        // Mark file as failing for stats
                        self.failing_files.insert(path.clone());

                        // Send deletes for the file's cached entries
                        let ops = self.processor.purge_file(
                            &path,
                            handler.as_mut(),
                            None::<FileProcessorCallback>,
                        );
                        self.send_enrichment_operations(ops, &path).await;
                    }
                }
            } else {
                error!("No handler found for file format {:?}", format);
            }
        } else {
            error!("No format found for file {:?}", path);
        }

        self.update_state_metrics();

        Ok(())
    }

    /// Handle file system events efficiently by filtering relevant events.
    ///
    /// Processes only modify, create, and remove events for configured files.
    /// Handles file creation by adding new files to the watcher, and file
    /// removal by purging cached entries and marking files as failing.
    async fn handle_file_system_event(&mut self, event: Event) {
        debug!("File system event: {:?}", event);

        // Only process relevant events
        if !matches!(
            event.kind,
            notify::EventKind::Modify(_)
                | notify::EventKind::Create(_)
                | notify::EventKind::Remove(_)
        ) {
            return;
        }

        for path in event.paths {
            if !self.is_configured(&path) {
                debug!("Ignoring event for non-configured file: {:?}", path);
                continue;
            }

            match event.kind {
                notify::EventKind::Modify(_) | notify::EventKind::Create(_) => {
                    if self.watched_files.contains_key(&path) {
                        if let Err(e) = self.handle_file_change(path).await {
                            error!("Failed to handle file change: {}", e);
                        }
                    } else {
                        for input in &self.config.paths {
                            if path.to_str() == Some(input.path()) {
                                info!("New file (re)created, adding to watcher: {:?}", path);
                                if let Err(e) =
                                    self.add_file_to_watcher(path, input.format().clone()).await
                                {
                                    error!("Failed to add file to watcher: {}", e);
                                }

                                info!(
                                    "File watcher configured for {}/{} paths, watching {} directories",
                                    self.watched_files.len(),
                                    self.config.paths.len(),
                                    self.watched_directories.len()
                                );

                                break;
                            }
                        }
                    }
                }
                notify::EventKind::Remove(_) => {
                    warn!("Watched file was removed: {:?}", path);

                    if let Some(format) = self.watched_files.get(&path).cloned() {
                        if let Some(handler) = self.handlers.get_mut(&format) {
                            let ops = self.processor.purge_file(
                                &path,
                                handler.as_mut(),
                                None::<FileProcessorCallback>,
                            );
                            self.send_enrichment_operations(ops, &path).await;
                        } else {
                            error!("No handler found for file format {:?}", format);
                        }
                    } else {
                        error!("No format found for file {:?}", path);
                    }

                    // Mark as failing for stats
                    self.failing_files.insert(path);
                    self.update_state_metrics();
                }
                _ => {} // Already filtered above
            }
        }
    }

    /// Main actor event loop
    async fn run(mut self) -> anyhow::Result<String> {
        info!(
            "Starting Files Actor with {} configured paths",
            self.config.paths.len()
        );

        // Setup file watcher
        self.setup_file_watcher().await?;

        loop {
            tokio::select! {
                biased;

                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(FilesActorCommand::Shutdown) => {
                            info!("Files actor shutting down");
                            Ok("Files actor terminated after a shutdown command".to_string())
                        }
                        None => {
                            warn!("Files actor terminated due to empty command channel");
                            Ok("Files actor terminated due to empty command channel".to_string())
                        }
                    }
                }

                file_event = self.file_event_rx.recv() => {
                    if let Some(event_result) = file_event {
                        match event_result {
                            Ok(event) => self.handle_file_system_event(event).await,
                            Err(e) => error!("File watcher error: {}", e),
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum FilesActorHandleError {
    SendError(String),
}

/// Handle for controlling and communicating with a files actor.
pub struct FilesActorHandle {
    cmd_send: mpsc::Sender<FilesActorCommand>,
}

impl FilesActorHandle {
    pub fn new<T>(
        config: FilesConfig,
        enrichment_handles: Vec<impl EnrichmentHandle<T> + 'static>,
        stats: either::Either<opentelemetry::metrics::Meter, FilesActorStats>,
        handlers: HashMap<InputFileFormat, Box<dyn FilesLineHandler<T>>>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self)
    where
        T: std::fmt::Display + Clone + Send + Sync + 'static,
    {
        let (cmd_send, cmd_rx) = mpsc::channel::<FilesActorCommand>(100);
        let (file_event_tx, file_event_rx) = mpsc::channel(100);
        let stats = match stats {
            either::Left(meter) => FilesActorStats::new(meter),
            either::Right(stats) => stats,
        };
        let actor = FilesActor::new(
            config,
            cmd_rx,
            file_event_tx,
            file_event_rx,
            enrichment_handles,
            stats,
            handlers,
        );
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_send };
        (join_handle, handle)
    }

    fn build_handlers_from_config<T>(
        config: &FilesConfig,
    ) -> HashMap<InputFileFormat, Box<dyn FilesLineHandler<T>>>
    where
        T: std::fmt::Display + Clone + Send + Sync + 'static,
        PmacctMapsHandler: FilesLineHandler<T>,
        FlowUpsertsHandler: FilesLineHandler<T>,
        YangPushUpsertsHandler: FilesLineHandler<T>,
    {
        let mut handlers: HashMap<InputFileFormat, Box<dyn FilesLineHandler<T>>> = HashMap::new();

        for input_file in &config.paths {
            match &input_file.format {
                format @ InputFileFormat::PmacctMaps { id, weight } => {
                    handlers.insert(
                        format.clone(),
                        Box::new(PmacctMapsHandler::new(*id, *weight)),
                    );
                }
                format @ InputFileFormat::FlowUpserts => {
                    handlers.insert(format.clone(), Box::new(FlowUpsertsHandler::new()));
                }
                format @ InputFileFormat::YangPushUpserts => {
                    handlers.insert(format.clone(), Box::new(YangPushUpsertsHandler::new()));
                }
            }
        }

        handlers
    }

    pub fn from_config<T>(
        config: FilesConfig,
        enrichment_handles: Vec<impl EnrichmentHandle<T> + 'static>,
        stats: either::Either<opentelemetry::metrics::Meter, FilesActorStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self)
    where
        T: std::fmt::Display + Clone + Send + Sync + 'static,
        PmacctMapsHandler: FilesLineHandler<T>,
        FlowUpsertsHandler: FilesLineHandler<T>,
        YangPushUpsertsHandler: FilesLineHandler<T>,
    {
        let handlers = Self::build_handlers_from_config(&config);
        Self::new(config, enrichment_handles, stats, handlers)
    }

    pub async fn shutdown(&self) -> Result<(), FilesActorHandleError> {
        self.cmd_send
            .send(FilesActorCommand::Shutdown)
            .await
            .map_err(|e| FilesActorHandleError::SendError(e.to_string()))
    }
}
