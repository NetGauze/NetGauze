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

//! External input processing infrastructure for the NetGauze collector.
//!
//! This module contains components for ingesting enrichment data from multiple
//! sources and applying enrichment operations. The primary abstractions
//! include:
//!
//! # Input Sources
//!
//! - [`files`] - File-based input processing
//! - [`kafka`] - Kafka-based input processing
//! - [`flow_options`] - Flow Options Data Records input processing
//!
//! # Enrichment
//!
//! The [`EnrichmentHandle`] trait enables asynchronous enrichment of incoming
//! data. Implementors can update enrichment state without blocking data
//! ingestion.

pub mod files;
pub mod flow_options;
pub mod kafka;

/// Asynchronous handle for applying enrichment to collected data.
///
/// Implementations should allow concurrent enrichment updates without
/// blocking the main data ingestion path. The generic parameter `T`
/// represents the enrichment operation type.
///
/// # Example usage
///
/// ```ignore
/// async fn enrich_data<H: EnrichmentHandle<MyOp>>(
///     handle: &H,
///     operation: MyOp
/// ) -> Result<(), anyhow::Error> {
///     handle.update_enrichment(operation).await
/// }
/// ```
pub trait EnrichmentHandle<T>: Send + Sync
where
    T: std::fmt::Display,
{
    /// Send an enrichment operation to the actor implementing this trait.
    ///
    /// Returns a boxed future to enable trait methods without `async_trait`.
    fn update_enrichment(&self, op: T)
        -> futures::future::BoxFuture<'_, Result<(), anyhow::Error>>;
}

/// Categorized errors from input processing operations.
///
/// Provides structured error information suitable for logging, metrics,
/// and operational decisions. Each variant contains:
/// - `context`: Where the error occurred
/// - `reason`: Why it occurred
#[derive(Debug, Clone, strum_macros::Display)]
pub enum InputProcessingError {
    #[strum(to_string = "Invalid format in {context}: {reason}")]
    InvalidFormat { context: String, reason: String },

    #[strum(to_string = "Conversion error in {context}: {reason}")]
    ConversionError { context: String, reason: String },

    #[strum(to_string = "UTF-8 decode error in {context}: {reason}")]
    Utf8Error { context: String, reason: String },

    #[strum(to_string = "JSON error in {context}: {reason}")]
    JsonError { context: String, reason: String },

    #[strum(to_string = "IO error in {context}: {reason}")]
    IoError { context: String, reason: String },

    #[strum(to_string = "Unsupported operation in {handler}: {reason}")]
    UnsupportedOperation { handler: String, reason: String },
}

impl std::error::Error for InputProcessingError {}

impl InputProcessingError {
    /// Returns a static category label for metrics classification.
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidFormat { .. } => "invalid_format",
            Self::ConversionError { .. } => "converstion_error",
            Self::Utf8Error { .. } => "utf8_error",
            Self::JsonError { .. } => "json_error",
            Self::IoError { .. } => "io_error",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
        }
    }
}
