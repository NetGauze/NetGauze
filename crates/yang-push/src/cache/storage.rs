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

//! YANG Library Cache Module
//!
//! This module provides functionality for caching and managing YANG library
//! references and their associated schemas for YANG-Push collectors.
//!
//! # Overview
//!
//! The YANG Library Cache is designed to:
//! - Store and retrieve YANG library references indexed by content ID
//! - Associate YANG libraries with subscription information (peer address,
//!   Target filters, module sets)
//! - Persist YANG libraries and schemas to disk for durability
//! - Load cached YANG libraries from disk on startup
//! - Support multiple subscriptions referencing the same YANG library.
//!
//! # Key Components
//!
//! - [`YangLibraryCache`]: The main cache structure that manages YANG library
//!   references, providing both in-memory indexing and persistent disk storage.
//!
//! - [`YangLibraryReference`]: A reference to a YANG Library stored on disk,
//!   containing the content ID, file path, and search directory for YANG
//!   modules.
//!
//! - [`SubscriptionInfo`]: Metadata about a YANG Push subscription, including
//!   peer address, content ID, Target filter, and associated YANG modules.
//!
//! # Storage Layout
//!
//! The cache persists data to disk in a structured directory hierarchy:
//!
//! ```text
//! <cache_root_path>/
//!   ├── <content-id-1>/
//!   │   ├── yang-lib.xml           # Serialized YANG library
//!   │   ├── subscriptions-info.json # Subscriptions metadata
//!   │   └── modules/               # YANG module files
//!   │       ├── module1@revision.yang
//!   │       └── module2@revision.yang
//!   └── <content-id-2>/
//!       └── ...
//! ```
//!
//! # Error Handling
//!
//! The module defines [`YangLibraryCacheError`] to handle various failure
//! modes:
//! - Missing or invalid YANG library paths
//! - Duplicate content IDs
//! - XML parsing errors
//! - Schema loading errors
//! - I/O and serialization errors
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use std::path::PathBuf;
//!
//! // Create a new cache
//! let mut cache = YangLibraryCache::new(PathBuf::from("/path/to/schemas"));
//!
//! // Or load existing cache from disk
//! let mut cache = YangLibraryCache::from_disk(PathBuf::from("/path/to/schemas"))?;
//!
//! // Store a YANG library with subscription info, or append the subscription info to the existing one
//! // if the YANG library already exists and is identical.
//! let yang_lib_ref = cache.put_yang_library(subscription_info, yang_lib, schemas)?;
//!
//! // Retrieve by subscription info
//! if let Some(yang_lib_ref) = cache.get_by_subscription_info(&subscription_info) {
//!     let schemas = yang_lib_ref.load_schemas()?;
//! }
//!
//! // Retrieve by content ID
//! if let Some(yang_lib_ref) = cache.get_by_content_id(&content_id) {
//!     let yang_library = yang_lib_ref.yang_library()?;
//! }
//! ```

use crate::ContentId;
use netgauze_netconf_proto::xml_utils::{XmlDeserialize, XmlSerialize, XmlWriter};
use netgauze_netconf_proto::yanglib::{SchemaLoadingError, YangLibrary};
use netgauze_udp_notif_pkt::notification::{SubscriptionId, Target};
use quick_xml::NsReader;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Need to add this at the end of yang library to make it work with libyang.
/// This is a temporary fix, hopefully new versions of libyang will fix this
/// issue.
const MODULE_STATE: &str = r#"
<modules-state xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
    <module-set-id>ALL</module-set-id>
</modules-state>
"#;

// default file names for yang library file
const YANG_LIBRARY_FILE_NAME: &str = "yang-lib.xml";

// default file names for the subscription info file
const SUBSCRIPTIONS_INFO_FILE_NAME: &str = "subscriptions-info.json";

/// Error types for YANG Library Cache operations.
///
/// This enum captures all the ways that YANG library cache operations can fail,
/// including file system errors, parsing errors, and validation errors.
#[derive(Debug, strum_macros::Display)]
pub enum YangLibraryCacheError {
    #[strum(to_string = "yang library is not found at path '{0:?}'")]
    YangLibraryPathNotFound(PathBuf),

    #[strum(to_string = "yang library at path '{0:?}' is not a file")]
    YangLibraryPathIsNotValid(PathBuf),

    #[strum(to_string = "yang library search path '{0:?}' is not found")]
    YangLibrarySearchPathNotFound(PathBuf),

    #[strum(to_string = "yang library search path '{0:?}' is not a directory")]
    YangLibrarySearchPathIsNotValid(PathBuf),

    #[strum(to_string = "duplicate yang library at path '{0:?}', check content id to be unique")]
    DuplicateYangLibrary(PathBuf),

    #[strum(to_string = "xml parsing error while parsing the yang library: {0}")]
    ParsingError(netgauze_netconf_proto::xml_utils::ParsingError),

    #[strum(to_string = "schema files loading error: {0}")]
    SchemaLoadingError(SchemaLoadingError),

    #[strum(to_string = "io error: {0}")]
    IoError(std::io::Error),

    #[strum(to_string = "quick-xml error: {0}")]
    QuickXmlError(quick_xml::Error),

    #[strum(to_string = "serde json error: {0}")]
    SerdeJsonError(serde_json::Error),

    #[strum(to_string = "failed to connect to netconf server: {0}")]
    NetConfClientError(netgauze_netconf_proto::client::NetConfSshClientError),
}

impl std::error::Error for YangLibraryCacheError {}

impl From<netgauze_netconf_proto::xml_utils::ParsingError> for YangLibraryCacheError {
    fn from(err: netgauze_netconf_proto::xml_utils::ParsingError) -> Self {
        YangLibraryCacheError::ParsingError(err)
    }
}

impl From<std::io::Error> for YangLibraryCacheError {
    fn from(err: std::io::Error) -> Self {
        YangLibraryCacheError::IoError(err)
    }
}

impl From<quick_xml::Error> for YangLibraryCacheError {
    fn from(err: quick_xml::Error) -> Self {
        YangLibraryCacheError::QuickXmlError(err)
    }
}

impl From<serde_json::Error> for YangLibraryCacheError {
    fn from(err: serde_json::Error) -> Self {
        YangLibraryCacheError::SerdeJsonError(err)
    }
}

impl From<SchemaLoadingError> for YangLibraryCacheError {
    fn from(err: SchemaLoadingError) -> Self {
        YangLibraryCacheError::SchemaLoadingError(err)
    }
}

impl From<netgauze_netconf_proto::client::NetConfSshClientError> for YangLibraryCacheError {
    fn from(err: netgauze_netconf_proto::client::NetConfSshClientError) -> Self {
        YangLibraryCacheError::NetConfClientError(err)
    }
}

impl From<tokio::time::error::Elapsed> for YangLibraryCacheError {
    fn from(_err: tokio::time::error::Elapsed) -> Self {
        YangLibraryCacheError::IoError(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout while waiting for yang library cache lock",
        ))
    }
}

/// A reference to a YANG Library stored on disk.
///
/// This structure provides a lightweight handle to a YANG library without
/// loading all the module contents into memory. It stores the essential
/// information needed to locate and load the YANG library and its associated
/// modules on demand.
///
/// # Multi-Subscription Support
///
/// A single `YangLibraryReference` can be associated with multiple
/// subscriptions from different peers, as long as they all use the same YANG
/// library (content-id).
///
/// - [`subscriptions_info`](Self::subscriptions_info): Retrieve all associated
///   subscriptions
/// - [`append_subscription_info`](Self::append_subscription_info): Add another
///   subscription
/// - [`save_to_disk`](Self::save_to_disk): Persist YANG library and
///   subscriptions
///
/// # Components
///
/// - **Content ID**: A unique identifier for the YANG library, extracted from
///   the library itself during construction to ensure consistency.
///
/// - **YANG Library Path**: The filesystem path to the serialized YANG library
///   XML file (`yang-lib.xml`).
///
/// - **YANG Library Reference Directory**: The directory containing the
///   `yang-lib.xml`, `subscriptions-info.json` and `modules` directory
///   containing YANG modules referenced by the library. Modules are loaded from
///   `{yang_lib_ref_path}/modules ` in this directory when
///   [`load_schemas`](Self::load_schemas) is called.
///
/// # Lazy Loading
///
/// The reference is designed for lazy loading - it validates that the paths
/// exist and extracts the content ID during construction, but does not load
/// the full YANG library or module contents until explicitly requested via
/// [`yang_library`](Self::yang_library) or
/// [`load_schemas`](Self::load_schemas).
///
/// # Example
///
/// ```rust,ignore
/// use std::path::PathBuf;
///
/// // Create a reference to an existing YANG library on disk
/// let yang_lib_ref = YangLibraryReference::new(
///     PathBuf::from("/schemas/content-id-123/yang-lib.xml"),
///     PathBuf::from("/schemas/content-id-123"),
/// )?;
///
/// // Access the content ID (available immediately)
/// let content_id = yang_lib_ref.content_id();
///
/// // Load the full YANG library when needed
/// let yang_library = yang_lib_ref.yang_library()?;
///
/// // Load all module schemas from disk
/// let schemas = yang_lib_ref.load_schemas()?;
/// ```
///
/// # Errors
///
/// Construction will fail if:
/// - The YANG library path does not exist or is not a file
/// - The search directory does not exist or is not a directory
/// - The YANG library XML cannot be parsed
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct YangLibraryReference {
    content_id: ContentId,
    yang_library_path: PathBuf,
    yang_lib_ref_path: PathBuf,
}

impl YangLibraryReference {
    /// Load a YANG Library Reference from the given YANG Library file path
    /// and root directory for the YANG Library reference.
    ///
    /// Note: the content ID is read from the YANG Library file to ensure its
    /// correctness.
    ///
    /// This does not load the YANG modules themselves, only the reference to
    /// them.
    pub fn load_from_disk(
        yang_library_path: PathBuf,
        yang_lib_ref_path: PathBuf,
    ) -> Result<Self, YangLibraryCacheError> {
        if !yang_library_path.exists() {
            tracing::warn!(
                yang_library_path = %yang_library_path.display(),
                "YANG library not found at path"
            );
            return Err(YangLibraryCacheError::YangLibraryPathNotFound(
                yang_library_path,
            ));
        }
        if !yang_library_path.is_file() {
            tracing::warn!(
                yang_library_path = %yang_library_path.display(),
                "YANG library path is not a file"
            );
            return Err(YangLibraryCacheError::YangLibraryPathIsNotValid(
                yang_library_path,
            ));
        }
        if !yang_lib_ref_path.exists() {
            tracing::warn!(
                 yang_lib_ref_path=%yang_lib_ref_path.display(),
                "YANG library reference path not found"
            );
            return Err(YangLibraryCacheError::YangLibrarySearchPathNotFound(
                yang_lib_ref_path,
            ));
        }
        if !yang_lib_ref_path.is_dir() {
            tracing::warn!(
                yang_lib_ref_path=%yang_lib_ref_path.display(),
                "YANG library reference path is not a directory"
            );
            return Err(YangLibraryCacheError::YangLibrarySearchPathIsNotValid(
                yang_lib_ref_path,
            ));
        }
        tracing::debug!(
            yang_library_path=%yang_library_path.display(),
            yang_lib_ref_path= %yang_lib_ref_path.display(),
            "loading YANG library reference",
        );
        let subscriptions_info_path = yang_lib_ref_path.join(SUBSCRIPTIONS_INFO_FILE_NAME);
        let subscriptions_info_file = std::fs::File::open(subscriptions_info_path.as_path()).map_err(|error| {
            tracing::warn!(
                subscriptions_info_path=%subscriptions_info_path.display(), "failed to open subscriptions info file");
            std::io::Error::other(format!(
                "failed to open subscriptions info file {}: {error}",
                subscriptions_info_path.display()
            ))
        })?;
        let subscriptions_info: Vec<SubscriptionInfo> = serde_json::from_reader(subscriptions_info_file).map_err(|error| {
           tracing::warn!(subscriptions_info_path=%subscriptions_info_path.display(), error=%error, "failed to parse subscriptions info file");
            YangLibraryCacheError::SerdeJsonError(error)
        })?;
        let yang_library = Self::load_yang_library(&yang_library_path)?;
        let content_id = yang_library.content_id().into();
        tracing::info!(
            yang_library_path=%yang_library_path.display(),
            yang_lib_ref_path=%yang_lib_ref_path.display(),
            content_id,
            subscriptions_count=subscriptions_info.len(),
            "loaded YANG library reference",
        );
        Ok(Self {
            content_id,
            yang_library_path,
            yang_lib_ref_path,
        })
    }

    /// Create and save a YANG Library Reference to disk.
    ///
    /// This will create the necessary directory structure and files to store
    /// the YANG library, subscription info, and YANG modules.
    ///
    /// If the YANG Library already exists on disk and differs from the provided
    /// YANG Library, an error is returned to prevent overwriting.
    ///
    /// If the YANG Library already exists and is identical, the existing
    /// reference is returned and the subscription info is extended with the new
    /// subscriptions.
    pub fn save_to_disk(
        yang_lib_ref_path: PathBuf,
        yang_library: &YangLibrary,
        schemas: HashMap<Box<str>, Box<str>>,
        subscriptions_info: &[SubscriptionInfo],
    ) -> Result<Self, YangLibraryCacheError> {
        if !yang_lib_ref_path.exists() {
            std::fs::create_dir_all(&yang_lib_ref_path).map_err(|error| {
                tracing::warn!(
                    yang_lib_ref_path=%yang_lib_ref_path.display(),
                    content_id=yang_library.content_id(),
                    "failed to create YANG Library Reference dir");
                std::io::Error::other(format!(
                    "failed to create YANG Library Reference {} dir {}: {error}",
                    yang_library.content_id(),
                    yang_lib_ref_path.display()
                ))
            })?
        }
        if !yang_lib_ref_path.is_dir() {
            tracing::warn!(
                yang_lib_ref_path=%yang_lib_ref_path.display(),
                "YANG library reference path is not a directory"
            );
            return Err(YangLibraryCacheError::YangLibrarySearchPathIsNotValid(
                yang_lib_ref_path,
            ));
        }
        let yang_library_path = yang_lib_ref_path.join(YANG_LIBRARY_FILE_NAME);
        if yang_library_path.exists() {
            if !yang_library_path.is_file() {
                tracing::warn!(
                    yang_library_path = %yang_library_path.display(),
                    "YANG library path is not a file"
                );
                return Err(YangLibraryCacheError::YangLibraryPathIsNotValid(
                    yang_library_path,
                ));
            }
            let loaded_yang_lib = Self::load_yang_library(yang_library_path.as_path())?;
            if &loaded_yang_lib != yang_library {
                tracing::warn!(
                    yang_library_path = %yang_library_path.display(),
                    "Different YANG library found, cannot override"
                );
                return Err(YangLibraryCacheError::DuplicateYangLibrary(
                    yang_library_path.clone(),
                ));
            }
        } else {
            let file = std::fs::File::create(&yang_library_path)?;
            let writer = std::io::BufWriter::new(file);
            let quick_xml_writer = quick_xml::writer::Writer::new_with_indent(writer, 32, 2);
            let mut xml_writer = XmlWriter::new(quick_xml_writer);
            yang_library.xml_serialize(&mut xml_writer)?;
            let mut inner = xml_writer.into_inner();
            inner.write_all(MODULE_STATE.as_bytes())?;
            inner.flush()?;
        }

        let subscriptions_info_path = yang_lib_ref_path.join(SUBSCRIPTIONS_INFO_FILE_NAME);
        let subscriptions_info = if subscriptions_info_path.is_file() {
            tracing::debug!(
                subscriptions_info_path=%subscriptions_info_path.display(),
                content_id=yang_library.content_id(),
                "subscriptions info file already exists, extending it with new subscriptions"
            );
            let subscriptions_info_file = std::fs::File::open(subscriptions_info_path.as_path())
                .map_err(|error| {
                    tracing::error!(
                    subscriptions_info_path=%subscriptions_info_path.display(),
                    error=%error,
                    "failed to open subscriptions info file");
                    std::io::Error::other(format!(
                        "failed to open subscriptions info file {}: {error}",
                        subscriptions_info_path.display()
                    ))
                })?;
            let mut read_subscriptions_info: HashSet<SubscriptionInfo> =
                serde_json::from_reader(subscriptions_info_file).map_err(|error| {
                    tracing::error!(
                        subscriptions_info_path=%subscriptions_info_path.display(),
                        error=%error,
                        "failed to parse subscriptions info file"
                    );
                    error
                })?;
            read_subscriptions_info.extend(subscriptions_info.iter().cloned());
            &read_subscriptions_info
                .into_iter()
                .collect::<Vec<SubscriptionInfo>>()
        } else {
            subscriptions_info
        };

        let subscriptions_info_file = std::fs::File::create(subscriptions_info_path.as_path())
            .map_err(|error| {
                tracing::warn!(
                subscriptions_info_path=%subscriptions_info_path.display(),
                error=%error,
                "failed to open subscriptions info file");
                std::io::Error::other(format!(
                    "failed to open subscriptions info file {}: {error}",
                    subscriptions_info_path.display()
                ))
            })?;
        serde_json::to_writer_pretty(subscriptions_info_file, subscriptions_info)?;

        let modules_path = yang_lib_ref_path.join("modules");
        std::fs::create_dir_all(&modules_path)?;
        for (name, schema) in &schemas {
            let mut revision = None;
            if let Some(module) = yang_library.find_module(name.as_ref()) {
                revision = module.revision();
            } else if let Some(import_only_modules) = yang_library.find_import_module(name.as_ref())
            {
                if let Some(import_only_module) = import_only_modules.into_iter().next() {
                    revision = import_only_module.revision();
                }
            } else if let Some(submodule) = yang_library.find_submodule(name.as_ref()) {
                revision = submodule.revision();
            }
            let filename = if let Some(revision) = revision {
                format!("{name}@{revision}.yang")
            } else {
                name.to_string()
            };
            let yang_module_path = modules_path.join(&filename);
            std::fs::write(&yang_module_path, schema.as_ref())?;
            tracing::info!(yang_module_path = %yang_module_path.display(), "saved yang module to disk");
        }
        tracing::info!(
            content_id=yang_library.content_id(),
            modules_count = schemas.len(),
            modules_path = %modules_path.display(),
            "saved YANG modules to disk"
        );

        Ok(Self {
            content_id: yang_library.content_id().into(),
            yang_library_path,
            yang_lib_ref_path,
        })
    }

    // Load the YANG Library from the given path.
    fn load_yang_library(yang_library_path: &Path) -> Result<YangLibrary, YangLibraryCacheError> {
        let reader = NsReader::from_file(yang_library_path)
            .map_err(|error| {
                tracing::warn!(yang_library_path=%yang_library_path.display(), error=%error, "failed to open yang library file");
                YangLibraryCacheError::ParsingError(error.into())
            })?;
        tracing::trace!(yang_library_path=%yang_library_path.display(), "parsing yang library from disk");
        let mut xml_reader = netgauze_netconf_proto::xml_utils::XmlParser::new(reader)?;
        let yang_library = YangLibrary::xml_deserialize(&mut xml_reader)?;
        Ok(yang_library)
    }
    /// Get the content ID of the YANG Library.
    pub const fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    /// Get the path to the YANG Library file.
    pub fn yang_library_path(&self) -> &Path {
        self.yang_library_path.as_path()
    }

    /// Load the YANG Library from disk.
    pub fn yang_library(&self) -> Result<YangLibrary, YangLibraryCacheError> {
        Self::load_yang_library(self.yang_library_path.as_path())
    }

    /// Get the path to the directory containing the YANG Library file.
    pub fn yang_lib_ref_path(&self) -> &Path {
        self.yang_lib_ref_path.as_path()
    }

    /// Get the path to the search directory containing the YANG modules.
    pub fn search_dir(&self) -> PathBuf {
        self.yang_lib_ref_path().join("modules")
    }

    ///Load the YANG schemas defined in the library from disk.
    pub fn load_schemas(&self) -> Result<HashMap<Box<str>, Box<str>>, YangLibraryCacheError> {
        let yang_library = Self::load_yang_library(self.yang_library_path.as_path())?;
        let search_dir = self.search_dir();
        tracing::info!(
            search_dir = %search_dir.display(),
            "loading yang schemas from search directory",
        );

        match yang_library.load_schemas_from_search_path(search_dir.as_path()) {
            Ok(schemas) => {
                tracing::debug!(
                    schemas_count = schemas.len(),
                    "loaded yang schemas successfully"
                );
                Ok(schemas)
            }
            Err(err) => {
                tracing::warn!(
                    search_dir = %search_dir.display(),
                    error = %err,
                    "failed to load yang schemas from search directory"
                );
                Err(err.into())
            }
        }
    }

    pub fn subscription_info_path(&self) -> PathBuf {
        self.yang_lib_ref_path.join(SUBSCRIPTIONS_INFO_FILE_NAME)
    }

    pub fn subscriptions_info(&self) -> Result<Vec<SubscriptionInfo>, YangLibraryCacheError> {
        let subscriptions_info_path = self.subscription_info_path();
        tracing::debug!(
            subscriptions_info_path = %subscriptions_info_path.display(),
            content_id=self.content_id,
            "loading subscription info from disk"
        );
        let subscriptions_info_file = std::fs::File::open(subscriptions_info_path.as_path())
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to read subscriptions info from {}: {error}",
                    subscriptions_info_path.display()
                ))
            })?;
        let subscriptions_info = serde_json::from_reader(subscriptions_info_file)?;
        Ok(subscriptions_info)
    }

    /// Appends a subscription information entry to the persisted list.
    ///
    /// If the subscription info already exists, this operation is idempotent
    /// (no duplicate entry is created). Uses file locking to prevent concurrent
    /// modification issues and atomic writes for crash safety.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The subscription info file cannot be accessed
    /// - JSON parsing/serialization fails
    /// - File system operations fail
    pub fn append_subscription_info(
        &self,
        subscription_info: SubscriptionInfo,
    ) -> Result<(), YangLibraryCacheError> {
        let subscriptions_info_path = self.subscription_info_path();

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&subscriptions_info_path)?;

        file.lock().map_err(|e| {
            YangLibraryCacheError::IoError(std::io::Error::other(format!(
                "failed to acquire lock on {}: {e}",
                subscriptions_info_path.display()
            )))
        })?;

        // Ensure unlock on all paths
        let result = (|| {
            let mut subscriptions_info: Vec<SubscriptionInfo> = serde_json::from_reader(&file)?;

            if subscriptions_info
                .iter()
                .any(|info| info == &subscription_info)
            {
                return Ok(());
            }

            subscriptions_info.push(subscription_info);

            // Atomic write via a temp file
            let temp_path = subscriptions_info_path.with_extension(".tmp");
            let temp_file = std::fs::File::create(&temp_path)?;
            serde_json::to_writer_pretty(temp_file, &subscriptions_info)?;
            std::fs::rename(temp_path, &subscriptions_info_path)?;

            Ok(())
        })();

        file.unlock()?;
        result
    }

    /// Remove a subscription info from the YANG library reference.
    ///
    /// If the subscription info is found and removed, it is returned.
    /// If not found, None is returned.
    pub fn remove_subscription_info(
        &self,
        subscription_info: &SubscriptionInfo,
    ) -> Result<Option<SubscriptionInfo>, YangLibraryCacheError> {
        let subscriptions_info_path = self.subscription_info_path();

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&subscriptions_info_path)?;

        file.lock().map_err(|e| {
            YangLibraryCacheError::IoError(std::io::Error::other(format!(
                "failed to acquire lock on {}: {e}",
                subscriptions_info_path.display()
            )))
        })?;

        let result = (|| {
            let mut subscriptions_info: Vec<SubscriptionInfo> = serde_json::from_reader(&file)?;

            let original_len = subscriptions_info.len();
            subscriptions_info.retain(|info| info != subscription_info);

            if subscriptions_info.len() == original_len {
                return Ok(None);
            }

            // Atomic write
            let temp_path = subscriptions_info_path.with_extension(".tmp");
            let temp_file = std::fs::File::create(&temp_path)?;
            serde_json::to_writer_pretty(temp_file, &subscriptions_info)?;
            std::fs::rename(temp_path, &subscriptions_info_path)?;

            Ok(Some(subscription_info.clone()))
        })();

        file.unlock()?;
        result
    }
}

/// Metadata about a YANG Push subscription.
///
/// This structure captures the essential information about a YANG Push
/// subscription, used to uniquely identify and associate subscriptions with
/// their corresponding YANG library references in the cache.
///
/// # Fields
///
/// - **peer**: The socket address (IP and port) of the remote device that
///   established the subscription. This identifies which network element sent
///   the subscription-started notification.
///
/// - **content_id**: The YANG Library content identifier associated with this
///   subscription. This links the subscription to a specific version of the
///   device's YANG schema set.
///
/// - **target**: The [Target] filter expression that defines what data the
///   subscription monitors. This determines which parts of the YANG data tree
///   are included in notifications.
///
/// - **models**: A list of YANG module names that are relevant to this
///   subscription. These modules define the schema for the subscribed data.
///
/// # Identity and Equality
///
/// `SubscriptionInfo` implements `Eq` and `Hash`, allowing it to be used as
/// a key in hash maps. Two subscription infos are considered equal if all
/// their fields match exactly.
///
/// # Serialization
///
/// This structure supports JSON serialization via serde, enabling persistent
/// storage of subscription metadata to disk alongside the YANG library files.
///
/// # Example
///
/// ```rust,ignore
/// use std::net::SocketAddr;
///
/// let subscription_info = SubscriptionInfo::new(
///     "192.168.1.100:830".parse().unwrap(),
///     1,
///     ContentId::from("2024-01-15-content-id"),
///     Target::new_datastore(
///         "ds:operational".to_string(),
///         either::Right("/ietf-interfaces:interfaces/ietf-interfaces/statistics".to_string()),
///     ),
///     vec!["ietf-interfaces".to_string(), "ietf-ip".to_string()],
/// );
///
/// // Access subscription details
/// println!("Peer: {}", subscription_info.peer());
/// println!("Content ID: {}", subscription_info.content_id());
/// println!("Subscription Target: {}", subscription_info.target());
/// println!("Models: {:?}", subscription_info.models());
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SubscriptionInfo {
    peer: SocketAddr,
    id: SubscriptionId,
    content_id: ContentId,
    target: Target,
    // TODO: add Module revision
    models: Vec<String>,
}

impl SubscriptionInfo {
    pub fn new(
        peer: SocketAddr,
        id: SubscriptionId,
        content_id: ContentId,
        target: Target,
        models: Vec<String>,
    ) -> Self {
        Self {
            peer,
            id,
            content_id,
            target,
            models,
        }
    }

    /// Create an empty subscription info placeholder.
    /// This can be used when no subscription info is available.
    /// Or to indicate that no yang library is associated with the subscription.
    pub fn new_empty(peer: SocketAddr, id: SubscriptionId) -> Self {
        Self {
            peer,
            id,
            content_id: "EMPTY".to_string(),
            target: Target::new_datastore("EMPTY".to_string(), either::Right("EMPTY".to_string())),
            models: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.content_id == "EMPTY"
    }

    /// The peer address of the device who sent the subscription started
    /// message.
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The subscription ID associated with the subscription. This is a unique
    /// identifier for the subscription within each peer
    pub const fn id(&self) -> SubscriptionId {
        self.id
    }

    /// The YANG Library content ID associated with the subscription by the
    /// device.
    pub const fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    /// The [Target] associated with the subscription.
    pub const fn target(&self) -> &Target {
        &self.target
    }

    /// The list of YANG modules associated with the subscription.
    pub fn models(&self) -> &[String] {
        &self.models
    }
}

impl std::fmt::Display for SubscriptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SubscriptionInfo {{ peer: {}, content_id: {}, target: {}, models: {:?} }}",
            self.peer, self.content_id, self.target, self.models
        )
    }
}

/// Cache for YANG library references used by a YANG-Push collector.
///
/// `YangLibraryCache` provides efficient lookup of YANG library references
/// through two indexing strategies:
///
/// - **Content ID index**: Direct O(1) lookup when the content identifier is
///   known
/// - **Subscription info index**: Lookup by the full subscription context
///   (peer, XPath, modules)
///
/// In addition, it maintains a mapping of subscription IDs per peer IP address
/// to facilitate lookups based on subscription ID to get the associated
/// [SubscriptionInfo]. This is useful when processing that has the subscription
/// started message read in the past and only received the period notifications.
///
/// The cache supports both in-memory creation and restoration from persistent
/// disk storage. See the [module documentation](self) for the disk storage
/// layout and detailed usage examples.
pub struct YangLibraryCache {
    cache_by_content_id: FxHashMap<ContentId, Arc<YangLibraryReference>>,
    cache_by_subscription_info: FxHashMap<SubscriptionInfo, Arc<YangLibraryReference>>,
    cache_by_subscription_id: FxHashMap<IpAddr, FxHashMap<SubscriptionId, SubscriptionInfo>>,
    cache_root_path: PathBuf,
}

impl YangLibraryCache {
    /// Create a new, empty YANG Library Cache.
    pub fn new(cache_root_path: PathBuf) -> Self {
        Self {
            cache_by_content_id: FxHashMap::default(),
            cache_by_subscription_info: FxHashMap::default(),
            cache_by_subscription_id: FxHashMap::default(),
            cache_root_path,
        }
    }

    /// Load an existing YANG Library Cache from disk.
    /// The cache is populated by reading all YANG library entries
    /// stored under the given root path.
    ///
    /// The YANG modules are loaded for each YANG Library reference to verify
    /// they are correctly stored.
    pub fn from_disk(cache_root_path: PathBuf) -> Result<Self, YangLibraryCacheError> {
        tracing::debug!(
            cache_root_path = %cache_root_path.display(),
            "loading YANG Library references cache",
        );
        let mut cache_by_content_id = FxHashMap::default();
        let mut cache_by_subscription_info = FxHashMap::default();
        let mut cache_by_subscription_id: FxHashMap<
            IpAddr,
            FxHashMap<SubscriptionId, SubscriptionInfo>,
        > = FxHashMap::default();
        let read_dir = std::fs::read_dir(cache_root_path.as_path()).map_err(|error| {
            std::io::Error::other(format!(
                "failed to read cached root path {}: {error}",
                cache_root_path.display()
            ))
        })?;
        for dir in read_dir {
            let entry = dir.map_err(|error| {
                std::io::Error::other(format!(
                    "failed to read cached entry in root path {}: {error}",
                    cache_root_path.display()
                ))
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let yang_lib_path = path.join(YANG_LIBRARY_FILE_NAME);
            let yang_lib_ref = YangLibraryReference::load_from_disk(yang_lib_path, path.clone())?;
            let yang_lib_ref = Arc::new(yang_lib_ref);
            // Loading the schemas to verify they are correctly stored
            _ = yang_lib_ref.load_schemas()?;
            let content_id = yang_lib_ref.content_id().clone();
            let subscriptions_info = yang_lib_ref.subscriptions_info()?;
            tracing::info!(
                yang_library_path = %path.display(),
                subscriptions_info = ?subscriptions_info,
                "loaded yang library reference ",
            );
            cache_by_content_id.insert(content_id, Arc::clone(&yang_lib_ref));
            for subscription_info in subscriptions_info {
                cache_by_subscription_id
                    .entry(subscription_info.peer().ip())
                    .or_default()
                    .insert(subscription_info.id(), subscription_info.clone());
                cache_by_subscription_info.insert(subscription_info, Arc::clone(&yang_lib_ref));
            }
        }
        tracing::info!(
            total_entries = %cache_by_content_id.len(),
            "loaded YANG Library references cache",
        );
        Ok(Self {
            cache_by_content_id,
            cache_by_subscription_info,
            cache_by_subscription_id,
            cache_root_path,
        })
    }

    /// Store a YANG Library along with its associated Subscription Info
    /// and schemas into the cache and persist them to disk.
    ///
    /// If the YANG Library already exists in the cache and is identical,
    /// the existing reference is returned and the subscription info is
    /// appended.
    pub fn put_yang_library(
        &mut self,
        subscription_info: SubscriptionInfo,
        yang_lib: YangLibrary,
        schemas: HashMap<Box<str>, Box<str>>,
    ) -> Result<Arc<YangLibraryReference>, YangLibraryCacheError> {
        let content_id = yang_lib.content_id();
        // Check if already cached
        if let Some(existing_ref) = self.cache_by_content_id.get(content_id) {
            if !self
                .cache_by_subscription_info
                .contains_key(&subscription_info)
            {
                existing_ref.append_subscription_info(subscription_info.clone())?;
                self.cache_by_subscription_info
                    .insert(subscription_info.clone(), Arc::clone(existing_ref));
                self.cache_by_subscription_id
                    .entry(subscription_info.peer().ip())
                    .or_default()
                    .insert(subscription_info.id(), subscription_info);
            }
            return Ok(Arc::clone(existing_ref));
        }
        // New entry - save to disk
        let entry_path = self.cache_root_path.join(yang_lib.content_id());
        let yang_lib_ref = YangLibraryReference::save_to_disk(
            entry_path,
            &yang_lib,
            schemas,
            std::slice::from_ref(&subscription_info),
        )?;
        let content_id = yang_lib_ref.content_id().clone();
        let yang_lib_ref = Arc::new(yang_lib_ref);
        self.cache_by_subscription_info
            .insert(subscription_info.clone(), Arc::clone(&yang_lib_ref));
        self.cache_by_content_id
            .insert(content_id, Arc::clone(&yang_lib_ref));
        self.cache_by_subscription_id
            .entry(subscription_info.peer().ip())
            .or_default()
            .insert(subscription_info.id(), subscription_info);
        Ok(yang_lib_ref)
    }

    pub fn remove_by_content_id(
        &mut self,
        content_id: &ContentId,
    ) -> Result<(), YangLibraryCacheError> {
        tracing::info!(content_id, "removing yang library for content from cache");
        if let Some(yang_lib_ref) = self.cache_by_content_id.remove(content_id) {
            self.cache_by_subscription_info
                .retain(|_, v| v.content_id() != content_id);
            self.cache_by_subscription_id.retain(|_, sub_map| {
                sub_map.retain(|_, sub_info| sub_info.content_id() != content_id);
                !sub_map.is_empty()
            });
            std::fs::remove_file(yang_lib_ref.yang_library_path())?;
            std::fs::remove_dir_all(yang_lib_ref.yang_lib_ref_path())?;
            tracing::info!(
                content_id,
                "removed yang library with content id from cache"
            );
        } else {
            tracing::info!(
                content_id,
                "no yang library reference found for content id in cache"
            );
        }
        Ok(())
    }

    pub fn remove_by_subscription_info(
        &mut self,
        subscription_info: &SubscriptionInfo,
    ) -> Result<Option<SubscriptionInfo>, YangLibraryCacheError> {
        // Step 1: Remove from subscription_info -> content_id mapping
        let yang_lib_ref = match self.cache_by_subscription_info.remove(subscription_info) {
            Some(yang_lib_ref) => yang_lib_ref,
            None => return Ok(None),
        };

        // Step 2: Remove from (peer_ip, sub_id) -> SubscriptionInfo mapping
        if let Some(sub_map) = self
            .cache_by_subscription_id
            .get_mut(&subscription_info.peer().ip())
        {
            sub_map.remove(&subscription_info.id());
            if sub_map.is_empty() {
                self.cache_by_subscription_id
                    .remove(&subscription_info.peer().ip());
            }
        }

        // Step 3: Check if any other subscriptions are still using this content_id
        let content_id_still_in_use = self
            .cache_by_subscription_info
            .values()
            .any(|lib_ref| lib_ref.content_id() == yang_lib_ref.content_id());

        // Step 4: Only remove YangLibraryReference and delete files if no subscriptions
        // remain
        if !content_id_still_in_use {
            if let Some(yang_lib_ref) = self.cache_by_content_id.remove(yang_lib_ref.content_id()) {
                // Remove subscription from the reference's internal list
                yang_lib_ref.remove_subscription_info(subscription_info)?;

                // Delete the directory and all its contents from the filesystem
                let content_dir = self.cache_root_path.join(yang_lib_ref.content_id());
                if content_dir.exists() {
                    std::fs::remove_dir_all(&content_dir).map_err(|error| {
                        YangLibraryCacheError::IoError(std::io::Error::other(format!(
                            "Failed to remove directory {}: {error}",
                            content_dir.display(),
                        )))
                    })?;
                }
            }
        } else {
            // Step 5: Content is still in use - just remove this subscription from the
            // reference
            if let Some(yang_lib_ref) = self.cache_by_content_id.get_mut(yang_lib_ref.content_id())
            {
                yang_lib_ref.remove_subscription_info(subscription_info)?;
            }
        }
        Ok(Some(subscription_info.clone()))
    }

    pub fn get_by_subscription_info(
        &self,
        subscription_info: &SubscriptionInfo,
    ) -> Option<Arc<YangLibraryReference>> {
        let result = self
            .cache_by_subscription_info
            .get(subscription_info)
            .map(Arc::clone);
        tracing::debug!(
            subscription_info = %subscription_info,
            hit = result.is_some(),
            "cache lookup by subscription info"
        );
        result
    }

    pub fn get_by_content_id(
        &mut self,
        content_id: &ContentId,
    ) -> Option<Arc<YangLibraryReference>> {
        let result = self.cache_by_content_id.get(content_id).map(Arc::clone);
        tracing::debug!(
            content_id,
            hit = result.is_some(),
            "cache lookup by content id"
        );
        result
    }

    pub fn get_by_subscription_id(
        &self,
        peer_ip: IpAddr,
        subscription_id: SubscriptionId,
    ) -> Option<(SubscriptionInfo, Option<Arc<YangLibraryReference>>)> {
        let result = self
            .cache_by_subscription_id
            .get(&peer_ip)
            .and_then(|x| x.get(&subscription_id))
            .cloned()
            .map(|subscription_info| {
                let yang_lib_ref = self
                    .cache_by_subscription_info
                    .get(&subscription_info)
                    .map(Arc::clone);
                (subscription_info, yang_lib_ref)
            });
        tracing::debug!(
            peer_ip=%peer_ip,
            hit = result.is_some(),
            "cache lookup by subscription id"
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    fn create_test_subscription_info(content_id: &str) -> SubscriptionInfo {
        SubscriptionInfo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 830),
            1,
            ContentId::from(content_id.to_string()),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='eth0']/statistics".to_string()),
            ),
            vec!["ietf-interfaces".to_string(), "ietf-ip".to_string()],
        )
    }

    fn create_minimal_yang_library_xml(content_id: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
  <module-set>
    <name>test-module-set</name>
    <module>
      <name>test-module</name>
      <revision>2025-12-12</revision>
      <namespace>urn:test:test-module</namespace>
    </module>
  </module-set>
  <schema>
    <name>test-schema</name>
    <module-set>test-module-set</module-set>
  </schema>
  <datastore>
    <name xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">ds:running</name>
    <schema>test-schema</schema>
  </datastore>
  <content-id>{content_id}</content-id>
</yang-library>"#
        )
    }

    fn create_test_yang_module() -> &'static str {
        r#"module test-module {
  namespace "urn:test:test-module";
  prefix tm;

  revision 2025-12-12;

  container test {
    leaf name {
      type string;
    }
  }
}"#
    }

    fn setup_yang_library_on_disk(
        temp_dir: &TempDir,
        content_id: &str,
        subscriptions_info: &[SubscriptionInfo],
    ) -> Result<PathBuf, YangLibraryCacheError> {
        let entry_path = temp_dir.path().join(content_id);
        std::fs::create_dir_all(&entry_path)?;

        // Write yang library file
        let yang_lib_path = entry_path.join(YANG_LIBRARY_FILE_NAME);
        let yang_lib_xml = create_minimal_yang_library_xml(content_id);
        std::fs::write(&yang_lib_path, yang_lib_xml)?;

        // Write subscription info
        let subscriptions_info_path = entry_path.join(SUBSCRIPTIONS_INFO_FILE_NAME);
        let subscriptions_info_file = std::fs::File::create(&subscriptions_info_path)?;
        serde_json::to_writer_pretty(subscriptions_info_file, subscriptions_info)?;

        // Create the modules directory with a test module
        let modules_path = entry_path.join("modules");
        std::fs::create_dir_all(&modules_path)?;
        let module_path = modules_path.join("test-module@2025-12-12.yang");
        tracing::debug!("creating test module at {module_path:?}");
        std::fs::write(&module_path, create_test_yang_module())?;

        Ok(entry_path)
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_new() {
        let temp_dir = TempDir::new().unwrap();
        let cache = YangLibraryCache::new(temp_dir.path().to_path_buf());

        assert!(cache.cache_by_content_id.is_empty());
        assert!(cache.cache_by_subscription_info.is_empty());
        assert_eq!(cache.cache_root_path, temp_dir.path());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_reference_new_file_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let yang_lib_path = temp_dir.path().join("nonexistent.xml");
        let search_dir = temp_dir.path().to_path_buf();

        let result = YangLibraryReference::load_from_disk(yang_lib_path.clone(), search_dir);
        assert!(matches!(
            result,
            Err(YangLibraryCacheError::YangLibraryPathNotFound(_))
        ));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_reference_new_path_is_directory() {
        let temp_dir = TempDir::new().unwrap();
        let yang_lib_path = temp_dir.path().to_path_buf();
        let search_dir = temp_dir.path().to_path_buf();

        let result = YangLibraryReference::load_from_disk(yang_lib_path.clone(), search_dir);
        assert!(matches!(
            result,
            Err(YangLibraryCacheError::YangLibraryPathIsNotValid(_))
        ));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_reference_new_search_dir_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let yang_lib_path = temp_dir.path().join("yang-lib.xml");
        std::fs::write(&yang_lib_path, create_minimal_yang_library_xml("test-id")).unwrap();
        let search_dir = temp_dir.path().join("nonexistent");

        let result = YangLibraryReference::load_from_disk(yang_lib_path, search_dir.clone());
        assert!(matches!(
            result,
            Err(YangLibraryCacheError::YangLibrarySearchPathNotFound(_))
        ));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_reference_new_search_dir_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let yang_lib_path = temp_dir.path().join("yang-lib.xml");
        std::fs::write(&yang_lib_path, create_minimal_yang_library_xml("test-id")).unwrap();
        let search_dir = temp_dir.path().join("file.txt");
        std::fs::write(&search_dir, "test").unwrap();

        let result = YangLibraryReference::load_from_disk(yang_lib_path, search_dir.clone());
        assert!(matches!(
            result,
            Err(YangLibraryCacheError::YangLibrarySearchPathIsNotValid(_))
        ));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_reference_new_success() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "test-content-id-123";
        let subscription_info = create_test_subscription_info(content_id);
        let entry_path = setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();
        let yang_lib_path = entry_path.join(YANG_LIBRARY_FILE_NAME);

        let result =
            YangLibraryReference::load_from_disk(yang_lib_path.clone(), entry_path.clone());
        assert!(result.is_ok());

        let yang_lib_ref = result.unwrap();
        assert_eq!(yang_lib_ref.content_id(), content_id);
        assert_eq!(yang_lib_ref.yang_library_path(), yang_lib_path);
        assert_eq!(yang_lib_ref.yang_lib_ref_path(), entry_path);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_reference_yang_library() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "test-content-id-456";
        let subscription_info = create_test_subscription_info(content_id);
        let entry_path = setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();
        let yang_lib_path = entry_path.join(YANG_LIBRARY_FILE_NAME);

        let yang_lib_ref = YangLibraryReference::load_from_disk(yang_lib_path, entry_path).unwrap();
        let yang_lib = yang_lib_ref.yang_library().unwrap();

        assert_eq!(yang_lib.content_id(), content_id);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_subscription_info_new() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let content_id = ContentId::from("content-123".to_string());
        let target = Target::new_datastore(
            "ds:operational".to_string(),
            either::Right("/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='eth0']/statistics".to_string()),
        );
        let models = vec!["model1".to_string(), "model2".to_string()];

        let info = SubscriptionInfo::new(peer, 1, content_id.clone(), Target::new_datastore(
            "ds:operational".to_string(),
            either::Right("/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='eth0']/statistics".to_string()),
        ), models.clone());

        assert_eq!(info.peer(), peer);
        assert_eq!(info.content_id(), &content_id);
        assert_eq!(info.target(), &target);
        assert_eq!(info.models(), models.as_slice());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_subscription_info_display() {
        let info = create_test_subscription_info("test-id");
        let display = format!("{info}");

        assert!(display.contains("192.168.1.100:830"));
        assert!(display.contains("test-id"));
        assert!(display.contains("/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='eth0']/statistics"));
        assert!(display.contains("ietf-interfaces"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_subscription_info_serialization() {
        let info = create_test_subscription_info("serialize-test");

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: SubscriptionInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(info, deserialized);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_from_disk_empty() {
        let temp_dir = TempDir::new().unwrap();

        let cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();

        assert!(cache.cache_by_content_id.is_empty());
        assert!(cache.cache_by_subscription_info.is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_from_disk_with_entries() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "disk-test-id";
        let subscription_info = create_test_subscription_info(content_id);
        setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();

        let cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();

        assert_eq!(cache.cache_by_content_id.len(), 1);
        assert_eq!(cache.cache_by_subscription_info.len(), 1);

        let yang_lib_ref = cache
            .cache_by_content_id
            .get(&ContentId::from(content_id.to_string()))
            .unwrap();
        assert_eq!(yang_lib_ref.content_id(), content_id);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_get_by_content_id() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "get-by-id-test";

        let subscription_info = create_test_subscription_info(content_id);
        setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();

        let mut cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();

        let result = cache.get_by_content_id(&ContentId::from(content_id.to_string()));
        assert!(result.is_some());
        assert_eq!(result.unwrap().content_id(), content_id);

        let not_found = cache.get_by_content_id(&ContentId::from("nonexistent".to_string()));
        assert!(not_found.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_get_by_subscription_info() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "get-by-sub-test";

        let subscription_info = create_test_subscription_info(content_id);
        setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();

        let cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();

        let subscription_info = create_test_subscription_info(content_id);
        let result = cache.get_by_subscription_info(&subscription_info);
        assert!(result.is_some());
        assert_eq!(result.unwrap().content_id(), content_id);

        let other_info = create_test_subscription_info("other-id");
        let not_found = cache.get_by_subscription_info(&other_info);
        assert!(not_found.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_get_by_subscription_id() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "get-by-sub-id-test";

        let subscription_info = create_test_subscription_info(content_id);
        setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();

        let cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();

        let subscription_info = create_test_subscription_info(content_id);
        let peer_ip = subscription_info.peer().ip();
        let subscription_id = subscription_info.id();

        // Test successful lookup
        let result = cache.get_by_subscription_id(peer_ip, subscription_id);
        assert!(result.is_some());
        let (retrieved_info, yang_lib_ref) = result.unwrap();
        assert_eq!(retrieved_info, subscription_info);
        assert!(yang_lib_ref.is_some());
        assert_eq!(yang_lib_ref.unwrap().content_id(), content_id);

        // Test lookup with wrong subscription id
        let not_found = cache.get_by_subscription_id(peer_ip, 9999);
        assert!(not_found.is_none());

        // Test lookup with wrong peer ip
        let wrong_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let not_found = cache.get_by_subscription_id(wrong_ip, subscription_id);
        assert!(not_found.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_remove_by_content_id() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "remove-by-id-test";

        let subscription_info = create_test_subscription_info(content_id);
        setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();

        let mut cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();
        assert_eq!(cache.cache_by_content_id.len(), 1);

        let content_id_key = ContentId::from(content_id.to_string());
        cache.remove_by_content_id(&content_id_key).unwrap();

        assert!(cache.cache_by_content_id.is_empty());
        assert!(cache.cache_by_subscription_info.is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_remove_by_subscription_info() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "remove-by-sub-test";

        let subscription_info = create_test_subscription_info(content_id);
        setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info),
        )
        .unwrap();

        let mut cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();
        assert_eq!(cache.cache_by_subscription_info.len(), 1);

        let subscription_info = create_test_subscription_info(content_id);
        cache
            .remove_by_subscription_info(&subscription_info)
            .unwrap();

        assert!(cache.cache_by_content_id.is_empty());
        assert!(cache.cache_by_subscription_info.is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_remove_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = YangLibraryCache::new(temp_dir.path().to_path_buf());

        // Should not error when removing non-existent entries
        let result = cache.remove_by_content_id(&ContentId::from("nonexistent".to_string()));
        assert!(result.is_ok());

        let subscription_info = create_test_subscription_info("nonexistent");
        let result = cache.remove_by_subscription_info(&subscription_info);
        assert!(result.is_ok());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_from_disk_skips_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create a file (not a directory) in the root path
        let file_path = temp_dir.path().join("some-file.txt");
        std::fs::write(&file_path, "this is a file, not a directory").unwrap();

        let cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();
        assert!(cache.cache_by_content_id.is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_multiple_entries() {
        let temp_dir = TempDir::new().unwrap();

        let subscription_info1 = create_test_subscription_info("content_id");
        let subscription_info2 = SubscriptionInfo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 830),
            2,
            ContentId::from("content_id2".to_string()),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-routing:routing/routing-protocols".to_string()),
            ),
            vec!["ietf-routing".to_string()],
        );
        let subscription_info3 = SubscriptionInfo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)), 830),
            2,
            ContentId::from("content_id3".to_string()),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-routing:routing/routing-protocols".to_string()),
            ),
            vec!["ietf-routing".to_string()],
        );
        setup_yang_library_on_disk(
            &temp_dir,
            "content-id-1",
            std::slice::from_ref(&subscription_info1),
        )
        .unwrap();
        setup_yang_library_on_disk(
            &temp_dir,
            "content-id-2",
            std::slice::from_ref(&subscription_info2),
        )
        .unwrap();
        setup_yang_library_on_disk(
            &temp_dir,
            "content-id-3",
            std::slice::from_ref(&subscription_info3),
        )
        .unwrap();

        let cache = YangLibraryCache::from_disk(temp_dir.path().to_path_buf()).unwrap();

        assert_eq!(cache.cache_by_content_id.len(), 3);
        assert_eq!(cache.cache_by_subscription_info.len(), 3);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_reference_append_subscription_info() {
        let temp_dir = TempDir::new().unwrap();
        let content_id = "append-sub-test";

        // Create initial subscription info
        let subscription_info1 = create_test_subscription_info(content_id);
        setup_yang_library_on_disk(
            &temp_dir,
            content_id,
            std::slice::from_ref(&subscription_info1),
        )
        .unwrap();

        let entry_path = temp_dir.path().join(content_id);
        let yang_lib_path = entry_path.join(YANG_LIBRARY_FILE_NAME);
        let yang_lib_ref = YangLibraryReference::load_from_disk(yang_lib_path, entry_path).unwrap();

        // Verify initial state
        let initial_subscriptions = yang_lib_ref.subscriptions_info().unwrap();
        assert_eq!(initial_subscriptions, vec![subscription_info1.clone()]);

        // Test appending duplicate subscription info, should have no effect
        yang_lib_ref
            .append_subscription_info(subscription_info1.clone())
            .unwrap();
        let subscriptions_after_duplicate = yang_lib_ref.subscriptions_info().unwrap();
        assert_eq!(
            subscriptions_after_duplicate,
            vec![subscription_info1.clone()]
        );

        // Create different subscription info with the same content_id
        let subscription_info2 = SubscriptionInfo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 830),
            2,
            ContentId::from(content_id.to_string()),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-routing:routing/routing-protocols".to_string()),
            ),
            vec!["ietf-routing".to_string()],
        );

        // Test appending new subscription info
        yang_lib_ref
            .append_subscription_info(subscription_info2.clone())
            .unwrap();
        let subscriptions_after_new = yang_lib_ref.subscriptions_info().unwrap();
        assert_eq!(
            HashSet::from_iter(subscriptions_after_new.into_iter()),
            HashSet::from([subscription_info1.clone(), subscription_info2.clone()])
        );

        // Verify persisted data on disk
        let reloaded_yang_lib_ref = YangLibraryReference::load_from_disk(
            yang_lib_ref.yang_library_path().to_path_buf(),
            yang_lib_ref.yang_lib_ref_path().to_path_buf(),
        )
        .unwrap();
        let persisted_subscriptions = reloaded_yang_lib_ref.subscriptions_info().unwrap();
        assert_eq!(
            HashSet::from_iter(persisted_subscriptions.into_iter()),
            HashSet::from([subscription_info1, subscription_info2])
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_yang_library_cache_put_with_same_content_id_different_subscription() {
        let cache_dir = TempDir::new().unwrap();
        let content_id = "shared-content-id";
        let mut cache = YangLibraryCache::new(cache_dir.path().to_path_buf());

        // Create first subscription info
        let subscription_info1 = SubscriptionInfo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 830),
            1,
            ContentId::from(content_id.to_string()),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='eth0']/statistics".to_string()),
            ),
            vec!["ietf-interfaces".to_string(), "ietf-ip".to_string()],
        );

        // Create YANG library and schemas
        let yang_lib_xml = create_minimal_yang_library_xml(content_id);
        let reader = NsReader::from_str(&yang_lib_xml);
        let mut xml_reader = netgauze_netconf_proto::xml_utils::XmlParser::new(reader).unwrap();
        let yang_library = YangLibrary::xml_deserialize(&mut xml_reader).unwrap();

        let mut schemas = HashMap::new();
        schemas.insert(
            Box::from("test-module"),
            Box::from(create_test_yang_module()),
        );

        // Put first subscription
        let yang_lib_ref1 = cache
            .put_yang_library(
                subscription_info1.clone(),
                yang_library.clone(),
                schemas.clone(),
            )
            .unwrap();

        // Verify the first subscription is stored
        assert_eq!(cache.cache_by_content_id.len(), 1);
        assert_eq!(cache.cache_by_subscription_info.len(), 1);
        assert_eq!(cache.cache_by_subscription_id.len(), 1);

        // Create second subscription info with different peer and target but same
        // content_id
        let subscription_info2 = SubscriptionInfo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 830),
            2,
            ContentId::from(content_id.to_string()),
            Target::new_datastore(
                "ds:operational".to_string(),
                either::Right("/ietf-routing:routing/routing-protocols".to_string()),
            ),
            vec!["ietf-routing".to_string()],
        );

        // Put a second subscription with the same YANG library
        let yang_lib_ref2 = cache
            .put_yang_library(
                subscription_info2.clone(),
                yang_library.clone(),
                schemas.clone(),
            )
            .unwrap();

        // Verify both subscriptions share the same YANG library reference
        assert_eq!(yang_lib_ref1.content_id(), yang_lib_ref2.content_id());
        assert_eq!(cache.cache_by_content_id.len(), 1);
        assert_eq!(cache.cache_by_subscription_info.len(), 2);
        assert_eq!(cache.cache_by_subscription_id.len(), 2);

        // Verify both subscriptions can be retrieved
        let retrieved1 = cache.get_by_subscription_info(&subscription_info1);
        assert!(retrieved1.is_some());
        assert_eq!(retrieved1.unwrap().content_id(), content_id);

        let retrieved2 = cache.get_by_subscription_info(&subscription_info2);
        assert!(retrieved2.is_some());
        assert_eq!(retrieved2.unwrap().content_id(), content_id);

        // Verify both subscription IDs can be retrieved
        let (sub1_info, sub1_ref) = cache
            .get_by_subscription_id(subscription_info1.peer().ip(), subscription_info1.id())
            .unwrap();
        assert_eq!(sub1_info, subscription_info1);
        assert!(sub1_ref.is_some());

        let (sub2_info, sub2_ref) = cache
            .get_by_subscription_id(subscription_info2.peer().ip(), subscription_info2.id())
            .unwrap();
        assert_eq!(sub2_info, subscription_info2);
        assert!(sub2_ref.is_some());

        // Verify both subscriptions are persisted in the reference
        let subscriptions = yang_lib_ref2.subscriptions_info().unwrap();
        assert_eq!(subscriptions.len(), 2);
        assert!(subscriptions.contains(&subscription_info1));
        assert!(subscriptions.contains(&subscription_info2));
    }
}
