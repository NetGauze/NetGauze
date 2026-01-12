// Copyright (C) 2026-present The NetGauze Authors.
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

//! # Kafka YANG Consumer Example
//!
//! This example demonstrates how to consume YANG-encoded telemetry messages
//! from Kafka and validate them against YANG schemas stored in a Schema
//! Registry.
//!
//! ## Features
//!
//! - Consumes messages from a Kafka topic with configurable partitions and
//!   offsets
//! - Fetches YANG schemas (including dependencies) from Schema Registry
//! - Builds and caches YANG Library contexts for validation
//! - Validates message payloads against their associated YANG schemas
//! - Supports tail mode to read last N messages per partition
//! - Supports follow mode to continuously consume new messages
use anyhow::Result;
use clap::Parser;
use futures_util::StreamExt;
use netgauze_netconf_proto::yanglib::{
    Datastore, DatastoreName, Module, ModuleSet, Schema, Submodule, YangLibrary,
};
use netgauze_netconf_proto::yangparser::extract_yang_metadata;
use netgauze_yang_push::cache::storage::{SubscriptionInfo, YangLibraryReference};
use rdkafka::TopicPartitionList;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{Headers, Message};
use rdkafka::util::Timeout;
use schema_registry_client::rest::schema_registry_client::{Client, SchemaRegistryClient};
use serde_json::json;
use shadow_rs::shadow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use tokio::signal;
use tracing::{debug, error, info, trace, warn};
use yang4::context::Context;
use yang4::data::{DataFormat, DataParserFlags, DataValidationFlags};

shadow!(build);

// ============================================================================
// CLI Arguments
// ============================================================================

/// Kafka YANG message consumer with Schema Registry validation
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Librdkafka config file (json)
    #[arg(short = 'c', long)]
    config_file: Option<std::path::PathBuf>,

    /// Kafka bootstrap servers
    /// (overrides bootstrap.servers or metadata.broker.list
    /// parameters if present in librdkafka config file)
    #[arg(short = 'b', long)]
    bootstrap_servers: Option<String>,

    /// Consumer Group to use for consumer
    /// (overrides group.id parameter if present in librdkafka config file)
    #[arg(short = 'g', long = "group")]
    group_id: Option<String>,

    /// Topic to consume from
    #[arg(short = 't', long)]
    topic: String,

    /// Schema Registry URL
    #[arg(short = 's', long)]
    schema_registry_url: String,

    /// Path to cache YANG libraries
    #[arg(long, default_value = "kafka-yang-consumer-cache")]
    cache_root_path: std::path::PathBuf,

    /// Partitions to consume from (if empty, consumes from all partitions)
    #[arg(short = 'p', long = "partitions", value_delimiter = ',')]
    partitions: Vec<i32>,

    /// Offset to start consuming. Possible values: oldest, newest, or integer
    #[arg(short = 'o', long, default_value = "oldest", conflicts_with = "tail")]
    offset: String,

    /// Limit messages per partition (0 = unlimited)
    #[arg(short = 'l', long = "limit-messages", conflicts_with = "tail")]
    limit_messages: Option<usize>,

    /// Print last n messages per partition
    #[arg(short = 'n', long = "tail", conflicts_with_all = ["offset", "limit_messages"])]
    tail: Option<i32>,

    /// Continue to consume messages until program execution is
    /// interrupted/terminated
    #[arg(short = 'f', long = "follow")]
    follow: bool,
}

// ============================================================================
// Metadata & Cache
// ============================================================================

/// Metadata extracted from Schema Registry for a YANG module
#[derive(Debug, Clone)]
struct SchemaMetadata {
    name: String,
    namespace: Option<String>,
    revision: Option<String>,
    features: Vec<String>,
    is_submodule_of: Option<String>,
}

/// Validation statistics
#[derive(Debug, Default)]
struct ValidationStats {
    passed: usize,
    failed: usize,
    context_errors: usize,
    no_schema: usize,
    no_tm_schema: usize,
}

/// Cache for YANG contexts indexed by schema ID
struct YangContextCache {
    contexts: HashMap<i32, Context>,
}

impl YangContextCache {
    fn new() -> Self {
        Self {
            contexts: HashMap::new(),
        }
    }

    /// Get cached YANG context or fetch, build, and create it
    async fn get_or_create(
        &mut self,
        schema_id: i32,
        sr_client: &SchemaRegistryClient,
        cache_root_path: &std::path::Path,
        subscription_info: &SubscriptionInfo,
    ) -> Result<&Context> {
        // Check if already cached
        if self.contexts.contains_key(&schema_id) {
            debug!("Using cached YANG context for schema ID: {}", schema_id);
            return Ok(&self.contexts[&schema_id]);
        }

        info!("Creating new YANG context for schema ID: {}", schema_id);

        // Fetch schema recursively with metadata
        let mut schemas_ids = HashSet::new();
        let mut schemas = HashMap::new();
        let mut metadata_map = HashMap::new();

        fetch_schema_recursively(
            sr_client,
            None,
            schema_id,
            &mut schemas_ids,
            &mut schemas,
            &mut metadata_map,
        )
        .await?;

        debug!(
            "Successfully fetched {} schemas (for root schema with id={})",
            schemas.len(),
            schema_id
        );
        debug!(fetched_schemas_list=?schemas.keys().collect::<Vec<_>>());

        // Build YangLibrary and save to disk
        let yang_lib_ref = build_yang_library_and_save(
            schema_id,
            schemas,
            metadata_map,
            cache_root_path,
            subscription_info,
        )?;

        debug!(
            "Successfully built and saved YangLibrary with content-id: {}",
            yang_lib_ref.content_id()
        );
        debug!("YangLibrary path: {:?}", yang_lib_ref.yang_library_path());
        debug!("Modules directory: {:?}", yang_lib_ref.search_dir());

        // Create YANG context from the library
        let search_dir = yang_lib_ref.search_dir();
        let yang_ctx = Context::new_from_yang_library_file(
            &yang_lib_ref.yang_library_path(),
            DataFormat::XML,
            &search_dir.as_path(),
            yang4::context::ContextFlags::empty(),
        )?;

        info!(
            "Successfully created YANG context for schema ID: {}\n",
            schema_id
        );

        // Cache it and return reference
        self.contexts.insert(schema_id, yang_ctx);
        Ok(&self.contexts[&schema_id])
    }
}

// ============================================================================
// Schema Registry Functions
// ============================================================================

/// Recursively fetch a schema and all its references from Schema Registry
fn fetch_schema_recursively<'a>(
    client: &'a SchemaRegistryClient,
    schema_subject: Option<&'a str>,
    schema_id: i32,
    visited: &'a mut HashSet<i32>,
    schemas: &'a mut HashMap<Box<str>, Box<str>>,
    metadata_map: &'a mut HashMap<Box<str>, SchemaMetadata>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        if visited.contains(&schema_id) {
            debug!("Already fetched schema ID {}, skipping", schema_id);
            return Ok(());
        }
        visited.insert(schema_id);

        // Fetch the schema by ID
        let schema = client
            .get_by_subject_and_id(schema_subject, schema_id, None)
            .await?;

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Fetched schema ID {}, type={:?} with metadata:{:?}",
                schema_id, schema.schema_type, schema.metadata
            );

            let schema_lines: Vec<&str> = schema.schema.lines().take(4).collect();
            debug!("Schema content preview:");
            for line in schema_lines {
                debug!("  {}", line);
            }
            debug!("  ...");
        }

        trace!("Full schema content:\n{}", &schema.schema);

        // Extract features from Schema Registry metadata
        let sr_features: Vec<String> = schema
            .metadata
            .as_ref()
            .and_then(|m| m.tags.as_ref())
            .and_then(|tags| tags.get("features"))
            .cloned()
            .unwrap_or_default();

        // Extract the module metadata from the schema content
        let yang_metadata = match extract_yang_metadata(&schema.schema) {
            Ok(yang_module_metadata) => {
                let module_type = if yang_module_metadata.is_submodule_of.is_some() {
                    "submodule"
                } else {
                    "module"
                };
                debug!("Extracted {} metadata:", module_type);
                debug!("  Name:      {}", yang_module_metadata.name);
                if let Some(parent) = &yang_module_metadata.is_submodule_of {
                    debug!("  Parent:    {}", parent);
                }
                debug!(
                    "  Namespace: {}",
                    yang_module_metadata
                        .namespace
                        .as_deref()
                        .unwrap_or("<none>")
                );
                debug!(
                    "  Revision:  {}",
                    yang_module_metadata.revision.as_deref().unwrap_or("<none>")
                );

                SchemaMetadata {
                    name: yang_module_metadata.name.clone(),
                    namespace: yang_module_metadata.namespace.clone(),
                    revision: yang_module_metadata.revision.clone(),
                    features: sr_features,
                    is_submodule_of: yang_module_metadata.is_submodule_of.clone(),
                }
            }
            Err(e) => {
                warn!(
                    "Failed to extract module metadata from schema ID {}: {}. Using fallback.",
                    schema_id, e
                );

                // Fallback: use schema subject name
                let fallback_name = schema_subject
                    .and_then(|subject| subject.rsplit('.').next())
                    .unwrap_or("unknown-schema-name")
                    .to_string();

                SchemaMetadata {
                    name: fallback_name,
                    namespace: None,
                    revision: None,
                    features: sr_features,
                    is_submodule_of: None,
                }
            }
        };

        let module_name = yang_metadata.name.clone();

        // Store the schema content and metadata
        debug!("Storing schema '{}' (ID: {})", &module_name, schema_id);
        schemas.insert(module_name.clone().into(), schema.schema.clone().into());
        metadata_map.insert(module_name.into(), yang_metadata);

        // Process references recursively
        if let Some(references) = &schema.references {
            for reference in references {
                if let (Some(ref_subject), Some(ref_version)) =
                    (&reference.subject, reference.version)
                {
                    debug!(
                        "Fetching reference: {} version {}",
                        ref_subject, ref_version
                    );

                    let ref_schema = client
                        .get_version(ref_subject, ref_version, false, None)
                        .await?;

                    if let Some(ref_id) = ref_schema.id {
                        debug!("Fetching reference schema_id: {}", ref_id);
                        fetch_schema_recursively(
                            client,
                            Some(ref_subject),
                            ref_id,
                            visited,
                            schemas,
                            metadata_map,
                        )
                        .await?;
                    }
                }
            }
        }

        Ok(())
    })
}

/// Build a YangLibrary from the fetched schemas and save it to disk
fn build_yang_library_and_save(
    schema_id: i32,
    schemas: HashMap<Box<str>, Box<str>>,
    metadata_map: HashMap<Box<str>, SchemaMetadata>,
    cache_root_path: &std::path::Path,
    subscription_info: &SubscriptionInfo,
) -> Result<YangLibraryReference> {
    debug!(
        "Building YangLibrary from {} modules/submodules",
        metadata_map.len()
    );

    // Separate modules and submodules
    let mut modules_metadata: HashMap<Box<str>, SchemaMetadata> = HashMap::new();
    let mut submodules_metadata: HashMap<Box<str>, SchemaMetadata> = HashMap::new();

    for (name, metadata) in metadata_map {
        if metadata.is_submodule_of.is_some() {
            submodules_metadata.insert(name, metadata);
        } else {
            modules_metadata.insert(name, metadata);
        }
    }

    // Build modules with their submodules
    let mut modules = Vec::new();

    for (name, metadata) in &modules_metadata {
        debug!(
            "Creating module '{}' with {} features",
            name,
            metadata.features.len()
        );

        // Find all submodules that belong to this module
        let module_submodules: Vec<Submodule> = submodules_metadata
            .iter()
            .filter(|(_, sub_meta)| {
                sub_meta
                    .is_submodule_of
                    .as_ref()
                    .map(|parent| parent.as_str() == name.as_ref())
                    .unwrap_or(false)
            })
            .map(|(sub_name, sub_meta)| {
                debug!("  Adding submodule '{}' to module '{}'", sub_name, name);
                Submodule::new(
                    sub_name.clone(),
                    sub_meta.revision.as_ref().map(|s| s.as_str().into()),
                    Box::new([]),
                )
            })
            .collect();

        let module = Module::new(
            name.clone(),
            metadata.revision.as_ref().map(|s| s.as_str().into()),
            metadata
                .namespace
                .as_ref()
                .map(|s| s.as_str().into())
                .unwrap_or_else(|| format!("urn:unknown:{}", name).into()),
            metadata
                .features
                .iter()
                .map(|f| f.as_str().into())
                .collect::<Vec<Box<str>>>()
                .into_boxed_slice(),
            Box::new([]),
            module_submodules.into_boxed_slice(),
            Box::new([]),
            Box::new([]),
        );

        modules.push(module);
    }

    debug!(
        "Created {} modules with {} total submodules",
        modules.len(),
        submodules_metadata.len()
    );

    // Create module set
    let module_set_name: Box<str> = "schema-registry-modules".into();
    let module_set = ModuleSet::new(module_set_name.clone(), modules, vec![]);

    // Create schema
    let schema_name: Box<str> = "schema-registry-schema".into();
    let schema = Schema::new(schema_name.clone(), Box::new([module_set_name]));

    // Create datastore
    let datastore = Datastore::new(DatastoreName::Operational, schema_name);

    // Use schema_id as content_id
    let content_id: Box<str> = format!("schema-id-{}", schema_id).into();

    // Build YangLibrary
    let yang_library = YangLibrary::new(
        content_id.clone(),
        vec![module_set],
        vec![schema],
        vec![datastore],
    );

    debug!("Built YangLibrary with content-id: {}", content_id);

    // Save to disk
    let yang_lib_ref_path = cache_root_path.join(content_id.as_ref());

    // Clear existing directory content if it exists
    if yang_lib_ref_path.exists() {
        debug!(
            "Clearing existing YangLibrary content at: {:?}",
            yang_lib_ref_path
        );
        for entry in std::fs::read_dir(&yang_lib_ref_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
        }
    }

    debug!("Saving YangLibraryReference to: {:?}", yang_lib_ref_path);

    let yang_lib_ref = YangLibraryReference::save_to_disk(
        yang_lib_ref_path,
        &yang_library,
        schemas,
        std::slice::from_ref(subscription_info),
    )?;

    debug!("Successfully saved YangLibraryReference to disk");

    Ok(yang_lib_ref)
}

// ============================================================================
// Kafka Consumer Functions
// ============================================================================

/// Extract schema ID from Kafka message headers
fn extract_schema_id(headers: Option<&rdkafka::message::BorrowedHeaders>) -> Option<i32> {
    headers?.iter().find_map(|h| {
        if h.key == "schema-id" {
            h.value
                .and_then(|v| String::from_utf8_lossy(v).parse::<i32>().ok())
        } else {
            None
        }
    })
}

/// Load any Kafka configuration from file and overwrite from cli args if needed
fn load_kafka_config(args: &Args) -> Result<(String, String, HashMap<String, String>)> {
    let config: HashMap<String, String> = if let Some(config_path) = &args.config_file {
        let content = std::fs::read_to_string(config_path)?;
        serde_json::from_str(&content)?
    } else {
        HashMap::new()
    };

    // CLI args take precedence over config file
    let bootstrap = if let Some(bootstrap) = &args.bootstrap_servers {
        bootstrap.clone()
    } else {
        config
            .get("bootstrap.servers")
            .or_else(|| config.get("metadata.broker.list"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "bootstrap.servers must be provided via --bootstrap-servers CLI argument or in librdkafka config file.\n\
                     At least one of the following must be specified:\n\
                     - --bootstrap-servers\n\
                     - --config-file (containing bootstrap.servers or metadata.broker.list)"
                )
            })?
            .clone()
    };

    let group_id = if let Some(group_id) = &args.group_id {
        group_id.clone()
    } else {
        config
            .get("group.id")
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "group.id must be provided via --group CLI argument or in librdkafka config file.\n\
                     At least one of the following must be specified:\n\
                     - --group\n\
                     - --config-file (containing group.id)"
                )
            })?
            .clone()
    };

    Ok((bootstrap, group_id, config))
}

/// Setup Kafka consumer with partition assignment
async fn setup_consumer(
    args: &Args,
    bootstrap_servers: &str,
    group_id: &str,
    config_file: &HashMap<String, String>,
) -> Result<(StreamConsumer, Vec<i32>, usize)> {
    // Create consumer config
    let mut client_config = ClientConfig::new();
    client_config.set("group.id", group_id);
    client_config.set("bootstrap.servers", bootstrap_servers);
    client_config.set("enable.auto.commit", "false");
    client_config.set("enable.auto.offset.store", "false");

    if args.tail.is_some() || args.offset != "oldest" {
        client_config.set("auto.offset.reset", "latest");
    }

    // Apply additional config from file (skip bootstrap.servers,
    // metadata.broker.list, and group.id which we already pre-fetched)
    for (key, value) in config_file {
        if key != "bootstrap.servers" && key != "metadata.broker.list" && key != "group.id" {
            client_config.set(key, value);
        }
    }

    let consumer: StreamConsumer = client_config.create()?;

    // Wait for metadata
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let metadata = consumer.fetch_metadata(
        Some(&args.topic),
        Timeout::After(std::time::Duration::from_secs(5)),
    )?;

    let topic_metadata = metadata
        .topics()
        .first()
        .ok_or_else(|| anyhow::anyhow!("Topic not found"))?;

    // Determine target partitions
    let target_partitions: Vec<i32> = if args.partitions.is_empty() {
        topic_metadata.partitions().iter().map(|p| p.id()).collect()
    } else {
        let available: Vec<i32> = topic_metadata.partitions().iter().map(|p| p.id()).collect();
        for &p in &args.partitions {
            if !available.contains(&p) {
                return Err(anyhow::anyhow!("Partition {} does not exist", p));
            }
        }
        args.partitions.clone()
    };

    // Setup topic partition list with offsets
    let mut tpl = TopicPartitionList::new();

    for &partition_id in &target_partitions {
        let offset = if let Some(tail) = args.tail {
            let (_low, high) = consumer.fetch_watermarks(
                &args.topic,
                partition_id,
                Timeout::After(std::time::Duration::from_secs(5)),
            )?;

            let start_offset = (high - tail as i64).max(0);
            info!(
                "Partition {}: tailing {} messages from offset {} (high: {})",
                partition_id, tail, start_offset, high
            );
            rdkafka::Offset::Offset(start_offset)
        } else {
            match args.offset.to_lowercase().as_str() {
                "oldest" | "beginning" => {
                    info!("Partition {}: seeking to oldest", partition_id);
                    rdkafka::Offset::Beginning
                }
                "newest" | "end" => {
                    info!("Partition {}: seeking to newest", partition_id);
                    rdkafka::Offset::End
                }
                offset_str => {
                    if let Ok(offset_num) = offset_str.parse::<i64>() {
                        info!(
                            "Partition {}: seeking to offset {}",
                            partition_id, offset_num
                        );
                        rdkafka::Offset::Offset(offset_num)
                    } else {
                        return Err(anyhow::anyhow!(
                            "Invalid offset '{}'. Use: oldest, newest, or integer",
                            offset_str
                        ));
                    }
                }
            }
        };

        tpl.add_partition_offset(&args.topic, partition_id, offset)?;
    }

    consumer.assign(&tpl)?;

    info!(
        "Consumer assigned to {} partition(s)\n",
        target_partitions.len()
    );

    // Calculate per-partition limit
    let per_partition_limit = args
        .tail
        .map(|t| t as usize)
        .or(args.limit_messages)
        .unwrap_or(usize::MAX);

    Ok((consumer, target_partitions, per_partition_limit))
}

// ============================================================================
// Logging & Display Functions
// ============================================================================

fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("Failed to set default tracing env filter");

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer())
        .try_init()
        .expect("Failed to register tracing subscriber");

    Ok(())
}

fn log_build_info() {
    info!("");
    info!("═════════════════════════════════════════════════════════");
    info!(" * Build Information * ");
    info!("═════════════════════════════════════════════════════════");
    info!("  Package Version:    {}", build::PKG_VERSION);
    info!("  Commit Hash:        {}", build::COMMIT_HASH);
    info!("  Commit Date:        {}", build::COMMIT_DATE);
    info!("  Branch:             {}", build::BRANCH);
    info!("  Tag:                {}", build::TAG);
    info!("  Build Time:         {}", build::BUILD_TIME);
    info!("  Rust Channel:       {}", build::RUST_CHANNEL);
    info!("  Rust Version:       {}", build::RUST_VERSION);
    info!("  Cargo Version:      {}", build::CARGO_VERSION);
    info!("═════════════════════════════════════════════════════════");
    info!("");
}

fn log_configuration(
    args: &Args,
    bootstrap_servers: &str,
    group_id: &str,
    config_file: &HashMap<String, String>,
) {
    info!("");
    info!("═════════════════════════════════════════════════════════");
    info!(" * Kafka YANG Consumer Configuration * ");
    info!("═════════════════════════════════════════════════════════");
    info!("Kafka:");
    info!("  Bootstrap servers: {}", bootstrap_servers);

    if args.config_file.is_some() {
        info!("  Additional librdkafka parameters:");
        let mut sorted_keys: Vec<_> = config_file.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            if key == "bootstrap.servers" || key == "metadata.broker.list" || key == "group.id" {
                continue;
            }
            let value = &config_file[key];
            info!(
                "    {} = {}",
                key,
                if key.to_lowercase().contains("password") {
                    "*****"
                } else {
                    value
                }
            );
        }
    }

    info!("Consumer:");
    info!("  Topic: {}", args.topic);
    info!("  Group ID: {}", group_id);
    if args.tail.is_some() {
        info!("  Mode: tail (offset parameter ignored)");
    } else {
        info!("  Offset: {}", args.offset);
    }
    if !args.partitions.is_empty() {
        info!("  Partitions: {:?}", args.partitions);
    } else {
        info!("  Partitions: all");
    }
    if let Some(tail) = args.tail {
        info!("  Tail: {} messages per partition", tail);
    }
    if let Some(limit) = args.limit_messages {
        info!("  Limit: {} messages per partition", limit);
    }
    info!("  Follow: {}", if args.follow { "yes" } else { "no" });

    info!("Schema Registry:");
    info!("  URL: {}", args.schema_registry_url);
    info!("  Cache path: {:?}", args.cache_root_path);

    info!("═════════════════════════════════════════════════════════");
    info!("");
}

fn log_statistics(stats: &ValidationStats, total_count: usize) {
    info!("");
    info!("═════════════════════════════════════════════════════════");
    info!(" * Kafka YANG Consumer Statistics * ");
    info!("═════════════════════════════════════════════════════════");
    info!("Total messages processed:        {}", total_count);
    info!("");
    info!("Validation Summary:");
    info!("  Passed:                      {}", stats.passed);
    info!("  Failed:                      {}", stats.failed);
    info!("  Context errors:              {}", stats.context_errors);
    info!("  No schema-id (skipped):      {}", stats.no_schema);
    info!("  No ietf-tm schema (skipped): {}", stats.no_tm_schema);
    info!("");

    let validated_total = stats.passed + stats.failed;
    if validated_total > 0 {
        let success_rate = (stats.passed as f64 / validated_total as f64) * 100.0;
        info!("Validation success rate:         {:.2}%", success_rate);
    } else {
        info!("Validation success rate:         N/A (no messages validated)");
    }

    info!("═════════════════════════════════════════════════════════");
    info!("");
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing().map_err(|x| anyhow::anyhow!("Failed to init tracing subscriber: {x}"))?;

    let args = Args::parse();

    log_build_info();

    // Load configuration
    let (bootstrap_servers, group_id, config_file) = load_kafka_config(&args)?;

    log_configuration(&args, &bootstrap_servers, &group_id, &config_file);

    // Setup consumer
    let (consumer, target_partitions, per_partition_limit) =
        setup_consumer(&args, &bootstrap_servers, &group_id, &config_file).await?;

    // Create Schema Registry client
    let sr_config = schema_registry_client::rest::client_config::ClientConfig::new(vec![
        args.schema_registry_url.clone(),
    ]);
    let sr_client = SchemaRegistryClient::new(sr_config);

    // Create placeholder subscription info (reused for all schemas)
    let subscription_info = SubscriptionInfo::new_empty(
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0),
        0,
    );

    // Create YANG context cache
    let mut yang_ctx_cache = YangContextCache::new();

    // Track messages per partition
    let mut partition_counts: HashMap<i32, usize> =
        target_partitions.iter().map(|&p| (p, 0)).collect();

    // Track if we've completed the tail phase (only relevant when both tail and
    // follow are set)
    let mut tail_completed = args.tail.is_none();

    // Message processing loop
    let mut message_stream = consumer.stream();
    let mut total_count = 0;
    let mut validation_stats = ValidationStats::default();

    // Setup Ctrl+C handler
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
            message_result = message_stream.next() => {
                match message_result {
                    Some(Ok(borrowed_message)) => {
                        let partition_id = borrowed_message.partition();

                        // Check per-partition limit (only applies during tail phase or when not
                        // following)
                        let current_count = partition_counts[&partition_id];
                        if !tail_completed && current_count >= per_partition_limit {
                            if partition_counts.values().all(|&c| c >= per_partition_limit) {
                                if args.follow {
                                    debug!("Tail completed, now following new messages...");
                                    tail_completed = true;
                                    // Reset counters for follow mode
                                    for count in partition_counts.values_mut() {
                                        *count = 0;
                                    }
                                } else {
                                    info!("All partitions reached message limit, exiting");
                                    break;
                                }
                            } else {
                                continue;
                            }
                        }

                        // Extract message components
                        let payload = borrowed_message.payload().unwrap_or(&[]);
                        let key = borrowed_message.key().unwrap_or(&[]);
                        let headers = borrowed_message.headers().map(|headers| {
                            headers
                                .iter()
                                .map(|h| {
                                    json!({
                                        "key": h.key,
                                        "value": h.value.map(|v| String::from_utf8_lossy(v).to_string())
                                    })
                                })
                                .collect::<Vec<_>>()
                        });

                        // Parse payload as JSON
                        let payload_json = if !payload.is_empty() {
                            match serde_json::from_slice::<serde_json::Value>(payload) {
                                Ok(json_value) => json_value,
                                Err(_) => json!(String::from_utf8_lossy(payload)),
                            }
                        } else {
                            serde_json::Value::Null
                        };

                        // Log message metadata
                        let message_metadata = json!({
                            "topic": borrowed_message.topic(),
                            "partition": borrowed_message.partition(),
                            "offset": borrowed_message.offset(),
                            "timestamp": borrowed_message.timestamp().to_millis(),
                            "key": String::from_utf8_lossy(key),
                            "headers": headers,
                            "payload_len": payload.len(),
                        });

                        debug!(
                            "Message Metadata:\n{}",
                            serde_json::to_string_pretty(&message_metadata)?
                        );
                        debug!(
                            "Message Payload:\n{}",
                            serde_json::to_string(&payload_json)?
                        );

                        // Extract and validate with schema
                        if let Some(schema_id) = extract_schema_id(borrowed_message.headers()) {
                            debug!("Found schema-id in headers: {}", schema_id);

                            match yang_ctx_cache
                                .get_or_create(
                                    schema_id,
                                    &sr_client,
                                    &args.cache_root_path,
                                    &subscription_info,
                                )
                                .await
                            {
                                Ok(yang_ctx) => {
                                    debug!("Using YANG context for schema ID: {}", schema_id);

                                    // Get Telemetry Message module
                                    let tm_module =
                                        yang_ctx.get_module_implemented("ietf-telemetry-message");

                                    if tm_module.is_none() {
                                        warn!(
                                            "Message validation SKIPPED - partition: {}, offset: {}",
                                            borrowed_message.partition(),
                                            borrowed_message.offset()
                                        );
                                        warn!("  --> ietf-telemetry-message schema not found");
                                        validation_stats.no_tm_schema += 1;
                                    } else {
                                        // Extract ietf-telemetry-message extension instance
                                        let tm_ext = tm_module.as_ref().and_then(|m| m.extensions().next());

                                        // Validate message payload
                                        let validation_result = match &tm_ext {
                                            Some(ext) => yang4::data::DataTree::parse_ext_string(
                                                ext,
                                                &payload,
                                                DataFormat::JSON,
                                                DataParserFlags::STRICT,
                                                DataValidationFlags::PRESENT,
                                            ),
                                            // Support legacy ietf-telemetry-message without YANG structure
                                            None => yang4::data::DataTree::parse_string(
                                                yang_ctx,
                                                &payload,
                                                DataFormat::JSON,
                                                DataParserFlags::STRICT,
                                                DataValidationFlags::PRESENT,
                                            ),
                                        };

                                        match validation_result {
                                            Ok(_) => {
                                                info!(
                                                    "Message validation PASSED ✓ - partition: {}, offset: {}, schema_id: {}",
                                                    borrowed_message.partition(),
                                                    borrowed_message.offset(),
                                                    schema_id
                                                );
                                                validation_stats.passed += 1;
                                            }
                                            Err(err) => {
                                                error!(
                                                    "Message validation FAILED ✗ - partition: {}, offset: {}, schema_id: {}",
                                                    borrowed_message.partition(),
                                                    borrowed_message.offset(),
                                                    schema_id
                                                );
                                                error!("  --> Validation error: {}", err);
                                                validation_stats.failed += 1;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Message validation FAILED ✗ - partition: {}, offset: {}, schema_id: {}",
                                        borrowed_message.partition(),
                                        borrowed_message.offset(),
                                        schema_id,
                                    );
                                    error!("  --> Failed to get/create YANG context: {}", e);
                                    validation_stats.context_errors += 1;
                                }
                            }
                        } else {
                            warn!(
                                "Message validation SKIPPED - partition: {}, offset: {}",
                                borrowed_message.partition(),
                                borrowed_message.offset()
                            );
                            warn!("  --> No schema-id found in message headers");
                            validation_stats.no_schema += 1;
                        }

                        // Update counters
                        *partition_counts.get_mut(&partition_id).unwrap() += 1;
                        total_count += 1;

                        // Check exit condition
                        if !args.follow && partition_counts.values().all(|&c| c >= per_partition_limit) {
                            info!("All partitions reached limit, exiting");
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error receiving message: {}", e);
                    }
                    None => {
                        // Stream ended
                        break;
                    }
                }
            }
        }
    }

    consumer.unsubscribe();

    // Display final statistics
    log_statistics(&validation_stats, total_count);

    Ok(())
}
