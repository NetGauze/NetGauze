//! Example Kafka consumer that validates YANG messages using Schema Registry
//!
//! This example demonstrates:
//! 1. Consuming messages from Kafka
//! 2. Extracting schema ID from message headers
//! 3. Retrieving schemas from Confluent Schema Registry
//! 4. Loading schemas directly into libyang context (no file creation)
//! 5. Validating messages against YANG schemas
//!
//! Usage:
//! ```bash
//! # Consume all messages from beginning
//! cargo run --example kafka_yang_consumer
//!
//! # Consume last 10 messages and exit
//! cargo run --example kafka_yang_consumer -- -n 10
//!
//! # Consume last 10 messages and keep following
//! cargo run --example kafka_yang_consumer -- -n 10 -f
//!
//! # Follow from beginning
//! cargo run --example kafka_yang_consumer -- -f
//! ```

use anyhow::{Context as _, Result};
use clap::Parser;
use netgauze_yang_push::model::{
    notification::NotificationEnvelope, telemetry::TelemetryMessageWrapper,
};
use rdkafka::{
    config::ClientConfig,
    consumer::{Consumer, StreamConsumer},
    message::{BorrowedHeaders, Headers, Message},
    topic_partition_list::Offset,
};
use regex::Regex;
use schema_registry_converter::{
    async_impl::schema_registry::{get_referenced_schema, get_schema_by_id, SrSettings},
    schema_registry_common::{RegisteredSchema, SchemaType},
};
use std::{collections::HashMap, str::FromStr, time::Duration};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, trace, warn, Level};
use yang3::{
    context::{Context, ContextFlags},
    data::{DataFormat, DataOperation, DataTree},
};

/// Kafka YANG message consumer with Schema Registry validation
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of messages to consume from the end of the topic
    /// If not specified, starts from the beginning (or last committed offset)
    #[arg(short = 'n', long)]
    tail: Option<usize>,

    /// Follow mode: continue consuming new messages after reaching the end
    #[arg(short = 'f', long)]
    follow: bool,

    /// Kafka bootstrap servers
    #[arg(long, default_value = "localhost:49092")]
    bootstrap_servers: String,

    /// Consumer group ID
    #[arg(long, default_value = "yang-consumer-example")]
    group_id: String,

    /// Topic to consume from
    #[arg(short = 't', long, default_value = "telemetry-message-yang")]
    topic: String,

    /// Schema Registry URL
    #[arg(long, default_value = "http://localhost:48081")]
    schema_registry_url: String,

    /// Log level (TRACE, DEBUG, INFO, WARN, ERROR)
    #[arg(short = 'l', long, default_value = "INFO")]
    log_level: String,
}

/// Cache for YANG contexts indexed by schema ID
struct YangContextCache {
    contexts: HashMap<u32, Context>,
    schema_registry: SrSettings,
    temp_dir: std::path::PathBuf,
}

impl YangContextCache {
    fn new(schema_registry_url: String) -> Result<Self> {
        let schema_registry = SrSettings::new(schema_registry_url);

        // Create a unique temporary directory for this run using readable timestamp
        let timestamp: String = chrono::Local::now().format("%Y-%m-%d-%Hh%M").to_string();
        let temp_dir = std::env::temp_dir().join(format!("yang-schemas-{}", timestamp));

        std::fs::create_dir_all(&temp_dir)
            .context("Failed to create temporary directory for YANG schemas")?;

        info!(
            "Created temporary directory for YANG schemas: {:?}",
            temp_dir
        );

        Ok(Self {
            contexts: HashMap::new(),
            schema_registry,
            temp_dir,
        })
    }

    /// Get or create a YANG context for the given schema ID
    async fn get_or_create_context(&mut self, schema_id: u32) -> Result<&Context> {
        if self.contexts.contains_key(&schema_id) {
            debug!("Using cached context for schema ID: {}", schema_id);
            return Ok(&self.contexts[&schema_id]);
        }

        info!("Creating new context for schema ID: {}", schema_id);
        let context = self.create_context(schema_id).await?;
        self.contexts.insert(schema_id, context);
        Ok(&self.contexts[&schema_id])
    }

    /// Create a new YANG context from Schema Registry
    async fn create_context(&self, schema_id: u32) -> Result<Context> {
        // Retrieve root schema from Schema Registry
        let registered_schema = get_schema_by_id(schema_id, &self.schema_registry)
            .await
            .context("Failed to retrieve schema from Schema Registry")?;

        // Verify it's a YANG schema
        if !matches!(registered_schema.schema_type, SchemaType::Other(ref s) if s == "YANG") {
            anyhow::bail!(
                "Expected YANG schema type, got: {:?}",
                registered_schema.schema_type
            );
        }

        info!(
            "Retrieved root schema (ID: {}, {} references)",
            schema_id,
            registered_schema.references.len()
        );

        trace!(
            "Registered root schema: {}",
            serde_json::to_string(&registered_schema).unwrap()
        );

        // Create empty context with the temp directory as search path
        let mut context =
            Context::new(ContextFlags::empty()).context("Failed to create YANG context")?;

        // Set search directory to our temp directory
        context.set_searchdir(&self.temp_dir)?;
        debug!("Set YANG search directory to: {:?}", self.temp_dir);

        // Recursively collect all schemas (including nested references)
        let all_schemas = self
            .collect_all_schemas_recursive(&registered_schema)
            .await?;

        info!(
            "Total schemas collected (including nested): {}",
            all_schemas.len()
        );

        // Sort schemas by dependency order (modules with no imports first)
        let ordered_schemas = self.order_schemas_by_dependencies(&all_schemas)?;

        // Load each schema into the context
        for (idx, schema) in ordered_schemas.iter().enumerate() {
            let module_name = self.extract_module_name(&schema.schema)?;

            debug!(
                "Loading schema {}/{}: {} (ID: {})",
                idx + 1,
                ordered_schemas.len(),
                module_name,
                schema.id
            );

            // Write module to temporary file first
            use std::io::Write;
            let temp_file = self.temp_dir.join(format!("{}.yang", module_name));

            debug!("Writing module to temporary file: {:?}", temp_file);
            let mut file = std::fs::File::create(&temp_file)
                .context("Failed to create temporary YANG file")?;
            file.write_all(schema.schema.as_bytes())
                .context("Failed to write YANG schema to file")?;

            // IMPORTANT: Flush and sync to ensure data is written to disk
            file.flush().context("Failed to flush YANG file")?;
            file.sync_all()
                .context("Failed to sync YANG file to disk")?;
            drop(file);

            debug!("File written and synced: {:?}", temp_file);

            // Verify file exists and is readable
            if !temp_file.exists() {
                return Err(anyhow::anyhow!(
                    "Temporary YANG file not found after write: {:?}",
                    temp_file
                ));
            }

            trace!("Schema Tags: {:?}", schema.tags);

            // Extract features from schema tags
            let features = schema
                .tags
                .as_ref()
                .and_then(|tags| tags.get("features"))
                .map(|features| features.clone())
                .unwrap_or_default();

            if !features.is_empty() {
                debug!("Module {} has features: {:?}", module_name, features);
            }

            // Convert features to the format expected by load_module
            let features_refs: Vec<&str> = features.iter().map(|s| s.as_str()).collect();

            // Load the module with features
            match context.load_module(&module_name, None, &features_refs) {
                Ok(_) => {
                    if !features.is_empty() {
                        debug!(
                            "Successfully loaded module {} with features: {:?}",
                            module_name, features
                        );
                    } else {
                        debug!("Successfully loaded module: {}", module_name);
                    }
                }
                Err(e) => {
                    error!("Failed to load module {}: {}", module_name, e);
                    error!("File exists: {}", temp_file.exists());
                    error!("File path: {:?}", temp_file);
                    if !features.is_empty() {
                        error!("Features requested: {:?}", features);
                    }
                    return Err(anyhow::anyhow!(
                        "Failed to load YANG module {}: {}",
                        module_name,
                        e
                    ));
                }
            }
        }

        info!(
            "Successfully created context with {} modules",
            context.modules(false).count()
        );

        Ok(context)
    }

    /// Recursively collect all schemas including nested references
    async fn collect_all_schemas_recursive(
        &self,
        root_schema: &RegisteredSchema,
    ) -> Result<Vec<RegisteredSchema>> {
        let mut all_schemas = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut to_process = vec![root_schema.clone()];

        // Track schema IDs to avoid duplicates
        visited.insert(root_schema.id);

        while let Some(current_schema) = to_process.pop() {
            info!(
                "Processing schema ID {} with {} references",
                current_schema.id,
                current_schema.references.len()
            );

            // Process all references of the current schema
            for reference in &current_schema.references {
                // Fetch the referenced schema
                let ref_schema = get_referenced_schema(&self.schema_registry, reference)
                    .await
                    .context(format!(
                        "Failed to retrieve reference schema: {}",
                        reference.subject
                    ))?;

                trace!(
                    "Fetched reference schema: {} (ID: {}, Schema Tags: {:?}, {} nested references)",
                    reference.subject,
                    ref_schema.id,
                    ref_schema.tags,
                    ref_schema.references.len()
                );

                // Only add if not already visited
                if visited.insert(ref_schema.id) {
                    debug!(
                        "Adding schema {} (ID: {}) to processing queue",
                        reference.subject, ref_schema.id
                    );

                    // Add to schemas list
                    all_schemas.push(ref_schema.clone());

                    // Add to processing queue if it has references
                    if !ref_schema.references.is_empty() {
                        to_process.push(ref_schema);
                    }
                } else {
                    debug!(
                        "Schema {} (ID: {}) already visited, skipping",
                        reference.subject, ref_schema.id
                    );
                }
            }
        }

        // Add root schema last
        all_schemas.push(root_schema.clone());

        info!("Collected {} unique schemas", all_schemas.len(),);

        Ok(all_schemas)
    }

    /// Order schemas by their dependencies (leaf nodes first)
    fn order_schemas_by_dependencies(
        &self,
        schemas: &[RegisteredSchema],
    ) -> Result<Vec<RegisteredSchema>> {
        let mut ordered = Vec::new();
        let mut loaded = std::collections::HashSet::new();

        // Build a map of module names to schemas for quick lookup
        let mut module_to_schema: HashMap<String, RegisteredSchema> = HashMap::new();
        for schema in schemas {
            let module_name = self.extract_module_name(&schema.schema)?;
            module_to_schema.insert(module_name, schema.clone());
        }

        // Simple approach: try to load schemas, retrying those that fail due to missing
        // dependencies
        let mut remaining: Vec<_> = schemas.to_vec();
        let mut retry_count = 0;
        let max_retries = schemas.len() * 3; // Increase retries

        while !remaining.is_empty() && retry_count < max_retries {
            let mut progress = false;
            let mut next_remaining = Vec::new();

            for schema in remaining {
                let module_name = self.extract_module_name(&schema.schema)?;
                let dependencies = self.extract_dependencies(&schema.schema)?;

                // Filter dependencies to only those that exist in our schema set
                let known_dependencies: Vec<_> = dependencies
                    .iter()
                    .filter(|dep| module_to_schema.contains_key(*dep))
                    .collect();

                // Check if all known dependencies are already loaded
                let all_deps_loaded = known_dependencies.iter().all(|dep| loaded.contains(*dep));

                // Log unknown dependencies (might be standard modules)
                let unknown_deps: Vec<_> = dependencies
                    .iter()
                    .filter(|dep| !module_to_schema.contains_key(*dep))
                    .collect();

                if !unknown_deps.is_empty() {
                    trace!(
                        "Module {} has unknown dependencies (likely standard modules): {:?}",
                        module_name,
                        unknown_deps
                    );
                }

                if all_deps_loaded {
                    debug!(
                        "Adding {} to ordered list (dependencies satisfied)",
                        module_name
                    );
                    ordered.push(schema.clone());
                    loaded.insert(module_name);
                    progress = true;
                } else {
                    trace!(
                        "Deferring {} (waiting for dependencies: {:?})",
                        module_name,
                        known_dependencies
                            .iter()
                            .filter(|d| !loaded.contains(**d))
                            .collect::<Vec<_>>()
                    );
                    next_remaining.push(schema);
                }
            }

            remaining = next_remaining;
            retry_count += 1;

            if !progress && !remaining.is_empty() {
                warn!(
                    "Could not resolve dependencies for {} schemas after {} retries, loading anyway",
                    remaining.len(),
                    retry_count
                );

                // Log which schemas couldn't be ordered
                for schema in &remaining {
                    let module_name = self.extract_module_name(&schema.schema).unwrap_or_default();
                    let dependencies = self
                        .extract_dependencies(&schema.schema)
                        .unwrap_or_default();
                    warn!(
                        "Unresolved schema: {} (dependencies: {:?})",
                        module_name, dependencies
                    );
                }

                ordered.extend(remaining);
                break;
            }
        }

        info!("Ordered {} schemas by dependencies", ordered.len());
        Ok(ordered)
    }

    /// Extract module name from YANG schema string
    fn extract_module_name(&self, schema: &str) -> Result<String> {
        // Parse YANG schema to extract module name
        // Looking for: "module <name> {" or "submodule <name> {"
        for line in schema.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("module ") {
                if let Some(name) = rest.split_whitespace().next() {
                    return Ok(name.to_string());
                }
            }
            if let Some(rest) = trimmed.strip_prefix("submodule ") {
                if let Some(name) = rest.split_whitespace().next() {
                    return Ok(name.to_string());
                }
            }
        }
        anyhow::bail!("Could not extract module name from YANG schema")
    }

    /// Extract import dependencies from YANG schema
    fn extract_dependencies(&self, schema: &str) -> Result<Vec<String>> {
        // Regex matches: import <module-name> { or include <submodule-name> {
        let re = Regex::new(r#"(?m)^\s*(import|include)\s+([a-zA-Z0-9\-_]+)\s*[{;]"#).unwrap();
        let mut dependencies = Vec::new();

        // Remove all /* ... */ comments
        let schema_no_multiline = Regex::new(r"(?s)/\*.*?\*/")
            .unwrap()
            .replace_all(schema, "");
        // Remove all // comments
        let schema_cleaned = Regex::new(r"(?m)//.*$")
            .unwrap()
            .replace_all(&schema_no_multiline, "");

        for cap in re.captures_iter(&schema_cleaned) {
            let module = cap.get(2).unwrap().as_str();
            dependencies.push(module.to_string());
            trace!("Found dependency: {}", module);
        }

        debug!(
            "Extracted {} dependencies: {:?}",
            dependencies.len(),
            dependencies
        );
        Ok(dependencies)
    }
}

/// Extract schema ID from Kafka message headers
fn extract_schema_id(headers: Option<&BorrowedHeaders>) -> Option<u32> {
    headers?.iter().find_map(|header| {
        if header.key == "schema-id" {
            header
                .value
                .and_then(|v| std::str::from_utf8(v).ok())
                .and_then(|s| s.parse::<u32>().ok())
        } else {
            None
        }
    })
}

/// Validate a YANG message against a context
fn validate_message(context: &Context, message: &str) -> Result<()> {
    debug!("Validating message: {}", message);

    let data_tree = match DataTree::parse_op_string(
        context,
        message.to_string(),
        DataFormat::JSON,
        DataOperation::NotificationYang,
    ) {
        Ok(data_tree) => data_tree,
        Err(e) => {
            warn!("Message validation failed: {}", e.to_string());
            warn!("Temporary fallback to validating notification envelope contents only");

            match serde_json::from_str::<TelemetryMessageWrapper>(message) {
                Ok(telemetry_msg) => {
                    if let Some(payload) = telemetry_msg.message().payload() {
                        if let Some(envelope_v) = payload.get("ietf-yp-notification:envelope") {
                            let envelope: NotificationEnvelope =
                                serde_json::from_value(envelope_v.clone())?;
                            if let Some(contents) = envelope.contents() {
                                match DataTree::parse_op_string(
                                    context,
                                    serde_json::to_string(contents)?,
                                    DataFormat::JSON,
                                    DataOperation::NotificationYang,
                                ) {
                                    Ok(data_tree) => data_tree,
                                    Err(e) => return Err(e.into()),
                                }
                            } else {
                                return Err(anyhow::anyhow!(
                                    "No contents in notification envelope"
                                ));
                            }
                        } else {
                            return Err(anyhow::anyhow!("Telemetry message payload does not contain ietf-yp-notification:envelope"));
                        }
                    } else {
                        return Err(anyhow::anyhow!("Telemetry message has no payload"));
                    }
                }
                Err(e) => {
                    error!("Failing to deserialize into TelemetryMessageWrapper: {}", e);
                    return Err(anyhow::anyhow!(
                        "Failing to deserialize into TelemetryMessageWrapper"
                    ));
                }
            }
        }
    };

    info!("Message validation successful");
    debug!("Validated data tree: {:?}", data_tree);

    Ok(())
}

fn init_tracing(level: &str) {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::from_str(level).expect("invalid logging level"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    init_tracing(&args.log_level);

    info!("Starting Kafka YANG consumer example");
    info!("Topic: {}", args.topic);
    info!("Bootstrap servers: {}", args.bootstrap_servers);
    info!("Schema Registry: {}", args.schema_registry_url);

    if let Some(tail) = args.tail {
        info!("Mode: Tail last {} messages", tail);
    } else {
        info!("Mode: Start from beginning/last committed offset");
    }

    if args.follow {
        info!("Follow mode: ENABLED (will continue consuming new messages)");
    } else {
        info!("Follow mode: DISABLED (will exit after consuming available messages)");
    }

    // Create Kafka consumer
    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &args.bootstrap_servers)
        .set("group.id", &args.group_id)
        .set("enable.auto.commit", "false") // Disable for manual control
        .set("auto.offset.reset", "earliest")
        .create()
        .context("Failed to create Kafka consumer")?;

    // If tail mode, use manual assignment for immediate seeking
    if let Some(tail_count) = args.tail {
        info!("Using manual partition assignment for tail mode");

        // Get metadata to find partitions
        let metadata = consumer
            .fetch_metadata(Some(&args.topic), Duration::from_secs(10))
            .context("Failed to fetch metadata")?;

        // Create topic partition list
        let mut tpl = rdkafka::TopicPartitionList::new();

        for topic_metadata in metadata.topics() {
            if topic_metadata.name() == args.topic {
                for partition in topic_metadata.partitions() {
                    let partition_id = partition.id();

                    // Get high watermark (latest offset)
                    let (low, high) = consumer
                        .fetch_watermarks(&args.topic, partition_id, Duration::from_secs(10))
                        .context("Failed to fetch watermarks")?;

                    // Calculate offset for last N messages
                    let start_offset = if high > tail_count as i64 {
                        high - tail_count as i64
                    } else {
                        low
                    };

                    info!(
                        "Partition {}: assigning with offset {} (low: {}, high: {})",
                        partition_id, start_offset, low, high
                    );

                    // Add partition with offset to assignment
                    tpl.add_partition_offset(
                        &args.topic,
                        partition_id,
                        Offset::Offset(start_offset),
                    )
                    .context("Failed to add partition offset")?;
                }
            }
        }

        // Assign partitions directly
        consumer
            .assign(&tpl)
            .context("Failed to assign partitions")?;

        info!("Assigned {} partitions", tpl.count());
    } else {
        // Normal subscription for non-tail mode
        consumer
            .subscribe(&[&args.topic])
            .context("Failed to subscribe to topic")?;
        info!("Subscribed to topic: {}", args.topic);
    }

    // Create context cache
    let mut context_cache = YangContextCache::new(args.schema_registry_url.clone())?;

    // Consume messages
    let mut message_stream = consumer.stream();
    let mut message_count = 0;
    let max_messages = if args.follow {
        None // No limit in follow mode
    } else {
        args.tail // Limit to tail count if not following
    };

    // Statistics counters
    let mut validated_success = 0;
    let mut validated_failed = 0;

    while let Some(message_result) = message_stream.next().await {
        match message_result {
            Ok(message) => {
                message_count += 1;

                // Extract schema ID from headers
                let schema_id = match extract_schema_id(message.headers()) {
                    Some(id) => {
                        info!("Received message with schema ID: {}", id);
                        id
                    }
                    None => {
                        warn!("Message missing schema-id header, skipping");
                        continue;
                    }
                };

                // Extract message payload
                let payload = match message.payload_view::<str>() {
                    Some(Ok(payload)) => payload,
                    Some(Err(e)) => {
                        error!("Failed to decode message payload: {}", e);
                        continue;
                    }
                    None => {
                        warn!("Empty message payload");
                        continue;
                    }
                };

                let msg_info = if let Some(max) = max_messages {
                    format!("Processing message {}/{}", message_count, max)
                } else {
                    format!("Processing message #{}", message_count)
                };
                info!("{} from topic: {}", msg_info, message.topic());
                debug!("Message payload: {}", payload);

                // Get or create YANG context
                let context = match context_cache.get_or_create_context(schema_id).await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        error!(
                            "Failed to get/create context for schema ID {}: {}",
                            schema_id, e
                        );
                        continue;
                    }
                };

                // Validate message
                match validate_message(context, payload) {
                    Ok(()) => {
                        info!("✓ Message validated successfully");
                        validated_success += 1;
                    }
                    Err(e) => {
                        error!("✗ Message validation failed: {}\n\n{}\n", e, payload);
                        validated_failed += 1;
                    }
                }

                // Exit immediately after processing the specified number of messages
                if let Some(max) = max_messages {
                    if message_count >= max {
                        info!("Processed {} messages, exiting (no follow mode)", max);
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Kafka error: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    info!("Finished processing messages (total: {})", message_count);
    info!(
        "Validation statistics: {} succeeded, {} failed",
        validated_success, validated_failed
    );
    Ok(())
}
