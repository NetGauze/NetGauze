use crate::{
    xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
    yangparser::{extract_yang_dependencies, YangDependencies},
    YANG_DATASTORES_NS_STR, YANG_LIBRARY_AUGMENTED_BY_NS, YANG_LIBRARY_NS,
};
use indexmap::IndexMap;
use petgraph::prelude::EdgeRef;
use quick_xml::{
    events::{BytesText, Event},
    name::{QName, ResolveResult},
};
use russh::keys::signature::digest::Digest;
use schema_registry_client::rest::{
    models::RegisteredSchema, schema_registry_client::Client as SRClient,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    path::Path,
};
// ============================================================================
// Core Structures
// ============================================================================

/// Root container for YANG Library (RFC 8525)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename = "ietf-yang-library:yang-library")]
pub struct YangLibrary {
    #[serde(rename = "content-id")]
    content_id: Box<str>,
    modules_set: IndexMap<Box<str>, ModuleSet>,
    schemas: IndexMap<Box<str>, Schema>,
    datastores: IndexMap<DatastoreName, Datastore>,
}

impl YangLibrary {
    pub fn new(
        content_id: Box<str>,
        modules_set: Vec<ModuleSet>,
        schemas: Vec<Schema>,
        datastores: Vec<Datastore>,
    ) -> Self {
        let mut modules_set_map = IndexMap::with_capacity(modules_set.len());
        let mut schemas_map = IndexMap::with_capacity(schemas.len());
        let mut datastores_map = IndexMap::with_capacity(datastores.len());
        for module in modules_set {
            modules_set_map.insert(module.name.clone(), module);
        }
        for schema in schemas {
            schemas_map.insert(schema.name.clone(), schema);
        }
        for datastore in datastores {
            datastores_map.insert(datastore.name.clone(), datastore);
        }
        Self {
            content_id,
            modules_set: modules_set_map,
            schemas: schemas_map,
            datastores: datastores_map,
        }
    }

    pub const fn content_id(&self) -> &str {
        &self.content_id
    }

    pub const fn module_sets(&self) -> &IndexMap<Box<str>, ModuleSet> {
        &self.modules_set
    }

    pub const fn schemas(&self) -> &IndexMap<Box<str>, Schema> {
        &self.schemas
    }

    pub const fn datastores(&self) -> &IndexMap<DatastoreName, Datastore> {
        &self.datastores
    }

    /// Helper to find a YANG module by name
    pub fn find_module(&self, name: &str) -> Option<&Module> {
        for module_set in self.modules_set.values() {
            if let Some(module) = module_set.modules().get(name) {
                return Some(module);
            }
        }
        None
    }

    /// Helper to find a YANG submodule by name
    pub fn find_submodule(&self, name: &str) -> Option<&Submodule> {
        for module_set in self.modules_set.values() {
            for module in module_set.modules().values() {
                for submodule in module.submodules() {
                    if submodule.name() == name {
                        return Some(submodule);
                    }
                }
            }
        }
        None
    }

    /// Helper to find an import-only YANG module by name returns a list of
    /// import only modules since YANG library allows multiple versions to
    /// co-exist.
    pub fn find_import_module(&self, name: &str) -> Option<Vec<&ImportOnlyModule>> {
        for module_set in self.modules_set.values() {
            if let Some(import_only) = module_set.import_only_modules().get(name) {
                let mut ret = Vec::with_capacity(import_only.len());
                for module in import_only.values() {
                    ret.push(module);
                }
                return Some(ret);
            }
        }
        None
    }

    /// Register the YANG Lib to in the Confluent Schema Registry.
    /// Note: references are registered recursively.
    pub async fn register_schema<T: SRClient>(
        &self,
        root_schema_name: &str,
        schemas: &HashMap<Box<str>, Box<str>>,
        client: &T,
    ) -> Result<RegisteredSchema, SchemaConstructionError> {
        if self.find_module(root_schema_name).is_none() {
            return Err(SchemaConstructionError::ModuleNotFound {
                module_name: root_schema_name.to_string(),
            });
        }
        // Convert the YANG library into a dependency graph.
        let graph = self
            .to_graph(schemas)
            .map_err(SchemaConstructionError::Graph)?;

        let mut root_index = None;
        let mut nodes_with_zero_outgoing_edges = HashSet::new();
        for node_idx in graph.node_indices() {
            // it's safe to unwrap here since we constructed the graph above
            if root_schema_name == *graph.node_weight(node_idx).unwrap() {
                root_index = Some(node_idx);
            }
            let in_degree: usize = graph
                .neighbors_directed(node_idx, petgraph::Direction::Outgoing)
                .count();
            if in_degree == 0 {
                nodes_with_zero_outgoing_edges.insert(*graph.node_weight(node_idx).unwrap());
            }
        }
        let topo_sorted = petgraph::algo::toposort(&graph, None).map_err(|x| {
            SchemaConstructionError::CycleDetected(
                graph.node_weight(x.node_id()).unwrap().to_string(),
            )
        })?;

        if tracing::enabled!(tracing::Level::DEBUG) {
            let topo_sort = topo_sorted
                .iter()
                .map(|idx| graph.node_weight(*idx).unwrap().to_string())
                .collect::<Vec<String>>()
                .join(",");
            tracing::debug!(
                "topological sort to register schemas in the the schema registry: {}",
                topo_sort
            );
        }
        // safe to unwrap since we constructed the graph above and checked the root
        // module exists
        let root_index = root_index.unwrap();
        let mut supplied_references: HashMap<
            &str,
            schema_registry_client::rest::models::SchemaReference,
        > = HashMap::new();
        for node_idx in topo_sorted {
            let name = *graph.node_weight(node_idx).unwrap();
            tracing::debug!("Starting process to register schema {name}");
            self.find_module(root_schema_name)
                .ok_or(SchemaConstructionError::ModuleNotFound {
                    module_name: name.to_string(),
                })?;
            // Extract features if this is a module (not a submodule)
            let tags = if let Some(module) = self.find_module(name) {
                Self::get_features(module.features())
            } else {
                None
            };
            let mut references = Vec::new();
            for incoming_edge in graph.edges_directed(node_idx, petgraph::Direction::Incoming) {
                let dep_name = *graph.node_weight(incoming_edge.source()).unwrap();
                let dep = supplied_references.get(dep_name).unwrap().clone();
                if tracing::enabled!(tracing::Level::DEBUG) {
                    let retrieved = client
                        .get_version(dep_name, dep.version.unwrap(), false, None)
                        .await
                        .expect("Failed to get schema");
                    let features = retrieved
                        .metadata
                        .unwrap_or_default()
                        .tags
                        .unwrap_or_default()
                        .get("features")
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>()
                        .join(",");
                    tracing::debug!("For schema `{name}` registering reference `{dep_name}` with features [{features}]");
                }

                references.push(dep);
            }

            let schema = schema_registry_client::rest::models::Schema {
                schema_type: Some("YANG".to_string()),
                references: Some(references),
                metadata: Some(Box::new(schema_registry_client::rest::models::Metadata {
                    properties: None,
                    tags: tags.clone(),
                    sensitive: None,
                })),
                rule_set: None,
                schema: schemas.get(name).unwrap().to_string(),
            };

            if tracing::enabled!(tracing::Level::DEBUG) {
                let schema_ref = &schema;
                let features = schema_ref
                    .metadata
                    .as_ref()
                    .unwrap_or(&Box::new(
                        schema_registry_client::rest::models::Metadata::default(),
                    ))
                    .tags
                    .as_ref()
                    .unwrap_or(&BTreeMap::default())
                    .get("features")
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                tracing::debug!("Registering schema `{name}` with features [{features}]");
            }
            let registered_schema = Self::register_with_retry(client, name, &schema).await?;
            tracing::info!(
                "registered schema {name} with subject `{:?}`, version `{:?}` and ID `{:?}`",
                registered_schema.subject,
                registered_schema.version,
                registered_schema.id
            );
            let schema_reference = schema_registry_client::rest::models::SchemaReference {
                name: Some(name.to_string()),
                subject: Some(registered_schema.subject.clone().unwrap_or_default()),
                version: Some(registered_schema.version.unwrap_or_default()),
            };
            supplied_references.insert(name, schema_reference);
        }
        let tags = if let Some(module) = self.find_module(root_schema_name) {
            Self::get_features(module.features())
        } else {
            None
        };
        let mut refs = Vec::new();
        let mut supplied_schema = schema_registry_client::rest::models::Schema {
            schema_type: Some("YANG".to_string()),
            references: None,
            metadata: Some(Box::new(schema_registry_client::rest::models::Metadata {
                tags,
                properties: None,
                sensitive: None,
            })),
            rule_set: None,
            schema: schemas.get(root_schema_name).unwrap().to_string(),
        };
        for incoming_edge in graph.edges_directed(root_index, petgraph::Direction::Incoming) {
            let dep = *graph.node_weight(incoming_edge.source()).unwrap();
            tracing::debug!("Adding Root {dep} Depending on {root_schema_name}");
            refs.push(supplied_references.get(dep).unwrap().clone());
        }
        // This part adds the deviations to the root scheme
        for n in nodes_with_zero_outgoing_edges {
            tracing::debug!("Adding Root {n} Depending on {root_schema_name}");
            refs.push(supplied_references.get(n).unwrap().clone());
        }
        if !refs.is_empty() {
            supplied_schema.references = Some(refs);
        }
        Self::register_with_retry(client, root_schema_name, &supplied_schema).await
    }

    async fn register_with_retry<T: SRClient>(
        client: &T,
        name: &str,
        schema: &schema_registry_client::rest::models::Schema,
    ) -> Result<RegisteredSchema, SchemaConstructionError> {
        let registered_schema_result = client.register_schema(name, schema, false).await;
        let registered_schema = match registered_schema_result {
            Ok(registered_schema) => registered_schema,
            Err(e) => {
                tracing::warn!("Failed to register schema `{name}` with error `{e}`, trying again with disabling compatibility check");
                let server_config = schema_registry_client::rest::models::ServerConfig {
                    compatibility: Some(
                        schema_registry_client::rest::models::CompatibilityLevel::None,
                    ),
                    ..Default::default()
                };
                client
                    .update_config(name, &server_config)
                    .await
                    .map_err(SchemaConstructionError::RegistrationError)?;
                client
                    .register_schema(name, schema, false)
                    .await
                    .map_err(SchemaConstructionError::RegistrationError)?
            }
        };
        tracing::info!(
            "registered schema {name} with subject `{:?}`, version `{:?}` and ID `{:?}`",
            registered_schema.subject,
            registered_schema.version,
            registered_schema.id,
        );
        Ok(registered_schema)
    }

    fn get_features(features: &[Box<str>]) -> Option<BTreeMap<String, Vec<String>>> {
        let features = features.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        if features.is_empty() {
            None
        } else {
            Some(BTreeMap::from([("features".to_string(), features)]))
        }
    }

    /// Create a graph representation of the YANG library
    /// that indicated the dependencies between the various modules listed
    /// in the library.
    pub fn to_graph(
        &self,
        yang_schemas: &HashMap<Box<str>, Box<str>>,
    ) -> Result<petgraph::graph::DiGraph<&str, ()>, String> {
        let mut graph = petgraph::Graph::<&str, ()>::new();
        let mut node_indices = HashMap::new();
        // Add nodes for all modules
        self.construct_nodes(&mut graph, &mut node_indices);
        for module_set in self.modules_set.values() {
            for module in module_set.modules().values() {
                self.add_module_to_graph(module, &mut graph, &mut node_indices, yang_schemas)?;
            }
            for import_modules in module_set.import_only_modules.values() {
                for import_only_module in import_modules.values() {
                    self.add_import_only_module_to_graph(
                        import_only_module,
                        &mut graph,
                        &mut node_indices,
                        yang_schemas,
                    )?;
                }
            }
        }
        Ok(graph)
    }

    fn add_import_only_module_to_graph(
        &self,
        import_only_module: &ImportOnlyModule,
        graph: &mut petgraph::Graph<&str, ()>,
        node_indices: &mut HashMap<&str, petgraph::prelude::NodeIndex>,
        yang_schemas: &HashMap<Box<str>, Box<str>>,
    ) -> Result<(), String> {
        let a = *node_indices.get(import_only_module.name()).unwrap();
        let schema = yang_schemas.get(import_only_module.name()).ok_or(format!(
            "No schema for import only module {}",
            import_only_module.name()
        ))?;
        let deps = extract_yang_dependencies(schema)?;
        self.add_deps_to_graph(&deps, graph, a, node_indices, yang_schemas)?;
        Ok(())
    }

    fn add_deps_to_graph(
        &self,
        deps: &YangDependencies,
        graph: &mut petgraph::Graph<&str, ()>,
        current_node_idx: petgraph::prelude::NodeIndex,
        node_indices: &mut HashMap<&str, petgraph::prelude::NodeIndex>,
        schemas: &HashMap<Box<str>, Box<str>>,
    ) -> Result<(), String> {
        for import in &deps.imports {
            self.check_module_exists(import.module_name.as_str())?;
            let b = *node_indices
                .get(import.module_name.as_str())
                .ok_or(format!("No module {} found in graph", import.module_name))?;
            if !graph.contains_edge(b, current_node_idx) {
                graph.add_edge(b, current_node_idx, ());
            }
        }
        for include in &deps.includes {
            self.find_submodule(include.submodule_name.as_str())
                .ok_or(format!(
                    "No submodule {} found in YANG Library",
                    include.submodule_name
                ))?;
            let b = *node_indices
                .get(include.submodule_name.as_str())
                .ok_or(format!(
                    "No submodule {} found in graph",
                    include.submodule_name
                ))?;
            if !graph.contains_edge(b, current_node_idx) {
                graph.add_edge(b, current_node_idx, ());
            }
            let include_deps =
                extract_yang_dependencies(schemas.get(include.submodule_name.as_str()).unwrap())?;
            self.add_deps_to_graph(&include_deps, graph, b, node_indices, schemas)?;
        }
        Ok(())
    }

    fn add_module_to_graph(
        &self,
        module: &Module,
        graph: &mut petgraph::Graph<&str, ()>,
        node_indices: &mut HashMap<&str, petgraph::prelude::NodeIndex>,
        yang_schemas: &HashMap<Box<str>, Box<str>>,
    ) -> Result<(), String> {
        let a = *node_indices.get(module.name()).unwrap();
        let schema = yang_schemas
            .get(module.name())
            .ok_or(format!("No schema for module {}", module.name()))?;
        let deps = extract_yang_dependencies(schema)?;
        self.add_deps_to_graph(&deps, graph, a, node_indices, yang_schemas)?;
        for augmented_by in module.augmented_by() {
            self.check_module_exists(augmented_by.as_ref())?;
            let b = *node_indices
                .get(augmented_by.as_ref())
                .ok_or(format!("No module {augmented_by} found in graph"))?;
            if !graph.contains_edge(a, b) {
                graph.add_edge(a, b, ());
            }
        }
        for deviation in module.deviations() {
            self.check_module_exists(deviation.as_ref())?;
            let b = *node_indices
                .get(deviation.as_ref())
                .ok_or(format!("No module {deviation} found in graph"))?;
            if !graph.contains_edge(a, b) {
                graph.add_edge(a, b, ());
            }
        }
        Ok(())
    }

    /// Helper method to check if a module exists in the YANG Library.s
    fn check_module_exists(&self, module_name: &str) -> Result<(), String> {
        if self.find_module(module_name).is_none() && self.find_import_module(module_name).is_none()
        {
            Err(format!("No module {module_name} found in YANG Library"))
        } else {
            Ok(())
        }
    }

    /// Add all modules/submodules/import-only modules to the graph and
    /// construct a HashMap of module name to graph
    /// [petgraph::prelude::NodeIndex].
    fn construct_nodes<'a>(
        &'a self,
        graph: &mut petgraph::Graph<&'a str, ()>,
        node_indices: &mut HashMap<&'a str, petgraph::prelude::NodeIndex>,
    ) {
        // Add nodes for all modules
        for module_set in self.modules_set.values() {
            for module in module_set.modules().values() {
                if node_indices.contains_key(module.name()) {
                    // Skip modules that are already in the graph.
                    continue;
                }
                let idx = graph.add_node(module.name());
                node_indices.insert(module.name(), idx);

                for submodule in module.submodules() {
                    if node_indices.contains_key(submodule.name()) {
                        // Skip modules that are already in the graph.
                        continue;
                    }
                    let idx = graph.add_node(submodule.name());
                    node_indices.insert(submodule.name(), idx);
                }
            }
            for (_, import_module_versions) in module_set.import_only_modules() {
                for import_only in import_module_versions.values() {
                    if node_indices.contains_key(import_only.name()) {
                        // Skip modules that are already in the graph.
                        continue;
                    }
                    let idx = graph.add_node(import_only.name());
                    node_indices.insert(import_only.name(), idx);

                    for (_, submodule) in import_only.submodules() {
                        if node_indices.contains_key(submodule.name()) {
                            // Skip modules that are already in the graph.
                            continue;
                        }
                        let idx = graph.add_node(submodule.name());
                        node_indices.insert(submodule.name(), idx);
                    }
                }
            }
        }
    }

    /// Load schemas according the to location given in the YANG Library
    /// for each module and submodule.
    ///
    /// Currently only file:// locations are supported, other locations are ignored.
    /// If no valid location is found for a module/submodule, an error is
    /// returned.
    pub fn load_schemas(&self) -> Result<HashMap<Box<str>, Box<str>>, SchemaLoadingError> {
        let mut schemas = HashMap::new();
        for module_set in self.modules_set.values() {
            for module in module_set.modules().values() {
                let schema =
                    Self::load_yang_schema_from_location(module.name(), module.locations())?;
                schemas.insert(module.name.clone(), schema);
                for submodule in module.submodules() {
                    let schema = Self::load_yang_schema_from_location(
                        submodule.name(),
                        submodule.locations(),
                    )?;
                    schemas.insert(submodule.name.clone(), schema);
                }
            }
            for import_modules in module_set.import_only_modules.values() {
                for import_only_module in import_modules.values() {
                    let schema = Self::load_yang_schema_from_location(
                        import_only_module.name(),
                        import_only_module.locations(),
                    )?;
                    schemas.insert(import_only_module.name.clone(), schema);
                    for submodule in import_only_module.submodules().values() {
                        let schema = Self::load_yang_schema_from_location(
                            submodule.name(),
                            submodule.locations(),
                        )?;
                        schemas.insert(submodule.name.clone(), schema);
                    }
                }
            }
        }
        Ok(schemas)
    }

    /// Load schemas from a given search path using as first choice
    /// module name and revision to locate the YANG schema files.
    /// If no exact revision match is found, it tries to load the schema
    /// without revision assuming the default version is the correct one.
    pub fn load_schemas_from_search_path(
        &self,
        search_path: &Path,
    ) -> Result<HashMap<Box<str>, Box<str>>, SchemaLoadingError> {
        let mut schemas = HashMap::new();
        for module_set in self.modules_set.values() {
            for module in module_set.modules().values() {
                let schema = Self::load_yang_schema_from_search_path(
                    module.name(),
                    module.revision(),
                    search_path,
                )?;
                schemas.insert(module.name.clone(), schema);
                for submodule in module.submodules() {
                    let schema = Self::load_yang_schema_from_search_path(
                        submodule.name(),
                        submodule.revision(),
                        search_path,
                    )?;
                    schemas.insert(submodule.name.clone(), schema);
                }
            }
            for import_modules in module_set.import_only_modules.values() {
                for import_only_module in import_modules.values() {
                    let schema = Self::load_yang_schema_from_search_path(
                        import_only_module.name(),
                        import_only_module.revision(),
                        search_path,
                    )?;
                    schemas.insert(import_only_module.name.clone(), schema);
                    for submodule in import_only_module.submodules().values() {
                        let schema = Self::load_yang_schema_from_search_path(
                            submodule.name(),
                            submodule.revision(),
                            search_path,
                        )?;
                        schemas.insert(submodule.name.clone(), schema);
                    }
                }
            }
        }
        Ok(schemas)
    }

    /// Helper function to load a single YANG schema from the given locations.
    fn load_yang_schema_from_location(
        module_name: &str,
        locations: &[Box<str>],
    ) -> Result<Box<str>, SchemaLoadingError> {
        for location in locations {
            if let Some(location) = location.strip_prefix("file://") {
                let schema_path = Path::new(location);
                return Ok(std::fs::read_to_string(schema_path)?.into_boxed_str());
            }
        }
        // TODO: support other location types (http, https, etc)
        Err(SchemaLoadingError::NoValidLocationFound {
            module_name: module_name.to_string(),
        })
    }

    /// Helper function to load a single YANG schema from the given search path.
    fn load_yang_schema_from_search_path(
        module_name: &str,
        revision: Option<&str>,
        search_path: &Path,
    ) -> Result<Box<str>, SchemaLoadingError> {
        // First try to find the exact revision of the schema
        if let Some(revision) = revision {
            let schema_path = Path::new(search_path).join(format!("{module_name}@{revision}.yang"));
            tracing::debug!("loading yang schema {module_name} from {schema_path:?}");
            if schema_path.exists() {
                let schema = std::fs::read_to_string(schema_path)?.into_boxed_str();
                return Ok(schema);
            }
            tracing::debug!(
                "file doesn't exist to load yang schema {module_name} from {schema_path:?}"
            );
        }
        // If not found, try to find the schema without revision
        let schema_path = Path::new(search_path).join(format!("{module_name}.yang"));
        tracing::debug!("loading yang schema {module_name} from {schema_path:?}");
        if schema_path.exists() {
            let schema = std::fs::read_to_string(schema_path)?.into_boxed_str();
            return Ok(schema);
        }
        tracing::debug!(
            "file doesn't exist to load yang schema {module_name} from {schema_path:?}"
        );
        Err(SchemaLoadingError::SchemaNotFoundInSearchPath {
            module_name: module_name.to_string(),
            search_path: search_path.to_string_lossy().to_string().to_string(),
        })
    }

    /// Convert the YangLibrary into a ModuleSetBuilder
    /// that can be used to build a ModuleSet with
    /// the given yang_schemas and backward compatibility checker.
    ///
    /// If any module or submodule schema is not found in the
    /// yang_schemas, a DependencyError is returned.
    ///
    /// All modules and submodules are added to one ModuleSetBuilder
    /// named default_name, even if they are in different ModuleSets in the
    /// YangLibrary.
    pub fn into_module_set_builder<C: BackwardCompatibilityChecker>(
        self,
        yang_schemas: &HashMap<Box<str>, Box<str>>,
        default_name: Box<str>,
        checker: &C,
    ) -> Result<ModuleSetBuilder, DependencyError> {
        let mut module_set_builder = ModuleSetBuilder::new(default_name);
        for module_set in self.modules_set.into_values() {
            for module in module_set.modules.into_values() {
                let module_name = module.name.clone();
                let module_schema = yang_schemas
                    .get(module.name())
                    .ok_or(DependencyError::SchemaNotFound {
                        module_name: module_name.to_string(),
                    })?
                    .clone();
                let mut submodules = Vec::with_capacity(module.submodule.len());
                for submodule in &module.submodule {
                    let submodule_schema = yang_schemas
                        .get(submodule.name())
                        .ok_or(DependencyError::SchemaNotFound {
                            module_name: submodule.name().to_string(),
                        })?
                        .clone();
                    submodules.push((submodule.clone(), submodule_schema));
                }
                module_set_builder.add_module(module, module_schema, checker)?;
                for (submodule, submodule_schema) in submodules {
                    module_set_builder.add_submodule_for_module(
                        &module_name,
                        submodule,
                        submodule_schema,
                        checker,
                    )?;
                }
            }
            for import_modules in module_set.import_only_modules.into_values() {
                for import_only_module in import_modules.into_values() {
                    let module_name = import_only_module.name.clone();
                    let module_schema = yang_schemas
                        .get(import_only_module.name())
                        .ok_or(DependencyError::SchemaNotFound {
                            module_name: module_name.to_string(),
                        })?
                        .clone();
                    let mut submodules = Vec::with_capacity(import_only_module.submodules.len());
                    for (_, submodule) in &import_only_module.submodules {
                        let submodule_schema = yang_schemas
                            .get(submodule.name())
                            .ok_or(DependencyError::SchemaNotFound {
                                module_name: submodule.name().to_string(),
                            })?
                            .clone();
                        submodules.push((submodule.clone(), submodule_schema));
                    }
                    module_set_builder.add_import_only_module(
                        import_only_module,
                        module_schema,
                        checker,
                    )?;
                    for (submodule, submodule_schema) in submodules {
                        module_set_builder.add_submodule_for_import_only_module(
                            &module_name,
                            submodule,
                            submodule_schema,
                            checker,
                        )?;
                    }
                }
            }
        }
        Ok(module_set_builder)
    }
}

impl XmlDeserialize<YangLibrary> for YangLibrary {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        // Parse yang-library children in any order
        parser.skip_text()?;
        let yang_library_start = parser.open(Some(YANG_LIBRARY_NS), "yang-library")?;
        parser.skip_text()?;

        let mut modules_set = Vec::new();
        let mut schemas = Vec::new();
        let mut datastores = Vec::new();
        let mut content_id: Option<Box<str>> = None;

        while parser.peek() != &Event::End(yang_library_start.to_end()) {
            if parser.is_tag(Some(YANG_LIBRARY_NS), "module-set") {
                let module_set = ModuleSet::xml_deserialize(parser)?;
                modules_set.push(module_set);
                parser.skip_text()?;
            } else if parser.is_tag(Some(YANG_LIBRARY_NS), "schema") {
                let schema = Schema::xml_deserialize(parser)?;
                schemas.push(schema);
                parser.skip_text()?;
            } else if parser.is_tag(Some(YANG_LIBRARY_NS), "datastore") {
                let datastore = Datastore::xml_deserialize(parser)?;
                datastores.push(datastore);
                parser.skip_text()?;
            } else if parser.is_tag(Some(YANG_LIBRARY_NS), "content-id") {
                parser.open(Some(YANG_LIBRARY_NS), "content-id")?;
                content_id = Some(parser.tag_string()?.trim().into());
                parser.close()?;
                parser.skip_text()?;
            } else {
                return Err(ParsingError::WrongToken {
                    expecting: "<module-set>, <schema>, <datastore>, <content-id>".to_string(),
                    found: parser.peek().clone(),
                });
            }
        }

        let content_id =
            content_id.ok_or_else(|| ParsingError::MissingElement("content-id".to_string()))?;

        // close yang-library
        parser.close()?;
        Ok(Self::new(content_id, modules_set, schemas, datastores))
    }
}

impl XmlSerialize for YangLibrary {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_LIBRARY_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_LIBRARY_NS, "".to_string())]))?;
        }
        let lib_start = writer.create_ns_element(YANG_LIBRARY_NS, "yang-library")?;
        writer.write_event(Event::Start(lib_start.clone()))?;
        for module_set in self.modules_set.values() {
            module_set.xml_serialize(writer)?;
        }
        for schema in self.schemas.values() {
            schema.xml_serialize(writer)?;
        }
        for datastore in self.datastores.values() {
            datastore.xml_serialize(writer)?;
        }
        let start = writer.create_ns_element(YANG_LIBRARY_NS, "content-id")?;
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.content_id.as_ref())))?;
        writer.write_event(Event::End(start.to_end()))?;
        writer.write_event(Event::End(lib_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModuleSet {
    name: Box<str>,
    modules: IndexMap<Box<str>, Module>,
    #[serde(
        rename = "import-only-modules",
        skip_serializing_if = "IndexMap::is_empty"
    )]
    import_only_modules: IndexMap<Box<str>, IndexMap<Option<Box<str>>, ImportOnlyModule>>,
}

impl ModuleSet {
    pub fn new(
        name: Box<str>,
        modules: Vec<Module>,
        import_only_modules: Vec<ImportOnlyModule>,
    ) -> Self {
        let modules_map = IndexMap::from_iter(modules.into_iter().map(|m| (m.name.clone(), m)));
        let mut import_only_map = IndexMap::with_capacity(import_only_modules.len());
        for import_only in import_only_modules {
            let tmp = import_only_map
                .entry(import_only.name.clone())
                .or_insert(IndexMap::new());
            tmp.insert(import_only.revision.clone(), import_only);
        }
        Self {
            name,
            modules: modules_map,
            import_only_modules: import_only_map,
        }
    }

    pub const fn name(&self) -> &str {
        &self.name
    }

    pub const fn modules(&self) -> &IndexMap<Box<str>, Module> {
        &self.modules
    }

    pub const fn import_only_modules(
        &self,
    ) -> &IndexMap<Box<str>, IndexMap<Option<Box<str>>, ImportOnlyModule>> {
        &self.import_only_modules
    }

    pub fn into_module_set_builder(
        self,
        yang_schemas: HashMap<Box<str>, Box<str>>,
    ) -> Result<ModuleSetBuilder, String> {
        let mut submodules = HashMap::new();
        for module in self.modules.values() {
            if !yang_schemas.contains_key(module.name()) {
                return Err(format!("No schema for module {}", module.name()));
            }
            for submodule in module.submodules() {
                if !yang_schemas.contains_key(submodule.name()) {
                    return Err(format!("No schema for submodule {}", submodule.name()));
                }
                submodules.insert(submodule.name.clone(), submodule.clone());
            }
        }
        for import_only_modules in self.import_only_modules.values() {
            if import_only_modules.len() != 1 {
                return Err(format!(
                    "Import only module {} has multiple revisions",
                    import_only_modules
                        .values()
                        .next()
                        .map(|x| x.name())
                        .unwrap_or("ZEROMODULES")
                ));
            }
            for import_only_module in import_only_modules.values() {
                if !yang_schemas.contains_key(import_only_module.name()) {
                    return Err(format!(
                        "No schema for import only module {}",
                        import_only_module.name()
                    ));
                }
                for (_, submodule) in import_only_module.submodules() {
                    if !yang_schemas.contains_key(submodule.name()) {
                        return Err(format!("No schema for submodule {}", submodule.name()));
                    }
                    submodules.insert(submodule.name.clone(), submodule.clone());
                }
            }
        }
        let builder = ModuleSetBuilder {
            module_set: self,
            yang_schemas,
            submodules,
        };
        Ok(builder)
    }
}

impl XmlDeserialize<ModuleSet> for ModuleSet {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "module-set")?;
        let name = parse_yang_lib_name(parser)?;

        parser.skip_text()?;
        let mut modules = Vec::new();
        while parser.is_tag(Some(YANG_LIBRARY_NS), "module") {
            let module = Module::xml_deserialize(parser)?;
            modules.push(module);
            parser.skip_text()?;
        }

        let mut import_only_modules = Vec::new();
        while parser.is_tag(Some(YANG_LIBRARY_NS), "import-only-module") {
            let module = ImportOnlyModule::xml_deserialize(parser)?;
            import_only_modules.push(module);
            parser.skip_text()?;
        }

        // close module-set
        parser.close()?;
        Ok(ModuleSet::new(name, modules, import_only_modules))
    }
}

impl XmlSerialize for ModuleSet {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_LIBRARY_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_LIBRARY_NS, "".to_string())]))?;
        }
        let module_set_start = writer.create_ns_element(YANG_LIBRARY_NS, "module-set")?;
        writer.write_event(Event::Start(module_set_start.clone()))?;

        serialize_yang_lib_name(writer, &self.name)?;

        for module in self.modules.values() {
            module.xml_serialize(writer)?;
        }

        for import_only_modules in self.import_only_modules.values() {
            for module in import_only_modules.values() {
                module.xml_serialize(writer)?;
            }
        }
        writer.write_event(Event::End(module_set_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Module {
    name: Box<str>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<Box<str>>,

    namespace: Box<str>,

    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    feature: Box<[Box<str>]>,

    /// List of deviation modules (just module names, not full structures)
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    deviation: Box<[Box<str>]>,

    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    submodule: Box<[Submodule]>,

    #[serde(
        rename = "ietf-yang-library-augmentedby:augmented-by",
        skip_serializing_if = "<[_]>::is_empty"
    )]
    augmented_by: Box<[Box<str>]>,

    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    location: Box<[Box<str>]>,
}

impl Module {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        name: Box<str>,
        revision: Option<Box<str>>,
        namespace: Box<str>,
        feature: Box<[Box<str>]>,
        deviation: Box<[Box<str>]>,
        submodule: Box<[Submodule]>,
        augmented_by: Box<[Box<str>]>,
        location: Box<[Box<str>]>,
    ) -> Self {
        Self {
            name,
            revision,
            namespace,
            feature,
            deviation,
            submodule,
            augmented_by,
            location,
        }
    }

    pub const fn name(&self) -> &str {
        &self.name
    }

    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    pub const fn namespace(&self) -> &str {
        &self.namespace
    }

    pub const fn features(&self) -> &[Box<str>] {
        &self.feature
    }

    pub const fn deviations(&self) -> &[Box<str>] {
        &self.deviation
    }

    pub const fn submodules(&self) -> &[Submodule] {
        &self.submodule
    }

    pub const fn augmented_by(&self) -> &[Box<str>] {
        &self.augmented_by
    }

    pub const fn locations(&self) -> &[Box<str>] {
        &self.location
    }
}

impl XmlDeserialize<Module> for Module {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "module")?;
        let name = parse_yang_lib_name(parser)?;
        let revision = parse_yang_lib_revision(parser)?;
        let namespace = parse_yang_lib_namespace(parser)?;
        let location = parse_yang_lib_location(parser)?;

        let mut submodule = Vec::new();
        while parser.is_tag(Some(YANG_LIBRARY_NS), "submodule") {
            submodule.push(Submodule::xml_deserialize(parser)?);
            parser.skip_text()?;
        }

        let mut feature = Vec::new();
        while parser
            .maybe_open(Some(YANG_LIBRARY_NS), "feature")?
            .is_some()
        {
            feature.push(parser.tag_string()?.trim().into());
            // close feature
            parser.close()?;
            parser.skip_text()?;
        }

        let mut deviation = Vec::new();
        while parser
            .maybe_open(Some(YANG_LIBRARY_NS), "deviation")?
            .is_some()
        {
            deviation.push(parser.tag_string()?.trim().into());
            // close deviation
            parser.close()?;
            parser.skip_text()?;
        }

        let mut augmented_by = Vec::new();
        while parser
            .maybe_open(Some(YANG_LIBRARY_AUGMENTED_BY_NS), "augmented-by")?
            .is_some()
        {
            augmented_by.push(parser.tag_string()?.trim().into());
            // close augmented-by
            parser.close()?;
            parser.skip_text()?;
        }

        // close module
        parser.close()?;
        Ok(Module::new(
            name,
            revision,
            namespace,
            feature.into_boxed_slice(),
            deviation.into_boxed_slice(),
            submodule.into_boxed_slice(),
            augmented_by.into_boxed_slice(),
            location,
        ))
    }
}

impl XmlSerialize for Module {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_LIBRARY_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_LIBRARY_NS, "".to_string())]))?;
        }
        let module_start = writer.create_ns_element(YANG_LIBRARY_NS, "module")?;
        writer.write_event(Event::Start(module_start.clone()))?;

        serialize_yang_lib_name(writer, &self.name)?;
        serialize_yang_lib_revision(writer, self.revision.as_deref())?;
        serialize_yang_lib_namespace(writer, &self.namespace)?;
        serialize_yang_lib_location(writer, &self.location)?;

        for submodule in &self.submodule {
            submodule.xml_serialize(writer)?;
        }

        for feature in &self.feature {
            let start = writer.create_ns_element(YANG_LIBRARY_NS, "feature")?;
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(feature.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }

        for deviation in &self.deviation {
            let start = writer.create_ns_element(YANG_LIBRARY_NS, "deviation")?;
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(deviation.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }

        for augmented_by in &self.augmented_by {
            let mut ns_added = false;
            if writer
                .get_namespace_prefix(YANG_LIBRARY_AUGMENTED_BY_NS)
                .is_none()
            {
                ns_added = true;
                writer.push_namespace_binding(IndexMap::from([(
                    YANG_LIBRARY_AUGMENTED_BY_NS,
                    "".to_string(),
                )]))?;
            }
            let start = writer.create_ns_element(YANG_LIBRARY_AUGMENTED_BY_NS, "augmented-by")?;
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(augmented_by.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
            if ns_added {
                writer.pop_namespace_binding();
            }
        }

        writer.write_event(Event::End(module_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Submodule {
    name: Box<str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<Box<str>>,

    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    locations: Box<[Box<str>]>,
}

impl Submodule {
    pub const fn new(
        name: Box<str>,
        revision: Option<Box<str>>,
        locations: Box<[Box<str>]>,
    ) -> Self {
        Self {
            name,
            revision,
            locations,
        }
    }

    pub const fn name(&self) -> &str {
        &self.name
    }

    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    pub const fn locations(&self) -> &[Box<str>] {
        &self.locations
    }
}

impl XmlDeserialize<Submodule> for Submodule {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "submodule")?;
        let name = parse_yang_lib_name(parser)?;
        let revision = parse_yang_lib_revision(parser)?;
        let location = parse_yang_lib_location(parser)?;
        // close submodule
        parser.close()?;
        Ok(Submodule::new(name, revision, location))
    }
}

impl XmlSerialize for Submodule {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_LIBRARY_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_LIBRARY_NS, "".to_string())]))?;
        }
        let module_start = writer.create_ns_element(YANG_LIBRARY_NS, "submodule")?;
        writer.write_event(Event::Start(module_start.clone()))?;

        serialize_yang_lib_name(writer, &self.name)?;
        serialize_yang_lib_revision(writer, self.revision.as_deref())?;
        serialize_yang_lib_location(writer, &self.locations)?;

        writer.write_event(Event::End(module_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportOnlyModule {
    name: Box<str>,
    revision: Option<Box<str>>,
    namespace: Box<str>,
    locations: Box<[Box<str>]>,
    submodules: IndexMap<Box<str>, Submodule>,
}

impl ImportOnlyModule {
    pub const fn new(
        name: Box<str>,
        revision: Option<Box<str>>,
        namespace: Box<str>,
        locations: Box<[Box<str>]>,
        submodules: IndexMap<Box<str>, Submodule>,
    ) -> Self {
        Self {
            name,
            revision,
            namespace,
            locations,
            submodules,
        }
    }

    pub const fn name(&self) -> &str {
        &self.name
    }

    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    pub const fn namespace(&self) -> &str {
        &self.namespace
    }

    pub const fn locations(&self) -> &[Box<str>] {
        &self.locations
    }

    pub const fn submodules(&self) -> &IndexMap<Box<str>, Submodule> {
        &self.submodules
    }
}

impl XmlDeserialize<ImportOnlyModule> for ImportOnlyModule {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "import-only-module")?;
        let name = parse_yang_lib_name(parser)?;
        let revision = parse_yang_lib_revision(parser)?;
        let namespace = parse_yang_lib_namespace(parser)?;
        let location = parse_yang_lib_location(parser)?;

        let mut submodules = IndexMap::new();
        while parser.is_tag(Some(YANG_LIBRARY_NS), "submodule") {
            let submodule = Submodule::xml_deserialize(parser)?;
            submodules.insert(submodule.name().into(), submodule);
            parser.skip_text()?;
        }

        // close module
        parser.close()?;
        Ok(ImportOnlyModule::new(
            name, revision, namespace, location, submodules,
        ))
    }
}

impl XmlSerialize for ImportOnlyModule {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let module_start = writer.create_ns_element(YANG_LIBRARY_NS, "import-only-module")?;
        writer.write_event(Event::Start(module_start.clone()))?;

        serialize_yang_lib_name(writer, &self.name)?;
        serialize_yang_lib_revision(writer, self.revision.as_deref())?;
        serialize_yang_lib_namespace(writer, &self.namespace)?;
        serialize_yang_lib_location(writer, &self.locations)?;

        for submodule in self.submodules.values() {
            submodule.xml_serialize(writer)?;
        }
        writer.write_event(Event::End(module_start.to_end()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Schema {
    name: Box<str>,

    #[serde(rename = "module-set")]
    modules_set: Box<[Box<str>]>,
}

impl Schema {
    pub const fn new(name: Box<str>, modules_set: Box<[Box<str>]>) -> Self {
        Self { name, modules_set }
    }

    pub const fn name(&self) -> &str {
        &self.name
    }

    pub const fn modules_sets(&self) -> &[Box<str>] {
        &self.modules_set
    }
}

impl XmlDeserialize<Schema> for Schema {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "schema")?;
        let name = parse_yang_lib_name(parser)?;
        parser.skip_text()?;
        let mut modules_set = Vec::new();
        while parser.is_tag(Some(YANG_LIBRARY_NS), "module-set") {
            parser.open(Some(YANG_LIBRARY_NS), "module-set")?;
            let name = parser.tag_string()?.trim().into();
            modules_set.push(name);
            parser.close()?;
            parser.skip_text()?;
        }
        parser.close()?;
        Ok(Self::new(name, modules_set.into_boxed_slice()))
    }
}

impl XmlSerialize for Schema {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_LIBRARY_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_LIBRARY_NS, "".to_string())]))?;
        }
        let schema_start = writer.create_ns_element(YANG_LIBRARY_NS, "schema")?;
        writer.write_event(Event::Start(schema_start.clone()))?;
        serialize_yang_lib_name(writer, &self.name)?;
        for module_set in &self.modules_set {
            let start = writer.create_ns_element(YANG_LIBRARY_NS, "module-set")?;
            writer.write_event(Event::Start(start.clone()))?;
            writer.write_event(Event::Text(BytesText::new(module_set.as_ref())))?;
            writer.write_event(Event::End(start.to_end()))?;
        }
        writer.write_event(Event::End(schema_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

/// Datastore name as defined in RFC8342.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum DatastoreName {
    Running,
    Candidate,
    StartUp,
    Intended,
    Operational,
    Unknown { ns: Box<str>, name: Box<str> },
}

impl From<(&str, &str)> for DatastoreName {
    fn from(value: (&str, &str)) -> Self {
        let (ns, name) = value;
        if ns != YANG_DATASTORES_NS_STR {
            return DatastoreName::Unknown {
                ns: ns.into(),
                name: name.into(),
            };
        }
        match name {
            "running" => DatastoreName::Running,
            "candidate" => DatastoreName::Candidate,
            "startup" => DatastoreName::StartUp,
            "intended" => DatastoreName::Intended,
            "operational" => DatastoreName::Operational,
            _ => DatastoreName::Unknown {
                ns: ns.into(),
                name: name.into(),
            },
        }
    }
}

impl From<DatastoreName> for (Box<str>, Box<str>) {
    fn from(value: DatastoreName) -> Self {
        let (ns, name) = match value {
            DatastoreName::Running => (YANG_DATASTORES_NS_STR.into(), "running".into()),
            DatastoreName::Candidate => (YANG_DATASTORES_NS_STR.into(), "candidate".into()),
            DatastoreName::StartUp => (YANG_DATASTORES_NS_STR.into(), "startup".into()),
            DatastoreName::Intended => (YANG_DATASTORES_NS_STR.into(), "intended".into()),
            DatastoreName::Operational => (YANG_DATASTORES_NS_STR.into(), "operational".into()),
            DatastoreName::Unknown { ns, name } => (ns, name),
        };
        (ns, name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Datastore {
    name: DatastoreName,
    schema: Box<str>,
}

impl Datastore {
    pub const fn new(name: DatastoreName, schema: Box<str>) -> Self {
        Self { name, schema }
    }

    pub const fn name(&self) -> &DatastoreName {
        &self.name
    }

    pub const fn schema(&self) -> &str {
        &self.schema
    }
}

impl XmlDeserialize<Datastore> for Datastore {
    fn xml_deserialize(parser: &mut XmlParser<impl io::BufRead>) -> Result<Self, ParsingError> {
        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "datastore")?;
        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "name")?;
        let name: Box<str> = parser.tag_string()?.trim().into();
        // Resolve datastore name
        let (ns, local) = parser.ns_reader().resolve(QName(name.as_bytes()), false);
        let ds_ns = match ns {
            ResolveResult::Bound(ns) => std::str::from_utf8(ns.into_inner())?,
            _ => return Err(ParsingError::InvalidValue(name.to_string())),
        };
        let ds_name = std::str::from_utf8(local.into_inner())?;
        let ds = DatastoreName::from((ds_ns, ds_name));
        // close name
        parser.close()?;

        parser.skip_text()?;
        parser.open(Some(YANG_LIBRARY_NS), "schema")?;
        let schema = parser.tag_string()?.trim().into();
        parser.close()?;

        // close datastore
        parser.close()?;
        Ok(Self::new(ds, schema))
    }
}

impl XmlSerialize for Datastore {
    fn xml_serialize<T: io::Write>(
        &self,
        writer: &mut XmlWriter<T>,
    ) -> Result<(), quick_xml::Error> {
        let mut ns_added = false;
        if writer.get_namespace_prefix(YANG_LIBRARY_NS).is_none() {
            ns_added = true;
            writer.push_namespace_binding(IndexMap::from([(YANG_LIBRARY_NS, "".to_string())]))?;
        }
        let schema_start = writer.create_ns_element(YANG_LIBRARY_NS, "datastore")?;
        writer.write_event(Event::Start(schema_start.clone()))?;

        let (ns, name) = self.name.clone().into();
        let mut name_start = writer.create_ns_element(YANG_LIBRARY_NS, "name")?;
        name_start.push_attribute(("xmlns:ds", ns.as_ref()));
        writer.write_event(Event::Start(name_start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(&format!("ds:{name}"))))?;
        writer.write_event(Event::End(name_start.to_end()))?;

        let start = writer.create_ns_element(YANG_LIBRARY_NS, "schema")?;
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(self.schema.as_ref())))?;
        writer.write_event(Event::End(start.to_end()))?;

        writer.write_event(Event::End(schema_start.to_end()))?;
        if ns_added {
            writer.pop_namespace_binding();
        }
        Ok(())
    }
}

#[inline]
fn parse_yang_lib_name(parser: &mut XmlParser<impl io::BufRead>) -> Result<Box<str>, ParsingError> {
    parser.skip_text()?;
    parser.open(Some(YANG_LIBRARY_NS), "name")?;
    let name = parser.tag_string()?.trim().into();
    // close name
    parser.close()?;
    Ok(name)
}

#[inline]
fn serialize_yang_lib_name<T: io::Write>(
    writer: &mut XmlWriter<T>,
    value: &str,
) -> Result<(), quick_xml::Error> {
    let name_start = writer.create_ns_element(YANG_LIBRARY_NS, "name")?;
    writer.write_event(Event::Start(name_start.clone()))?;
    writer.write_event(Event::Text(BytesText::new(value)))?;
    writer.write_event(Event::End(name_start.to_end()))?;
    Ok(())
}

#[inline]
fn parse_yang_lib_revision(
    parser: &mut XmlParser<impl io::BufRead>,
) -> Result<Option<Box<str>>, ParsingError> {
    parser.skip_text()?;
    if parser
        .maybe_open(Some(YANG_LIBRARY_NS), "revision")?
        .is_some()
    {
        let rev = parser.tag_string()?.trim().into();
        parser.close()?;
        Ok(Some(rev))
    } else {
        Ok(None)
    }
}

#[inline]
fn serialize_yang_lib_revision<T: io::Write>(
    writer: &mut XmlWriter<T>,
    value: Option<&str>,
) -> Result<(), quick_xml::Error> {
    if let Some(revision) = value {
        let start = writer.create_ns_element(YANG_LIBRARY_NS, "revision")?;
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(revision)))?;
        writer.write_event(Event::End(start.to_end()))?;
    }
    Ok(())
}

#[inline]
fn parse_yang_lib_namespace(
    parser: &mut XmlParser<impl io::BufRead>,
) -> Result<Box<str>, ParsingError> {
    parser.skip_text()?;
    parser.open(Some(YANG_LIBRARY_NS), "namespace")?;
    let name = parser.tag_string()?.trim().into();
    parser.close()?;
    Ok(name)
}

#[inline]
fn serialize_yang_lib_namespace<T: io::Write>(
    writer: &mut XmlWriter<T>,
    value: &str,
) -> Result<(), quick_xml::Error> {
    let name_start = writer.create_ns_element(YANG_LIBRARY_NS, "namespace")?;
    writer.write_event(Event::Start(name_start.clone()))?;
    writer.write_event(Event::Text(BytesText::new(value)))?;
    writer.write_event(Event::End(name_start.to_end()))?;
    Ok(())
}

#[inline]
fn parse_yang_lib_location(
    parser: &mut XmlParser<impl io::BufRead>,
) -> Result<Box<[Box<str>]>, ParsingError> {
    let mut location = Vec::new();
    while parser
        .maybe_open(Some(YANG_LIBRARY_NS), "location")?
        .is_some()
    {
        location.push(parser.tag_string()?.trim().into());
        // close location
        parser.close()?;
        parser.skip_text()?;
    }
    Ok(location.into_boxed_slice())
}

#[inline]
fn serialize_yang_lib_location<T: io::Write>(
    writer: &mut XmlWriter<T>,
    value: &[Box<str>],
) -> Result<(), quick_xml::Error> {
    for location in value {
        let start = writer.create_ns_element(YANG_LIBRARY_NS, "location")?;
        writer.write_event(Event::Start(start.clone()))?;
        writer.write_event(Event::Text(BytesText::new(location.as_ref())))?;
        writer.write_event(Event::End(start.to_end()))?;
    }
    Ok(())
}

/// Helper struct for building a `ModuleSet` with backward compatibility checks.
/// Only the latest version of each module is allowed in the set.
/// User can update the version of a module by adding a new module with the same
/// name, and it will replace the existing module if the compatability check
/// passes.
///
/// The module Builder records the latest version of each schema in a HashMap
/// with as module name and value as the raw schema string.
pub struct ModuleSetBuilder {
    module_set: ModuleSet,
    // The yang schema string indexed by name
    yang_schemas: HashMap<Box<str>, Box<str>>,
    // Keep track of submodule schemas separately for easier backward compatibility checks
    submodules: HashMap<Box<str>, Submodule>,
}

impl ModuleSetBuilder {
    pub fn new(name: Box<str>) -> Self {
        Self {
            module_set: ModuleSet::new(name, Vec::new(), Vec::new()),
            yang_schemas: HashMap::new(),
            submodules: HashMap::new(),
        }
    }

    /// Adds a module to the builder and checks for backward compatibility.
    pub fn add_module<C: BackwardCompatibilityChecker>(
        &mut self,
        module: Module,
        schema: Box<str>,
        checker: &C,
    ) -> Result<AddResult, DependencyError> {
        let name = module.name.clone();
        let existing_module = if let Some(existing_module) = self.module_set.modules().get(&name) {
            existing_module
        } else {
            // New module - just add it
            self.yang_schemas.insert(name.clone(), schema);
            self.module_set.modules.insert(name, module);
            return Ok(AddResult::Added);
        };

        let compatability_result = checker.check_backward_compatible(
            existing_module.name(),
            existing_module.revision(),
            module.revision(),
            self.yang_schemas
                .get(existing_module.name())
                .unwrap_or(&schema),
            &schema,
        );
        match compatability_result {
            CompatabilityResult::Same => Ok(AddResult::AlreadyExists),
            CompatabilityResult::Compatible => {
                // Backward compatible - update to the new version
                let existing_version = existing_module.revision().map(|s| s.to_string());
                let new_version = module.revision().map(|s| s.to_string());
                self.yang_schemas.insert(name.clone(), schema);
                self.module_set.modules.insert(name, module);
                Ok(AddResult::Updated {
                    old_version: existing_version,
                    new_version,
                })
            }
            CompatabilityResult::Incompatible => {
                // Not backward compatible - conflict
                Err(DependencyError::VersionConflict {
                    module_name: name.to_string(),
                    existing_version: existing_module.revision().map(|s| s.to_string()),
                    new_version: module.revision().map(|s| s.to_string()),
                })
            }
        }
    }

    /// Adds a submodule to the builder and checks for backward
    /// compatibility. A submodule is always attached to a parent module, and it
    /// should be declared a priori in the submodule list of the parent module.
    pub fn add_submodule_for_module<C>(
        &mut self,
        module_name: &str,
        submodule: Submodule,
        schema: Box<str>,
        checker: &C,
    ) -> Result<AddResult, DependencyError>
    where
        C: BackwardCompatibilityChecker,
    {
        // Check the module which is the submodule is attached to is already defined in
        // the module set.
        let module = if let Some(module) = self.module_set.modules.get(module_name) {
            module
        } else {
            return Err(DependencyError::ModuleNotFound {
                module_name: module_name.to_string(),
            });
        };
        let submodule_name = submodule.name.clone();
        // Check that the submodule is already defined in the parent module
        if !module
            .submodule
            .iter()
            .any(|submodule| submodule.name == submodule_name)
        {
            return Err(DependencyError::SubmoduleNotFound {
                module_name: module_name.to_string(),
                submodule_name: submodule_name.to_string(),
            });
        }
        let existing_submodule =
            if let Some(existing) = self.submodules.get_mut(submodule_name.as_ref()) {
                existing
            } else {
                self.yang_schemas.insert(submodule_name.clone(), schema);
                self.submodules.insert(submodule_name, submodule);
                return Ok(AddResult::Added);
            };

        let compatability_result = checker.check_backward_compatible(
            &submodule_name,
            existing_submodule.revision(),
            submodule.revision(),
            self.yang_schemas.get(&submodule_name).unwrap_or(&schema),
            &schema,
        );
        match compatability_result {
            CompatabilityResult::Same => Ok(AddResult::AlreadyExists),
            CompatabilityResult::Compatible => {
                // Backward compatible - update to the new version
                let old_version = existing_submodule.revision().map(|s| s.to_string());
                let new_version = submodule.revision().map(|s| s.to_string());
                self.yang_schemas.insert(submodule_name.clone(), schema);
                self.submodules.insert(submodule_name, submodule);
                Ok(AddResult::Updated {
                    old_version,
                    new_version,
                })
            }
            CompatabilityResult::Incompatible => Err(DependencyError::VersionConflict {
                module_name: submodule_name.to_string(),
                existing_version: existing_submodule.revision().map(|s| s.to_string()),
                new_version: submodule.revision().map(|s| s.to_string()),
            }),
        }
    }

    /// Adds an import-only module to the builder and checks for backward
    /// compatibility. Only one version of import only modules is allowed by
    /// this builder.
    pub fn add_import_only_module<C>(
        &mut self,
        import_only_module: ImportOnlyModule,
        schema: Box<str>,
        checker: &C,
    ) -> Result<AddResult, DependencyError>
    where
        C: BackwardCompatibilityChecker,
    {
        let name = import_only_module.name.clone();
        let (_, existing) = if let Some(existing) = self.module_set.import_only_modules().get(&name)
        {
            let tmp = existing
                .iter()
                .find(|m| m.1.revision() == import_only_module.revision())
                .ok_or(existing.first());
            match tmp {
                Ok(tmp) => tmp,
                Err(_) => {
                    return Err(DependencyError::ModuleNotFound {
                        module_name: name.to_string(),
                    })
                }
            }
        } else {
            self.yang_schemas.insert(name.clone(), schema);
            self.module_set.import_only_modules.insert(
                name,
                IndexMap::from([(
                    import_only_module.revision.clone(),
                    import_only_module.clone(),
                )]),
            );
            return Ok(AddResult::Added);
        };

        let compatability_result = checker.check_backward_compatible(
            &name,
            existing.revision(),
            import_only_module.revision(),
            self.yang_schemas.get(&name).unwrap_or(&schema),
            &schema,
        );
        match compatability_result {
            CompatabilityResult::Same => Ok(AddResult::AlreadyExists),
            CompatabilityResult::Compatible => {
                // Backward compatible - update to the new version
                let old_version = existing.revision().map(|s| s.to_string());
                let new_version = import_only_module.revision().map(|s| s.to_string());
                self.yang_schemas.insert(name.clone(), schema);
                self.module_set.import_only_modules.insert(
                    name,
                    IndexMap::from([(
                        import_only_module.revision.clone(),
                        import_only_module.clone(),
                    )]),
                );
                Ok(AddResult::Updated {
                    old_version,
                    new_version,
                })
            }
            CompatabilityResult::Incompatible => {
                // Not backward compatible - conflict
                Err(DependencyError::VersionConflict {
                    module_name: name.to_string(),
                    existing_version: existing.revision().map(|s| s.to_string()),
                    new_version: import_only_module.revision().map(|s| s.to_string()),
                })
            }
        }
    }

    /// Add a submodule that is part of an import-only module.
    ///
    /// Submodule is only accepted if the import-only module is already added
    /// and declares the submodule in its submodules list.
    pub fn add_submodule_for_import_only_module<C>(
        &mut self,
        import_only_module_name: &str,
        submodule: Submodule,
        schema: Box<str>,
        checker: &C,
    ) -> Result<AddResult, DependencyError>
    where
        C: BackwardCompatibilityChecker,
    {
        if !self
            .module_set
            .import_only_modules
            .contains_key(import_only_module_name)
        {
            return Err(DependencyError::ModuleNotFound {
                module_name: import_only_module_name.to_string(),
            });
        };
        let submodule_name = submodule.name.clone();
        let existing = if let Some(existing) = self.submodules.get_mut(&submodule_name) {
            existing
        } else {
            self.yang_schemas.insert(submodule_name.clone(), schema);
            self.submodules.insert(submodule_name, submodule);
            return Ok(AddResult::Added);
        };

        let compatability_result = checker.check_backward_compatible(
            &submodule_name,
            existing.revision(),
            submodule.revision(),
            self.yang_schemas.get(&submodule_name).unwrap_or(&schema),
            &schema,
        );
        match compatability_result {
            CompatabilityResult::Same => Ok(AddResult::AlreadyExists),
            CompatabilityResult::Compatible => {
                // Backward compatible - update to the new version
                let old_version = existing.revision().map(|s| s.to_string());
                let new_version = submodule.revision().map(|s| s.to_string());
                self.yang_schemas.insert(submodule_name.clone(), schema);
                self.submodules.insert(submodule_name, submodule);
                Ok(AddResult::Updated {
                    old_version,
                    new_version,
                })
            }
            CompatabilityResult::Incompatible => Err(DependencyError::VersionConflict {
                module_name: submodule_name.to_string(),
                existing_version: existing.revision().map(|s| s.to_string()),
                new_version: submodule.revision().map(|s| s.to_string()),
            }),
        }
    }

    pub fn build(self) -> (ModuleSet, HashMap<Box<str>, Box<str>>) {
        (self.module_set, self.yang_schemas)
    }

    /// Produce a YANG library that contains only one module set
    pub fn build_yang_lib(self) -> (YangLibrary, HashMap<Box<str>, Box<str>>) {
        let default_name: Box<str> = "ALL".into();
        let mut content_id = sha2::Sha256::new();
        for module in self.module_set.modules().values() {
            for feature in module.features() {
                content_id.update(feature.as_ref());
            }
            for submodule in module.submodules() {
                content_id.update(self.yang_schemas.get(submodule.name()).unwrap().as_ref());
            }
            content_id.update(self.yang_schemas.get(module.name()).unwrap().as_ref());
        }
        for import_only_versions in self.module_set.import_only_modules().values() {
            for module in import_only_versions.values() {
                for (_, submodule) in module.submodules() {
                    content_id.update(self.yang_schemas.get(submodule.name()).unwrap().as_ref());
                }
                content_id.update(self.yang_schemas.get(module.name()).unwrap().as_ref());
            }
        }
        let content_id = content_id.finalize();
        let content_id = format!("{content_id:x}");
        let yang_lib_schema = Schema::new(
            default_name.clone(),
            Box::new([self.module_set.name().into()]),
        );
        let yang_lib = YangLibrary::new(
            content_id.into(),
            vec![self.module_set],
            vec![yang_lib_schema],
            vec![Datastore::new(
                DatastoreName::Operational,
                default_name.clone(),
            )],
        );
        (yang_lib, self.yang_schemas)
    }
}

pub enum CompatabilityResult {
    Same,
    Compatible,
    Incompatible,
}

/// Trait for checking backward compatibility between module versions
/// Implement this trait to provide your own compatibility logic
pub trait BackwardCompatibilityChecker {
    /// Check if new_version is backward compatible with old_version
    /// Returns [CompatabilityResult] indicating the result of the check
    fn check_backward_compatible(
        &self,
        module_name: &str,
        old_version: Option<&str>,
        new_version: Option<&str>,
        old_schema: &str,
        new_schema: &str,
    ) -> CompatabilityResult;
}

/// Permissive checker that always allows version updates
pub struct PermissiveVersionChecker;

impl BackwardCompatibilityChecker for PermissiveVersionChecker {
    fn check_backward_compatible(
        &self,
        _module_name: &str,
        old_version: Option<&str>,
        new_version: Option<&str>,
        old_schema: &str,
        new_schema: &str,
    ) -> CompatabilityResult {
        if old_version.is_none() == new_version.is_none() && old_schema == new_schema {
            CompatabilityResult::Same
        } else {
            CompatabilityResult::Compatible
        }
    }
}

/// Result of attempting to add a module
#[derive(Debug)]
pub enum AddResult {
    Added,
    Updated {
        old_version: Option<String>,
        new_version: Option<String>,
    },
    AlreadyExists,
}

#[derive(Debug, strum_macros::Display)]
pub enum DependencyError {
    #[strum(
        to_string = "Version conflict for module '{module_name}': existing version {existing_version:?}, attempted to add incompatible version {new_version:?}"
    )]
    VersionConflict {
        module_name: String,
        existing_version: Option<String>,
        new_version: Option<String>,
    },

    #[strum(to_string = "Module '{module_name}' not found")]
    ModuleNotFound { module_name: String },

    #[strum(to_string = "Submodule '{submodule_name}' not found in module '{module_name}'")]
    SubmoduleNotFound {
        module_name: String,
        submodule_name: String,
    },

    #[strum(to_string = "YANG schema for module '{module_name}' is not found")]
    SchemaNotFound { module_name: String },
}

impl std::error::Error for DependencyError {}

#[derive(Debug, strum_macros::Display)]
pub enum SchemaConstructionError {
    #[strum(to_string = "Failed to convert schema to graph {0}")]
    Graph(String),

    #[strum(to_string = "Module '{module_name}' not found")]
    ModuleNotFound {
        module_name: String,
    },

    #[strum(to_string = "Dependency cycle detected at node {0}")]
    CycleDetected(String),

    RegistrationError(schema_registry_client::rest::apis::Error),
}

impl std::error::Error for SchemaConstructionError {}

#[derive(Debug, strum_macros::Display)]
pub enum SchemaLoadingError {
    #[strum(to_string = "no valid location found to the schema of the module `{module_name}`")]
    NoValidLocationFound {
        module_name: String,
    },

    #[strum(
        to_string = "failed find the schema of the module `{module_name}` from search path {search_path}"
    )]
    SchemaNotFoundInSearchPath {
        module_name: String,
        search_path: String,
    },

    IoError(io::Error),
}

impl std::error::Error for SchemaLoadingError {}

impl From<io::Error> for SchemaLoadingError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_xml_value;

    #[test]
    fn test_submodule() {
        let full_str = r#"<submodule xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
             <name>submodule1</name>
             <revision>2023-01-11</revision>
             <location>https://example.com/submodule1</location>
             <location>https://example.com/copy/submodule1</location>
            </submodule>"#;
        let min_str = r#"<submodule xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
             <name>submodule1</name>
            </submodule>"#;
        let full = Submodule::new(
            "submodule1".into(),
            Some("2023-01-11".into()),
            Box::new([
                "https://example.com/submodule1".into(),
                "https://example.com/copy/submodule1".into(),
            ]),
        );
        let min = Submodule::new("submodule1".into(), None, Box::new([]));

        test_xml_value(full_str, full).expect("failed to test full submodule");
        test_xml_value(min_str, min).expect("failed to test minimal submodule");
    }

    #[test]
    fn test_module() {
        let full_str = r#"<module xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
         <name>ietf-interfaces</name>
         <revision>2018-02-20</revision>
         <namespace>
           urn:ietf:params:xml:ns:yang:ietf-interfaces
         </namespace>
         <location>https://example1.com</location>
         <location>https://example2.com</location>
        <submodule>
            <name>ietf-interfaces-ext</name>
            <revision>2018-02-20</revision>
            <location>https://example.com/ietf-interfaces-ext</location>
        </submodule>
        <feature>if-mib</feature>
       <feature>ethernet</feature>
       <deviation>deviation1</deviation>
       <deviation>deviation2</deviation>
         <augmented-by xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library-augmentedby">module1</augmented-by>
         <augmented-by xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library-augmentedby">module2</augmented-by>
       </module>"#;

        let min_str = r#"<module xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
         <name>ietf-interfaces</name>
         <namespace>urn:ietf:params:xml:ns:yang:ietf-interfaces</namespace>
       </module>"#;

        let full = Module::new(
            "ietf-interfaces".into(),
            Some("2018-02-20".into()),
            "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            Box::new(["if-mib".into(), "ethernet".into()]),
            Box::new(["deviation1".into(), "deviation2".into()]),
            Box::new([Submodule::new(
                "ietf-interfaces-ext".into(),
                Some("2018-02-20".into()),
                Box::new(["https://example.com/ietf-interfaces-ext".into()]),
            )]),
            Box::new(["module1".into(), "module2".into()]),
            Box::new(["https://example1.com".into(), "https://example2.com".into()]),
        );

        let min = Module::new(
            "ietf-interfaces".into(),
            None,
            "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
        );

        test_xml_value(full_str, full).expect("failed to test full module");
        test_xml_value(min_str, min).expect("failed to test minimal module");
    }

    #[test]
    fn test_module_set() {
        let full_str = r#"<module-set xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
               <name>config-modules</name>
               <module>
                 <name>ietf-interfaces</name>
                 <revision>2018-02-20</revision>
                 <namespace>
                   urn:ietf:params:xml:ns:yang:ietf-interfaces
                 </namespace>
               </module>
               <module>
                 <name>ietf-ip</name>
                 <revision>2018-02-22</revision>
                 <namespace>
                   urn:ietf:params:xml:ns:yang:ietf-ip
                 </namespace>
               </module>
               <import-only-module>
                 <name>ietf-yang-types</name>
                 <revision>2013-07-15</revision>
                 <namespace>
                   urn:ietf:params:xml:ns:yang:ietf-yang-types
                 </namespace>
               </import-only-module>
               <import-only-module>
                 <name>ietf-inet-types</name>
                 <namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>
               </import-only-module>
             </module-set>"#;

        let min_str = r#"<module-set xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
         <name>set1</name>
       </module-set>"#;

        let full = ModuleSet::new(
            "config-modules".into(),
            vec![
                Module::new(
                    "ietf-interfaces".into(),
                    Some("2018-02-20".into()),
                    "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                ),
                Module::new(
                    "ietf-ip".into(),
                    Some("2018-02-22".into()),
                    "urn:ietf:params:xml:ns:yang:ietf-ip".into(),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                ),
            ],
            vec![
                ImportOnlyModule::new(
                    "ietf-yang-types".into(),
                    Some("2013-07-15".into()),
                    "urn:ietf:params:xml:ns:yang:ietf-yang-types".into(),
                    Box::new([]),
                    IndexMap::new(),
                ),
                ImportOnlyModule::new(
                    "ietf-inet-types".into(),
                    None,
                    "urn:ietf:params:xml:ns:yang:ietf-inet-types".into(),
                    Box::new([]),
                    IndexMap::new(),
                ),
            ],
        );
        let min = ModuleSet::new("set1".into(), vec![], vec![]);

        test_xml_value(full_str, full).expect("failed to test full module-set");
        test_xml_value(min_str, min).expect("failed to test minimal module-set");
    }

    #[test]
    fn test_schema() {
        let full_str = r#"<schema xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
           <name>All</name>
           <module-set>mod-set-1</module-set>
           <module-set>mod-set-2</module-set>
          </schema>"#;
        let min_str = r#"<schema xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
           <name>min</name>
          </schema>"#;
        let full = Schema::new(
            "All".into(),
            Box::new(["mod-set-1".into(), "mod-set-2".into()]),
        );
        let min = Schema::new("min".into(), Box::new([]));

        test_xml_value(full_str, full).expect("failed to test full schema");
        test_xml_value(min_str, min).expect("failed to test minimal schema");
    }

    #[test]
    fn test_datastore() {
        let ds1_str = r#"<datastore xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
            <name xmlns:idx="urn:ietf:params:xml:ns:yang:ietf-datastores">idx:running</name>
            <schema>All</schema>
           </datastore>"#;

        let ds2_str = r#"<datastore xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
            <name xmlns:ds="urn:ietf:params:xml:ns:example">ds:other</name>
            <schema>All</schema>
           </datastore>"#;

        let ds1 = Datastore::new(DatastoreName::Running, "All".into());
        let ds2 = Datastore::new(
            DatastoreName::Unknown {
                ns: "urn:ietf:params:xml:ns:example".into(),
                name: "other".into(),
            },
            "All".into(),
        );

        test_xml_value(ds1_str, ds1).expect("failed to test ds1");
        test_xml_value(ds2_str, ds2).expect("failed to test ds1");
    }

    #[test]
    fn test_rfc8525_appendix_c_advanced_server() {
        // RFC 8525 Appendix C - Example YANG Library Instance for an Advanced Server
        let xml = r#"<yang-library
       xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library"
       xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">
     <module-set>
       <name>state-only-modules</name>
       <module>
         <name>ietf-hardware</name>
         <revision>2018-03-13</revision>
         <namespace>
           urn:ietf:params:xml:ns:yang:ietf-hardware
         </namespace>
         <deviation>example-vendor-hardware-deviations</deviation>
       </module>
       <module>
         <name>ietf-routing</name>
         <revision>2018-03-13</revision>
         <namespace>
           urn:ietf:params:xml:ns:yang:ietf-routing
         </namespace>
         <feature>multiple-ribs</feature>
         <feature>router-id</feature>
       </module>
     </module-set>
     <schema>
       <name>state-schema</name>
       <module-set>state-only-modules</module-set>
     </schema>
     <datastore>
       <name>ds:operational</name>
       <schema>state-schema</schema>
     </datastore>
     <content-id>14782ab9bd56b92aacc156a2958fbe12312fb285</content-id>
   </yang-library>"#;

        let expected = YangLibrary::new(
            "14782ab9bd56b92aacc156a2958fbe12312fb285".into(),
            vec![ModuleSet::new(
                "state-only-modules".into(),
                vec![
                    Module::new(
                        "ietf-hardware".into(),
                        Some("2018-03-13".into()),
                        "urn:ietf:params:xml:ns:yang:ietf-hardware".into(),
                        Box::new([]),
                        Box::new(["example-vendor-hardware-deviations".into()]),
                        Box::new([]),
                        Box::new([]),
                        Box::new([]),
                    ),
                    Module::new(
                        "ietf-routing".into(),
                        Some("2018-03-13".into()),
                        "urn:ietf:params:xml:ns:yang:ietf-routing".into(),
                        Box::new(["multiple-ribs".into(), "router-id".into()]),
                        Box::new([]),
                        Box::new([]),
                        Box::new([]),
                        Box::new([]),
                    ),
                ],
                vec![],
            )],
            vec![Schema::new(
                "state-schema".into(),
                Box::new(["state-only-modules".into()]),
            )],
            vec![Datastore::new(
                DatastoreName::Operational,
                "state-schema".into(),
            )],
        );
        test_xml_value(xml, expected).expect("failed");
    }

    #[test]
    fn test_find_module_submodule() {
        let ietf_hardware_module = Module::new(
            "ietf-hardware".into(),
            Some("2018-03-13".into()),
            "urn:ietf:params:xml:ns:yang:ietf-hardware".into(),
            Box::new([]),
            Box::new(["example-vendor-hardware-deviations".into()]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
        );
        let ietf_routing_module = Module::new(
            "ietf-routing".into(),
            Some("2018-03-13".into()),
            "urn:ietf:params:xml:ns:yang:ietf-routing".into(),
            Box::new(["multiple-ribs".into(), "router-id".into()]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
        );
        let ietf_interfaces_module = Module::new(
            "ietf-interfaces".into(),
            Some("2018-02-20".into()),
            "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            Box::new(["if-mib".into(), "ethernet".into()]),
            Box::new(["deviation1".into(), "deviation2".into()]),
            Box::new([Submodule::new(
                "ietf-interfaces-ext".into(),
                Some("2018-02-20".into()),
                Box::new(["https://example.com/ietf-interfaces-ext".into()]),
            )]),
            Box::new(["module1".into(), "module2".into()]),
            Box::new(["https://example1.com".into(), "https://example2.com".into()]),
        );
        let example_submodule = Submodule::new(
            "example-submodule".into(),
            Some("2018-02-20".into()),
            Box::new(["https://example.com/submodule1".into()]),
        );
        let example_module = Module::new(
            "example".into(),
            Some("2018-02-20".into()),
            "urn:ietf:params:xml:ns:example".into(),
            Box::new([]),
            Box::new([]),
            Box::new([example_submodule.clone()]),
            Box::new(["module1".into(), "module2".into()]),
            Box::new(["https://example1.com".into(), "https://example2.com".into()]),
        );
        let ietf_yang_types_module = ImportOnlyModule::new(
            "ietf-yang-types".into(),
            Some("2013-07-15".into()),
            "urn:ietf:params:xml:ns:yang:ietf-yang-types".into(),
            Box::new([]),
            IndexMap::new(),
        );
        let ietf_inet_types_module = ImportOnlyModule::new(
            "ietf-inet-types".into(),
            None,
            "urn:ietf:params:xml:ns:yang:ietf-inet-types".into(),
            Box::new([]),
            IndexMap::new(),
        );
        let input = YangLibrary::new(
            "14782ab9bd56b92aacc156a2958fbe12312fb285".into(),
            vec![
                ModuleSet::new(
                    "Set1".into(),
                    vec![ietf_hardware_module.clone()],
                    vec![ietf_yang_types_module.clone()],
                ),
                ModuleSet::new(
                    "Set2".into(),
                    vec![
                        ietf_interfaces_module.clone(),
                        ietf_routing_module.clone(),
                        example_module.clone(),
                    ],
                    vec![
                        ietf_yang_types_module.clone(),
                        ietf_inet_types_module.clone(),
                    ],
                ),
            ],
            vec![Schema::new(
                "ALLSchema".into(),
                Box::new(["Set1".into(), "Set2".into()]),
            )],
            vec![Datastore::new(
                DatastoreName::Operational,
                "ALLSchema".into(),
            )],
        );

        let found_ietf_routing = input.find_module("ietf-routing");
        let found_ietf_interfaces = input.find_module("ietf-interfaces");
        let found_example = input.find_module("example");
        let not_found_module = input.find_module("ietf-yang-types");
        let found_ietf_yang_types = input.find_import_module("ietf-yang-types");
        let found_ietf_inet_types = input.find_import_module("ietf-inet-types");
        let not_found_import_module = input.find_import_module("ietf-routing");
        let found_submodule = input.find_submodule("example-submodule");
        let not_found_submodule = input.find_submodule("non-existent-submodule");

        assert_eq!(found_ietf_routing, Some(&ietf_routing_module));
        assert_eq!(found_ietf_interfaces, Some(&ietf_interfaces_module));
        assert_eq!(found_example, Some(&example_module));
        assert_eq!(not_found_module, None);
        assert_eq!(found_ietf_yang_types, Some(vec![&ietf_yang_types_module]));
        assert_eq!(found_ietf_inet_types, Some(vec![&ietf_inet_types_module]));
        assert_eq!(not_found_import_module, None);
        assert_eq!(found_submodule, Some(&example_submodule));
        assert_eq!(not_found_submodule, None);
    }
}
