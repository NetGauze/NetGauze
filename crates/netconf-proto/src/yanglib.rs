use crate::{
    xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
    YANG_DATASTORES_NS_STR, YANG_LIBRARY_AUGMENTED_BY_NS, YANG_LIBRARY_NS,
};
use indexmap::IndexMap;
use quick_xml::{
    events::{BytesText, Event},
    name::{QName, ResolveResult},
};
use serde::{Deserialize, Serialize};
use std::io;
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
}
