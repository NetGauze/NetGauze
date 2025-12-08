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

use anyhow::anyhow;
use clap::Parser;
use netgauze_netconf_proto::{
    client::{connect, NetconfSshConnectConfig, SshAuth, SshHandler},
    xml_utils::{XmlDeserialize, XmlSerialize, XmlWriter},
    yanglib::{PermissiveVersionChecker, YangLibrary},
};
use quick_xml::NsReader;
use std::{collections::HashMap, io::Write, path::Path, sync::Arc, time::Duration};

#[derive(clap::Parser, Debug)]
struct Args {
    #[arg(help = "Host address (IP:port or hostname:port)")]
    host: String,

    #[clap(short, long)]
    user: String,

    /// Password for authentication by username/password or the
    /// password for the key if provided.
    #[clap(short, long)]
    password: Option<String>,

    /// Path of the private key to be used in authentication
    #[clap(short, long)]
    key: Option<String>,

    /// Output path to dump the YANG schemas to.
    #[clap(short, long)]
    output: Option<String>,

    /// Kafka Schema registry URL to register to
    #[clap(short, long)]
    registry_url: Option<String>,

    /// List of initial YANG modules to load (typically the ones in the
    /// subscription started) When registering with the schema registry, the
    /// first module is considered the root and main schema.
    #[clap(short, long)]
    modules: Vec<String>,

    /// Output inverted dependency graph in dot format
    #[clap(short, long, default_value = "false")]
    graph: bool,

    /// A path of a YANG library file to extend with the loaded modules with.
    /// For instance, adding the telemetry-message dependencies to an existing
    /// YANG push subscription.
    #[clap(short, long)]
    extend_yang_lib: Option<String>,

    /// YANG search path
    #[clap(long)]
    yang_search_path: Option<String>,
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    init_tracing().map_err(|x| anyhow!("failed to init tracing subscriber: {x}"))?;
    let args = Args::parse();
    let host = std::net::ToSocketAddrs::to_socket_addrs(&args.host)?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve host from: {}", &args.host))?;

    let ssh_handler = SshHandler::default();
    let ssh_config = russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        ..<_>::default()
    };
    let ssh_config = Arc::new(ssh_config);
    tracing::info!("connecting to {}", args.host);
    let auth = get_auth(&args)?;

    let config = NetconfSshConnectConfig::new(auth, host, ssh_handler, ssh_config);
    let mut client = connect(config).await?;
    tracing::info!("connected to {}", args.host);

    let modules = args
        .modules
        .as_slice()
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<&str>>();
    tracing::info!(
        "loading seed modules {} and their dependencies from {}",
        modules.join(","),
        args.host
    );
    let (mut yang_lib, mut schemas) = client
        .load_from_modules(modules.as_slice(), &PermissiveVersionChecker)
        .await
        .expect("Failed to load dependency graph");
    tracing::info!(
        "created a the yang library for the dependencies with {} schemas total",
        schemas.len()
    );

    if let Some(yang_lib_path) = &args.extend_yang_lib {
        tracing::info!("Loading existing yang library from {yang_lib_path}");
        let reader = NsReader::from_file(yang_lib_path)?;
        let mut xml_reader = netgauze_netconf_proto::xml_utils::XmlParser::new(reader)?;
        let existing_yang_lib = YangLibrary::xml_deserialize(&mut xml_reader)?;
        let existing_yang_schemas = if let Some(search_path) = &args.yang_search_path {
            let search_path = Path::new(search_path);
            tracing::info!("Loading schemas for existing yang library from {search_path:?}");
            existing_yang_lib.load_schemas_from_search_path(search_path)?
        } else {
            existing_yang_lib.load_schemas()?
        };
        let mut builder = yang_lib.clone().into_module_set_builder(
            &schemas,
            "ALL".into(),
            &PermissiveVersionChecker,
        )?;
        builder.extend_from_yang_lib(
            existing_yang_lib,
            &existing_yang_schemas,
            &PermissiveVersionChecker,
        )?;
        let (yang_lib_extended, schemas_extended) = builder.build_yang_lib();
        yang_lib = yang_lib_extended;
        schemas = schemas_extended;
    }

    if let Some(output) = &args.output {
        let output_path = Path::new(&output);
        if !output_path.exists() {
            std::fs::create_dir_all(output_path)?;
        }
        save_modules_to_disk(&yang_lib, &schemas, output_path)?;
    }

    if args.graph {
        let graph = yang_lib.to_graph(&schemas).map_err(|x| anyhow!(x))?;
        let dot = petgraph::dot::Dot::with_config(&graph, &[petgraph::dot::Config::EdgeNoLabel]);
        if let Some(output) = &args.output {
            let output_path = Path::new(&output).join("inverted_graph.dot");
            tracing::info!("writing inverted dependency graph in DOT format to {output_path:?}");
            std::fs::write(output_path, format!("{:?}\n", dot))?;
        } else {
            tracing::info!("writing inverted dependency graph to stdout in DOT format");
            println!("{dot:?}");
        }
    }

    if let Some(url) = &args.registry_url {
        use schema_registry_client::rest::schema_registry_client::Client;
        let root_schema_name = args
            .modules
            .first()
            .ok_or(anyhow!("no schemas defined to obtain from the router"))?;
        tracing::info!(
            "writing schemas to registry URL {url} with root schema `{root_schema_name}`"
        );
        // Setup connection to schema registry
        let client_conf =
            schema_registry_client::rest::client_config::ClientConfig::new(vec![url.to_string()]);
        let sr_client =
            schema_registry_client::rest::schema_registry_client::SchemaRegistryClient::new(
                client_conf,
            );
        let registered_schema = yang_lib
            .register_schema(root_schema_name, &schemas, &sr_client)
            .await
            .map_err(|x| anyhow!(x))?;

        tracing::info!(
            "registered schemas for {root_schema_name} with subject `{:?}` and ID `{:?}`",
            registered_schema.subject,
            registered_schema.id
        );
    }

    Ok(())
}

fn get_auth(args: &Args) -> anyhow::Result<SshAuth> {
    let auth = if let Some(private_key_path) = &args.key {
        tracing::info!("Loading the private key at: {}", private_key_path);
        let key_string = std::fs::read_to_string(private_key_path).map_err(|x| {
            anyhow!("failed to read private key from `{private_key_path}` due to error `{x}`")
        })?;
        tracing::debug!("Private key string loaded");
        let private_key =
            russh::keys::decode_secret_key(key_string.as_str(), args.password.as_deref())?;
        tracing::debug!("Private key parsed");
        SshAuth::Key {
            user: args.user.clone(),
            private_key: Arc::new(private_key),
        }
    } else if let Some(password) = &args.password {
        SshAuth::Password {
            user: args.user.clone(),
            password: secrecy::SecretBox::new(password.clone().into()),
        }
    } else {
        anyhow::bail!("Either username/password or username/private key need to be defined");
    };
    Ok(auth)
}

fn save_modules_to_disk(
    yang_lib: &YangLibrary,
    schemas: &HashMap<Box<str>, Box<str>>,
    output_path: &Path,
) -> anyhow::Result<()> {
    let yang_lib_path = output_path.join("yanglib.xml");
    tracing::info!("writing yang library of dependence to {yang_lib_path:?}");
    let file = std::fs::File::create(&yang_lib_path)?;
    let writer = std::io::BufWriter::new(file);
    let quick_xml_writer = quick_xml::writer::Writer::new_with_indent(writer, 32, 2);
    let mut xml_writer = XmlWriter::new(quick_xml_writer);
    yang_lib.xml_serialize(&mut xml_writer)?;
    xml_writer.into_inner().flush()?;

    for (name, schema) in schemas {
        let mut revision = None;
        if let Some(module) = yang_lib.find_module(name.as_ref()) {
            revision = module.revision();
        } else if let Some(import_only_modules) = yang_lib.find_import_module(name.as_ref()) {
            for import_only_module in import_only_modules {
                revision = import_only_module.revision();
                break;
            }
        } else if let Some(submodule) = yang_lib.find_submodule(name.as_ref()) {
            revision = submodule.revision();
        }
        let filename = if let Some(revision) = revision {
            format!("{}@{}.yang", name, revision)
        } else {
            name.to_string()
        };
        let yang_module_path = output_path.join(&filename);
        tracing::info!("writing yang module `{name}` to `{yang_module_path:?}`");
        std::fs::write(&yang_module_path, schema.as_ref())?;
    }
    Ok(())
}
