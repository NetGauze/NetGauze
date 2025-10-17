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

use clap::Parser;
use netgauze_netconf_proto::{
    client::{connect, NetconfSshConnectConfig, SshAuth, SshHandler},
    protocol::{
        RpcOperation, RpcReplyContent, RpcResponse, WellKnownOperation, WellKnownRpcResponse,
        YangSchemaFormat,
    },
};
use std::{sync::Arc, time::Duration};

#[derive(clap::Parser, Debug)]
struct Args {
    #[arg(help = "Host address (IP:port or domain:port)")]
    host: String,

    #[clap(short, long)]
    user: String,

    /// Use user/name password for authentication
    #[clap(short, long)]
    password: Option<String>,

    /// Path of private key to be used in authentication
    #[clap(long)]
    key_path: Option<String>,

    /// Optional password for the private key
    #[clap(long)]
    key_pass: Option<String>,
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    // Set up the log -> tracing bridge first
    // tracing_log::LogTracer::init().expect("Failed to initialize tracing logger");

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
    init_tracing().expect("init tracing subscriber");
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
    let auth = if let Some(password) = &args.password {
        SshAuth::Password {
            user: args.user.clone(),
            password: secrecy::SecretBox::new(password.clone().into()),
        }
    } else if let Some(private_key_path) = &args.key_path {
        tracing::info!("Using the private key at: {}", private_key_path);
        let key_string =
            std::fs::read_to_string(private_key_path).expect("failed to read private key");
        tracing::info!("Private key string loaded");
        let private_key =
            russh::keys::decode_secret_key(key_string.as_str(), args.key_pass.as_deref())?;
        tracing::info!("Private key parsed");
        SshAuth::Key {
            user: args.user.clone(),
            private_key: Arc::new(private_key),
        }
    } else {
        anyhow::bail!("Either username/password or username/private key need to be defined");
    };

    let config = NetconfSshConnectConfig::new(auth, host, ssh_handler, ssh_config);
    let mut client = connect(config).await?;
    tracing::info!("Connected to server with caps: {:#?}", client.peer_caps());

    tokio::time::sleep(Duration::from_secs(1)).await;

    let get_schema_op = RpcOperation::WellKnown(WellKnownOperation::GetSchema {
        identifier: "ietf-datastores".into(),
        version: None,
        format: Some(YangSchemaFormat::Yang),
    });
    let message_id = client.rpc(get_schema_op).await?;
    let response = client.rpc_reply().await?;
    if response.message_id().is_some() && response.message_id() != Some(&message_id) {
        anyhow::bail!(
            "RPC returned unexpected message_id, expecting {message_id}, got {}",
            response.message_id().unwrap()
        );
    }

    tracing::info!("RPC returned message_id: {:?}", response.message_id());
    if let RpcReplyContent::ErrorsAndData {
        errors: _,
        responses,
    } = response.reply()
    {
        if let RpcResponse::WellKnown(WellKnownRpcResponse::YangSchema { schema }) = responses {
            eprintln!(
                "RPC YANG Schema response:\n==================\n{schema}\n================\n"
            );
        } else {
            anyhow::bail!("Expecting get-schema response got:\n==================\n{response:?}\n================\n");
        }
    }

    let message_id = client
        .rpc(RpcOperation::WellKnown(WellKnownOperation::GetYangLibrary))
        .await?;
    let response = client.rpc_reply().await?;
    if response.message_id().is_some() && response.message_id() != Some(&message_id) {
        anyhow::bail!(
            "RPC returned unexpected message_id, expecting {message_id}, got {}",
            response.message_id().unwrap()
        );
    }

    tracing::info!("RPC returned message_id: {:?}", response.message_id());
    if let RpcReplyContent::ErrorsAndData {
        errors: _,
        responses,
    } = response.reply()
    {
        if let RpcResponse::WellKnown(WellKnownRpcResponse::YangLibrary(library)) = responses {
            eprintln!(
                "RPC YANG LIBRARY
            response:\n==================\n{library:#?}\n================\n"
            );
        } else {
            anyhow::bail!("Expecting RPC YANG library response got:\n==================\n{responses:?}\n================\n");
        }
    }

    client.close().await?;
    Ok(())
}
