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
use log::trace;
use netgauze_netconf_proto::{client::NetConfClient, codec::SshCodec};
use russh::keys::{ssh_key, PrivateKeyWithHashAlg};
use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // trust everything
        Ok(true)
    }
}

#[derive(clap::Parser, Debug)]
struct Args {
    host: SocketAddr,

    #[clap(short, long)]
    user: String,

    #[clap(short, long)]
    password: Option<String>,

    #[clap(short, long)]
    key: Option<String>,
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

    let config = russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),

        ..<_>::default()
    };

    let config = Arc::new(config);

    // Establish connection and authenticate the user
    let ssh_client = Client {};
    tracing::info!("connecting to {}", args.host);
    let mut session = russh::client::connect(config, args.host, ssh_client).await?;
    tracing::info!("connecting to {}", args.host);
    let auth_res = if let Some(password) = &args.password {
        session.authenticate_password(&args.user, password).await?
    } else if let Some(private_key) = &args.key {
        tracing::info!("Using private key: {}", private_key);
        let key_string = std::fs::read_to_string(private_key).expect("failed to read private key");
        tracing::info!("Private key string loaded");
        let key = ssh_key::PrivateKey::from_str(&key_string).expect("failed to parse private key");
        tracing::info!("Private key parsed");
        let private_key = PrivateKeyWithHashAlg::new(
            Arc::new(key),
            session.best_supported_rsa_hash().await?.flatten(),
        );
        tracing::info!("Negotiated private key");
        session
            .authenticate_publickey(&args.user, private_key)
            .await?
    } else {
        return Err(anyhow::anyhow!(
            "Either password or private key need to be defined"
        ));
    };
    if !auth_res.success() {
        anyhow::bail!("Authentication failed");
    } else {
        tracing::info!(
            "Connected Authenticated to {} as user {}",
            args.host,
            args.user
        );
    }
    tracing::info!("Starting the netconf subsystem");
    // Establish communication channel with netconf subsystem
    let mut channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "netconf").await?;
    let stream = channel.into_stream();
    let framed = tokio_util::codec::Framed::new(stream, SshCodec::default());

    let client = NetConfClient::connect(framed, "../../assets/yang".to_string()).await?;

    tracing::info!(
        "Connected to the router with session id: {}",
        client.session_id()
    );
    tracing::info!("Terminating NETCONF session with the router");
    Ok(())
}
