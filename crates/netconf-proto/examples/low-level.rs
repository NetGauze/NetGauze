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
use futures::{SinkExt, StreamExt};
use netgauze_netconf_proto::{
    capabilities::{Base, Capability},
    codec::SshCodec,
    protocol::{Hello, NetConfMessage, Rpc, RpcReplyValue},
};
use russh::keys::ssh_key;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

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
    user: String,
    password: String,
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

    // Set up the log -> tracing bridge first
    //tracing_log::LogTracer::init().expect("Failed to initialize tracing logger");

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
    let mut session = russh::client::connect(config, args.host, ssh_client).await?;
    let auth_res = session
        .authenticate_password(&args.user, &args.password)
        .await?;
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
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "netconf").await?;
    let stream = channel.into_stream();
    let framed = tokio_util::codec::Framed::new(stream, SshCodec::default());
    let (mut tx, mut rx) = framed.split();

    tracing::info!("Waiting for the router to send hello message");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let recv_hello = match rx.next().await {
        Some(Ok(NetConfMessage::Hello(value))) => value,
        Some(Ok(msg)) => {
            tracing::error!("Unexcepted message {:?}", msg);
            return Err(anyhow::anyhow!("Received unexpected message"));
        }
        Some(Err(err)) => {
            tracing::error!("ERROR {}", err);
            // if matches!(err, SshCodecError::IO(io::ErrorKind::Rec)) {}
            // return Err(anyhow::anyhow!("Received error message"));
            Hello {
                capabilities: HashMap::new(),
                session_id: Some(1),
            }
        }
        None => return Err(anyhow::anyhow!("channel closed unexpectedly")),
    };

    tracing::debug!("Received Hello:\n{:?}", recv_hello);
    tracing::info!(
        "Received Hello with session id: {:?}",
        recv_hello.session_id
    );
    tracing::info!("Router announced capabilities:");
    for (name, cap) in &recv_hello.capabilities {
        tracing::info!(" - `{name}`  ---  `{cap}`")
    }

    tracing::info!("Sending Hello with the same capabilities announced by the router");
    tokio::time::sleep(Duration::from_millis(100)).await;
    tx.send(NetConfMessage::Hello(Hello {
        session_id: None,
        capabilities: recv_hello
            .capabilities
            .iter()
            .filter_map(|(k, cap)| {
                if let Capability::Base(Base::V1_0) = cap {
                    None
                } else {
                    Some((k.clone(), cap.clone()))
                }
            })
            .collect::<HashMap<_, _>>(),
    }))
    .await?;
    tracing::info!("Hello message sent");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let yang_library_supported = recv_hello.capabilities.contains_key(":ietf-yang-library");
    if !yang_library_supported {
        tracing::warn!("YANG Library is not supported");
    } else {
        tracing::info!("Retrieving YANG library from the router");
        let lib_request = "<get><filter type=\"subtree\"><yang-library xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"></yang-library></filter></get>".to_string();
        tx.send(NetConfMessage::Rpc(Rpc {
            message_id: "1011".to_string(),
            operation: lib_request,
        }))
        .await?;
        let yang_lib_reply = if let Some(Ok(NetConfMessage::RpcReply(value))) = rx.next().await {
            value
        } else {
            return Err(anyhow::anyhow!("Received unexpected message"));
        };

        tracing::info!("Got YANG library reply:\n{:?}", yang_lib_reply);
    }

    tracing::info!("Retrieving ietf-ip schema from the router");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let request = r#"<get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><identifier>ietf-ip</identifier></get-schema>"#.to_string();
    tx.send(NetConfMessage::Rpc(Rpc {
        message_id: "101".to_string(),
        operation: request,
    }))
    .await?;
    tracing::info!("Request sent");
    tokio::time::sleep(Duration::from_millis(100)).await;
    while let Some(msg) = rx.next().await {
        match msg {
            Ok(NetConfMessage::RpcReply(reply)) => {
                tracing::info!("Got reply message_id: {:?}", reply.message_id);
                match &reply.reply {
                    RpcReplyValue::Data(_, payload) => {
                        tracing::info!("Got reply payload:\n{}", payload);
                    }
                    RpcReplyValue::Ok => {
                        tracing::info!("OK");
                    }
                }
            }
            x => tracing::info!("Got REPLY FROM ROUTER:\n{:?}", x),
        }
        break;
    }

    tracing::info!("Terminating NETCONF session with the router");
    Ok(())
}
