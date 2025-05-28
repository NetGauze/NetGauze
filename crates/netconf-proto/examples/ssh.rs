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

use std::future::Future;
use std::net::{SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;
use futures::{SinkExt, StreamExt};
use russh::keys::ssh_key;
use netgauze_netconf_proto::codec::SshCodec;
use netgauze_netconf_proto::protocol::{Hello, NetConfMessage};

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl russh::client::Handler for Client {
    type Error = russh::Error;
}



#[derive(clap::Parser, Debug)]
struct Args {
    host: SocketAddr,
    user: String,
    password: String,
}


#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    let args = Args::parse();

    let config = russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        ..<_>::default()
    };

    let config = Arc::new(config);

    // Establish connection and authenticate the user
    let ssh_client = Client {};
    let mut session = russh::client::connect(config, args.host, ssh_client).await?;
    let auth_res = session.authenticate_password(&args.user, &args.password).await?;
    if !auth_res.success() {
        anyhow::bail!("Authentication failed");
    } else {
        log::info!("Connected Authenticated to {} as user {}", args.host, args.user);
    }
    log::info!("Starting the netconf subsystem");
    // Establish communication channel with netconf subsystem
    let mut channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "netconf").await?;
    let stream = channel.into_stream();
    let framed = tokio_util::codec::Framed::new(stream, SshCodec::default());
    let (mut tx, mut rx) = framed.split();

    log::info!("Waiting for the router to send hello message");
    let recv_hello = if let Some(Ok(NetConfMessage::Hello(value))) = rx.next().await  {
        value
    } else {
        return Err(anyhow::anyhow!("Received unexpected message"));
    };
    log::info!("Received Hello:\n{:?}", recv_hello);

    log::info!("Sending Hello with the same capabilities announced by the router");
    tx.send(NetConfMessage::Hello(Hello {
        session_id: None,
        capabilities: recv_hello.capabilities.clone(),
    })).await?;
    log::info!("Hello message sent");
    Ok(())
}