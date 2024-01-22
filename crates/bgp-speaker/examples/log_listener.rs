// Copyright (C) 2023-present The NetGauze Authors.
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
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    vec,
};
use tokio::net::TcpStream;

use netgauze_bgp_speaker::{
    connection::TcpActiveConnect,
    listener::BgpListener,
    peer::{EchoCapabilitiesPolicy, PeerConfigBuilder, PeerHandle, PeerProperties},
    supervisor::PeersSupervisor,
};

#[derive(clap::Parser, Debug)]
struct Args {
    my_asn: u32,
    my_bgp_id: Ipv4Addr,
}

/// Example of manually adding peer
fn create_peer(
    my_asn: u32,
    peer_asn: u32,
    my_bgp_id: Ipv4Addr,
    peer_bgp_id: Ipv4Addr,
    peer_addr: SocketAddr,
    supervisor: &mut PeersSupervisor<IpAddr, SocketAddr, TcpStream>,
) -> PeerHandle<SocketAddr, TcpStream> {
    let config = PeerConfigBuilder::new()
        .open_delay_timer_duration(1)
        .build();
    let policy = EchoCapabilitiesPolicy::new(
        my_asn,
        true,
        my_bgp_id,
        config.hold_timer_duration_large_value().as_secs() as u16,
        vec![],
        vec![],
    );

    let properties = PeerProperties::new(
        my_asn,
        peer_asn,
        my_bgp_id,
        peer_bgp_id,
        peer_addr,
        true,
        true,
    );

    let (mut received_rx, peer_handle) = supervisor
        .create_peer(peer_addr.ip(), properties, config, TcpActiveConnect, policy)
        .unwrap();
    peer_handle.start().unwrap();
    tokio::spawn(async move {
        while let Some(event) = received_rx.recv().await {
            log::info!("[LISTENER] GOT EVENT: {:?}", event);
        }
    });
    peer_handle
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let env = env_logger::Env::default()
        .filter_or("MY_LOG_LEVEL", "INFO")
        .write_style_or("MY_LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let args = Args::parse();

    let my_asn = args.my_asn;
    let my_bgp_id = args.my_bgp_id;

    let mut supervisor = PeersSupervisor::new(my_asn, my_bgp_id);

    let mut listener = BgpListener::new(
        vec![
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 179)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 179, 0, 0)),
        ],
        true,
    );

    // Example registering peer manually
    let peer_asn = 100;
    let peer_bgp_id = Ipv4Addr::new(172, 16, 0, 10);
    let peer_addr: SocketAddr = "192.168.56.10:179".parse().unwrap();
    let peer_handle = create_peer(
        my_asn,
        peer_asn,
        my_bgp_id,
        peer_bgp_id,
        peer_addr,
        &mut supervisor,
    );
    listener.reg_peer(peer_addr.ip(), peer_handle.clone());

    listener.run(&mut supervisor).await?;
    Ok(())
}
