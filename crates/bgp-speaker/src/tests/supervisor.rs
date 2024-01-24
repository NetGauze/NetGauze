// Copyright (C) 2024-present The NetGauze Authors.
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

use crate::{
    codec::BgpCodec,
    connection::TcpActiveConnect,
    peer::{EchoCapabilitiesPolicy, PeerConfig},
    supervisor::{PeersSupervisor, PeersSupervisorError},
    tests::{HOLD_TIME, MY_AS, MY_BGP_ID, PEER_ADDR, PROPERTIES},
};
use std::net::SocketAddr;

const TCP_STREAM_POLICY: EchoCapabilitiesPolicy<SocketAddr, tokio::net::TcpStream, BgpCodec> =
    EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());

#[test_log::test(tokio::test)]
async fn test_add_remove_peers() -> Result<(), PeersSupervisorError> {
    let mut supervisor = PeersSupervisor::new(MY_AS, MY_BGP_ID);

    let (_rx, _peer_handle) = supervisor.create_peer(
        PEER_ADDR.ip(),
        PROPERTIES,
        PeerConfig::default(),
        TcpActiveConnect,
        TCP_STREAM_POLICY,
    )?;
    let second_create = supervisor.create_peer(
        PEER_ADDR.ip(),
        PROPERTIES,
        PeerConfig::default(),
        TcpActiveConnect,
        TCP_STREAM_POLICY,
    );
    let removed_peer = supervisor.remove_peer(&PEER_ADDR.ip());
    let non_existing_peer = supervisor.remove_peer(&PEER_ADDR.ip());

    assert_eq!(second_create.err(), Some(PeersSupervisorError::PeerExists));
    assert!(removed_peer.is_some());
    assert!(non_existing_peer.is_none());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_dynamic_peers() -> Result<(), PeersSupervisorError> {
    let mut supervisor = PeersSupervisor::new(MY_AS, MY_BGP_ID);
    let (_rx, _peer_handle) =
        supervisor.dynamic_peer(PEER_ADDR.ip(), PEER_ADDR, TcpActiveConnect)?;
    let second_create = supervisor.create_peer(
        PEER_ADDR.ip(),
        PROPERTIES,
        PeerConfig::default(),
        TcpActiveConnect,
        TCP_STREAM_POLICY,
    );

    let removed_peer = supervisor.remove_peer(&PEER_ADDR.ip());
    let non_existing_peer = supervisor.remove_peer(&PEER_ADDR.ip());
    assert_eq!(second_create.err(), Some(PeersSupervisorError::PeerExists));
    assert!(removed_peer.is_some());
    assert!(non_existing_peer.is_none());
    Ok(())
}
