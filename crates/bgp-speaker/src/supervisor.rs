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
    codec::{BgpCodecDecoderError, BgpCodecInitializer},
    connection::ActiveConnect,
    peer::{
        EchoCapabilitiesPolicy, Peer, PeerConfig, PeerConfigBuilder, PeerController, PeerHandle,
        PeerPolicy, PeerProperties, PeerStateResult,
    },
};
use netgauze_bgp_pkt::{
    wire::{deserializer::BgpParsingIgnoredErrors, serializer::BgpMessageWritingError},
    BgpMessage,
};
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    net::Ipv4Addr,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, mpsc::UnboundedReceiver},
};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PeersSupervisorError {
    PeerExists,
}

/// Peer lifetime management
/// At the moment this is a simple implementation and need more work
#[derive(Debug)]
pub struct PeersSupervisor<K: Hash + Eq + PartialEq, A, I: AsyncWrite + AsyncRead> {
    my_asn: u32,
    my_bgp_id: Ipv4Addr,
    peers: HashMap<K, PeerController<K, A, I>>,
}

impl<
        K: Display + Hash + Eq + PartialEq + Copy + Send + Sync + 'static,
        A: Copy + Display + Debug + Send + Sync + 'static,
        I: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    > PeersSupervisor<K, A, I>
{
    pub fn new(my_asn: u32, my_bgp_id: Ipv4Addr) -> Self {
        Self {
            my_asn,
            my_bgp_id,
            peers: HashMap::new(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn create_peer<
        D: BgpCodecInitializer<Peer<K, A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send
            + Sync,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
        P: PeerPolicy<A, I, D> + Send + Sync + 'static,
    >(
        &mut self,
        peer_key: K,
        peer_properties: PeerProperties<A>,
        peer_config: PeerConfig,
        active_connect: C,
        policy: P,
    ) -> Result<(UnboundedReceiver<PeerStateResult<A>>, PeerHandle<A, I>), PeersSupervisorError>
    {
        if self.peers.contains_key(&peer_key) {
            return Err(PeersSupervisorError::PeerExists);
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let peer_controller = PeerController::new(
            peer_key,
            peer_properties,
            peer_config,
            tx,
            policy,
            active_connect,
        );
        let peer_handle = peer_controller.get_new_handle();
        self.peers.insert(peer_key, peer_controller);
        Ok((rx, peer_handle))
    }

    pub fn remove_peer(&mut self, peer_key: &K) -> Option<PeerController<K, A, I>> {
        self.peers.remove(peer_key).map(|controller| {
            let handler = controller.get_new_handle();
            let _ = handler.shutdown();
            controller
        })
    }

    pub fn peer_handler(&mut self, peer_key: &K) -> Option<PeerHandle<A, I>> {
        self.peers.get(peer_key).map(|ctrl| ctrl.get_new_handle())
    }

    pub fn peer_keys(&self) -> Vec<K> {
        self.peers.keys().cloned().collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn dynamic_peer<
        D: BgpCodecInitializer<Peer<K, A, I, D, C, EchoCapabilitiesPolicy<A, I, D>>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send
            + Sync
            + 'static,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
    >(
        &mut self,
        peer_key: K,
        peer_addr: A,
        active_connect: C,
    ) -> Result<(UnboundedReceiver<PeerStateResult<A>>, PeerHandle<A, I>), PeersSupervisorError>
    {
        let peer_properties = PeerProperties::new(
            self.my_asn,
            self.my_asn,
            self.my_bgp_id,
            self.my_bgp_id, // Just assume a default bgp id
            peer_addr,
            true,
            true,
        );
        let peer_config = PeerConfigBuilder::new()
            // set open_delay_Timer to max, to allow the peer to communicate it's open message first
            .open_delay_timer_duration(u16::MAX)
            .passive_tcp_establishment(true)
            .build();
        let policy = EchoCapabilitiesPolicy::new(
            self.my_asn,
            true,
            self.my_bgp_id,
            peer_config.hold_timer_duration_large_value,
            Vec::new(),
            Vec::new(),
        );
        let (rx, peer_handle) = self.create_peer(
            peer_key,
            peer_properties,
            peer_config,
            active_connect,
            policy,
        )?;
        Ok((rx, peer_handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::TcpActiveConnect;
    use std::net::{SocketAddr, SocketAddrV4};

    #[tokio::test]
    async fn test_add_remove_peers() -> Result<(), PeersSupervisorError> {
        let my_bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer_bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        let my_asn = 100;
        let peer_asn = 200;
        let peer_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 179));
        let peer_properties = PeerProperties::new(
            my_asn,
            peer_asn,
            my_bgp_id,
            peer_bgp_id,
            peer_addr,
            false,
            false,
        );
        let mut supervisor = PeersSupervisor::new(my_asn, my_bgp_id);

        let (_rx, _peer_handle) = supervisor.create_peer(
            peer_addr.ip(),
            peer_properties,
            PeerConfig::default(),
            TcpActiveConnect,
            EchoCapabilitiesPolicy::new(my_asn, false, my_bgp_id, 100, Vec::new(), Vec::new()),
        )?;
        let second_create = supervisor.create_peer(
            peer_addr.ip(),
            peer_properties,
            PeerConfig::default(),
            TcpActiveConnect,
            EchoCapabilitiesPolicy::new(my_asn, false, my_bgp_id, 100, Vec::new(), Vec::new()),
        );
        let removed_peer = supervisor.remove_peer(&peer_addr.ip());
        let non_existing_peer = supervisor.remove_peer(&peer_addr.ip());

        assert_eq!(second_create.err(), Some(PeersSupervisorError::PeerExists));
        assert!(removed_peer.is_some());
        assert!(non_existing_peer.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_dynamic_peers() -> Result<(), PeersSupervisorError> {
        let my_bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer_bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        let my_asn = 100;
        let peer_asn = 200;
        let peer_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 179));
        let peer_properties = PeerProperties::new(
            my_asn,
            peer_asn,
            my_bgp_id,
            peer_bgp_id,
            peer_addr,
            false,
            false,
        );
        let mut supervisor = PeersSupervisor::new(my_asn, my_bgp_id);

        let (_rx, _peer_handle) =
            supervisor.dynamic_peer(peer_addr.ip(), peer_addr, TcpActiveConnect)?;
        let second_create = supervisor.create_peer(
            peer_addr.ip(),
            peer_properties,
            PeerConfig::default(),
            TcpActiveConnect,
            EchoCapabilitiesPolicy::new(my_asn, false, my_bgp_id, 100, Vec::new(), Vec::new()),
        );

        let removed_peer = supervisor.remove_peer(&peer_addr.ip());
        let non_existing_peer = supervisor.remove_peer(&peer_addr.ip());
        assert_eq!(second_create.err(), Some(PeersSupervisorError::PeerExists));
        assert!(removed_peer.is_some());
        assert!(non_existing_peer.is_none());
        Ok(())
    }
}
