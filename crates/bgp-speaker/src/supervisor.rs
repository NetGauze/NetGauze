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
use netgauze_bgp_pkt::{wire::serializer::BgpMessageWritingError, BgpMessage};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    net::Ipv4Addr,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, mpsc::UnboundedReceiver},
};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PeerSupervisorError {
    PeerExists,
}

/// Peer lifetime management
/// At the moment this is a simple implementation and need more work
#[derive(Debug)]
pub struct PeerSupervisor<A, I: AsyncWrite + AsyncRead> {
    my_asn: u32,
    my_bgp_id: Ipv4Addr,
    peers: HashMap<Ipv4Addr, PeerController<A, I>>,
}

impl<
        A: Clone + Display + Debug + Send + Sync + 'static,
        I: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    > PeerSupervisor<A, I>
{
    pub fn new(my_asn: u32, my_bgp_id: Ipv4Addr) -> Self {
        Self {
            my_asn,
            my_bgp_id,
            peers: HashMap::new(),
        }
    }

    pub fn add_peer<
        D: BgpCodecInitializer<Peer<A, I, D, C, P>>
            + Decoder<Item = BgpMessage, Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send
            + Sync,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
        P: PeerPolicy<A, I, D> + Send + Sync + 'static,
    >(
        &mut self,
        peer_properties: PeerProperties<A>,
        peer_config: PeerConfig,
        active_connect: C,
        policy: P,
    ) -> Result<UnboundedReceiver<PeerStateResult<A>>, PeerSupervisorError> {
        if self.peers.contains_key(&peer_properties.peer_bgp_id()) {
            return Err(PeerSupervisorError::PeerExists);
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let peer_bgp_id = peer_properties.peer_bgp_id();
        let peer_controller =
            PeerController::new(peer_properties, peer_config, tx, policy, active_connect);
        self.peers.insert(peer_bgp_id, peer_controller);
        Ok(rx)
    }

    pub fn remove_peer(&mut self, peer_bgp_id: Ipv4Addr) {
        if let Some(controller) = self.peers.remove(&peer_bgp_id) {
            let handler = controller.get_new_handle();
            let _ = handler.shutdown();
            drop(handler);
        }
    }

    pub fn peer_handler(&mut self, peer_bgp_id: Ipv4Addr) -> Option<PeerHandle<A, I>> {
        self.peers
            .get(&peer_bgp_id)
            .map(|ctrl| ctrl.get_new_handle())
    }

    pub fn peers(&self) -> Vec<Ipv4Addr> {
        self.peers.keys().cloned().collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn dynamic_peer<
        D: BgpCodecInitializer<Peer<A, I, D, C, EchoCapabilitiesPolicy<A, I, D>>>
            + Decoder<Item = BgpMessage, Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send
            + Sync
            + 'static,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
    >(
        &mut self,
        peer_bgp_id: Ipv4Addr,
        peer_addr: A,
        active_connect: C,
    ) -> Result<(UnboundedReceiver<PeerStateResult<A>>, PeerHandle<A, I>), PeerSupervisorError>
    {
        let peer_properties = PeerProperties::new(
            self.my_asn,
            self.my_asn,
            self.my_bgp_id,
            peer_bgp_id,
            peer_addr,
            true,
            true,
        );
        let peer_config = PeerConfigBuilder::new()
            .open_delay_timer_duration(1)
            .passive_tcp_establishment(true)
            .build();
        let policy = EchoCapabilitiesPolicy::new(
            self.my_asn,
            self.my_bgp_id,
            peer_config.hold_timer_duration_large_value,
            HashMap::new(),
            HashSet::new(),
        );
        let rx = self.add_peer(peer_properties, peer_config, active_connect, policy)?;
        let peer_handle = self.peer_handler(peer_bgp_id).unwrap();
        Ok((rx, peer_handle))
    }
}
