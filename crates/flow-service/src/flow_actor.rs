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

//! Flow Actor Module
//!
//! This module implements the `FlowCollectorActor`, which uses the actor model
//! to handle concurrent reception and processing of flow packets
//! (NetFlow/IPFIX) over UDP.
//!
//! # Actor Model in FlowCollectorActor
//!
//! The actor model is a conceptual model for concurrent computation. In this
//! implementation:
//!
//! 1. The `FlowCollectorActor` is an independent unit of computation (an
//!    actor).
//! 2. It maintains its own state (subscriptions, peer information, etc.) which
//!    is not directly accessible from outside.
//! 3. It communicates with the outside world exclusively through message
//!    passing.
//!
//! ## Key Characteristics
//!
//! - **Encapsulation**: The actor encapsulates its state and behavior. External
//!   entities can't directly modify its internal state.
//! - **Message-Driven**: All interactions with the actor are done through
//!   asynchronous messages (commands).
//! - **Concurrency**: Multiple actors can run concurrently without explicit
//!   locking mechanisms.
//!
//! ## Actor Communication
//!
//! The `FlowCollectorActor` communicates through two main channels:
//!
//! 1. **Command Channel**: Receives `FlowCollectorActorCommand` messages to
//!    control the actor's behavior.
//! 2. **UDP Socket**: Receives flow packets from the network.
//!
//! ## Actor Lifecycle
//!
//! 1. **Creation**: The actor is created and started when
//!    [FlowCollectorActorHandle::new()] is called.
//! 2. **Running**: The actor processes incoming UDP packets and commands in its
//!    `run()` method.
//! 3. **Shutdown**: The actor can be gracefully shut down using the `Shutdown`
//!    command.
//!
//! # Benefits of the Actor Model in this Context
//!
//! - **Concurrency**: Efficiently handles multiple UDP streams without explicit
//!   locking.
//! - **Scalability**: Easy to scale by creating multiple actors for different
//!   or same (with port reuse) UDP ports or high-load scenarios.
//! - **Fault Isolation**: Errors in one actor don't directly affect others,
//!   enhancing system resilience.
//! - **Flexibility**: Easy to add new behaviors by introducing new command
//!   types.
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use netgauze_flow_service::flow_actor::FlowCollectorActorHandle;
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     use std::time::Duration;
//!     let addr: SocketAddr = "127.0.0.1:9995".parse().unwrap();
//!     let (events_tx, events_rx) = async_channel::bounded(100);
//!     let (join_handle, actor_handle) =
//!         FlowCollectorActorHandle::new(1, addr, 100, events_tx, events_rx.clone())
//!             .await
//!             .expect("Failed to create FlowCollectorActor");
//!
//!     // In a real application, you might want to spawn a new task to handle packets
//!     tokio::spawn(async move {
//!         while let Ok(packet) = events_rx.recv().await {
//!             println!("Received packet: {:?}", packet);
//!         }
//!     });
//!     // Shut down the actor
//!     actor_handle
//!         .shutdown()
//!         .await
//!         .expect("Failed to shut down actor");
//!     // Wait for the actor to complete (in practice, you might wait for a shutdown signal)
//!     join_handle
//!         .await
//!         .expect("Actor failed")
//!         .expect("actor failed");
//! }
//! ```

use crate::{ActorId, FlowReceiver, FlowRequest, FlowSender};
use bytes::{Bytes, BytesMut};
use futures_util::{stream::SplitSink, StreamExt};
use netgauze_flow_pkt::{codec::FlowInfoCodec, ipfix, netflow};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::{
    codec::{BytesCodec, Decoder},
    udp::UdpFramed,
};
use tracing::{debug, error, info, warn};

/// Represents the IDs of templates received from a specific peer.
#[derive(Clone, Debug)]
pub struct PeerTemplateIds {
    /// The socket address of the peer.
    pub peer: SocketAddr,
    /// List of NetFlow v9 template IDs.
    pub v9: Vec<u16>,
    /// List of IPFIX template IDs.
    pub v10: Vec<u16>,
}

/// Commands that can be sent to the [FlowCollectorActor].
#[derive(Debug, Clone, strum_macros::Display)]
pub(crate) enum FlowCollectorActorCommand {
    /// Command to shut down the actor.
    Shutdown(mpsc::Sender<ActorId>),
    PurgeUnusedPeers(Duration, mpsc::Sender<Vec<SocketAddr>>),
    PurgePeer(SocketAddr, mpsc::Sender<Option<ActorId>>),
    LocalAddr(mpsc::Sender<(ActorId, SocketAddr)>),
    GetPeers(mpsc::Sender<(ActorId, Vec<SocketAddr>)>),
    GetPeerTemplateIds(SocketAddr, mpsc::Sender<(ActorId, PeerTemplateIds)>),
    GetPeerTemplates(
        SocketAddr,
        mpsc::Sender<(ActorId, netflow::TemplatesMap, ipfix::TemplatesMap)>,
    ),
}

/// This struct keeps track of the usage of a peer.
/// It keeps track of the number of packets received from the peer since
/// last_set time.
#[derive(Debug)]
struct PeerUsage {
    last_set: Instant,
    current_count: usize,
}

impl Default for PeerUsage {
    fn default() -> Self {
        Self {
            last_set: Instant::now(),
            current_count: 0,
        }
    }
}

/// Errors that can occur in the `FlowCollectorActor`.
#[derive(Debug)]
pub enum FlowCollectorActorError {
    SocketBindError(ActorId, SocketAddr, std::io::Error),
    GetLocalAddressError(ActorId, SocketAddr, std::io::Error),
    CommandChannelClosed(ActorId, SocketAddr),
    UnrecoverablePacketProcessingError(ActorId, SocketAddr, std::io::Error),
}

impl std::fmt::Display for FlowCollectorActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketBindError(actor_id, addr, err) => write!(
                f,
                "[Actor {actor_id}-{addr}] failed to bind to socket address {addr}: {err}"
            ),
            Self::GetLocalAddressError(actor_id, addr, err) => write!(
                f,
                "[Actor {actor_id}-{addr}] failed to get local address: {err}"
            ),
            Self::CommandChannelClosed(actor_id, addr) => {
                write!(f, "[Actor {actor_id}-{addr}] command channel closed",)
            }
            Self::UnrecoverablePacketProcessingError(actor_id, addr, err) => write!(
                f,
                "[Actor {actor_id}-{addr}] unrecoverable error processing packet: {err}"
            ),
        }
    }
}

impl std::error::Error for FlowCollectorActorError {
    fn description(&self) -> &str {
        match self {
            Self::SocketBindError(_, _, _) => "failed tob bind to socket address",
            Self::GetLocalAddressError(_, _, _) => "failed to get local address",
            Self::CommandChannelClosed(_, _) => "command channel closed",
            Self::UnrecoverablePacketProcessingError(_, _, _) => {
                "unrecoverable error processing packet"
            }
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            Self::SocketBindError(_, _, err) => Some(err),
            Self::GetLocalAddressError(_, _, err) => Some(err),
            Self::CommandChannelClosed(_, _) => None,
            Self::UnrecoverablePacketProcessingError(_, _, err) => Some(err),
        }
    }
}

/// The main actor struct responsible for receiving and processing flow packets.
///
/// This struct encapsulates the state and behavior of the actor. In the actor
/// model, this internal state is not directly accessible from outside the
/// actor.
#[derive(Debug)]
struct FlowCollectorActor {
    actor_id: ActorId,
    socket_addr: SocketAddr,
    cmd_rx: mpsc::Receiver<FlowCollectorActorCommand>,
    events_tx: FlowSender,
    peers_usage: HashMap<SocketAddr, PeerUsage>,
    clients: HashMap<SocketAddr, FlowInfoCodec>,
}

impl FlowCollectorActor {
    fn new(
        actor_id: ActorId,
        socket_addr: SocketAddr,
        cmd_rx: mpsc::Receiver<FlowCollectorActorCommand>,
        events_tx: FlowSender,
    ) -> Self {
        Self {
            actor_id,
            socket_addr,
            cmd_rx,
            events_tx,
            peers_usage: HashMap::default(),
            clients: HashMap::new(),
        }
    }

    /// This function decodes a packet and returns the decoded packet if
    /// successful. For minor errors (e.g. buffer not long enough or a
    /// decoding error), it logs the error and returns None.
    pub fn decode_pkt(&mut self, next: (BytesMut, SocketAddr)) -> Option<FlowRequest> {
        let (mut buf, addr) = next;
        // If we haven't seen the client before, create a new FlowInfoCodec for it.
        // FlowInfoCodec handles the decoding/encoding of packets and caches
        // the templates learned from the client
        let result = self.clients.entry(addr).or_default().decode(&mut buf);
        match result {
            Ok(Some(pkt)) => Some((addr, pkt)),
            Ok(None) => {
                debug!(
                    "[Actor {}-{}] Needs more data to decode the packet",
                    self.actor_id, self.socket_addr
                );
                None
            }
            Err(err) => {
                warn!(
                    "[Actor {}-{}] Dropping packet due to an error in decoding packet: {err:?}",
                    self.actor_id, self.socket_addr
                );
                None
            }
        }
    }

    /// This function handles a decoded packet.
    /// In the current implementation, it sends the packet to all subscribers.
    async fn handle_decoded_pkt(&mut self, next: Option<FlowRequest>) {
        if let Some((peer, pkt)) = next {
            let usage = self.peers_usage.entry(peer).or_default();
            usage.current_count += 1;
            let flow_request = (peer, pkt);
            let actor_id = self.actor_id;
            let socket_addr = self.socket_addr;
            if let Err(err) = self.events_tx.send(flow_request).await {
                error!("[Actor {actor_id}-{socket_addr}] Error sending flow request to subscribers: {err:?}");
            } else {
                debug!("[Actor {actor_id}-{socket_addr}] Sent flow flow to subscribers");
            }
        }
    }

    async fn handle_shutdown(&self, tx: mpsc::Sender<ActorId>) -> bool {
        info!(
            "[Actor {}-{}] Received shutdown command, shutting down",
            self.actor_id, self.socket_addr
        );
        let _ = tx.send(self.actor_id).await;
        true
    }

    async fn handle_purge_peer(
        &mut self,
        peer: SocketAddr,
        tx: mpsc::Sender<Option<ActorId>>,
    ) -> bool {
        match self.clients.remove(&peer).map(|_| self.actor_id) {
            Some(_) => {
                info!(
                    "[Actor {}-{}] Removing templates cache for peer {peer}",
                    self.actor_id, self.socket_addr
                );
                let _ = self.peers_usage.remove(&peer);
                let _ = tx.send(Some(self.actor_id)).await;
            }
            None => {
                info!(
                    "[Actor {}-{}] Peer {peer} not found",
                    self.actor_id, self.socket_addr
                );
                let _ = tx.send(None).await;
            }
        }
        false
    }

    async fn handle_purge_unused_peers(
        &mut self,
        dur: Duration,
        ret_tx: mpsc::Sender<Vec<SocketAddr>>,
    ) -> bool {
        let mut cleared_peers = vec![];
        info!(
            "[Actor {}-{}] removing templates cache for peers that were inactive for {dur:?}",
            self.actor_id, self.socket_addr
        );
        let now = Instant::now();
        self.peers_usage.retain(
            |peer, usage| {
                let since = now.duration_since(usage.last_set);
                if since > dur && usage.current_count == 0 {
                    info!("[Actor {}-{}] Cleaning peers that have not been used for the past: {dur:?}", self.actor_id, self.socket_addr);
                    cleared_peers.push(*peer);
                    false
                } else if since > dur && usage.current_count > 0 {
                    usage.last_set = now;
                    usage.current_count = 0;
                    debug!("[Actor {}-{}] Keeping templates cache for peer {peer} and resetting counters for it", self.actor_id, self.socket_addr);
                    true
                } else {
                    debug!("[Actor {}-{}] Keeping templates cache for peer {peer} that was used {} times since {since:?}", self.actor_id, self.socket_addr, usage.current_count);
                    true
                }
            }
        );
        info!(
            "[Actor {}-{}] Cleaned {} inactive peers",
            self.actor_id,
            self.socket_addr,
            cleared_peers.len()
        );
        if let Err(_err) = ret_tx.send(cleared_peers).await {
            error!("[Actor {}-{}] communicating back the list of peers whom templates cache is cleared", self.actor_id, self.socket_addr);
        }
        false
    }

    async fn handle_local_addr(&self, tx: mpsc::Sender<(ActorId, SocketAddr)>) -> bool {
        if let Err(err) = tx.send((self.actor_id, self.socket_addr)).await {
            error!(
                "[Actor {}-{}] Unable to send back the local address: {err}",
                self.actor_id, self.socket_addr
            );
        }
        false
    }

    async fn handle_get_peers(&self, tx: mpsc::Sender<(ActorId, Vec<SocketAddr>)>) -> bool {
        let peers = self.clients.keys().cloned().collect::<Vec<_>>();
        if let Err(err) = tx.send((self.actor_id, peers)).await {
            error!(
                "[Actor {}-{}] Unable to send back the list of peers: {err}",
                self.actor_id, self.socket_addr,
            );
        }
        false
    }

    async fn handle_get_peer_template_ids(
        &self,
        peer: SocketAddr,
        tx: mpsc::Sender<(ActorId, PeerTemplateIds)>,
    ) -> bool {
        let template_ids = self
            .clients
            .get(&peer)
            .map(|x| {
                let v9 = x.netflow_templates_map().keys().copied().collect();
                let v10 = x.ipfix_templates_map().keys().copied().collect();
                PeerTemplateIds { peer, v9, v10 }
            })
            .unwrap_or(PeerTemplateIds {
                peer,
                v9: vec![],
                v10: vec![],
            });
        if let Err(err) = tx.send((self.actor_id, template_ids)).await {
            error!(
                "[Actor {}-{}] Unable to send back the list of template IDs: {}",
                self.actor_id, self.socket_addr, err
            );
        }
        false
    }

    async fn handle_get_peer_templates(
        &self,
        peer: SocketAddr,
        tx: mpsc::Sender<(ActorId, netflow::TemplatesMap, ipfix::TemplatesMap)>,
    ) -> bool {
        let (v9, v10) = self
            .clients
            .get(&peer)
            .map(|x| {
                (
                    x.netflow_templates_map().clone(),
                    x.ipfix_templates_map().clone(),
                )
            })
            .unwrap_or((HashMap::new(), HashMap::new()));
        if let Err(err) = tx.send((self.actor_id, v9, v10)).await {
            error!(
                "[Actor {}-{}] Unable to send back the list of templates: {}",
                self.actor_id, self.socket_addr, err
            );
        }
        false
    }

    async fn handle_cmd(
        &mut self,
        cmd: Option<FlowCollectorActorCommand>,
    ) -> Result<bool, FlowCollectorActorError> {
        let actor_id = self.actor_id;
        let socket_addr = self.socket_addr;

        let cmd_result = match cmd {
            Some(FlowCollectorActorCommand::Shutdown(tx)) => self.handle_shutdown(tx).await,
            // Some(FlowCollectorActorCommand::Subscribe(tx, pkt_tx)) => {
            //     self.handle_subscribe(tx, pkt_tx).await
            // }
            // Some(FlowCollectorActorCommand::Unsubscribe(id, tx)) => {
            //     self.handle_unsubscribe(id, tx).await
            // }
            Some(FlowCollectorActorCommand::PurgePeer(peer, tx)) => {
                self.handle_purge_peer(peer, tx).await
            }
            Some(FlowCollectorActorCommand::PurgeUnusedPeers(dur, ret_tx)) => {
                self.handle_purge_unused_peers(dur, ret_tx).await
            }
            Some(FlowCollectorActorCommand::LocalAddr(tx)) => self.handle_local_addr(tx).await,
            Some(FlowCollectorActorCommand::GetPeers(tx)) => self.handle_get_peers(tx).await,
            Some(FlowCollectorActorCommand::GetPeerTemplateIds(peer, tx)) => {
                self.handle_get_peer_template_ids(peer, tx).await
            }
            Some(FlowCollectorActorCommand::GetPeerTemplates(peer, tx)) => {
                self.handle_get_peer_templates(peer, tx).await
            }
            None => {
                warn!(
                    "[Actor {actor_id}-{socket_addr}] Command channel is closed, shutting down actor"
                );
                return Err(FlowCollectorActorError::CommandChannelClosed(
                    actor_id,
                    socket_addr,
                ));
            }
        };
        Ok(cmd_result)
    }

    /// Runs the actor, processing incoming packets and commands until shutdown.
    ///
    /// This method implements the core logic of the actor. It runs in a loop,
    /// handling both incoming UDP packets and command messages. This
    /// dual-channel approach allows the actor to efficiently manage network
    /// I/O and control messages concurrently.
    async fn run(mut self) -> Result<(ActorId, SocketAddr), FlowCollectorActorError> {
        let actor_id = self.actor_id;
        let socket_addr = self.socket_addr;
        info!("[Actor {actor_id}-{socket_addr}] Spawning Actor and binding UDP listener",);
        let socket = crate::new_udp_reuse_port(self.socket_addr, None).map_err(|err| {
            FlowCollectorActorError::SocketBindError(self.actor_id, socket_addr, err)
        })?;
        // Get the local address of the socket, handy in cases where the port is 0
        self.socket_addr = socket.local_addr().map_err(|err| {
            FlowCollectorActorError::GetLocalAddressError(self.actor_id, socket_addr, err)
        })?;
        let framed = UdpFramed::new(socket, BytesCodec::default());
        let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
        loop {
            tokio::select! {
                biased; // Prioritize command messages
                cmd = self.cmd_rx.recv() =>{
                    match self.handle_cmd(cmd).await {
                        Ok(true) => return Ok((actor_id, socket_addr)),
                        Ok(false) => {}
                        Err(err) => return Err(err),
                    }
                }
                next = stream.next() => {
                    match next {
                        Some(Ok(next)) => {
                            let next = self.decode_pkt(next);
                            self.handle_decoded_pkt(next).await;
                        }
                        Some(Err(err)) => {
                            error!("[Actor {actor_id}-{socket_addr}] Shutting down due to unrecoverable error: {err}");
                            return Err(FlowCollectorActorError::UnrecoverablePacketProcessingError(actor_id, socket_addr, err))
                        }
                        None => {
                            error!("[Actor {actor_id}-{socket_addr}] Shutting down because UDP socket is down");
                            return Ok((actor_id, socket_addr))
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum FlowCollectorActorHandleError {
    SendError,
    ReceiveError,
}

impl std::fmt::Display for FlowCollectorActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            FlowCollectorActorHandleError::SendError => write!(f, "Error sending command to actor"),
            FlowCollectorActorHandleError::ReceiveError => {
                write!(f, "Error receiving response from actor")
            }
        }
    }
}

impl std::error::Error for FlowCollectorActorHandleError {
    fn description(&self) -> &str {
        match *self {
            FlowCollectorActorHandleError::SendError => "Error sending command to actor",
            FlowCollectorActorHandleError::ReceiveError => "Error receiving response from actor",
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

/// A handle is the public interface for interacting with a
/// `FlowCollectorActor`.
///
///
/// This handle provides a way to send commands to the actor and receive
/// responses. It encapsulates the communication channels to the actor, adhering
/// to the principle of message-passing in the actor model.
///
/// The handle is clonable allowing multiple entities to interact with the
/// actor.
#[derive(Debug, Clone)]
pub struct FlowCollectorActorHandle {
    actor_id: ActorId,
    local_addr: SocketAddr,
    cmd_buffer_size: usize,
    pub(crate) cmd_tx: mpsc::Sender<FlowCollectorActorCommand>,
    events_rx: FlowReceiver,
}

impl FlowCollectorActorHandle {
    pub async fn new(
        actor_id: ActorId,
        socket_addr: SocketAddr,
        cmd_buffer_size: usize,
        events_tx: FlowSender,
        events_rx: FlowReceiver,
    ) -> Result<
        (
            JoinHandle<Result<(ActorId, SocketAddr), FlowCollectorActorError>>,
            Self,
        ),
        FlowCollectorActorHandleError,
    > {
        let (cmd_tx, cmd_rx) = mpsc::channel(cmd_buffer_size);
        let actor = FlowCollectorActor::new(actor_id, socket_addr, cmd_rx, events_tx);
        let join_handle = tokio::spawn(actor.run());
        let (tx, mut rx) = mpsc::channel(cmd_buffer_size);
        cmd_tx
            .send(FlowCollectorActorCommand::LocalAddr(tx))
            .await
            .map_err(|_| FlowCollectorActorHandleError::SendError)?;
        let local_addr = rx
            .recv()
            .await
            .ok_or(FlowCollectorActorHandleError::ReceiveError)?
            .1;

        Ok((
            join_handle,
            Self {
                actor_id,
                local_addr,
                cmd_buffer_size,
                cmd_tx,
                events_rx,
            },
        ))
    }

    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// This function sends a command to the actor to subscribe to the packets.
    pub fn subscribe(&self) -> FlowReceiver {
        self.events_rx.clone()
    }

    pub async fn shutdown(&self) -> Result<Vec<ActorId>, FlowCollectorActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(FlowCollectorActorCommand::Shutdown(tx))
            .await
            .map_err(|_| FlowCollectorActorHandleError::SendError)?;
        let mut actors = vec![];
        while let Some(actor_id) = rx.recv().await {
            actors.push(actor_id);
        }
        Ok(actors)
    }

    pub async fn purge_unused_peers(
        &self,
        duration: Duration,
    ) -> Result<Vec<SocketAddr>, FlowCollectorActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        // If the command fails, the recv after will fail, no need to double handle the
        // error
        self.cmd_tx
            .send(FlowCollectorActorCommand::PurgeUnusedPeers(duration, tx))
            .await
            .map_err(|_| FlowCollectorActorHandleError::SendError)?;
        let mut peers = vec![];
        while let Some(got_peers) = rx.recv().await {
            peers.extend(got_peers)
        }
        Ok(peers)
    }

    pub async fn purge_peer(
        &self,
        peer: SocketAddr,
    ) -> Result<Option<ActorId>, FlowCollectorActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(FlowCollectorActorCommand::PurgePeer(peer, tx))
            .await
            .map_err(|_| FlowCollectorActorHandleError::SendError)?;
        Ok(rx.recv().await.flatten())
    }

    pub async fn get_peers(
        &self,
    ) -> Result<(ActorId, Vec<SocketAddr>), FlowCollectorActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(FlowCollectorActorCommand::GetPeers(tx))
            .await
            .map_err(|_| FlowCollectorActorHandleError::SendError)?;
        if let Some(peers) = rx.recv().await {
            Ok(peers)
        } else {
            Ok((self.actor_id, vec![]))
        }
    }

    pub async fn get_peer_template_ids(
        &self,
        peer: SocketAddr,
    ) -> Result<(ActorId, PeerTemplateIds), FlowCollectorActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(FlowCollectorActorCommand::GetPeerTemplateIds(peer, tx))
            .await
            .map_err(|_| FlowCollectorActorHandleError::SendError)?;
        if let Some(peers) = rx.recv().await {
            Ok(peers)
        } else {
            Ok((
                self.actor_id,
                PeerTemplateIds {
                    peer,
                    v9: vec![],
                    v10: vec![],
                },
            ))
        }
    }

    pub async fn get_peer_templates(
        &self,
        peer: SocketAddr,
    ) -> Result<(ActorId, netflow::TemplatesMap, ipfix::TemplatesMap), FlowCollectorActorHandleError>
    {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(FlowCollectorActorCommand::GetPeerTemplates(peer, tx))
            .await
            .map_err(|_| FlowCollectorActorHandleError::SendError)?;
        if let Some(peers) = rx.recv().await {
            Ok(peers)
        } else {
            Ok((self.actor_id, HashMap::new(), HashMap::new()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_channel::RecvError;
    use bytes::{Buf, BytesMut};
    use chrono::{TimeZone, Utc};
    use netgauze_flow_pkt::{
        codec::FlowInfoCodec, ie, ipfix::*, netflow, FieldSpecifier, FlowInfo,
    };
    use tokio::{net::UdpSocket, time::Duration};
    use tokio_util::codec::Encoder;

    async fn setup_actor() -> (
        SocketAddr,
        FlowCollectorActorHandle,
        JoinHandle<Result<(ActorId, SocketAddr), FlowCollectorActorError>>,
    ) {
        let actor_id = 1;
        let socket_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (events_tx, events_rx) = async_channel::bounded(100);
        let (join_handle, handle) =
            FlowCollectorActorHandle::new(actor_id, socket_addr, 10, events_tx, events_rx)
                .await
                .expect("Couldn't start test actor");
        let socket_addr = handle.local_addr();
        (socket_addr, handle, join_handle)
    }

    async fn send_data(listening_socket: SocketAddr, socket: &UdpSocket, data: &mut BytesMut) {
        while data.remaining() > 0 {
            let sent = socket.send_to(data, listening_socket).await.unwrap();
            data.advance(sent);
            tokio::task::yield_now().await;
        }
    }

    fn generate_flow_info_data() -> (FlowInfo, BytesMut) {
        // sample IPFIX packet
        let ipfix_template = IpfixPacket::new(
            Utc.with_ymd_and_hms(2024, 7, 8, 10, 0, 0).unwrap(),
            0,
            0,
            vec![Set::Template(vec![TemplateRecord::new(
                400,
                vec![
                    FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                    FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                ],
            )])],
        );
        // Create a FlowInfo struct with some test data
        let flow_info = FlowInfo::IPFIX(ipfix_template);

        // Encode the FlowInfo struct into bytes
        let mut codec = FlowInfoCodec::default();
        let mut buf = BytesMut::new();
        codec.encode(flow_info.clone(), &mut buf).unwrap();
        (flow_info, buf)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_decode_pkt_error_handling() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send invalid data to trigger a decoding error
        let invalid_data = BytesMut::from(&[0u8; 10][..]);
        send_data(listening_socket, &socket, &mut invalid_data.clone()).await;

        // Subscribe to receive packets
        let receiver = handle.subscribe();

        // Ensure no packet is received due to decoding error
        let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await;
        assert!(received.is_err());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_shutdown() {
        let (_, handle, join_handle) = setup_actor().await;

        // Shutdown
        let shutdown_result = handle.shutdown().await.unwrap();
        assert_eq!(shutdown_result.len(), 1);
        assert_eq!(shutdown_result[0], handle.actor_id());

        // Ensure the actor has shut down
        let result = join_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_purge_unused_peers() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send FlowInfo data to register the peer
        let (_, mut data) = generate_flow_info_data();
        tokio::task::yield_now().await;
        send_data(listening_socket, &socket, &mut data).await;

        // Wait for a short duration to simulate inactivity
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Purge unused peers
        let duration = Duration::from_millis(100);
        let purged_peers = handle.purge_unused_peers(duration).await.unwrap();
        assert_eq!(purged_peers.len(), 0);

        // Wait for a short duration to simulate inactivity
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Second round the peer should be purged
        let purged_peers = handle.purge_unused_peers(duration).await.unwrap();
        assert_eq!(purged_peers.len(), 1);
        assert_eq!(purged_peers[0], socket.local_addr().unwrap());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_purge_peer() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let flow_rx = handle.subscribe();

        // Generate and send FlowInfo data to register the peer
        let (sent_pkt, mut data) = generate_flow_info_data();
        send_data(listening_socket, &socket, &mut data).await;

        let handled_pkt = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv())
            .await
            .unwrap();
        // Ensure the packet was handled
        assert_eq!(handled_pkt, Ok((socket.local_addr().unwrap(), sent_pkt)));

        // Purge the specific peer
        let peer_addr = socket.local_addr().unwrap();
        let purged_peer = handle.purge_peer(peer_addr).await.unwrap();
        assert_eq!(purged_peer, Some(handle.actor_id()));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_receive_udp_packet() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send FlowInfo data to register the peer
        let (sent_pkt, mut data) = generate_flow_info_data();
        send_data(listening_socket, &socket, &mut data).await;

        // Subscribe to receive packets
        let flow_rx = handle.subscribe();

        // Receive the packet
        let received = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv()).await;
        assert!(received.is_ok());
        let received_packet = received.unwrap();
        assert_eq!(
            received_packet,
            Ok((socket.local_addr().unwrap(), sent_pkt))
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_concurrent_behavior() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind multiple UDP sockets to send packets
        let socket1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr1 = socket1.local_addr().unwrap();
        let local_addr2 = socket2.local_addr().unwrap();

        // Subscribe to receive packets
        let flow_rx = handle.subscribe();

        // Generate and send FlowInfo data from multiple sockets
        let (pkt1, mut data1) = generate_flow_info_data();
        let (pkt2, mut data2) = generate_flow_info_data();
        send_data(listening_socket, &socket1, &mut data1).await;
        send_data(listening_socket, &socket2, &mut data2).await;

        // Receive packets
        let received1 = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv()).await;
        assert_eq!(received1, Ok(Ok((local_addr1, pkt1))));

        let received2 = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv()).await;
        assert_eq!(received2, Ok(Ok((local_addr2, pkt2))));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_get_peers() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;
        let flow_rx = handle.subscribe();

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send FlowInfo data to register the peer
        let (sent_pkt, mut data) = generate_flow_info_data();
        send_data(listening_socket, &socket, &mut data).await;
        // Ensure the packet was handled before getting peers
        let handled_pkt = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv())
            .await
            .unwrap();
        assert_eq!(handled_pkt, Ok((socket.local_addr().unwrap(), sent_pkt)));

        // Get peers
        let (actor_id, peers) = handle.get_peers().await.unwrap();
        assert_eq!(actor_id, handle.actor_id());
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], socket.local_addr().unwrap());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_get_peer_template_ids() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;
        let flow_rx = handle.subscribe();

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send FlowInfo data to register the peer
        let (sent_pkt, mut data) = generate_flow_info_data();
        send_data(listening_socket, &socket, &mut data).await;
        // Ensure the packet was handled before getting template IDs
        let handled_pkt = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv())
            .await
            .unwrap();
        assert_eq!(handled_pkt, Ok((socket.local_addr().unwrap(), sent_pkt)));

        // Get peer template IDs
        let peer_addr = socket.local_addr().unwrap();
        let (actor_id, template_ids) = handle.get_peer_template_ids(peer_addr).await.unwrap();
        assert_eq!(actor_id, handle.actor_id());
        assert_eq!(template_ids.peer, peer_addr);
        assert!(!template_ids.v9.is_empty() || !template_ids.v10.is_empty());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_get_peer_templates() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;
        let flow_rx = handle.subscribe();

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send FlowInfo data to register the peer
        let (sent_pkt, mut data) = generate_flow_info_data();
        send_data(listening_socket, &socket, &mut data).await;
        // Ensure the packet was handled before getting templates
        let handled_pkt = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv())
            .await
            .unwrap();
        assert_eq!(
            handled_pkt,
            Ok((socket.local_addr().unwrap(), sent_pkt.clone()))
        );

        // Get peer templates
        let peer_addr = socket.local_addr().unwrap();
        let (actor_id, netflow_templates, ipfix_templates) =
            handle.get_peer_templates(peer_addr).await.unwrap();
        assert_eq!(actor_id, handle.actor_id());
        match sent_pkt {
            FlowInfo::NetFlowV9(v9_pkt) => {
                for set in v9_pkt.sets() {
                    match set {
                        netflow::Set::Template(templates) => {
                            for template in templates {
                                assert!(netflow_templates.contains_key(&template.id()));
                                assert_eq!(
                                    netflow_templates.get(&template.id()),
                                    Some(&(vec![], template.field_specifiers().clone()))
                                );
                            }
                        }
                        netflow::Set::OptionsTemplate(templates) => {
                            for template in templates {
                                assert!(netflow_templates.contains_key(&template.id()));
                                assert_eq!(
                                    netflow_templates.get(&template.id()),
                                    Some(&(template.scope_field_specifiers().clone(), vec![]))
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            FlowInfo::IPFIX(v10_pkt) => {
                for set in v10_pkt.sets() {
                    match set {
                        ipfix::Set::Template(templates) => {
                            for template in templates {
                                assert!(ipfix_templates.contains_key(&template.id()));
                                assert_eq!(
                                    ipfix_templates.get(&template.id()),
                                    Some(&(vec![], template.field_specifiers().clone()))
                                );
                            }
                        }
                        ipfix::Set::OptionsTemplate(templates) => {
                            for template in templates {
                                assert!(ipfix_templates.contains_key(&template.id()));
                                assert_eq!(
                                    ipfix_templates.get(&template.id()),
                                    Some(&(template.scope_field_specifiers().clone(), vec![]))
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_flow_receiver_actor_lifecycle() {
        let (_, handle, join_handle) = setup_actor().await;

        // Test subscribe and unsubscribe
        let flow_rx = handle.subscribe();

        // Test shutdown
        let shutdown_result = handle.shutdown().await.unwrap();
        assert_eq!(shutdown_result.len(), 1, "Should have shut down one actor");
        assert_eq!(
            shutdown_result[0],
            handle.actor_id(),
            "Shut down actor should have correct ID"
        );

        // Ensure the actor has terminated
        let result = tokio::time::timeout(Duration::from_secs(5), join_handle).await;
        assert!(result.is_ok(), "Actor should have terminated");

        let result = tokio::time::timeout(Duration::from_secs(1), flow_rx.recv()).await;
        assert_eq!(result, Ok(Err(RecvError)), "channel should be closed");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_send_command_to_closed_actor() {
        let (_, handle, join_handle) = setup_actor().await;

        // Shutdown the actor
        handle.shutdown().await.unwrap();
        join_handle.await.unwrap().unwrap();

        // Try to send a command to the closed actor
        let result = handle.subscribe().recv().await;
        assert!(matches!(result, Err(async_channel::RecvError)));
    }
}
