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

//! # Flow Supervisor Module
//!
//! This module implements a supervisor actor that manages multiple
//! `FlowCollectorActor` instances. It utilizes the actor model to provide a
//! scalable and fault-tolerant system for collecting and processing flow data
//! (NetFlow/IPFIX) over UDP.
//!
//! ## Actor Model Implementation
//!
//! The module uses the actor model in the following ways:
//!
//! 1. **Supervisor Actor**: The `FlowCollectorsSupervisorActor` acts as a
//!    supervisor, managing multiple `FlowCollectorActor` instances.
//! 2. **Message Passing**: Communication between the supervisor and its child
//!    actors is done through asynchronous message passing.
//! 3. **Encapsulation**: Each actor (supervisor and children) encapsulates its
//!    own state and behavior.
//! 4. **Concurrency**: Multiple `FlowCollectorActor` instances can run
//!    concurrently, each handling its own UDP socket.
//!
//! ## Key Components
//!
//! ### [SupervisorConfig]
//!
//! Defines the configuration for the supervisor, including binding addresses
//! and the number of workers for each address.
//!
//! ### a private FlowCollectorsSupervisorActor
//!
//! The main supervisor actor that manages multiple `FlowCollectorActor`
//! instances. It handles commands and broadcasts them to child actors, and
//! manages the lifecycle of child actors.
//!
//! ### [FlowCollectorsSupervisorActorHandle]
//!
//! Provides a public interface for interacting with the supervisor actor. It
//! allows clients to send commands and receive responses from the supervisor.
//!
//! ## Fault Tolerance and Scaling
//!
//! - The supervisor can manage multiple `FlowCollectorActor` instances,
//!   allowing for horizontal scaling.
//! - If a child actor fails, the supervisor can detect this and potentially
//!   restart it (though this is not currently implemented).
//! - The supervisor provides a centralized point for managing and interacting
//!   with multiple flow collectors.

use crate::{
    create_flow_channel,
    flow_actor::{
        FlowCollectorActorCommand, FlowCollectorActorError, FlowCollectorActorHandle,
        PeerTemplateIds,
    },
    ActorId, FlowReceiver, FlowSender, SubscriberId, Subscription,
};
use netgauze_flow_pkt::{ipfix, netflow};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, str::FromStr, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, error, info, trace};

#[derive(Debug, Serialize, Deserialize)]
pub struct SupervisorConfig {
    pub binding_addresses: Vec<BindingAddress>,
    pub cmd_buffer_size: usize,
    pub subscriber_timeout: Duration,
}

/// Configuration to a given listening address
#[derive(Debug, Serialize, Deserialize)]
pub struct BindingAddress {
    /// Socket address to bind to
    pub socket_addr: SocketAddr,
    /// How many workers assigned to the given socket
    pub num_workers: usize,
    pub interface: Option<String>,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            binding_addresses: vec![BindingAddress {
                socket_addr: SocketAddr::from_str("0.0.0.0:9991").unwrap(),
                num_workers: 2,
                interface: None,
            }],
            cmd_buffer_size: 100,
            subscriber_timeout: Duration::from_secs(1),
        }
    }
}

/// The command used to interact with the `FlowCollectorsSupervisorActor`
#[derive(Debug, strum_macros::Display)]
enum FlowCollectorsSupervisorActorCommand {
    /// Command to send to all [FlowCollectorActor]
    FlowActorCommand(FlowCollectorActorCommand),
    /// Command to subscribe to flow data
    Unsubscribe(Vec<Subscription>, mpsc::Sender<Option<ActorId>>),
    /// Shutdown the supervisor and all its manged actors
    Shutdown(oneshot::Sender<()>),
}

/// The supervisor actor that manages multiple `FlowCollectorActor` instances.
#[derive(Debug)]
struct FlowCollectorsSupervisorActor {
    actor_handlers: HashMap<ActorId, FlowCollectorActorHandle>,
}

impl FlowCollectorsSupervisorActor {
    fn new(actor_handlers: HashMap<ActorId, FlowCollectorActorHandle>) -> Self {
        Self { actor_handlers }
    }

    /// Wait for all [FlowCollectorActor]s to finish
    async fn join_flow_receiver_actors(
        join_handles: Vec<JoinHandle<Result<(ActorId, SocketAddr), FlowCollectorActorError>>>,
    ) {
        let mut join_handles = join_handles;
        loop {
            let awaited = futures::future::select_all(join_handles);
            join_handles = match awaited.await {
                (Ok(ret), _, rest) => {
                    // TODO(AH): Have some policy to allow to restart actors or terminate supervisor
                    //           if failed
                    if let Err(err) = ret {
                        error!("[Supervisor] actor terminated with error: {err}");
                    }
                    if rest.is_empty() {
                        info!("[Supervisor] no more active actors, shutting down");
                        break;
                    }
                    rest
                }
                (Err(err), _, rest) => {
                    // AH: if we did our job correctly, this should never happen
                    error!("[Supervisor] Unrecoverable error in worker: {:?}", err);
                    if rest.is_empty() {
                        info!("[Supervisor] Supervisor is shutting down, no remaining workers are still running");
                        return;
                    }
                    rest
                }
            };
        }
    }

    /// Handles [FlowCollectorsSupervisorActorCommand]
    async fn cmd(
        &mut self,
        mut rx: mpsc::Receiver<FlowCollectorsSupervisorActorCommand>,
    ) -> Result<(), ()> {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                FlowCollectorsSupervisorActorCommand::FlowActorCommand(flow_cmd) => {
                    debug!(
                        "[FlowSupervisor] Broadcasting to {} actors the flow command: {flow_cmd}",
                        self.actor_handlers.len()
                    );
                    for handle in self.actor_handlers.values() {
                        if let Err(_err) = handle.cmd_tx.send(flow_cmd.clone()).await {
                            error!(
                                "[FlowSupervisor] Failed to send command to Actor {}-{}",
                                handle.actor_id(),
                                handle.local_addr(),
                            )
                        };
                    }
                }
                FlowCollectorsSupervisorActorCommand::Unsubscribe(subscriptions, tx) => {
                    let mut mapped: HashMap<ActorId, Vec<SubscriberId>> = HashMap::new();
                    subscriptions
                        .iter()
                        .for_each(|s| mapped.entry(s.actor_id).or_default().push(s.id));
                    for (actor_id, handle) in &self.actor_handlers {
                        let mut send_back = None;
                        if let Some(subscription_ids) = mapped.get(actor_id) {
                            for id in subscription_ids {
                                match handle.unsubscribe(*id).await {
                                    Ok(_) => {
                                        info!(
                                            "[FlowSupervisor] Unsubscribed from actor {}-{}",
                                            handle.actor_id(),
                                            handle.local_addr(),
                                        );
                                        send_back = Some(*actor_id);
                                    }
                                    Err(err) => {
                                        error!(
                                            "[FlowSupervisor] Failed to send command to Actor {}-{}: {err:?}",
                                            handle.actor_id(),
                                            handle.local_addr(),
                                        )
                                    }
                                }
                            }
                        }
                        if let Err(err) = tx.send(send_back).await {
                            error!(
                                "[FlowSupervisor] Failed to send back the results unsubscribe command from Actor {}-{}: {err:?}",
                                handle.actor_id(),
                                handle.local_addr(),
                            )
                        }
                    }
                }
                FlowCollectorsSupervisorActorCommand::Shutdown(tx) => {
                    info!("[FlowSupervisor] Received shutdown command, shutting down all actors");
                    for handle in self.actor_handlers.values() {
                        let _ = handle.shutdown().await;
                    }
                    if let Err(_err) = tx.send(()) {
                        return Err(());
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Consume the actor, run it and block till it finishes
    async fn run(
        mut self,
        join_handles: Vec<JoinHandle<Result<(ActorId, SocketAddr), FlowCollectorActorError>>>,
        rx: mpsc::Receiver<FlowCollectorsSupervisorActorCommand>,
    ) {
        tokio::select! {
            biased;
            _ = self.cmd(rx) => {
            }
            _ = Self::join_flow_receiver_actors(join_handles) => {
            }
        }
    }
}

#[derive(Debug)]
pub enum FlowCollectorsSupervisorActorHandleError {
    SendError,
    ReceiveError,
}

impl std::fmt::Display for FlowCollectorsSupervisorActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SendError => write!(f, "Error sending command to supervisor actor"),
            Self::ReceiveError => {
                write!(f, "Error receiving response from supervisor actor")
            }
        }
    }
}

impl std::error::Error for FlowCollectorsSupervisorActorHandleError {
    fn description(&self) -> &str {
        match *self {
            Self::SendError => "Error sending command to supervisor actor",
            Self::ReceiveError => "Error receiving response from supervisor actor",
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

/// Handle to interact with the `FlowCollectorsSupervisorActor`
#[derive(Debug, Clone)]
pub struct FlowCollectorsSupervisorActorHandle {
    cmd_tx: mpsc::Sender<FlowCollectorsSupervisorActorCommand>,
    cmd_buffer_size: usize,
}

impl FlowCollectorsSupervisorActorHandle {
    pub async fn new(
        config: SupervisorConfig,
    ) -> (JoinHandle<()>, FlowCollectorsSupervisorActorHandle) {
        let mut next_actor_id = 0;
        let mut actor_handlers = HashMap::new();
        let mut actors_join = vec![];
        for binding_address in config.binding_addresses {
            for _ in 0..binding_address.num_workers {
                info!(
                    "[SupervisorHandle] Starting actor {next_actor_id} listening on socket: {}",
                    binding_address.socket_addr
                );
                let actor_ret = FlowCollectorActorHandle::new(
                    next_actor_id,
                    binding_address.socket_addr,
                    binding_address.interface.clone(),
                    10,
                    config.subscriber_timeout,
                )
                .await;
                match actor_ret {
                    Err(err) => {
                        error!("[SupervisorHandle] Failed to start actor: {err:?}");
                    }
                    Ok((join_handle, actor_handle)) => {
                        actor_handlers.insert(next_actor_id, actor_handle);
                        actors_join.push(join_handle);
                        next_actor_id += 1;
                    }
                }
            }
        }
        let (tx, rx) = mpsc::channel(100);
        let supervisor = FlowCollectorsSupervisorActor::new(actor_handlers);
        let handle = FlowCollectorsSupervisorActorHandle {
            cmd_tx: tx.clone(),
            cmd_buffer_size: config.cmd_buffer_size,
        };

        let join_handle = tokio::spawn(async move { supervisor.run(actors_join, rx).await });
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending shutting down message to supervisor");
        let (tx, rx) = oneshot::channel();
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::Shutdown(tx))
            .await
        {
            error!("[SupervisorHandle] Error sending shutdown: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        rx.await
            .map_err(|_| FlowCollectorsSupervisorActorHandleError::ReceiveError)
    }

    pub async fn subscribe(
        &self,
        buffer_size: usize,
    ) -> Result<(FlowReceiver, Vec<Subscription>), FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending new subscription request to supervisor");
        let (pkt_tx, pkt_rx) = create_flow_channel(buffer_size);
        let subscriptions = self.subscribe_tx(pkt_tx).await?;
        Ok((pkt_rx, subscriptions))
    }

    pub async fn subscribe_tx(
        &self,
        pkt_tx: FlowSender,
    ) -> Result<Vec<Subscription>, FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending new subscription with pre-created channel request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::FlowActorCommand(
                FlowCollectorActorCommand::Subscribe(tx, pkt_tx),
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending subscription request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut subscriptions = vec![];
        while let Some(subscription) = rx.recv().await {
            subscriptions.push(subscription);
        }
        Ok(subscriptions)
    }

    pub async fn unsubscribe(
        &self,
        subscriptions: Vec<Subscription>,
    ) -> Result<Vec<Option<ActorId>>, FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending unsubscribe request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::Unsubscribe(
                subscriptions,
                tx,
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending unsubscription request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut actors = vec![];
        while let Some(actor) = rx.recv().await {
            actors.push(actor);
        }
        Ok(actors)
    }

    pub async fn purge_unused_peers(
        &self,
        duration: Duration,
    ) -> Result<Vec<SocketAddr>, FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending new purge unused peers request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::FlowActorCommand(
                FlowCollectorActorCommand::PurgeUnusedPeers(duration, tx),
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending purge unused peers request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut purged_peers = vec![];
        while let Some(ret) = rx.recv().await {
            purged_peers.extend(ret);
        }
        Ok(purged_peers)
    }

    pub async fn purge_peer(
        &self,
        peer: SocketAddr,
    ) -> Result<Vec<Option<ActorId>>, FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending new purge {peer} request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::FlowActorCommand(
                FlowCollectorActorCommand::PurgePeer(peer, tx),
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending purge unused peers request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut purged_peers = vec![];
        while let Some(ret) = rx.recv().await {
            purged_peers.push(ret);
        }
        Ok(purged_peers)
    }

    /// Get local addresses that the flow actors are listening on.
    pub async fn local_addresses(
        &self,
    ) -> Result<Vec<(ActorId, SocketAddr)>, FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending get local addresses request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::FlowActorCommand(
                FlowCollectorActorCommand::LocalAddr(tx),
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending purge unused peers request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut local = vec![];
        while let Some(ret) = rx.recv().await {
            local.push(ret);
        }
        Ok(local)
    }

    pub async fn get_peers(
        &self,
    ) -> Result<Vec<(ActorId, Vec<SocketAddr>)>, FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending get peers request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::FlowActorCommand(
                FlowCollectorActorCommand::GetPeers(tx),
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending get peers request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut peers = vec![];
        while let Some(ret) = rx.recv().await {
            peers.push(ret);
        }
        Ok(peers)
    }

    pub async fn get_peer_template_ids(
        &self,
        peer: SocketAddr,
    ) -> Result<Vec<(ActorId, PeerTemplateIds)>, FlowCollectorsSupervisorActorHandleError> {
        trace!("[SupervisorHandle] Sending get peer template ids request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::FlowActorCommand(
                FlowCollectorActorCommand::GetPeerTemplateIds(peer, tx),
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending get peer template ids request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut template_ids = vec![];
        while let Some(ret) = rx.recv().await {
            template_ids.push(ret);
        }
        Ok(template_ids)
    }

    pub async fn get_peer_templates(
        &self,
        peer: SocketAddr,
    ) -> Result<
        Vec<(ActorId, netflow::TemplatesMap, ipfix::TemplatesMap)>,
        FlowCollectorsSupervisorActorHandleError,
    > {
        trace!("[SupervisorHandle] Sending get peer templates request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(FlowCollectorsSupervisorActorCommand::FlowActorCommand(
                FlowCollectorActorCommand::GetPeerTemplates(peer, tx),
            ))
            .await
        {
            error!("[SupervisorHandle] Error sending get peer templates request: {err:?}");
            return Err(FlowCollectorsSupervisorActorHandleError::SendError);
        }
        let mut templates = vec![];
        while let Some(ret) = rx.recv().await {
            templates.push(ret);
        }
        Ok(templates)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;
    use bytes::{Buf, BytesMut};
    use chrono::{TimeZone, Utc};
    use netgauze_flow_pkt::{codec::FlowInfoCodec, ie, ipfix::*, FieldSpecifier, FlowInfo};
    use tokio::{
        net::UdpSocket,
        time::{timeout, Duration},
    };
    use tokio_util::codec::Encoder;

    // Helper function to create a test configuration
    fn create_test_config() -> SupervisorConfig {
        SupervisorConfig {
            binding_addresses: vec![
                BindingAddress {
                    socket_addr: "127.0.0.1:0".parse().unwrap(),
                    num_workers: 2,
                    interface: None,
                },
                BindingAddress {
                    socket_addr: "127.0.0.1:0".parse().unwrap(),
                    num_workers: 1,
                    interface: None,
                },
            ],
            cmd_buffer_size: 10,
            subscriber_timeout: Duration::from_secs(1),
        }
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
    async fn test_supervisor_creation() {
        let config = create_test_config();
        let (join_handle, handle) = FlowCollectorsSupervisorActorHandle::new(config).await;

        assert!(!join_handle.is_finished());

        // Shutdown the supervisor
        handle
            .shutdown()
            .await
            .expect("Failed to shutdown supervisor");

        // Wait for the join handle to complete
        timeout(Duration::from_secs(5), join_handle)
            .await
            .expect("Supervisor didn't shut down in time")
            .expect("Supervisor panicked");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_supervisor_subscribe_unsubscribe() {
        let config = create_test_config();
        let (_join_handle, handle) = FlowCollectorsSupervisorActorHandle::new(config).await;

        // Subscribe
        let (pkt_rx, subscriptions) = handle.subscribe(10).await.expect("Failed to subscribe");
        assert_eq!(subscriptions.len(), 3); // 2 + 1 workers from our config

        // Unsubscribe
        let unsubscribe_results = handle
            .unsubscribe(subscriptions)
            .await
            .expect("Failed to unsubscribe");
        assert_eq!(unsubscribe_results.len(), 3);
        assert!(unsubscribe_results.iter().all(|r| r.is_some()));
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Try to receive a message (should return None denoting channel is closed as
        // we've unsubscribed)
        let timeout_result = timeout(Duration::from_secs(1), pkt_rx.recv()).await;
        assert!(matches!(timeout_result, Ok(Err(_))));

        handle
            .shutdown()
            .await
            .expect("Failed to shutdown supervisor");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_supervisor_purge_unused_peers() {
        let config = create_test_config();
        let (_join_handle, handle) = FlowCollectorsSupervisorActorHandle::new(config).await;

        // Purge unused peers (should be none at this point)
        let purged_peers = handle
            .purge_unused_peers(Duration::from_secs(60))
            .await
            .expect("Failed to purge unused peers");
        assert!(purged_peers.is_empty());

        let local_addrs = handle
            .local_addresses()
            .await
            .expect("Failed to get local addresses");

        let mut peers = vec![];
        for addr in local_addrs {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = socket
                .local_addr()
                .expect("Couldn't get local address of a test client");
            peers.push(peer);
            let (_flow_info, mut buf) = generate_flow_info_data();
            send_data(addr.1, &socket, &mut buf).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let purged_peers = handle
            .purge_unused_peers(Duration::from_millis(100))
            .await
            .expect("Failed to purge unused peers");
        assert!(purged_peers.is_empty());

        tokio::time::sleep(Duration::from_millis(200)).await;
        let purged_peers = handle
            .purge_unused_peers(Duration::from_millis(100))
            .await
            .expect("Failed to purge unused peers");
        assert_eq!(
            HashSet::<SocketAddr>::from_iter(purged_peers.into_iter()),
            HashSet::from_iter(peers.into_iter())
        );

        handle
            .shutdown()
            .await
            .expect("Failed to shutdown supervisor");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_supervisor_get_peer_templates() {
        let config = create_test_config();
        let (_join_handle, handle) = FlowCollectorsSupervisorActorHandle::new(config).await;

        // Get local addresses that the flow actors are listening on
        let local_addrs = handle
            .local_addresses()
            .await
            .expect("Failed to get local addresses");
        assert!(
            !local_addrs.is_empty(),
            "Should have at least one local address"
        );
        // Generate and send test template packets to each local address
        let mut peers = vec![];
        for (_, addr) in local_addrs {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = socket
                .local_addr()
                .expect("Couldn't get local address of a test client");
            peers.push(peer);
            let (_flow_info, mut buf) = generate_flow_info_data();
            send_data(addr, &socket, &mut buf).await;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Get peers
        let peers = handle.get_peers().await.expect("Failed to get peers");
        assert!(!peers.is_empty(), "Should have at least one peer");

        // Check templates for each peer
        for (actor_id, peer_addrs) in peers {
            for peer_addr in peer_addrs {
                let templates = handle
                    .get_peer_templates(peer_addr)
                    .await
                    .expect("Failed to get peer templates");

                for (received_actor_id, nf9_templates, ipfix_templates) in templates {
                    // Check NetFlow v9 templates
                    assert!(
                        nf9_templates.is_empty(),
                        "Should NOT have NetFlow v9 templates for actor {actor_id}"
                    );

                    // Check IPFIX templates
                    if actor_id == received_actor_id {
                        assert!(
                            !ipfix_templates.is_empty(),
                            "Should have IPFIX templates for actor {actor_id}"
                        );
                    } else {
                        assert!(
                            ipfix_templates.is_empty(),
                            "Should NOT have IPFIX templates for actor {actor_id}"
                        );
                    }
                }
            }
        }

        handle
            .shutdown()
            .await
            .expect("Failed to shutdown supervisor");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_supervisor_get_peer_template_ids() {
        let config = create_test_config();
        let (_join_handle, handle) = FlowCollectorsSupervisorActorHandle::new(config).await;

        // Get local addresses that the flow actors are listening on
        let local_addrs = handle
            .local_addresses()
            .await
            .expect("Failed to get local addresses");
        assert!(
            !local_addrs.is_empty(),
            "Should have at least one local address"
        );
        // Generate and send test template packets to each local address
        let mut peers = vec![];
        for (_, addr) in local_addrs {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = socket
                .local_addr()
                .expect("Couldn't get local address of a test client");
            peers.push(peer);
            let (_flow_info, mut buf) = generate_flow_info_data();
            send_data(addr, &socket, &mut buf).await;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Get peers
        let peers = handle.get_peers().await.expect("Failed to get peers");
        assert!(!peers.is_empty(), "Should have at least one peer");

        // Check templates for each peer
        for (actor_id, peer_addrs) in peers {
            for peer_addr in peer_addrs {
                let templates = handle
                    .get_peer_template_ids(peer_addr)
                    .await
                    .expect("Failed to get peer templates");

                for (received_actor_id, peer_template_id) in templates {
                    // Check NetFlow v9 templates
                    assert!(
                        peer_template_id.v9.is_empty(),
                        "Should NOT have NetFlow v9 templates for actor {actor_id}"
                    );

                    // Check IPFIX templates
                    if actor_id == received_actor_id {
                        assert!(
                            !peer_template_id.v10.is_empty(),
                            "Should have IPFIX templates for actor {actor_id}"
                        );
                    } else {
                        assert!(
                            peer_template_id.v10.is_empty(),
                            "Should NOT have IPFIX templates for actor {actor_id}",
                        );
                    }
                }
            }
        }

        handle
            .shutdown()
            .await
            .expect("Failed to shutdown supervisor");
    }
}
