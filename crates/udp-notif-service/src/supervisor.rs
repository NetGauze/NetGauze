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

//! # UdpNotif Supervisor Module
//!
//! This module implements a supervisor that manages multiple `UdpNotifActor`
//! instances. It utilizes the actor model to provide a scalable and
//! fault-tolerant system for collecting and processing udp-notif data.
//!
//! ## Actor Model Implementation
//!
//! The module uses the actor model in the following ways:
//!
//! 1. **Supervisor**: The `UdpNotifSupervisor` acts as a supervisor, managing
//!    multiple `UdpNotifActor` instances.
//! 2. **Message Passing**: Communication between the supervisor and its child
//!    actors is done through asynchronous message passing.
//! 3. **Encapsulation**: Each actor (supervisor and children) encapsulates its
//!    own state and behavior.
//! 4. **Concurrency**: Multiple `UdpNotifActor` instances can run concurrently,
//!    each handling its own UDP socket.
//!
//! ## Key Components
//!
//! ### [SupervisorConfig]
//!
//! Defines the configuration for the supervisor, including binding addresses
//! and the number of workers for each address.
//!
//! ### A private UdpNotifSupervisor
//!
//! The main supervisor that manages multiple `UdpNotifActor` instances.
//! It handles commands and broadcasts them to child actors, and manages
//! the lifecycle of child actors.
//!
//! ### [UdpNotifSupervisorHandle]
//!
//! Provides a public interface for interacting with the supervisor. It allows
//! clients to send commands and receive responses from the supervisor.
//!
//! ## Fault Tolerance and Scaling
//!
//! - The supervisor can manage multiple `UdpNotifActor` instances, allowing for
//!   horizontal scaling.
//! - If a child actor fails, the supervisor can detect this and potentially
//!   restart it (though this is not currently implemented).
//! - The supervisor provides a centralized point for managing and interacting
//!   with multiple udp-notif collectors.

use crate::{
    actor::{ActorCommand, ActorHandle, UdpNotifActorError, UdpNotifCollectorStats},
    create_udp_notif_channel, ActorId, SubscriberId, Subscription, UdpNotifReceiver,
    UdpNotifSender,
};
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
                socket_addr: SocketAddr::from_str("0.0.0.0:9999").unwrap(),
                num_workers: 2,
                interface: None,
            }],
            cmd_buffer_size: 100,
            subscriber_timeout: Duration::from_secs(1),
        }
    }
}

/// The command used to interact with the `UdpNotifSupervisor`
#[derive(Debug, strum_macros::Display)]
enum SupervisorCommand {
    /// Command to send to all [UdpNotifActor]
    ActorCommand(ActorCommand),
    /// Command to subscribe to udp-notif data
    Unsubscribe(Vec<Subscription>, mpsc::Sender<Option<ActorId>>),
    /// Shutdown the supervisor and all its manged actors
    Shutdown(oneshot::Sender<()>),
}

/// The supervisor that manages multiple `UdpNotifActor` instances.
#[derive(Debug)]
struct UdpNotifSupervisor {
    actor_handlers: HashMap<ActorId, ActorHandle>,
}

impl UdpNotifSupervisor {
    fn new(actor_handlers: HashMap<ActorId, ActorHandle>) -> Self {
        Self { actor_handlers }
    }

    /// Wait for all [UdpNotifActor]s to finish
    async fn join_actors(
        join_handles: Vec<JoinHandle<Result<(ActorId, SocketAddr), UdpNotifActorError>>>,
    ) {
        let mut handles = join_handles;
        loop {
            let awaited = futures::future::select_all(handles);
            handles = match awaited.await {
                (Ok(ret), _, rest) => {
                    // TODO(AH): Have some policy to allow to restart actors or terminate supervisor
                    //           if failed
                    if let Err(err) = ret {
                        error!("[Supervisor] actor terminated with error: {}", err);
                    }
                    if rest.is_empty() {
                        info!("[Supervisor] no more active actors, shutting down");
                        return;
                    }
                    rest
                }
                (Err(err), _, rest) => {
                    // AH: if we did our job correctly, this should never happen
                    error!("[Supervisor] unrecoverable error in actor: {:?}", err);
                    if rest.is_empty() {
                        info!("[Supervisor] no more active actors, shutting down");
                        return;
                    }
                    rest
                }
            };
        }
    }

    /// Handles [SupervisorCommand]
    async fn cmd(&mut self, mut rx: mpsc::Receiver<SupervisorCommand>) -> Result<(), ()> {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                SupervisorCommand::ActorCommand(actor_cmd) => {
                    debug!(
                        "[Supervisor] broadcasting command \"{}\" to {} actors",
                        actor_cmd,
                        self.actor_handlers.len(),
                    );
                    for handle in self.actor_handlers.values() {
                        if let Err(_err) = handle.cmd_tx.send(actor_cmd.clone()).await {
                            error!(
                                "[Supervisor] failed to send command to actor {}-{}",
                                handle.actor_id(),
                                handle.local_addr(),
                            )
                        };
                    }
                }
                SupervisorCommand::Unsubscribe(subscriptions, tx) => {
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
                                            "[Supervisor] unsubscribed from actor {}-{}",
                                            handle.actor_id(),
                                            handle.local_addr(),
                                        );
                                        send_back = Some(*actor_id);
                                    }
                                    Err(err) => {
                                        error!(
                                            "[Supervisor] failed to unsubscribe from actor {}-{}: {:?}",
                                            handle.actor_id(),
                                            handle.local_addr(),
                                            err
                                        )
                                    }
                                }
                            }
                        }
                        if let Err(err) = tx.send(send_back).await {
                            error!(
                                "[Supervisor] failed to reply to actor {}-{}: {:?}",
                                handle.actor_id(),
                                handle.local_addr(),
                                err
                            )
                        }
                    }
                }
                SupervisorCommand::Shutdown(tx) => {
                    info!("[Supervisor] received shutdown command, shutting down all actors");
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
        join_handles: Vec<JoinHandle<Result<(ActorId, SocketAddr), UdpNotifActorError>>>,
        rx: mpsc::Receiver<SupervisorCommand>,
    ) {
        tokio::select! {
            biased;
            _ = self.cmd(rx) => {
            }
            _ = Self::join_actors(join_handles) => {
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum UdpNotifSupervisorHandleError {
    #[strum(to_string = "error sending command to supervisor")]
    SendError,
    #[strum(to_string = "error receiving response from supervisor")]
    ReceiveError,
}

impl std::error::Error for UdpNotifSupervisorHandleError {
    fn description(&self) -> &str {
        match *self {
            Self::SendError => "error sending command to supervisor",
            Self::ReceiveError => "error receiving response from supervisor",
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

/// Handle to interact with the `UdpNotifSupervisor`
#[derive(Debug, Clone)]
pub struct UdpNotifSupervisorHandle {
    cmd_tx: mpsc::Sender<SupervisorCommand>,
    cmd_buffer_size: usize,
}

impl UdpNotifSupervisorHandle {
    pub async fn new(
        config: SupervisorConfig,
        meter: opentelemetry::metrics::Meter,
    ) -> (JoinHandle<()>, UdpNotifSupervisorHandle) {
        let mut next_actor_id = 0;
        let mut actor_handlers = HashMap::new();
        let mut actors_join = vec![];
        let stats = UdpNotifCollectorStats::new(meter);
        for binding_address in config.binding_addresses {
            for _ in 0..binding_address.num_workers {
                info!(
                    "[Supervisor] starting actor {} listening on socket: {}",
                    next_actor_id, binding_address.socket_addr
                );
                let actor_ret = ActorHandle::new(
                    next_actor_id,
                    binding_address.socket_addr,
                    binding_address.interface.clone(),
                    10,
                    config.subscriber_timeout,
                    either::Either::Right(stats.clone()),
                )
                .await;
                match actor_ret {
                    Err(err) => {
                        error!("[Supervisor] failed to start actor: {:?}", err);
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
        let supervisor = UdpNotifSupervisor::new(actor_handlers);
        let handle = UdpNotifSupervisorHandle {
            cmd_tx: tx.clone(),
            cmd_buffer_size: config.cmd_buffer_size,
        };

        let join_handle = tokio::spawn(async move { supervisor.run(actors_join, rx).await });
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), UdpNotifSupervisorHandleError> {
        trace!("[Supervisor] sending shutdown message to supervisor");
        let (tx, rx) = oneshot::channel();
        if let Err(err) = self.cmd_tx.send(SupervisorCommand::Shutdown(tx)).await {
            error!("[Supervisor] error sending shutdown: {:?}", err);
            return Err(UdpNotifSupervisorHandleError::SendError);
        }
        rx.await
            .map_err(|_| UdpNotifSupervisorHandleError::ReceiveError)
    }

    pub async fn subscribe(
        &self,
        buffer_size: usize,
    ) -> Result<(UdpNotifReceiver, Vec<Subscription>), UdpNotifSupervisorHandleError> {
        trace!("[Supervisor] sending subscribe request to supervisor");
        let (pkt_tx, pkt_rx) = create_udp_notif_channel(buffer_size);
        let subscriptions = self.subscribe_tx(pkt_tx).await?;
        Ok((pkt_rx, subscriptions))
    }

    pub async fn subscribe_tx(
        &self,
        pkt_tx: UdpNotifSender,
    ) -> Result<Vec<Subscription>, UdpNotifSupervisorHandleError> {
        trace!("[Supervisor] sending subscribe request with pre-created channel to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::ActorCommand(ActorCommand::Subscribe(
                tx, pkt_tx,
            )))
            .await
        {
            error!("[Supervisor] error sending subscribe request: {:?}", err);
            return Err(UdpNotifSupervisorHandleError::SendError);
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
    ) -> Result<Vec<Option<ActorId>>, UdpNotifSupervisorHandleError> {
        trace!("[Supervisor] sending unsubscribe request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::Unsubscribe(subscriptions, tx))
            .await
        {
            error!("[Supervisor] error sending unsubscribe request: {:?}", err);
            return Err(UdpNotifSupervisorHandleError::SendError);
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
    ) -> Result<Vec<SocketAddr>, UdpNotifSupervisorHandleError> {
        trace!("[Supervisor] sending purge unused peers request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::ActorCommand(
                ActorCommand::PurgeUnusedPeers(duration, tx),
            ))
            .await
        {
            error!(
                "[Supervisor] error sending purge unused peers request: {:?}",
                err
            );
            return Err(UdpNotifSupervisorHandleError::SendError);
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
    ) -> Result<Vec<Option<ActorId>>, UdpNotifSupervisorHandleError> {
        trace!(
            "[Supervisor] sending purge request for peer {} to supervisor",
            peer
        );
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::ActorCommand(ActorCommand::PurgePeer(
                peer, tx,
            )))
            .await
        {
            error!(
                "[Supervisor] error sending purge request for peer {}: {:?}",
                peer, err
            );
            return Err(UdpNotifSupervisorHandleError::SendError);
        }
        let mut purged_peers = vec![];
        while let Some(ret) = rx.recv().await {
            purged_peers.push(ret);
        }
        Ok(purged_peers)
    }

    /// Get local addresses that the udp-notif actors are listening on.
    pub async fn local_addresses(
        &self,
    ) -> Result<Vec<(ActorId, SocketAddr)>, UdpNotifSupervisorHandleError> {
        trace!("[Supervisor] sending get local addresses request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::ActorCommand(ActorCommand::LocalAddr(tx)))
            .await
        {
            error!(
                "[Supervisor] error sending get local addresses request: {:?}",
                err
            );
            return Err(UdpNotifSupervisorHandleError::SendError);
        }
        let mut local = vec![];
        while let Some(ret) = rx.recv().await {
            local.push(ret);
        }
        Ok(local)
    }

    pub async fn get_peers(
        &self,
    ) -> Result<Vec<(ActorId, Vec<SocketAddr>)>, UdpNotifSupervisorHandleError> {
        trace!("[Supervisor] sending get peers request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::ActorCommand(ActorCommand::GetPeers(tx)))
            .await
        {
            error!("[Supervisor] error sending get peers request: {:?}", err);
            return Err(UdpNotifSupervisorHandleError::SendError);
        }
        let mut peers = vec![];
        while let Some(ret) = rx.recv().await {
            peers.push(ret);
        }
        Ok(peers)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;
    use bytes::{Buf, Bytes, BytesMut};
    use netgauze_parse_utils::WritablePdu;
    use netgauze_udp_notif_pkt::{MediaType, UdpNotifPacket};
    use std::io::Cursor;
    use tokio::{
        net::UdpSocket,
        time::{timeout, Duration},
    };

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

    fn generate_udp_notif_data(payload: Bytes) -> BytesMut {
        // Create udp-notif test data
        let pkt = UdpNotifPacket::new(MediaType::YangDataJson, 1, 1, HashMap::new(), payload);
        let mut vec: Vec<u8> = vec![];
        let mut cursor = Cursor::new(&mut vec);
        pkt.write(&mut cursor)
            .expect("failed to serialize udp-notif data");
        let buf = Bytes::from(vec);
        buf.into()
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_supervisor_create() {
        let config = create_test_config();
        let meter = opentelemetry::global::meter("test-meter");
        let (join_handle, handle) = UdpNotifSupervisorHandle::new(config, meter).await;

        assert!(!join_handle.is_finished());

        // Shutdown the supervisor
        handle
            .shutdown()
            .await
            .expect("failed to shutdown supervisor");

        // Wait for the join handle to complete
        timeout(Duration::from_secs(5), join_handle)
            .await
            .expect("supervisor didn't shut down in time")
            .expect("supervisor panicked");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_supervisor_subscribe_unsubscribe() {
        let config = create_test_config();
        let meter = opentelemetry::global::meter("test-meter");
        let (_join_handle, handle) = UdpNotifSupervisorHandle::new(config, meter).await;

        // Subscribe
        let (pkt_rx, subscriptions) = handle.subscribe(10).await.expect("failed to subscribe");
        assert_eq!(subscriptions.len(), 3); // 2 + 1 workers from our config

        // Unsubscribe
        let unsubscribe_results = handle
            .unsubscribe(subscriptions)
            .await
            .expect("failed to unsubscribe");
        assert_eq!(unsubscribe_results.len(), 3);
        assert!(unsubscribe_results.iter().all(|r| r.is_some()));
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Try to receive a message (should return None as we've unsubscribed)
        let timeout_result = timeout(Duration::from_secs(1), pkt_rx.recv()).await;
        assert!(matches!(timeout_result, Ok(Err(_))));

        handle
            .shutdown()
            .await
            .expect("failed to shutdown supervisor");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_supervisor_purge_unused_peers() {
        let config = create_test_config();
        let meter = opentelemetry::global::meter("test-meter");
        let (_join_handle, handle) = UdpNotifSupervisorHandle::new(config, meter).await;

        // Purge unused peers (should be none at this point)
        let purged_peers = handle
            .purge_unused_peers(Duration::from_secs(60))
            .await
            .expect("failed to purge unused peers");
        assert!(purged_peers.is_empty());

        let local_addrs = handle
            .local_addresses()
            .await
            .expect("failed to get local addresses");

        let mut peers = vec![];
        for addr in local_addrs {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = socket
                .local_addr()
                .expect("couldn't get local address of a test client");
            peers.push(peer);
            let mut buf = generate_udp_notif_data(Bytes::from_static(b"test data"));
            send_data(addr.1, &socket, &mut buf).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let purged_peers = handle
            .purge_unused_peers(Duration::from_millis(100))
            .await
            .expect("failed to purge unused peers");
        assert!(purged_peers.is_empty());

        tokio::time::sleep(Duration::from_millis(200)).await;
        let purged_peers = handle
            .purge_unused_peers(Duration::from_millis(100))
            .await
            .expect("failed to purge unused peers");
        assert_eq!(
            HashSet::<SocketAddr>::from_iter(purged_peers.into_iter()),
            HashSet::from_iter(peers.into_iter())
        );

        handle
            .shutdown()
            .await
            .expect("failed to shutdown supervisor");
    }
}
