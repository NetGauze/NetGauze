// Copyright (C) 2026-present The NetGauze Authors.
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

//! # BMP Supervisor Module
//!
//! This module implements a supervisor that manages multiple `BmpActor`
//! instances. It utilizes the actor model to provide a scalable and
//! fault-tolerant system for collecting and processing BMP data.
//!
//! ## Actor Model Implementation
//!
//! The module uses the actor model in the following ways:
//!
//! 1. **Supervisor**: The `BmpSupervisor` acts as a supervisor, managing
//!    multiple `BmpActor` instances.
//! 2. **Message Passing**: Communication between the supervisor and its child
//!    actors is done through asynchronous message passing.
//! 3. **Encapsulation**: Each actor (supervisor and children) encapsulates its
//!    own state and behavior.
//! 4. **Concurrency**: Multiple `BmpActor` instances can run concurrently, each
//!    handling its own TCP listener.
//!
//! ## Key Components
//!
//! ### [SupervisorConfig]
//!
//! Defines the configuration for the supervisor, including binding addresses
//! and the number of workers for each address.
//!
//! ### A private BmpSupervisor
//!
//! The main supervisor that manages multiple `BmpActor` instances.
//! It handles commands and broadcasts them to child actors, and manages
//! the lifecycle of child actors.
//!
//! ### [BmpSupervisorHandle]
//!
//! Provides a public interface for interacting with the supervisor. It allows
//! clients to send commands and receive responses from the supervisor.
//!
//! ## Fault Tolerance and Scaling
//!
//! - The supervisor can manage multiple `BmpActor` instances, allowing for
//!   horizontal scaling.
//! - If a child actor fails, the supervisor can detect this and potentially
//!   restart it (though this is not currently implemented).
//! - The supervisor provides a centralized point for managing and interacting
//!   with multiple BMP collectors.

use crate::actor::{BmpActorCommand, BmpActorError, BmpActorHandle, BmpActorStats};
use crate::{ActorId, BmpReceiver, BmpSender, SubscriberId, Subscription, create_bmp_channel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
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

    // TODO: rename to num_listeners or something more meaningful?
    // TODO: expose TCP listen backlog parameter?
    /// Number of parallel accept() loops for this socket.
    ///
    /// With SO_REUSEPORT, multiple actors can bind to the same address,
    /// and the kernel load-balances new connections between them.
    ///
    /// **Typical values:**
    /// - `1`: Single accept loop (recommended for most deployments)
    /// - `2-4`: Multiple accept loops for very high connection rates
    ///
    /// **Note:** This does NOT limit concurrent connections. Each actor spawns
    /// a separate task per connection, so actual concurrency = num_listeners ×
    /// connections_per_listener. The TCP socket is configured to listen with
    /// backlog=1024, so if more is needed consider adding workers.
    #[serde(default = "default_num_workers")]
    pub num_workers: usize,

    /// Optional network interface or VRF to bind to
    pub interface: Option<String>,
}

fn default_num_workers() -> usize {
    1
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            binding_addresses: vec![BindingAddress {
                socket_addr: SocketAddr::from_str("[::]:1790").unwrap(),
                num_workers: 1,
                interface: None,
            }],
            cmd_buffer_size: 100,
            subscriber_timeout: Duration::from_secs(1),
        }
    }
}

/// The command used to interact with the `BmpSupervisor`
#[derive(Debug, strum_macros::Display)]
enum SupervisorCommand {
    /// Command to send to all [BmpActor]
    BmpActorCommand(BmpActorCommand),
    /// Command to unsubscribe
    Unsubscribe(Vec<Subscription>, mpsc::Sender<Option<ActorId>>),
    /// Shutdown the supervisor and all its managed actors
    Shutdown(oneshot::Sender<()>),
}

/// The supervisor actor that manages multiple `BmpActor` instances.
#[derive(Debug)]
struct BmpSupervisor {
    actor_handlers: HashMap<ActorId, BmpActorHandle>,
}

impl BmpSupervisor {
    fn new(actor_handlers: HashMap<ActorId, BmpActorHandle>) -> Self {
        Self { actor_handlers }
    }

    /// Wait for all [BmpActor]s to finish
    async fn join_actors(
        join_handles: Vec<JoinHandle<Result<(ActorId, SocketAddr), BmpActorError>>>,
    ) {
        let mut join_handles = join_handles;
        loop {
            let awaited = futures::future::select_all(join_handles);
            join_handles = match awaited.await {
                (Ok(ret), _, rest) => {
                    // TODO(AH): Have some policy to allow to restart actors or terminate supervisor
                    //           if failed
                    if let Err(err) = ret {
                        error!(error = %err, "Actor terminated with error");
                    }
                    if rest.is_empty() {
                        info!("No more active actors, shutting down");
                        break;
                    }
                    rest
                }
                (Err(err), _, rest) => {
                    // AH: if we did our job correctly, this should never happen
                    error!(error = ?err, "Unrecoverable error in worker");
                    if rest.is_empty() {
                        info!(
                            "Supervisor is shutting down, no remaining workers are still running"
                        );
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
                SupervisorCommand::BmpActorCommand(actor_cmd) => {
                    debug!(
                        count = self.actor_handlers.len(),
                        command = %actor_cmd,
                        "Broadcasting command to actors"
                    );
                    for handle in self.actor_handlers.values() {
                        if let Err(_err) = handle.cmd_tx.send(actor_cmd.clone()).await {
                            error!(
                                actor_id = handle.actor_id(),
                                local_addr = %handle.local_addr(),
                                "Failed to send command to Actor"
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
                                            actor_id = handle.actor_id(),
                                            local_addr = %handle.local_addr(),
                                            "Unsubscribed from actor"
                                        );
                                        send_back = Some(*actor_id);
                                    }
                                    Err(err) => {
                                        error!(
                                            actor_id = handle.actor_id(),
                                            local_addr = %handle.local_addr(),
                                            error = ?err,
                                            "Failed to send command to Actor"
                                        )
                                    }
                                }
                            }
                        }
                        if let Err(err) = tx.send(send_back).await {
                            error!(
                                actor_id = handle.actor_id(),
                                local_addr = %handle.local_addr(),
                                error = ?err,
                                "Failed to send back the results unsubscribe command from Actor"
                            )
                        }
                    }
                }
                SupervisorCommand::Shutdown(tx) => {
                    info!("Received shutdown command, shutting down all actors");
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
        join_handles: Vec<JoinHandle<Result<(ActorId, SocketAddr), BmpActorError>>>,
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
pub enum BmpSupervisorHandleError {
    #[strum(to_string = "No BMP actor started successfully")]
    NoListenerStarted,
    #[strum(to_string = "Error sending command to supervisor actor")]
    SendError,
    #[strum(to_string = "Error receiving response from supervisor actor")]
    ReceiveError,
}

impl std::error::Error for BmpSupervisorHandleError {}

/// Handle to interact with the `BmpSupervisor`
#[derive(Debug, Clone)]
pub struct BmpSupervisorHandle {
    cmd_tx: mpsc::Sender<SupervisorCommand>,
    cmd_buffer_size: usize,
}

impl BmpSupervisorHandle {
    pub fn new(
        config: SupervisorConfig,
        meter: opentelemetry::metrics::Meter,
    ) -> Result<(JoinHandle<()>, BmpSupervisorHandle), BmpSupervisorHandleError> {
        let mut next_actor_id = 0;
        let mut actor_handlers = HashMap::new();
        let mut actors_join = vec![];
        let stats = BmpActorStats::new(meter);
        for binding_address in config.binding_addresses {
            for _ in 0..binding_address.num_workers {
                info!(
                    actor_id = next_actor_id,
                    socket_addr = %binding_address.socket_addr,
                    "Starting actor listening on socket"
                );
                let actor_ret = BmpActorHandle::new(
                    next_actor_id,
                    binding_address.socket_addr,
                    binding_address.interface.clone(),
                    10,
                    config.subscriber_timeout,
                    either::Either::Right(stats.clone()),
                );
                match actor_ret {
                    Err(err) => {
                        error!(error = ?err, "Failed to start actor");
                    }
                    Ok((join_handle, actor_handle)) => {
                        actor_handlers.insert(next_actor_id, actor_handle);
                        actors_join.push(join_handle);
                        next_actor_id += 1;
                    }
                }
            }
        }
        if actors_join.is_empty() {
            error!("There are no actors to run, shutting down");
            return Err(BmpSupervisorHandleError::NoListenerStarted);
        }
        let (tx, rx) = mpsc::channel(100);
        let supervisor = BmpSupervisor::new(actor_handlers);
        let handle = BmpSupervisorHandle {
            cmd_tx: tx.clone(),
            cmd_buffer_size: config.cmd_buffer_size,
        };

        let join_handle = tokio::spawn(async move { supervisor.run(actors_join, rx).await });
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), BmpSupervisorHandleError> {
        trace!("Sending shutting down message to supervisor");
        let (tx, rx) = oneshot::channel();
        if let Err(err) = self.cmd_tx.send(SupervisorCommand::Shutdown(tx)).await {
            error!(error = ?err, "Error sending shutdown");
            return Err(BmpSupervisorHandleError::SendError);
        }
        rx.await.map_err(|_| BmpSupervisorHandleError::ReceiveError)
    }

    pub async fn subscribe(
        &self,
        buffer_size: usize,
    ) -> Result<(BmpReceiver, Vec<Subscription>), BmpSupervisorHandleError> {
        trace!(
            buffer_size,
            "Sending new subscription request to supervisor"
        );
        let (pkt_tx, pkt_rx) = create_bmp_channel(buffer_size);
        let subscriptions = self.subscribe_tx(pkt_tx).await?;
        Ok((pkt_rx, subscriptions))
    }

    pub async fn subscribe_shards(
        &self,
        num_workers: usize,
        buffer_size: usize,
    ) -> Result<(Vec<BmpReceiver>, Vec<Subscription>), BmpSupervisorHandleError> {
        trace!(
            num_workers,
            buffer_size, "Sending new subscription request to supervisor"
        );
        let mut pkt_tx = Vec::with_capacity(num_workers);
        let mut pkt_rx = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let (tx, rx) = create_bmp_channel(buffer_size);
            pkt_tx.push(tx);
            pkt_rx.push(rx);
        }
        let subscriptions = self.subscribe_shards_tx(pkt_tx).await?;
        Ok((pkt_rx, subscriptions))
    }

    pub async fn subscribe_tx(
        &self,
        pkt_tx: BmpSender,
    ) -> Result<Vec<Subscription>, BmpSupervisorHandleError> {
        trace!("Sending new subscription with pre-created channel request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::BmpActorCommand(
                BmpActorCommand::Subscribe(tx, vec![pkt_tx]),
            ))
            .await
        {
            error!(error = ?err, "Error sending subscription request");
            return Err(BmpSupervisorHandleError::SendError);
        }
        let mut subscriptions = vec![];
        while let Some(subscription) = rx.recv().await {
            subscriptions.push(subscription);
        }
        Ok(subscriptions)
    }

    pub async fn subscribe_shards_tx(
        &self,
        pkt_tx: Vec<BmpSender>,
    ) -> Result<Vec<Subscription>, BmpSupervisorHandleError> {
        trace!("Sending new subscription with pre-created sharded channels request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::BmpActorCommand(
                BmpActorCommand::Subscribe(tx, pkt_tx),
            ))
            .await
        {
            error!(error = ?err, "Error sending subscription request");
            return Err(BmpSupervisorHandleError::SendError);
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
    ) -> Result<Vec<Option<ActorId>>, BmpSupervisorHandleError> {
        trace!("Sending unsubscribe request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::Unsubscribe(subscriptions, tx))
            .await
        {
            error!(error = ?err, "Error sending unsubscribe request");
            return Err(BmpSupervisorHandleError::SendError);
        }
        let mut results = vec![];
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        Ok(results)
    }

    /// Disconnect a specific peer by remote address from all actors.
    /// Returns a list of (actor_id, was_disconnected) for each actor.
    pub async fn disconnect_peer(
        &self,
        addr: SocketAddr,
    ) -> Result<Vec<(ActorId, bool)>, BmpSupervisorHandleError> {
        trace!(
            peer_addr = %addr,
            "Sending disconnect peer request to supervisor"
        );
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::BmpActorCommand(
                BmpActorCommand::DisconnectPeer(addr, tx),
            ))
            .await
        {
            error!(
                peer_addr = %addr,
                error = ?err,
                "Error sending disconnect peer request"
            );
            return Err(BmpSupervisorHandleError::SendError);
        }
        let mut results = vec![];
        while let Some((actor_id, disconnected)) = rx.recv().await {
            results.push((actor_id, disconnected));
        }
        Ok(results)
    }

    pub async fn local_addresses(
        &self,
    ) -> Result<Vec<(ActorId, SocketAddr)>, BmpSupervisorHandleError> {
        trace!("Sending local addresses request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::BmpActorCommand(
                BmpActorCommand::LocalAddr(tx),
            ))
            .await
        {
            error!(error = ?err, "Error sending local addresses request");
            return Err(BmpSupervisorHandleError::SendError);
        }
        let mut results = vec![];
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        Ok(results)
    }

    /// Get list of currently connected peers from all actors.
    pub async fn get_connected_peers(
        &self,
    ) -> Result<Vec<(ActorId, Vec<SocketAddr>)>, BmpSupervisorHandleError> {
        trace!("Sending get connected peers request to supervisor");
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        if let Err(err) = self
            .cmd_tx
            .send(SupervisorCommand::BmpActorCommand(
                BmpActorCommand::GetConnectedPeers(tx),
            ))
            .await
        {
            error!(error = ?err, "Error sending get connected peers request");
            return Err(BmpSupervisorHandleError::SendError);
        }
        let mut results = vec![];
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests;
