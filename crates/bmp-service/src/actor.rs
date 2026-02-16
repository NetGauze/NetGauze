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

//! # BMP Actor Module
//!
//! This module implements the `BmpActor`, which uses the actor
//! model to handle concurrent reception and processing of BMP messages over
//! TCP.
//!
//! ## Actor Model in BmpActor
//!
//! The actor model is a conceptual model for concurrent computation. In this
//! implementation:
//!
//! 1. The `BmpActor` is an independent unit of computation (an actor).
//! 2. It maintains its own state (subscriptions, connection info, etc.) which
//!    is not directly accessible from outside.
//! 3. It communicates with the outside world exclusively through message
//!    passing.
//!
//! ### Key Characteristics
//!
//! - **Encapsulation**: The actor encapsulates its state and behavior. External
//!   entities can't directly modify its internal state.
//! - **Message-Driven**: All interactions with the actor are done through
//!   asynchronous messages (commands).
//! - **Concurrency**: Multiple actors can run concurrently without explicit
//!   locking mechanisms.
//!
//! ### Actor Communication
//!
//! The `BmpActor` communicates through two main channels:
//!
//! 1. **Command Channel**: Receives `BmpActorCommand` messages to control the
//!    actor's behavior.
//! 2. **TCP Listener**: Accepts BMP connections from the network.
//!
//! ### Actor Lifecycle
//!
//! 1. **Creation**: The actor is created and started when
//!    [BmpActorHandle::new()] is called.
//! 2. **Running**: The actor processes incoming TCP connections and commands in
//!    its `run()` method.
//! 3. **Shutdown**: The actor can be gracefully shut down using the `Shutdown`
//!    command.
//!
//! ## TCP Connection Management
//!
//! The actor:
//! - Tracks active connections automatically
//! - Cleans up when connections close
//! - Provides methods to query active peers and disconnect them

use crate::{
    ActorId, AddrInfo, BmpReceiver, BmpSender, SubscriberId, Subscription, create_bmp_channel,
    new_tcp_reuse_port,
};
use futures_util::StreamExt;
use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmp_pkt::codec::{BmpCodec, BmpCodecDecoderError};
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, trace, warn};

/// Commands that can be sent to the [BmpActor].
#[derive(Debug, Clone, strum_macros::Display)]
pub(crate) enum BmpActorCommand {
    /// Command to shut down the actor.
    Shutdown(mpsc::Sender<ActorId>),

    /// Command to subscribe to BMP messages.
    /// Use multiple-senders for sharding by remote address
    Subscribe(mpsc::Sender<Subscription>, Vec<BmpSender>),

    /// Command to unsubscribe a previously registered subscriber.
    Unsubscribe(SubscriberId, mpsc::Sender<Option<Subscription>>),

    /// Disconnect a specific peer by its remote address
    DisconnectPeer(SocketAddr, mpsc::Sender<(ActorId, bool)>),

    /// Get the local address the actor is bound to.
    LocalAddr(mpsc::Sender<(ActorId, SocketAddr)>),

    /// Get list of currently connected peers
    GetConnectedPeers(mpsc::Sender<(ActorId, Vec<SocketAddr>)>),
}

/// Errors that can occur in the `BmpActor`.
#[derive(Debug, strum_macros::Display)]
pub enum BmpActorError {
    #[strum(to_string = "[Actor {0}-{1}] failed to bind to socket address {1}: {2}")]
    SocketBindError(ActorId, SocketAddr, std::io::Error),

    #[strum(to_string = "[Actor {0}-{1}] failed to get local address: {2}")]
    GetLocalAddressError(ActorId, SocketAddr, std::io::Error),

    #[strum(to_string = "[Actor {0}-{1}] command channel closed")]
    CommandChannelClosed(ActorId, SocketAddr),

    #[strum(to_string = "[Actor {0}-{1}] unrecoverable error accepting connection: {2}")]
    AcceptError(ActorId, SocketAddr, std::io::Error),
}

impl std::error::Error for BmpActorError {}

/// Statistics for the BMP Actor.
#[derive(Debug, Clone)]
pub struct BmpActorStats {
    pub received_messages: opentelemetry::metrics::Counter<u64>,
    pub active_connections: opentelemetry::metrics::Gauge<u64>,
    pub connections_accepted: opentelemetry::metrics::Counter<u64>,
    pub connections_closed: opentelemetry::metrics::Counter<u64>,
    pub decoder_errors: opentelemetry::metrics::Counter<u64>,
    pub subscribers: opentelemetry::metrics::Gauge<u64>,
    pub subscriber_sent: opentelemetry::metrics::Counter<u64>,
    pub subscriber_dropped: opentelemetry::metrics::Counter<u64>,
    pub connection_closed_notification_dropped: opentelemetry::metrics::Counter<u64>,
}

impl BmpActorStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        Self {
            received_messages: meter
                .u64_counter("netgauze.bmp.decoder.received.messages")
                .with_description("Total number of BMP messages received")
                .build(),
            active_connections: meter
                .u64_gauge("netgauze.bmp.active.connections")
                .with_description("Number of active BMP connections")
                .build(),
            connections_accepted: meter
                .u64_counter("netgauze.bmp.connections.accepted")
                .with_description("Total number of accepted BMP connections")
                .build(),
            connections_closed: meter
                .u64_counter("netgauze.bmp.connections.closed")
                .with_description("Total number of closed BMP connections")
                .build(),
            decoder_errors: meter
                .u64_counter("netgauze.bmp.decoder.errors")
                .with_description("Total number of decoder errors")
                .build(),
            subscribers: meter
                .u64_gauge("netgauze.bmp.subscribers")
                .with_description("Number of active subscribers")
                .build(),
            subscriber_sent: meter
                .u64_counter("netgauze.bmp.subscriber.sent")
                .with_description("Total number of messages sent to subscribers")
                .build(),
            subscriber_dropped: meter
                .u64_counter("netgauze.bmp.subscriber.dropped")
                .with_description("Total number of messages dropped due to channel full or error")
                .build(),
            connection_closed_notification_dropped: meter
                .u64_counter("netgauze.bmp.connections.closed.notification.dropped")
                .with_description(
                    "Total number of dropped connection closed notifications due to full channel",
                )
                .build(),
        }
    }
}

/// The main actor responsible for receiving and processing BMP messages.
struct BmpActor {
    /// Unique identifier for this actor instance.
    actor_id: ActorId,

    /// Local address the actor is bound to.
    local_addr: SocketAddr,

    /// TCP listener for incoming BMP connections.
    listener: TcpListener,

    /// Receiver for commands sent to the actor.
    cmd_rx: mpsc::Receiver<BmpActorCommand>,

    /// Counter for generating unique subscriber IDs.
    next_subscriber_id: SubscriberId,

    /// Map of active subscribers and their sender channels.
    subscribers: Arc<HashMap<SubscriberId, Vec<BmpSender>>>,

    /// Broadcast channel to notify connection tasks of subscriber changes
    subscribers_tx: broadcast::Sender<Arc<HashMap<SubscriberId, Vec<BmpSender>>>>,

    /// Timeout for sending a BMP message to a subscriber before dropping it.
    subscriber_timeout: Duration,

    /// Track active async tasks for open TCP connections
    connection_tasks: HashMap<SocketAddr, JoinHandle<()>>,

    /// Channel to receive notifications when connections close
    connection_closed_rx: mpsc::Receiver<SocketAddr>,

    /// Sender handle for connection closed notifications (passed to tasks)
    connection_closed_tx: mpsc::Sender<SocketAddr>,

    stats: BmpActorStats,
}

impl BmpActor {
    fn new(
        actor_id: ActorId,
        local_addr: SocketAddr,
        listener: TcpListener,
        cmd_rx: mpsc::Receiver<BmpActorCommand>,
        subscriber_timeout: Duration,
        stats: BmpActorStats,
    ) -> Self {
        let (subscribers_tx, _) = broadcast::channel(1); // only keep latest subscriber map
        let (connection_closed_tx, connection_closed_rx) = mpsc::channel(1000);
        Self {
            actor_id,
            local_addr,
            listener,
            cmd_rx,
            next_subscriber_id: 0,
            subscribers: Arc::new(HashMap::new()),
            subscribers_tx,
            subscriber_timeout,
            connection_tasks: HashMap::new(),
            connection_closed_rx,
            connection_closed_tx,
            stats,
        }
    }

    /// Helper to generate OpenTelemetry tags for metrics.
    fn get_tags(
        actor_id: ActorId,
        local_addr: &SocketAddr,
        remote_addr: Option<&SocketAddr>,
    ) -> Vec<KeyValue> {
        let mut tags = vec![
            KeyValue::new("actor.id", actor_id.to_string()),
            KeyValue::new("network.local.address", local_addr.to_string()),
        ];
        if let Some(remote) = remote_addr {
            tags.push(KeyValue::new("network.peer.address", remote.to_string()));
        }
        tags
    }

    /// Handle command from the actor handle.
    /// Returns Some(tx) if shutdown was requested, None otherwise.
    fn handle_command(&mut self, cmd: BmpActorCommand) -> Option<mpsc::Sender<ActorId>> {
        match cmd {
            BmpActorCommand::Shutdown(tx) => {
                info!(
                    actor_id = %self.actor_id,
                    local_addr = %self.local_addr,
                    "Received shutdown command"
                );
                // Abort all connection tasks on shutdown
                for (addr, task) in self.connection_tasks.drain() {
                    debug!(
                        actor_id = %self.actor_id,
                        local_addr = %self.local_addr,
                        peer_addr = %addr,
                        "Aborting connection task for shutdown"
                    );
                    task.abort();
                }
                return Some(tx);
            }

            BmpActorCommand::Subscribe(tx, senders) => {
                self.handle_subscribe(tx, senders);
            }
            BmpActorCommand::Unsubscribe(subscriber_id, tx) => {
                self.handle_unsubscribe(subscriber_id, tx);
            }
            BmpActorCommand::LocalAddr(tx) => {
                let _ = tx.try_send((self.actor_id, self.local_addr));
            }
            BmpActorCommand::DisconnectPeer(addr, tx) => {
                self.handle_disconnect_peer(addr, tx);
            }
            BmpActorCommand::GetConnectedPeers(tx) => {
                let peers: Vec<SocketAddr> = self.connection_tasks.keys().copied().collect();
                debug!(
                    actor_id = %self.actor_id,
                    local_addr = %self.local_addr,
                    connected_peers_count = %peers.len(),
                    "GetConnectedPeers: responding with peers list"
                );
                let _ = tx.try_send((self.actor_id, peers));
            }
        }
        None
    }

    /// Register a new subscriber and update the subscription map.
    fn handle_subscribe(&mut self, tx: mpsc::Sender<Subscription>, senders: Vec<BmpSender>) {
        let subscriber_id = self.next_subscriber_id;
        self.next_subscriber_id += 1;

        // Clone, update and create new subscriber map
        let mut new_subscribers = (*self.subscribers).clone();
        new_subscribers.insert(subscriber_id, senders);
        self.subscribers = Arc::new(new_subscribers);

        // Broadcast updated subscribers to all connections tasks
        if let Err(e) = self.subscribers_tx.send(self.subscribers.clone()) {
            // This only happens if there are no active receivers (connection tasks), which
            // is fine
            debug!(
                actor_id = %self.actor_id,
                local_addr = %self.local_addr,
                error = %e,
                "No active connections to notify of new subscriber"
            );
        }
        self.stats.subscribers.record(
            self.subscribers.len() as u64,
            &Self::get_tags(self.actor_id, &self.local_addr, None),
        );

        let subscription = Subscription {
            actor_id: self.actor_id,
            id: subscriber_id,
        };
        debug!(
            actor_id = %self.actor_id,
            local_addr = %self.local_addr,
            subscriber_id = %subscription.id,
            total_subscribers = %self.subscribers.len(),
            "New subscriber registered"
        );
        let _ = tx.try_send(subscription);
    }

    /// Remove a subscriber and update the subscription map.
    fn handle_unsubscribe(
        &mut self,
        subscriber_id: SubscriberId,
        tx: mpsc::Sender<Option<Subscription>>,
    ) {
        // Clone, update and create new subscriber map
        let mut new_subscribers = (*self.subscribers).clone();
        let removed = new_subscribers.remove(&subscriber_id);
        self.subscribers = Arc::new(new_subscribers);

        // Broadcast updated subscribers to all connections tasks
        if let Err(e) = self.subscribers_tx.send(self.subscribers.clone()) {
            // This only happens if there are no active receivers (connection tasks), which
            // is fine
            debug!(
                actor_id = %self.actor_id,
                local_addr = %self.local_addr,
                error = %e,
                "No active connections to notify of subscriber removal"
            );
        }

        self.stats.subscribers.record(
            self.subscribers.len() as u64,
            &Self::get_tags(self.actor_id, &self.local_addr, None),
        );

        let subscription = removed.map(|_| Subscription {
            actor_id: self.actor_id,
            id: subscriber_id,
        });
        debug!(
            actor_id = %self.actor_id,
            local_addr = %self.local_addr,
            subscriber_id = ?subscriber_id,
            remaining_subscribers = %self.subscribers.len(),
            "Unsubscribed"
        );
        let _ = tx.try_send(subscription);
    }

    /// Disconnects a peer if connected.
    fn handle_disconnect_peer(&mut self, addr: SocketAddr, tx: mpsc::Sender<(ActorId, bool)>) {
        let disconnected = if let Some(task) = self.connection_tasks.remove(&addr) {
            self.stats.active_connections.record(
                self.connection_tasks.len() as u64,
                &Self::get_tags(self.actor_id, &self.local_addr, None),
            );
            self.stats.connections_closed.add(
                1,
                &Self::get_tags(self.actor_id, &self.local_addr, Some(&addr)),
            );

            task.abort();

            info!(
                actor_id = %self.actor_id,
                local_addr = %self.local_addr,
                peer_addr = %addr,
                "Disconnected peer"
            );
            true
        } else {
            warn!(
                actor_id = %self.actor_id,
                local_addr = %self.local_addr,
                peer_addr = %addr,
                "Peer not found for disconnect"
            );
            false
        };
        let _ = tx.try_send((self.actor_id, disconnected));
    }

    /// Send a BMP message to all subscribers.
    /// If there are multiple senders per subscriber, shard by the remote
    /// address hash.
    async fn send_to_subscribers(
        actor_id: ActorId,
        addr_info: AddrInfo,
        msg: BmpMessage,
        subscribers: &HashMap<SubscriberId, Vec<BmpSender>>,
        timeout: Duration,
        stats: &BmpActorStats,
    ) {
        let local_addr = addr_info.local_socket();
        let peer_addr = addr_info.remote_socket();
        let peer_tags = Self::get_tags(actor_id, &local_addr, Some(&peer_addr));
        let request = Arc::new((addr_info, msg));
        for senders in subscribers.values() {
            let sender = if senders.len() == 1 {
                &senders[0]
            } else {
                // Shard by remote address hash
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                addr_info.remote_socket().hash(&mut hasher);
                let index = (hasher.finish() as usize) % senders.len();
                &senders[index]
            };

            match tokio::time::timeout(timeout, sender.send(request.clone())).await {
                Ok(Ok(())) => {
                    trace!(
                        actor_id = %actor_id,
                        local_addr = %local_addr,
                        peer_addr = %peer_addr,
                        "Sent message to subscriber"
                    );
                    stats.subscriber_sent.add(1, &peer_tags);
                }
                Ok(Err(_)) => {
                    debug!(
                        actor_id = %actor_id,
                        local_addr = %local_addr,
                        peer_addr = %peer_addr,
                        "Subscriber channel closed"
                    );
                    stats.subscriber_dropped.add(1, &peer_tags);
                }
                Err(_) => {
                    warn!(
                        actor_id = %actor_id,
                        local_addr = %local_addr,
                        peer_addr = %peer_addr,
                        "Timeout sending to subscriber"
                    );
                    stats.subscriber_dropped.add(1, &peer_tags);
                }
            }
        }
    }

    /// Handle decoding errors for a connection.
    /// Returns `true` if the connection should continue, `false` to close it.
    fn handle_bmp_decoder_error(
        actor_id: ActorId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        err: BmpCodecDecoderError,
        stats: &BmpActorStats,
    ) -> bool {
        let peer_tags = Self::get_tags(actor_id, &local_addr, Some(&remote_addr));
        warn!(
            actor_id = %actor_id,
            local_addr = %local_addr,
            peer_addr = %remote_addr,
            error = ?err,
            "BMP codec decoder error"
        );
        stats.decoder_errors.add(1, &peer_tags);

        // TODO: finalize decision on how to behave with these errors
        //       (recoverable, unrecoverable?)
        match err {
            BmpCodecDecoderError::Incomplete(_) => {
                warn!(
                    actor_id = %actor_id,
                    local_addr = %local_addr,
                    peer_addr = %remote_addr,
                    "Incomplete BMP frame, closing connection"
                );
                false
            }
            BmpCodecDecoderError::BmpMessageParsingError(_) => {
                warn!(
                    actor_id = %actor_id,
                    local_addr = %local_addr,
                    peer_addr = %remote_addr,
                    "BmpMessageParsingError, closing connection"
                );
                false
            }
            BmpCodecDecoderError::IoError(_) => {
                warn!(
                    actor_id = %actor_id,
                    local_addr = %local_addr,
                    peer_addr = %remote_addr,
                    "I/O error, closing connection"
                );
                false
            }
        }
    }

    /// Per-connection handler triggered in a separate task.
    /// Manages the lifecycle of a single TCP connection, decoding messages and
    /// sending them to subscribers.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        actor_id: ActorId,
        addr_info: AddrInfo,
        stream: TcpStream,
        initial_subscribers: Arc<HashMap<SubscriberId, Vec<BmpSender>>>,
        mut subscribers_rx: broadcast::Receiver<Arc<HashMap<SubscriberId, Vec<BmpSender>>>>,
        subscriber_timeout: Duration,
        connection_closed_tx: mpsc::Sender<SocketAddr>,
        stats: BmpActorStats,
    ) {
        let local_addr = addr_info.local_socket();
        let remote_addr = addr_info.remote_socket();

        info!(
            actor_id = %actor_id,
            local_addr = %local_addr,
            peer_addr = %remote_addr,
            "New connection accepted"
        );
        let peer_tags = Self::get_tags(actor_id, &local_addr, Some(&remote_addr));

        let (rx, _tx) = stream.into_split();
        let mut framed = FramedRead::new(rx, BmpCodec::default());

        // Initialize subscribers map
        let mut current_subscribers = initial_subscribers;
        debug!(
            actor_id = %actor_id,
            local_addr = %local_addr,
            peer_addr = %remote_addr,
            subscriber_count = %current_subscribers.len(),
            "Connection initialized with subscribers"
        );

        loop {
            tokio::select! {
                // Check for subscriber updates
                update = subscribers_rx.recv() => {
                    match update {
                        Ok(new_subscribers) => {
                            debug!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                peer_addr = %remote_addr,
                                new_subscriber_count = %new_subscribers.len(),
                                "Connection task received subscriber update"
                            );
                            current_subscribers = new_subscribers;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            // With buffer_size=1, lagging means previous update was overwritten
                            // Next recv() will anyway give us the most up to date subscribers map
                            debug!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                peer_addr = %remote_addr,
                                skipped_updates = %skipped,
                                "Connection lagged updates (will get latest on next recv)"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            warn!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                peer_addr = %remote_addr,
                                "Subscriber broadcast closed"
                            );
                            break;
                        }
                    }
                }

                result = framed.next() => {
                    match result {
                        Some(Ok(msg)) => {
                            trace!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                peer_addr = %remote_addr,
                                "Received BMP message"
                            );
                            stats.received_messages.add(1, &peer_tags);

                            Self::send_to_subscribers(
                                actor_id,
                                addr_info,
                                msg,
                                &current_subscribers,
                                subscriber_timeout,
                                &stats,
                            )
                            .await;
                        }
                        Some(Err(err)) => {
                            if !Self::handle_bmp_decoder_error(
                                actor_id,
                                local_addr,
                                remote_addr,
                                err,
                                &stats,
                            ) {
                                break;
                            }
                        }
                        None => {
                            debug!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                peer_addr = %remote_addr,
                                "Connection closed by peer (EOF, no more frames to decode)"
                            );
                            break;
                        }
                    }
                }
            }
        }

        info!(
            actor_id = %actor_id,
            local_addr = %local_addr,
            peer_addr = %remote_addr,
            "Connection closed"
        );

        // Notify actor that this connection is closed
        match connection_closed_tx.try_send(remote_addr) {
            Ok(_) => {
                debug!(
                    actor_id = %actor_id,
                    local_addr = %local_addr,
                    peer_addr = %remote_addr,
                    "Notified actor of connection closure"
                );
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full - actor is backed up processing closures
                // TODO: consider a periodic sweep task if we observe such warn
                warn!(
                    actor_id = %actor_id,
                    local_addr = %local_addr,
                    peer_addr = %remote_addr,
                    "Connection closure notification channel full"
                );
                stats
                    .connection_closed_notification_dropped
                    .add(1, &peer_tags);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Actor is shutting down - this is expected during shutdown
                debug!(
                    actor_id = %actor_id,
                    local_addr = %local_addr,
                    peer_addr = %remote_addr,
                    "Actor closed, ignoring connection closure notification"
                );
            }
        }
    }

    /// Main run loop for the actor.
    ///
    /// This loop handles:
    /// 1. Commands from the handle (e.g., shutdown, subscribe).
    /// 2. Notifications of closed connections to clean up tasks.
    /// 3. Incoming TCP connections.
    ///
    /// It uses a biased select to prioritize administrative tasks over
    /// accepting new connections.
    async fn run(mut self) -> Result<(ActorId, SocketAddr), BmpActorError> {
        let actor_id = self.actor_id;
        let local_addr = self.local_addr;

        info!(
            actor_id = %actor_id,
            local_addr = %local_addr,
            "Started listening on socket"
        );

        loop {
            tokio::select! {
                biased;

                // Handle commands
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            if let Some(shutdown_tx) = self.handle_command(cmd) {
                                let _ = shutdown_tx.send(actor_id).await;
                                return Ok((actor_id, local_addr));
                            }
                        }
                        None => {
                            error!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                "Command channel closed unexpectedly"
                            );
                            return Err(BmpActorError::CommandChannelClosed(actor_id, local_addr));
                        }
                    }
                }

                // Handle connection closed notifications
                Some(closed_addr) = self.connection_closed_rx.recv() => {
                    // Remove the closed connection from connection_tasks
                    if let Some(_task) = self.connection_tasks.remove(&closed_addr) {
                        self.stats.active_connections.record(
                            self.connection_tasks.len() as u64,
                            &Self::get_tags(actor_id, &local_addr, None),
                        );
                        self.stats.connections_closed.add(
                            1,
                            &Self::get_tags(actor_id, &local_addr, Some(&closed_addr)),
                        );

                        debug!(
                            actor_id = %actor_id,
                            local_addr = %local_addr,
                            peer_addr = %closed_addr,
                            "Cleaned up finished task"
                        );
                    } else {
                        debug!(
                            actor_id = %actor_id,
                            local_addr = %local_addr,
                            peer_addr = %closed_addr,
                            "Close notification arrived after task was already removed"
                        );
                    }
                }

                // TODO: decide how/if to handle aggressive clients (e.g. exp-backoff on collector)
                // Handle new TCP connections and spawn async tasks
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, remote_addr)) => {
                            let addr_info = AddrInfo::new(local_addr, remote_addr);

                            if let Some(old_task) = self.connection_tasks.remove(&remote_addr) {
                                self.stats.active_connections.record(
                                    self.connection_tasks.len() as u64,
                                    &Self::get_tags(actor_id, &local_addr, None),
                                );
                                self.stats.connections_closed.add(
                                    1,
                                    &Self::get_tags(actor_id, &local_addr, Some(&remote_addr)),
                                );

                                warn!(
                                    actor_id = %actor_id,
                                    local_addr = %local_addr,
                                    peer_addr = %remote_addr,
                                    "Replacing existing connection"
                                );
                                old_task.abort();
                            }

                            // Subscribe to broadcast buffer and send current subscription state
                            let subscribers_rx = self.subscribers_tx.subscribe();
                            let initial_subscribers = self.subscribers.clone();

                            // Spawn task to handle BMP session
                            let task = tokio::spawn(Self::handle_connection(
                                actor_id,
                                addr_info,
                                stream,
                                initial_subscribers,
                                subscribers_rx,
                                self.subscriber_timeout,
                                self.connection_closed_tx.clone(),
                                self.stats.clone(),
                            ));

                            // Update stats
                            self.connection_tasks.insert(remote_addr, task);
                            self.stats.active_connections.record(
                                self.connection_tasks.len() as u64,
                                &Self::get_tags(actor_id, &local_addr, None),
                            );
                            self.stats.connections_accepted.add(
                                1,
                                &Self::get_tags(actor_id, &local_addr, Some(&remote_addr)),
                            );

                            debug!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                peer_addr = %remote_addr,
                                active_connections = %self.connection_tasks.len(),
                                "Spawned connection task"
                            );
                        }
                        Err(e) => {
                            error!(
                                actor_id = %actor_id,
                                local_addr = %local_addr,
                                error = %e,
                                "Error accepting connection");
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum BmpActorHandleError {
    #[strum(to_string = "Error sending command to actor")]
    SendError,
    #[strum(to_string = "Error receiving response from actor")]
    ReceiveError,
    #[strum(to_string = "Error binding socket: {0}")]
    SocketBindError(std::io::Error),
    #[strum(to_string = "Error getting local address: {0}")]
    GetLocalAddressError(std::io::Error),
}

impl std::error::Error for BmpActorHandleError {}

/// A handle is the public interface for interacting with a `BmpActor`.
///
/// This handle provides a way to send commands to the actor and receive
/// responses. It encapsulates the communication channels to the actor, adhering
/// to the principle of message-passing in the actor model.
///
/// The handle is cloneable allowing multiple entities to interact with the
/// actor.
#[derive(Debug, Clone)]
pub struct BmpActorHandle {
    actor_id: ActorId,
    local_addr: SocketAddr,
    interface_bind: Option<String>,
    cmd_buffer_size: usize,
    pub(crate) cmd_tx: mpsc::Sender<BmpActorCommand>,
}

pub type BmpActorJoinHandle = JoinHandle<Result<(ActorId, SocketAddr), BmpActorError>>;

impl BmpActorHandle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor_id: ActorId,
        socket_addr: SocketAddr,
        interface_bind: Option<String>,
        cmd_buffer_size: usize,
        subscriber_timeout: Duration,
        stats: either::Either<opentelemetry::metrics::Meter, BmpActorStats>,
    ) -> Result<(BmpActorJoinHandle, Self), BmpActorHandleError> {
        let stats = match stats {
            either::Either::Left(meter) => BmpActorStats::new(meter),
            either::Either::Right(stats) => stats,
        };

        // Create the TCP listener with backlog=1024 (accept queue)
        let listener =
            new_tcp_reuse_port(socket_addr, interface_bind.clone(), 1024).map_err(|e| {
                error!(
                    actor_id = %actor_id,
                    bind_addr = %socket_addr,
                    error = %e,
                    "Failed to bind TCP listener"
                );
                BmpActorHandleError::SocketBindError(e)
            })?;

        let local_addr = listener.local_addr().map_err(|e| {
            error!(
                actor_id = %actor_id,
                bind_addr = %socket_addr,
                error = %e,
                "Failed to get local address"
            );
            BmpActorHandleError::GetLocalAddressError(e)
        })?;

        let (cmd_tx, cmd_rx) = mpsc::channel(cmd_buffer_size);
        let actor = BmpActor::new(
            actor_id,
            local_addr,
            listener,
            cmd_rx,
            subscriber_timeout,
            stats,
        );
        let join_handle = tokio::spawn(actor.run());
        Ok((
            join_handle,
            Self {
                actor_id,
                local_addr,
                interface_bind,
                cmd_buffer_size,
                cmd_tx,
            },
        ))
    }

    /// Get the actor ID.
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the interface name bind.
    pub fn interface_bind(&self) -> Option<&str> {
        self.interface_bind.as_deref()
    }

    /// Subscribe to BMP messages.
    /// Returns a receiver for the messages and a subscription handle.
    pub async fn subscribe(
        &self,
        buffer_size: usize,
    ) -> Result<(BmpReceiver, Subscription), BmpActorHandleError> {
        debug!(
            actor_id = %self.actor_id,
            local_addr = %self.local_addr,
            buffer_size = %buffer_size,
            "Subscribing"
        );
        let (pkt_tx, pkt_rx) = create_bmp_channel(buffer_size);
        let subscription = self.subscribe_tx(pkt_tx).await?;
        Ok((pkt_rx, subscription))
    }

    /// Subscribe to BMP messages with multiple channels (sharding).
    /// Used to distribute load across multiple consumers.
    pub async fn subscribe_shards(
        &self,
        num_shards: usize,
        buffer_size: usize,
    ) -> Result<(Vec<BmpReceiver>, Subscription), BmpActorHandleError> {
        debug!(
            actor_id = %self.actor_id,
            local_addr = %self.local_addr,
            num_shards = %num_shards,
            buffer_size = %buffer_size,
            "Subscribing with shards"
        );
        let mut txs = Vec::with_capacity(num_shards);
        let mut rxs = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            let (tx, rx) = create_bmp_channel(buffer_size);
            txs.push(tx);
            rxs.push(rx);
        }
        let subscription = self.subscribe_shards_tx(txs).await?;
        Ok((rxs, subscription))
    }

    /// Register a pre-created sender for subscription.
    pub async fn subscribe_tx(
        &self,
        pkt_tx: BmpSender,
    ) -> Result<Subscription, BmpActorHandleError> {
        self.subscribe_shards_tx(vec![pkt_tx]).await
    }

    /// Register multiple pre-created senders for sharded subscription.
    pub async fn subscribe_shards_tx(
        &self,
        pkt_txs: Vec<BmpSender>,
    ) -> Result<Subscription, BmpActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(BmpActorCommand::Subscribe(tx, pkt_txs))
            .await
            .map_err(|_| BmpActorHandleError::SendError)?;
        rx.recv().await.ok_or(BmpActorHandleError::ReceiveError)
    }

    /// Unsubscribe a previously registered subscription.
    pub async fn unsubscribe(
        &self,
        subscriber_id: SubscriberId,
    ) -> Result<Option<Subscription>, BmpActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(BmpActorCommand::Unsubscribe(subscriber_id, tx))
            .await
            .map_err(|_| BmpActorHandleError::SendError)?;
        rx.recv().await.ok_or(BmpActorHandleError::ReceiveError)
    }

    pub async fn shutdown(&self) -> Result<Vec<ActorId>, BmpActorHandleError> {
        debug!(
            actor_id = %self.actor_id,
            local_addr = %self.local_addr,
            "Sending shutdown command"
        );
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(BmpActorCommand::Shutdown(tx))
            .await
            .map_err(|_| BmpActorHandleError::SendError)?;
        let mut results = vec![];
        while let Some(actor_id) = rx.recv().await {
            results.push(actor_id);
        }
        Ok(results)
    }

    /// Disconnect a specific peer by remote address.
    /// Returns true if the peer was connected and disconnected, false if not
    /// found.
    pub async fn disconnect_peer(&self, addr: SocketAddr) -> Result<bool, BmpActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(BmpActorCommand::DisconnectPeer(addr, tx))
            .await
            .map_err(|_| BmpActorHandleError::SendError)?;
        rx.recv()
            .await
            .map(|(_, disconnected)| disconnected)
            .ok_or(BmpActorHandleError::ReceiveError)
    }

    /// Get list of currently connected peers.
    pub async fn get_connected_peers(
        &self,
    ) -> Result<(ActorId, Vec<SocketAddr>), BmpActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(BmpActorCommand::GetConnectedPeers(tx))
            .await
            .map_err(|_| BmpActorHandleError::SendError)?;
        rx.recv().await.ok_or(BmpActorHandleError::ReceiveError)
    }
}

#[cfg(test)]
mod tests;
