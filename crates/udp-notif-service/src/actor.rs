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

//! # UdpNotif Actor Module
//!
//! This module implements the `UdpNotifActor`, which uses the actor
//! model to handle concurrent reception and processing of udp-notif packets.
//!
//! ## Actor Model in UdpNotifActor
//!
//! The actor model is a conceptual model for concurrent computation. In this
//! implementation:
//!
//! 1. The `UdpNotifActor` is an independent unit of computation (an actor).
//! 2. It maintains its own state (subscriptions, peer information, etc.) which
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
//! The `UdpNotifActor` communicates through two main channels:
//!
//! 1. **Command Channel**: Receives `ActorCommand` messages to control the
//!    actor's behavior.
//! 2. **UDP Socket**: Receives udp-notif packets from the network.
//!
//! ### Actor Lifecycle
//!
//! 1. **Creation**: The actor is created and started when [ActorHandle::new()]
//!    is called.
//! 2. **Running**: The actor processes incoming UDP packets and commands in its
//!    `run()` method.
//! 3. **Shutdown**: The actor can be gracefully shut down using the `Shutdown`
//!    command.
//!
//! ## Benefits of the Actor Model in this Context
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
//! ## Usage Example
//!
//! ```rust,no_run
//! use netgauze_udp_notif_service::actor::ActorHandle;
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     use std::time::Duration;
//!     let addr: SocketAddr = "127.0.0.1:9995".parse().unwrap();
//!     let interface_bind = None;
//!     let meter = opentelemetry::global::meter("my-library-name");
//!     let (join_handle, actor_handle) = ActorHandle::new(
//!         1,
//!         addr,
//!         interface_bind,
//!         100,
//!         Duration::from_millis(500),
//!         either::Either::Left(meter),
//!     )
//!     .await
//!     .expect("failed to create UdpNotifActor");
//!
//!     // Subscribe to receive udp-notif packets
//!     let (mut packet_rx, _) = actor_handle.subscribe(10).await.unwrap();
//!
//!     // In a real application, you might want to spawn a new task to handle packets
//!     tokio::spawn(async move {
//!         while let Ok(packet) = packet_rx.recv().await {
//!             println!("received packet: {:?}", packet);
//!         }
//!     });
//!     // Shut down the actor
//!     actor_handle
//!         .shutdown()
//!         .await
//!         .expect("failed to shut down actor");
//!     // Wait for the actor to complete (in practice, you might wait for a shutdown signal)
//!     join_handle
//!         .await
//!         .expect("join handle failed")
//!         .expect("actor failed");
//! }
//! ```

use crate::{
    create_udp_notif_channel, ActorId, SubscriberId, Subscription, UdpNotifReceiver,
    UdpNotifRequest, UdpNotifSender,
};
use bytes::{Bytes, BytesMut};
use futures_util::{stream::SplitSink, StreamExt};
use netgauze_udp_notif_pkt::codec::UdpPacketCodec;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::{
    codec::{BytesCodec, Decoder},
    udp::UdpFramed,
};
use tracing::{debug, error, info, warn};

/// Commands that can be sent to the [UdpNotifActor].
#[derive(Debug, Clone, strum_macros::Display)]
pub(crate) enum ActorCommand {
    /// Command to shut down the actor.
    Shutdown(mpsc::Sender<ActorId>),
    /// Command to subscribe to udp-notif packets.
    Subscribe(mpsc::Sender<Subscription>, UdpNotifSender),
    Unsubscribe(SubscriberId, mpsc::Sender<Option<Subscription>>),
    PurgeUnusedPeers(Duration, mpsc::Sender<Vec<SocketAddr>>),
    PurgePeer(SocketAddr, mpsc::Sender<Option<ActorId>>),
    LocalAddr(mpsc::Sender<(ActorId, SocketAddr)>),
    GetPeers(mpsc::Sender<(ActorId, Vec<SocketAddr>)>),
}

/// This struct keeps track of the usage of a peer. It stores
/// the number of packets received from the peer since last_set time.
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

/// Errors that can occur in the `UdpNotifActor`.
#[derive(Debug)]
pub enum UdpNotifActorError {
    SocketBindError(ActorId, SocketAddr, std::io::Error),
    GetLocalAddressError(ActorId, SocketAddr, std::io::Error),
    CommandChannelClosed(ActorId, SocketAddr),
    PacketProcessingError(ActorId, SocketAddr, std::io::Error),
}

impl std::fmt::Display for UdpNotifActorError {
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
            Self::PacketProcessingError(actor_id, addr, err) => write!(
                f,
                "[Actor {actor_id}-{addr}] unrecoverable error processing packet: {err}"
            ),
        }
    }
}

impl std::error::Error for UdpNotifActorError {}

/// The main actor struct responsible for receiving and processing udp-notif
/// packets. This struct encapsulates the state and behavior of the actor.
/// In the actor model, this internal state is not directly accessible from
/// outside the actor.
#[derive(Debug)]
struct UdpNotifActor {
    actor_id: ActorId,
    socket_addr: SocketAddr,
    interface_bind: Option<String>,
    cmd_rx: mpsc::Receiver<ActorCommand>,
    next_subscriber_id: SubscriberId,
    // TODO: in future allow subscribers to subscribe to a subset of events
    //       (i.e., specific peers or specific record types)
    subscribers: HashMap<SubscriberId, UdpNotifSender>,
    /// Timeout for sending a udp-notif packet to a subscriber before dropping
    /// it.
    subscriber_timeout: Duration,
    peers_usage: HashMap<SocketAddr, PeerUsage>,
    clients: HashMap<SocketAddr, UdpPacketCodec>,
    stats: UdpNotifCollectorStats,
}

#[derive(Debug, Clone)]
pub struct UdpNotifCollectorStats {
    received: opentelemetry::metrics::Counter<u64>,
    decoded: opentelemetry::metrics::Counter<u64>,
    malformed: opentelemetry::metrics::Counter<u64>,
    subscribers: opentelemetry::metrics::Gauge<u64>,
    subscriber_sent: opentelemetry::metrics::Counter<u64>,
    subscriber_dropped: opentelemetry::metrics::Counter<u64>,
}

impl UdpNotifCollectorStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netgauze.udp-notif.decoder.received")
            .with_description("Number of successfully received udp-notif packets from the network")
            .build();
        let decoded = meter
            .u64_counter("netgauze.udp-notif.decoder.decoded")
            .with_description("Number of successfully decoded udp-notif packets")
            .build();
        let malformed = meter
            .u64_counter("netgauze.udp-notif.decoder.malformed")
            .with_description("Number of udp-notif packets that were not decoded correctly")
            .build();
        let subscribers = meter
            .u64_gauge("netgauze.udp-notif.subscribers.number")
            .with_description(
                "Number of actors subscribed to receive udp-notif info events from this actor",
            )
            .build();
        let subscriber_sent = meter
            .u64_counter("netgauze.udp-notif.subscribers.sent")
            .with_description("Number of udp-notif packets successfully sent to subscribers")
            .build();
        let subscriber_dropped = meter
            .u64_counter("netgauze.udp-notif.subscribers.dropped")
            .with_description("Number of udp-notif packets dropped before sending to subscribers")
            .build();

        Self {
            received,
            decoded,
            malformed,
            subscribers,
            subscriber_sent,
            subscriber_dropped,
        }
    }
}

impl UdpNotifActor {
    fn new(
        actor_id: ActorId,
        socket_addr: SocketAddr,
        interface_bind: Option<String>,
        cmd_rx: mpsc::Receiver<ActorCommand>,
        subscriber_timeout: Duration,
        stats: UdpNotifCollectorStats,
    ) -> Self {
        Self {
            actor_id,
            socket_addr,
            interface_bind,
            cmd_rx,
            next_subscriber_id: 1,
            subscribers: HashMap::default(),
            subscriber_timeout,
            peers_usage: HashMap::default(),
            clients: HashMap::new(),
            stats,
        }
    }

    /// This function decodes a udp-notif packet and returns the message when
    /// successful. For minor errors (e.g. buffer not long enough or a
    /// decoding error), it logs the error and returns None.
    pub fn decode_pkt(&mut self, next: (BytesMut, SocketAddr)) -> Option<UdpNotifRequest> {
        let (mut buf, addr) = next;
        // If we haven't seen the client before, create a new UdpPacketCodec for it.
        // UdpPacketCodec handles the decoding/encoding of packets.
        let result = self.clients.entry(addr).or_default().decode(&mut buf);
        match result {
            Ok(Some(pkt)) => {
                self.stats.decoded.add(
                    1,
                    &[
                        opentelemetry::KeyValue::new(
                            "netgauze.udp-notif.actor",
                            format!("{}", self.actor_id),
                        ),
                        opentelemetry::KeyValue::new(
                            "network.peer.address",
                            format!("{}", addr.ip()),
                        ),
                        opentelemetry::KeyValue::new(
                            "network.peer.port",
                            opentelemetry::Value::I64(addr.port().into()),
                        ),
                    ],
                );
                Some((addr, pkt))
            }
            Ok(None) => {
                debug!(
                    "[Actor {}-{}] needs more data to decode the packet",
                    self.actor_id, self.socket_addr
                );
                None
            }
            Err(err) => {
                self.stats.malformed.add(
                    1,
                    &[
                        opentelemetry::KeyValue::new(
                            "netgauze.udp-notif.actor",
                            format!("{}", self.actor_id),
                        ),
                        opentelemetry::KeyValue::new(
                            "network.peer.address",
                            format!("{}", addr.ip()),
                        ),
                        opentelemetry::KeyValue::new(
                            "network.peer.port",
                            opentelemetry::Value::I64(addr.port().into()),
                        ),
                        opentelemetry::KeyValue::new(
                            "netgauze.udp-notif.decoding.error.msg",
                            opentelemetry::Value::String(err.to_string().into()),
                        ),
                    ],
                );
                warn!(
                    "[Actor {}-{}] dropping packet due to an error in decoding packet: {}",
                    self.actor_id, self.socket_addr, err
                );
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_to_subscriber(
        actor_id: ActorId,
        socket_addr: SocketAddr,
        msg: Arc<UdpNotifRequest>,
        id: SubscriberId,
        tx: UdpNotifSender,
        timeout: Duration,
        sent_counter: opentelemetry::metrics::Counter<u64>,
        drop_counter: opentelemetry::metrics::Counter<u64>,
    ) {
        // The send operation is bounded by timeout period to avoid blocking on a slow
        // subscriber.
        let ref_clone = msg.clone();
        let drop_counter_clone = drop_counter.clone();
        let timeout_ret = tokio::time::timeout(timeout, async move {
            if tx.is_full() {
                warn!(
                    "[Actor {}-{}] channel for subscriber {} is full, dropping message",
                    actor_id, socket_addr, id
                );
                drop_counter.add(
                    1,
                    &[
                        opentelemetry::KeyValue::new(
                            "network.peer.address",
                            format!("{}", socket_addr.ip()),
                        ),
                        opentelemetry::KeyValue::new(
                            "network.peer.port",
                            opentelemetry::Value::I64(socket_addr.port().into()),
                        ),
                        opentelemetry::KeyValue::new(
                            "netgauze.udp-notif.actor",
                            format!("{actor_id}"),
                        ),
                        opentelemetry::KeyValue::new(
                            "netgauze.udp-notif.subscriber.id",
                            format!("{id}"),
                        ),
                        opentelemetry::KeyValue::new(
                            "netgauze.udp-notif.subscriber.error.type",
                            "channel is full".to_string(),
                        ),
                    ],
                );
                return;
            }
            match tx.send(ref_clone).await {
                Ok(_) => {
                    debug!(
                        "[Actor {}-{}] sent udp-notif message to subscriber: {}",
                        actor_id, socket_addr, id
                    );
                    sent_counter.add(
                        1,
                        &[
                            opentelemetry::KeyValue::new(
                                "network.peer.address",
                                format!("{}", socket_addr.ip()),
                            ),
                            opentelemetry::KeyValue::new(
                                "network.peer.port",
                                opentelemetry::Value::I64(socket_addr.port().into()),
                            ),
                            opentelemetry::KeyValue::new(
                                "netgauze.udp-notif.actor",
                                format!("{actor_id}"),
                            ),
                            opentelemetry::KeyValue::new(
                                "netgauze.udp-notif.subscriber.id",
                                format!("{id}"),
                            ),
                        ],
                    );
                }
                Err(_err) => {
                    warn!(
                        "[Actor {}-{}] subscriber {} is unresponsive, removing it from the list",
                        actor_id, socket_addr, id
                    );
                    drop_counter.add(
                        1,
                        &[
                            opentelemetry::KeyValue::new(
                                "network.peer.address",
                                format!("{}", socket_addr.ip()),
                            ),
                            opentelemetry::KeyValue::new(
                                "network.peer.port",
                                opentelemetry::Value::I64(socket_addr.port().into()),
                            ),
                            opentelemetry::KeyValue::new(
                                "netgauze.udp-notif.actor",
                                format!("{actor_id}"),
                            ),
                            opentelemetry::KeyValue::new(
                                "netgauze.udp-notif.subscriber.id",
                                format!("{id}"),
                            ),
                            opentelemetry::KeyValue::new(
                                "netgauze.udp-notif.subscriber.error.type",
                                "send error".to_string(),
                            ),
                        ],
                    );
                }
            }
        })
        .await;
        if timeout_ret.is_err() {
            warn!("[Actor {}-{}] subscriber {} is experiencing backpressure and possibly dropping packets",
                actor_id, socket_addr, id);
            drop_counter_clone.add(
                1,
                &[
                    opentelemetry::KeyValue::new(
                        "network.peer.address",
                        format!("{}", socket_addr.ip()),
                    ),
                    opentelemetry::KeyValue::new(
                        "network.peer.port",
                        opentelemetry::Value::I64(socket_addr.port().into()),
                    ),
                    opentelemetry::KeyValue::new("netgauze.udp-notif.actor", format!("{actor_id}")),
                    opentelemetry::KeyValue::new(
                        "netgauze.udp-notif.subscriber.id",
                        format!("{id}"),
                    ),
                    opentelemetry::KeyValue::new(
                        "netgauze.udp-notif.subscriber.error.type",
                        "timeout".to_string(),
                    ),
                ],
            );
        }
    }

    /// This function handles a decoded udp-notif message. In the current
    /// implementation, it sends the message to all subscribers.
    async fn handle_decoded_msg(&mut self, next: Option<UdpNotifRequest>) {
        if let Some((peer, msg)) = next {
            let usage = self.peers_usage.entry(peer).or_default();
            usage.current_count += 1;
            // Clean closed subscribers
            self.subscribers.retain(|id, tx| {
                if tx.is_closed() {
                    info!(
                        "[Actor {}-{}] subscriber {} is closed, removing it from the list",
                        self.actor_id, self.socket_addr, id
                    );
                    false
                } else {
                    true
                }
            });
            self.stats.subscribers.record(
                self.subscribers.len() as u64,
                &[opentelemetry::KeyValue::new(
                    "netgauze.udp-notif.actor",
                    format!("{}", self.actor_id),
                )],
            );
            debug!("[Actor {}-{}] sending udp-notif packet received from {} to a total of {} subscribers",
                self.actor_id, self.socket_addr, peer,
                self.subscribers.len());
            let mut send_handlers = vec![];
            let udp_notif_request = Arc::new((peer, msg));
            for (id, tx) in &self.subscribers {
                // We fire and run all the send operations to the subscribers
                // in parallel
                // TODO: if there's only one subscriber avoid clone
                let send_handler = Self::send_to_subscriber(
                    self.actor_id,
                    self.socket_addr,
                    udp_notif_request.clone(),
                    *id,
                    tx.clone(),
                    self.subscriber_timeout,
                    self.stats.subscriber_sent.clone(),
                    self.stats.subscriber_dropped.clone(),
                );
                send_handlers.push(send_handler);
            }
            futures::future::join_all(send_handlers).await;
        }
    }

    async fn handle_shutdown(&self, tx: mpsc::Sender<ActorId>) -> bool {
        info!(
            "[Actor {}-{}] received shutdown command, shutting down",
            self.actor_id, self.socket_addr
        );
        let _ = tx.send(self.actor_id).await;
        true
    }

    async fn handle_subscribe(
        &mut self,
        tx: mpsc::Sender<Subscription>,
        msg_tx: UdpNotifSender,
    ) -> bool {
        let id = self.next_subscriber_id;
        self.next_subscriber_id += 1;
        self.subscribers.insert(id, msg_tx);
        info!(
            "[Actor {}-{}] new subscriber {} registered",
            self.actor_id, self.socket_addr, id
        );
        if let Err(_err) = tx
            .send(Subscription {
                actor_id: self.actor_id,
                id,
            })
            .await
        {
            self.subscribers.remove(&id);
            warn!(
                "[Actor {}-{}] new subscriber {} removed, unable to send back the subscriber id",
                self.actor_id, self.socket_addr, id
            );
        }
        false
    }

    async fn handle_unsubscribe(
        &mut self,
        id: SubscriberId,
        tx: mpsc::Sender<Option<Subscription>>,
    ) -> bool {
        info!(
            "[Actor {}-{}] removing subscriber {}",
            self.actor_id, self.socket_addr, id
        );
        let ret = self.subscribers.remove(&id);
        match ret {
            Some(_) => {
                info!(
                    "[Actor {}-{}] subscriber {} removed",
                    self.actor_id, self.socket_addr, id
                );
                let _ = tx
                    .send(Some(Subscription {
                        actor_id: self.actor_id,
                        id,
                    }))
                    .await;
            }
            None => {
                info!(
                    "[Actor {}-{}] subscriber {} not found",
                    self.actor_id, self.socket_addr, id
                );
            }
        }
        false
    }

    async fn handle_purge_peer(
        &mut self,
        peer: SocketAddr,
        tx: mpsc::Sender<Option<ActorId>>,
    ) -> bool {
        match self.clients.remove(&peer).map(|_| self.actor_id) {
            Some(_) => {
                info!(
                    "[Actor {}-{}] removing peer {}",
                    self.actor_id, self.socket_addr, peer
                );
                let _ = self.peers_usage.remove(&peer);
                let _ = tx.send(Some(self.actor_id)).await;
            }
            None => {
                info!(
                    "[Actor {}-{}] peer {} not found",
                    self.actor_id, self.socket_addr, peer
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
            "[Actor {}-{}] removing peers that were inactive for {:?}",
            self.actor_id, self.socket_addr, dur
        );
        let now = Instant::now();
        self.peers_usage.retain(|peer, usage| {
            let since = now.duration_since(usage.last_set);
            if since > dur && usage.current_count == 0 {
                info!(
                    "[Actor {}-{}] removing peer {} which has not been used for the past {:?}",
                    self.actor_id, self.socket_addr, peer, dur
                );
                cleared_peers.push(*peer);
                false
            } else if since > dur && usage.current_count > 0 {
                usage.last_set = now;
                usage.current_count = 0;
                debug!(
                    "[Actor {}-{}] keeping peer {} and resetting counters for it",
                    self.actor_id, self.socket_addr, peer
                );
                true
            } else {
                debug!(
                    "[Actor {}-{}] keeping peer {} that was used {} times since {:?}",
                    self.actor_id, self.socket_addr, usage.current_count, peer, since
                );
                true
            }
        });
        info!(
            "[Actor {}-{}] removed {} inactive peers",
            self.actor_id,
            self.socket_addr,
            cleared_peers.len()
        );
        if let Err(_err) = ret_tx.send(cleared_peers).await {
            error!(
                "[Actor {}-{}] communicating back the list of removed peers",
                self.actor_id, self.socket_addr
            );
        }
        false
    }

    async fn handle_local_addr(&self, tx: mpsc::Sender<(ActorId, SocketAddr)>) -> bool {
        if let Err(err) = tx.send((self.actor_id, self.socket_addr)).await {
            error!(
                "[Actor {}-{}] unable to send back the local address: {}",
                self.actor_id, self.socket_addr, err
            );
        }
        false
    }

    async fn handle_get_peers(&self, tx: mpsc::Sender<(ActorId, Vec<SocketAddr>)>) -> bool {
        let peers = self.clients.keys().cloned().collect::<Vec<_>>();
        if let Err(err) = tx.send((self.actor_id, peers)).await {
            error!(
                "[Actor {}-{}] unable to send back the list of peers: {}",
                self.actor_id, self.socket_addr, err
            );
        }
        false
    }

    async fn handle_cmd(&mut self, cmd: Option<ActorCommand>) -> Result<bool, UdpNotifActorError> {
        let cmd_result = match cmd {
            Some(ActorCommand::Shutdown(tx)) => self.handle_shutdown(tx).await,
            Some(ActorCommand::Subscribe(tx, msg_tx)) => self.handle_subscribe(tx, msg_tx).await,
            Some(ActorCommand::Unsubscribe(id, tx)) => self.handle_unsubscribe(id, tx).await,
            Some(ActorCommand::PurgePeer(peer, tx)) => self.handle_purge_peer(peer, tx).await,
            Some(ActorCommand::PurgeUnusedPeers(dur, ret_tx)) => {
                self.handle_purge_unused_peers(dur, ret_tx).await
            }
            Some(ActorCommand::LocalAddr(tx)) => self.handle_local_addr(tx).await,
            Some(ActorCommand::GetPeers(tx)) => self.handle_get_peers(tx).await,
            None => {
                warn!(
                    "[Actor {}-{}] command channel is closed, shutting down actor",
                    self.actor_id, self.socket_addr
                );
                return Err(UdpNotifActorError::CommandChannelClosed(
                    self.actor_id,
                    self.socket_addr,
                ));
            }
        };
        Ok(cmd_result)
    }

    /// Runs the actor, processes incoming packets and commands until shutdown.
    /// This method implements the core logic of the actor. It runs in a loop,
    /// handling both incoming UDP packets and command messages. This
    /// dual-channel approach allows the actor to efficiently manage network
    /// I/O and control messages concurrently.
    async fn run(mut self) -> Result<(ActorId, SocketAddr), UdpNotifActorError> {
        info!(
            "[Actor {}-{}] spawning actor and binding UDP listener",
            self.actor_id, self.socket_addr
        );
        let socket = crate::new_udp_reuse_port(self.socket_addr, self.interface_bind.clone())
            .map_err(|err| {
                UdpNotifActorError::SocketBindError(self.actor_id, self.socket_addr, err)
            })?;
        // Get the local address of the socket, handy in cases where the port is 0
        self.socket_addr = socket.local_addr().map_err(|err| {
            UdpNotifActorError::GetLocalAddressError(self.actor_id, self.socket_addr, err)
        })?;
        let framed = UdpFramed::new(socket, BytesCodec::default());
        let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
        loop {
            tokio::select! {
                biased; // Prioritize command messages
                cmd = self.cmd_rx.recv() =>{
                    match self.handle_cmd(cmd).await {
                        Ok(true) => return Ok((self.actor_id, self.socket_addr)),
                        Ok(false) => {}
                        Err(err) => return Err(err),
                    }
                }
                next = stream.next() => {
                    match next {
                        Some(Ok(next)) => {
                            self.stats.received.add(1, &[
                                opentelemetry::KeyValue::new("netgauze.udp-notif.actor", format!("{}", self.actor_id)),
                                opentelemetry::KeyValue::new("network.peer.address", format!("{}", next.1.ip())),
                                opentelemetry::KeyValue::new("network.peer.port", opentelemetry::Value::I64(next.1.port().into())),
                            ]);
                            let next = self.decode_pkt(next);
                            self.handle_decoded_msg(next).await;
                        }
                        Some(Err(err)) => {
                            error!("[Actor {}-{}] shutting down due to unrecoverable error: {}",
                                self.actor_id, self.socket_addr, err);
                            return Err(UdpNotifActorError::PacketProcessingError(self.actor_id, self.socket_addr, err))
                        }
                        None => {
                            error!("[Actor {}-{}] shutting down because UDP socket is down",
                                self.actor_id, self.socket_addr);
                            return Ok((self.actor_id, self.socket_addr))
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ActorHandleError {
    SendError,
    ReceiveError,
}

impl std::fmt::Display for ActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ActorHandleError::SendError => {
                write!(f, "error sending command to actor")
            }
            ActorHandleError::ReceiveError => {
                write!(f, "error receiving response from actor")
            }
        }
    }
}

impl std::error::Error for ActorHandleError {
    fn description(&self) -> &str {
        match *self {
            ActorHandleError::SendError => "error sending command to actor",
            ActorHandleError::ReceiveError => "error receiving response from actor",
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

/// A handle is the public interface for interacting with a `UdpNotifActor`.
/// This handle provides a way to send commands to the actor and receive
/// responses. It encapsulates the communication channels to the actor, adhering
/// to the principle of message-passing in the actor model. The handle is
/// cloneable, allowing multiple entities to interact with the actor.
#[derive(Debug, Clone)]
pub struct ActorHandle {
    actor_id: ActorId,
    local_addr: SocketAddr,
    interface_bind: Option<String>,
    cmd_buffer_size: usize,
    pub(crate) cmd_tx: mpsc::Sender<ActorCommand>,
}

impl ActorHandle {
    pub async fn new(
        actor_id: ActorId,
        socket_addr: SocketAddr,
        interface_bind: Option<String>,
        cmd_buffer_size: usize,
        subscriber_timeout: Duration,
        stats: either::Either<opentelemetry::metrics::Meter, UdpNotifCollectorStats>,
    ) -> Result<
        (
            JoinHandle<Result<(ActorId, SocketAddr), UdpNotifActorError>>,
            Self,
        ),
        ActorHandleError,
    > {
        let stats = match stats {
            either::Either::Left(meter) => UdpNotifCollectorStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let (cmd_tx, cmd_rx) = mpsc::channel(cmd_buffer_size);
        let actor = UdpNotifActor::new(
            actor_id,
            socket_addr,
            interface_bind.clone(),
            cmd_rx,
            subscriber_timeout,
            stats,
        );
        let join_handle = tokio::spawn(actor.run());
        let (tx, mut rx) = mpsc::channel(cmd_buffer_size);
        cmd_tx
            .send(ActorCommand::LocalAddr(tx))
            .await
            .map_err(|_| ActorHandleError::SendError)?;
        let local_addr = rx.recv().await.ok_or(ActorHandleError::ReceiveError)?.1;
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

    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn interface_bind(&self) -> Option<&String> {
        self.interface_bind.as_ref()
    }

    /// This function sends a command to the actor to subscribe to the packets.
    pub async fn subscribe(
        &self,
        buffer_size: usize,
    ) -> Result<(UdpNotifReceiver, Vec<Subscription>), ActorHandleError> {
        let (msg_tx, msg_rx) = create_udp_notif_channel(buffer_size);
        let subscriptions = self.subscribe_tx(msg_tx).await?;
        Ok((msg_rx, subscriptions))
    }

    pub async fn subscribe_tx(
        &self,
        msg_tx: UdpNotifSender,
    ) -> Result<Vec<Subscription>, ActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(ActorCommand::Subscribe(tx, msg_tx))
            .await
            .map_err(|_| ActorHandleError::SendError)?;
        let mut subscriptions = vec![];
        while let Some(subscription) = rx.recv().await {
            subscriptions.push(subscription);
        }
        Ok(subscriptions)
    }

    pub async fn unsubscribe(
        &self,
        subscription: SubscriberId,
    ) -> Result<Vec<Subscription>, ActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(ActorCommand::Unsubscribe(subscription, tx))
            .await
            .map_err(|_| ActorHandleError::SendError)?;
        let mut subscriptions = vec![];
        while let Some(subscription) = rx.recv().await {
            if let Some(s) = subscription {
                subscriptions.push(s);
            }
        }
        Ok(subscriptions)
    }

    pub async fn shutdown(&self) -> Result<Vec<ActorId>, ActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(ActorCommand::Shutdown(tx))
            .await
            .map_err(|_| ActorHandleError::SendError)?;
        let mut actors = vec![];
        while let Some(actor_id) = rx.recv().await {
            actors.push(actor_id);
        }
        Ok(actors)
    }

    pub async fn purge_unused_peers(
        &self,
        duration: Duration,
    ) -> Result<Vec<SocketAddr>, ActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        // If the command fails, the recv after will fail, no need to double handle the
        // error
        self.cmd_tx
            .send(ActorCommand::PurgeUnusedPeers(duration, tx))
            .await
            .map_err(|_| ActorHandleError::SendError)?;
        let mut peers = vec![];
        while let Some(got_peers) = rx.recv().await {
            peers.extend(got_peers)
        }
        Ok(peers)
    }

    pub async fn purge_peer(&self, peer: SocketAddr) -> Result<Option<ActorId>, ActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(ActorCommand::PurgePeer(peer, tx))
            .await
            .map_err(|_| ActorHandleError::SendError)?;
        Ok(rx.recv().await.flatten())
    }

    pub async fn get_peers(&self) -> Result<(ActorId, Vec<SocketAddr>), ActorHandleError> {
        let (tx, mut rx) = mpsc::channel(self.cmd_buffer_size);
        self.cmd_tx
            .send(ActorCommand::GetPeers(tx))
            .await
            .map_err(|_| ActorHandleError::SendError)?;
        if let Some(peers) = rx.recv().await {
            Ok(peers)
        } else {
            Ok((self.actor_id, vec![]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, Bytes, BytesMut};
    use netgauze_parse_utils::WritablePdu;
    use netgauze_udp_notif_pkt::{MediaType, UdpNotifPacket};
    use std::io::Cursor;
    use tokio::{net::UdpSocket, time::Duration};

    async fn setup_actor() -> (
        SocketAddr,
        ActorHandle,
        JoinHandle<Result<(ActorId, SocketAddr), UdpNotifActorError>>,
    ) {
        let actor_id = 1;
        let socket_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let meter = opentelemetry::global::meter("test-meter");
        let (join_handle, handle) = ActorHandle::new(
            actor_id,
            socket_addr,
            None,
            10,
            Duration::from_secs(1),
            either::Either::Left(meter),
        )
        .await
        .expect("couldn't start test actor");
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

    fn generate_udp_notif_data(payload: Bytes) -> (UdpNotifPacket, BytesMut) {
        // Create udp-notif test data
        let pkt = UdpNotifPacket::new(MediaType::YangDataJson, 1, 1, HashMap::new(), payload);
        let mut vec: Vec<u8> = vec![];
        let mut cursor = Cursor::new(&mut vec);
        pkt.write(&mut cursor)
            .expect("failed to serialize udp-notif data");
        let buf = Bytes::from(vec);
        (pkt, buf.into())
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_actor_lifecycle() {
        let (_, handle, join_handle) = setup_actor().await;

        // Subscribe
        let (_rx, subscriptions) = handle.subscribe(10).await.unwrap();
        assert_eq!(subscriptions.len(), 1, "should have one subscription");

        // Unsubscribe
        let subscription_id = subscriptions[0].id;
        let unsubscribed = handle.unsubscribe(subscription_id).await.unwrap();
        assert_eq!(
            unsubscribed.len(),
            1,
            "should have unsubscribed successfully"
        );
        assert_eq!(unsubscribed[0].id, subscription_id);

        // Test shutdown
        let shutdown_result = handle.shutdown().await.unwrap();
        assert_eq!(shutdown_result.len(), 1, "should have shut down one actor");
        assert_eq!(
            shutdown_result[0],
            handle.actor_id(),
            "shut down actor should have correct ID"
        );

        // Ensure the actor has terminated
        let result = tokio::time::timeout(Duration::from_secs(5), join_handle).await;
        assert!(result.is_ok(), "actor should have terminated");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_send_command_to_closed_actor() {
        let (_, handle, join_handle) = setup_actor().await;

        // Shutdown the actor
        handle.shutdown().await.unwrap();
        join_handle.await.unwrap().unwrap();

        // Try to send a command to the closed actor
        let result = handle.subscribe(10).await;
        assert!(matches!(result, Err(ActorHandleError::SendError)));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_unsubscribe_non_existent() {
        let (_, handle, _join_handle) = setup_actor().await;

        // Unsubscribe a non-existent subscriber
        let unsubscribed = handle.unsubscribe(999).await.unwrap();
        assert!(unsubscribed.is_empty());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_receive() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send udp-notif data to register the peer
        let (pkt, mut data) = generate_udp_notif_data(Bytes::from_static(b"test data"));
        send_data(listening_socket, &socket, &mut data).await;

        // Subscribe to receive packets
        let (pkt_rx, _subscriptions) = handle.subscribe(10).await.unwrap();

        // Receive the packet
        let received = tokio::time::timeout(Duration::from_secs(1), pkt_rx.recv()).await;
        assert!(received.is_ok());
        let received_packet = received.unwrap();
        assert_eq!(
            received_packet,
            Ok(Arc::new((socket.local_addr().unwrap(), pkt)))
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_concurrent_receive() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind multiple UDP sockets to send packets
        let socket1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr1 = socket1.local_addr().unwrap();
        let local_addr2 = socket2.local_addr().unwrap();

        // Subscribe to receive packets
        let (pkt_rx, _subscriptions) = handle.subscribe(10).await.unwrap();

        // Generate and send udp-notif data from multiple sockets
        let (pkt1, mut data1) = generate_udp_notif_data(Bytes::from_static(b"test data 1"));
        let (pkt2, mut data2) = generate_udp_notif_data(Bytes::from_static(b"test data 2"));
        send_data(listening_socket, &socket1, &mut data1).await;
        send_data(listening_socket, &socket2, &mut data2).await;

        // Receive packets
        let rec1 = tokio::time::timeout(Duration::from_secs(1), pkt_rx.recv()).await;
        let rec2 = tokio::time::timeout(Duration::from_secs(1), pkt_rx.recv()).await;
        assert_eq!(rec1, Ok(Ok(Arc::new((local_addr1, pkt1)))));
        assert_eq!(rec2, Ok(Ok(Arc::new((local_addr2, pkt2)))));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_get_peers() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;
        let (pkt_rx, _subscriptions) = handle.subscribe(10).await.unwrap();

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send udp-notif data to register the peer
        let (pkt, mut data) = generate_udp_notif_data(Bytes::from_static(b"test data"));
        send_data(listening_socket, &socket, &mut data).await;
        // Ensure the packet was handled before getting peers
        let handled_pkt = tokio::time::timeout(Duration::from_secs(1), pkt_rx.recv())
            .await
            .unwrap();
        assert_eq!(
            handled_pkt,
            Ok(Arc::new((socket.local_addr().unwrap(), pkt)))
        );

        // Get peers
        let (actor_id, peers) = handle.get_peers().await.unwrap();
        assert_eq!(actor_id, handle.actor_id());
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], socket.local_addr().unwrap());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_purge_peer() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (pkt_rx, _subscriptions) = handle.subscribe(10).await.unwrap();

        // Generate and send udp-notif data to register the peer
        let (pkt, mut data) = generate_udp_notif_data(Bytes::from_static(b"test data"));
        send_data(listening_socket, &socket, &mut data).await;

        let handled_pkt = tokio::time::timeout(Duration::from_secs(1), pkt_rx.recv())
            .await
            .unwrap();
        // Ensure the packet was handled
        assert_eq!(
            handled_pkt,
            Ok(Arc::new((socket.local_addr().unwrap(), pkt)))
        );

        // Purge the specific peer
        let peer_addr = socket.local_addr().unwrap();
        let purged_peer = handle.purge_peer(peer_addr).await.unwrap();
        assert_eq!(purged_peer, Some(handle.actor_id()));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_purge_unused_peers() {
        let (listening_socket, handle, _join_handle) = setup_actor().await;

        // Bind a UDP socket to send a packet
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Generate and send udp-notif data to register the peer
        let (_pkt, mut data) = generate_udp_notif_data(Bytes::from_static(b"test data"));
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
}
