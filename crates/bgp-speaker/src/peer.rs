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

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{Debug, Display},
    marker::PhantomData,
    net::Ipv4Addr,
    ops::Add,
    time::Duration,
};

use async_trait::async_trait;
use futures::StreamExt;
use futures_util::SinkExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, mpsc::error::SendError, oneshot},
    task::JoinHandle,
    time::Interval,
};
use tokio_util::codec::{Decoder, Encoder, Framed};

use netgauze_bgp_pkt::{
    capabilities::BgpCapability,
    iana::{BgpCapabilityCode, AS_TRANS},
    notification::{BgpNotificationMessage, CeaseError},
    open::{BgpOpenMessage, BgpOpenMessageParameter},
    wire::{deserializer::BgpParsingIgnoredErrors, serializer::BgpMessageWritingError},
    BgpMessage,
};

use crate::{
    codec::{BgpCodecDecoderError, BgpCodecInitializer},
    connection::{ActiveConnect, Connection, ConnectionState, ConnectionStats, ConnectionType},
    events::{BgpEvent, ConnectionEvent},
    fsm::{FsmState, FsmStateError},
};

pub type PeerResult<A> = Result<BgpEvent<A>, FsmStateError<A>>;

pub type PeerStateResult<A> = Result<(FsmState, BgpEvent<A>), FsmStateError<A>>;

type PeerJoinHandle<A> = JoinHandle<Result<(), SendError<PeerStateResult<A>>>>;

#[async_trait]
pub trait PeerPolicy<
    A,
    I: AsyncWrite + AsyncRead,
    D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
        + Encoder<BgpMessage, Error = BgpMessageWritingError>,
>
{
    async fn open_message(&mut self) -> BgpOpenMessage;

    async fn pre_handle_connection_event_hook(
        &mut self,
        event: ConnectionEvent<A>,
        connection: &Connection<A, I, D>,
    ) -> ConnectionEvent<A>;

    async fn post_handle_connection_event_hook(
        &self,
        event: ConnectionEvent<A>,
        connection: Option<&Connection<A, I, D>>,
    ) -> ConnectionEvent<A>;

    async fn pre_handle_peer_event_hook(
        &self,
        event: Option<PeerEvent<A, I>>,
    ) -> Option<PeerEvent<A, I>>;

    async fn post_handle_peer_event_hook(
        &self,
        event: Option<PeerEvent<A, I>>,
    ) -> Option<PeerEvent<A, I>>;
}

/// Echo back BGP Capabilities to a peer. With the options to force using a
/// capability and rejecting some capabilities. For this policy to be effective,
/// OpenDelayTimer must be set to large enough value. Otherwise, only initially
/// defined `capabilities` are sent to the peer.
#[derive(Debug, Clone)]
pub struct EchoCapabilitiesPolicy<A, I, D> {
    my_asn: u32,
    my_bgp_id: Ipv4Addr,
    remote_as: Option<u32>,
    hold_timer_duration: u16,
    capabilities: HashMap<BgpCapabilityCode, BgpCapability>,
    reject_capabilities: HashSet<BgpCapabilityCode>,
    peer_capabilities: Vec<BgpCapability>,
    _address_marker: PhantomData<A>,
    _inner_marker: PhantomData<I>,
    _codec_marker: PhantomData<D>,
}

impl<A, I, D> EchoCapabilitiesPolicy<A, I, D> {
    pub fn new(
        my_asn: u32,
        my_bgp_id: Ipv4Addr,
        hold_timer_duration: u16,
        capabilities: HashMap<BgpCapabilityCode, BgpCapability>,
        reject_capabilities: HashSet<BgpCapabilityCode>,
    ) -> Self {
        Self {
            my_asn,
            my_bgp_id,
            remote_as: None,
            hold_timer_duration,
            capabilities,
            reject_capabilities,
            peer_capabilities: vec![],
            _address_marker: PhantomData,
            _inner_marker: PhantomData,
            _codec_marker: PhantomData,
        }
    }
}

#[async_trait]
impl<
        A: Send + Sync + 'static,
        I: AsyncWrite + AsyncRead + Send + Sync + 'static,
        D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send
            + Sync,
    > PeerPolicy<A, I, D> for EchoCapabilitiesPolicy<A, I, D>
{
    async fn open_message(&mut self) -> BgpOpenMessage {
        let mut capabilities: Vec<BgpCapability> = self.capabilities.values().cloned().collect();
        for cap in &self.peer_capabilities {
            if let Ok(code) = cap.code() {
                // Check that the capability has not been added before and not in the reject
                // list
                if !self.capabilities.contains_key(&code)
                    && !self.reject_capabilities.contains(&code)
                {
                    capabilities.push(cap.clone());
                }
            }
        }
        // ASN in BGP header is always 2-octets,
        // 4-octets are encoded in as a BGP Capability
        let my_asn = if self.my_asn > u16::MAX as u32 {
            AS_TRANS
        } else {
            self.my_asn as u16
        };
        BgpOpenMessage::new(
            my_asn,
            self.hold_timer_duration,
            self.my_bgp_id,
            vec![BgpOpenMessageParameter::Capabilities(capabilities)],
        )
    }

    async fn pre_handle_connection_event_hook(
        &mut self,
        event: ConnectionEvent<A>,
        _connection: &Connection<A, I, D>,
    ) -> ConnectionEvent<A> {
        match &event {
            ConnectionEvent::BGPOpen(open) | ConnectionEvent::BGPOpenWithDelayOpenTimer(open) => {
                let asn = open.my_asn4();
                self.remote_as.replace(asn);
                self.peer_capabilities = open.capabilities().values().cloned().cloned().collect();
            }
            _ => {}
        }
        event
    }

    async fn post_handle_connection_event_hook(
        &self,
        event: ConnectionEvent<A>,
        _connection: Option<&Connection<A, I, D>>,
    ) -> ConnectionEvent<A> {
        event
    }

    async fn pre_handle_peer_event_hook(
        &self,
        event: Option<PeerEvent<A, I>>,
    ) -> Option<PeerEvent<A, I>> {
        event
    }

    async fn post_handle_peer_event_hook(
        &self,
        event: Option<PeerEvent<A, I>>,
    ) -> Option<PeerEvent<A, I>> {
        event
    }
}

/// Subset from standard BGP events that are administrative
#[derive(Debug)]
pub enum PeerAdminEvents<A, I: AsyncWrite + AsyncRead> {
    ManualStart,
    ManualStop,

    AutomaticStart,
    AutomaticStop,

    TcpConnectionConfirmed((A, I)),
}

#[derive(Debug)]
pub enum PeerEvent<A, I: AsyncWrite + AsyncRead> {
    Admin(PeerAdminEvents<A, I>),
    BgpMessage(BgpMessage),
    GetPeerStats(oneshot::Sender<PeerStats>),
    GetConnectionStats(oneshot::Sender<Option<ConnectionStats>>),
    GetTrackedConnectionStats(oneshot::Sender<Option<ConnectionStats>>),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, strum_macros::Display)]
pub enum PeerState {
    AdminUp,
    AdminDown,
}

/// Error result from initiating a connection to a peer
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ConnectError {
    TcpConnectionFails,
}

impl<A> From<ConnectError> for BgpEvent<A> {
    fn from(val: ConnectError) -> Self {
        match val {
            ConnectError::TcpConnectionFails => BgpEvent::TcpConnectionFails,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct PeerStats {
    connect_retry_counter: u32,
}

impl PeerStats {
    pub const fn connect_retry_counter(&self) -> u32 {
        self.connect_retry_counter
    }
}

/// Peer Configurations that are allowed to change without needing to restart
/// the peer
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PeerConfig {
    allow_auto_start: bool,
    allow_auto_stop: bool,
    send_notif_without_open: bool,
    connect_retry_duration: u16,
    pub(crate) open_delay_timer_duration: u16,
    pub(crate) hold_timer_duration: u16,
    pub(crate) hold_timer_duration_large_value: u16,
    pub(crate) keepalive_timer_duration: u16,
    pub(crate) idle_hold_duration: u16,
    passive_tcp_establishment: bool,
    collision_detect_established_state: bool,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            allow_auto_start: true,
            allow_auto_stop: true,
            send_notif_without_open: true,
            connect_retry_duration: 10,
            open_delay_timer_duration: 0,
            hold_timer_duration: 180,
            // RFC 4271 recommends hold timer large value to be 4 minutes
            hold_timer_duration_large_value: 240,
            keepalive_timer_duration: 30,
            idle_hold_duration: 1,
            passive_tcp_establishment: false,
            collision_detect_established_state: false,
        }
    }
}

impl PeerConfig {
    pub const fn allow_auto_start(&self) -> bool {
        self.allow_auto_start
    }

    pub const fn allow_auto_stop(&self) -> bool {
        self.allow_auto_stop
    }

    pub const fn send_notif_without_open(&self) -> bool {
        self.send_notif_without_open
    }

    pub const fn connect_retry_duration(&self) -> Duration {
        if self.connect_retry_duration == 0 {
            Duration::from_millis(1)
        } else {
            Duration::from_secs(self.connect_retry_duration as u64)
        }
    }

    pub const fn open_delay_timer_duration(&self) -> Duration {
        Duration::from_secs(self.open_delay_timer_duration as u64)
    }

    pub const fn hold_timer_duration(&self) -> Duration {
        Duration::from_secs(self.hold_timer_duration as u64)
    }

    pub const fn hold_timer_duration_large_value(&self) -> Duration {
        Duration::from_secs(self.hold_timer_duration_large_value as u64)
    }

    pub const fn keepalive_timer_duration(&self) -> Duration {
        Duration::from_secs(self.keepalive_timer_duration as u64)
    }

    pub const fn idle_hold_duration(&self) -> Duration {
        Duration::from_secs(self.idle_hold_duration as u64)
    }

    pub const fn passive_tcp_establishment(&self) -> bool {
        self.passive_tcp_establishment
    }
}

#[derive(Debug, Default)]
pub struct PeerConfigBuilder {
    config: PeerConfig,
}

impl PeerConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn allow_auto_start(mut self, value: bool) -> Self {
        self.config.allow_auto_start = value;
        self
    }

    pub const fn allow_auto_stop(mut self, value: bool) -> Self {
        self.config.allow_auto_stop = value;
        self
    }

    pub const fn send_notif_without_open(mut self, value: bool) -> Self {
        self.config.send_notif_without_open = value;
        self
    }

    pub const fn connect_retry_duration(mut self, value: u16) -> Self {
        self.config.connect_retry_duration = value;
        self
    }

    pub const fn open_delay_timer_duration(mut self, value: u16) -> Self {
        self.config.open_delay_timer_duration = value;
        self
    }

    pub const fn hold_timer_duration(mut self, value: u16) -> Self {
        self.config.hold_timer_duration = value;
        self
    }

    pub const fn hold_timer_duration_large_value(mut self, value: u16) -> Self {
        self.config.hold_timer_duration_large_value = value;
        self
    }

    pub const fn keepalive_timer_duration(mut self, value: u16) -> Self {
        self.config.keepalive_timer_duration = value;
        self
    }

    pub const fn idle_hold_duration(mut self, value: u16) -> Self {
        self.config.idle_hold_duration = value;
        self
    }

    pub const fn passive_tcp_establishment(mut self, value: bool) -> Self {
        self.config.passive_tcp_establishment = value;
        self
    }

    pub const fn collision_detect_established_state(mut self, value: bool) -> Self {
        self.config.collision_detect_established_state = value;
        self
    }

    pub const fn build(self) -> PeerConfig {
        self.config
    }
}

/// Peer configurations that are not changed without restarting the peer
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PeerProperties<A> {
    my_asn: u32,
    peer_asn: u32,
    my_bgp_id: Ipv4Addr,
    peer_bgp_id: Ipv4Addr,
    peer_addr: A,
    allow_dynamic_as: bool,
    allow_dynamic_bgp_id: bool,
}

impl<A: Clone> PeerProperties<A> {
    pub const fn new(
        my_asn: u32,
        peer_asn: u32,
        my_bgp_id: Ipv4Addr,
        peer_bgp_id: Ipv4Addr,
        peer_addr: A,
        allow_dynamic_as: bool,
        allow_dynamic_bgp_id: bool,
    ) -> Self {
        Self {
            my_asn,
            peer_asn,
            my_bgp_id,
            peer_bgp_id,
            peer_addr,
            allow_dynamic_as,
            allow_dynamic_bgp_id,
        }
    }

    pub const fn my_asn(&self) -> u32 {
        self.my_asn
    }
    pub const fn peer_asn(&self) -> u32 {
        self.peer_asn
    }
    pub const fn my_bgp_id(&self) -> Ipv4Addr {
        self.my_bgp_id
    }
    pub const fn peer_bgp_id(&self) -> Ipv4Addr {
        self.peer_bgp_id
    }
    pub fn peer_addr(&self) -> A {
        self.peer_addr.clone()
    }
    pub const fn allow_dynamic_as(&self) -> bool {
        self.allow_dynamic_as
    }
    pub const fn allow_dynamic_bgp_id(&self) -> bool {
        self.allow_dynamic_bgp_id
    }
}

#[derive(Debug)]
pub struct Peer<
    A,
    I: AsyncWrite + AsyncRead,
    D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
        + Encoder<BgpMessage, Error = BgpMessageWritingError>,
    C: ActiveConnect<A, I, D>,
    P: PeerPolicy<A, I, D>,
> {
    properties: PeerProperties<A>,
    policy: P,
    peer_state: PeerState,
    fsm_state: FsmState,
    config: PeerConfig,
    connection: Option<Connection<A, I, D>>,
    tracked_connection: Option<Connection<A, I, D>>,
    connect_retry_timer: Option<Interval>,
    stats: PeerStats,
    active_connect: C,
    allowed_to_active_connect: bool,
    waiting_admin_events: Vec<PeerAdminEvents<A, I>>,
}

impl<
        A: Display + Debug + Clone,
        I: AsyncWrite + AsyncRead + Unpin,
        D: BgpCodecInitializer<Peer<A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>,
        C: ActiveConnect<A, I, D>,
        P: PeerPolicy<A, I, D>,
    > Peer<A, I, D, C, P>
{
    pub fn new(
        properties: PeerProperties<A>,
        config: PeerConfig,
        policy: P,
        active_connect: C,
    ) -> Self {
        Self {
            properties,
            policy,
            peer_state: PeerState::AdminDown,
            fsm_state: FsmState::Idle,
            config,
            connection: None,
            tracked_connection: None,
            connect_retry_timer: None,
            stats: PeerStats::default(),
            active_connect,
            allowed_to_active_connect: false,
            waiting_admin_events: vec![],
        }
    }

    pub const fn fsm_state(&self) -> FsmState {
        self.fsm_state
    }

    pub const fn peer_state(&self) -> PeerState {
        self.peer_state
    }

    pub const fn connection(&self) -> Option<&Connection<A, I, D>> {
        self.connection.as_ref()
    }

    pub const fn tracked_connection(&self) -> Option<&Connection<A, I, D>> {
        self.tracked_connection.as_ref()
    }

    pub const fn connect_retry_timer(&self) -> Option<&Interval> {
        self.connect_retry_timer.as_ref()
    }

    pub const fn stats(&self) -> PeerStats {
        self.stats
    }

    pub const fn config(&self) -> &PeerConfig {
        &self.config
    }

    // Central method for transitioning to make it easier for consistent logging
    #[inline]
    fn fsm_transition(&mut self, new_state: FsmState) {
        if new_state == self.fsm_state {
            return;
        }
        let before = self.fsm_state;
        self.fsm_state = new_state;
        log::info!(
            "[{}][{}] FSM state transitions from {} to {}",
            self.properties.peer_bgp_id,
            self.fsm_state,
            before,
            new_state
        );
    }
    fn add_connection(&mut self, connection: Connection<A, I, D>) {
        if self.connection.is_some() {
            log::debug!(
                "[{}][{}] tracking a second connection: {}",
                self.properties.peer_bgp_id,
                self.fsm_state,
                connection.peer_addr()
            );
            self.tracked_connection.replace(connection);
        } else {
            let before = self.fsm_state;
            let after = match connection.state() {
                ConnectionState::Terminate => before,
                ConnectionState::Connected => before,
                ConnectionState::OpenSent => FsmState::OpenSent,
                ConnectionState::OpenConfirm => FsmState::OpenConfirm,
                ConnectionState::Established => FsmState::Established,
            };
            if before != after {
                log::info!(
                    "[{}][{}] FSM transitioned from {before} to {after}",
                    self.properties.peer_bgp_id,
                    self.fsm_state
                );
            }
            self.fsm_transition(after);
            self.connection.replace(connection);
        }
    }

    fn create_connection(
        &mut self,
        peer_addr: A,
        stream: I,
        connection_type: ConnectionType,
    ) -> Result<Connection<A, I, D>, FsmStateError<A>> {
        let codec = D::new(self);
        let framed = Framed::new(stream, codec);
        let connection = Connection::new(
            &self.properties,
            peer_addr,
            HashMap::new(),
            connection_type,
            (&self.config).into(),
            framed,
        );
        Ok(connection)
    }

    /// Accept connection initiated by peer
    async fn accept_connection(
        &mut self,
        peer_addr: A,
        tcp_stream: I,
    ) -> Result<Option<BgpEvent<A>>, FsmStateError<A>> {
        if self.peer_state == PeerState::AdminDown
            || (self.connection.is_some() && self.tracked_connection.is_some())
            || (self.fsm_state == FsmState::Established
                && !self.config.collision_detect_established_state)
        {
            log::info!(
                "[{}][{}] Connection Rejected: {}",
                self.properties.peer_bgp_id,
                self.fsm_state,
                peer_addr
            );
            if self.config.send_notif_without_open() {
                let notif = BgpNotificationMessage::CeaseError(CeaseError::ConnectionRejected {
                    value: vec![],
                });
                let codec = D::new(self);
                let mut framed = Framed::new(tcp_stream, codec);
                // Error is ignored since it's optional to send a notification message
                let _ = framed.send(BgpMessage::Notification(notif)).await;
                let _ = framed.close().await;
            }
            return Ok(None);
        }
        log::info!(
            "[{}][{}] Passive connected",
            self.properties.peer_bgp_id,
            self.fsm_state
        );
        self.connect_retry_timer.take();
        let mut connection =
            self.create_connection(peer_addr.clone(), tcp_stream, ConnectionType::Passive)?;
        let event = connection
            .handle_event(
                &mut self.policy,
                ConnectionEvent::TcpConnectionConfirmed(peer_addr.clone()),
            )
            .await?
            .into();
        self.add_connection(connection);
        Ok(Some(event))
    }

    pub async fn send_bgp_message(&mut self, msg: BgpMessage) -> Result<(), FsmStateError<A>> {
        if let Some(tracked) = self.tracked_connection.as_mut() {
            if let Err(err) = tracked.send(msg.clone()).await {
                // Errors writing to a tracked connection are ignored and we assume that the
                // connection is not good anymore.
                log::info!(
                    "[{}][{}] Error writing to tracked connection at state {} : {err:?}",
                    self.properties.peer_bgp_id,
                    self.fsm_state,
                    tracked.state()
                );
                self.tracked_connection.take();
            }
        }
        if let Some(connection) = self.connection.as_mut() {
            connection.send(msg).await?;
        }
        Ok(())
    }

    pub fn peer_stats(&self) -> PeerStats {
        self.stats
    }

    pub fn waiting_admin_events(&self) -> &Vec<PeerAdminEvents<A, I>> {
        &self.waiting_admin_events
    }

    pub fn main_connection_stats(&self) -> Option<ConnectionStats> {
        self.connection.as_ref().map(|c| *c.stats())
    }

    pub fn tracked_connection_stats(&self) -> Option<ConnectionStats> {
        self.tracked_connection.as_ref().map(|c| *c.stats())
    }

    async fn shutdown(&mut self) {
        log::info!(
            "[{}][{}] Shutting down peer",
            self.properties.peer_bgp_id,
            self.fsm_state
        );
        self.connect_retry_timer.take();
        self.peer_state = PeerState::AdminDown;
        self.fsm_transition(FsmState::Idle);
        // Dropping connections
        if let Some(conn) = self.connection.as_mut() {
            let _ = conn
                .send(BgpMessage::Notification(
                    BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown {
                        value: vec![],
                    }),
                ))
                .await;
        }
        self.connection.take();
        if let Some(conn) = self.tracked_connection.as_mut() {
            let _ = conn
                .send(BgpMessage::Notification(
                    BgpNotificationMessage::CeaseError(CeaseError::AdministrativeShutdown {
                        value: vec![],
                    }),
                ))
                .await;
        }
        self.tracked_connection.take();
    }

    fn start(&mut self) {
        self.peer_state = PeerState::AdminUp;
        self.stats.connect_retry_counter = 0;
        if self.fsm_state != FsmState::Idle {
            // Start events are ignored in already started peer
            return;
        }
        if self.config.passive_tcp_establishment {
            self.fsm_transition(FsmState::Active);
        } else {
            let mut interval = tokio::time::interval(self.config.connect_retry_duration());
            interval.reset();
            self.connect_retry_timer.replace(interval);
            self.fsm_transition(FsmState::Connect);
            self.allowed_to_active_connect = true;
        }
    }

    async fn handle_active_connection(
        &mut self,
        connect_result: Result<I, ConnectError>,
    ) -> PeerResult<A> {
        match connect_result {
            Ok(stream) => {
                let mut connection = self.create_connection(
                    self.properties.peer_addr.clone(),
                    stream,
                    ConnectionType::Active,
                )?;
                self.connect_retry_timer.take();
                let event = connection
                    .handle_event(
                        &mut self.policy,
                        ConnectionEvent::TcpConnectionRequestAcked(
                            self.properties.peer_addr.clone(),
                        ),
                    )
                    .await?
                    .into();
                self.add_connection(connection);
                Ok(event)
            }
            Err(ConnectError::TcpConnectionFails) => {
                self.connect_retry_timer.take();
                Ok(BgpEvent::TcpConnectionFails)
            }
        }
    }

    async fn get_connection_event(
        connection: Option<&mut Connection<A, I, D>>,
    ) -> ConnectionEvent<A> {
        match connection {
            None => std::future::pending().await,
            Some(connection) => match connection.next().await {
                None => std::future::pending().await,
                Some(event) => event,
            },
        }
    }

    fn fsm_state_from_tracked(
        fsm_state: FsmState,
        open: BgpOpenMessage,
        tracked: &Connection<A, I, D>,
    ) -> Result<FsmState, FsmStateError<A>> {
        match tracked.state() {
            ConnectionState::Connected => Err(FsmStateError::InvalidConnectionStateTransition(
                BgpEvent::BGPOpen(open),
                fsm_state,
                ConnectionState::Connected,
                ConnectionState::Connected,
            )),
            ConnectionState::Terminate => Err(FsmStateError::InvalidConnectionStateTransition(
                BgpEvent::BGPOpen(open),
                fsm_state,
                ConnectionState::Terminate,
                ConnectionState::Terminate,
            )),
            ConnectionState::OpenSent => Ok(FsmState::OpenSent),
            ConnectionState::OpenConfirm => Ok(FsmState::OpenConfirm),
            ConnectionState::Established => Ok(FsmState::Established),
        }
    }

    async fn handle_tracked_connection_event(
        &mut self,
        value: Result<BgpOpenMessage, ()>,
    ) -> Result<BgpEvent<A>, FsmStateError<A>> {
        match (
            value,
            self.connection.take(),
            self.tracked_connection.take(),
        ) {
            (Ok(open), Some(mut connection), Some(mut tracked)) => {
                let main_created = connection.stats().created();
                let tracked_created = tracked.stats().created();
                if open.bgp_id() < self.properties.my_bgp_id
                    || (open.bgp_id() == self.properties.my_bgp_id
                        && tracked_created < main_created)
                {
                    self.connection.replace(connection);
                    let _ = tracked
                        .send(BgpMessage::Notification(
                            BgpNotificationMessage::CeaseError(
                                CeaseError::ConnectionCollisionResolution { value: vec![] },
                            ),
                        ))
                        .await;
                } else {
                    self.stats.connect_retry_counter += 1;
                    let new_state = Self::fsm_state_from_tracked(self.fsm_state, open, &tracked)?;
                    self.fsm_transition(new_state);
                    self.connection.replace(tracked);
                    let _ = connection
                        .send(BgpMessage::Notification(
                            BgpNotificationMessage::CeaseError(
                                CeaseError::ConnectionCollisionResolution { value: vec![] },
                            ),
                        ))
                        .await;
                }
            }
            (Ok(open), None, Some(tracked)) => {
                self.stats.connect_retry_counter += 1;
                let new_state = Self::fsm_state_from_tracked(self.fsm_state, open, &tracked)?;
                self.fsm_transition(new_state);
                self.connection.replace(tracked);
            }
            (_, Some(connection), _) => {
                self.connection.replace(connection);
            }
            (_, None, Some(tracked)) => {
                self.connection.replace(tracked);
            }
            (_, None, None) => {}
        }
        Ok(BgpEvent::OpenCollisionDump)
    }

    async fn handle_connection_event(
        &mut self,
        event: ConnectionEvent<A>,
    ) -> Result<BgpEvent<A>, FsmStateError<A>> {
        let conn = match self.connection.as_mut() {
            Some(conn) => conn,
            None => {
                if self.fsm_state == FsmState::OpenSent {
                    self.fsm_transition(FsmState::Active);
                } else {
                    self.fsm_transition(FsmState::Idle);
                }
                return Ok(BgpEvent::TcpConnectionFails);
            }
        };
        let event = self
            .policy
            .pre_handle_connection_event_hook(event, conn)
            .await;
        let conn_state_before = conn.state();
        let event = conn.handle_event(&mut self.policy, event).await?;
        let event = self
            .policy
            .post_handle_connection_event_hook(event, Some(conn))
            .await;
        let conn_state_after = conn.state();
        match (conn_state_before, conn_state_after, &event) {
            (ConnectionState::Connected, ConnectionState::Connected, event) => match event {
                ConnectionEvent::TcpConnectionRequestAcked(_)
                | ConnectionEvent::TcpConnectionConfirmed(_) => {
                    self.connect_retry_timer.take();
                    if conn.open_delay_timer().is_none() {
                        // Only allowed to stay in this state if open delay timer is running
                        return Err(FsmStateError::InvalidConnectionStateTransition(
                            event.clone().into(),
                            self.fsm_state,
                            conn_state_before,
                            conn_state_after,
                        ));
                    }
                }
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::Connected, ConnectionState::OpenSent, event) => match event {
                ConnectionEvent::TcpConnectionRequestAcked(_)
                | ConnectionEvent::TcpConnectionConfirmed(_) => {
                    self.connect_retry_timer.take();
                    self.fsm_transition(FsmState::OpenSent);
                }
                ConnectionEvent::DelayOpenTimerExpires => self.fsm_transition(FsmState::OpenSent),
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::Connected, ConnectionState::OpenConfirm, _) => match event {
                ConnectionEvent::BGPOpen(_) | ConnectionEvent::BGPOpenWithDelayOpenTimer(_) => {
                    self.connect_retry_timer.take();
                    self.fsm_transition(FsmState::OpenConfirm);
                }
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::Connected, ConnectionState::Established, _) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::Connected, ConnectionState::Terminate, _) => match event {
                ConnectionEvent::TcpConnectionFails => {
                    if self.fsm_state == FsmState::Connect && conn.open_delay_timer().is_some() {
                        let mut interval =
                            tokio::time::interval(self.config.connect_retry_duration());
                        interval.reset();
                        self.connect_retry_timer.replace(interval);
                        self.fsm_transition(FsmState::Active);
                    } else {
                        self.connect_retry_timer.take();
                        if self.fsm_state == FsmState::Active {
                            self.stats.connect_retry_counter += 1;
                        }
                        self.fsm_transition(FsmState::Idle);
                    }
                    self.connection.take();
                }
                ConnectionEvent::BGPHeaderErr(_) | ConnectionEvent::BGPOpenMsgErr(_) => {
                    self.connection.take();
                    self.connect_retry_timer.take();
                    self.stats.connect_retry_counter += 1;
                    self.connection.take();
                    self.fsm_transition(FsmState::Idle);
                }
                ConnectionEvent::NotifMsgVerErr => {
                    self.connect_retry_timer.take();
                    if conn.open_delay_timer().is_none() {
                        self.stats.connect_retry_counter += 1;
                    }
                    self.connection.take();
                    self.fsm_transition(FsmState::Idle);
                }
                ConnectionEvent::HoldTimerExpires
                | ConnectionEvent::KeepAliveTimerExpires
                | ConnectionEvent::BGPOpen(_)
                | ConnectionEvent::NotifMsg(_)
                | ConnectionEvent::KeepAliveMsg
                | ConnectionEvent::UpdateMsg(_, _)
                | ConnectionEvent::UpdateMsgErr(_)
                | ConnectionEvent::RouteRefresh(_)
                | ConnectionEvent::RouteRefreshErr(_) => {
                    self.connect_retry_timer.take();
                    conn.open_delay_timer().take();
                    self.stats.connect_retry_counter += 1;
                    self.connection.take();
                    self.fsm_transition(FsmState::Idle);
                }
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::OpenSent, ConnectionState::Connected, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::OpenSent, ConnectionState::OpenSent, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::OpenSent, ConnectionState::OpenConfirm, event) => match event {
                ConnectionEvent::BGPOpen(_) => {
                    self.connect_retry_timer.take();
                    self.fsm_transition(FsmState::OpenConfirm);
                }
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::OpenSent, ConnectionState::Established, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::OpenSent, ConnectionState::Terminate, event) => {
                self.connection.take();
                match event {
                    ConnectionEvent::HoldTimerExpires => {
                        self.connect_retry_timer.take();
                        self.stats.connect_retry_counter += 1;
                        self.fsm_transition(FsmState::Idle);
                    }
                    ConnectionEvent::TcpConnectionFails => {
                        let mut interval =
                            tokio::time::interval(self.config.connect_retry_duration());
                        interval.reset();
                        self.connect_retry_timer.replace(interval);
                        self.fsm_transition(FsmState::Active);
                    }
                    ConnectionEvent::NotifMsgVerErr => {
                        self.connect_retry_timer.take();
                        self.fsm_transition(FsmState::Idle);
                    }
                    ConnectionEvent::BGPHeaderErr(_)
                    | ConnectionEvent::BGPOpenMsgErr(_)
                    | ConnectionEvent::KeepAliveTimerExpires
                    | ConnectionEvent::DelayOpenTimerExpires
                    | ConnectionEvent::BGPOpenWithDelayOpenTimer(_)
                    | ConnectionEvent::KeepAliveMsg
                    | ConnectionEvent::NotifMsg(_)
                    | ConnectionEvent::UpdateMsg(_, _)
                    | ConnectionEvent::UpdateMsgErr(_)
                    | ConnectionEvent::RouteRefresh(_)
                    | ConnectionEvent::RouteRefreshErr(_) => {
                        self.connect_retry_timer.take();
                        self.stats.connect_retry_counter += 1;
                        self.connection.take();
                        self.fsm_transition(FsmState::Idle);
                    }
                    _ => {
                        return Err(FsmStateError::InvalidConnectionStateTransition(
                            event.clone().into(),
                            self.fsm_state,
                            conn_state_before,
                            conn_state_after,
                        ));
                    }
                }
            }
            (ConnectionState::OpenConfirm, ConnectionState::Connected, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::OpenConfirm, ConnectionState::OpenSent, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::OpenConfirm, ConnectionState::OpenConfirm, event) => {
                match event {
                    ConnectionEvent::KeepAliveTimerExpires => {
                        // stay in the same FSM state
                    }
                    _ => {
                        return Err(FsmStateError::InvalidConnectionStateTransition(
                            event.clone().into(),
                            self.fsm_state,
                            conn_state_before,
                            conn_state_after,
                        ));
                    }
                }
            }
            (ConnectionState::OpenConfirm, ConnectionState::Established, _) => match event {
                ConnectionEvent::KeepAliveMsg => {
                    self.fsm_transition(FsmState::Established);
                }
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::OpenConfirm, ConnectionState::Terminate, event) => match event {
                ConnectionEvent::HoldTimerExpires
                | ConnectionEvent::TcpConnectionFails
                | ConnectionEvent::BGPOpen(_)
                | ConnectionEvent::BGPOpenMsgErr(_)
                | ConnectionEvent::BGPHeaderErr(_)
                | ConnectionEvent::DelayOpenTimerExpires
                | ConnectionEvent::BGPOpenWithDelayOpenTimer(_)
                | ConnectionEvent::NotifMsg(_)
                | ConnectionEvent::UpdateMsg(_, _)
                | ConnectionEvent::UpdateMsgErr(_)
                | ConnectionEvent::RouteRefresh(_)
                | ConnectionEvent::RouteRefreshErr(_) => {
                    self.connect_retry_timer.take();
                    self.stats.connect_retry_counter += 1;
                    self.connection.take();
                    self.fsm_transition(FsmState::Idle);
                }
                ConnectionEvent::NotifMsgVerErr => {
                    self.connect_retry_timer.take();
                    self.connection.take();
                    self.fsm_transition(FsmState::Idle);
                }
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::Established, ConnectionState::Connected, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::Established, ConnectionState::OpenSent, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::Established, ConnectionState::OpenConfirm, event) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
            (ConnectionState::Established, ConnectionState::Established, event) => {
                match event {
                    ConnectionEvent::KeepAliveTimerExpires
                    | ConnectionEvent::KeepAliveMsg
                    | ConnectionEvent::UpdateMsg(_, _)
                    | ConnectionEvent::RouteRefresh(_) => {
                        // stay in the same FSM state
                    }
                    ConnectionEvent::NotifMsg(_) | ConnectionEvent::NotifMsgVerErr => {
                        self.connect_retry_timer.take();
                        self.stats.connect_retry_counter += 1;
                        self.connection.take();
                        self.fsm_transition(FsmState::Idle);
                    }
                    _ => {
                        return Err(FsmStateError::InvalidConnectionStateTransition(
                            event.clone().into(),
                            self.fsm_state,
                            conn_state_before,
                            conn_state_after,
                        ));
                    }
                }
            }
            (ConnectionState::Established, ConnectionState::Terminate, event) => match event {
                ConnectionEvent::HoldTimerExpires
                | ConnectionEvent::DelayOpenTimerExpires
                | ConnectionEvent::TcpConnectionFails
                | ConnectionEvent::BGPOpen(_)
                | ConnectionEvent::BGPOpenWithDelayOpenTimer(_)
                | ConnectionEvent::BGPHeaderErr(_)
                | ConnectionEvent::BGPOpenMsgErr(_)
                | ConnectionEvent::UpdateMsgErr(_) // TODO handle update errors according to RFC 7606
                | ConnectionEvent::RouteRefreshErr(_)
                | ConnectionEvent::NotifMsg(_)
                | ConnectionEvent::NotifMsgVerErr => {
                    self.connection.take();
                    self.connect_retry_timer.take();
                    self.stats.connect_retry_counter += 1;
                    self.fsm_transition(FsmState::Idle);
                }
                _ => {
                    return Err(FsmStateError::InvalidConnectionStateTransition(
                        event.clone().into(),
                        self.fsm_state,
                        conn_state_before,
                        conn_state_after,
                    ));
                }
            },
            (ConnectionState::Terminate, _, _) => {
                return Err(FsmStateError::InvalidConnectionStateTransition(
                    event.clone().into(),
                    self.fsm_state,
                    conn_state_before,
                    conn_state_after,
                ));
            }
        }
        Ok(event.into())
    }
    async fn connect(
        peer: Ipv4Addr,
        peer_addr: A,
        active_connect: &mut C,
        fsm_state: FsmState,
        connect_timeout: Duration,
        allowed_to_active_connect: &mut bool,
    ) -> Result<I, ConnectError> {
        match (fsm_state, &allowed_to_active_connect) {
            (FsmState::Connect, true) => {
                log::info!("[{peer}][{fsm_state}] Connecting to peer: {peer_addr}");
                *allowed_to_active_connect = false;
                match tokio::time::timeout(connect_timeout, active_connect.connect(peer_addr)).await
                {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(err)) => {
                        log::info!("[{peer}][{fsm_state}] Couldn't establish connection: {err:?}");
                        Err(ConnectError::TcpConnectionFails)
                    }
                    Err(_) => {
                        log::info!("[{peer}][{fsm_state}] Timeout establishing connection");
                        Err(ConnectError::TcpConnectionFails)
                    }
                }
            }
            _ => std::future::pending().await,
        }
    }

    /// Drive tracked connection I/O loop till a BGP open message is received.
    /// If any error occurred, we simply drop the tracked connection. Thus, we
    /// don't return verbose error type.
    async fn get_tracked_connection_event(
        fsm_state: FsmState,
        policy: &mut P,
        connection: Option<&mut Connection<A, I, D>>,
    ) -> Result<BgpOpenMessage, ()> {
        if fsm_state == FsmState::Connect {
            return std::future::pending().await;
        }
        match connection {
            None => std::future::pending().await,
            Some(connection) => match connection.next().await {
                None => std::future::pending().await,
                Some(event) => {
                    let event = policy
                        .pre_handle_connection_event_hook(event, connection)
                        .await;
                    let event = connection
                        .handle_event(policy, event)
                        .await
                        .map_err(|_| ())?;
                    let event = policy
                        .post_handle_connection_event_hook(event, Some(connection))
                        .await;
                    if let ConnectionEvent::BGPOpen(open) = event {
                        Ok(open)
                    } else {
                        Err(())
                    }
                }
            },
        }
    }

    pub fn add_admin_event(&mut self, event: PeerAdminEvents<A, I>) {
        self.waiting_admin_events.push(event);
    }

    pub async fn run(&mut self) -> PeerResult<A> {
        // First check if there's any pending admin event to handle
        if let Some(admin_event) = self.waiting_admin_events.pop() {
            let bgp_event = match admin_event {
                PeerAdminEvents::ManualStart => {
                    if self.fsm_state != FsmState::Idle {
                        None
                    } else {
                        self.start();
                        if self.config.passive_tcp_establishment {
                            let mut interval =
                                tokio::time::interval(self.config.connect_retry_duration());
                            interval.reset();
                            self.connect_retry_timer.replace(interval);
                            Some(BgpEvent::ManualStartWithPassiveTcp)
                        } else {
                            Some(BgpEvent::ManualStart)
                        }
                    }
                }
                PeerAdminEvents::ManualStop => {
                    self.shutdown().await;
                    self.stats.connect_retry_counter = 0;
                    Some(BgpEvent::ManualStop)
                }
                PeerAdminEvents::AutomaticStart => {
                    if self.fsm_state != FsmState::Idle {
                        None
                    } else {
                        self.start();
                        if self.config.passive_tcp_establishment {
                            let mut interval =
                                tokio::time::interval(self.config.connect_retry_duration());
                            interval.reset();
                            self.connect_retry_timer.replace(interval);
                            Some(BgpEvent::AutomaticStartWithPassiveTcp)
                        } else {
                            Some(BgpEvent::AutomaticStart)
                        }
                    }
                }
                PeerAdminEvents::AutomaticStop => {
                    self.shutdown().await;
                    self.stats.connect_retry_counter += 1;
                    Some(BgpEvent::AutomaticStop)
                }
                PeerAdminEvents::TcpConnectionConfirmed((peer_addr, stream)) => {
                    self.accept_connection(peer_addr, stream).await?
                }
            };
            if let Some(event) = bgp_event {
                return Ok(event);
            }
        }
        tokio::select! {
            connect_result = Self::connect(
                self.properties.peer_bgp_id,
                self.properties.peer_addr.clone(),
                &mut self.active_connect,
                self.fsm_state,
                // Arbitrary one second timeout if connect retry duration is very small
                self.config.connect_retry_duration().add(Duration::from_secs(1)),
                &mut self.allowed_to_active_connect)
            => {
                self.handle_active_connection(connect_result).await
            }
            _ = async {match self.connect_retry_timer.as_mut() {Some(interval) => {interval.tick().await;}, None => std::future::pending().await}} => {
                if self.fsm_state == FsmState::Active {
                    self.fsm_transition(FsmState::Connect);
                }
                self.allowed_to_active_connect = self.fsm_state == FsmState::Connect;
                self.connection.take();
                Ok(BgpEvent::ConnectRetryTimerExpires)
            }
            event = Self::get_connection_event(self.connection.as_mut()) => {
                self.handle_connection_event(event).await
            }
            event = Self::get_tracked_connection_event(self.fsm_state, &mut self.policy, self.tracked_connection.as_mut()) => {
                self.handle_tracked_connection_event(event).await
            }
        }
    }
}

#[derive(Debug)]
pub struct PeerController<A, I: AsyncWrite + AsyncRead> {
    properties: PeerProperties<A>,
    join_handle: PeerJoinHandle<A>,
    peer_events_tx: mpsc::UnboundedSender<PeerEvent<A, I>>,
}

impl<
        A: Display + Debug + Clone + Send + Sync + 'static,
        I: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    > PeerController<A, I>
{
    pub fn new<
        D: BgpCodecInitializer<Peer<A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send
            + Sync,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
        P: PeerPolicy<A, I, D> + Send + Sync + 'static,
    >(
        properties: PeerProperties<A>,
        config: PeerConfig,
        received_events_tx: mpsc::UnboundedSender<PeerStateResult<A>>,
        policy: P,
        active_connect: C,
    ) -> Self {
        let (join_handle, peer_events_tx) = Self::start_peer(
            properties.clone(),
            config,
            received_events_tx,
            policy,
            active_connect,
        );
        Self {
            properties,
            join_handle,
            peer_events_tx,
        }
    }

    pub async fn handle_peer_event<
        D: BgpCodecInitializer<Peer<A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>,
        C: ActiveConnect<A, I, D> + Send,
        P: PeerPolicy<A, I, D>,
    >(
        peer: &mut Peer<A, I, D, C, P>,
        peer_event: Option<PeerEvent<A, I>>,
    ) -> Result<(), FsmStateError<A>> {
        if let Some(event) = peer_event {
            match event {
                PeerEvent::Admin(admin_event) => {
                    peer.waiting_admin_events.push(admin_event);
                }
                PeerEvent::BgpMessage(msg) => {
                    peer.send_bgp_message(msg).await?;
                }
                PeerEvent::GetPeerStats(tx) => {
                    let stats = peer.peer_stats();
                    if let Err(err) = tx.send(stats) {
                        log::error!("Error sending peer stats: {err:?}");
                    }
                }
                PeerEvent::GetConnectionStats(tx) => {
                    let stats = peer.main_connection_stats();
                    if let Err(err) = tx.send(stats) {
                        log::error!("Error sending main connection stats: {err:?}");
                    }
                }
                PeerEvent::GetTrackedConnectionStats(tx) => {
                    let stats = peer.tracked_connection_stats();
                    if let Err(err) = tx.send(stats) {
                        log::error!("Error sending tracked connection stats: {err:?}");
                    }
                }
            }
        }
        Ok(())
    }

    fn start_peer<
        D: BgpCodecInitializer<Peer<A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
        P: PeerPolicy<A, I, D> + Send + Sync + 'static,
    >(
        properties: PeerProperties<A>,
        config: PeerConfig,
        received_events_tx: mpsc::UnboundedSender<PeerStateResult<A>>,
        policy: P,
        active_connect: C,
    ) -> (PeerJoinHandle<A>, mpsc::UnboundedSender<PeerEvent<A, I>>) {
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();
        let rec_tx = received_events_tx.clone();
        let handle = tokio::spawn(async move {
            let mut peer = Peer::new(properties, config, policy, active_connect);
            loop {
                tokio::select! {
                    biased;
                    peer_event = peer_rx.recv() => {
                        if let Err(err) = Self::handle_peer_event(&mut peer, peer_event).await {
                            log::error!("Terminating Peer due to error in handling PeerEvent: {err}");
                            rec_tx.send(Err(err))?;
                            break;
                        }
                    }
                    bgp_event = peer.run() => {
                        log::debug!(
                            "[{:?}][{:?}] BGP Event {}",
                            peer.fsm_state(),
                            peer.peer_state(),
                            match &bgp_event {
                                Ok(event) => format!("{event}"),
                                Err(err) => format!("{err}"),
                            }
                        );
                        match bgp_event {
                            Ok(event) => {
                                rec_tx.send(Ok((peer.fsm_state(), event))).unwrap();
                            }
                            Err(err) => {
                                log::error!("Terminating Peer due to error in handling BgpEvent: {err}");
                                rec_tx.send(Err(err))?;
                                break;
                            }
                        }
                    }
                }
            }
            Ok(())
        });
        (handle, peer_tx)
    }

    pub const fn peer_addr(&self) -> &A {
        &self.properties.peer_addr
    }

    pub fn get_new_handle(&self) -> PeerHandle<A, I> {
        PeerHandle::new(
            self.peer_events_tx.clone(),
            self.properties.peer_addr.clone(),
        )
    }
}

impl<A, I: AsyncWrite + AsyncRead> Drop for PeerController<A, I> {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

#[derive(Debug)]
pub struct PeerHandle<A, I: AsyncWrite + AsyncRead> {
    peer_events_tx: mpsc::UnboundedSender<PeerEvent<A, I>>,
    peer_addr: A,
}

impl<A: Clone, I: AsyncWrite + AsyncRead> Clone for PeerHandle<A, I> {
    fn clone(&self) -> Self {
        Self {
            peer_events_tx: self.peer_events_tx.clone(),
            peer_addr: self.peer_addr.clone(),
        }
    }
}

impl<A: Display + Debug + 'static, I: AsyncWrite + AsyncRead + 'static> PeerHandle<A, I> {
    fn new(peer_events_tx: mpsc::UnboundedSender<PeerEvent<A, I>>, peer_addr: A) -> Self {
        Self {
            peer_events_tx,
            peer_addr,
        }
    }

    pub const fn peer_addr(&self) -> &A {
        &self.peer_addr
    }

    pub fn start(&self) -> Result<(), SendError<PeerEvent<A, I>>> {
        self.peer_events_tx
            .send(PeerEvent::Admin(PeerAdminEvents::ManualStart))
    }

    pub fn shutdown(&self) -> Result<(), SendError<PeerEvent<A, I>>> {
        self.peer_events_tx
            .send(PeerEvent::Admin(PeerAdminEvents::ManualStop))
    }

    pub fn accept_connection(
        &mut self,
        peer_addr: A,
        connection: I,
    ) -> Result<(), SendError<PeerEvent<A, I>>> {
        self.peer_events_tx
            .send(PeerEvent::Admin(PeerAdminEvents::TcpConnectionConfirmed((
                peer_addr, connection,
            ))))
    }

    pub async fn peer_stats(&mut self) -> Result<PeerStats, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        self.peer_events_tx.send(PeerEvent::GetPeerStats(tx))?;
        Ok(rx.await?)
    }

    pub async fn connection_stats(&mut self) -> Result<Option<ConnectionStats>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        self.peer_events_tx
            .send(PeerEvent::GetConnectionStats(tx))?;
        Ok(rx.await?)
    }

    pub async fn tracked_connection_stats(
        &mut self,
    ) -> Result<Option<ConnectionStats>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        self.peer_events_tx
            .send(PeerEvent::GetTrackedConnectionStats(tx))?;
        Ok(rx.await?)
    }
}
