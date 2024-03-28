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
    fmt::{Debug, Display, Formatter},
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
    sync::oneshot,
    time::Interval,
};
use tokio_util::codec::{Decoder, Encoder, Framed};

use netgauze_bgp_pkt::{
    capabilities::{BgpCapability, FourOctetAsCapability},
    codec::{BgpCodecDecoderError, BgpCodecInitializer},
    iana::{BgpCapabilityCode, AS_TRANS},
    notification::{BgpNotificationMessage, CeaseError, OpenMessageError},
    open::{BgpOpenMessage, BgpOpenMessageParameter},
    wire::{deserializer::BgpParsingIgnoredErrors, serializer::BgpMessageWritingError},
    BgpMessage,
};

use crate::{
    connection::{ActiveConnect, Connection, ConnectionState, ConnectionStats, ConnectionType},
    events::{BgpEvent, ConnectionEvent},
    fsm::{FsmState, FsmStateError},
};

pub type PeerResult<A> = Result<BgpEvent<A>, FsmStateError<A>>;

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
    send_asn4_cap_by_default: bool,
    my_bgp_id: Ipv4Addr,
    remote_as: Option<u32>,
    hold_timer_duration: u16,
    capabilities: Vec<BgpCapability>,
    reject_capabilities: Vec<BgpCapability>,
    peer_capabilities: Vec<BgpCapability>,
    _address_marker: PhantomData<A>,
    _inner_marker: PhantomData<I>,
    _codec_marker: PhantomData<D>,
}

impl<A, I, D> EchoCapabilitiesPolicy<A, I, D> {
    pub const fn new(
        my_asn: u32,
        send_asn4_cap_by_default: bool,
        my_bgp_id: Ipv4Addr,
        hold_timer_duration: u16,
        capabilities: Vec<BgpCapability>,
        reject_capabilities: Vec<BgpCapability>,
    ) -> Self {
        Self {
            my_asn,
            send_asn4_cap_by_default,
            my_bgp_id,
            remote_as: None,
            hold_timer_duration,
            capabilities,
            reject_capabilities,
            peer_capabilities: Vec::new(),
            _address_marker: PhantomData,
            _inner_marker: PhantomData,
            _codec_marker: PhantomData,
        }
    }

    pub const fn is_send_asn4_cap_by_default(&self) -> bool {
        self.send_asn4_cap_by_default
    }

    pub fn send_asn4_cap_by_default(&mut self, value: bool) {
        self.send_asn4_cap_by_default = value;
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
        // ASN in BGP header is always 2-octets,
        // 4-octets are encoded in as a BGP Capability
        let (my_asn, asn4_cap) = if self.my_asn > u16::MAX as u32 {
            (
                AS_TRANS,
                BgpCapability::FourOctetAs(FourOctetAsCapability::new(self.my_asn)),
            )
        } else {
            (
                self.my_asn as u16,
                BgpCapability::FourOctetAs(FourOctetAsCapability::new(self.my_asn)),
            )
        };

        let mut capabilities: Vec<BgpCapability> = self.capabilities.clone();
        // Make sure ASN4 capability is inserted only once
        if (self.send_asn4_cap_by_default || my_asn == AS_TRANS)
            && !capabilities.contains(&asn4_cap)
        {
            capabilities.insert(0, asn4_cap);
        }

        for cap in &self.peer_capabilities {
            // Check that the capability has not been added before and not in the reject
            // list
            if !self.capabilities.contains(cap) && !self.reject_capabilities.contains(cap) {
                capabilities.push(cap.clone());
            }
        }

        let params = if capabilities.is_empty() {
            vec![]
        } else {
            // TODO check for param size and spread capabilities across multiple params or
            // use extended params RFC 9072
            vec![BgpOpenMessageParameter::Capabilities(capabilities)]
        };

        BgpOpenMessage::new(my_asn, self.hold_timer_duration, self.my_bgp_id, params)
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
                self.peer_capabilities = open
                    .capabilities()
                    .into_iter()
                    .filter(|cap| cap.code() != Ok(BgpCapabilityCode::FourOctetAs))
                    .cloned()
                    .collect();
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

impl<A: Display, I: AsyncWrite + AsyncRead> Display for PeerAdminEvents<A, I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAdminEvents::ManualStart => write!(f, "ManualStart"),
            PeerAdminEvents::ManualStop => write!(f, "ManualStop"),
            PeerAdminEvents::AutomaticStart => write!(f, "AutomaticStart"),
            PeerAdminEvents::AutomaticStop => write!(f, "AutomaticStop"),
            PeerAdminEvents::TcpConnectionConfirmed(_) => write!(f, "TcpConnectionConfirmed"),
        }
    }
}
#[derive(Debug)]
pub enum PeerEvent<A, I: AsyncWrite + AsyncRead> {
    Admin(PeerAdminEvents<A, I>),
    BgpMessage(BgpMessage),
    GetPeerStats(oneshot::Sender<PeerStats>),
    GetConnectionStats(oneshot::Sender<Option<ConnectionStats>>),
    GetTrackedConnectionStats(oneshot::Sender<Option<ConnectionStats>>),
    ConnectionSentCapabilities(oneshot::Sender<Option<Vec<BgpCapability>>>),
    ConnectionReceivedCapabilities(oneshot::Sender<Option<Vec<BgpCapability>>>),
    TrackedConnectionSentCapabilities(oneshot::Sender<Option<Vec<BgpCapability>>>),
    TrackedConnectionReceivedCapabilities(oneshot::Sender<Option<Vec<BgpCapability>>>),
}

impl<A: Display, I: AsyncWrite + AsyncRead> Display for PeerEvent<A, I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerEvent::Admin(admin) => write!(f, "Admin({admin})"),
            PeerEvent::BgpMessage(msg) => write!(f, "BgpMessage({msg:?})"),
            PeerEvent::GetPeerStats(_) => write!(f, "GetPeerStats"),
            PeerEvent::GetConnectionStats(_) => write!(f, "GetConnectionStats"),
            PeerEvent::GetTrackedConnectionStats(_) => write!(f, "GetTrackedConnectionStats"),
            PeerEvent::ConnectionSentCapabilities(_) => write!(f, "ConnectionSentCapabilities"),
            PeerEvent::ConnectionReceivedCapabilities(_) => {
                write!(f, "ConnectionReceivedCapabilities")
            }
            PeerEvent::TrackedConnectionSentCapabilities(_) => {
                write!(f, "TrackedConnectionSentCapabilities")
            }
            PeerEvent::TrackedConnectionReceivedCapabilities(_) => {
                write!(f, "TrackedConnectionReceivedCapabilities")
            }
        }
    }
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

/// Internally used return type to signal the results of the BGP collision
/// process
#[derive(Debug, Clone, PartialEq)]
enum CollisionCheckRet {
    DropMain,
    DropTracked,
    /// Drop tracked connection and send a notif message with BGP Peer ID.
    InvalidTrackedBgpId(Ipv4Addr),
}

/// Internally used return type when polling main and tracked connection for
/// next ConnectionEvent to handle.
#[derive(Debug, Clone, PartialEq)]
enum ConnectionNextEvent<A> {
    DropMain,
    DropTracked,
    Event(ConnectionEvent<A>),
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
    peer_addr: A,
    allow_dynamic_as: bool,
}

impl<A: Clone> PeerProperties<A> {
    pub const fn new(
        my_asn: u32,
        peer_asn: u32,
        my_bgp_id: Ipv4Addr,
        peer_addr: A,
        allow_dynamic_as: bool,
    ) -> Self {
        Self {
            my_asn,
            peer_asn,
            my_bgp_id,
            peer_addr,
            allow_dynamic_as,
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
    pub fn peer_addr(&self) -> A {
        self.peer_addr.clone()
    }
    pub const fn allow_dynamic_as(&self) -> bool {
        self.allow_dynamic_as
    }
}

#[derive(Debug)]
pub struct Peer<
    K,
    A,
    I: AsyncWrite + AsyncRead,
    D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
        + Encoder<BgpMessage, Error = BgpMessageWritingError>,
    C: ActiveConnect<A, I, D>,
    P: PeerPolicy<A, I, D>,
> {
    peer_key: K,
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
        K: Display + Copy,
        A: Display + Copy + Debug + Clone,
        I: AsyncWrite + AsyncRead + Unpin,
        D: BgpCodecInitializer<Peer<K, A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>,
        C: ActiveConnect<A, I, D>,
        P: PeerPolicy<A, I, D>,
    > Peer<K, A, I, D, C, P>
{
    pub fn new(
        peer_key: K,
        properties: PeerProperties<A>,
        config: PeerConfig,
        policy: P,
        active_connect: C,
    ) -> Self {
        Self {
            peer_key,
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
            self.peer_key,
            self.fsm_state,
            before,
            new_state
        );
    }
    fn add_connection(&mut self, connection: Connection<A, I, D>) {
        if self.connection.is_some() {
            log::debug!(
                "[{}][{}] tracking a second connection: {}",
                self.peer_key,
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
                    self.peer_key,
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
                self.peer_key,
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
        log::info!("[{}][{}] Passive connected", self.peer_key, self.fsm_state);
        self.connect_retry_timer.take();
        let mut connection =
            self.create_connection(peer_addr, tcp_stream, ConnectionType::Passive)?;
        let event = connection
            .handle_event(
                &mut self.policy,
                ConnectionEvent::TcpConnectionConfirmed(peer_addr),
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
                    self.peer_key,
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

    pub fn main_connection_sent_capabilities(&self) -> Option<Vec<BgpCapability>> {
        self.connection
            .as_ref()
            .and_then(|c| c.sent_capabilities().cloned())
    }

    pub fn main_connection_received_capabilities(&self) -> Option<Vec<BgpCapability>> {
        self.connection
            .as_ref()
            .and_then(|c| c.received_capabilities().cloned())
    }

    pub fn tracked_connection_sent_capabilities(&self) -> Option<Vec<BgpCapability>> {
        self.tracked_connection
            .as_ref()
            .and_then(|c| c.sent_capabilities().cloned())
    }

    pub fn tracked_connection_received_capabilities(&self) -> Option<Vec<BgpCapability>> {
        self.tracked_connection
            .as_ref()
            .and_then(|c| c.received_capabilities().cloned())
    }

    async fn shutdown(&mut self) {
        log::info!("[{}][{}] Shutting down peer", self.peer_key, self.fsm_state);
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
                    self.properties.peer_addr,
                    stream,
                    ConnectionType::Active,
                )?;
                self.connect_retry_timer.take();
                let event = connection
                    .handle_event(
                        &mut self.policy,
                        ConnectionEvent::TcpConnectionRequestAcked(self.properties.peer_addr),
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
        connection: &mut Option<&mut Connection<A, I, D>>,
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
        tracked: &Connection<A, I, D>,
    ) -> Result<FsmState, FsmStateError<A>> {
        match tracked.state() {
            ConnectionState::Connected => Err(FsmStateError::InvalidConnectionStateTransition(
                BgpEvent::OpenCollisionDump,
                fsm_state,
                ConnectionState::Connected,
                ConnectionState::Connected,
            )),
            ConnectionState::Terminate => Err(FsmStateError::InvalidConnectionStateTransition(
                BgpEvent::OpenCollisionDump,
                fsm_state,
                ConnectionState::Terminate,
                ConnectionState::Terminate,
            )),
            ConnectionState::OpenSent => Ok(FsmState::OpenSent),
            ConnectionState::OpenConfirm => Ok(FsmState::OpenConfirm),
            ConnectionState::Established => Ok(FsmState::Established),
        }
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
                ConnectionEvent::NotifMsgErr(_) => {
                    // Ignore notif message parsing errors
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
                match event {
                    ConnectionEvent::NotifMsgErr(_) => {
                        // Ignore notif message parsing errors
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
                    ConnectionEvent::KeepAliveTimerExpires | ConnectionEvent::NotifMsgErr(_) => {
                        // stay in the same FSM state
                        // Ignore notif message parsing errors
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
                    | ConnectionEvent::RouteRefresh(_)
                    | ConnectionEvent::NotifMsgErr(_) => {
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
        peer_key: K,
        peer_addr: A,
        active_connect: &mut C,
        fsm_state: FsmState,
        connect_timeout: Duration,
        allowed_to_active_connect: &mut bool,
    ) -> Result<I, ConnectError> {
        match (fsm_state, &allowed_to_active_connect) {
            (FsmState::Connect, true) => {
                log::info!("[{peer_key}][{fsm_state}] Connecting to peer: {peer_addr}");
                *allowed_to_active_connect = false;
                match tokio::time::timeout(connect_timeout, active_connect.connect(peer_addr)).await
                {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(err)) => {
                        log::info!(
                            "[{peer_key}][{fsm_state}] Couldn't establish connection: {err:?}"
                        );
                        Err(ConnectError::TcpConnectionFails)
                    }
                    Err(_) => {
                        log::info!("[{peer_key}][{fsm_state}] Timeout establishing connection");
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
        connection: &mut Option<&mut Connection<A, I, D>>,
    ) -> Result<BgpOpenMessage, ()> {
        if fsm_state == FsmState::Connect
            || connection.as_ref().map(|x| x.state()) == Some(ConnectionState::OpenConfirm)
        {
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

    fn check_connection_collision(
        my_bgp_id: Ipv4Addr,
        connection: &mut Option<&mut Connection<A, I, D>>,
        tracked_connection: &mut Option<&mut Connection<A, I, D>>,
    ) -> Option<CollisionCheckRet> {
        let main_info = if let Some((Some(id), time)) = connection
            .as_ref()
            .map(|x| (x.peer_bgp_id(), x.stats().created()))
        {
            Some((id, time))
        } else {
            None
        };

        let tracked_info = if let Some((Some(id), time)) = tracked_connection
            .as_ref()
            .map(|x| (x.peer_bgp_id(), x.stats().created()))
        {
            Some((id, time))
        } else {
            None
        };
        if let (
            Some((main_peer_bgp_id, main_created)),
            Some((tracked_peer_bgp_id, tracked_created)),
        ) = (main_info, tracked_info)
        {
            // This is not part of the BGP Spec, currently it's not defined if the BGP
            // Peer ID signaled in main and tracked connections are different.
            // We take the one in the main connection as the reference one and close the
            // tracked connection.
            if tracked_peer_bgp_id != main_peer_bgp_id {
                return Some(CollisionCheckRet::InvalidTrackedBgpId(tracked_peer_bgp_id));
            }
            let peer_bgp_id = main_peer_bgp_id;
            if my_bgp_id < peer_bgp_id
                || (my_bgp_id == peer_bgp_id && tracked_created < main_created)
            {
                Some(CollisionCheckRet::DropMain)
            } else {
                Some(CollisionCheckRet::DropTracked)
            }
        } else {
            None
        }
    }

    /// Poll the main and tracked connections to get the next
    /// [ConnectionNextEvent] event to be handled by the BGP FSM.
    async fn next_connection_event(
        my_bgp_id: Ipv4Addr,
        fsm_state: FsmState,
        policy: &mut P,
        mut connection: Option<&mut Connection<A, I, D>>,
        mut tracked_connection: Option<&mut Connection<A, I, D>>,
    ) -> ConnectionNextEvent<A> {
        // Looping to till one event is produced. Note this is because we ignore tracked
        // connection events and we wait for either main connection event or a
        // collision detection event.
        loop {
            let event = tokio::select! {
                event = Self::get_connection_event(&mut connection) => {
                    let check = Self::check_connection_collision(
                        my_bgp_id,
                        &mut connection,
                        &mut tracked_connection);
                    match check {
                        Some(CollisionCheckRet::DropMain) => Some(ConnectionNextEvent::DropMain),
                        Some(CollisionCheckRet::DropTracked) => Some(ConnectionNextEvent::DropTracked),
                        Some(CollisionCheckRet::InvalidTrackedBgpId(peer_id)) => {
                            if let Some(tracked) = tracked_connection.take() {
                                let _ = tracked.send(
                                    BgpMessage::Notification(
                                        BgpNotificationMessage::OpenMessageError(
                                            OpenMessageError::BadBgpIdentifier {
                                                value: peer_id.octets().to_vec()}))).await;
                            }
                            None
                        },
                        None => {
                             Some(ConnectionNextEvent::Event(event))
                        }
                    }
                }
                _ = Self::get_tracked_connection_event(fsm_state, policy, &mut tracked_connection) => {
                    let check = Self::check_connection_collision(
                        my_bgp_id,
                        &mut connection,
                        &mut tracked_connection);
                    match check {
                        Some(CollisionCheckRet::DropMain) => Some(ConnectionNextEvent::DropMain),
                        Some(CollisionCheckRet::DropTracked) => Some(ConnectionNextEvent::DropTracked),
                        Some(CollisionCheckRet::InvalidTrackedBgpId(peer_id)) => {
                            if let Some(tracked) = tracked_connection.take() {
                                let _ = tracked.send(
                                    BgpMessage::Notification(
                                        BgpNotificationMessage::OpenMessageError(
                                            OpenMessageError::BadBgpIdentifier {
                                                value: peer_id.octets().to_vec()}))).await;
                            }
                            None
                        },
                        None => {
                             None
                        }
                    }
                }
            };
            if let Some(event) = event {
                return event;
            }
        }
    }

    async fn handle_connect_event(&mut self, event: ConnectionNextEvent<A>) -> PeerResult<A> {
        match event {
            ConnectionNextEvent::DropMain => {
                if let Some(tracked) = self.tracked_connection.take() {
                    self.stats.connect_retry_counter += 1;
                    let new_state = Self::fsm_state_from_tracked(self.fsm_state, &tracked)?;
                    log::info!(
                        "[{}][{}] BGP Collision replacing main connection with tracked connection: {}",
                        self.peer_key, self.fsm_state, tracked.peer_addr());
                    self.fsm_transition(new_state);
                    if let Some(mut connection) = self.connection.take() {
                        let _ = connection
                            .send(BgpMessage::Notification(
                                BgpNotificationMessage::CeaseError(
                                    CeaseError::ConnectionCollisionResolution { value: vec![] },
                                ),
                            ))
                            .await;
                    }
                    self.connection.replace(tracked);
                }

                Ok(BgpEvent::OpenCollisionDump)
            }
            ConnectionNextEvent::DropTracked => {
                if let Some(mut tracked) = self.tracked_connection.take() {
                    log::info!(
                        "[{}][{}] BGP Collision detection dropping tracked connection: {}",
                        self.peer_key,
                        self.fsm_state,
                        tracked.peer_addr()
                    );
                    let _ = tracked
                        .send(BgpMessage::Notification(
                            BgpNotificationMessage::CeaseError(
                                CeaseError::ConnectionCollisionResolution { value: vec![] },
                            ),
                        ))
                        .await;
                }
                Ok(BgpEvent::OpenCollisionDump)
            }
            ConnectionNextEvent::Event(event) => self.handle_connection_event(event).await,
        }
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
                self.peer_key,
                self.properties.peer_addr,
                &mut self.active_connect,
                self.fsm_state,
                // Arbitrary one second timeout if connect retry duration is very small
                self.config.connect_retry_duration().add(Duration::from_secs(1)),
                &mut self.allowed_to_active_connect)
            => {
                self.handle_active_connection(connect_result).await
            }
            _ = async {
                    match self.connect_retry_timer.as_mut() {
                        Some(interval) => {
                            interval.tick().await;
                        },
                        None => std::future::pending().await,
                    }
                }
            => {
                if self.fsm_state == FsmState::Active {
                    self.fsm_transition(FsmState::Connect);
                }
                self.allowed_to_active_connect = self.fsm_state == FsmState::Connect;
                self.connection.take();
                Ok(BgpEvent::ConnectRetryTimerExpires)
            }
            value = Self::next_connection_event(
                self.properties.my_bgp_id,
                self.fsm_state,
                &mut self.policy,
                self.connection.as_mut(),
                self.tracked_connection.as_mut())
            => {
               self.handle_connect_event(value).await
            }
        }
    }
}
