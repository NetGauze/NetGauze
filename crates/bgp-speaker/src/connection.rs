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

use chrono::prelude::*;
use futures::{Sink, Stream, StreamExt};
use futures_util::{FutureExt, SinkExt};

use pin_project::pin_project;
use std::{
    fmt::{Debug, Display},
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::codec::{Decoder, Encoder, Framed};

use netgauze_bgp_pkt::{
    capabilities::BgpCapability,
    codec::{BgpCodec, BgpCodecDecoderError},
    iana::PathAttributeType,
    notification::{
        BgpNotificationMessage, FiniteStateMachineError, HoldTimerExpiredError, OpenMessageError,
        UpdateMessageError,
    },
    open::BgpOpenMessage,
    path_attribute::{InvalidPathAttribute, PathAttributeValue},
    update::BgpUpdateMessage,
    wire::{
        deserializer::{
            path_attribute::{
                MpReachParsingError, MpUnreachParsingError, PathAttributeParsingError,
            },
            BgpParsingIgnoredErrors,
        },
        serializer::BgpMessageWritingError,
    },
    BgpMessage,
};
use netgauze_iana::address_family::{AddressFamily, SubsequentAddressFamily};

use crate::{
    events::{ConnectionEvent, UpdateTreatment},
    fsm::FsmStateError,
    peer::{PeerConfig, PeerPolicy, PeerProperties},
};

#[derive(Debug, Default, Copy, Clone)]
pub struct ConnectionStats {
    created: DateTime<Utc>,
    messages_received: u64,
    messages_sent: u64,
    open_received: u64,
    open_sent: u64,
    update_received: u64,
    update_sent: u64,
    keepalive_received: u64,
    keepalive_sent: u64,
    notification_received: u64,
    notification_sent: u64,
    route_refresh_received: u64,
    route_refresh_sent: u64,
    last_received: Option<DateTime<Utc>>,
    last_sent: Option<DateTime<Utc>>,
}

impl ConnectionStats {
    pub const fn created(&self) -> DateTime<Utc> {
        self.created
    }

    pub const fn messages_received(&self) -> u64 {
        self.messages_received
    }

    pub const fn messages_sent(&self) -> u64 {
        self.messages_sent
    }

    pub const fn open_received(&self) -> u64 {
        self.open_received
    }

    pub const fn open_sent(&self) -> u64 {
        self.open_sent
    }

    pub const fn update_received(&self) -> u64 {
        self.update_received
    }

    pub const fn update_sent(&self) -> u64 {
        self.update_sent
    }

    pub const fn keepalive_received(&self) -> u64 {
        self.keepalive_received
    }

    pub const fn keepalive_sent(&self) -> u64 {
        self.keepalive_sent
    }

    pub const fn notification_received(&self) -> u64 {
        self.notification_received
    }

    pub const fn notification_sent(&self) -> u64 {
        self.notification_sent
    }

    pub const fn route_refresh_received(&self) -> u64 {
        self.route_refresh_received
    }

    pub const fn route_refresh_sent(&self) -> u64 {
        self.route_refresh_sent
    }

    pub const fn last_received(&self) -> Option<DateTime<Utc>> {
        self.last_received
    }

    pub const fn last_sent(&self) -> Option<DateTime<Utc>> {
        self.last_sent
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, strum_macros::Display)]
pub enum ConnectionState {
    /// Tcp Connection is established either in [crate::fsm::FsmState::Connect]
    /// or [crate::fsm::FsmState::Active]
    Connected,

    /// Equivalent to [crate::fsm::FsmState::OpenSent]
    OpenSent,

    /// Equivalent to [crate::fsm::FsmState::OpenConfirm]
    OpenConfirm,

    /// Equivalent to [crate::fsm::FsmState::Established]
    Established,

    /// Connection terminated and is marked for deletion
    Terminate,
}

/// Connection type with respect to initiation. Active connection is when the
/// local node request Tcp Connection. Passive connection is when the local node
/// received a connection request.
#[derive(Debug, Copy, Clone, Eq, PartialEq, strum_macros::Display)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum ConnectionType {
    Active,
    Passive,
}

/// User-configuration for connection.
///
/// For duration config, unsigned numbers are used to represent values in
/// seconds. They're lighter and naturally keep upper bounds on the max values
/// over custom runtime checks needed if `Duration` is used.
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ConnectionConfig {
    send_notif_without_open: bool,
    open_delay_timer_duration: u16,
    hold_timer_duration: u16,
    hold_timer_duration_large_value: u16,
    keepalive_timer_duration: u16,
    idle_hold_duration: u16,
}

impl ConnectionConfig {
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
}
impl From<&PeerConfig> for ConnectionConfig {
    fn from(peer_config: &PeerConfig) -> Self {
        Self {
            send_notif_without_open: peer_config.send_notif_without_open(),
            open_delay_timer_duration: peer_config.open_delay_timer_duration,
            hold_timer_duration: peer_config.hold_timer_duration,
            hold_timer_duration_large_value: peer_config.hold_timer_duration_large_value,
            keepalive_timer_duration: peer_config.keepalive_timer_duration,
            idle_hold_duration: peer_config.idle_hold_duration,
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            send_notif_without_open: true,
            open_delay_timer_duration: 0,
            hold_timer_duration: 180,
            // RFC 4271 recommends hold timer large value to be 4 minutes
            hold_timer_duration_large_value: 240,
            keepalive_timer_duration: 30,
            idle_hold_duration: 1,
        }
    }
}

#[derive(Debug, Default)]
pub struct ConnectionConfigBuilder {
    config: ConnectionConfig,
}

impl ConnectionConfigBuilder {
    pub fn new() -> ConnectionConfigBuilder {
        Self {
            config: ConnectionConfig::default(),
        }
    }

    pub const fn send_notif_without_open(mut self, value: bool) -> Self {
        self.config.send_notif_without_open = value;
        self
    }

    pub const fn open_delay_timer_duration(mut self, value: u16) -> Self {
        self.config.open_delay_timer_duration = value;
        self
    }

    pub fn hold_timer_duration(mut self, value: u16) -> Self {
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

    pub const fn build(self) -> ConnectionConfig {
        self.config
    }
}

/// Maintain the connection and associated state to a remote peer
#[derive(Debug)]
#[pin_project]
pub struct Connection<
    A,
    I: AsyncRead + AsyncWrite,
    D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
        + Encoder<BgpMessage, Error = BgpMessageWritingError>,
> {
    peer_addr: A,
    state: ConnectionState,
    connection_type: ConnectionType,
    config: ConnectionConfig,
    my_asn: u32,
    #[pin]
    peer_asn: Option<u32>,
    my_bgp_id: Ipv4Addr,
    #[pin]
    peer_bgp_id: Option<Ipv4Addr>,
    #[pin]
    sent_capabilities: Option<Vec<BgpCapability>>,
    received_capabilities: Option<Vec<BgpCapability>>,
    peer_hold_time: Option<u16>,
    remote_bgp_id: Option<Ipv4Addr>,
    #[pin]
    inner: Framed<I, D>,
    #[pin]
    stats: ConnectionStats,
    #[pin]
    keepalive_timer: Option<tokio::time::Interval>,
    keepalive_timer_duration: Duration,
    #[pin]
    open_delay_timer: Option<tokio::time::Interval>,
    #[pin]
    hold_timer: Option<tokio::time::Interval>,
    hold_timer_duration: Duration,
    /// RFC 4721: A given BGP speaker MAY apply the same jitter to each of these
    /// quantities, regardless of the destinations to which the updates are
    /// being sent; that is, jitter need not be configured on a per-peer basis.
    /// The suggested default amount of jitter SHALL be determined by
    /// multiplying the base value of the appropriate timer by a random factor,
    /// which is uniformly distributed in the range from 0.75 to 1.0.
    #[pin]
    jitter: f32,
}

impl<
        A: Clone + Display,
        I: AsyncRead + AsyncWrite + Unpin,
        D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>,
    > Connection<A, I, D>
{
    pub fn new(
        peer_properties: &PeerProperties<A>,
        peer_addr: A,
        connection_type: ConnectionType,
        config: ConnectionConfig,
        inner: Framed<I, D>,
        jitter: f32,
    ) -> Self {
        let my_asn = peer_properties.my_asn();
        let peer_asn = if peer_properties.allow_dynamic_as() {
            None
        } else {
            Some(peer_properties.peer_asn())
        };
        let my_bgp_id = peer_properties.my_bgp_id();

        Self {
            peer_addr,
            state: ConnectionState::Connected,
            connection_type,
            config,
            my_asn,
            peer_asn,
            my_bgp_id,
            peer_bgp_id: None,
            sent_capabilities: None,
            received_capabilities: None,
            peer_hold_time: None,
            remote_bgp_id: None,
            inner,
            stats: ConnectionStats::default(),
            keepalive_timer: None,
            keepalive_timer_duration: config.keepalive_timer_duration(),
            open_delay_timer: None,
            hold_timer: None,
            hold_timer_duration: config.hold_timer_duration(),
            jitter,
        }
    }

    pub const fn peer_addr(&self) -> &A {
        &self.peer_addr
    }

    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    pub const fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    pub const fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    pub const fn keepalive_timer_duration(&self) -> Duration {
        self.keepalive_timer_duration
    }

    pub const fn keepalive_timer(&self) -> Option<&tokio::time::Interval> {
        self.keepalive_timer.as_ref()
    }

    pub const fn hold_timer_duration(&self) -> Duration {
        self.hold_timer_duration
    }

    pub const fn hold_timer(&self) -> Option<&tokio::time::Interval> {
        self.hold_timer.as_ref()
    }

    pub const fn open_delay_timer(&self) -> Option<&tokio::time::Interval> {
        self.open_delay_timer.as_ref()
    }

    pub const fn peer_bgp_id(&self) -> Option<Ipv4Addr> {
        self.peer_bgp_id
    }

    pub const fn connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    pub const fn sent_capabilities(&self) -> Option<&Vec<BgpCapability>> {
        self.sent_capabilities.as_ref()
    }
    pub const fn received_capabilities(&self) -> Option<&Vec<BgpCapability>> {
        self.received_capabilities.as_ref()
    }

    fn read_open_msg(&mut self, open: &BgpOpenMessage) {
        self.peer_asn = Some(open.my_asn4());
        self.peer_bgp_id = Some(open.bgp_id());
        self.received_capabilities =
            Some(open.capabilities().iter().map(|x| (*x).clone()).collect());
        self.peer_hold_time = Some(open.hold_time());
    }

    fn set_negotiated_timers(&mut self) {
        // Peer is configured not to use any timers
        if self.config.hold_timer_duration().is_zero() {
            self.hold_timer_duration = Duration::from_secs(0);
            self.keepalive_timer_duration = Duration::from_secs(0);
            return;
        }

        match self.peer_hold_time {
            Some(received_hold_time) => {
                self.hold_timer_duration = Duration::from_secs(
                    self.config.hold_timer_duration.min(received_hold_time) as u64,
                );
            }
            None => {
                self.hold_timer_duration = self.config.hold_timer_duration_large_value();
            }
        }
        self.keepalive_timer_duration = self.hold_timer_duration.div_f32(3.0);
    }

    #[inline]
    fn start_hold_timer(&mut self) {
        if self.config.hold_timer_duration_large_value != 0 {
            log::debug!(
                "[{}][{}] Set hold timer to: {:?}",
                self.peer_addr,
                self.state,
                self.config.hold_timer_duration_large_value
            );
            self.hold_timer_duration = self.config.hold_timer_duration_large_value();
            let mut interval = tokio::time::interval(self.hold_timer_duration);
            interval.reset();
            self.hold_timer.replace(interval);
        }
    }

    pub async fn handle_event<P: PeerPolicy<A, I, D>>(
        &mut self,
        policy: &mut P,
        event: ConnectionEvent<A>,
    ) -> Result<ConnectionEvent<A>, FsmStateError<A>> {
        if log::log_enabled!(log::Level::Debug) {
            log::debug!("[{}][{}] handling: {}", self.peer_addr, self.state, event);
        }
        let pre_state = self.state;
        let post_event = match pre_state {
            ConnectionState::Terminate => {
                // Events are ignored once connection is marked for termination
                event
            }
            ConnectionState::Connected => self.handle_connected_event(policy, event).await?,
            ConnectionState::OpenSent => self.handle_open_sent_event(event).await?,
            ConnectionState::OpenConfirm => self.handle_open_confirm_event(event).await?,
            ConnectionState::Established => self.handle_established_event(event).await?,
        };
        if self.state != pre_state {
            if log::log_enabled!(log::Level::Debug) {
                log::debug!(
                    "[{}][{}] Transitioned from {pre_state:?} to {:?} on event: {post_event}",
                    self.peer_addr,
                    self.state,
                    self.state
                );
            } else {
                log::info!(
                    "[{}][{}] Transitioned from {pre_state:?} to {:?}",
                    self.peer_addr,
                    self.state,
                    self.state
                );
            }
        }
        Ok(post_event)
    }

    async fn handle_connected_event<P: PeerPolicy<A, I, D>>(
        &mut self,
        policy: &mut P,
        event: ConnectionEvent<A>,
    ) -> Result<ConnectionEvent<A>, FsmStateError<A>> {
        match event {
            ConnectionEvent::DelayOpenTimerExpires => {
                self.start_hold_timer();
                let open = policy.open_message().await;
                self.send(BgpMessage::Open(open)).await?;
                self.state = ConnectionState::OpenSent;
            }
            ConnectionEvent::TcpConnectionRequestAcked(_)
            | ConnectionEvent::TcpConnectionConfirmed(_) => {
                if self.config.open_delay_timer_duration == 0 {
                    self.start_hold_timer();
                    let open = policy.open_message().await;
                    self.send(BgpMessage::Open(open)).await?;
                    self.state = ConnectionState::OpenSent;
                } else {
                    log::debug!(
                        "[{}][{}] Set open delay timer to: {:?}",
                        self.peer_addr,
                        self.state,
                        self.config.open_delay_timer_duration
                    );
                    let mut interval =
                        tokio::time::interval(self.config.open_delay_timer_duration());
                    interval.reset();
                    self.open_delay_timer.replace(interval);
                }
            }
            ConnectionEvent::BGPOpenWithDelayOpenTimer(ref open) => {
                self.open_delay_timer.take();
                self.read_open_msg(open);
                self.set_negotiated_timers();
                let open = policy.open_message().await;
                if !self.keepalive_timer_duration.is_zero() {
                    let duration = self.keepalive_timer_duration.mul_f32(self.jitter);
                    let mut interval = tokio::time::interval(duration);
                    interval.reset();
                    self.keepalive_timer.replace(interval);
                }
                if !self.hold_timer_duration.is_zero() {
                    let mut interval = tokio::time::interval(self.hold_timer_duration);
                    interval.reset();
                    self.hold_timer.replace(interval);
                }
                self.send(BgpMessage::Open(open)).await?;
                self.send(BgpMessage::KeepAlive).await?;
                self.state = ConnectionState::OpenConfirm;
            }
            ConnectionEvent::BGPHeaderErr(ref err) => {
                if self.config.send_notif_without_open {
                    let ret = self
                        .send(BgpMessage::Notification(
                            BgpNotificationMessage::MessageHeaderError(err.clone()),
                        ))
                        .await;
                    if let Err(send_err) = ret {
                        log::error!(
                            "[{}][{}] Error sending notification message to peer: {send_err:?}",
                            self.peer_addr,
                            self.state,
                        );
                    }
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::BGPOpenMsgErr(ref err) => {
                if self.config.send_notif_without_open {
                    let ret = self
                        .send(BgpMessage::Notification(
                            BgpNotificationMessage::OpenMessageError(err.clone()),
                        ))
                        .await;
                    if let Err(send_err) = ret {
                        log::error!(
                            "[{}][{}] Error sending notification message to peer: {send_err:?}",
                            self.peer_addr,
                            self.state,
                        );
                    }
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::NotifMsgVerErr => {
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::NotifMsgErr(ref err) => {
                log::error!(
                    "[{}][{}] Error parsing notification message from peer: {err:?}",
                    self.peer_addr,
                    self.state,
                );
            }
            ConnectionEvent::HoldTimerExpires
            | ConnectionEvent::KeepAliveTimerExpires
            | ConnectionEvent::TcpConnectionFails
            | ConnectionEvent::BGPOpen(_)
            | ConnectionEvent::NotifMsg(_)
            | ConnectionEvent::KeepAliveMsg
            | ConnectionEvent::UpdateMsg(_, _)
            | ConnectionEvent::UpdateMsgErr(_)
            | ConnectionEvent::RouteRefresh(_)
            | ConnectionEvent::RouteRefreshErr(_) => {
                self.state = ConnectionState::Terminate;
            }
        };
        Ok(event)
    }

    async fn handle_open_sent_event(
        &mut self,
        event: ConnectionEvent<A>,
    ) -> Result<ConnectionEvent<A>, FsmStateError<A>> {
        match event {
            ConnectionEvent::HoldTimerExpires => {
                let msg = BgpMessage::Notification(BgpNotificationMessage::HoldTimerExpiredError(
                    HoldTimerExpiredError::Unspecific {
                        sub_code: 0,
                        value: vec![],
                    },
                ));
                self.send(msg).await?;
                self.state = ConnectionState::Terminate;
            }

            ConnectionEvent::BGPOpen(ref open) => {
                self.open_delay_timer.take();
                self.read_open_msg(open);
                self.set_negotiated_timers();
                if !self.keepalive_timer_duration.is_zero() {
                    let duration = self.keepalive_timer_duration.mul_f32(self.jitter);
                    let mut interval = tokio::time::interval(duration);
                    interval.reset();
                    self.keepalive_timer.replace(interval);
                }
                if !self.hold_timer_duration.is_zero() {
                    let mut interval = tokio::time::interval(self.hold_timer_duration);
                    interval.reset();
                    self.hold_timer.replace(interval);
                }
                self.send(BgpMessage::KeepAlive).await?;
                self.state = ConnectionState::OpenConfirm;
            }
            ConnectionEvent::TcpConnectionFails => {
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::BGPHeaderErr(ref err) => {
                let notif = BgpNotificationMessage::MessageHeaderError(err.clone());
                let ret = self.send(BgpMessage::Notification(notif)).await;
                if let Err(send_err) = ret {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {send_err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::BGPOpenMsgErr(ref err) => {
                let notif = BgpNotificationMessage::OpenMessageError(err.clone());
                let ret = self.send(BgpMessage::Notification(notif)).await;
                if let Err(send_err) = ret {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {send_err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::NotifMsgErr(ref err) => {
                log::error!(
                    "[{}][{}] Error parsing notification message from peer: {err:?}",
                    self.peer_addr,
                    self.state,
                );
            }
            ConnectionEvent::NotifMsgVerErr => self.state = ConnectionState::Terminate,
            ConnectionEvent::KeepAliveTimerExpires
            | ConnectionEvent::DelayOpenTimerExpires
            | ConnectionEvent::BGPOpenWithDelayOpenTimer(_)
            | ConnectionEvent::NotifMsg(_)
            | ConnectionEvent::KeepAliveMsg
            | ConnectionEvent::UpdateMsg(_, _)
            | ConnectionEvent::UpdateMsgErr(_)
            | ConnectionEvent::RouteRefresh(_)
            | ConnectionEvent::RouteRefreshErr(_) => {
                let notif = BgpNotificationMessage::FiniteStateMachineError(
                    FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState {
                        value: vec![],
                    },
                );
                if let Err(err) = self.send(BgpMessage::Notification(notif)).await {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::TcpConnectionRequestAcked(_)
            | ConnectionEvent::TcpConnectionConfirmed(_) => {
                self.state = ConnectionState::Terminate;
            }
        }
        Ok(event)
    }

    async fn handle_open_confirm_event(
        &mut self,
        event: ConnectionEvent<A>,
    ) -> Result<ConnectionEvent<A>, FsmStateError<A>> {
        match event {
            ConnectionEvent::HoldTimerExpires => {
                let msg = BgpMessage::Notification(BgpNotificationMessage::HoldTimerExpiredError(
                    HoldTimerExpiredError::Unspecific {
                        sub_code: 0,
                        value: vec![],
                    },
                ));
                self.state = ConnectionState::Terminate;
                self.send(msg).await?;
            }
            ConnectionEvent::KeepAliveTimerExpires => {
                self.send(BgpMessage::KeepAlive).await?;
            }
            ConnectionEvent::NotifMsgVerErr => self.state = ConnectionState::Terminate,
            ConnectionEvent::NotifMsg(_) => self.state = ConnectionState::Terminate,
            ConnectionEvent::BGPHeaderErr(ref err) => {
                let notif = BgpNotificationMessage::MessageHeaderError(err.clone());
                let ret = self.send(BgpMessage::Notification(notif)).await;
                if let Err(send_err) = ret {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {send_err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::BGPOpenMsgErr(ref err) => {
                let notif = BgpNotificationMessage::OpenMessageError(err.clone());
                if let Err(send_err) = self.send(BgpMessage::Notification(notif)).await {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {send_err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::BGPOpen(_) => {
                let notif = BgpNotificationMessage::FiniteStateMachineError(
                    FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
                        value: vec![],
                    },
                );
                let ret = self.send(BgpMessage::Notification(notif)).await;
                if let Err(send_err) = ret {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {send_err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::KeepAliveMsg => {
                if let Some(x) = self.hold_timer.as_mut() {
                    x.reset()
                }
                self.state = ConnectionState::Established;
            }
            ConnectionEvent::TcpConnectionFails => {
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::NotifMsgErr(ref err) => {
                log::error!(
                    "[{}][{}] Error parsing notification message from peer: {err:?}",
                    self.peer_addr,
                    self.state,
                );
            }
            ConnectionEvent::DelayOpenTimerExpires
            | ConnectionEvent::BGPOpenWithDelayOpenTimer(_)
            | ConnectionEvent::UpdateMsg(_, _)
            | ConnectionEvent::UpdateMsgErr(_)
            | ConnectionEvent::RouteRefresh(_)
            | ConnectionEvent::RouteRefreshErr(_) => {
                let notif = BgpNotificationMessage::FiniteStateMachineError(
                    FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
                        value: vec![],
                    },
                );
                if let Err(err) = self.send(BgpMessage::Notification(notif)).await {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::TcpConnectionRequestAcked(_)
            | ConnectionEvent::TcpConnectionConfirmed(_) => {
                self.state = ConnectionState::Terminate;
            }
        }
        Ok(event)
    }

    async fn handle_established_event(
        &mut self,
        event: ConnectionEvent<A>,
    ) -> Result<ConnectionEvent<A>, FsmStateError<A>> {
        match event {
            ConnectionEvent::HoldTimerExpires => {
                let notif = BgpNotificationMessage::HoldTimerExpiredError(
                    HoldTimerExpiredError::Unspecific {
                        sub_code: 0,
                        value: vec![],
                    },
                );
                if let Err(err) = self.send(BgpMessage::Notification(notif)).await {
                    log::error!(
                        "[{}][{}] Error sending notification message to peer: {err:?}",
                        self.peer_addr,
                        self.state,
                    );
                }
                self.state = ConnectionState::Terminate
            }
            ConnectionEvent::KeepAliveTimerExpires => {
                self.send(BgpMessage::KeepAlive).await?;
            }
            ConnectionEvent::DelayOpenTimerExpires => self.state = ConnectionState::Terminate,
            ConnectionEvent::BGPOpen(_) => self.state = ConnectionState::Terminate,
            ConnectionEvent::BGPOpenWithDelayOpenTimer(_) => {
                self.state = ConnectionState::Terminate
            }
            ConnectionEvent::BGPHeaderErr(_) => self.state = ConnectionState::Terminate,
            ConnectionEvent::BGPOpenMsgErr(_) => self.state = ConnectionState::Terminate,
            ConnectionEvent::NotifMsgVerErr => self.state = ConnectionState::Terminate,
            ConnectionEvent::NotifMsg(_) => {
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::KeepAliveMsg => {
                if let Some(x) = self.hold_timer.as_mut() {
                    x.reset()
                }
            }
            ConnectionEvent::UpdateMsg(_, _) | ConnectionEvent::RouteRefresh(_) => {}
            ConnectionEvent::UpdateMsgErr(_) => self.state = ConnectionState::Terminate,
            ConnectionEvent::RouteRefreshErr(_) => self.state = ConnectionState::Terminate,
            ConnectionEvent::TcpConnectionFails => {
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::TcpConnectionRequestAcked(_)
            | ConnectionEvent::TcpConnectionConfirmed(_) => {
                self.state = ConnectionState::Terminate;
            }
            ConnectionEvent::NotifMsgErr(ref err) => {
                log::error!(
                    "[{}][{}] Error parsing notification message from peer: {err:?}",
                    self.peer_addr,
                    self.state,
                );
            }
        }
        Ok(event)
    }
}

fn update_treatment(errors: &BgpParsingIgnoredErrors) -> UpdateTreatment {
    let mut treatment = UpdateTreatment::Normal;
    for path_err in errors.path_attr_errors() {
        match path_err {
            PathAttributeParsingError::NomError(_) => {
                if treatment < UpdateTreatment::TreatAsWithdraw {
                    treatment = UpdateTreatment::TreatAsWithdraw
                }
            }
            PathAttributeParsingError::OriginError(_)
            | PathAttributeParsingError::AsPathError(_)
            | PathAttributeParsingError::NextHopError(_)
            | PathAttributeParsingError::MultiExitDiscriminatorError(_)
            | PathAttributeParsingError::LocalPreferenceError(_) => {
                // RFC 7606 "Treat-as-withdraw" MUST be used for the cases that specify a
                // session reset and involve any of the attributes ORIGIN, AS_PATH,  NEXT_HOP,
                // MULTI_EXIT_DISC, or LOCAL_PREF.
                if treatment < UpdateTreatment::TreatAsWithdraw {
                    treatment = UpdateTreatment::TreatAsWithdraw
                }
            }
            PathAttributeParsingError::AtomicAggregateError(_)
            | PathAttributeParsingError::AggregatorError(_) => {
                if treatment < UpdateTreatment::AttributeDiscard {
                    treatment = UpdateTreatment::AttributeDiscard
                }
            }
            PathAttributeParsingError::CommunitiesError(_)
            | PathAttributeParsingError::ExtendedCommunitiesError(_)
            | PathAttributeParsingError::ExtendedCommunitiesErrorIpv6(_)
            | PathAttributeParsingError::LargeCommunitiesError(_) => {
                // RFC 7606 An UPDATE message with a malformed Community attribute SHALL be
                // handled using the approach of "treat-as-withdraw".
                if treatment < UpdateTreatment::TreatAsWithdraw {
                    treatment = UpdateTreatment::TreatAsWithdraw
                }
            }
            PathAttributeParsingError::OriginatorError(_) => {
                // RFC 7606  If malformed, the UPDATE message SHALL be handled using the
                // approach of "treat-as-withdraw".
                if treatment < UpdateTreatment::TreatAsWithdraw {
                    treatment = UpdateTreatment::TreatAsWithdraw
                }
            }
            PathAttributeParsingError::ClusterListError(_) => {
                // RFC 7606  If malformed, the UPDATE message SHALL be handled using the
                // approach of "treat-as-withdraw".
                if treatment < UpdateTreatment::TreatAsWithdraw {
                    treatment = UpdateTreatment::TreatAsWithdraw
                }
            }
            PathAttributeParsingError::MpReachErrorError(err) => {
                match err {
                    MpReachParsingError::NomError(_) => {
                        // No meaningful AFI/SAFI read
                        if treatment < UpdateTreatment::SessionReset {
                            treatment = UpdateTreatment::SessionReset
                        }
                    }
                    MpReachParsingError::UndefinedAddressFamily(_)
                    | MpReachParsingError::UndefinedSubsequentAddressFamily(_) => {
                        // AFI/SAFI is not supported, this would've been blocked from open message
                        // in the first place
                        if treatment < UpdateTreatment::SessionReset {
                            treatment = UpdateTreatment::SessionReset
                        }
                    }
                    MpReachParsingError::IpAddrError(address_type, _) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            address_type.address_family().into(),
                            address_type.subsequent_address_family().into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::LabeledNextHopError(address_type, _) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            address_type.address_family().into(),
                            address_type.subsequent_address_family().into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv4UnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::Unicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv4MulticastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::Multicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv4NlriMplsLabelsAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::NlriMplsLabels.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv4MplsVpnUnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::MplsVpn.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv6UnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::Unicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv6NlriMplsLabelsAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::NlriMplsLabels.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv6MulticastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::Multicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::Ipv6MplsVpnUnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::MplsVpn.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::L2EvpnAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::L2vpn.into(),
                            SubsequentAddressFamily::BgpEvpn.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::RouteTargetMembershipAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::RouteTargetConstrains.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpReachParsingError::BgpLsNlriParsingError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::RouteTargetConstrains.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                }
            }
            PathAttributeParsingError::MpUnreachErrorError(err) => {
                match err {
                    MpUnreachParsingError::NomError(_) => {
                        // No meaningful AFI/SAFI read
                        if treatment < UpdateTreatment::SessionReset {
                            treatment = UpdateTreatment::SessionReset
                        }
                    }
                    MpUnreachParsingError::UndefinedAddressFamily(_)
                    | MpUnreachParsingError::UndefinedSubsequentAddressFamily(_) => {
                        // AFI/SAFI is not supported, this would've been blocked from open message
                        // in the first place
                        if treatment < UpdateTreatment::SessionReset {
                            treatment = UpdateTreatment::SessionReset
                        }
                    }
                    MpUnreachParsingError::Ipv4UnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::Unicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::Ipv4MulticastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::Multicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::Ipv4NlriMplsLabelsAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::NlriMplsLabels.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::Ipv4MplsVpnUnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::MplsVpn.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::Ipv6UnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::Unicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::Ipv6NlriMplsLabelsAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::NlriMplsLabels.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::Ipv6MulticastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::Multicast.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::Ipv6MplsVpnUnicastAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv6.into(),
                            SubsequentAddressFamily::MplsVpn.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::L2EvpnAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::L2vpn.into(),
                            SubsequentAddressFamily::BgpEvpn.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::RouteTargetMembershipAddressError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::RouteTargetConstrains.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                    MpUnreachParsingError::BgpLsError(_) => {
                        let tmp = UpdateTreatment::ResetAddressFamily(
                            AddressFamily::IPv4.into(),
                            SubsequentAddressFamily::RouteTargetConstrains.into(),
                        );
                        if treatment < tmp {
                            treatment = tmp
                        }
                    }
                }
            }
            PathAttributeParsingError::OnlyToCustomerError(_) => {
                if treatment < UpdateTreatment::AttributeDiscard {
                    treatment = UpdateTreatment::AttributeDiscard
                }
            }
            PathAttributeParsingError::AigpError(_) => {
                if treatment < UpdateTreatment::AttributeDiscard {
                    treatment = UpdateTreatment::AttributeDiscard
                }
            }
            PathAttributeParsingError::UnknownAttributeError(_) => {
                // Keep treatment as is
            }
            PathAttributeParsingError::InvalidPathAttribute(err, _) => {
                // RFC 7606:  If the value of either the Optional or Transitive bits in the
                // Attribute Flags is in conflict with their specified values, then the
                // attribute MUST be treated as malformed and the "treat-as-withdraw" approach
                // used, unless the specification for the attribute mandates different handling
                // for incorrect Attribute Flags.
                match err {
                    InvalidPathAttribute::InvalidOptionalFlagValue(_)
                    | InvalidPathAttribute::InvalidTransitiveFlagValue(_) => {
                        if treatment < UpdateTreatment::TreatAsWithdraw {
                            treatment = UpdateTreatment::TreatAsWithdraw
                        }
                    }
                    InvalidPathAttribute::InvalidPartialFlagValue(_) => {
                        // Keep treatment as is
                    }
                }
            }
            PathAttributeParsingError::BgpLsError(_) => {
                if treatment < UpdateTreatment::AttributeDiscard {
                    treatment = UpdateTreatment::AttributeDiscard
                }
            }
            PathAttributeParsingError::SegmentIdentifierParsingError(_) => {
                if treatment < UpdateTreatment::AttributeDiscard {
                    treatment = UpdateTreatment::AttributeDiscard
                }
            }
        }
    }
    treatment
}

fn handle_open_message<A>(
    open: BgpOpenMessage,
    peer_asn: Option<u32>,
    delay_timer_running: bool,
) -> (Ipv4Addr, ConnectionEvent<A>) {
    // Check Peer ASN number
    if let Some(peer_asn) = peer_asn {
        if peer_asn != open.my_asn4() {
            return (
                open.bgp_id(),
                ConnectionEvent::BGPOpenMsgErr(OpenMessageError::BadPeerAs {
                    value: peer_asn.to_be_bytes().to_vec(),
                }),
            );
        }
    }
    // TODO: check BGP ID according to RFC4271: If the BGP Identifier field of the
    // OPEN message is syntactically incorrect, then the Error Subcode MUST be set
    // to Bad BGP Identifier. Syntactic correctness means that the BGP Identifier
    // field represents a valid unicast IP host address.

    if delay_timer_running {
        (
            open.bgp_id(),
            ConnectionEvent::BGPOpenWithDelayOpenTimer(open),
        )
    } else {
        (open.bgp_id(), ConnectionEvent::BGPOpen(open))
    }
}

fn handle_update_message<A>(
    update: BgpUpdateMessage,
    parsing_errors: BgpParsingIgnoredErrors,
) -> Option<ConnectionEvent<A>> {
    // RFC 7606 If any of the well-known mandatory attributes are not present in an
    // UPDATE message, then "treat-as-withdraw" MUST be used. (Note that [RFC4760]
    // reclassifies NEXT_HOP as what is effectively discretionary.)
    let end_of_rib = update.end_of_rib();
    let mut has_origin = false;
    let mut has_asn_path = false;
    let mut has_next_hop = false;
    let mut bgp_mp_reach_count = 0;
    let mut bgp_mp_unreach_count = 0;
    for attr in update.path_attributes() {
        if has_origin && has_asn_path {
            break;
        }
        if let PathAttributeValue::Origin(_) = attr.value() {
            has_origin = true;
        } else if let PathAttributeValue::AsPath(_) = attr.value() {
            has_asn_path = true;
        } else if let PathAttributeValue::As4Path(_) = attr.value() {
            has_asn_path = true;
        } else if let PathAttributeValue::NextHop(_) = attr.value() {
            has_next_hop = true;
        } else if let PathAttributeValue::MpReach(_) = attr.value() {
            bgp_mp_reach_count += 1;
        } else if let PathAttributeValue::MpUnreach(_) = attr.value() {
            bgp_mp_unreach_count += 1;
        }
    }
    if end_of_rib.is_none() && !has_origin {
        return Some(ConnectionEvent::UpdateMsgErr(
            UpdateMessageError::MissingWellKnownAttribute {
                value: vec![PathAttributeType::Origin as u8],
            },
        ));
    }
    if end_of_rib.is_none() && !has_asn_path {
        return Some(ConnectionEvent::UpdateMsgErr(
            UpdateMessageError::MissingWellKnownAttribute {
                value: vec![PathAttributeType::AsPath as u8],
            },
        ));
    }
    if end_of_rib.is_none()
        && bgp_mp_reach_count == 0
        && bgp_mp_unreach_count == 0
        && !has_next_hop
        && !update.nlri().is_empty()
    {
        // RFC7606: RFC4760 reclassifies NEXT_HOP as what is effectively discretionary.
        // Complain if BGP-MP is not used and there are reachable NLRI announced.
        return Some(ConnectionEvent::UpdateMsgErr(
            UpdateMessageError::MissingWellKnownAttribute {
                value: vec![PathAttributeType::NextHop as u8],
            },
        ));
    }
    if bgp_mp_reach_count > 1 || bgp_mp_unreach_count > 1 {
        // RFC7606: If the MP_REACH_NLRI attribute or the MP_UNREACH_NLRI [RFC4760]
        // attribute appears more than once in the UPDATE message, then a NOTIFICATION
        // message MUST be sent with the Error Subcode "Malformed Attribute List".
        return Some(ConnectionEvent::UpdateMsgErr(
            UpdateMessageError::MalformedAttributeList { value: vec![] },
        ));
    }
    let treatment = update_treatment(&parsing_errors);
    Some(ConnectionEvent::UpdateMsg(update, treatment))
}

impl<
        A: Display,
        I: AsyncRead + AsyncWrite,
        D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>,
    > Stream for Connection<A, I, D>
where
    Self: Unpin,
{
    type Item = ConnectionEvent<A>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let x = async {
            futures::select_biased! {
                _instance = async {
                    match *this.keepalive_timer.as_mut() {
                        None => std::future::pending().await,
                        Some(ref mut interval) => interval.tick().await,
                    }
                }.fuse() => {
                    Some(ConnectionEvent::KeepAliveTimerExpires)
                }
                _ = async {
                    match *this.open_delay_timer.as_mut() {
                        None => std::future::pending().await,
                        Some(ref mut interval) => {
                            interval.tick().await;
                            this.open_delay_timer.take();
                        }
                    }
                }.fuse() => {
                    Some(ConnectionEvent::DelayOpenTimerExpires)
                }
                _instance = async {
                    match *this.hold_timer.as_mut() {
                        None => std::future::pending().await,
                        Some(ref mut interval) => interval.tick().await,
                    }
                }.fuse() => {
                    Some(ConnectionEvent::HoldTimerExpires)
                }
                msg = this.inner.next().fuse() => {
                    match msg {
                        None => Some(ConnectionEvent::TcpConnectionFails),
                        Some(Err(err)) => {
                            Some(err.into())
                        },
                        Some(Ok((msg, parsing_errors))) => {
                            let current = Utc::now();
                            this.stats.messages_received += 1;
                            this.stats.last_received = Some(current);
                            match msg {
                                BgpMessage::Open(open) => {
                                    this.stats.open_received += 1;
                                    // As per RFC5492 Section 5, Capability errors are ignored
                                    if log::log_enabled!(log::Level::Debug) {
                                        for cap_err in parsing_errors.capability_errors() {
                                            log::debug!(
                                                "[{}][{}] Ignored BGP Capability parsing error: {cap_err:?}",
                                                this.peer_addr,
                                                this.state,
                                            );
                                        }
                                    }
                                    let (peer_bgp_id, event) = handle_open_message(open, *this.peer_asn, this.open_delay_timer.is_some());
                                    this.peer_bgp_id.replace(peer_bgp_id);
                                    Some(event)
                                }
                                BgpMessage::Update(update) => {
                                    this.stats.update_received += 1;
                                    handle_update_message(update, parsing_errors)
                                }
                                BgpMessage::Notification(notif) => {
                                    this.stats.notification_received += 1;
                                    // Version error have a special event in BGP FSM
                                    if let BgpNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {value: _}) = &notif {
                                        Some(ConnectionEvent::NotifMsgVerErr)
                                    } else {
                                        Some(ConnectionEvent::NotifMsg(notif))
                                    }
                                }
                                BgpMessage::RouteRefresh(refresh) => {
                                    this.stats.route_refresh_received += 1;
                                    Some(ConnectionEvent::RouteRefresh(refresh))
                                }
                                BgpMessage::KeepAlive => {
                                    this.stats.keepalive_received += 1;
                                    Some(ConnectionEvent::KeepAliveMsg)
                                }
                            }
                        }
                    }
                }
            }
        };
        futures::pin_mut!(x);
        Pin::new(&mut x).poll(cx)
    }
}

impl<
        A: Clone + Display,
        I: AsyncRead + AsyncWrite,
        D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>,
    > Sink<BgpMessage> for Connection<A, I, D>
{
    type Error = BgpMessageWritingError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, message: BgpMessage) -> Result<(), Self::Error> {
        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                "[{}][{}] Sending message: {message:?}",
                self.peer_addr,
                self.state,
            );
        }
        let mut this = self.project();
        this.stats.messages_sent += 1;
        this.stats.last_sent = Some(Utc::now());
        match &message {
            BgpMessage::Open(open) => {
                this.stats.open_sent += 1;
                this.sent_capabilities
                    .replace(open.capabilities().iter().map(|x| (*x).clone()).collect());
            }
            BgpMessage::Update(_) => {
                match *this.keepalive_timer.as_mut() {
                    None => {}
                    Some(ref mut interval) => interval.reset(),
                }
                this.stats.update_sent += 1;
            }
            BgpMessage::Notification(_) => {
                this.stats.notification_sent += 1;
            }
            BgpMessage::KeepAlive => {
                match *this.keepalive_timer.as_mut() {
                    None => {}
                    Some(ref mut interval) => interval.reset(),
                }
                this.stats.keepalive_sent += 1;
            }
            BgpMessage::RouteRefresh(_) => {
                this.stats.route_refresh_sent += 1;
            }
        }
        this.inner.start_send(message)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_close(cx)
    }
}

/// Encapsulate initiating a connection to a peer
pub trait ActiveConnect<
    P,
    I: AsyncRead + AsyncWrite,
    D: Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
        + Encoder<BgpMessage, Error = BgpMessageWritingError>,
>
{
    fn connect(&mut self, peer_addr: P) -> impl Future<Output = io::Result<I>> + Send;
}

#[derive(Debug, Clone)]
pub struct TcpActiveConnect;

impl ActiveConnect<SocketAddr, TcpStream, BgpCodec> for TcpActiveConnect {
    async fn connect(&mut self, peer_addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(peer_addr).await
    }
}
