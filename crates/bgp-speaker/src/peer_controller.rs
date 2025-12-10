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
    connection::{ActiveConnect, ConnectionStats},
    events::BgpEvent,
    fsm::{FsmState, FsmStateError},
    peer::*,
};
use netgauze_bgp_pkt::{
    BgpMessage,
    capabilities::BgpCapability,
    codec::{BgpCodecDecoderError, BgpCodecInitializer},
    wire::{deserializer::BgpParsingIgnoredErrors, serializer::BgpMessageWritingError},
};
use std::{
    error::Error,
    fmt::{Debug, Display},
    marker::PhantomData,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, mpsc::error::SendError, oneshot},
    task::JoinHandle,
};
use tokio_util::codec::{Decoder, Encoder};

pub type PeerStateResult<A> = Result<(FsmState, BgpEvent<A>), FsmStateError<A>>;

type PeerJoinHandle<A> = JoinHandle<Result<(), SendError<PeerStateResult<A>>>>;

#[derive(Debug)]
pub struct PeerController<K, A, I: AsyncWrite + AsyncRead> {
    properties: PeerProperties<A>,
    join_handle: PeerJoinHandle<A>,
    peer_events_tx: mpsc::UnboundedSender<PeerEvent<A, I>>,
    _marker: PhantomData<K>,
}

impl<
    K: Display + Copy + Send + Sync + 'static,
    A: Display + Debug + Copy + Send + Sync + 'static,
    I: AsyncWrite + AsyncRead + Send + Unpin + 'static,
> PeerController<K, A, I>
{
    pub fn new<
        D: BgpCodecInitializer<Peer<K, A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send
            + Sync,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
        P: PeerPolicy<A, I, D> + Send + Sync + 'static,
    >(
        peer_key: K,
        properties: PeerProperties<A>,
        config: PeerConfig,
        received_events_tx: mpsc::UnboundedSender<PeerStateResult<A>>,
        policy: P,
        active_connect: C,
    ) -> Self {
        let (join_handle, peer_events_tx) = Self::start_peer(
            peer_key,
            properties,
            config,
            received_events_tx,
            policy,
            active_connect,
        );
        Self {
            properties,
            join_handle,
            peer_events_tx,
            _marker: PhantomData,
        }
    }

    pub async fn handle_peer_event<
        D: BgpCodecInitializer<Peer<K, A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>,
        C: ActiveConnect<A, I, D> + Send,
        P: PeerPolicy<A, I, D>,
    >(
        peer: &mut Peer<K, A, I, D, C, P>,
        peer_event: Option<PeerEvent<A, I>>,
    ) -> Result<(), FsmStateError<A>> {
        if let Some(event) = peer_event {
            match event {
                PeerEvent::Admin(admin_event) => {
                    peer.add_admin_event(admin_event);
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
                PeerEvent::ConnectionSentCapabilities(tx) => {
                    let caps = peer.main_connection_sent_capabilities();
                    if let Err(err) = tx.send(caps) {
                        log::error!("Error sending main connection sent capabilities: {err:?}");
                    }
                }
                PeerEvent::ConnectionReceivedCapabilities(tx) => {
                    let caps = peer.main_connection_received_capabilities();
                    if let Err(err) = tx.send(caps) {
                        log::error!("Error sending main connection received capabilities: {err:?}");
                    }
                }
                PeerEvent::TrackedConnectionSentCapabilities(tx) => {
                    let caps = peer.tracked_connection_sent_capabilities();
                    if let Err(err) = tx.send(caps) {
                        log::error!("Error sending tracked sent tracked capabilities: {err:?}");
                    }
                }
                PeerEvent::TrackedConnectionReceivedCapabilities(tx) => {
                    let caps = peer.tracked_connection_received_capabilities();
                    if let Err(err) = tx.send(caps) {
                        log::error!(
                            "Error sending tracked connection received capabilities: {err:?}"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_bgp_event(
        bgp_event: PeerResult<A>,
        peer_key: K,
        fsm_state: FsmState,
        rec_tx: mpsc::UnboundedSender<PeerStateResult<A>>,
    ) -> Result<(), ()> {
        log::debug!(
            "[{}][{}] BGP Event {}",
            peer_key,
            fsm_state,
            match &bgp_event {
                Ok(event) => format!("{event}"),
                Err(err) => format!("{err}"),
            }
        );
        match bgp_event {
            Ok(event) => {
                if let Err(err) = rec_tx.send(Ok((fsm_state, event))) {
                    log::error!(
                        "[{peer_key}][{fsm_state}] Couldn't send BGP event message, terminating the connection: {err:?}"
                    );
                    return Err(());
                }
                Ok(())
            }
            Err(err) => {
                log::error!(
                    "[{peer_key}][{fsm_state}] Terminating Peer due to error in handling BgpEvent: {err}"
                );
                if let Err(err) = rec_tx.send(Err(err)) {
                    log::error!(
                        "[{peer_key}][{fsm_state}] Couldn't report error in handling BgpEvent: {err:?}"
                    );
                    return Err(());
                }
                Err(())
            }
        }
    }

    fn start_peer<
        D: BgpCodecInitializer<Peer<K, A, I, D, C, P>>
            + Decoder<Item = (BgpMessage, BgpParsingIgnoredErrors), Error = BgpCodecDecoderError>
            + Encoder<BgpMessage, Error = BgpMessageWritingError>
            + Send,
        C: ActiveConnect<A, I, D> + Send + Sync + 'static,
        P: PeerPolicy<A, I, D> + Send + Sync + 'static,
    >(
        peer_key: K,
        properties: PeerProperties<A>,
        config: PeerConfig,
        received_events_tx: mpsc::UnboundedSender<PeerStateResult<A>>,
        policy: P,
        active_connect: C,
    ) -> (PeerJoinHandle<A>, mpsc::UnboundedSender<PeerEvent<A, I>>) {
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();
        let rec_tx = received_events_tx.clone();
        let handle = tokio::spawn(async move {
            let mut peer = Peer::new(peer_key, properties, config, policy, active_connect);
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
                        let ret = Self::handle_bgp_event(bgp_event, peer_key,peer.fsm_state(), rec_tx.clone());
                        if ret.is_err() {
                            // Errors should be logged in [Self::handle_bgp_event]
                            break;
                        }
                    }
                }
            }
            Ok(())
        });
        (handle, peer_tx)
    }

    pub fn peer_addr(&self) -> A {
        self.properties.peer_addr()
    }

    pub fn get_new_handle(&self) -> PeerHandle<A, I> {
        PeerHandle::new(self.peer_events_tx.clone(), self.properties.peer_addr())
    }
}

impl<K, A, I: AsyncWrite + AsyncRead> Drop for PeerController<K, A, I> {
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

    pub async fn connection_sent_capabilities(
        &mut self,
    ) -> Result<Option<Vec<BgpCapability>>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        self.peer_events_tx
            .send(PeerEvent::ConnectionSentCapabilities(tx))?;
        Ok(rx.await?)
    }

    pub async fn connection_received_capabilities(
        &mut self,
    ) -> Result<Option<Vec<BgpCapability>>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        self.peer_events_tx
            .send(PeerEvent::ConnectionReceivedCapabilities(tx))?;
        Ok(rx.await?)
    }

    pub async fn tracked_connection_sent_capabilities(
        &mut self,
    ) -> Result<Option<Vec<BgpCapability>>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        self.peer_events_tx
            .send(PeerEvent::TrackedConnectionSentCapabilities(tx))?;
        Ok(rx.await?)
    }

    pub async fn tracked_connection_received_capabilities(
        &mut self,
    ) -> Result<Option<Vec<BgpCapability>>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        self.peer_events_tx
            .send(PeerEvent::TrackedConnectionReceivedCapabilities(tx))?;
        Ok(rx.await?)
    }
}
