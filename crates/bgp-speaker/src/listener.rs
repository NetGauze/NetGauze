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

use futures_core::Stream;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::connection::TcpActiveConnect;
use crate::fsm::FsmState;
use crate::peer_controller::PeerHandle;
use crate::supervisor::PeersSupervisor;
use futures_util::stream::FuturesUnordered;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

/// A modified version of Tokio's TcpListenerStream wrapper that returns the
/// peer socket along the incoming stream
#[derive(Debug)]
pub struct TcpListenerStream {
    inner: TcpListener,
}

impl TcpListenerStream {
    /// Create a new `TcpListenerStream`.
    pub fn new(listener: TcpListener) -> Self {
        Self { inner: listener }
    }

    /// Get back the inner `TcpListener`.
    pub fn into_inner(self) -> TcpListener {
        self.inner
    }
}

impl Stream for TcpListenerStream {
    type Item = io::Result<(TcpStream, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_accept(cx) {
            Poll::Ready(Ok((stream, socket))) => Poll::Ready(Some(Ok((stream, socket)))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug)]
pub struct BgpListener<A: Display, I: AsyncWrite + AsyncRead> {
    sockets: Vec<SocketAddr>,
    /// Holding PeerHandle to control peers, and indexed by ip address of the
    /// peer
    peers: HashMap<IpAddr, PeerHandle<A, I>>,
    // TODO: change the flag to a policy trait
    allow_dynamic_peers: bool,
}

impl<
    A: Clone + Display + Debug + Send + Sync + 'static,
    I: AsyncWrite + AsyncRead + Send + Unpin + 'static,
> BgpListener<A, I>
{
    pub fn new(sockets: Vec<SocketAddr>, allow_dynamic_peers: bool) -> Self {
        Self {
            sockets,
            peers: HashMap::new(),
            allow_dynamic_peers,
        }
    }

    pub fn reg_peer(&mut self, peer_ip: IpAddr, peer_handle: PeerHandle<A, I>) {
        self.peers.insert(peer_ip, peer_handle);
    }
}

impl BgpListener<SocketAddr, TcpStream> {
    async fn accept_peer_connection(
        &mut self,
        peer_key: IpAddr,
        peer_addr: SocketAddr,
        stream: TcpStream,
        peer_supervisor: &mut PeersSupervisor<IpAddr, SocketAddr, TcpStream>,
    ) {
        match self.peers.get_mut(&peer_key) {
            Some(peer_handle) => {
                info!("Accepted Connection for peer {peer_key}");
                if let Err(err) = peer_handle.accept_connection(peer_addr, stream) {
                    error!("Error sending event to peer: {err:?}");
                }
            }
            None => {
                if !self.allow_dynamic_peers {
                    info!("No peer configured for: {peer_addr}");
                } else {
                    // TODO: rewrite for more clear logic and dynamic peer handling factory
                    if let Ok((mut rx, mut peer_handle)) =
                        peer_supervisor.dynamic_peer(peer_key, peer_addr, TcpActiveConnect)
                    {
                        if let Err(err) = peer_handle.start() {
                            error!("Error starting dynamic peer: {err:?}");
                            return;
                        }
                        rx.recv().await;
                        if let Err(err) = peer_handle.accept_connection(peer_addr, stream) {
                            error!(
                                "[{peer_addr}] Dynamic connection error sending event to peer: {err:?}"
                            );
                            return;
                        }
                        while let Some(Ok((state, event))) = rx.recv().await {
                            info!(
                                "[{peer_addr}] Dynamic connection at state {state} GOT EVENT: {event:?}"
                            );
                            if state == FsmState::Idle {
                                warn!(
                                    "[{peer_addr}] Dynamic Connection failed before reaching OpenConfirm state"
                                );
                                return;
                            }
                            if state == FsmState::OpenConfirm {
                                info!("[{peer_addr}] Accepted Dynamic Connection: {peer_addr}");
                                self.peers.insert(peer_key, peer_handle);
                                tokio::spawn(async move {
                                    while let Some(event) = rx.recv().await {
                                        info!(
                                            "[{peer_addr}] dynamic connection got event: {event:?}"
                                        );
                                    }
                                });
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn run(
        &mut self,
        peer_supervisor: &mut PeersSupervisor<IpAddr, SocketAddr, TcpStream>,
    ) -> Result<(), io::Error> {
        info!("Configured listening socket: {:?}", self.sockets);
        let mut listening_sockets = Vec::with_capacity(self.sockets.len());

        for socket in &self.sockets {
            let listener = TcpListener::bind(socket).await?;
            let listener_stream = TcpListenerStream::new(listener);
            listening_sockets.push(listener_stream);
        }
        loop {
            let mut listen_futures = FuturesUnordered::new();
            for incoming in &mut listening_sockets {
                listen_futures.push(incoming.next());
            }
            info!("BGP Listener listening on sockets: {:?}", self.sockets);
            while let Some(Some(Ok((stream, peer_addr)))) = listen_futures.next().await {
                self.accept_peer_connection(peer_addr.ip(), peer_addr, stream, peer_supervisor)
                    .await;
            }
        }
    }
}
