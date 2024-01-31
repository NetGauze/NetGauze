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

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use netgauze_bgp_speaker::peer::{
    EchoCapabilitiesPolicy, Peer, PeerAdminEvents, PeerConfig, PeerProperties,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    time::{self, Duration, Instant, Sleep},
};
use tokio_stream::wrappers::UnboundedReceiverStream;

use futures_core::{ready, Stream};
use netgauze_bgp_speaker::{
    codec::BgpCodec, connection::ActiveConnect, events::BgpEvent, fsm::FsmState,
};
use std::{
    cmp,
    collections::VecDeque,
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{self, Poll, Waker},
};

/// A modified version of [tokio_test::io::Mock] with a predefined script for
/// I/O reads, and writes are discarded.
///
/// This value is created by `Builder` and implements `AsyncRead` +
/// `AsyncWrite`. Reads follows the scenario described by the builder and panics
/// otherwise.
#[derive(Debug)]
pub struct Mock {
    inner: IoInner,
}

/// A handle to send additional actions to the related `Mock`.
#[derive(Debug)]
pub struct IoHandle {
    tx: mpsc::UnboundedSender<IoAction>,
}

/// Builds `Mock` instances.
#[derive(Debug, Clone, Default)]
pub struct IoBuilder {
    // Sequence of actions for the Mock to take
    actions: VecDeque<IoAction>,
}

#[derive(Debug, Clone)]
enum IoAction {
    Read(Vec<u8>),
    Wait(Duration),
    // Wrapped in Arc so that Builder can be cloned and Send.
    // Mock is not cloned as does not need to check Rc for ref counts.
    ReadError(Option<Arc<io::Error>>),
}

struct IoInner {
    actions: VecDeque<IoAction>,
    waiting: Option<Instant>,
    sleep: Option<Pin<Box<Sleep>>>,
    read_wait: Option<Waker>,
    rx: UnboundedReceiverStream<IoAction>,
}

impl IoBuilder {
    /// Return a new, empty `Builder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sequence a `read` operation.
    ///
    /// The next operation in the mock's script will be to expect a `read` call
    /// and return `buf`.
    pub fn read(&mut self, buf: &[u8]) -> &mut Self {
        self.actions.push_back(IoAction::Read(buf.into()));
        self
    }

    /// Sequence a `read` operation that produces an error.
    ///
    /// The next operation in the mock's script will be to expect a `read` call
    /// and return `error`.
    pub fn read_error(&mut self, error: io::Error) -> &mut Self {
        let error = Some(error.into());
        self.actions.push_back(IoAction::ReadError(error));
        self
    }

    /// Sequence a wait.
    ///
    /// The next operation in the mock's script will be to wait without doing so
    /// for `duration` amount of time.
    pub fn wait(&mut self, duration: Duration) -> &mut Self {
        let duration = cmp::max(duration, Duration::from_millis(1));
        self.actions.push_back(IoAction::Wait(duration));
        self
    }

    /// Build a `Mock` value according to the defined script.
    pub fn build(&mut self) -> Mock {
        let (mock, _) = self.build_with_handle();
        mock
    }

    /// Build a `Mock` value paired with a handle
    pub fn build_with_handle(&mut self) -> (Mock, IoHandle) {
        let (inner, handle) = IoInner::new(self.actions.clone());

        let mock = Mock { inner };

        (mock, handle)
    }
}

impl IoHandle {
    /// Sequence a `read` operation.
    ///
    /// The next operation in the mock's script will be to expect a `read` call
    /// and return `buf`.
    pub fn read(&mut self, buf: &[u8]) -> &mut Self {
        self.tx.send(IoAction::Read(buf.into())).unwrap();
        self
    }

    /// Sequence a `read` operation error.
    ///
    /// The next operation in the mock's script will be to expect a `read` call
    /// and return `error`.
    pub fn read_error(&mut self, error: io::Error) -> &mut Self {
        let error = Some(error.into());
        self.tx.send(IoAction::ReadError(error)).unwrap();
        self
    }
}

impl IoInner {
    fn new(actions: VecDeque<IoAction>) -> (IoInner, IoHandle) {
        let (tx, rx) = mpsc::unbounded_channel();

        let rx = UnboundedReceiverStream::new(rx);

        let inner = IoInner {
            actions,
            sleep: None,
            read_wait: None,
            rx,
            waiting: None,
        };

        let handle = IoHandle { tx };

        (inner, handle)
    }

    fn poll_action(&mut self, cx: &mut task::Context<'_>) -> Poll<Option<IoAction>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }

    fn read(&mut self, dst: &mut ReadBuf<'_>) -> io::Result<()> {
        match self.action() {
            Some(&mut IoAction::Read(ref mut data)) => {
                // Figure out how much to copy
                let n = cmp::min(dst.remaining(), data.len());

                // Copy the data into the `dst` slice
                dst.put_slice(&data[..n]);

                // Drain the data from the source
                data.drain(..n);

                Ok(())
            }
            Some(&mut IoAction::ReadError(ref mut err)) => {
                // As the
                let err = err.take().expect("Should have been removed from actions.");
                let err = Arc::try_unwrap(err).expect("There are no other references.");
                Err(err)
            }
            Some(_) => {
                // Either waiting or expecting a write
                Err(io::ErrorKind::WouldBlock.into())
            }
            None => Ok(()),
        }
    }

    fn write(&self, src: &[u8]) -> io::Result<usize> {
        let ret = src.len();
        Ok(ret)
    }

    fn remaining_wait(&mut self) -> Option<Duration> {
        match self.action() {
            Some(&mut IoAction::Wait(dur)) => Some(dur),
            _ => None,
        }
    }

    fn action(&mut self) -> Option<&mut IoAction> {
        loop {
            if self.actions.is_empty() {
                return None;
            }

            match self.actions[0] {
                IoAction::Read(ref mut data) => {
                    if !data.is_empty() {
                        break;
                    }
                }
                IoAction::Wait(ref mut dur) => {
                    if let Some(until) = self.waiting {
                        let now = Instant::now();

                        if now < until {
                            break;
                        } else {
                            self.waiting = None;
                        }
                    } else {
                        self.waiting = Some(Instant::now() + *dur);
                        break;
                    }
                }
                IoAction::ReadError(ref mut error) => {
                    if error.is_some() {
                        break;
                    }
                }
            }

            let _action = self.actions.pop_front();
        }

        self.actions.front_mut()
    }
}

impl Mock {
    fn maybe_wakeup_reader(&mut self) {
        match self.inner.action() {
            Some(&mut IoAction::Read(_)) | Some(&mut IoAction::ReadError(_)) | None => {
                if let Some(waker) = self.inner.read_wait.take() {
                    waker.wake();
                }
            }
            _ => {}
        }
    }
}

impl AsyncRead for Mock {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut sleep) = self.inner.sleep {
                ready!(Pin::new(sleep).poll(cx));
            }

            // If a sleep is set, it has already fired
            self.inner.sleep = None;

            // Capture 'filled' to monitor if it changed
            let filled = buf.filled().len();

            match self.inner.read(buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Some(rem) = self.inner.remaining_wait() {
                        let until = Instant::now() + rem;
                        self.inner.sleep = Some(Box::pin(time::sleep_until(until)));
                    } else {
                        self.inner.read_wait = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                }
                Ok(()) => {
                    if buf.filled().len() == filled {
                        match ready!(self.inner.poll_action(cx)) {
                            Some(action) => {
                                self.inner.actions.push_back(action);
                                continue;
                            }
                            None => {
                                return Poll::Ready(Ok(()));
                            }
                        }
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for Mock {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Some(ref mut sleep) = self.inner.sleep {
                ready!(Pin::new(sleep).poll(cx));
            }

            // If a sleep is set, it has already fired
            self.inner.sleep = None;

            match self.inner.write(buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Some(rem) = self.inner.remaining_wait() {
                        let until = Instant::now() + rem;
                        self.inner.sleep = Some(Box::pin(time::sleep_until(until)));
                    } else {
                        panic!("unexpected WouldBlock");
                    }
                }
                Ok(0) => {
                    // TODO: Is this correct?
                    if !self.inner.actions.is_empty() {
                        return Poll::Pending;
                    }

                    // TODO: Extract
                    match ready!(self.inner.poll_action(cx)) {
                        Some(action) => {
                            self.inner.actions.push_back(action);
                            continue;
                        }
                        None => {
                            panic!("unexpected write");
                        }
                    }
                }
                ret => {
                    self.maybe_wakeup_reader();
                    return Poll::Ready(ret);
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl fmt::Debug for IoInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Inner {{...}}")
    }
}

pub struct MockActiveConnect {
    peer_addr: SocketAddr,
    io_builder: IoBuilder,
}

#[async_trait::async_trait]
impl ActiveConnect<SocketAddr, Mock, BgpCodec> for MockActiveConnect {
    async fn connect(&mut self, peer_addr: SocketAddr) -> io::Result<Mock> {
        assert_eq!(self.peer_addr, peer_addr);
        Ok(self.io_builder.build())
    }
}

fuzz_target!(
    |data: (&[u8], u32, u32, bool, bool, Ipv4Addr, IpAddr, PeerConfig)| {
        let (
            buf,
            my_asn,
            peer_asn,
            send_asn4_cap_by_default,
            allow_dynamic_as,
            my_bgp_id,
            peer,
            config,
        ) = data;
        let peer_addr = match peer {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, 179)),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, 179, 0, 0)),
        };
        let policy = EchoCapabilitiesPolicy::new(
            my_asn,
            send_asn4_cap_by_default,
            my_bgp_id,
            100,
            vec![],
            vec![],
        );

        tokio_test::block_on(async {
            let mut io_builder = IoBuilder::new();
            // Divide buffer into smaller read chunks
            for chunk in buf.chunks(1024) {
                io_builder.read(chunk);
            }

            let active_connect = MockActiveConnect {
                peer_addr,
                io_builder,
            };

            let properties =
                PeerProperties::new(my_asn, peer_asn, my_bgp_id, peer_addr, allow_dynamic_as);

            let mut peer = Peer::new(peer_addr.ip(), properties, config, policy, active_connect);
            peer.add_admin_event(PeerAdminEvents::ManualStart);
            loop {
                let ret = tokio::time::timeout(Duration::from_millis(100), peer.run()).await;
                match ret {
                    Ok(Ok(event)) => {
                        if event == BgpEvent::TcpConnectionFails {
                            return;
                        }
                        if peer.fsm_state() == FsmState::Idle
                            || peer.fsm_state() == FsmState::Active
                        {
                            // Peer with terminated or reached an active state in which it waits for
                            // TCP connection
                            return;
                        }
                    }
                    Ok(Err(err)) => {
                        panic!("State: {}, Err: {err:?}", peer.fsm_state());
                    }
                    Err(_) => {
                        assert_eq!(
                            peer.fsm_state(),
                            FsmState::Active,
                            "State: {}, Timeout",
                            peer.fsm_state()
                        );
                        return;
                    }
                }
            }
        });
    }
);
