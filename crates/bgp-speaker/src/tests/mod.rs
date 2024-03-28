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

use crate::peer::{EchoCapabilitiesPolicy, PeerProperties};
use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use std::{io, io::Cursor, net::SocketAddr, time::Duration};

use crate::connection::ActiveConnect;
use netgauze_bgp_pkt::{codec::BgpCodec, BgpMessage};
use netgauze_parse_utils::WritablePdu;

mod connection;
mod peer;
mod peer_controller;
mod supervisor;

pub(crate) const MY_AS: u32 = 100;
pub(crate) const PEER_AS: u32 = 200;
pub(crate) const HOLD_TIME: u16 = 180;
pub(crate) const MY_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);

pub(crate) const PEER_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 2);
pub(crate) const PEER_KEY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2));
pub(crate) const PEER_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)), 179);

pub(crate) const PROPERTIES: PeerProperties<SocketAddr> =
    PeerProperties::new(MY_AS, PEER_AS, MY_BGP_ID, PEER_ADDR, false);

pub(crate) const POLICY: EchoCapabilitiesPolicy<SocketAddr, tokio_test::io::Mock, BgpCodec> =
    EchoCapabilitiesPolicy::new(MY_AS, false, MY_BGP_ID, HOLD_TIME, Vec::new(), Vec::new());

/// Wrap [Builder] allowing it to accept BgpMessages for read and write
/// mocks rather than `&[u8]`.
#[derive(Default, Debug)]
pub struct BgpIoMockBuilder {
    io_builder: tokio_test::io::Builder,
}

impl BgpIoMockBuilder {
    pub fn new() -> Self {
        Self {
            io_builder: tokio_test::io::Builder::new(),
        }
    }

    /// See [Builder::read]
    pub fn read(&mut self, msg: BgpMessage) -> &mut Self {
        let buf = vec![];
        let mut cursor = Cursor::new(buf);
        msg.write(&mut cursor).unwrap();
        self.io_builder.read(&cursor.into_inner());
        self
    }

    /// See [Builder::read]
    pub fn read_u8(&mut self, buf: &[u8]) -> &mut Self {
        self.io_builder.read(buf);
        self
    }

    /// See [Builder::write]
    pub fn write(&mut self, msg: BgpMessage) -> &mut Self {
        let buf = vec![];
        let mut cursor = Cursor::new(buf);
        msg.write(&mut cursor).unwrap();
        self.io_builder.write(&cursor.into_inner());
        self
    }

    /// See [Builder::write]
    #[allow(dead_code)]
    pub fn write_u8(&mut self, buf: &[u8]) -> &mut Self {
        self.io_builder.write(buf);
        self
    }

    /// See [Builder::wait]
    pub fn wait(&mut self, duration: Duration) -> &mut Self {
        self.io_builder.wait(duration);
        self
    }

    /// See [Builder::build]
    pub fn build(&mut self) -> tokio_test::io::Mock {
        self.io_builder.build()
    }
}

pub struct MockActiveConnect {
    pub peer_addr: SocketAddr,
    pub io_builder: BgpIoMockBuilder,
    pub connect_delay: Duration,
}

#[async_trait]
impl ActiveConnect<SocketAddr, tokio_test::io::Mock, BgpCodec> for MockActiveConnect {
    async fn connect(&mut self, peer_addr: SocketAddr) -> io::Result<tokio_test::io::Mock> {
        assert_eq!(self.peer_addr, peer_addr);
        if !self.connect_delay.is_zero() {
            tokio::time::sleep(self.connect_delay).await;
        }
        Ok(self.io_builder.build())
    }
}

/// An [ActiveConnect] that always fail to make a connection
pub struct MockFailedActiveConnect {
    pub peer_addr: SocketAddr,
    pub connect_delay: Duration,
}

#[async_trait]
impl ActiveConnect<SocketAddr, tokio_test::io::Mock, BgpCodec> for MockFailedActiveConnect {
    async fn connect(&mut self, peer_addr: SocketAddr) -> io::Result<tokio_test::io::Mock> {
        assert_eq!(self.peer_addr, peer_addr);
        if !self.connect_delay.is_zero() {
            tokio::time::sleep(self.connect_delay).await;
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "MockFailedActiveConnect connection refused",
        ))
    }
}
