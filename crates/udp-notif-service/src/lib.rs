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

use netgauze_udp_notif_pkt::UdpNotifPacket;
use std::{fmt::Display, io, net::SocketAddr, sync::Arc};

pub mod actor;
pub mod supervisor;

pub type ActorId = u32;
pub type SubscriberId = u32;
pub type UdpNotifRequest = (SocketAddr, UdpNotifPacket);

pub type UdpNotifSender = async_channel::Sender<Arc<UdpNotifRequest>>;
pub type UdpNotifReceiver = async_channel::Receiver<Arc<UdpNotifRequest>>;

pub fn create_udp_notif_channel(buffer_size: usize) -> (UdpNotifSender, UdpNotifReceiver) {
    async_channel::bounded(buffer_size)
}

#[derive(Debug, Clone)]
pub struct Subscription {
    actor_id: ActorId,
    id: SubscriberId,
}

impl Display for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "subscription {{ actor_id: {}, id: {} }}",
            self.actor_id, self.id
        )
    }
}

/// Enable socket reuse
/// TODO: Allow interface bind to be optionally specified
/// See: [bind_device_by_index_v4](https://docs.rs/socket2/latest/socket2/struct.Socket.html#method.bind_device_by_index_v4)
/// and [bind_device_by_index_v6](https://docs.rs/socket2/latest/socket2/struct.Socket.html#method.bind_device_by_index_v6)
pub fn new_udp_reuse_port(
    local_addr: SocketAddr,
    _device: Option<String>,
) -> io::Result<tokio::net::UdpSocket> {
    let udp_sock = socket2::Socket::new(
        if local_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        None,
    )?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    udp_sock.set_reuse_port(true)?;
    udp_sock.set_recv_buffer_size(1024 * 1024 * 20)?; // 20 MB
    #[cfg(unix)]
    // from tokio-rs/mio/blob/master/src/sys/unix/net.rs
    udp_sock.set_cloexec(true)?;
    udp_sock.set_nonblocking(true)?;
    udp_sock.bind(&socket2::SockAddr::from(local_addr))?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into()
}
