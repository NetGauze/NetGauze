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

use netgauze_udp_notif_pkt::raw::UdpNotifPacket;
use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

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

/// Enable socket reuse and bind to a device or a VRF on selected platforms.
/// Binding to a device or VRF is supported on: MacOS and Linux.
/// Unused variables is enabled to silence the Clippy error for platforms
/// that doesn't support binding to an interface.
#[allow(unused_variables)]
pub fn new_udp_reuse_port(
    local_addr: SocketAddr,
    device: Option<String>,
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
    // Binding a socket to a device or VRF is a platform specific operation,
    // hence we guard it for only a selected subset of target platforms.
    // The first cfg block filters for the supported platforms to avoid Clippy
    // errors about unused `name` for the unsupported platforms.
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux"
    ))]
    if let Some(name) = device {
        #[cfg(any(
            target_os = "ios",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos",
        ))]
        {
            let c_str = std::ffi::CString::new(name)?;
            let c_index = unsafe { libc::if_nametoindex(c_str.as_ptr() as *const libc::c_char) };
            let index = std::num::NonZeroU32::new(c_index as u32);
            if local_addr.is_ipv4() {
                udp_sock.bind_device_by_index_v4(index)?;
            } else {
                udp_sock.bind_device_by_index_v6(index)?;
            }
        }
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        udp_sock.bind_device(Some(name.as_bytes()))?
    }
    udp_sock.bind(&socket2::SockAddr::from(local_addr))?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into()
}
