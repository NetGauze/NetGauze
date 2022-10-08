// Copyright (C) 2022-present The NetGauze Authors.
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

use std::net::SocketAddr;

pub mod codec;
pub mod transport;

/// Capture the address of both sides of a socket
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct AddrInfo {
    local_socket: SocketAddr,
    remote_socket: SocketAddr,
}

impl AddrInfo {
    pub const fn new(local_socket: SocketAddr, remote_socket: SocketAddr) -> Self {
        Self {
            local_socket,
            remote_socket,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaggedData<T, V> {
    tag: T,
    value: V,
}

impl<T: Copy, V> TaggedData<T, V> {
    pub const fn new(tag: T, value: V) -> Self {
        Self { tag, value }
    }

    pub const fn tag(&self) -> T {
        self.tag
    }

    pub const fn value(&self) -> &V {
        &self.value
    }
}
