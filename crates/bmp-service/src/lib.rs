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

#![allow(clippy::upper_case_acronyms)]
#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(unreachable_pub)]
#![deny(unused_allocation)]
#![deny(unused_assignments)]
#![deny(unused_comparisons)]
#![deny(clippy::clone_on_ref_ptr)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::missing_const_for_fn)]

use serde::{Deserialize, Serialize};

use crate::codec::BmpCodecDecoderError;
use std::{
    fmt::{Display, Formatter},
    net::SocketAddr,
};

pub mod codec;
pub mod handle;
pub mod server;
pub mod service;
pub mod transport;

/// Capture the address of both sides of a socket
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
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

    pub const fn local_socket(&self) -> SocketAddr {
        self.local_socket
    }

    pub const fn remote_socket(&self) -> SocketAddr {
        self.remote_socket
    }
}

/// Associate a value with a tag
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

impl Display for TaggedData<AddrInfo, BmpCodecDecoderError> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TaggedData<AddrInfo, BmpCodecDecoderError> {}
