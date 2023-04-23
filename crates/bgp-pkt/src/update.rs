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

//! Representations for BGP Update message

use crate::nlri::Ipv4UnicastAddress;
use serde::{Deserialize, Serialize};

use crate::path_attribute::PathAttribute;

/// UPDATE messages are used to transfer routing information between BGP peers
/// as defined by [RFC4271](https://datatracker.ietf.org/doc/html/RFC4271).
///
/// ```text
/// +-----------------------------------------------------+
/// |   Withdrawn Routes Length (2 octets)                |
/// +-----------------------------------------------------+
/// |   Withdrawn Routes (variable)                       |
/// +-----------------------------------------------------+
/// |   Total Path Attribute Length (2 octets)            |
/// +-----------------------------------------------------+
/// |   Path Attributes (variable)                        |
/// +-----------------------------------------------------+
/// |   Network Layer Reachability Information (variable) |
/// +-----------------------------------------------------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpUpdateMessage {
    withdrawn_routes: Vec<Ipv4UnicastAddress>,
    path_attributes: Vec<PathAttribute>,
    nlri: Vec<Ipv4UnicastAddress>,
}

impl BgpUpdateMessage {
    #[inline]
    pub fn new(
        withdrawn_routes: Vec<Ipv4UnicastAddress>,
        path_attributes: Vec<PathAttribute>,
        nlri: Vec<Ipv4UnicastAddress>,
    ) -> Self {
        BgpUpdateMessage {
            withdrawn_routes,
            path_attributes,
            nlri,
        }
    }
    pub const fn withdraw_routes(&self) -> &Vec<Ipv4UnicastAddress> {
        &self.withdrawn_routes
    }

    pub const fn path_attributes(&self) -> &Vec<PathAttribute> {
        &self.path_attributes
    }

    #[inline]
    pub const fn nlri(&self) -> &Vec<Ipv4UnicastAddress> {
        &self.nlri
    }
}
