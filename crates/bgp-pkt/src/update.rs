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

use ipnet::Ipv4Net;
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
    withdrawn_routes: Vec<WithdrawRoute>,
    path_attributes: Vec<PathAttribute>,
    network_layer_reachability_information: NetworkLayerReachabilityInformation,
}

impl BgpUpdateMessage {
    #[inline]
    pub fn new(
        withdrawn_routes: Vec<WithdrawRoute>,
        path_attributes: Vec<PathAttribute>,
        network_layer_reachability_information: NetworkLayerReachabilityInformation,
    ) -> Self {
        BgpUpdateMessage {
            withdrawn_routes,
            path_attributes,
            network_layer_reachability_information,
        }
    }
    pub const fn withdraw_routes(&self) -> &Vec<WithdrawRoute> {
        &self.withdrawn_routes
    }

    pub const fn path_attributes(&self) -> &Vec<PathAttribute> {
        &self.path_attributes
    }

    #[inline]
    pub const fn network_layer_reachability_information(
        &self,
    ) -> &NetworkLayerReachabilityInformation {
        &self.network_layer_reachability_information
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WithdrawRoute {
    path_id: Option<u32>,
    prefix: Ipv4Net,
}

impl WithdrawRoute {
    pub const fn new(path_id: Option<u32>, prefix: Ipv4Net) -> Self {
        Self { path_id, prefix }
    }

    pub const fn path_id(&self) -> Option<u32> {
        self.path_id
    }

    pub const fn prefix(&self) -> &Ipv4Net {
        &self.prefix
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AddPathIpv4Net {
    path_id: u32,
    prefix: Ipv4Net,
}

impl AddPathIpv4Net {
    pub const fn new(path_id: u32, prefix: Ipv4Net) -> Self {
        Self { path_id, prefix }
    }

    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    pub const fn prefix(&self) -> Ipv4Net {
        self.prefix
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum NetworkLayerReachabilityInformation {
    Ipv4(Vec<Ipv4Net>),
    Ipv4AddPath(Vec<AddPathIpv4Net>),
}
