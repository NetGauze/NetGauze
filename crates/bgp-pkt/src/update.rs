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

use crate::path_attribute::PathAttribute;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

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
pub struct BGPUpdateMessage {
    withdrawn_routes: Vec<WithdrawRoute>,
    path_attributes: Vec<PathAttribute>,
    network_layer_reachability_information: Vec<NetworkLayerReachabilityInformation>,
}

impl BGPUpdateMessage {
    #[inline]
    pub fn new(
        withdrawn_routes: Vec<WithdrawRoute>,
        path_attributes: Vec<PathAttribute>,
        network_layer_reachability_information: Vec<NetworkLayerReachabilityInformation>,
    ) -> Self {
        BGPUpdateMessage {
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
    ) -> &Vec<NetworkLayerReachabilityInformation> {
        &self.network_layer_reachability_information
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WithdrawRoute {
    prefix: Ipv4Net,
}

impl WithdrawRoute {
    pub const fn new(prefix: Ipv4Net) -> Self {
        Self { prefix }
    }

    pub const fn prefix(&self) -> &Ipv4Net {
        &self.prefix
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkLayerReachabilityInformation(Vec<Ipv4Net>);

impl NetworkLayerReachabilityInformation {
    pub fn new(networks: Vec<Ipv4Net>) -> Self {
        Self(networks)
    }

    pub const fn networks(&self) -> &Vec<Ipv4Net> {
        &self.0
    }
}
