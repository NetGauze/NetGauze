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

use crate::capabilities::BGPCapability;
use std::net::Ipv4Addr;

pub const BGP_VERSION: u8 = 4;

/// BGP Open message
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+
/// |    Version    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     My Autonomous System      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Hold Time           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         BGP Identifier                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Opt Parm Len  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |             Optional Parameters (variable)                    |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BGPOpenMessage {
    version: u8,
    my_as: u16,
    hold_time: u16,
    bgp_id: Ipv4Addr,
    params: Vec<BGPOpenMessageParameter>, // TODO (AH): rfc5492
}

impl BGPOpenMessage {
    pub fn new(
        my_as: u16,
        hold_time: u16,
        bgp_id: Ipv4Addr,
        params: Vec<BGPOpenMessageParameter>,
    ) -> BGPOpenMessage {
        BGPOpenMessage {
            version: BGP_VERSION,
            my_as,
            hold_time,
            bgp_id,
            params,
        }
    }

    pub const fn version(&self) -> u8 {
        self.version
    }

    pub const fn my_as(&self) -> u16 {
        self.my_as
    }

    pub const fn hold_time(&self) -> u16 {
        self.hold_time
    }

    pub const fn bgp_id(&self) -> Ipv4Addr {
        self.bgp_id
    }

    pub const fn params(&self) -> &Vec<BGPOpenMessageParameter> {
        &self.params
    }

    /// Shortcut to get a list of all the capabilities from all the parameters
    pub fn capabilities(&self) -> Vec<&BGPCapability> {
        return self
            .params
            .iter()
            .flat_map(|x| match x {
                BGPOpenMessageParameter::Capabilities(capabilities_vec) => capabilities_vec,
            })
            .collect::<Vec<&BGPCapability>>();
    }
}

/// Optional Parameter included in [BGPOpenMessage].
///
/// ```text
/// 0                   1
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
/// |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BGPOpenMessageParameter {
    /// Capabilities Advertisement
    Capabilities(Vec<BGPCapability>),
}
