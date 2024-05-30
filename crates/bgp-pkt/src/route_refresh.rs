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

//! Representation for `RouteRefresh` BGP message.

use crate::iana::RouteRefreshSubcode;
use netgauze_iana::address_family::AddressType;
use serde::{Deserialize, Serialize};

/// Route Refresh message as defined in
/// Route Refresh Capability for BGP-4 [RFC2918](https://datatracker.ietf.org/doc/html/rfc2918)
/// and
/// Enhanced Route Refresh Capability for BGP-4 [RFC7313](https://datatracker.ietf.org/doc/html/rfc7313)
///
/// ```text
///  0       7      15      23      31
/// +-------+-------+-------+-------+
/// |      AFI      | S. typ.| SAFI  |
/// +-------+-------+-------+-------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct BgpRouteRefreshMessage {
    address_type: AddressType,
    operation_type: RouteRefreshSubcode,
}

impl BgpRouteRefreshMessage {
    pub const fn new(address_type: AddressType, operation_type: RouteRefreshSubcode) -> Self {
        Self {
            address_type,
            operation_type,
        }
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    pub const fn operation_type(&self) -> RouteRefreshSubcode {
        self.operation_type
    }
}
