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

use netgauze_iana::address_family::AddressType;

/// BGP Capabilities are included as parameters in the BGPOpen message
/// to indicate support of certain BGP Features.
///
/// See [RFC5492 Capabilities Advertisement with BGP-4](https://datatracker.ietf.org/doc/html/rfc5492)
///
/// ```text
/// +------------------------------+
/// | Capability Code (1 octet)    |
/// +------------------------------+
/// | Capability Length (1 octet)  |
/// +------------------------------+
/// | Capability Value (variable)  |
/// ~                              ~
/// +------------------------------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BGPCapability {
    /// Defined in [RFC2858](https://datatracker.ietf.org/doc/html/rfc2858)
    MultiProtocolExtensions(MultiProtocolExtensionsCapability),

    /// Defined in [RFC2918](https://datatracker.ietf.org/doc/html/rfc2918)
    RouteRefresh,

    /// Defined in [RFC7313](https://datatracker.ietf.org/doc/html/rfc7313)
    EnhancedRouteRefresh,
}

/// Capability advertisement to speak a multi-protocol for a given
/// [AddressType] as defined in [RFC2858 Multiprotocol Extensions for BGP-4](https://datatracker.ietf.org/doc/html/rfc2858)
///
/// ```text
/// 0       7      15      23      31
/// +-------+-------+-------+-------+
/// |      AFI      | Res.  | SAFI  |
/// +-------+-------+-------+-------+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MultiProtocolExtensionsCapability {
    address_type: AddressType,
}

impl MultiProtocolExtensionsCapability {
    pub const fn new(address_type: AddressType) -> Self {
        Self { address_type }
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }
}
