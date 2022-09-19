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
use strum_macros::{Display, FromRepr};

/// Enhanced route refresh have fixed length as per RFC2918
pub(crate) const ROUTE_REFRESH_CAPABILITY_LENGTH: u8 = 0;

/// Enhanced route refresh have fixed length as per RFC7313
pub(crate) const ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH: u8 = 0;

/// Multi Protocol extension have fixed length as per RFC2858
pub(crate) const MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH: u8 = 4;

/// Four octet as capability have fixed length as per RFC6793
pub(crate) const FOUR_OCTET_AS_CAPABILITY_LENGTH: u8 = 4;

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

    FourOctetAS(FourOctetASCapability),

    Experimental(ExperimentalCapability),

    Unrecognized(UnrecognizedCapability),
}

/// Generic struct to carry all the unsupported BGP capabilities
#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnrecognizedCapability {
    code: u8,
    value: Vec<u8>,
}

impl UnrecognizedCapability {
    pub const fn new(code: u8, value: Vec<u8>) -> Self {
        Self { code, value }
    }

    pub const fn code(&self) -> &u8 {
        &self.code
    }

    pub const fn value(&self) -> &Vec<u8> {
        &self.value
    }
}

/// Experimental Capabilities Codes as defined by [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug)]
pub enum ExperimentalCapabilityCode {
    Experimental239 = 239,
    Experimental240 = 240,
    Experimental241 = 241,
    Experimental242 = 242,
    Experimental243 = 243,
    Experimental244 = 244,
    Experimental245 = 245,
    Experimental246 = 246,
    Experimental247 = 247,
    Experimental248 = 248,
    Experimental249 = 249,
    Experimental250 = 250,
    Experimental251 = 251,
    Experimental252 = 252,
    Experimental253 = 253,
    Experimental254 = 254,
}

/// Generic struct to carry all capabilities that are designated as experimental
/// by IANA See [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExperimentalCapability {
    code: ExperimentalCapabilityCode,
    value: Vec<u8>,
}

impl ExperimentalCapability {
    pub const fn new(code: ExperimentalCapabilityCode, value: Vec<u8>) -> Self {
        Self { code, value }
    }

    pub const fn code(&self) -> ExperimentalCapabilityCode {
        self.code
    }

    pub const fn value(&self) -> &Vec<u8> {
        &self.value
    }
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

/// Defined in [RFC6793](https://datatracker.ietf.org/doc/html/rfc6793)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FourOctetASCapability {
    asn4: u32,
}

impl FourOctetASCapability {
    pub const fn new(asn4: u32) -> Self {
        Self { asn4 }
    }

    pub const fn asn4(&self) -> u32 {
        self.asn4
    }
}
