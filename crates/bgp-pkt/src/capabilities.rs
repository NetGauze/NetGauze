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

//! BGP Capabilities advertised in BGP Open Messages.
//! See [RFC5492 Capabilities Advertisement with BGP-4](https://datatracker.ietf.org/doc/html/rfc5492)

use crate::iana::{BgpCapabilityCode, BgpRoleValue};
use netgauze_iana::address_family::{AddressFamily, AddressType};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, FromRepr};

/// BGP Capabilities are included as parameters in the
/// [`crate::open::BgpOpenMessage`] message to indicate support of certain BGP
/// Features.
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
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum BgpCapability {
    /// Defined in [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    MultiProtocolExtensions(MultiProtocolExtensionsCapability),

    /// Defined in [RFC2918](https://datatracker.ietf.org/doc/html/rfc2918)
    RouteRefresh,

    /// Defined in [RFC7313](https://datatracker.ietf.org/doc/html/rfc7313)
    EnhancedRouteRefresh,

    CiscoRouteRefresh,

    /// Defined in [RFC4724](https://datatracker.ietf.org/doc/html/rfc4724)
    /// and [RFC8538](https://datatracker.ietf.org/doc/html/rfc8538)
    GracefulRestartCapability(GracefulRestartCapability),

    /// Defined in [RFC9494](https://datatracker.ietf.org/doc/html/rfc9494)
    LongLivedGracefulRestart(LongLivedGracefulRestartCapability),

    /// Defined in [draft-walton-bgp-hostname-capability](https://datatracker.ietf.org/doc/html/draft-walton-bgp-hostname-capability-01)
    Fqdn(FqdnCapability),

    /// Defined in [RFC7911](https://datatracker.ietf.org/doc/html/rfc7911)
    AddPath(AddPathCapability),

    /// Defined in [RFC8654](https://datatracker.ietf.org/doc/html/rfc8654)
    ExtendedMessage,

    /// Defined in [RFC8277](https://datatracker.ietf.org/doc/html/rfc8277)
    MultipleLabels(Vec<MultipleLabel>),

    /// The BGP Role characterizes the relationship between the eBGP speakers
    /// forming a session. BGP Role used in the route leak prevention and
    /// detection procedures.
    ///
    /// Defined in [RFC9234](https://datatracker.ietf.org/doc/html/rfc9234)
    BgpRole(BgpRoleCapability),

    /// Defined in [RFC6793](https://datatracker.ietf.org/doc/html/rfc6793)
    FourOctetAs(FourOctetAsCapability),

    /// Defined in [RFC8950](https://datatracker.ietf.org/doc/html/rfc8950)
    ExtendedNextHopEncoding(ExtendedNextHopEncodingCapability),

    Experimental(ExperimentalCapability),

    Unrecognized(UnrecognizedCapability),
}

impl BgpCapability {
    pub const fn code(&self) -> Result<BgpCapabilityCode, u8> {
        match self {
            Self::MultiProtocolExtensions(_) => Ok(BgpCapabilityCode::MultiProtocolExtensions),
            Self::RouteRefresh => Ok(BgpCapabilityCode::RouteRefreshCapability),
            Self::EnhancedRouteRefresh => Ok(BgpCapabilityCode::EnhancedRouteRefresh),
            Self::CiscoRouteRefresh => Ok(BgpCapabilityCode::CiscoRouteRefresh),
            Self::GracefulRestartCapability(_) => Ok(BgpCapabilityCode::GracefulRestartCapability),
            Self::LongLivedGracefulRestart(_) => {
                Ok(BgpCapabilityCode::LongLivedGracefulRestartLLGRCapability)
            }
            Self::Fqdn(_) => Ok(BgpCapabilityCode::FQDN),
            Self::AddPath(_) => Ok(BgpCapabilityCode::AddPathCapability),
            Self::ExtendedMessage => Ok(BgpCapabilityCode::BgpExtendedMessage),
            Self::MultipleLabels(_) => Ok(BgpCapabilityCode::MultipleLabelsCapability),
            Self::BgpRole(_) => Ok(BgpCapabilityCode::BgpRole),
            Self::FourOctetAs(_) => Ok(BgpCapabilityCode::FourOctetAs),
            Self::ExtendedNextHopEncoding(_) => Ok(BgpCapabilityCode::ExtendedNextHopEncoding),
            Self::Experimental(value) => match value.code() {
                ExperimentalCapabilityCode::Experimental239 => {
                    Ok(BgpCapabilityCode::Experimental239)
                }
                ExperimentalCapabilityCode::Experimental240 => {
                    Ok(BgpCapabilityCode::Experimental240)
                }
                ExperimentalCapabilityCode::Experimental241 => {
                    Ok(BgpCapabilityCode::Experimental241)
                }
                ExperimentalCapabilityCode::Experimental242 => {
                    Ok(BgpCapabilityCode::Experimental242)
                }
                ExperimentalCapabilityCode::Experimental243 => {
                    Ok(BgpCapabilityCode::Experimental243)
                }
                ExperimentalCapabilityCode::Experimental244 => {
                    Ok(BgpCapabilityCode::Experimental244)
                }
                ExperimentalCapabilityCode::Experimental245 => {
                    Ok(BgpCapabilityCode::Experimental245)
                }
                ExperimentalCapabilityCode::Experimental246 => {
                    Ok(BgpCapabilityCode::Experimental246)
                }
                ExperimentalCapabilityCode::Experimental247 => {
                    Ok(BgpCapabilityCode::Experimental247)
                }
                ExperimentalCapabilityCode::Experimental248 => {
                    Ok(BgpCapabilityCode::Experimental248)
                }
                ExperimentalCapabilityCode::Experimental249 => {
                    Ok(BgpCapabilityCode::Experimental249)
                }
                ExperimentalCapabilityCode::Experimental250 => {
                    Ok(BgpCapabilityCode::Experimental250)
                }
                ExperimentalCapabilityCode::Experimental251 => {
                    Ok(BgpCapabilityCode::Experimental251)
                }
                ExperimentalCapabilityCode::Experimental252 => {
                    Ok(BgpCapabilityCode::Experimental252)
                }
                ExperimentalCapabilityCode::Experimental253 => {
                    Ok(BgpCapabilityCode::Experimental253)
                }
                ExperimentalCapabilityCode::Experimental254 => {
                    Ok(BgpCapabilityCode::Experimental254)
                }
            },
            Self::Unrecognized(value) => Err(value.code),
        }
    }
}

/// Generic struct to carry all the unsupported BGP capabilities
#[repr(C)]
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
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
#[derive(Display, FromRepr, Hash, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
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
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
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
/// [`AddressType`] as defined in [RFC4760 Multiprotocol Extensions for BGP-4](https://datatracker.ietf.org/doc/html/rfc4760)
///
/// ```text
/// 0       7      15      23      31
/// +-------+-------+-------+-------+
/// |      AFI      | Res.  | SAFI  |
/// +-------+-------+-------+-------+
/// ```
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
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
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FourOctetAsCapability {
    asn4: u32,
}

impl FourOctetAsCapability {
    pub const fn new(asn4: u32) -> Self {
        Self { asn4 }
    }

    pub const fn asn4(&self) -> u32 {
        self.asn4
    }
}

/// Defined in [RFC4724](https://datatracker.ietf.org/doc/html/rfc4724)
/// and [RFC8538](https://datatracker.ietf.org/doc/html/rfc8538)
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct GracefulRestartCapability {
    restart: bool,
    graceful_notification: bool,
    time: u16,
    address_families: Vec<GracefulRestartAddressFamily>,
}

impl GracefulRestartCapability {
    pub fn new(
        restart: bool,
        graceful_notification: bool,
        time: u16,
        address_families: Vec<GracefulRestartAddressFamily>,
    ) -> Self {
        Self {
            restart,
            graceful_notification,
            time,
            address_families,
        }
    }

    pub const fn restart(&self) -> bool {
        self.restart
    }

    pub const fn graceful_notification(&self) -> bool {
        self.graceful_notification
    }

    pub const fn time(&self) -> u16 {
        self.time
    }

    pub const fn address_families(&self) -> &Vec<GracefulRestartAddressFamily> {
        &self.address_families
    }
}

#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct GracefulRestartAddressFamily {
    forwarding_state: bool,
    address_type: AddressType,
}

/// Long-Lived Graceful Restart (LLGR) Capability
///
/// ```text
/// +--------------------------------------------------+
/// | Address Family Identifier (16 bits)              |
/// +--------------------------------------------------+
/// | Subsequent Address Family Identifier (8 bits)    |
/// +--------------------------------------------------+
/// | Flags for Address Family (8 bits)                |
/// +--------------------------------------------------+
/// | Long-lived Stale Time (24 bits)                  |
/// +--------------------------------------------------+
/// | ...                                              |
/// +--------------------------------------------------+
/// ```
///
/// The capability value is a sequence of the tuples above, one per address
/// family, each 7 octets wide.
///
/// Defined in [RFC9494](https://datatracker.ietf.org/doc/html/rfc9494)
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct LongLivedGracefulRestartCapability {
    address_families: Vec<LongLivedGracefulRestartAddressFamily>,
}

impl LongLivedGracefulRestartCapability {
    pub const fn new(address_families: Vec<LongLivedGracefulRestartAddressFamily>) -> Self {
        Self { address_families }
    }

    pub const fn address_families(&self) -> &Vec<LongLivedGracefulRestartAddressFamily> {
        &self.address_families
    }
}

/// One `<AFI, SAFI, Flags, Long-lived Stale Time>` tuple of the
/// [`LongLivedGracefulRestartCapability`].
///
/// Defined in [RFC9494](https://datatracker.ietf.org/doc/html/rfc9494)
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct LongLivedGracefulRestartAddressFamily {
    /// The `F` bit: the forwarding state for routes of this address family was
    /// preserved across the previous BGP restart.
    forwarding_state: bool,
    address_type: AddressType,
    /// Long-lived Stale Time in seconds. Carried on the wire in 24 bits, so
    /// values above [`Self::MAX_STALE_TIME`] cannot be represented.
    stale_time: u32,
}

impl LongLivedGracefulRestartAddressFamily {
    /// The Long-lived Stale Time is a 24-bit field
    pub const MAX_STALE_TIME: u32 = 0x00ff_ffff;

    pub const fn new(forwarding_state: bool, address_type: AddressType, stale_time: u32) -> Self {
        Self {
            forwarding_state,
            address_type,
            stale_time,
        }
    }

    pub const fn forwarding_state(&self) -> bool {
        self.forwarding_state
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Long-lived Stale Time in seconds
    pub const fn stale_time(&self) -> u32 {
        self.stale_time
    }
}

/// Fully Qualified Domain Name (FQDN) Capability
///
/// Advertises the hostname and domain name of the BGP speaker, which is
/// primarily an operational aid: it lets a peer or a monitoring station label
/// a session with a human-readable name rather than just an IP address.
///
/// ```text
/// +--------------------------------+
/// |  Hostname Length (1 octet)     |
/// +--------------------------------+
/// |  Hostname (variable)           |
/// +--------------------------------+
/// |  Domain Name Length (1 octet)  |
/// +--------------------------------+
/// |  Domain Name (variable)        |
/// +--------------------------------+
/// ```
///
/// Both fields are UTF-8 and both length fields are a single octet, so neither
/// string can exceed [`Self::MAX_NAME_LEN`] bytes. Speakers that have no domain
/// name configured advertise a zero-length domain name rather than omitting the
/// field.
///
/// Defined in [draft-walton-bgp-hostname-capability](https://datatracker.ietf.org/doc/html/draft-walton-bgp-hostname-capability-01).
/// This is an individual draft rather than a published RFC, but it is widely
/// implemented (FRRouting, Cisco, and others advertise it by default).
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FqdnCapability {
    hostname: String,
    domain_name: String,
}

impl FqdnCapability {
    /// Both lengths are carried in a single octet
    pub const MAX_NAME_LEN: usize = u8::MAX as usize;

    pub const fn new(hostname: String, domain_name: String) -> Self {
        Self {
            hostname,
            domain_name,
        }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The domain name, empty when the speaker did not advertise one
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }
}

impl GracefulRestartAddressFamily {
    pub const fn new(forwarding_state: bool, address_type: AddressType) -> Self {
        Self {
            forwarding_state,
            address_type,
        }
    }

    pub const fn forwarding_state(&self) -> bool {
        self.forwarding_state
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }
}

/// Allows the advertisement on multiple paths for the same address prefix
/// without replacing any previous ones.
///
/// See [RFC7911](https://datatracker.ietf.org/doc/html/RFC7911)
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct AddPathCapability {
    address_families: Vec<AddPathAddressFamily>,
}

impl AddPathCapability {
    pub const fn new(address_families: Vec<AddPathAddressFamily>) -> Self {
        Self { address_families }
    }

    pub const fn address_families(&self) -> &Vec<AddPathAddressFamily> {
        &self.address_families
    }
}

/// Single Address Family with Add Path capability enabled
/// ```text
/// +------------------------------------------------+
/// | Address Family Identifier (2 octets)           |
/// +------------------------------------------------+
/// | Subsequent Address Family Identifier (1 octet) |
/// +------------------------------------------------+
/// | Send/Receive (1 octet)                         |
/// +------------------------------------------------+
/// ```
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct AddPathAddressFamily {
    address_type: AddressType,
    send: bool,
    receive: bool,
}

impl AddPathAddressFamily {
    pub const fn new(address_type: AddressType, send: bool, receive: bool) -> Self {
        Self {
            address_type,
            send,
            receive,
        }
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    ///  This field indicates whether the sender is able to send multiple paths
    /// to its peer the [`AddressType`]
    pub const fn send(&self) -> bool {
        self.send
    }

    ///  This field indicates whether the sender is able to receive multiple
    /// paths from its peer the [`AddressType`]
    pub const fn receive(&self) -> bool {
        self.receive
    }
}

/// Advertising IPv4 Network Layer Reachability Information with an IPv6 Next
/// Hop
//
/// defined by: [RFC8950](https://datatracker.ietf.org/doc/html/rfc8950)
///
/// ```text
/// +-----------------------------------------------------+
/// | NLRI AFI - 1 (2 octets)                             |
/// +-----------------------------------------------------+
/// | NLRI SAFI - 1 (2 octets)                            |
/// +-----------------------------------------------------+
/// | Nexthop AFI - 1 (2 octets)                          |
/// +-----------------------------------------------------+
/// | .....                                               |
/// +-----------------------------------------------------+
/// | NLRI AFI - N (2 octets)                             |
/// +-----------------------------------------------------+
/// | NLRI SAFI - N (2 octets)                            |
/// +-----------------------------------------------------+
/// | Nexthop AFI - N (2 octets)                          |
/// +-----------------------------------------------------+
/// ```
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ExtendedNextHopEncodingCapability {
    encodings: Vec<ExtendedNextHopEncoding>,
}

impl ExtendedNextHopEncodingCapability {
    pub const fn new(encodings: Vec<ExtendedNextHopEncoding>) -> Self {
        Self { encodings }
    }

    pub const fn encodings(&self) -> &Vec<ExtendedNextHopEncoding> {
        &self.encodings
    }
}

/// Encoding for a single extended next hop
///
/// ```text
/// +-----------------------------------------------------+
/// | NLRI AFI - 1 (2 octets)                             |
/// +-----------------------------------------------------+
/// | NLRI SAFI - 1 (2 octets)                            |
/// +-----------------------------------------------------+
/// | Nexthop AFI - 1 (2 octets)                          |
/// +-----------------------------------------------------+
/// ```
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ExtendedNextHopEncoding {
    address_type: AddressType,
    next_hop_afi: AddressFamily,
}

impl ExtendedNextHopEncoding {
    pub const fn new(address_type: AddressType, next_hop_afi: AddressFamily) -> Self {
        Self {
            address_type,
            next_hop_afi,
        }
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    pub const fn next_hop_afi(&self) -> AddressFamily {
        self.next_hop_afi
    }
}

/// Addresses support for Multiple Labels Capability
/// defined by: [RFC8277](https://datatracker.ietf.org/doc/html/rfc8277)
/// ```text
/// 0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              AFI              |    SAFI       |    Count      ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MultipleLabel {
    address_type: AddressType,
    count: u8,
}

impl MultipleLabel {
    pub const fn new(address_type: AddressType, count: u8) -> Self {
        Self {
            address_type,
            count,
        }
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    pub const fn count(&self) -> u8 {
        self.count
    }
}

/// BGP Role used in the route leak prevention and detection procedures
/// defined by: [RFC9234](https://datatracker.ietf.org/doc/html/rfc9234)
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct BgpRoleCapability {
    role: BgpRoleValue,
}

impl BgpRoleCapability {
    pub const fn new(role: BgpRoleValue) -> Self {
        Self { role }
    }

    pub const fn role(&self) -> BgpRoleValue {
        self.role
    }
}
