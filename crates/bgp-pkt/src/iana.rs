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

//! Contains BGP codes that are registered at IANA [BGP Parameters](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml)

use serde::{Deserialize, Serialize};
use strum_macros::{Display, FromRepr};

/// BGP Message types as registered in IANA [BGP Message Types](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-1)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpMessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    KeepAlive = 4,
    /// Route Refresh message is registered in [RFC2918](https://datatracker.ietf.org/doc/html/rfc2918)
    RouteRefresh = 5,
}

/// BGP Message type is not one of [`BgpMessageType`], the carried value is the
/// undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedBgpMessageType(pub u8);

impl From<BgpMessageType> for u8 {
    fn from(value: BgpMessageType) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for BgpMessageType {
    type Error = UndefinedBgpMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBgpMessageType(value)),
        }
    }
}

/// BGP Path Attributes as defined by IANA [BGP Path Attributes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PathAttributeType {
    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    Origin = 1,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    AsPath = 2,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    NextHop = 3,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    MultiExitDiscriminator = 4,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    LocalPreference = 5,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    AtomicAggregate = 6,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    Aggregator = 7,

    /// [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
    Communities = 8,

    /// [RFC4456](https://datatracker.ietf.org/doc/html/rfc4456)
    OriginatorId = 9,

    /// [RFC4456](https://datatracker.ietf.org/doc/html/rfc4456)
    ClusterList = 10,

    /// [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    MpReachNlri = 14,

    /// [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    MpUnreachNlri = 15,

    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    ExtendedCommunities = 16,

    /// [RFC6793](https://datatracker.ietf.org/doc/html/rfc6793)
    As4Path = 17,

    /// [RFC6793](https://datatracker.ietf.org/doc/html/rfc6793)
    As4Aggregator = 18,

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    PmsiTunnel = 22,

    /// [RFC9012](https://datatracker.ietf.org/doc/html/rfc9012)
    TunnelEncapsulation = 23,

    /// [RFC5543](https://datatracker.ietf.org/doc/html/rfc5543)
    TrafficEngineering = 24,

    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    ExtendedCommunitiesIpv6 = 25,

    /// [RFC7311](https://datatracker.ietf.org/doc/html/rfc7311)
    AccumulatedIgp = 26,

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    PeDistinguisherLabels = 27,

    /// [RFC7752](https://datatracker.ietf.org/doc/html/rfc7752)
    BgpLsAttribute = 29,

    /// [RFC8092](https://datatracker.ietf.org/doc/html/rfc8092)
    LargeCommunities = 32,

    /// [RFC8205](https://datatracker.ietf.org/doc/html/rfc8205)
    BgpPSecPath = 33,

    /// [RFC9234](https://datatracker.ietf.org/doc/html/rfc9234)
    OnlyToCustomer = 35,

    /// D-PATH [draft-ietf-bess-evpn-ipvpn-interworking](https://datatracker.ietf.org/doc/html/draft-ietf-bess-evpn-ipvpn-interworking)
    BgpDomainPath = 36,

    /// [RFC9015](https://datatracker.ietf.org/doc/html/rfc9015)
    SfpAttribute = 37,

    /// [RFC9026](https://datatracker.ietf.org/doc/html/rfc9026)
    BfdDiscriminator = 38,

    /// [RFC8669](https://datatracker.ietf.org/doc/html/rfc8669)
    BgpPrefixSid = 40,

    /// [RFC6368](https://datatracker.ietf.org/doc/html/rfc6368)
    AttributesSet = 128,

    /// [RFC2042](https://datatracker.ietf.org/doc/html/rfc2042)
    Development = 255,
}

impl From<PathAttributeType> for u8 {
    fn from(value: PathAttributeType) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedPathAttributeType(pub u8);

impl TryFrom<u8> for PathAttributeType {
    type Error = UndefinedPathAttributeType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedPathAttributeType(value)),
        }
    }
}

/// BGP Error (Notification) Codes as defined by IANA [BGP Error (Notification) Codes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-3)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpErrorNotificationCode {
    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    MessageHeaderError = 1,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    OpenMessageError = 2,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    UpdateMessageError = 3,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    HoldTimerExpired = 4,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    FiniteStateMachineError = 5,

    /// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    Cease = 6,

    /// [RFC7313](https://datatracker.ietf.org/doc/html/rfc7313)
    RouteRefreshMessageError = 7,
}

impl From<BgpErrorNotificationCode> for u8 {
    fn from(value: BgpErrorNotificationCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedBgpErrorNotificationCode(pub u8);

impl TryFrom<u8> for BgpErrorNotificationCode {
    type Error = UndefinedBgpErrorNotificationCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBgpErrorNotificationCode(value)),
        }
    }
}

/// Message Header Error sub-codes for [`BgpErrorNotificationCode::MessageHeaderError`] as defined by IANA [Message Header Error subcodes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-5)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum MessageHeaderErrorSubCode {
    /// [RFC Errata 4493](https://www.rfc-editor.org/errata_search.php?eid=4493)
    Unspecific = 0,
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

impl From<MessageHeaderErrorSubCode> for u8 {
    fn from(value: MessageHeaderErrorSubCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedMessageHeaderErrorSubCode(pub u8);

impl TryFrom<u8> for MessageHeaderErrorSubCode {
    type Error = UndefinedMessageHeaderErrorSubCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedMessageHeaderErrorSubCode(value)),
        }
    }
}

/// OPEN Message Error sub-codes for [`BgpErrorNotificationCode::OpenMessageError`] as defined by IANA [OPEN Message Error subcodes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-6)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum OpenMessageErrorSubCode {
    /// [RFC Errata 4493](https://www.rfc-editor.org/errata_search.php?eid=4493)
    Unspecific = 0,
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,

    /// [RFC5492](https://datatracker.ietf.org/doc/html/rfc5492)
    UnsupportedCapability = 7,

    /// [RFC9234](https://datatracker.ietf.org/doc/html/rfc9234)
    RoleMismatch = 11,
}

impl From<OpenMessageErrorSubCode> for u8 {
    fn from(value: OpenMessageErrorSubCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedOpenMessageErrorSubCode(pub u8);

impl TryFrom<u8> for OpenMessageErrorSubCode {
    type Error = UndefinedOpenMessageErrorSubCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedOpenMessageErrorSubCode(value)),
        }
    }
}

/// UPDATE Message Error sub-codes for [`BgpErrorNotificationCode::UpdateMessageError`] as defined by IANA [UPDATE Message Error subcodes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-7)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum UpdateMessageErrorSubCode {
    /// [RFC Errata 4493](https://www.rfc-editor.org/errata_search.php?eid=4493)
    Unspecific = 0,
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    InvalidNextHopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAsPath = 11,
}

impl From<UpdateMessageErrorSubCode> for u8 {
    fn from(value: UpdateMessageErrorSubCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedUpdateMessageErrorSubCode(pub u8);

impl TryFrom<u8> for UpdateMessageErrorSubCode {
    type Error = UndefinedUpdateMessageErrorSubCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedUpdateMessageErrorSubCode(value)),
        }
    }
}

/// BGP Finite State Machine Error sub-codes for [`BgpErrorNotificationCode::FiniteStateMachineError`] as defined by IANA [BGP Finite State Machine Error Subcodes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-finite-state-machine-error-subcodes)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum FiniteStateMachineErrorSubCode {
    /// [RFC6608](https://datatracker.ietf.org/doc/html/rfc6608)
    UnspecifiedError = 0,

    /// [RFC6608](https://datatracker.ietf.org/doc/html/rfc6608)
    ReceiveUnexpectedMessageInOpenSentState = 1,

    /// [RFC6608](https://datatracker.ietf.org/doc/html/rfc6608)
    ReceiveUnexpectedMessageInOpenConfirmState = 2,

    /// [RFC6608](https://datatracker.ietf.org/doc/html/rfc6608)
    ReceiveUnexpectedMessageInEstablishedState = 3,
}

impl From<FiniteStateMachineErrorSubCode> for u8 {
    fn from(value: FiniteStateMachineErrorSubCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedFiniteStateMachineErrorSubCode(pub u8);

impl TryFrom<u8> for FiniteStateMachineErrorSubCode {
    type Error = UndefinedFiniteStateMachineErrorSubCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedFiniteStateMachineErrorSubCode(value)),
        }
    }
}

/// BGP Cease NOTIFICATION message Error sub-codes for [`BgpErrorNotificationCode::Cease]` as defined by IANA [BGP Cease NOTIFICATION message subcodes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-8)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum CeaseErrorSubCode {
    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486)
    MaximumNumberOfPrefixesReached = 1,

    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486) and [RFC9003](https://datatracker.ietf.org/doc/html/rfc9003)
    AdministrativeShutdown = 2,

    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486)
    PeerDeConfigured = 3,

    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486) and [RFC9003](https://datatracker.ietf.org/doc/html/rfc9003)
    AdministrativeReset = 4,

    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486)
    ConnectionRejected = 5,

    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486)
    OtherConfigurationChange = 6,

    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486)
    ConnectionCollisionResolution = 7,

    /// [RFC4486](https://datatracker.ietf.org/doc/html/rfc4486)
    OutOfResources = 8,

    /// [RFC8538](https://datatracker.ietf.org/doc/html/rfc8538)
    HardReset = 9,

    /// [draft-ietf-idr-bfd-subcode](https://datatracker.ietf.org/doc/html/draft-ietf-idr-bfd-subcode)
    BfdDown = 10,
}

impl From<CeaseErrorSubCode> for u8 {
    fn from(value: CeaseErrorSubCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedCeaseErrorSubCode(pub u8);

impl TryFrom<u8> for CeaseErrorSubCode {
    type Error = UndefinedCeaseErrorSubCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedCeaseErrorSubCode(value)),
        }
    }
}

/// BGP ROUTE-REFRESH Message Error subcodes for [`BgpErrorNotificationCode::RouteRefreshMessageError`] as defined by IANA [BGP ROUTE-REFRESH Message Error subcodes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#route-refresh-error-subcodes)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteRefreshMessageErrorSubCode {
    /// [RFC7313](https://datatracker.ietf.org/doc/html/rfc7313)
    InvalidMessageLength = 1,
}

impl From<RouteRefreshMessageErrorSubCode> for u8 {
    fn from(value: RouteRefreshMessageErrorSubCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedRouteRefreshMessageError(pub u8);

impl TryFrom<u8> for RouteRefreshMessageErrorSubCode {
    type Error = UndefinedRouteRefreshMessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedRouteRefreshMessageError(value)),
        }
    }
}

/// [BGP OPEN Optional Parameter Types](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpOpenMessageParameterType {
    /// [RFC5492](https://datatracker.ietf.org/doc/html/rfc5492)
    Capability = 2,

    /// [RFC59072](https://datatracker.ietf.org/doc/html/rfc9072)
    ExtendedLength = 255,
}

impl From<BgpOpenMessageParameterType> for u8 {
    fn from(value: BgpOpenMessageParameterType) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedBgpOpenMessageParameterType(pub u8);

impl TryFrom<u8> for BgpOpenMessageParameterType {
    type Error = UndefinedBgpOpenMessageParameterType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBgpOpenMessageParameterType(value)),
        }
    }
}

/// [BGP Capabilities Codes](https://www.iana.org/assignments/capability-codes/capability-codes.xhtml)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpCapabilityCode {
    /// [RFC4760](https://datatracker.ietf.org/doc/html/rfc4760)
    MultiProtocolExtensions = 1,

    /// [RFC2918](https://datatracker.ietf.org/doc/html/rfc2918)
    RouteRefreshCapability = 2,

    /// [RFC5291](https://datatracker.ietf.org/doc/html/rfc5291)
    OutboundRouteFilteringCapability = 3,

    /// [RFC8950](https://datatracker.ietf.org/doc/html/rfc8950)
    ExtendedNextHopEncoding = 5,

    /// [RFC8654](https://datatracker.ietf.org/doc/html/RFC8654)
    BgpExtendedMessage = 6,

    /// [RFC8205](https://datatracker.ietf.org/doc/html/RFC8205)
    BgpSecCapability = 7,

    /// [RFC8277](https://datatracker.ietf.org/doc/html/RFC8277)
    MultipleLabelsCapability = 8,

    /// [RFC9234](https://datatracker.ietf.org/doc/html/RFC9234)
    BgpRole = 9,

    /// [RFC4724](https://datatracker.ietf.org/doc/html/RFC4724)
    GracefulRestartCapability = 64,

    /// [RFC6793](https://datatracker.ietf.org/doc/html/RFC6793)
    FourOctetAs = 65,

    /// [draft-ietf-idr-dynamic-cap](https://datatracker.ietf.org/doc/html/draft-ietf-idr-dynamic-cap)
    SupportForDynamicCapability = 67,

    /// [draft-ietf-idr-bgp-multisession](https://datatracker.ietf.org/doc/html/draft-ietf-idr-bgp-multisession)
    MultiSessionBgpCapability = 68,

    /// [RFC7911](https://datatracker.ietf.org/doc/html/RFC7911)
    AddPathCapability = 69,

    /// [RFC7313](https://datatracker.ietf.org/doc/html/RFC7313)
    EnhancedRouteRefresh = 70,

    /// [draft-uttaro-idr-bgp-persistence](https://datatracker.ietf.org/doc/html/draft-uttaro-idr-bgp-persistence)
    LongLivedGracefulRestartLLGRCapability = 71,

    /// [draft-ietf-idr-rpd](https://datatracker.ietf.org/doc/html/draft-ietf-idr-rpd)
    RoutingPolicyDistribution = 72,

    /// [draft-ietf-idr-dynamic-cap](https://datatracker.ietf.org/doc/html/draft-ietf-idr-dynamic-cap)
    FQDN = 73,

    CiscoRouteRefresh = 128,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental239 = 239,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental240 = 240,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental241 = 241,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental242 = 242,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental243 = 243,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental244 = 244,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental245 = 245,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental246 = 246,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental247 = 247,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental248 = 248,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental249 = 249,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental250 = 250,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental251 = 251,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental252 = 252,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental253 = 253,

    /// [RFC8810](https://datatracker.ietf.org/doc/html/RFC8810)
    Experimental254 = 254,
}

impl From<BgpCapabilityCode> for u8 {
    fn from(value: BgpCapabilityCode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedBgpCapabilityCode(pub u8);

impl TryFrom<u8> for BgpCapabilityCode {
    type Error = UndefinedBgpCapabilityCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBgpCapabilityCode(value)),
        }
    }
}

/// [BGP Route Refresh Subcodes](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#route-refresh-subcodes)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteRefreshSubcode {
    NormalRequest = 0,
    BeginningOfRouteRefresh = 1,
    EndOfRouteRefresh = 2,
}

impl From<RouteRefreshSubcode> for u8 {
    fn from(value: RouteRefreshSubcode) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedRouteRefreshSubcode(pub u8);

impl TryFrom<u8> for RouteRefreshSubcode {
    type Error = UndefinedRouteRefreshSubcode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedRouteRefreshSubcode(value)),
        }
    }
}

/// [Route Distinguisher Type Field](https://www.iana.org/assignments/route-distinguisher-types/route-distinguisher-types.xhtml)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteDistinguisherTypeCode {
    As2Administrator = 0,
    Ipv4Administrator = 1,
    As4Administrator = 2,
    /// [RFC7524](https://datatracker.ietf.org/doc/html/rfc7524)
    LeafAdRoutes = 65535,
}

impl From<RouteDistinguisherTypeCode> for u16 {
    fn from(value: RouteDistinguisherTypeCode) -> Self {
        value as u16
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedRouteDistinguisherTypeCode(pub u16);

impl TryFrom<u16> for RouteDistinguisherTypeCode {
    type Error = UndefinedRouteDistinguisherTypeCode;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedRouteDistinguisherTypeCode(value)),
        }
    }
}

/// [BGP Well-known Communities](https://www.iana.org/assignments/bgp-well-known-communities/bgp-well-known-communities.xhtml)
///
/// Out of the total community space defined by [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
/// of 0x00000000 - 0xFFFFFFFF, the following ranges and values are reserved for
/// communities that have global significance and their operations shall be
/// implemented in any community-attribute-aware BGP speaker. The remainder of
/// the space, specifically 0x00010000 - 0xFFFEFFFF, is for Private Use, with
/// the first two octets encoding the autonomous system value as described by
/// the RFC.
#[repr(u32)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum WellKnownCommunity {
    /// [RFC8326](https://datatracker.ietf.org/doc/html/rfc8326)
    GracefulShutdown = 0xFFFF0000,
    /// [RFC7611](https://datatracker.ietf.org/doc/html/rfc7611)
    AcceptOwn = 0xFFFF0001,
    /// [draft-uttaro-idr-bgp-persistence](https://datatracker.ietf.org/doc/html/draft-uttaro-idr-bgp-persistence)
    LlgrStale = 0xFFFF0006,
    /// [draft-uttaro-idr-bgp-persistence](https://datatracker.ietf.org/doc/html/draft-uttaro-idr-bgp-persistence)
    NoLlgr = 0xFFFF0007,
    /// [RFC9026](https://datatracker.ietf.org/doc/html/rfc9026)
    StandbyPe = 0xFFFF0009,
    /// [RFC7999](https://datatracker.ietf.org/doc/html/rfc7999)
    BlackHole = 0xFFFF029A,
    /// [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
    NoExport = 0xFFFFFF01,
    /// [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
    NoAdvertise = 0xFFFFFF02,
    /// [RFC1997](https://datatracker.ietf.org/doc/html/rfc1997)
    NoExportSubConfederation = 0xFFFFFF03,
    /// [RFC3765](https://datatracker.ietf.org/doc/html/rfc3765)
    NoPeer = 0xFFFFFF04,
}

/// [BGP Data Collection Standard Communities](https://www.iana.org/assignments/bgp-data-collection-communities-std/bgp-data-collection-communities-std.xhtml)
///
/// Standard (outbound) communities and their encodings for export to BGP route
/// collectors defined by [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpDataCollectionCommunityValueCode {
    CustomerRoutes = 0b0000000000000001,
    PeerRoutes = 0b0000000000000010,
    InternalRoutes = 0b0000000000000011,
    InternalMoreSpecificRoutes = 0b0000000000000100,
    SpecialPurposeRoutes = 0b0000000000000101,
    UpstreamRoutes = 0b0000000000000110,
}

/// [BGP Data Collection Standard Communities](https://www.iana.org/assignments/bgp-data-collection-communities-std/bgp-data-collection-communities-std.xhtml)
///
/// Region Identifiers defined [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpDataCollectionCommunityRegionIdentifierCode {
    Africa = 0b00001,
    Oceania = 0b00010,
    Asia = 0b00011,
    Antarctic = 0b00100,
    Europe = 0b00101,
    LatinAmericaCaribbeanIslands = 0b00110,
    NorthAmerica = 0b00111,
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpExtendedCommunityType {
    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    TransitiveTwoOctet = 0x00,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    NonTransitiveTwoOctet = 0x40,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    TransitiveIpv4 = 0x01,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    NonTransitiveIpv4 = 0x41,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    TransitiveFourOctet = 0x02,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    NonTransitiveFourOctet = 0x42,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    TransitiveOpaque = 0x03,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    NonTransitiveOpaque = 0x43,

    TransitiveQosMarking = 0x04,

    NonTransitiveQosMarking = 0x44,

    CosCapability = 0x05,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Evpn = 0x06,

    // Expired draft
    // /// [draft-ietf-idr-flowspec-interfaceset](https://datatracker.ietf.org/doc/draft-ietf-idr-flowspec-interfaceset/)
    //TransitiveFlowSpec = 0x07,
    //NonTransitiveFlowSpec = 0x47,
    /// [draft-simpson-idr-flowspec-redirect](https://datatracker.ietf.org/doc/draft-simpson-idr-flowspec-redirect/)
    FlowSpecNextHop = 0x08,

    /// [draft-ietf-idr-flowspec-path-redirect](https://datatracker.ietf.org/doc/draft-ietf-idr-flowspec-path-redirect/)
    FlowSpecIndirectionId = 0x09,

    /// [draft-kaliraj-idr-bgp-classful-transport-planes](https://datatracker.ietf.org/doc/draft-kaliraj-idr-bgp-classful-transport-planes/)
    TransitiveTransportClass = 0x0a,

    /// [draft-kaliraj-idr-bgp-classful-transport-planes](https://datatracker.ietf.org/doc/draft-kaliraj-idr-bgp-classful-transport-planes/)
    NonTransitiveTransportClass = 0x4a,

    /// [RFC9015](https://datatracker.ietf.org/doc/html/rfc9015)
    ServiceFunctionChain = 0x0b,

    /// [draft-mpmz-bess-mup-safi](https://datatracker.ietf.org/doc/draft-mpmz-bess-mup-safi/)
    Srv6MobileUserPlane = 0x0c,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    /// and [RFC9184](https://datatracker.ietf.org/doc/html/rfc9184)
    GenericPart1 = 0x80,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    /// and [RFC9184](https://datatracker.ietf.org/doc/html/rfc9184)
    GenericPart2 = 0x81,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    /// and [RFC9184](https://datatracker.ietf.org/doc/html/rfc9184)
    GenericPart3 = 0x82,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental83 = 0x83,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental84 = 0x84,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental85 = 0x85,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental86 = 0x86,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental87 = 0x87,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental88 = 0x88,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental89 = 0x89,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental8A = 0x8a,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental8B = 0x8b,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental8C = 0x8c,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental8D = 0x8d,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental8E = 0x8e,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    Experimental8F = 0x8f,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    ExperimentalC0 = 0xc0,
    ExperimentalC1 = 0xc1,
    ExperimentalC2 = 0xc2,
    ExperimentalC3 = 0xc3,
    ExperimentalC4 = 0xc4,
    ExperimentalC5 = 0xc5,
    ExperimentalC6 = 0xc6,
    ExperimentalC7 = 0xc7,
    ExperimentalC8 = 0xc8,
    ExperimentalC9 = 0xc9,
    ExperimentalCa = 0xca,
    ExperimentalCb = 0xcb,
    ExperimentalCc = 0xcc,
    ExperimentalCd = 0xcd,
    ExperimentalCe = 0xce,
    ExperimentalCf = 0xcf,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedBgpExtendedCommunityType(pub u8);

impl TryFrom<u8> for BgpExtendedCommunityType {
    type Error = UndefinedBgpExtendedCommunityType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBgpExtendedCommunityType(value)),
        }
    }
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpExtendedCommunityIpv6Type {
    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    TransitiveIpv6 = 0x00,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    NonTransitiveIpv6 = 0x40,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedBgpExtendedCommunityIpv6Type(pub u8);

impl TryFrom<u8> for BgpExtendedCommunityIpv6Type {
    type Error = UndefinedBgpExtendedCommunityIpv6Type;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBgpExtendedCommunityIpv6Type(value)),
        }
    }
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveTwoOctetExtendedCommunitySubType {
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteTarget = 0x02,
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteOrigin = 0x03,

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfDomainIdentifier = 0x05,

    /// [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    BgpDataCollection = 0x08,

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    SourceAs = 0x09,

    /// [RFC6074](https://datatracker.ietf.org/doc/html/rfc6074)
    L2VpnIdentifier = 0x0a,

    CiscoVpnDistinguisher = 0x10,

    /// [draft-ietf-bess-service-chaining](https://datatracker.ietf.org/doc/html/draft-ietf-bess-service-chaining)
    RouteTargetRecord = 0x13,

    /// [draft-zzhang-idr-rt-derived-community-00](https://datatracker.ietf.org/doc/html/draft-zzhang-idr-rt-derived-community-00)
    RtDerivedEc = 0x15,

    VirtualNetworkIdentifier = 0x80,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedTransitiveTwoOctetExtendedCommunitySubType(pub u8);

impl TryFrom<u8> for TransitiveTwoOctetExtendedCommunitySubType {
    type Error = UndefinedTransitiveTwoOctetExtendedCommunitySubType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedTransitiveTwoOctetExtendedCommunitySubType(value)),
        }
    }
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum NonTransitiveTwoOctetExtendedCommunitySubType {
    /// [draft-ietf-idr-link-bandwidth](https://datatracker.ietf.org/doc/draft-ietf-idr-link-bandwidth/)
    LinkBandwidth = 0x04,

    /// [draft-drao-bgp-l3vpn-virtual-network-overlays](https://datatracker.ietf.org/doc/draft-drao-bgp-l3vpn-virtual-network-overlays/)
    VirtualNetworkIdentifier = 0x80,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedNonTransitiveTwoOctetExtendedCommunitySubType(pub u8);

impl TryFrom<u8> for NonTransitiveTwoOctetExtendedCommunitySubType {
    type Error = UndefinedNonTransitiveTwoOctetExtendedCommunitySubType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedNonTransitiveTwoOctetExtendedCommunitySubType(
                value,
            )),
        }
    }
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveFourOctetExtendedCommunitySubType {
    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    RouteTarget = 0x02,

    /// [RFC5668](https://datatracker.ietf.org/doc/html/rfc5668)
    RouteOrigin = 0x03,

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfDomainIdentifier = 0x05,

    /// [RFC4384](https://datatracker.ietf.org/doc/html/rfc4384)
    BgpDataCollection = 0x08,

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    SourceAs = 0x09,

    CiscoVpnDistinguisher = 0x10,

    /// [draft-ietf-bess-service-chaining](https://datatracker.ietf.org/doc/html/draft-ietf-bess-service-chaining)
    RouteTargetRecord = 0x13,

    /// [draft-zzhang-idr-rt-derived-community-00](https://datatracker.ietf.org/doc/html/draft-zzhang-idr-rt-derived-community-00)
    RtDerivedEc = 0x15,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedTransitiveFourOctetExtendedCommunitySubType(pub u8);

impl TryFrom<u8> for TransitiveFourOctetExtendedCommunitySubType {
    type Error = UndefinedTransitiveFourOctetExtendedCommunitySubType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedTransitiveFourOctetExtendedCommunitySubType(value)),
        }
    }
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveIpv4ExtendedCommunitySubType {
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteTarget = 0x02,
    /// [RFC4360](https://datatracker.ietf.org/doc/html/rfc4360)
    RouteOrigin = 0x03,

    /// [draft-wang-idr-bgp-ifit-capabilities](https://datatracker.ietf.org/doc/html/draft-wang-idr-bgp-ifit-capabilities)
    Ipv4Ifit = 0x04,

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfDomainIdentifier = 0x05,

    /// [RFC4577](https://datatracker.ietf.org/doc/html/rfc4577)
    OspfRouteID = 0x08,

    /// [draft-ietf-idr-node-target-ext-comm](https://datatracker.ietf.org/doc/html/draft-ietf-idr-node-target-ext-comm)
    NodeTarget = 0x09,

    /// [RFC6074](https://datatracker.ietf.org/doc/html/rfc6074)
    L2VpnIdentifier = 0x0a,

    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    VrfRouteImport = 0x0b,

    /// [draft-dong-idr-node-target-ext-comm](https://datatracker.ietf.org/doc/draft-dong-idr-node-target-ext-comm/03/)
    FlowSpecRedirectToIpv4 = 0x0c,

    CiscoVpnDistinguisher = 0x10,

    /// [RFC7524](https://datatracker.ietf.org/doc/html/rfc7524])
    InterAreaP2MpSegmentedNextHop = 0x12,

    /// [draft-ietf-bess-service-chaining](https://datatracker.ietf.org/doc/html/draft-ietf-bess-service-chaining)
    RouteTargetRecord = 0x13,

    VrfRecursiveNextHop = 0x14,

    /// [draft-zzhang-idr-rt-derived-community-00](https://datatracker.ietf.org/doc/html/draft-zzhang-idr-rt-derived-community-00)
    RtDerivedEc = 0x15,

    /// [RFC9081](https://datatracker.ietf.org/doc/html/rfc9081])
    MulticastVpnRpAddress = 0x80,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedTransitiveIpv4ExtendedCommunitySubType(pub u8);

impl TryFrom<u8> for TransitiveIpv4ExtendedCommunitySubType {
    type Error = UndefinedTransitiveIpv4ExtendedCommunitySubType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedTransitiveIpv4ExtendedCommunitySubType(value)),
        }
    }
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveIpv6ExtendedCommunitySubType {
    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    RouteTarget = 0x02,

    /// [RFC5701](https://datatracker.ietf.org/doc/html/rfc5701)
    RouteOrigin = 0x03,

    /// [draft-wang-idr-bgp-ifit-capabilities](https://datatracker.ietf.org/doc/html/draft-wang-idr-bgp-ifit-capabilities)
    Ipv6Ifit = 0x05,

    /// [RFC6515](https://datatracker.ietf.org/doc/html/rfc6515) and
    /// [RFC6514](https://datatracker.ietf.org/doc/html/rfc6514)
    VrfRouteImport = 0x0b,

    /// [draft-dong-idr-node-target-ext-comm](https://datatracker.ietf.org/doc/draft-dong-idr-node-target-ext-comm/03/)
    FlowSpecRedirectToIpv6 = 0x0c,

    /// [RFC8956](https://datatracker.ietf.org/doc/html/rfc8956)
    FlowSpecRtRedirectToIpv6 = 0x0d,

    CiscoVpnDistinguisher = 0x10,

    /// [RFC7524](https://datatracker.ietf.org/doc/html/rfc7524])
    InterAreaP2MpSegmentedNextHop = 0x12,

    /// [draft-zzhang-idr-rt-derived-community-00](https://datatracker.ietf.org/doc/html/draft-zzhang-idr-rt-derived-community-00)
    RtDerivedEc = 0x15,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedTransitiveIpv6ExtendedCommunitySubType(pub u8);

impl TryFrom<u8> for TransitiveIpv6ExtendedCommunitySubType {
    type Error = UndefinedTransitiveIpv6ExtendedCommunitySubType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedTransitiveIpv6ExtendedCommunitySubType(value)),
        }
    }
}

/// EVPN Route Types [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum L2EvpnRouteTypeCode {
    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    EthernetAutoDiscovery = 0x01,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    MacIpAdvertisement = 0x02,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    InclusiveMulticastEthernetTagRoute = 0x03,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    EthernetSegmentRoute = 0x04,

    /// [RFC9136](https://datatracker.ietf.org/doc/html/rfc9136)
    IpPrefix = 0x05,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    SelectiveMulticastEthernetTagRoute = 0x06,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    MulticastMembershipReportSynchRoute = 0x07,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    MulticastLeaveSynchRoute = 0x08,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedL2EvpnRouteTypeCode(pub u8);

impl TryFrom<u8> for L2EvpnRouteTypeCode {
    type Error = UndefinedL2EvpnRouteTypeCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedL2EvpnRouteTypeCode(value)),
        }
    }
}

/// EVPN Extended Community Sub-Types [IANA](https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#evpn)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum EvpnExtendedCommunitySubType {
    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    MacMobility = 0x00,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    EsiLabel = 0x01,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    EsImportRouteTarget = 0x02,

    /// [RFC9135](https://datatracker.ietf.org/doc/html/rfc9135)
    EvpnRoutersMac = 0x03,

    /// [RFC8214](https://datatracker.ietf.org/doc/html/rfc8214)
    EvpnL2Attribute = 0x04,

    /// [RFC8317](https://datatracker.ietf.org/doc/html/rfc8317)
    ETree = 0x05,

    /// [RFC8584](https://datatracker.ietf.org/doc/html/rfc8584)
    DfSelection = 0x06,

    /// [RFC9047](https://datatracker.ietf.org/doc/html/rfc9047)
    ArpNd = 0x08,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    MulticastFlags = 0x09,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    EviRtType0 = 0x0a,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    EviRtType1 = 0x0b,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    EviRtType2 = 0x0c,

    /// [RFC9251](https://datatracker.ietf.org/doc/html/rfc9251)
    EviRtType3 = 0x0d,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedEvpnExtendedCommunitySubType(pub u8);

impl TryFrom<u8> for EvpnExtendedCommunitySubType {
    type Error = UndefinedEvpnExtendedCommunitySubType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedEvpnExtendedCommunitySubType(value)),
        }
    }
}

/// Transitive Opaque Extended Community Sub-Types [IANA](https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#trans-opaque)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TransitiveOpaqueExtendedCommunitySubType {
    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    DefaultGateway = 0x0d,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedTransitiveOpaqueExtendedCommunitySubType(pub u8);

impl TryFrom<u8> for TransitiveOpaqueExtendedCommunitySubType {
    type Error = UndefinedTransitiveOpaqueExtendedCommunitySubType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedTransitiveOpaqueExtendedCommunitySubType(value)),
        }
    }
}

/// BGP Role Values used in the route leak prevention and detection procedures
/// [RFC9234](https://datatracker.ietf.org/doc/html/rfc9234)
#[repr(u8)]
#[derive(Display, FromRepr, Hash, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpRoleValue {
    /// The local AS is a transit provider of the remote AS
    Provider = 0x00,

    /// the local AS is a transit customer of the remote AS
    Customer = 0x01,

    /// the local AS is a Route Server (usually at an Internet exchange point),
    /// and the remote AS is its RS-Client
    RS = 0x02,

    /// the local AS is a client of an RS and the RS is the remote AS
    RsClient = 0x03,

    /// the local and remote ASes are Peers (i.e., have a lateral peering
    /// relationship)
    Peer = 0x04,
}

impl From<BgpRoleValue> for u8 {
    fn from(value: BgpRoleValue) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedBgpRoleValue(pub u8);

impl TryFrom<u8> for BgpRoleValue {
    type Error = UndefinedBgpRoleValue;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBgpRoleValue(value)),
        }
    }
}

/// Accumulated IGP Type [RFC7311](https://datatracker.ietf.org/doc/html/rfc7311)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AigpAttributeType {
    /// Accumulated IGP Metric
    AccumulatedIgpMetric = 0x01,
}

impl From<AigpAttributeType> for u8 {
    fn from(value: AigpAttributeType) -> Self {
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedAigpAttributeType(pub u8);

impl TryFrom<u8> for AigpAttributeType {
    type Error = UndefinedAigpAttributeType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedAigpAttributeType(value)),
        }
    }
}

/// Reserved by RFC6793 for AS4 that are non-mappable to AS2
pub const AS_TRANS: u16 = 23456;

/// BGP-LS NLRI Types [IANA](https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#nlri-types)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsNlriType {
    /// [RFC7752](https://datatracker.ietf.org/doc/html/rfc7752)
    Node = 1,
    /// [RFC7752](https://datatracker.ietf.org/doc/html/rfc7752)
    Link = 2,
    /// [RFC7752](https://datatracker.ietf.org/doc/html/rfc7752)
    Ipv4TopologyPrefix = 3,
    /// [RFC7752](https://datatracker.ietf.org/doc/html/rfc7752)
    Ipv6TopologyPrefix = 4,
    TePolicy = 5,
    /// [RFC9514](https://datatracker.ietf.org/doc/rfc9514/)
    Srv6Sid = 6,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnknownBgpLsNlriType(pub u16);

impl From<BgpLsNlriType> for u16 {
    fn from(value: BgpLsNlriType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for BgpLsNlriType {
    type Error = UnknownBgpLsNlriType;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UnknownBgpLsNlriType(value)),
        }
    }
}

/// BGP-LS Protocol IDs [IANA](https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#protocol-ids)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpLsProtocolId {
    IsIsLevel1 = 1,
    IsIsLevel2 = 2,
    OspfV2 = 3,
    Direct = 4,
    StaticConfiguration = 5,
    OspfV3 = 6,
    Bgp = 7,
    RsvpTe = 8,
    SegmentRouting = 9,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BgpLsProtocolIdError(pub BgpLsIanaValueError<u8>);

impl From<BgpLsProtocolId> for u8 {
    fn from(value: BgpLsProtocolId) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for BgpLsProtocolId {
    type Error = BgpLsProtocolIdError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => {
                if value == 0 {
                    Err(BgpLsProtocolIdError(BgpLsIanaValueError::Reserved(value)))
                } else {
                    Err(BgpLsProtocolIdError(BgpLsIanaValueError::Unknown(value)))
                }
            }
        }
    }
}
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsNodeDescriptorType {
    LocalNodeDescriptor = 256,
    RemoteNodeDescriptor = 257,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BgpLsNodeDescriptorTypeError(pub BgpLsIanaValueError<u16>);

impl From<BgpLsNodeDescriptorType> for u16 {
    fn from(value: BgpLsNodeDescriptorType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for BgpLsNodeDescriptorType {
    type Error = BgpLsNodeDescriptorTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => {
                if value <= 255 {
                    Err(BgpLsNodeDescriptorTypeError(BgpLsIanaValueError::Reserved(
                        value,
                    )))
                } else {
                    Err(BgpLsNodeDescriptorTypeError(BgpLsIanaValueError::Unknown(
                        value,
                    )))
                }
            }
        }
    }
}

/// BGP-LS Node Descriptor Sub-TLVs [IANA](https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsNodeDescriptorSubType {
    AutonomousSystem = 512,
    BgpLsIdentifier = 513,
    OspfAreaId = 514,
    IgpRouterId = 515,
    BgpRouterIdentifier = 516,
    MemberAsNumber = 517,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NodeDescriptorSubTypeError(pub BgpLsIanaValueError<u16>);

impl From<BgpLsNodeDescriptorSubType> for u16 {
    fn from(value: BgpLsNodeDescriptorSubType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for BgpLsNodeDescriptorSubType {
    type Error = NodeDescriptorSubTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => {
                if value <= 255 {
                    Err(NodeDescriptorSubTypeError(BgpLsIanaValueError::Reserved(
                        value,
                    )))
                } else {
                    Err(NodeDescriptorSubTypeError(BgpLsIanaValueError::Unknown(
                        value,
                    )))
                }
            }
        }
    }
}

#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsPrefixDescriptorType {
    MultiTopologyIdentifier = 263,
    OspfRouteType = 264,
    IpReachabilityInformation = 265,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrefixDescriptorTypeError(pub BgpLsIanaValueError<u16>);

impl From<BgpLsPrefixDescriptorType> for u16 {
    fn from(value: BgpLsPrefixDescriptorType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for BgpLsPrefixDescriptorType {
    type Error = PrefixDescriptorTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => {
                if value <= 255 {
                    Err(PrefixDescriptorTypeError(BgpLsIanaValueError::Reserved(
                        value,
                    )))
                } else {
                    Err(PrefixDescriptorTypeError(BgpLsIanaValueError::Unknown(
                        value,
                    )))
                }
            }
        }
    }
}

#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsLinkDescriptorType {
    LinkLocalRemoteIdentifiers = 258,
    IPv4InterfaceAddress = 259,
    IPv4NeighborAddress = 260,
    IPv6InterfaceAddress = 261,
    IPv6NeighborAddress = 262,
    MultiTopologyIdentifier = 263,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LinkDescriptorTypeError(pub BgpLsIanaValueError<u16>);

impl From<BgpLsLinkDescriptorType> for u16 {
    fn from(value: BgpLsLinkDescriptorType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for BgpLsLinkDescriptorType {
    type Error = LinkDescriptorTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => {
                if value <= 255 {
                    Err(LinkDescriptorTypeError(BgpLsIanaValueError::Reserved(
                        value,
                    )))
                } else {
                    Err(LinkDescriptorTypeError(BgpLsIanaValueError::Unknown(value)))
                }
            }
        }
    }
}

#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsDescriptorTlvType {
    LocalNodeDescriptor = 256,
    RemoteNodeDescriptor = 257,
    MultiTopologyIdentifier = 263,
    OspfRouteType = 264,
    IpReachabilityInformation = 265,
    LinkLocalRemoteIdentifiers = 258,
    IPv4InterfaceAddress = 259,
    IPv4NeighborAddress = 260,
    IPv6InterfaceAddress = 261,
    IPv6NeighborAddress = 262,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DescriptorTlvTypeError(pub BgpLsIanaValueError<u16>);

impl From<BgpLsDescriptorTlvType> for u16 {
    fn from(value: BgpLsDescriptorTlvType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for BgpLsDescriptorTlvType {
    type Error = DescriptorTlvTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => {
                if value <= 255 {
                    Err(DescriptorTlvTypeError(BgpLsIanaValueError::Reserved(value)))
                } else {
                    Err(DescriptorTlvTypeError(BgpLsIanaValueError::Unknown(value)))
                }
            }
        }
    }
}
/// Aggregate of [BgpLsLinkAttributeType] [BgpLsNodeAttributeType]
/// [BgpLsPrefixAttributeType]
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsAttributeType {
    MultiTopologyIdentifier = 263,
    NodeFlagBits = 1024,
    OpaqueNodeAttribute = 1025,
    NodeNameTlv = 1026,
    IsIsArea = 1027,
    LocalNodeIpv4RouterId = 1028,
    LocalNodeIpv6RouterId = 1029,
    RemoteNodeIpv4RouterId = 1030,
    RemoteNodeIpv6RouterId = 1031,
    RemoteNodeAdministrativeGroupColor = 1088,
    MaximumLinkBandwidth = 1089,
    MaximumReservableLinkBandwidth = 1090,
    UnreservedBandwidth = 1091,
    TeDefaultMetric = 1092,
    LinkProtectionType = 1093,
    MplsProtocolMask = 1094,
    IgpMetric = 1095,
    SharedRiskLinkGroup = 1096,
    OpaqueLinkAttribute = 1097,
    LinkName = 1098,
    IgpFlags = 1152,
    IgpRouteTag = 1153,
    IgpExtendedRouteTag = 1154,
    PrefixMetric = 1155,
    OspfForwardingAddress = 1156,
    OpaquePrefixAttribute = 1157,
    PeerNodeSid = 1101,
    PeerAdjSid = 1102,
    PeerSetSid = 1103,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Display)]
pub enum BgpLsIanaValueError<T> {
    /// Reserved Values
    Reserved(T),

    /// Unassigned or Private Use values
    Unknown(T),
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BgpLsAttributeTypeError(pub BgpLsIanaValueError<u16>);

impl From<BgpLsAttributeType> for u16 {
    fn from(afi: BgpLsAttributeType) -> Self {
        afi as u16
    }
}

impl TryFrom<u16> for BgpLsAttributeType {
    type Error = BgpLsAttributeTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => {
                if value <= 255 {
                    Err(BgpLsAttributeTypeError(BgpLsIanaValueError::Reserved(
                        value,
                    )))
                } else {
                    Err(BgpLsAttributeTypeError(BgpLsIanaValueError::Unknown(value)))
                }
            }
        }
    }
}

#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsNodeAttributeType {
    MultiTopologyIdentifier = 263,
    NodeFlagBits = 1024,
    OpaqueNodeAttribute = 1025,
    NodeNameTlv = 1026,
    IsIsArea = 1027,
    LocalNodeIpv4RouterId = 1028,
    LocalNodeIpv6RouterId = 1029,
}
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsLinkAttributeType {
    LocalNodeIpv4RouterId = 1028,
    LocalNodeIpv6RouterId = 1029,
    RemoteNodeIpv4RouterId = 1030,
    RemoteNodeIpv6RouterId = 1031,
    RemoteNodeAdministrativeGroupColor = 1088,
    MaximumLinkBandwidth = 1089,
    MaximumReservableLinkBandwidth = 1090,
    UnreservedBandwidth = 1091,
    TeDefaultMetric = 1092,
    LinkProtectionType = 1093,
    MplsProtocolMask = 1094,
    IgpMetric = 1095,
    SharedRiskLinkGroup = 1096,
    OpaqueLinkAttribute = 1097,
    LinkName = 1098,
}

#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsPrefixAttributeType {
    IgpFlags = 1152,
    IgpRouteTag = 1153,
    IgpExtendedRouteTag = 1154,
    PrefixMetric = 1155,
    OspfForwardingAddress = 1156,
    OpaquePrefixAttribute = 1157,
}

/// ```text
///        0 1 2 3 4 5 6 7
///       +-+-+-+-+-+-+-+-+
///       |V|L|B|P| Rsvd  |
///       +-+-+-+-+-+-+-+-+
/// ```
/// - V-Flag: Value Flag.  If set, then the SID carries a label value.  By
///   default, the flag is SET.
///
/// - L-Flag: Local Flag.  If set, then the value/index carried by the SID has
///   local significance.  By default, the flag is SET.
///
/// - B-Flag: Backup Flag.  If set, the SID refers to a path that is eligible
///   for protection using fast reroute (FRR).  The computation of the backup
///   forwarding path and its association with the BGP Peering SID forwarding
///   entry is implementation specific.  Section 3.6 of RFC9087 discusses some
///   of the possible ways of identifying backup paths for BGP Peering SIDs.
///
/// - P-Flag: Persistent Flag: If set, the SID is persistently allocated, i.e.,
///   the SID value remains consistent across router restart and
///   session/interface flap.
///
/// - Rsvd bits: Reserved for future use and MUST be zero when originated and
///   ignored when received.
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsSidAttributeFlags {
    ValueFlag = 0b_1000_0000,
    LocalFlag = 0b_0100_0000,
    BackupFlag = 0b_0010_0000,
    PersistentFlag = 0b_0001_0000,
}

/// ```text
/// +-----------------+-------------------------+------------+
/// |       Bit       | Description             | Reference  |
/// +-----------------+-------------------------+------------+
/// |       'O'       | Overload Bit            | [ISO10589] |
/// |       'T'       | Attached Bit            | [ISO10589] |
/// |       'E'       | External Bit            | [RFC2328]  |
/// |       'B'       | ABR Bit                 | [RFC2328]  |
/// |       'R'       | Router Bit              | [RFC5340]  |
/// |       'V'       | V6 Bit                  | [RFC5340]  |
/// | Reserved (Rsvd) | Reserved for future use |            |
/// +-----------------+-------------------------+------------+
/// ```
/// see [RFC7752 Section 3.2.3.2](https://www.rfc-editor.org/rfc/rfc7752#section-3.2.3.2)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BgpLsNodeFlagsBits {
    Overload = 0b_1000_0000,
    Attached = 0b_0100_0000,
    External = 0b_0010_0000,
    Abr = 0b_0001_0000,
    Router = 0b_0000_1000,
    V6 = 0b_0000_0100,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bgp_message_type() {
        let undefined_code = 255;
        let open_code = 1;
        let open = BgpMessageType::try_from(open_code);
        let undefined = BgpMessageType::try_from(undefined_code);
        let open_u8: u8 = BgpMessageType::Open.into();
        assert_eq!(open, Ok(BgpMessageType::Open));
        assert_eq!(open_u8, open_code);
        assert_eq!(undefined, Err(UndefinedBgpMessageType(undefined_code)));
    }

    #[test]
    fn test_bgp_path_attribute_type() {
        let undefined_code = 0;
        let origin_code = 1;
        let origin = PathAttributeType::try_from(origin_code);
        let undefined = PathAttributeType::try_from(undefined_code);
        let origin_u8: u8 = PathAttributeType::Origin.into();
        assert_eq!(origin, Ok(PathAttributeType::Origin));
        assert_eq!(origin_u8, origin_code);
        assert_eq!(undefined, Err(UndefinedPathAttributeType(undefined_code)));
    }

    #[test]
    fn test_bgp_error_notification_codee() {
        let undefined_code = 0;
        let valid_code = 1;
        let ret = BgpErrorNotificationCode::try_from(valid_code);
        let undefined = BgpErrorNotificationCode::try_from(undefined_code);
        let valid_u8: u8 = BgpErrorNotificationCode::MessageHeaderError.into();
        assert_eq!(ret, Ok(BgpErrorNotificationCode::MessageHeaderError));
        assert_eq!(valid_u8, valid_code);
        assert_eq!(
            undefined,
            Err(UndefinedBgpErrorNotificationCode(undefined_code))
        );
    }

    #[test]
    fn test_message_header_error_sub_code() {
        let undefined_code = 255;
        let valid_code = 1;
        let ret = MessageHeaderErrorSubCode::try_from(valid_code);
        let undefined = MessageHeaderErrorSubCode::try_from(undefined_code);
        let valid_u8: u8 = MessageHeaderErrorSubCode::ConnectionNotSynchronized.into();
        assert_eq!(
            ret,
            Ok(MessageHeaderErrorSubCode::ConnectionNotSynchronized)
        );
        assert_eq!(valid_u8, valid_code);
        assert_eq!(
            undefined,
            Err(UndefinedMessageHeaderErrorSubCode(undefined_code))
        );
    }

    #[test]
    fn test_message_open_message_error_sub_code() {
        let undefined_code = 255;
        let valid_code = 1;
        let ret = OpenMessageErrorSubCode::try_from(valid_code);
        let undefined = OpenMessageErrorSubCode::try_from(undefined_code);
        let valid_u8: u8 = OpenMessageErrorSubCode::UnsupportedVersionNumber.into();
        assert_eq!(ret, Ok(OpenMessageErrorSubCode::UnsupportedVersionNumber));
        assert_eq!(valid_u8, valid_code);
        assert_eq!(
            undefined,
            Err(UndefinedOpenMessageErrorSubCode(undefined_code))
        );
    }

    #[test]
    fn test_message_update_message_error_sub_code() {
        let undefined_code = 255;
        let valid_code = 1;
        let ret = UpdateMessageErrorSubCode::try_from(valid_code);
        let undefined = UpdateMessageErrorSubCode::try_from(undefined_code);
        let valid_u8: u8 = UpdateMessageErrorSubCode::MalformedAttributeList.into();
        assert_eq!(ret, Ok(UpdateMessageErrorSubCode::MalformedAttributeList));
        assert_eq!(valid_u8, valid_code);
        assert_eq!(
            undefined,
            Err(UndefinedUpdateMessageErrorSubCode(undefined_code))
        );
    }

    #[test]
    fn test_message_finite_state_machine_error_sub_code() {
        let undefined_code = 255;
        let valid_code = 1;
        let ret = FiniteStateMachineErrorSubCode::try_from(valid_code);
        let undefined = FiniteStateMachineErrorSubCode::try_from(undefined_code);
        let valid_u8: u8 =
            FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenSentState.into();
        assert_eq!(
            ret,
            Ok(FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenSentState)
        );
        assert_eq!(valid_u8, valid_code);
        assert_eq!(
            undefined,
            Err(UndefinedFiniteStateMachineErrorSubCode(undefined_code))
        );
    }

    #[test]
    fn test_cease_notification_message_error_sub_code() {
        let undefined_code = 255;
        let valid_code = 9;
        let ret = CeaseErrorSubCode::try_from(valid_code);
        let undefined = CeaseErrorSubCode::try_from(undefined_code);
        let valid_u8: u8 = CeaseErrorSubCode::HardReset.into();
        assert_eq!(ret, Ok(CeaseErrorSubCode::HardReset));
        assert_eq!(valid_u8, valid_code);
        assert_eq!(undefined, Err(UndefinedCeaseErrorSubCode(undefined_code)));
    }

    #[test]
    fn test_route_refresh_message_error_sub_code() {
        let undefined_code = 255;
        let valid_code = 1;
        let ret = RouteRefreshMessageErrorSubCode::try_from(valid_code);
        let undefined = RouteRefreshMessageErrorSubCode::try_from(undefined_code);
        let valid_u8: u8 = RouteRefreshMessageErrorSubCode::InvalidMessageLength.into();
        assert_eq!(
            ret,
            Ok(RouteRefreshMessageErrorSubCode::InvalidMessageLength)
        );
        assert_eq!(valid_u8, valid_code);
        assert_eq!(
            undefined,
            Err(UndefinedRouteRefreshMessageError(undefined_code))
        );
    }

    #[test]
    fn test_bgp_open_message_parameter_type() {
        let undefined_code = 0;
        let valid_code = 2;
        let ret = BgpOpenMessageParameterType::try_from(valid_code);
        let undefined = BgpOpenMessageParameterType::try_from(undefined_code);
        let valid_u8: u8 = BgpOpenMessageParameterType::Capability.into();
        assert_eq!(ret, Ok(BgpOpenMessageParameterType::Capability));
        assert_eq!(valid_u8, valid_code);
        assert_eq!(
            undefined,
            Err(UndefinedBgpOpenMessageParameterType(undefined_code))
        );
    }
    #[test]
    fn test_bgp_capability_code() {
        let undefined_code = 0;
        let valid_code = 2;
        let ret = BgpCapabilityCode::try_from(valid_code);
        let undefined = BgpCapabilityCode::try_from(undefined_code);
        let valid_u8: u8 = BgpCapabilityCode::RouteRefreshCapability.into();
        assert_eq!(ret, Ok(BgpCapabilityCode::RouteRefreshCapability));
        assert_eq!(valid_u8, valid_code);
        assert_eq!(undefined, Err(UndefinedBgpCapabilityCode(undefined_code)));
    }

    #[test]
    fn test_route_refresh_subcode() {
        let undefined_code = 255;
        let valid_code = 1;
        let ret = RouteRefreshSubcode::try_from(valid_code);
        let undefined = RouteRefreshSubcode::try_from(undefined_code);
        let valid_u8: u8 = RouteRefreshSubcode::BeginningOfRouteRefresh.into();
        assert_eq!(ret, Ok(RouteRefreshSubcode::BeginningOfRouteRefresh));
        assert_eq!(valid_u8, valid_code);
        assert_eq!(undefined, Err(UndefinedRouteRefreshSubcode(255)));
    }

    #[test]
    fn test_route_distinguisher_type_code() {
        let undefined_code = 255;
        let valid_code = 1;
        let ret = RouteDistinguisherTypeCode::try_from(valid_code);
        let undefined = RouteDistinguisherTypeCode::try_from(undefined_code);
        let valid_u16: u16 = RouteDistinguisherTypeCode::Ipv4Administrator.into();
        assert_eq!(ret, Ok(RouteDistinguisherTypeCode::Ipv4Administrator));
        assert_eq!(valid_u16, valid_code);
        assert_eq!(undefined, Err(UndefinedRouteDistinguisherTypeCode(255)));
    }
}
