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
pub enum BgpExtendedCommunityIpv6Type {
    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    TransitiveIpv6 = 0x00,

    /// [RFC7153](https://datatracker.ietf.org/doc/html/rfc7153)
    NonTransitiveIpv6 = 0x40,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
pub enum NonTransitiveTwoOctetExtendedCommunitySubType {
    /// [draft-ietf-idr-link-bandwidth](https://datatracker.ietf.org/doc/draft-ietf-idr-link-bandwidth/)
    LinkBandwidth = 0x04,

    /// [draft-drao-bgp-l3vpn-virtual-network-overlays](https://datatracker.ietf.org/doc/draft-drao-bgp-l3vpn-virtual-network-overlays/)
    VirtualNetworkIdentifier = 0x80,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
pub enum EvpnRouteTypeCode {
    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    EthernetAutoDiscovery = 0x01,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    MacIpAdvertisement = 0x02,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    InclusiveMulticastEthernetTag = 0x03,

    /// [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432)
    EthernetSegment = 0x04,

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
pub struct UndefinedEvpnRouteTypeCode(pub u8);

impl TryFrom<u8> for EvpnRouteTypeCode {
    type Error = UndefinedEvpnRouteTypeCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedEvpnRouteTypeCode(value)),
        }
    }
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
