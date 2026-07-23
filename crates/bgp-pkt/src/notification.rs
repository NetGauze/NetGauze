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

//! Representations for BGP Notification message

use serde::{Deserialize, Serialize};

/// BGP Notification message
///
///```text
/// 0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | Error code    | Error subcode |   Data (variable)             |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum BgpNotificationMessage {
    MessageHeaderError(MessageHeaderError),
    OpenMessageError(OpenMessageError),
    UpdateMessageError(UpdateMessageError),
    HoldTimerExpiredError(HoldTimerExpiredError),
    FiniteStateMachineError(FiniteStateMachineError),
    CeaseError(CeaseError),
    RouteRefreshError(RouteRefreshError),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum MessageHeaderError {
    Unspecific { value: Box<[u8]> },
    ConnectionNotSynchronized { value: Box<[u8]> },
    BadMessageLength { value: Box<[u8]> },
    BadMessageType { value: Box<[u8]> },
}

/// See [`crate::iana::OpenMessageErrorSubCode`] for full documentation
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum OpenMessageError {
    Unspecific { value: Box<[u8]> },
    UnsupportedVersionNumber { value: Box<[u8]> },
    BadPeerAs { value: Box<[u8]> },
    BadBgpIdentifier { value: Box<[u8]> },
    UnsupportedOptionalParameter { value: Box<[u8]> },
    UnacceptableHoldTime { value: Box<[u8]> },
    UnsupportedCapability { value: Box<[u8]> },
    RoleMismatch { value: Box<[u8]> },
}

/// See [`crate::iana::UpdateMessageErrorSubCode`] for full documentation
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum UpdateMessageError {
    Unspecific { value: Box<[u8]> },
    MalformedAttributeList { value: Box<[u8]> },
    UnrecognizedWellKnownAttribute { value: Box<[u8]> },
    MissingWellKnownAttribute { value: Box<[u8]> },
    AttributeFlagsError { value: Box<[u8]> },
    AttributeLengthError { value: Box<[u8]> },
    InvalidOriginAttribute { value: Box<[u8]> },
    InvalidNextHopAttribute { value: Box<[u8]> },
    OptionalAttributeError { value: Box<[u8]> },
    InvalidNetworkField { value: Box<[u8]> },
    MalformedAsPath { value: Box<[u8]> },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum HoldTimerExpiredError {
    Unspecific { sub_code: u8, value: Box<[u8]> },
}

/// See [`crate::iana::FiniteStateMachineErrorSubCode`] for full documentation
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum FiniteStateMachineError {
    Unspecific { value: Box<[u8]> },
    ReceiveUnexpectedMessageInOpenSentState { value: Box<[u8]> },
    ReceiveUnexpectedMessageInOpenConfirmState { value: Box<[u8]> },
    ReceiveUnexpectedMessageInEstablishedState { value: Box<[u8]> },
}

/// See [`crate::iana::CeaseErrorSubCode`] for full documentation
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum CeaseError {
    MaximumNumberOfPrefixesReached { value: Box<[u8]> },
    AdministrativeShutdown { value: Box<[u8]> },
    PeerDeConfigured { value: Box<[u8]> },
    AdministrativeReset { value: Box<[u8]> },
    ConnectionRejected { value: Box<[u8]> },
    OtherConfigurationChange { value: Box<[u8]> },
    ConnectionCollisionResolution { value: Box<[u8]> },
    OutOfResources { value: Box<[u8]> },
    HardReset { value: Box<[u8]> },
    BfdDown { value: Box<[u8]> },
}

/// See [`crate::iana::RouteRefreshMessageErrorSubCode`] for full documentation
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum RouteRefreshError {
    InvalidMessageLength { value: Box<[u8]> },
}
