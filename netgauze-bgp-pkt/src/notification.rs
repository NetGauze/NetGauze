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

/// BGP Notification message
///
///```text
/// 0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | Error code    | Error subcode |   Data (variable)             |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BGPNotificationMessage {
    MessageHeaderError(MessageHeaderError),
    OpenMessageError(OpenMessageError),
    UpdateMessageError(UpdateMessageError),
    HoldTimerExpiredError(HoldTimerExpiredError),
    FiniteStateMachineError(FiniteStateMachineError),
    CeaseError(CeaseError),
    RouteRefreshError(RouteRefreshError),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MessageHeaderError {
    Unspecific { value: Vec<u8> },
    ConnectionNotSynchronized { value: Vec<u8> },
    BadMessageLength { value: Vec<u8> },
    BadMessageType { value: Vec<u8> },
}

/// See [crate::iana::OpenMessageErrorSubCode] for full documentation
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OpenMessageError {
    Unspecific { value: Vec<u8> },
    UnsupportedVersionNumber { value: Vec<u8> },
    BadPeerAS { value: Vec<u8> },
    BadBGPIdentifier { value: Vec<u8> },
    UnsupportedOptionalParameter { value: Vec<u8> },
    UnacceptableHoldTime { value: Vec<u8> },
}

/// See [crate::iana::UpdateMessageErrorSubCode] for full documentation
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UpdateMessageError {
    MalformedAttributeList { value: Vec<u8> },
    UnrecognizedWellKnownAttribute { value: Vec<u8> },
    MissingWellKnownAttribute { value: Vec<u8> },
    AttributeFlagsError { value: Vec<u8> },
    AttributeLengthError { value: Vec<u8> },
    InvalidOriginAttribute { value: Vec<u8> },
    InvalidNextHopAttribute { value: Vec<u8> },
    OptionalAttributeError { value: Vec<u8> },
    InvalidNetworkField { value: Vec<u8> },
    MalformedASPath { value: Vec<u8> },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HoldTimerExpiredError {
    Unspecific { sub_code: u8, value: Vec<u8> },
}

/// See [crate::iana::FiniteStateMachineErrorSubCode] for full documentation
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FiniteStateMachineError {
    Unspecific { sub_code: u8, value: Vec<u8> },
    ReceiveUnexpectedMessageInOpenSentState { value: Vec<u8> },
    ReceiveUnexpectedMessageInOpenConfirmState { value: Vec<u8> },
    ReceiveUnexpectedMessageInEstablishedState { value: Vec<u8> },
}

/// See [crate::iana::CeaseErrorSubCode] for full documentation
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CeaseError {
    MaximumNumberOfPrefixesReached { value: Vec<u8> },
    AdministrativeShutdown { value: Vec<u8> },
    PeerDeConfigured { value: Vec<u8> },
    AdministrativeReset { value: Vec<u8> },
    ConnectionRejected { value: Vec<u8> },
    OtherConfigurationChange { value: Vec<u8> },
    ConnectionCollisionResolution { value: Vec<u8> },
    OutOfResources { value: Vec<u8> },
    HardReset { value: Vec<u8> },
    BFDDown { value: Vec<u8> },
}

/// See [crate::iana::RouteRefreshMessageErrorSubCode] for full documentation
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RouteRefreshError {
    InvalidMessageLength { value: Vec<u8> },
}
