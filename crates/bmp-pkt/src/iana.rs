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

//! Contains BMP codes that are registered at IANA [BGP Monitoring Protocol (BMP) Parameters](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml)

use serde::{Deserialize, Serialize};
use strum_macros::{Display, FromRepr};

/// Corresponds to the V flag. If set indicates that the Peer address is an IPv6
/// address. See [RFC7854](https://datatracker.ietf.org/doc/html/rfc7854)
pub const PEER_FLAGS_IS_IPV6: u8 = 0b10000000;

/// Corresponds to the L flag. If set indicates that the message reflects the
/// post-policy Adj-RIB-In See [RFC7854](https://datatracker.ietf.org/doc/html/rfc7854)
pub const PEER_FLAGS_IS_POST_POLICY: u8 = 0b01000000;

/// Corresponds to the A flag. If set indicates that the message is formatted
/// using the legacy 2-byte `AS_PATH` format See [RFC7854](https://datatracker.ietf.org/doc/html/rfc7854)
pub const PEER_FLAGS_IS_ASN2: u8 = 0b00100000;

/// Corresponds to the O flag. If set indicates that the message is from
/// Adj-RIB-Out See [RFC8671](https://datatracker.ietf.org/doc/html/rfc8671)
pub const PEER_FLAGS_IS_ADJ_RIB_OUT: u8 = 0b00010000;

/// Corresponds to the F flag. If set indicates that the Loc-RIB is filtered.
/// See [RFC9069](https://datatracker.ietf.org/doc/html/rfc9069)
pub const PEER_FLAGS_IS_FILTERED: u8 = 0b10000000;

/// Currently supported BMP versions
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpVersion {
    Version3 = 3,
    Version4 = 4,
}

/// BGP version is not one of [`BmpVersion`], the carried value is the undefined
/// code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedBmpVersion(pub u8);

impl From<BmpVersion> for u8 {
    fn from(value: BmpVersion) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for BmpVersion {
    type Error = UndefinedBmpVersion;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBmpVersion(value)),
        }
    }
}

/// BMP Message types as registered in IANA [BMP Message Types](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#message-types)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpMessageType {
    RouteMonitoring = 0,
    StatisticsReport = 1,
    PeerDownNotification = 2,
    PeerUpNotification = 3,
    Initiation = 4,
    Termination = 5,
    RouteMirroring = 6,
    Experimental251 = 251,
    Experimental252 = 252,
    Experimental253 = 253,
    Experimental254 = 254,
}

/// BGP Message type is not one of [`BmpMessageType`], the carried value is the
/// undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedBmpMessageType(pub u8);

impl From<BmpMessageType> for u8 {
    fn from(value: BmpMessageType) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for BmpMessageType {
    type Error = UndefinedBmpMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBmpMessageType(value)),
        }
    }
}

/// BMP Message types as registered in IANA [BMP Message Types](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#message-types)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpPeerTypeCode {
    GlobalInstancePeer = 0,
    RdInstancePeer = 1,
    LocalInstancePeer = 2,
    LocRibInstancePeer = 3,
    Experimental251 = 251,
    Experimental252 = 252,
    Experimental253 = 253,
    Experimental254 = 254,
}

/// BGP Message type is not one of [`BmpPeerTypeCode`], the carried value is the
/// undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedBmpPeerTypeCode(pub u8);

impl From<BmpPeerTypeCode> for u8 {
    fn from(value: BmpPeerTypeCode) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for BmpPeerTypeCode {
    type Error = UndefinedBmpPeerTypeCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBmpPeerTypeCode(value)),
        }
    }
}

/// BMP `InformationTLV` types as registered in IANA [BMP Initiation and Peer Up Information TLVs](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#initiation-peer-up-tlvs)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum InitiationInformationTlvType {
    String = 0,
    SystemDescription = 1,
    SystemName = 2,
    VrfTableName = 3,
    AdminLabel = 4,
    Experimental65531 = 65531,
    Experimental65532 = 65532,
    Experimental65533 = 65533,
    Experimental65534 = 65534,
}

/// BMP `InformationTLV` type is not one of [`InitiationInformationTlvType`],
/// the carried value is the undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedInitiationInformationTlvType(pub u16);

impl From<InitiationInformationTlvType> for u16 {
    fn from(value: InitiationInformationTlvType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for InitiationInformationTlvType {
    type Error = UndefinedInitiationInformationTlvType;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedInitiationInformationTlvType(value)),
        }
    }
}

/// BMP Termination `InformationTLV` types as registered in IANA [BMP Termination Message TLVs](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#termination-message-tlvs)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum TerminationInformationTlvType {
    String = 0,
    Reason = 1,
    Experimental65531 = 65531,
    Experimental65532 = 65532,
    Experimental65533 = 65533,
    Experimental65534 = 65534,
}

/// BMP `InformationTLV` type is not one of [`TerminationInformationTlvType`],
/// the carried value is the undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedTerminationInformationTlvType(pub u16);

impl From<TerminationInformationTlvType> for u16 {
    fn from(value: TerminationInformationTlvType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for TerminationInformationTlvType {
    type Error = UndefinedTerminationInformationTlvType;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedTerminationInformationTlvType(value)),
        }
    }
}

/// BMP peer termination Reason codes as registered in IANA [BMP Termination Message Reason Codes](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#termination-message-reason-codes)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PeerTerminationCode {
    AdministrativelyClosed = 0,
    UnspecifiedReason = 1,
    OutOfResources = 2,
    RedundantConnection = 3,
    PermanentlyAdministrativelyClosed = 4,
    Experimental65531 = 65531,
    Experimental65532 = 65532,
    Experimental65533 = 65533,
    Experimental65534 = 65534,
}

/// BMP termination reason code type is not one of [`PeerTerminationCode`], the
/// carried value is the undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedPeerTerminationCode(pub u16);

impl From<PeerTerminationCode> for u16 {
    fn from(value: PeerTerminationCode) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for PeerTerminationCode {
    type Error = UndefinedPeerTerminationCode;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedPeerTerminationCode(value)),
        }
    }
}

/// BMP Peer down Reason codes as registered in IANA [BMP Peer Down Reason Codes](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-down-reason-codes)
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum PeerDownReasonCode {
    LocalSystemClosedNotificationPduFollows = 1,
    LocalSystemClosedFsmEventFollows = 2,
    RemoteSystemClosedNotificationPduFollows = 3,
    RemoteSystemClosedNoData = 4,
    PeerDeConfigured = 5,
    LocalSystemClosedTlvDataFollows = 6,
    Experimental251 = 251,
    Experimental252 = 252,
    Experimental253 = 253,
    Experimental254 = 254,
}

/// BMP Peer down reason code type is not one of [`PeerDownReasonCode`], the
/// carried value is the undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedPeerDownReasonCode(pub u8);

impl From<PeerDownReasonCode> for u8 {
    fn from(value: PeerDownReasonCode) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for PeerDownReasonCode {
    type Error = UndefinedPeerDownReasonCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedPeerDownReasonCode(value)),
        }
    }
}

/// [BMP Route Mirroring TLVs](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#route-mirroring-tlvs)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteMirroringTlvType {
    BgpMessage = 0,
    Information = 1,
    Experimental65531 = 65531,
    Experimental65532 = 65532,
    Experimental65533 = 65533,
    Experimental65534 = 65534,
}

/// BMP type is not one of [`RouteMirroringTlvType`], the carried value is the
/// undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedRouteMirroringTlvType(pub u16);

impl From<RouteMirroringTlvType> for u16 {
    fn from(value: RouteMirroringTlvType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for RouteMirroringTlvType {
    type Error = UndefinedRouteMirroringTlvType;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedRouteMirroringTlvType(value)),
        }
    }
}

/// [BMP Route Mirroring Information Codes](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#route-mirroring-information-codes)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum RouteMirroringInformation {
    ErroredPdu = 0,
    MessagesLost = 1,
    Experimental65531 = 65531,
    Experimental65532 = 65532,
    Experimental65533 = 65533,
    Experimental65534 = 65534,
}

/// Code is not one of [`RouteMirroringInformation`], the carried value is the
/// undefined code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedRouteMirroringInformation(pub u16);

impl From<RouteMirroringInformation> for u16 {
    fn from(value: RouteMirroringInformation) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for RouteMirroringInformation {
    type Error = UndefinedRouteMirroringInformation;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedRouteMirroringInformation(value)),
        }
    }
}

/// [BMP Statistics Types](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#statistics-types)
#[repr(u16)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BmpStatisticsType {
    NumberOfPrefixesRejectedByInboundPolicy = 0,
    NumberOfDuplicatePrefixAdvertisements = 1,
    NumberOfDuplicateWithdraws = 2,
    NumberOfUpdatesInvalidatedDueToClusterListLoop = 3,
    NumberOfUpdatesInvalidatedDueToAsPathLoop = 4,
    NumberOfUpdatesInvalidatedDueToOriginatorId = 5,
    NumberOfUpdatesInvalidatedDueToAsConfederationLoop = 6,
    NumberOfRoutesInAdjRibIn = 7,
    NumberOfRoutesInLocRib = 8,
    NumberOfRoutesInPerAfiSafiAdjRibIn = 9,
    NumberOfRoutesInPerAfiSafiLocRib = 10,
    NumberOfUpdatesSubjectedToTreatAsWithdraw = 11,
    NumberOfPrefixesSubjectedToTreatAsWithdraw = 12,
    NumberOfDuplicateUpdateMessagesReceived = 13,
    NumberOfRoutesInPrePolicyAdjRibOut = 14,
    NumberOfRoutesInPostPolicyAdjRibOut = 15,
    NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut = 16,
    NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut = 17,
    Experimental65531 = 65531,
    Experimental65532 = 65532,
    Experimental65533 = 65533,
    Experimental65534 = 65534,
}

/// Code is not one of [`BmpStatisticsType`], the carried value is the undefined
/// code.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UndefinedBmpStatisticsType(pub u16);

impl From<BmpStatisticsType> for u16 {
    fn from(value: BmpStatisticsType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for BmpStatisticsType {
    type Error = UndefinedBmpStatisticsType;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(UndefinedBmpStatisticsType(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bmp_message_type() {
        let undefined_code = 255;
        let stats_report_code = 1;
        let stats_report = BmpMessageType::try_from(stats_report_code);
        let undefined = BmpMessageType::try_from(undefined_code);
        let stats_report_u8: u8 = BmpMessageType::StatisticsReport.into();
        assert_eq!(stats_report, Ok(BmpMessageType::StatisticsReport));
        assert_eq!(stats_report_u8, stats_report_code);
        assert_eq!(undefined, Err(UndefinedBmpMessageType(undefined_code)));
    }

    #[test]
    fn test_bmp_peer_type() {
        let undefined_code = 255;
        let local_instance_peer_code = 2;
        let local_instance_peer = BmpPeerTypeCode::try_from(local_instance_peer_code);
        let undefined = BmpPeerTypeCode::try_from(undefined_code);
        let local_instance_peer_u8: u8 = BmpPeerTypeCode::LocalInstancePeer.into();
        assert_eq!(local_instance_peer, Ok(BmpPeerTypeCode::LocalInstancePeer));
        assert_eq!(local_instance_peer_u8, local_instance_peer_code);
        assert_eq!(undefined, Err(UndefinedBmpPeerTypeCode(undefined_code)));
    }

    #[test]
    fn test_initiation_information_tlv_type() {
        let undefined_code = 255;
        let defined_code = 2;
        let defined_value = InitiationInformationTlvType::try_from(defined_code);
        let undefined = InitiationInformationTlvType::try_from(undefined_code);
        let defined_code_u16: u16 = InitiationInformationTlvType::SystemName.into();
        assert_eq!(defined_value, Ok(InitiationInformationTlvType::SystemName));
        assert_eq!(defined_code_u16, defined_code);
        assert_eq!(
            undefined,
            Err(UndefinedInitiationInformationTlvType(undefined_code))
        );
    }

    #[test]
    fn test_termination_information_tlv_type() {
        let undefined_code = 255;
        let defined_code = 1;
        let defined_value = TerminationInformationTlvType::try_from(defined_code);
        let undefined = TerminationInformationTlvType::try_from(undefined_code);
        let defined_code_u16: u16 = TerminationInformationTlvType::Reason.into();
        assert_eq!(defined_value, Ok(TerminationInformationTlvType::Reason));
        assert_eq!(defined_code_u16, defined_code);
        assert_eq!(
            undefined,
            Err(UndefinedTerminationInformationTlvType(undefined_code))
        );
    }

    #[test]
    fn test_peer_termination_reason_code_type() {
        let undefined_code = 255;
        let defined_code = 3;
        let defined_value = PeerTerminationCode::try_from(defined_code);
        let undefined = PeerTerminationCode::try_from(undefined_code);
        let defined_code_u16: u16 = PeerTerminationCode::RedundantConnection.into();
        assert_eq!(defined_value, Ok(PeerTerminationCode::RedundantConnection));
        assert_eq!(defined_code_u16, defined_code);
        assert_eq!(undefined, Err(UndefinedPeerTerminationCode(undefined_code)));
    }

    #[test]
    fn test_peer_down_reason_code_type() {
        let undefined_code = 255;
        let defined_code = 5;
        let defined_value = PeerDownReasonCode::try_from(defined_code);
        let undefined = PeerDownReasonCode::try_from(undefined_code);
        let defined_code_u16: u8 = PeerDownReasonCode::PeerDeConfigured.into();
        assert_eq!(defined_value, Ok(PeerDownReasonCode::PeerDeConfigured));
        assert_eq!(defined_code_u16, defined_code);
        assert_eq!(undefined, Err(UndefinedPeerDownReasonCode(undefined_code)));
    }

    #[test]
    fn test_route_mirroring_tlv_type() {
        let undefined_code = 255;
        let defined_code = 1;
        let defined_value = RouteMirroringTlvType::try_from(defined_code);
        let undefined = RouteMirroringTlvType::try_from(undefined_code);
        let defined_code_u16: u16 = RouteMirroringTlvType::Information.into();
        assert_eq!(defined_value, Ok(RouteMirroringTlvType::Information));
        assert_eq!(defined_code_u16, defined_code);
        assert_eq!(
            undefined,
            Err(UndefinedRouteMirroringTlvType(undefined_code))
        );
    }

    #[test]
    fn test_route_mirroring_information() {
        let undefined_code = 255;
        let defined_code = 1;
        let defined_value = RouteMirroringInformation::try_from(defined_code);
        let undefined = RouteMirroringInformation::try_from(undefined_code);
        let defined_code_u16: u16 = RouteMirroringInformation::MessagesLost.into();
        assert_eq!(defined_value, Ok(RouteMirroringInformation::MessagesLost));
        assert_eq!(defined_code_u16, defined_code);
        assert_eq!(
            undefined,
            Err(UndefinedRouteMirroringInformation(undefined_code))
        );
    }

    #[test]
    fn test_bmp_statistics_type() {
        let undefined_code = 65535;
        let defined_code = 1;
        let defined_value = BmpStatisticsType::try_from(defined_code);
        let undefined = BmpStatisticsType::try_from(undefined_code);
        let defined_code_u16: u16 = BmpStatisticsType::NumberOfDuplicatePrefixAdvertisements.into();
        assert_eq!(
            defined_value,
            Ok(BmpStatisticsType::NumberOfDuplicatePrefixAdvertisements)
        );
        assert_eq!(defined_code_u16, defined_code);
        assert_eq!(undefined, Err(UndefinedBmpStatisticsType(undefined_code)));
    }
}
