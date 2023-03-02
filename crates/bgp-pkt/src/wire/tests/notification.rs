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

use crate::{
    iana::{
        UndefinedBGPErrorNotificationCode, UndefinedCeaseErrorSubCode,
        UndefinedFiniteStateMachineErrorSubCode, UndefinedMessageHeaderErrorSubCode,
        UndefinedOpenMessageErrorSubCode, UndefinedRouteRefreshMessageError,
        UndefinedUpdateMessageErrorSubCode,
    },
    notification::{
        CeaseError, FiniteStateMachineError, HoldTimerExpiredError, MessageHeaderError,
        OpenMessageError, RouteRefreshError, UpdateMessageError,
    },
    wire::{deserializer::notification::*, serializer::notification::*},
    BGPNotificationMessage,
};
use netgauze_parse_utils::{
    test_helpers::{test_parse_error, test_parsed_completely, test_write},
    Span,
};
use nom::error::ErrorKind;

#[test]
fn test_message_header_error() -> Result<(), MessageHeaderErrorWritingError> {
    let good_unspecific_wire = [0x00, 0x01, 0x01];
    let good_synchronized_wire = [0x01, 0x01, 0x01];
    let good_length_wire = [0x02, 0x02, 0x02];
    let good_type_wire = [0x03, 0x03, 0x03];
    let bad_undefined_wire = [0xff, 0x02, 0x02];
    let bad_incomplete_wire = [];

    let good_unspecific = MessageHeaderError::Unspecific {
        value: good_synchronized_wire[1..].to_vec(),
    };
    let good_synchronized = MessageHeaderError::ConnectionNotSynchronized {
        value: good_synchronized_wire[1..].to_vec(),
    };
    let good_length = MessageHeaderError::BadMessageLength {
        value: good_length_wire[1..].to_vec(),
    };
    let good_type = MessageHeaderError::BadMessageType {
        value: good_type_wire[1..].to_vec(),
    };
    let bad_undefined = LocatedMessageHeaderErrorParsingError::new(
        Span::new(&bad_undefined_wire),
        MessageHeaderErrorParsingError::UndefinedMessageHeaderErrorType(
            UndefinedMessageHeaderErrorSubCode(0xff),
        ),
    );
    let bad_incomplete = LocatedMessageHeaderErrorParsingError::new(
        Span::new(&bad_incomplete_wire),
        MessageHeaderErrorParsingError::NomError(ErrorKind::Eof),
    );
    test_parsed_completely(&good_unspecific_wire, &good_unspecific);
    test_parsed_completely(&good_synchronized_wire, &good_synchronized);
    test_parsed_completely(&good_length_wire, &good_length);
    test_parsed_completely(&good_type_wire, &good_type);
    test_parse_error::<MessageHeaderError, LocatedMessageHeaderErrorParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<MessageHeaderError, LocatedMessageHeaderErrorParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good_unspecific, &good_unspecific_wire)?;
    test_write(&good_synchronized, &good_synchronized_wire)?;
    test_write(&good_length, &good_length_wire)?;
    test_write(&good_type, &good_type_wire)?;
    Ok(())
}

#[test]
fn test_bgp_notification_message_header() -> Result<(), BGPNotificationMessageWritingError> {
    let good_header_wire = [0x01, 0x01, 0x01, 0x01];
    let bad_undefined_code_wire = [0xff, 0x01, 0x01, 0x01];
    let bad_undefined_sub_code_wire = [0x01, 0xff, 0x01, 0x01];
    let bad_incomplete_wire = [0x01];

    let good_header =
        BGPNotificationMessage::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized {
            value: good_header_wire[2..].to_vec(),
        });
    let bad_undefined_code = LocatedBGPNotificationMessageParsingError::new(
        Span::new(&bad_undefined_code_wire),
        BGPNotificationMessageParsingError::UndefinedBGPErrorNotificationCode(
            UndefinedBGPErrorNotificationCode(0xff),
        ),
    );
    let bad_undefined_sub_code = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_undefined_sub_code_wire[1..]) },
        BGPNotificationMessageParsingError::MessageHeaderError(
            MessageHeaderErrorParsingError::UndefinedMessageHeaderErrorType(
                UndefinedMessageHeaderErrorSubCode(0xff),
            ),
        ),
    );
    let bad_incomplete = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BGPNotificationMessageParsingError::MessageHeaderError(
            MessageHeaderErrorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_header_wire, &good_header);
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_undefined_code_wire,
        &bad_undefined_code,
    );
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_undefined_sub_code_wire,
        &bad_undefined_sub_code,
    );
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good_header, &good_header_wire)?;
    Ok(())
}

#[test]
fn test_open_message_error() -> Result<(), OpenMessageErrorWritingError> {
    let good_unspecific_wire = [0x00, 0x00, 0x05];
    let good_version_wire = [0x01, 0x00, 0x00];
    let good_peer_wire = [0x02, 0x01, 0x01];
    let good_bgp_id_wire = [0x03, 0x02, 0x02];
    let good_optional_wire = [0x04, 0x03, 0x03];
    let good_hold_time_wire = [0x06, 0x04, 0x04];
    let good_capability_wire = [0x07, 0x01, 0x04];
    let good_role_mismatch_wire = [0x0b, 0x09, 0x04];
    let bad_undefined_wire = [0xff, 0x02, 0x02];
    let bad_incomplete_wire = [];

    let good_unspecific = OpenMessageError::Unspecific {
        value: good_unspecific_wire[1..].to_vec(),
    };
    let good_version = OpenMessageError::UnsupportedVersionNumber {
        value: good_version_wire[1..].to_vec(),
    };
    let good_peer = OpenMessageError::BadPeerAS {
        value: good_peer_wire[1..].to_vec(),
    };
    let good_bgp_id = OpenMessageError::BadBGPIdentifier {
        value: good_bgp_id_wire[1..].to_vec(),
    };
    let good_optional = OpenMessageError::UnsupportedOptionalParameter {
        value: good_optional_wire[1..].to_vec(),
    };
    let good_hold_time = OpenMessageError::UnacceptableHoldTime {
        value: good_hold_time_wire[1..].to_vec(),
    };
    let good_capability = OpenMessageError::UnsupportedCapability {
        value: good_capability_wire[1..].to_vec(),
    };
    let good_role_mismatch = OpenMessageError::RoleMismatch {
        value: good_role_mismatch_wire[1..].to_vec(),
    };

    let bad_undefined = LocatedOpenMessageErrorParsingError::new(
        Span::new(&bad_undefined_wire),
        OpenMessageErrorParsingError::UndefinedOpenMessageErrorSubCode(
            UndefinedOpenMessageErrorSubCode(0xff),
        ),
    );

    let bad_incomplete = LocatedOpenMessageErrorParsingError::new(
        Span::new(&bad_incomplete_wire),
        OpenMessageErrorParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_unspecific_wire, &good_unspecific);
    test_parsed_completely(&good_version_wire, &good_version);
    test_parsed_completely(&good_peer_wire, &good_peer);
    test_parsed_completely(&good_bgp_id_wire, &good_bgp_id);
    test_parsed_completely(&good_optional_wire, &good_optional);
    test_parsed_completely(&good_hold_time_wire, &good_hold_time);
    test_parsed_completely(&good_capability_wire, &good_capability);
    test_parsed_completely(&good_role_mismatch_wire, &good_role_mismatch);
    test_parse_error::<OpenMessageError, LocatedOpenMessageErrorParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<OpenMessageError, LocatedOpenMessageErrorParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good_version, &good_version_wire)?;
    test_write(&good_peer, &good_peer_wire)?;
    test_write(&good_bgp_id, &good_bgp_id_wire)?;
    test_write(&good_optional, &good_optional_wire)?;
    test_write(&good_hold_time, &good_hold_time_wire)?;
    test_write(&good_capability, &good_capability_wire)?;
    test_write(&good_role_mismatch, &good_role_mismatch_wire)?;
    Ok(())
}

#[test]
fn test_bgp_notification_open_message() -> Result<(), BGPNotificationMessageWritingError> {
    let good_wire = [0x02, 0x01, 0x01, 0x01];
    let bad_undefined_wire = [0x02, 0xff, 0x01, 0x01];
    let bad_incomplete_wire = [0x02];

    let good =
        BGPNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: good_wire[2..].to_vec(),
        });
    let bad_undefined = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_undefined_wire[1..]) },
        BGPNotificationMessageParsingError::OpenMessageError(
            OpenMessageErrorParsingError::UndefinedOpenMessageErrorSubCode(
                UndefinedOpenMessageErrorSubCode(0xff),
            ),
        ),
    );
    let bad_incomplete = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BGPNotificationMessageParsingError::OpenMessageError(
            OpenMessageErrorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_update_message_error() -> Result<(), UpdateMessageErrorWritingError> {
    let good_unspecific_wire = [0x00, 0x01, 0xff];
    let good_malformed_attributes_wire = [0x01, 0x00, 0x00];
    let good_unrecognized_well_known_attribute_wire = [0x02, 0x01, 0x01];
    let good_missing_well_know_attribute_wire = [0x03, 0x02, 0x02];
    let good_attribute_flags_wire = [0x04, 0x03, 0x03];
    let good_attribute_length_wire = [0x05, 0x04, 0x04];
    let good_invalid_origin_wire = [0x06, 0x05, 0x05];
    let good_next_hop_wire = [0x08, 0x06, 0x06];
    let good_optional_attribute_wire = [0x09, 0x07, 0x07];
    let good_network_field_wire = [0x0A, 0x08, 0x08];
    let good_malformed_as_path_wire = [0x0B, 0x09, 0x09];
    let bad_undefined_wire = [0xff, 0x020, 0x02];
    let bad_incomplete_wire = [];

    let good_unspecific = UpdateMessageError::Unspecific {
        value: good_unspecific_wire[1..].to_vec(),
    };
    let good_malformed_attributes = UpdateMessageError::MalformedAttributeList {
        value: good_malformed_attributes_wire[1..].to_vec(),
    };
    let good_unrecognized_well_known_attribute =
        UpdateMessageError::UnrecognizedWellKnownAttribute {
            value: good_unrecognized_well_known_attribute_wire[1..].to_vec(),
        };
    let good_missing_well_know_attribute = UpdateMessageError::MissingWellKnownAttribute {
        value: good_missing_well_know_attribute_wire[1..].to_vec(),
    };
    let good_attribute_flags = UpdateMessageError::AttributeFlagsError {
        value: good_attribute_flags_wire[1..].to_vec(),
    };
    let good_attribute_length = UpdateMessageError::AttributeLengthError {
        value: good_attribute_length_wire[1..].to_vec(),
    };
    let good_invalid_origin = UpdateMessageError::InvalidOriginAttribute {
        value: good_invalid_origin_wire[1..].to_vec(),
    };
    let good_next_hop = UpdateMessageError::InvalidNextHopAttribute {
        value: good_next_hop_wire[1..].to_vec(),
    };
    let good_optional_attribute = UpdateMessageError::OptionalAttributeError {
        value: good_optional_attribute_wire[1..].to_vec(),
    };
    let good_network_field = UpdateMessageError::InvalidNetworkField {
        value: good_network_field_wire[1..].to_vec(),
    };
    let good_malformed_as_path = UpdateMessageError::MalformedASPath {
        value: good_malformed_as_path_wire[1..].to_vec(),
    };

    let bad_undefined = LocatedUpdateMessageErrorParsingError::new(
        Span::new(&bad_undefined_wire),
        UpdateMessageErrorParsingError::UndefinedUpdateMessageErrorSubCode(
            UndefinedUpdateMessageErrorSubCode(0xff),
        ),
    );
    let bad_incomplete = LocatedUpdateMessageErrorParsingError::new(
        Span::new(&bad_incomplete_wire),
        UpdateMessageErrorParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_unspecific_wire, &good_unspecific);
    test_parsed_completely(&good_malformed_attributes_wire, &good_malformed_attributes);
    test_parsed_completely(
        &good_unrecognized_well_known_attribute_wire,
        &good_unrecognized_well_known_attribute,
    );
    test_parsed_completely(
        &good_missing_well_know_attribute_wire,
        &good_missing_well_know_attribute,
    );
    test_parsed_completely(&good_attribute_flags_wire, &good_attribute_flags);
    test_parsed_completely(&good_attribute_length_wire, &good_attribute_length);
    test_parsed_completely(&good_invalid_origin_wire, &good_invalid_origin);
    test_parsed_completely(&good_next_hop_wire, &good_next_hop);
    test_parsed_completely(&good_optional_attribute_wire, &good_optional_attribute);
    test_parsed_completely(&good_network_field_wire, &good_network_field);
    test_parsed_completely(&good_malformed_as_path_wire, &good_malformed_as_path);
    test_parse_error::<UpdateMessageError, LocatedUpdateMessageErrorParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<UpdateMessageError, LocatedUpdateMessageErrorParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good_malformed_attributes, &good_malformed_attributes_wire)?;
    test_write(
        &good_unrecognized_well_known_attribute,
        &good_unrecognized_well_known_attribute_wire,
    )?;
    test_write(
        &good_missing_well_know_attribute,
        &good_missing_well_know_attribute_wire,
    )?;
    test_write(&good_unspecific, &good_unspecific_wire)?;
    test_write(&good_attribute_flags, &good_attribute_flags_wire)?;
    test_write(&good_attribute_length, &good_attribute_length_wire)?;
    test_write(&good_invalid_origin, &good_invalid_origin_wire)?;
    test_write(&good_next_hop, &good_next_hop_wire)?;
    test_write(&good_optional_attribute, &good_optional_attribute_wire)?;
    test_write(&good_network_field, &good_network_field_wire)?;
    test_write(&good_malformed_as_path, &good_malformed_as_path_wire)?;
    Ok(())
}

#[test]
fn test_bgp_notification_update_message() -> Result<(), BGPNotificationMessageWritingError> {
    let good_wire = [0x03, 0x01, 0x01, 0x01];
    let bad_undefined_wire = [0x03, 0xff, 0x01, 0x01];
    let bad_incomplete_wire = [0x03];

    let good =
        BGPNotificationMessage::UpdateMessageError(UpdateMessageError::MalformedAttributeList {
            value: good_wire[2..].to_vec(),
        });

    let bad_undefined = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_undefined_wire[1..]) },
        BGPNotificationMessageParsingError::UpdateMessageError(
            UpdateMessageErrorParsingError::UndefinedUpdateMessageErrorSubCode(
                UndefinedUpdateMessageErrorSubCode(0xff),
            ),
        ),
    );
    let bad_incomplete = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BGPNotificationMessageParsingError::UpdateMessageError(
            UpdateMessageErrorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_hold_timer_expired_error() -> Result<(), HoldTimerExpiredErrorWritingError> {
    let good_wire = [0x01, 0x02, 0x02];
    let bad_incomplete_wire = [];

    let good = HoldTimerExpiredError::Unspecific {
        sub_code: good_wire[0],
        value: good_wire[1..].to_vec(),
    };
    let bad_incomplete = LocatedHoldTimerExpiredErrorParsingError::new(
        Span::new(&bad_incomplete_wire),
        HoldTimerExpiredErrorParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<HoldTimerExpiredError, LocatedHoldTimerExpiredErrorParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_bgp_notification_hold_timer_expired() -> Result<(), BGPNotificationMessageWritingError> {
    let good_wire = [0x04, 0x03, 0x01, 0x01];
    let bad_incomplete_wire = [0x04];

    let good = BGPNotificationMessage::HoldTimerExpiredError(HoldTimerExpiredError::Unspecific {
        sub_code: good_wire[1],
        value: good_wire[2..].to_vec(),
    });

    let bad_incomplete = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BGPNotificationMessageParsingError::HoldTimerExpiredError(
            HoldTimerExpiredErrorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_finite_state_machine_error() -> Result<(), FiniteStateMachineErrorWritingError> {
    let good_unspecified_wire = [0x00, 0x02, 0x02];
    let good_in_open_wire = [0x01, 0x02, 0x02];
    let good_in_open_confirm_wire = [0x02, 0x02, 0x02];
    let good_in_establish_wire = [0x03, 0x02, 0x02];
    let bad_undefined_wire = [0xff, 0x020, 0x02];
    let bad_incomplete_wire = [];

    let good_unspecified = FiniteStateMachineError::Unspecific {
        value: good_unspecified_wire[1..].to_vec(),
    };
    let good_in_open = FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState {
        value: good_in_open_wire[1..].to_vec(),
    };
    let good_in_open_confirm =
        FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
            value: good_in_open_confirm_wire[1..].to_vec(),
        };
    let good_in_establish = FiniteStateMachineError::ReceiveUnexpectedMessageInEstablishedState {
        value: good_in_establish_wire[1..].to_vec(),
    };

    let bad_undefined = LocatedFiniteStateMachineErrorParsingError::new(
        Span::new(&bad_undefined_wire),
        FiniteStateMachineErrorParsingError::Undefined(UndefinedFiniteStateMachineErrorSubCode(
            0xff,
        )),
    );
    let bad_incomplete = LocatedFiniteStateMachineErrorParsingError::new(
        Span::new(&bad_incomplete_wire),
        FiniteStateMachineErrorParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_unspecified_wire, &good_unspecified);
    test_parsed_completely(&good_in_open_wire, &good_in_open);
    test_parsed_completely(&good_in_open_confirm_wire, &good_in_open_confirm);
    test_parsed_completely(&good_in_establish_wire, &good_in_establish);

    test_parse_error::<FiniteStateMachineError, LocatedFiniteStateMachineErrorParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<FiniteStateMachineError, LocatedFiniteStateMachineErrorParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );
    test_write(&good_unspecified, &good_unspecified_wire)?;
    test_write(&good_in_open, &good_in_open_wire)?;
    test_write(&good_in_open_confirm, &good_in_open_confirm_wire)?;
    test_write(&good_in_establish, &good_in_establish_wire)?;
    Ok(())
}

#[test]
fn test_bgp_notification_finite_state_machine() -> Result<(), BGPNotificationMessageWritingError> {
    let good_wire = [0x05, 0x01, 0x01, 0x01];
    let bad_undefined_wire = [0x05, 0xff, 0x01, 0x01];
    let bad_incomplete_wire = [0x05];

    let good = BGPNotificationMessage::FiniteStateMachineError(
        FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState {
            value: good_wire[2..].to_vec(),
        },
    );

    let bad_undefined = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_undefined_wire[1..]) },
        BGPNotificationMessageParsingError::FiniteStateMachineError(
            FiniteStateMachineErrorParsingError::Undefined(
                UndefinedFiniteStateMachineErrorSubCode(0xff),
            ),
        ),
    );
    let bad_incomplete = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BGPNotificationMessageParsingError::FiniteStateMachineError(
            FiniteStateMachineErrorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_cease_error() -> Result<(), CeaseErrorWritingError> {
    let good_max_prefix_wire = [0x01, 0x02, 0x02];
    let good_admin_down_wire = [0x02, 0x02, 0x02];
    let good_deconfig_wire = [0x03, 0x02, 0x02];
    let good_admin_reset_wire = [0x04, 0x02, 0x02];
    let good_conn_reject_wire = [0x05, 0x02, 0x02];
    let good_config_chg_wire = [0x06, 0x02, 0x02];
    let good_conn_collision_wire = [0x07, 0x02, 0x02];
    let good_out_wire = [0x08, 0x02, 0x02];
    let good_reset_wire = [0x09, 0x02, 0x02];
    let good_bfd_wire = [0x0a, 0x02, 0x02];
    let bad_undefined_wire = [0xff, 0x020, 0x02];
    let bad_incomplete_wire = [];

    let good_max_prefix = CeaseError::MaximumNumberOfPrefixesReached {
        value: good_max_prefix_wire[1..].to_vec(),
    };
    let good_admin_down = CeaseError::AdministrativeShutdown {
        value: good_admin_down_wire[1..].to_vec(),
    };
    let good_deconfig = CeaseError::PeerDeConfigured {
        value: good_deconfig_wire[1..].to_vec(),
    };
    let good_admin_reset = CeaseError::AdministrativeReset {
        value: good_admin_reset_wire[1..].to_vec(),
    };
    let good_conn_reject = CeaseError::ConnectionRejected {
        value: good_conn_reject_wire[1..].to_vec(),
    };
    let good_config_chg = CeaseError::OtherConfigurationChange {
        value: good_config_chg_wire[1..].to_vec(),
    };
    let good_conn_collision = CeaseError::ConnectionCollisionResolution {
        value: good_conn_collision_wire[1..].to_vec(),
    };
    let good_out = CeaseError::OutOfResources {
        value: good_out_wire[1..].to_vec(),
    };
    let good_reset = CeaseError::HardReset {
        value: good_reset_wire[1..].to_vec(),
    };
    let good_bfd = CeaseError::BfdDown {
        value: good_bfd_wire[1..].to_vec(),
    };

    let bad_undefined = LocatedCeaseErrorParsingError::new(
        Span::new(&bad_undefined_wire),
        CeaseErrorParsingError::Undefined(UndefinedCeaseErrorSubCode(0xff)),
    );
    let bad_incomplete = LocatedCeaseErrorParsingError::new(
        Span::new(&bad_incomplete_wire),
        CeaseErrorParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_max_prefix_wire, &good_max_prefix);
    test_parsed_completely(&good_admin_down_wire, &good_admin_down);
    test_parsed_completely(&good_deconfig_wire, &good_deconfig);
    test_parsed_completely(&good_admin_reset_wire, &good_admin_reset);
    test_parsed_completely(&good_conn_reject_wire, &good_conn_reject);
    test_parsed_completely(&good_config_chg_wire, &good_config_chg);
    test_parsed_completely(&good_conn_collision_wire, &good_conn_collision);
    test_parsed_completely(&good_out_wire, &good_out);
    test_parsed_completely(&good_reset_wire, &good_reset);
    test_parsed_completely(&good_bfd_wire, &good_bfd);

    test_parse_error::<CeaseError, LocatedCeaseErrorParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<CeaseError, LocatedCeaseErrorParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );
    test_write(&good_max_prefix, &good_max_prefix_wire)?;
    test_write(&good_admin_down, &good_admin_down_wire)?;
    test_write(&good_deconfig, &good_deconfig_wire)?;
    test_write(&good_admin_reset, &good_admin_reset_wire)?;
    test_write(&good_conn_reject, &good_conn_reject_wire)?;
    test_write(&good_config_chg, &good_config_chg_wire)?;
    test_write(&good_conn_collision, &good_conn_collision_wire)?;
    test_write(&good_out, &good_out_wire)?;
    test_write(&good_reset, &good_reset_wire)?;
    test_write(&good_bfd, &good_bfd_wire)?;
    Ok(())
}

#[test]
fn test_bgp_notification_cease() -> Result<(), BGPNotificationMessageWritingError> {
    let good_wire = [0x06, 0x01, 0x01, 0x01];
    let bad_undefined_wire = [0x06, 0xff, 0x01, 0x01];
    let bad_incomplete_wire = [0x06];

    let good = BGPNotificationMessage::CeaseError(CeaseError::MaximumNumberOfPrefixesReached {
        value: good_wire[2..].to_vec(),
    });

    let bad_undefined = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_undefined_wire[1..]) },
        BGPNotificationMessageParsingError::CeaseError(CeaseErrorParsingError::Undefined(
            UndefinedCeaseErrorSubCode(0xff),
        )),
    );
    let bad_incomplete = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BGPNotificationMessageParsingError::CeaseError(CeaseErrorParsingError::NomError(
            ErrorKind::Eof,
        )),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_route_refresh_error() -> Result<(), RouteRefreshErrorWritingError> {
    let good_wire = [0x01, 0x02, 0x02];
    let bad_undefined_wire = [0xff];
    let bad_incomplete_wire = [];

    let good = RouteRefreshError::InvalidMessageLength {
        value: good_wire[1..].to_vec(),
    };

    let bad_undefined = LocatedRouteRefreshErrorParsingError::new(
        Span::new(&bad_undefined_wire),
        RouteRefreshErrorParsingError::Undefined(UndefinedRouteRefreshMessageError(0xff)),
    );
    let bad_incomplete = LocatedRouteRefreshErrorParsingError::new(
        Span::new(&bad_incomplete_wire),
        RouteRefreshErrorParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<RouteRefreshError, LocatedRouteRefreshErrorParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<RouteRefreshError, LocatedRouteRefreshErrorParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_bgp_notification_route_refresh_error() -> Result<(), BGPNotificationMessageWritingError> {
    let good_wire = [0x07, 0x01, 0x01, 0x01];
    let bad_undefined_wire = [0x07, 0xff];
    let bad_incomplete_wire = [0x07];

    let good = BGPNotificationMessage::RouteRefreshError(RouteRefreshError::InvalidMessageLength {
        value: good_wire[2..].to_vec(),
    });

    let bad_undefined = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_undefined_wire[1..]) },
        BGPNotificationMessageParsingError::RouteRefreshError(
            RouteRefreshErrorParsingError::Undefined(UndefinedRouteRefreshMessageError(0xff)),
        ),
    );

    let bad_incomplete = LocatedBGPNotificationMessageParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_incomplete_wire[1..]) },
        BGPNotificationMessageParsingError::RouteRefreshError(
            RouteRefreshErrorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_undefined_wire,
        &bad_undefined,
    );
    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}
