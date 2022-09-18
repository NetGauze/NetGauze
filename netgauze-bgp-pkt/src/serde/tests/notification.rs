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
        UndefinedBGPErrorNotificationCode, UndefinedMessageHeaderErrorSubCode,
        UndefinedOpenMessageErrorSubCode,
    },
    notification::{MessageHeaderError, OpenMessageError},
    serde::{
        deserializer::notification::{
            BGPNotificationMessageParsingError, LocatedBGPNotificationMessageParsingError,
            LocatedMessageHeaderErrorParsingError, LocatedOpenMessageErrorParsingError,
            MessageHeaderErrorParsingError, OpenMessageErrorParsingError,
        },
        serializer::notification::{
            BGPNotificationMessageWritingError, MessageHeaderErrorWritingError,
            OpenMessageErrorWritingError,
        },
    },
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
    let bad_invalid_code_wire = [0xff, 0x01, 0x01, 0x01];

    let good_header =
        BGPNotificationMessage::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized {
            value: good_header_wire[2..].to_vec(),
        });
    let bad_invalid_code = LocatedBGPNotificationMessageParsingError::new(
        Span::new(&bad_invalid_code_wire),
        BGPNotificationMessageParsingError::UndefinedBGPErrorNotificationCode(
            UndefinedBGPErrorNotificationCode(0xff),
        ),
    );
    test_parsed_completely(&good_header_wire, &good_header);

    test_parse_error::<BGPNotificationMessage, LocatedBGPNotificationMessageParsingError<'_>>(
        &bad_invalid_code_wire,
        &bad_invalid_code,
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

    let good =
        BGPNotificationMessage::OpenMessageError(OpenMessageError::UnsupportedVersionNumber {
            value: good_wire[2..].to_vec(),
        });

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
