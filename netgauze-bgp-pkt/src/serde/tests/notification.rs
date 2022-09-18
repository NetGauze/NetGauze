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
    iana::{UndefinedBGPErrorNotificationCode, UndefinedMessageHeaderErrorSubCode},
    notification::MessageHeaderError,
    serde::{
        deserializer::notification::{
            BGPNotificationMessageParsingError, LocatedBGPNotificationMessageParsingError,
            LocatedMessageHeaderErrorParsingError, MessageHeaderErrorParsingError,
        },
        serializer::notification::{
            BGPNotificationMessageWritingError, MessageHeaderErrorWritingError,
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
