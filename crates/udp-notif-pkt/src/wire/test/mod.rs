// Copyright (C) 2024-present The NetGauze Authors.
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

use crate::raw::{MediaType, UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket};
use crate::wire::deserialize::UdpNotifPacketParsingError;
use crate::wire::serialize::UdpNotifPacketWritingError;
use bytes::Bytes;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::test_helpers::{
    test_parse_error_bytes_reader, test_parsed_completely_bytes_reader, test_write,
};
use netgauze_parse_utils::traits::ParseFrom;
use std::collections::HashMap;

#[cfg(feature = "codec")]
pub mod pcap_tests;

#[test]
fn test_simple() -> Result<(), UdpNotifPacketWritingError> {
    let good_wire = [
        0x21, // version 1, no private space, Media type: 1 = YANG data JSON
        0x0c, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];
    let good = UdpNotifPacket::new(
        MediaType::YangDataJson,
        0x01000001,
        0x02000002,
        HashMap::new(),
        Bytes::from(&[0xff, 0xff][..]),
    );

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_invalid_s_flat() {
    let bad_wire = [
        0x31, // version 1, private space set, Media type: 1 = YANG data JSON
        0x0c, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];

    test_parse_error_bytes_reader::<UdpNotifPacket, UdpNotifPacketParsingError>(
        &bad_wire,
        &UdpNotifPacketParsingError::InvalidSFlag,
    );
}

#[test]
fn test_invalid_version() {
    let bad_wire = [
        0x01, // version 0, no private space, Media type: 1 = YANG data JSON
        0x0c, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];

    test_parse_error_bytes_reader::<UdpNotifPacket, UdpNotifPacketParsingError>(
        &bad_wire,
        &UdpNotifPacketParsingError::InvalidVersion(0),
    );
}

#[test]
fn test_invalid_header_length() {
    let bad_wire = [
        0x21, // version 0, no private space, Media type: 1 = YANG data JSON
        0xff, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];

    test_parse_error_bytes_reader::<UdpNotifPacket, UdpNotifPacketParsingError>(
        &bad_wire,
        &UdpNotifPacketParsingError::InvalidHeaderLength(0xff),
    );
}

#[test]
fn test_segment() -> Result<(), UdpNotifPacketWritingError> {
    let good_wire = [
        0x21, // version 1, no private space, Media type: 1 = YANG data JSON
        0x10, // Header length
        0x00, 0x14, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0x01, 0x04, 0x00, 0x00, // segment 0, not last segment
        0xff, 0xff, 0xff, 0xff, // dummy payload
        0x21, // version 1, no private space, Media type: 1 = YANG data JSON
        0x10, // Header length
        0x00, 0x18, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0x01, 0x04, 0x00, 0x03, // segment 1, last segment
        0xee, 0xee, 0xee, 0xee, // dummy payload
        0xdd, 0xdd, 0xdd, 0xdd, // dummy payload
    ];

    let good_pkt1 = UdpNotifPacket::new(
        MediaType::YangDataJson,
        0x01000001,
        0x02000002,
        HashMap::from([(
            UdpNotifOptionCode::Segment,
            UdpNotifOption::Segment {
                number: 0,
                last: false,
            },
        )]),
        Bytes::from(&[0xff, 0xff, 0xff, 0xff][..]),
    );

    let good_pkt2 = UdpNotifPacket::new(
        MediaType::YangDataJson,
        0x01000001,
        0x02000002,
        HashMap::from([(
            UdpNotifOptionCode::Segment,
            UdpNotifOption::Segment {
                number: 1,
                last: true,
            },
        )]),
        Bytes::from(&[0xee, 0xee, 0xee, 0xee, 0xdd, 0xdd, 0xdd, 0xdd][..]),
    );

    // Two back-to-back messages in one buffer: parse each in turn off the
    // same reader and check the consumed span round-trips.
    let mut reader = SliceReader::new(&good_wire);
    let parsed1 = UdpNotifPacket::parse(&mut reader).expect("first segment failed to parse");
    assert_eq!(parsed1, good_pkt1);
    let consumed = reader.offset();
    test_write(&good_pkt1, &good_wire[..consumed])?;

    let parsed2 = UdpNotifPacket::parse(&mut reader).expect("second segment failed to parse");
    assert_eq!(parsed2, good_pkt2);
    assert!(reader.is_empty());
    test_write(&good_pkt2, &good_wire[20..])?;
    Ok(())
}

#[test]
fn test_private_encoding() -> Result<(), UdpNotifPacketWritingError> {
    let good_wire = [
        0x3a, // version 1, private space, Media type: 10 (just arbitrary picked)
        0x10, // Header length
        0x00, 0x14, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0x02, 0x04, 0xdd, 0xee, // private encoding pen
        0xff, 0xff, 0xff, 0xff, // dummy payload
    ];
    let good = UdpNotifPacket::new(
        MediaType::Unknown(0xa),
        0x01000001,
        0x02000002,
        HashMap::from([(
            UdpNotifOptionCode::PrivateEncoding,
            UdpNotifOption::PrivateEncoding(vec![0xdd, 0xee].into()),
        )]),
        Bytes::from(&[0xff, 0xff, 0xff, 0xff][..]),
    );

    test_parsed_completely_bytes_reader(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_private_encoding_pen_not_present() {
    let bad_wire = [
        0x3a, // version 1, private space, Media type: 10 (just arbitrary picked)
        0x0c, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];

    test_parse_error_bytes_reader::<UdpNotifPacket, UdpNotifPacketParsingError>(
        &bad_wire,
        &UdpNotifPacketParsingError::PrivateEncodingOptionIsNotPresent,
    );
}
