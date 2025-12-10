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

use crate::{
    MediaType, UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket,
    wire::{
        deserialize::{LocatedUdpNotifPacketParsingError, UdpNotifPacketParsingError},
        serialize::UdpNotifPacketWritingError,
    },
};
use bytes::Bytes;
use netgauze_parse_utils::{
    Span,
    test_helpers::{test_parse_error, test_parsed, test_parsed_completely, test_write},
};
use nom::AsBytes;
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

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_invalid_s_flat() -> Result<(), UdpNotifPacketWritingError> {
    let bad_wire = [
        0x31, // version 1, private space set, Media type: 1 = YANG data JSON
        0x0c, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];

    let error = LocatedUdpNotifPacketParsingError::new(
        Span::new(&bad_wire),
        UdpNotifPacketParsingError::InvalidSFlag,
    );
    test_parse_error::<UdpNotifPacket, LocatedUdpNotifPacketParsingError<'_>>(&bad_wire, &error);
    Ok(())
}

#[test]
fn test_invalid_version() -> Result<(), UdpNotifPacketWritingError> {
    let bad_wire = [
        0x01, // version 0, no private space, Media type: 1 = YANG data JSON
        0x0c, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];

    let error = LocatedUdpNotifPacketParsingError::new(
        Span::new(&bad_wire),
        UdpNotifPacketParsingError::InvalidVersion(0),
    );
    test_parse_error::<UdpNotifPacket, LocatedUdpNotifPacketParsingError<'_>>(&bad_wire, &error);
    Ok(())
}

#[test]
fn test_invalid_header_length() -> Result<(), UdpNotifPacketWritingError> {
    let bad_wire = [
        0x21, // version 0, no private space, Media type: 1 = YANG data JSON
        0xff, // Header length
        0x00, 0x0e, // Message length
        0x01, 0x00, 0x00, 0x01, // Publisher ID
        0x02, 0x00, 0x00, 0x02, // Message ID
        0xff, 0xff, // dummy payload
    ];

    let error = LocatedUdpNotifPacketParsingError::new(
        Span::new(&bad_wire),
        UdpNotifPacketParsingError::InvalidHeaderLength(0xff),
    );
    test_parse_error::<UdpNotifPacket, LocatedUdpNotifPacketParsingError<'_>>(&bad_wire, &error);
    Ok(())
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
    let (remaining, _) = test_parsed(&good_wire, &good_pkt1);
    test_write(
        &good_pkt1,
        &good_wire[..(good_wire.len() - remaining.len())],
    )?;

    let (remaining, _) = test_parsed(remaining.as_bytes(), &good_pkt2);
    assert!(remaining.is_empty());
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
            UdpNotifOption::PrivateEncoding(vec![0xdd, 0xee]),
        )]),
        Bytes::from(&[0xff, 0xff, 0xff, 0xff][..]),
    );

    test_parsed_completely(&good_wire, &good);
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

    let error = LocatedUdpNotifPacketParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_wire[2..]) },
        UdpNotifPacketParsingError::PrivateEncodingOptionIsNotPresent,
    );
    test_parse_error::<UdpNotifPacket, LocatedUdpNotifPacketParsingError<'_>>(&bad_wire, &error);
}
