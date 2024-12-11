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
    wire::serialize::UdpNotifPacketWritingError, MediaType, UdpNotifOption, UdpNotifOptionCode,
    UdpNotifPacket,
};
use bytes::Bytes;
use netgauze_parse_utils::test_helpers::{test_parsed, test_parsed_completely, test_write};
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
