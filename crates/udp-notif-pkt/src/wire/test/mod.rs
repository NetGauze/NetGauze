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
    wire::serialize::UdpNotifPacketWritingError, MediaType, UdpNotifHeader, UdpNotifPacket,
};
use bytes::Bytes;
use netgauze_parse_utils::{test_helpers::test_write, ReadablePduWithOneInput, Span};
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
        UdpNotifHeader::new(
            1,
            false,
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
        ),
        Bytes::from(&[0xff, 0xff][..]),
    );
    let bytes_buf = Bytes::from(Vec::from(good_wire));
    let ret = UdpNotifPacket::from_wire(Span::new(&good_wire), bytes_buf);
    assert!(ret.is_ok());
    let (_, parsed) = ret.unwrap();
    assert_eq!(parsed, good);
    test_write(&good, &good_wire)?;
    Ok(())
}
