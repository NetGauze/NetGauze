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

#![no_main]

use libfuzzer_sys::fuzz_target;
use netgauze_parse_utils::WritablePdu;
use netgauze_udp_notif_pkt::raw::UdpNotifPacket;
use std::io::Cursor;

fuzz_target!(|pkt: UdpNotifPacket| {
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    let _ = pkt.write(&mut cursor);
});
