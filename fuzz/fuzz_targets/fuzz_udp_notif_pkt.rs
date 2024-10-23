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
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};
use netgauze_udp_notif_pkt::UdpNotifPacket;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let mut bytes_buf = Bytes::from(Vec::from(buf));
    while let Ok((retbuf, _msg)) = UdpNotifPacket::from_wire(Span::new(buf), bytes_buf.clone()) {
        buf = retbuf.fragment();
        bytes_buf = Bytes::from(Vec::from(buf));
    }
});
