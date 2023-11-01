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

#![no_main]
#![allow(clippy::type_complexity)]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;

use netgauze_bmp_pkt::{BmpMessage, PeerKey};
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{ReadablePduWithTwoInputs, Span};

fuzz_target!(|data: (
    &[u8],
    HashMap<PeerKey, HashMap<AddressType, u8>>,
    HashMap<PeerKey, HashMap<AddressType, bool>>
)| {
    let (mut buf, multiple_labels, addpath) = data;
    while let Ok((retbuf, _msg)) = BmpMessage::from_wire(Span::new(buf), &multiple_labels, &addpath)
    {
        buf = retbuf.fragment();
    }
});
