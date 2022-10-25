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
extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;
use netgauze_ipfix_pkt::IpfixPacket;
use netgauze_parse_utils::{ReadablePDUWithOneInput, Span};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let templates_map = Rc::new(RefCell::new(HashMap::new()));
    while let Ok((retbuf, _msg)) = IpfixPacket::from_wire(Span::new(buf), templates_map.clone()) {
        buf = retbuf.fragment();
    }
});
