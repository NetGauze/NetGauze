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
use libfuzzer_sys::fuzz_target;
use netgauze_flow_pkt::ipfix::IpfixPacket;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFromWithOneInput;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    {
        let mut reader = SliceReader::new(data);
        let templates_map = HashMap::new();
        while !reader.is_empty() {
            {
                if IpfixPacket::parse(&mut reader, &mut templates_map.clone()).is_err() {
                    {
                        break;
                    }
                }
            }
        }
    }
});
