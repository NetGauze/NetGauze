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

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

use netgauze_bgp_pkt::{wire::deserializer::BgpParsingContext, BgpMessage};
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};

// We don't pass BgpParsingContext as fuzzed input since we don't want to generate BgpParsingContext::parsing_errors.
fuzz_target!(|data: (
    &[u8],
    bool,
    HashMap<AddressType, u8>,
    HashMap<AddressType, bool>,
    bool,
    bool,
    bool,
    bool
)| {
    let (
        mut buf,
        asn4,
        multiple_labels,
        add_path,
        fail_on_non_unicast_withdraw_nlri,
        fail_on_non_unicast_update_nlri,
        fail_on_capability_error,
        fail_on_malformed_path_attr,
    ) = data;
    let mut ctx = BgpParsingContext::new(
        asn4,
        multiple_labels,
        add_path,
        fail_on_non_unicast_withdraw_nlri,
        fail_on_non_unicast_update_nlri,
        fail_on_capability_error,
        fail_on_malformed_path_attr,
    );
    while let Ok((retbuf, _msg)) = BgpMessage::from_wire(Span::new(buf), &mut ctx) {
        buf = retbuf.fragment();
        ctx.reset_parsing_errors();
    }
});
