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

use crate::{
    wire::{
        deserializer::BgpParsingContext, serializer::BgpMessageWritingError, tests::BGP_MARKER,
    },
    BgpMessage,
};
use netgauze_parse_utils::test_helpers::{
    combine, test_parsed_completely_with_one_input, test_write,
};

#[test]
fn test_keep_alive() -> Result<(), BgpMessageWritingError> {
    let good_wire = combine(vec![BGP_MARKER, &[0x00, 0x13, 0x04]]);

    let good = BgpMessage::KeepAlive;

    test_parsed_completely_with_one_input(
        &good_wire[..],
        &mut BgpParsingContext::asn2_default(),
        &good,
    );
    test_parsed_completely_with_one_input(&good_wire[..], &mut BgpParsingContext::default(), &good);

    test_write(&good, &good_wire[..])?;
    Ok(())
}
