// Copyright (C) 2023-present The NetGauze Authors.
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
    community::UnknownExtendedCommunity,
    wire::serializer::community::UnknownExtendedCommunityWritingError,
};
use netgauze_parse_utils::test_helpers::{test_parsed_completely_with_one_input, test_write};

#[test]
fn test_unknown_extended_community() -> Result<(), UnknownExtendedCommunityWritingError> {
    let good_wire = [0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good = UnknownExtendedCommunity::new(0, 2, [0, 1, 0, 0, 0, 1]);

    test_parsed_completely_with_one_input(&good_wire, 0, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
