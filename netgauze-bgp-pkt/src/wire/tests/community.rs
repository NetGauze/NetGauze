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

use crate::{community::*, wire::serializer::community::*};
use netgauze_parse_utils::test_helpers::{
    test_parsed_completely, test_parsed_completely_with_one_input, test_write,
};
use std::net::Ipv4Addr;

#[test]
fn test_transitive_two_extended_community(
) -> Result<(), TransitiveTwoOctetExtendedCommunityWritingError> {
    let good_wire = [0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good = TransitiveTwoOctetExtendedCommunity::RouteTarget {
        global_admin: 1,
        local_admin: 1,
    };

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_non_transitive_two_extended_community(
) -> Result<(), NonTransitiveTwoOctetExtendedCommunityWritingError> {
    let good_wire = [0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good = NonTransitiveTwoOctetExtendedCommunity::LinkBandwidth {
        global_admin: 1,
        local_admin: 1,
    };

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_transitive_ipv4_extended_community(
) -> Result<(), TransitiveIpv4ExtendedCommunityWritingError> {
    let good_wire = [0x02, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x2d];
    let good = TransitiveIpv4ExtendedCommunity::RouteTarget {
        global_admin: Ipv4Addr::new(10, 11, 12, 8),
        local_admin: 45,
    };

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_unknown_extended_community() -> Result<(), UnknownExtendedCommunityWritingError> {
    let good_wire = [0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good = UnknownExtendedCommunity::new(0, 2, [0, 1, 0, 0, 0, 1]);

    test_parsed_completely_with_one_input(&good_wire, 0, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
