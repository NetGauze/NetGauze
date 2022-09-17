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
    capabilities::{BGPCapability, UnrecognizedCapability},
    serde::{
        deserializer::capabilities::{BGPCapabilityParsingError, LocatedBGPCapabilityParsingError},
        serializer::capabilities::BGPCapabilityWritingError,
    },
};
use netgauze_parse_utils::{
    test_helpers::{test_parse_error, test_parsed_completely, test_write},
    Span,
};

#[test]
fn test_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x02, 0x00];
    let bad_wire = [0x02, 1];

    let good = BGPCapability::RouteRefresh;
    let bad = LocatedBGPCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_wire[1..]) },
        BGPCapabilityParsingError::InvalidRouteRefreshLength(1),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPCapability, LocatedBGPCapabilityParsingError<'_>>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_enhanced_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x46, 0x00];
    let bad_wire = [0x46, 1];

    let good = BGPCapability::EnhancedRouteRefresh;
    let bad = LocatedBGPCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_wire[1..]) },
        BGPCapabilityParsingError::InvalidEnhancedRouteRefreshLength(1),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPCapability, LocatedBGPCapabilityParsingError<'_>>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_unrecognized_capability() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x80, 0x01, 0x01];

    let good = BGPCapability::Unrecognized(UnrecognizedCapability::new(128, vec![1]));

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}
