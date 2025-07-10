// Copyright (C) 2025-present The NetGauze Authors.
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

use crate::flow::aggregation::{aggregator::*, config::*};
use chrono::{TimeZone, Utc};
use netgauze_flow_pkt::{
    ie::{Field, IE},
    DataSetId,
};
use netgauze_iana::tcp::TCPHeaderFlags;
use std::collections::HashSet;

#[test]
fn test_reduce_add_operations() {
    let time1 = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
    let time2 = Utc.with_ymd_and_hms(2025, 1, 1, 11, 0, 0).unwrap();

    let agg_select = vec![
        AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
        AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add),
        AggFieldRef::new(IE::minimumTTL, 0, AggOp::Min),
        AggFieldRef::new(IE::maximumTTL, 0, AggOp::Max),
        AggFieldRef::new(IE::sourceTransportPort, 0, AggOp::Min),
        AggFieldRef::new(IE::destinationTransportPort, 0, AggOp::Max),
        AggFieldRef::new(IE::tcpControlBits, 0, AggOp::BoolMapOr),
        AggFieldRef::new(IE::fragmentFlags, 0, AggOp::BoolMapOr),
    ];

    let mut record1 = FlowCacheRecord::new(
        HashSet::from([9995, 1234]),
        HashSet::from([100, 105]),
        HashSet::from([DataSetId::new(256).unwrap()]),
        time1,
        time1,
        time1,
        time1,
        Box::new([
            Some(Field::octetDeltaCount(1000)),
            Some(Field::packetDeltaCount(10)),
            Some(Field::minimumTTL(64)),
            Some(Field::maximumTTL(128)),
            Some(Field::sourceTransportPort(80)),
            None,
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                true, true, false, false, false, false, false, false,
            ))),
            None,
        ]),
        5,
    );

    let record2 = FlowCacheRecord::new(
        HashSet::from([9996]),
        HashSet::from([101]),
        HashSet::from([DataSetId::new(257).unwrap()]),
        time2,
        time2,
        time2,
        time2,
        Box::new([
            Some(Field::octetDeltaCount(2000)),
            Some(Field::packetDeltaCount(20)),
            Some(Field::minimumTTL(32)),
            Some(Field::maximumTTL(255)),
            None,
            Some(Field::destinationTransportPort(22)),
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                false, false, false, false, false, false, true, true,
            ))),
            None,
        ]),
        1,
    );

    // Create expected reduce result
    let expected_record = FlowCacheRecord::new(
        HashSet::from([9995, 1234, 9996]),
        HashSet::from([100, 105, 101]),
        HashSet::from([DataSetId::new(256).unwrap(), DataSetId::new(257).unwrap()]),
        time1,
        time2,
        time1,
        time2,
        Box::new([
            Some(Field::octetDeltaCount(3000)),
            Some(Field::packetDeltaCount(30)),
            Some(Field::minimumTTL(32)),
            Some(Field::maximumTTL(255)),
            Some(Field::sourceTransportPort(80)),
            Some(Field::destinationTransportPort(22)),
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                true, true, false, false, false, false, true, true,
            ))),
            None,
        ]),
        6,
    );

    // Perform the reduce operation
    record1.reduce(&record2, &agg_select);

    // Compare the result with expected
    assert_eq!(record1, expected_record);
}
