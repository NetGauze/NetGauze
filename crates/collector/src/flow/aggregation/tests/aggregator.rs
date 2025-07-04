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

#[cfg(test)]
mod tests {
    use crate::flow::aggregation::{aggregator::*, config::*};
    use chrono::{TimeZone, Utc};
    use netgauze_analytics::aggregation::Aggregator;
    use netgauze_flow_pkt::{
        ie::{Field, IE},
        DataSetId,
    };
    use netgauze_iana::tcp::TCPHeaderFlags;
    use rustc_hash::FxHashMap;
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    fn create_test_config(
        key_select: Box<[FieldRef]>,
        agg_select: Box<[AggFieldRef]>,
    ) -> UnifiedConfig {
        UnifiedConfig::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            key_select,
            agg_select,
        )
    }

    fn create_test_agg_flow_info(
        peer_ip: IpAddr,
        key_fields: Box<[Option<Field>]>,
        agg_fields: Box<[Option<Field>]>,
        record_count: u64,
    ) -> AggFlowInfo {
        let time = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();

        AggFlowInfo::from((
            FlowCacheKey::new(peer_ip, key_fields),
            FlowCacheRecord::new(
                HashSet::from([9995]),
                HashSet::from([100]),
                HashSet::from([DataSetId::new(256).unwrap()]),
                time,
                time,
                time,
                time,
                agg_fields,
                record_count,
            ),
        ))
    }

    #[test]
    fn test_aggregator_init() {
        let config = create_test_config(Box::new([]), Box::new([]));
        let aggregator = FlowAggregator::init(config.clone());

        assert_eq!(aggregator.config(), &config);

        // Test flush (empty)
        let flushed_cache = aggregator.flush();
        assert!(flushed_cache.is_empty());
    }

    #[test]
    fn test_aggregator_push_new_flow() {
        let config = create_test_config(
            Box::new([
                FieldRef::new(IE::sourceIPv4Address, 0),
                FieldRef::new(IE::destinationIPv4Address, 0),
            ]),
            Box::new([
                AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
                AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add),
                AggFieldRef::new(IE::minimumTTL, 0, AggOp::Min),
                AggFieldRef::new(IE::maximumTTL, 0, AggOp::Max),
            ]),
        );
        let mut aggregator = FlowAggregator::init(config.clone());

        // Input AggFlowInfo
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let key_fields = Box::new([
            Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
            Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
        ]);
        let agg_fields = Box::new([
            Some(Field::octetDeltaCount(1000)),
            Some(Field::packetDeltaCount(10)),
            Some(Field::minimumTTL(64)),
            Some(Field::maximumTTL(128)),
        ]);
        let agg_flow_info = create_test_agg_flow_info(peer_ip, key_fields, agg_fields, 1);

        // Expected cache
        let expected_cache = FxHashMap::from_iter(vec![(
            agg_flow_info.key().clone(),
            agg_flow_info.record().clone(),
        )]);

        // Push to aggregator
        aggregator.push(agg_flow_info);

        // Compare aggregator cache with expected cache
        assert_eq!(aggregator.cache(), &expected_cache);

        // Test flush
        let flushed_cache = aggregator.flush();
        assert_eq!(flushed_cache, expected_cache);
    }

    #[test]
    fn test_aggregator_push_duplicate_flow_key() {
        let config = create_test_config(
            Box::new([
                FieldRef::new(IE::sourceIPv4Address, 0),
                FieldRef::new(IE::destinationIPv4Address, 0),
            ]),
            Box::new([
                AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
                AggFieldRef::new(IE::tcpControlBits, 0, AggOp::BoolMapOr),
            ]),
        );
        let mut aggregator = FlowAggregator::init(config.clone());

        // Create Input AggFlowInfos with same key
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let key_fields = Box::new([
            Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
            Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
        ]);

        let agg_fields_1 = Box::new([Some(Field::octetDeltaCount(1000)), None]);
        let agg_fields_2 = Box::new([
            Some(Field::octetDeltaCount(500)),
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                true, true, false, false, false, false, false, false,
            ))),
        ]);
        let agg_fields_3 = Box::new([
            None,
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                false, true, false, false, false, false, true, true,
            ))),
        ]);

        let agg_flow_info_1 =
            create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_1, 1);
        let agg_flow_info_2 =
            create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_2, 1);
        let agg_flow_info_3 =
            create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_3, 1);

        // Expected cache
        let agg_fields_result = Box::new([
            Some(Field::octetDeltaCount(1500)), // 1000 + 500
            Some(Field::tcpControlBits(TCPHeaderFlags::new(
                true, true, false, false, false, false, true, true,
            ))), // BoolMapOr aggregation
        ]);
        let agg_flow_info_result =
            create_test_agg_flow_info(peer_ip, key_fields.clone(), agg_fields_result, 3);

        let expected_cache = FxHashMap::from_iter(vec![(
            agg_flow_info_result.key().clone(),
            agg_flow_info_result.record().clone(),
        )]);

        // Push to aggregator
        aggregator.push(agg_flow_info_1.clone());
        aggregator.push(agg_flow_info_2.clone());
        aggregator.push(agg_flow_info_3.clone());

        // Compare aggregator cache with expected cache
        assert_eq!(aggregator.cache(), &expected_cache);

        // Test flush
        let flushed_cache = aggregator.flush();
        assert_eq!(flushed_cache, expected_cache);
    }

    #[test]
    fn test_aggregator_push_different_flow_keys() {
        let config = create_test_config(
            Box::new([
                FieldRef::new(IE::sourceIPv4Address, 0),
                FieldRef::new(IE::destinationIPv4Address, 0),
            ]),
            Box::new([
                AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
                AggFieldRef::new(IE::tcpControlBits, 0, AggOp::BoolMapOr),
            ]),
        );
        let mut aggregator = FlowAggregator::init(config.clone());

        // Create Input AggFlowInfos with same key
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let key_fields_1 = Box::new([
            Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
            Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
        ]);
        let key_fields_2 = Box::new([
            Some(Field::sourceIPv4Address(Ipv4Addr::new(20, 0, 0, 1))),
            Some(Field::destinationIPv4Address(Ipv4Addr::new(20, 0, 0, 2))),
        ]);

        let agg_fields = Box::new([Some(Field::octetDeltaCount(1000)), None]);

        let agg_flow_info_1 =
            create_test_agg_flow_info(peer_ip, key_fields_1, agg_fields.clone(), 1);
        let agg_flow_info_2 =
            create_test_agg_flow_info(peer_ip, key_fields_2, agg_fields.clone(), 1);

        let expected_cache = FxHashMap::from_iter(vec![
            (
                agg_flow_info_1.key().clone(),
                agg_flow_info_1.record().clone(),
            ),
            (
                agg_flow_info_2.key().clone(),
                agg_flow_info_2.record().clone(),
            ),
        ]);

        // Push to aggregator
        aggregator.push(agg_flow_info_1.clone());
        aggregator.push(agg_flow_info_2.clone());

        // Compare aggregator cache with expected cache
        assert_eq!(aggregator.cache(), &expected_cache);

        // Test flush
        let flushed_cache = aggregator.flush();
        assert_eq!(flushed_cache, expected_cache);
    }
}
