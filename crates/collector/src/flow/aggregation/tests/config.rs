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
    use crate::flow::aggregation::config::*;
    use indexmap::IndexMap;
    use netgauze_flow_pkt::ie::IE;
    use std::time::Duration;

    #[test]
    fn test_aggregation_config_validate_success() {
        let config = AggregationConfig {
            workers: 4,
            window_duration: Duration::from_secs(300),
            lateness: Duration::from_secs(30),
            transform: IndexMap::new(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_aggregation_config_validate_invalid_worker_count() {
        let config = AggregationConfig {
            workers: 0,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform: IndexMap::new(),
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigurationError::InvalidWorkerCount)
        ));
    }

    #[test]
    fn test_aggregation_config_validate_invalid_window_duration() {
        let config = AggregationConfig {
            workers: 1,
            window_duration: Duration::ZERO,
            lateness: Duration::from_secs(10),
            transform: IndexMap::new(),
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigurationError::InvalidWindowDuration)
        ));
    }

    #[test]
    fn test_aggregation_config_validate_lateness_exceeds_window() {
        let config = AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(30),
            lateness: Duration::from_secs(60),
            transform: IndexMap::new(),
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigurationError::LatenessExceedsWindowDuration)
        ));
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_single_transforms() {
        let mut transform = IndexMap::new();
        transform.insert(IE::sourceIPv4Address, Transform::Single(Op::Key));
        transform.insert(IE::destinationIPv4Address, Transform::Single(Op::Key));
        transform.insert(IE::octetDeltaCount, Transform::Single(Op::Add));
        transform.insert(IE::packetDeltaCount, Transform::Single(Op::Add));

        let config = AggregationConfig {
            workers: 2,
            window_duration: Duration::from_secs(180),
            lateness: Duration::from_secs(30),
            transform,
        };

        let unified_config: UnifiedConfig = config.try_into().unwrap();

        // Create expected unified config
        let expected_key_select = vec![
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::destinationIPv4Address, 0),
        ];
        let expected_agg_select = vec![
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add),
        ];
        let expected_unified_config = UnifiedConfig::new(
            Duration::from_secs(180),
            Duration::from_secs(30),
            expected_key_select.into_boxed_slice(),
            expected_agg_select.into_boxed_slice(),
        );

        assert_eq!(unified_config, expected_unified_config);
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_multi_transforms() {
        let mut source_map = IndexMap::new();
        source_map.insert(0, Op::Key);
        source_map.insert(3, Op::Key);
        source_map.insert(2, Op::Key);

        let mut octet_map = IndexMap::new();
        octet_map.insert(0, Op::Add);
        octet_map.insert(3, Op::Max);
        octet_map.insert(1, Op::Min);

        let mut src_port_map = IndexMap::new();
        src_port_map.insert(1, Op::Key);

        let mut dest_port_map = IndexMap::new();
        dest_port_map.insert(1, Op::BoolMapOr);

        let mut transform = IndexMap::new();
        transform.insert(IE::sourceIPv4Address, Transform::Multi(source_map));
        transform.insert(IE::octetDeltaCount, Transform::Multi(octet_map));
        transform.insert(IE::sourceTransportPort, Transform::Multi(src_port_map));
        transform.insert(
            IE::destinationTransportPort,
            Transform::Multi(dest_port_map),
        );

        let config = AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(240),
            lateness: Duration::from_secs(40),
            transform,
        };

        let unified_config: UnifiedConfig = config.try_into().unwrap();

        // Create expected unified config
        let expected_key_select = vec![
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::sourceIPv4Address, 3),
            FieldRef::new(IE::sourceIPv4Address, 2),
            FieldRef::new(IE::sourceTransportPort, 1),
        ];
        let expected_agg_select = vec![
            AggFieldRef::new(IE::octetDeltaCount, 0, AggOp::Add),
            AggFieldRef::new(IE::octetDeltaCount, 3, AggOp::Max),
            AggFieldRef::new(IE::octetDeltaCount, 1, AggOp::Min),
            AggFieldRef::new(IE::destinationTransportPort, 1, AggOp::BoolMapOr),
        ];
        let expected_unified_config = UnifiedConfig::new(
            Duration::from_secs(240),
            Duration::from_secs(40),
            expected_key_select.into_boxed_slice(),
            expected_agg_select.into_boxed_slice(),
        );

        assert_eq!(unified_config, expected_unified_config);
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_mixed_transforms() {
        let mut octet_map = IndexMap::new();
        octet_map.insert(0, Op::Key);
        octet_map.insert(6, Op::BoolMapOr);
        octet_map.insert(2, Op::Add);

        let mut transform = IndexMap::new();
        transform.insert(IE::sourceIPv4Address, Transform::Single(Op::Key));
        transform.insert(IE::octetDeltaCount, Transform::Multi(octet_map));
        transform.insert(IE::packetDeltaCount, Transform::Single(Op::Add));

        let config = AggregationConfig {
            workers: 3,
            window_duration: Duration::from_secs(300),
            lateness: Duration::from_secs(50),
            transform,
        };

        let unified_config: UnifiedConfig = config.try_into().unwrap();

        // Create expected unified config
        let expected_key_select = vec![
            FieldRef::new(IE::sourceIPv4Address, 0),
            FieldRef::new(IE::octetDeltaCount, 0),
        ];
        let expected_agg_select = vec![
            AggFieldRef::new(IE::octetDeltaCount, 6, AggOp::BoolMapOr),
            AggFieldRef::new(IE::octetDeltaCount, 2, AggOp::Add),
            AggFieldRef::new(IE::packetDeltaCount, 0, AggOp::Add),
        ];

        let expected_unified_config = UnifiedConfig::new(
            Duration::from_secs(300),
            Duration::from_secs(50),
            expected_key_select.into_boxed_slice(),
            expected_agg_select.into_boxed_slice(),
        );

        assert_eq!(unified_config, expected_unified_config);
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_validation_failure() {
        let config = AggregationConfig {
            workers: 0, // Invalid
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform: IndexMap::new(),
        };

        let result: Result<UnifiedConfig, ConfigurationError> = config.try_into();
        assert!(matches!(
            result,
            Err(ConfigurationError::InvalidWorkerCount)
        ));
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_invalid_operation_arithmetic() {
        let mut transform = IndexMap::new();
        transform.insert(IE::destinationTransportPort, Transform::Single(Op::Add)); // invalid operation

        let config = AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform,
        };

        let result: Result<UnifiedConfig, ConfigurationError> = config.try_into();
        assert!(matches!(
            result,
            Err(ConfigurationError::InvalidOperation {
                ie: IE::destinationTransportPort,
                op: Op::Add,
                ..
            })
        ));
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_invalid_operation_comparison() {
        let mut transform = IndexMap::new();
        transform.insert(IE::samplerName, Transform::Single(Op::Min)); // invalid operation

        let config = AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform,
        };

        let result: Result<UnifiedConfig, ConfigurationError> = config.try_into();
        assert!(matches!(
            result,
            Err(ConfigurationError::InvalidOperation {
                ie: IE::samplerName,
                op: Op::Min,
                ..
            })
        ));
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_invalid_operation_bitwise() {
        let mut transform = IndexMap::new();
        transform.insert(IE::wlanSSID, Transform::Single(Op::BoolMapOr));

        let config = AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform,
        };

        let result: Result<UnifiedConfig, ConfigurationError> = config.try_into();
        assert!(matches!(
            result,
            Err(ConfigurationError::InvalidOperation {
                ie: IE::wlanSSID,
                op: Op::BoolMapOr,
                ..
            })
        ));
    }

    #[test]
    fn test_aggregation_config_try_into_unified_config_invalid_operation_multi_transform() {
        let mut iface_map = IndexMap::new();
        iface_map.insert(0, Op::Key); // valid operation
        iface_map.insert(1, Op::BoolMapOr); // invalid operation
        iface_map.insert(2, Op::Add); // valid operation
        iface_map.insert(6, Op::Max); // invalid operation

        let mut transform = IndexMap::new();
        transform.insert(IE::interfaceName, Transform::Multi(iface_map));

        let config = AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform,
        };

        let result: Result<UnifiedConfig, ConfigurationError> = config.try_into();
        assert!(matches!(
            result,
            Err(ConfigurationError::InvalidOperation {
                ie: IE::interfaceName,
                op: Op::BoolMapOr,
                ..
            })
        ));
    }
}
