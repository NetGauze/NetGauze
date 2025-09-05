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

use crate::flow::config::*;
use apache_avro::types::ValueKind as AvroValueKind;
use chrono::{TimeZone, Utc};
use netgauze_flow_pkt::ie::{Field, IE};
use netgauze_iana::tcp::TCPHeaderFlags;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::net::Ipv4Addr;

#[test]
fn test_field_select_function_single() {
    let field_select =
        FieldSelectFunction::Single(SingleFieldSelect::new(IE::sourceIPv4Address, 0));

    // Test is_nullable
    assert!(field_select.is_nullable());

    // Test avro_type
    assert_eq!(field_select.avro_type(), AvroValueKind::String);

    // Create test flow map with multiple fields for variety
    let octet_field = Field::octetDeltaCount(1500);
    let port_field = Field::sourceTransportPort(8080);
    let src_ip_field = Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1));
    let dst_ip_field = Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2));

    let mut flow_map = FxHashMap::with_hasher(FxBuildHasher);
    flow_map.insert(SingleFieldSelect::new(IE::octetDeltaCount, 0), &octet_field);
    flow_map.insert(
        SingleFieldSelect::new(IE::sourceTransportPort, 0),
        &port_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::sourceIPv4Address, 0),
        &src_ip_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::destinationIPv4Address, 0),
        &dst_ip_field,
    );

    // Test apply - should only select the requested field (sourceIPv4Address)
    let result = field_select.apply(&flow_map);
    assert_eq!(result.unwrap()[0], src_ip_field);
}

#[test]
fn test_field_select_function_coalesce() {
    let coalesce_select = CoalesceFieldSelect {
        ies: vec![
            SingleFieldSelect::new(IE::sourceIPv4Address, 0),
            SingleFieldSelect::new(IE::destinationIPv4Address, 0),
        ],
    };
    let field_select = FieldSelectFunction::Coalesce(coalesce_select.clone());

    // Test is_nullable
    assert!(field_select.is_nullable());

    // Test avro_type (same IE types)
    assert_eq!(field_select.avro_type(), AvroValueKind::String);

    let octet_field = Field::octetDeltaCount(2500);
    let src_ip_field = Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1));
    let dst_ip_field = Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2));
    let packet_field = Field::packetDeltaCount(150);

    let mut flow_map = FxHashMap::with_hasher(FxBuildHasher);
    flow_map.insert(SingleFieldSelect::new(IE::octetDeltaCount, 0), &octet_field);
    flow_map.insert(
        SingleFieldSelect::new(IE::sourceIPv4Address, 0),
        &src_ip_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::destinationIPv4Address, 0),
        &dst_ip_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::packetDeltaCount, 0),
        &packet_field,
    );

    let result = field_select.apply(&flow_map);
    assert_eq!(result.unwrap()[0], src_ip_field);

    // Remove source address to test coalesce missing first option
    flow_map.remove(&SingleFieldSelect::new(IE::sourceIPv4Address, 0));

    // Now should select the second field since first is missing
    let result = field_select.apply(&flow_map);
    assert_eq!(result.unwrap()[0], dst_ip_field);
}

#[test]
fn test_field_select_function_multi() {
    let multi_select = MultiSelect {
        ies: vec![
            SingleFieldSelect::new(IE::sourceIPv4Address, 0),
            SingleFieldSelect::new(IE::destinationIPv4Address, 0),
        ],
    };
    let field_select = FieldSelectFunction::Multi(multi_select.clone());

    // Test is_nullable
    assert!(field_select.is_nullable());

    // Test avro_type
    assert_eq!(field_select.avro_type(), AvroValueKind::Array);

    // Create test flow map with more variety
    let octet_field = Field::octetDeltaCount(3000);
    let packet_field = Field::packetDeltaCount(200);
    let src_ip_field = Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1));
    let dst_ip_field = Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2));
    let src_port_field = Field::sourceTransportPort(443);
    let dst_port_field = Field::destinationTransportPort(8443);

    let mut flow_map = FxHashMap::with_hasher(FxBuildHasher);
    flow_map.insert(SingleFieldSelect::new(IE::octetDeltaCount, 0), &octet_field);
    flow_map.insert(
        SingleFieldSelect::new(IE::packetDeltaCount, 0),
        &packet_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::sourceIPv4Address, 0),
        &src_ip_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::destinationIPv4Address, 0),
        &dst_ip_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::sourceTransportPort, 0),
        &src_port_field,
    );
    flow_map.insert(
        SingleFieldSelect::new(IE::destinationTransportPort, 0),
        &dst_port_field,
    );

    // Test apply - should select only the two fields specified in multi_select
    let result = field_select.apply(&flow_map);
    let fields = result.unwrap();
    assert_eq!(fields.len(), 2);
    assert!(fields.contains(&src_ip_field));
    assert!(fields.contains(&dst_ip_field));
}

#[test]
fn test_field_transform_function_string() {
    let transform = FieldTransformFunction::String;

    assert_eq!(
        transform.avro_type(AvroValueKind::Long),
        AvroValueKind::String
    );

    let fields = vec![Field::octetDeltaCount(1000)];
    let result = transform.apply(Some(fields)).unwrap();
    assert_eq!(result.unwrap(), RawValue::String("1000".to_string()));
}

#[test]
fn test_field_transform_function_trimmed_string() {
    let transform = FieldTransformFunction::TrimmedString;

    assert_eq!(
        transform.avro_type(AvroValueKind::Bytes),
        AvroValueKind::String
    );

    let fields = vec![Field::applicationName(
        "test\0\0\0".to_string().into_boxed_str(),
    )];
    let result = transform.apply(Some(fields)).unwrap();
    assert_eq!(result.unwrap(), RawValue::String("test".to_string()));
}

#[test]
fn test_field_transform_function_lowercase_string() {
    let transform = FieldTransformFunction::LowercaseString;

    let fields = vec![Field::applicationName(
        "TEST-test-ABC".to_string().into_boxed_str(),
    )];
    let result = transform.apply(Some(fields)).unwrap();
    assert_eq!(
        result.unwrap(),
        RawValue::String("test-test-abc".to_string())
    );
}

#[test]
fn test_field_transform_function_timestamp_millis_string() {
    let transform = FieldTransformFunction::TimestampMillisString;

    let timestamp = Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap();
    let fields = vec![Field::flowStartMilliseconds(timestamp)];
    let result = transform.apply(Some(fields)).unwrap();
    assert_eq!(
        result.unwrap(),
        RawValue::String(timestamp.timestamp().to_string())
    );
}

#[test]
fn test_field_transform_function_rename() {
    let mut rename_map = IndexMap::new();
    rename_map.insert("tcp".to_string(), "TCP".to_string());
    rename_map.insert("udp".to_string(), "UDP".to_string());
    let transform = FieldTransformFunction::Rename(rename_map);

    // Test apply with matching value
    let fields = vec![Field::selectorName("tcp".to_string().into_boxed_str())];
    let result = transform.apply(Some(fields)).unwrap();
    assert_eq!(result.unwrap(), RawValue::String("TCP".to_string()));

    // Test apply with non-matching value
    let fields = vec![Field::selectorName("icmp".to_string().into_boxed_str())];
    let result = transform.apply(Some(fields)).unwrap();
    assert_eq!(result.unwrap(), RawValue::String("icmp".to_string()));
}

#[test]
fn test_field_transform_function_string_array() {
    let transform = FieldTransformFunction::StringArray;

    assert_eq!(
        transform.avro_type(AvroValueKind::Bytes),
        AvroValueKind::Array
    );

    let fields = vec![Field::tcpControlBits(TCPHeaderFlags::new(
        true, true, false, false, false, false, false, false,
    ))];
    let result = transform.apply(Some(fields)).unwrap();

    assert_eq!(
        result,
        Some(RawValue::StringArray(vec![
            "FIN".to_string(),
            "SYN".to_string()
        ]))
    );
}

#[test]
fn test_field_transform_function_string_array_agg() {
    let transform = FieldTransformFunction::StringArrayAgg;

    // Test avro_type
    assert_eq!(
        transform.avro_type(AvroValueKind::String),
        AvroValueKind::Array
    );

    // Test apply with multiple fields
    let fields = vec![
        Field::bgpSourceAsNumber(65001),
        Field::bgpSourceAsNumber(65002),
        Field::bgpSourceAsNumber(65003),
    ];
    let result = transform.apply(Some(fields)).unwrap();
    assert_eq!(
        result,
        Some(RawValue::StringArray(vec![
            "65001".to_string(),
            "65002".to_string(),
            "65003".to_string()
        ]))
    );
}

#[test]
fn test_field_transform_function_string_map_agg() {
    let transform = FieldTransformFunction::StringMapAgg(None);

    // Test avro_type
    assert_eq!(
        transform.avro_type(AvroValueKind::String),
        AvroValueKind::Map
    );

    // Test apply
    let fields = vec![
        Field::bgpSourceAsNumber(65001),
        Field::bgpDestinationAsNumber(65002),
    ];
    let result = transform.apply(Some(fields)).unwrap();
    assert!(result.is_some());
    assert_eq!(
        result,
        Some(RawValue::StringMap(HashMap::from([
            ("bgpSourceAsNumber".to_string(), "65001".to_string()),
            ("bgpDestinationAsNumber".to_string(), "65002".to_string()),
        ])))
    );
}

#[test]
fn test_field_transform_function_string_map_agg_with_rename() {
    // Create KeyValueRename configs for different IEs
    let bgp_source_rename = KeyValueRename {
        key_rename: "source_asn".to_string(),
        val_rename: Some({
            let mut val_map = IndexMap::new();
            val_map.insert("65001".to_string(), "AS_PRIVATE_1".to_string());
            val_map
        }),
    };

    let bgp_dest_rename = KeyValueRename {
        key_rename: "dest_asn".to_string(),
        val_rename: None,
    };

    let mut rename_map = IndexMap::new();
    rename_map.insert(IE::bgpSourceAsNumber, bgp_source_rename);
    rename_map.insert(IE::bgpDestinationAsNumber, bgp_dest_rename);

    let transform = FieldTransformFunction::StringMapAgg(Some(rename_map));

    assert_eq!(
        transform.avro_type(AvroValueKind::String),
        AvroValueKind::Map
    );

    // Test apply with some fields that have rename mappings
    let fields = vec![
        Field::bgpSourceAsNumber(65001),
        Field::bgpDestinationAsNumber(65002),
        Field::octetDeltaCount(1500),
    ];
    let result = transform.apply(Some(fields)).unwrap();

    assert_eq!(
        result,
        Some(RawValue::StringMap(HashMap::from([
            ("source_asn".to_string(), "AS_PRIVATE_1".to_string()), // key and value rename
            ("dest_asn".to_string(), "65002".to_string()),          // only key rename
            ("octetDeltaCount".to_string(), "1500".to_string()),    // no rename
        ])))
    );
}

#[test]
fn test_flow_output_config_get_avro_schema() {
    let mut fields = IndexMap::new();

    // Add regular fields
    fields.insert(
        "src_ip".to_string(),
        FieldConfig {
            select: FieldSelectFunction::Single(SingleFieldSelect::new(IE::sourceIPv4Address, 0)),
            default: None,
            transform: FieldTransformFunction::Identity,
        },
    );

    fields.insert(
        "dst_ip".to_string(),
        FieldConfig {
            select: FieldSelectFunction::Single(SingleFieldSelect::new(
                IE::destinationIPv4Address,
                0,
            )),
            default: Some(RawValue::String("0.0.0.0".to_string())),
            transform: FieldTransformFunction::Identity,
        },
    );

    fields.insert(
        "bytes".to_string(),
        FieldConfig {
            select: FieldSelectFunction::Single(SingleFieldSelect::new(IE::octetDeltaCount, 0)),
            default: None,
            transform: FieldTransformFunction::StringArray,
        },
    );

    // Add custom primitive field
    fields.insert(
        "custom_primitives.test_field".to_string(),
        FieldConfig {
            select: FieldSelectFunction::Single(SingleFieldSelect::new(IE::packetDeltaCount, 0)),
            default: None,
            transform: FieldTransformFunction::String,
        },
    );

    let config = FlowOutputConfig { fields };
    let schema = config.get_avro_schema();

    // Verify schema structure
    assert!(schema.contains("\"type\": \"record\""));
    assert!(schema.contains("\"name\": \"acct_data\""));
    assert!(schema.contains("\"fields\":"));

    // Verify field definitions
    assert!(schema.contains("\"name\": \"src_ip\""));
    assert!(schema.contains("\"type\": [\"null\", \"string\"]")); // nullable
    assert!(schema.contains("\"name\": \"dst_ip\""));
    assert!(schema.contains("\"type\": \"string\"")); // not nullable due to default
    assert!(schema.contains("\"name\": \"bytes\""));
    assert!(schema.contains("\"type\": [\"null\", {\"type\": \"array\", \"items\": \"string\"}]"));

    // Verify custom_primitives map
    assert!(schema.contains("\"name\": \"custom_primitives\""));
    assert!(schema.contains("\"type\": {\"type\": \"map\", \"values\": \"string\"}"));

    // Verify it's valid JSON structure
    assert!(schema.starts_with('{'));
    assert!(schema.ends_with('}'));
}
