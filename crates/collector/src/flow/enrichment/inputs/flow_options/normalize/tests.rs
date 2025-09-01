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

use crate::flow::enrichment::inputs::flow_options::normalize::*;
use netgauze_flow_pkt::ie::Field;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_options_data_record_try_from_valid_scope_fields() {
    let scope_fields = vec![Field::selectorId(42)];
    let fields = vec![Field::samplingInterval(1000)];

    let ipfix_record =
        ipfix::DataRecord::new(scope_fields.into_boxed_slice(), fields.into_boxed_slice());

    let result = OptionsDataRecord::try_from(ipfix_record);
    assert!(result.is_ok());
}

#[test]
fn test_options_data_record_try_from_no_scope_fields() {
    let fields = vec![Field::samplingInterval(1000)];

    let ipfix_record = ipfix::DataRecord::new(Box::new([]), fields.into_boxed_slice());

    let result = OptionsDataRecord::try_from(ipfix_record);
    assert!(matches!(result, Err(OptionsDataRecordError::NoScopeFields)));
}

#[test]
fn test_is_sampling_type_sampling_interval() {
    let scope_fields = vec![Field::selectorId(1)];
    let fields = vec![Field::samplingInterval(1000)];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_is_sampling_type_sampler_random_interval() {
    let scope_fields = vec![Field::observationPointId(1)];
    let fields = vec![Field::samplerRandomInterval(500)];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_is_sampling_type_packet_interval_and_space() {
    let scope_fields = vec![Field::selectorId(2)];
    let fields = vec![
        Field::samplingPacketInterval(10),
        Field::samplingPacketSpace(90),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_is_sampling_type_packet_interval_only() {
    let scope_fields = vec![Field::selectorId(2)];
    let fields = vec![Field::samplingPacketInterval(10)];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    // Should be false - needs both interval and space
    assert!(!OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_is_sampling_type_time_interval_and_space() {
    let scope_fields = vec![Field::selectorId(3)];
    let fields = vec![
        Field::samplingTimeInterval(1000),
        Field::samplingTimeSpace(9000),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_is_sampling_type_size_and_population() {
    let scope_fields = vec![Field::selectorId(4)];
    let fields = vec![Field::samplingSize(100), Field::samplingPopulation(1000)];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_is_sampling_type_sampling_probability() {
    let scope_fields = vec![Field::selectorId(5)];
    let fields = vec![Field::samplingProbability(ordered_float::OrderedFloat(0.1))];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_is_sampling_type_false() {
    let scope_fields = vec![Field::selectorId(1)];
    let fields = vec![Field::interfaceName("eth0".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(!OptionsDataRecord::is_sampling_type(&record));
}

#[test]
fn test_normalize_sampling_type_basic() {
    let scope_fields = vec![Field::selectorId(42)];
    let fields = vec![
        Field::samplingInterval(1000),
        Field::paddingOctets(Box::new([0, 0, 0, 0])),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let results = OptionsDataRecord::normalize_sampling_type(record);

    // Construct expected normalized record
    let expected_scope_fields = vec![Field::selectorId(42)];
    let expected_fields = vec![Field::samplingInterval(1000)];
    let expected_record = IndexedDataRecord::new(&expected_scope_fields, &expected_fields);
    let expected_records = vec![expected_record];

    assert_eq!(results, expected_records);
}

#[test]
fn test_normalize_sampling_type_filters_exporting_process_id() {
    let scope_fields = vec![
        Field::selectorId(42),
        Field::exportingProcessId(123),
        Field::paddingOctets(Box::new([0, 0])),
        Field::applicationGroupName("app-scope".into()),
    ];
    let fields = vec![
        Field::samplingInterval(1000),
        Field::paddingOctets(Box::new([0, 0, 0, 0])),
        Field::samplingAlgorithm(2),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let results = OptionsDataRecord::normalize_sampling_type(record);

    // Construct expected normalized record
    let expected_scope_fields = vec![
        Field::selectorId(42),
        Field::applicationGroupName("app-scope".into()),
    ];
    let expected_fields = vec![Field::samplingInterval(1000), Field::samplingAlgorithm(2)];
    let expected_record = IndexedDataRecord::new(&expected_scope_fields, &expected_fields);
    let expected_records = vec![expected_record];

    assert_eq!(results, expected_records);
}

#[test]
fn test_is_interface_type_ingress_and_name() {
    let scope_fields = vec![Field::ingressInterface(1)];
    let fields = vec![Field::interfaceName("eth0".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_interface_type(&record));
}

#[test]
fn test_is_interface_type_egress_and_description() {
    let scope_fields = vec![Field::egressInterface(2)];
    let fields = vec![Field::interfaceDescription(
        "Management Interface".to_string().into(),
    )];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_interface_type(&record));
}

#[test]
fn test_is_interface_type_interface_only() {
    let scope_fields = vec![Field::ingressInterface(1)];
    let fields = vec![Field::octetDeltaCount(1000)];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    // Should be false - needs name or description
    assert!(!OptionsDataRecord::is_interface_type(&record));
}

#[test]
fn test_is_interface_type_name_only() {
    let scope_fields = vec![Field::selectorId(1)];
    let fields = vec![Field::interfaceName("eth0".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    // Should be false - needs interface field
    assert!(!OptionsDataRecord::is_interface_type(&record));
}

#[test]
fn test_normalize_interface_type_matching_interfaces() {
    let scope_fields = vec![
        Field::ingressInterface(1),
        Field::egressInterface(1),
        Field::selectorId(42),
    ];
    let fields = vec![
        Field::interfaceName("eth0".to_string().into()),
        Field::interfaceDescription("MGMT Interface".to_string().into()),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_interface_type(record).unwrap();

    // Construct expected records vec
    let mut expected = Vec::new();

    // Expected ingress record
    let expected_ingress_scope = vec![Field::ingressInterface(1), Field::selectorId(42)];
    let expected_ingress_fields = vec![
        Field::NetGauze(netgauze::Field::ingressInterfaceName(
            "eth0".to_string().into(),
        )),
        Field::NetGauze(netgauze::Field::ingressInterfaceDescription(
            "MGMT Interface".to_string().into(),
        )),
    ];
    expected.push(IndexedDataRecord::new(
        &expected_ingress_scope,
        &expected_ingress_fields,
    ));

    // Expected egress record
    let expected_egress_scope = vec![Field::egressInterface(1), Field::selectorId(42)];
    let expected_egress_fields = vec![
        Field::NetGauze(netgauze::Field::egressInterfaceName(
            "eth0".to_string().into(),
        )),
        Field::NetGauze(netgauze::Field::egressInterfaceDescription(
            "MGMT Interface".to_string().into(),
        )),
    ];
    expected.push(IndexedDataRecord::new(
        &expected_egress_scope,
        &expected_egress_fields,
    ));

    // Check if results contain expected records (order might vary)
    assert_eq!(expected, normalized);
}

#[test]
fn test_normalize_interface_type_ingress_only() {
    let scope_fields = vec![
        Field::ingressInterface(1),
        Field::selectorId(42),
        Field::paddingOctets(Box::new([0, 0, 0])),
    ];
    let fields = vec![
        Field::interfaceName("eth1".to_string().into()),
        Field::interfaceDescription("Ingress Interface".to_string().into()),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_interface_type(record).unwrap();

    // Construct expected records vec
    let mut expected = Vec::new();

    let expected_scope = vec![Field::ingressInterface(1), Field::selectorId(42)];
    let expected_fields = vec![
        Field::NetGauze(netgauze::Field::ingressInterfaceName(
            "eth1".to_string().into(),
        )),
        Field::NetGauze(netgauze::Field::ingressInterfaceDescription(
            "Ingress Interface".to_string().into(),
        )),
    ];
    expected.push(IndexedDataRecord::new(&expected_scope, &expected_fields));

    assert_eq!(expected, normalized);
}

#[test]
fn test_normalize_interface_type_egress_only() {
    let scope_fields = vec![Field::egressInterface(2), Field::observationPointId(100)];
    let fields = vec![Field::interfaceName("eth2".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_interface_type(record).unwrap();

    // Construct expected records vec
    let mut expected = Vec::new();

    let expected_scope = vec![Field::egressInterface(2), Field::observationPointId(100)];
    let expected_fields = vec![Field::NetGauze(netgauze::Field::egressInterfaceName(
        "eth2".to_string().into(),
    ))];
    expected.push(IndexedDataRecord::new(&expected_scope, &expected_fields));

    assert_eq!(expected, normalized);
}

#[test]
fn test_normalize_interface_type_different_interfaces() {
    let scope_fields = vec![Field::ingressInterface(1), Field::egressInterface(2)];
    let fields = vec![Field::interfaceName("eth0".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_interface_type(record);

    assert!(matches!(
        normalized,
        Err(OptionsDataRecordError::UnsupportedInterfaceType)
    ));
}

#[test]
fn test_normalize_interface_type_empty_fields() {
    let scope_fields = vec![Field::ingressInterface(1)];
    let fields: Vec<Field> = vec![];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_interface_type(record);

    assert_eq!(
        normalized,
        Err(OptionsDataRecordError::MissingRequiredFields {
            record_type: "interface".to_string(),
        })
    );
}

#[test]
fn test_is_vrf_type_ingress_and_name() {
    let scope_fields = vec![Field::ingressVRFID(100)];
    let fields = vec![Field::VRFname("management".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_vrf_type(&record));
}

#[test]
fn test_is_vrf_type_egress_and_rd() {
    let scope_fields = vec![Field::egressVRFID(200)];
    let fields = vec![Field::mplsVpnRouteDistinguisher(Box::new([
        1, 2, 3, 4, 5, 6, 7, 8,
    ]))];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    assert!(OptionsDataRecord::is_vrf_type(&record));
}

#[test]
fn test_is_vrf_type_vrf_only() {
    let scope_fields = vec![Field::ingressVRFID(100)];
    let fields = vec![Field::octetDeltaCount(1000)];

    let record = IndexedDataRecord::new(&scope_fields, &fields);

    // Should be false - needs name or RD
    assert!(!OptionsDataRecord::is_vrf_type(&record));
}

#[test]
fn test_normalize_vrf_type_matching_vrfs() {
    let scope_fields = vec![
        Field::ingressVRFID(100),
        Field::egressVRFID(100),
        Field::observationPointId(42),
    ];
    let fields = vec![
        Field::VRFname("customer_a".to_string().into()),
        Field::mplsVpnRouteDistinguisher(Box::new([1, 2, 3, 4, 5, 6, 7, 8])),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_vrf_type(record).unwrap();

    // Construct expected records vec
    let mut expected = Vec::new();

    // Expected ingress record
    let expected_ingress_scope = vec![Field::ingressVRFID(100), Field::observationPointId(42)];
    let expected_ingress_fields = vec![
        Field::NetGauze(netgauze::Field::ingressVRFname(
            "customer_a".to_string().into(),
        )),
        Field::NetGauze(netgauze::Field::ingressMplsVpnRouteDistinguisher(Box::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
        ))),
    ];
    expected.push(IndexedDataRecord::new(
        &expected_ingress_scope,
        &expected_ingress_fields,
    ));

    // Expected egress record
    let expected_egress_scope = vec![Field::egressVRFID(100), Field::observationPointId(42)];
    let expected_egress_fields = vec![
        Field::NetGauze(netgauze::Field::egressVRFname(
            "customer_a".to_string().into(),
        )),
        Field::NetGauze(netgauze::Field::egressMplsVpnRouteDistinguisher(Box::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
        ))),
    ];
    expected.push(IndexedDataRecord::new(
        &expected_egress_scope,
        &expected_egress_fields,
    ));

    assert_eq!(normalized, expected);
}

#[test]
fn test_normalize_vrf_type_ingress_only() {
    let scope_fields = vec![Field::ingressVRFID(100), Field::observationPointId(42)];
    let fields = vec![
        Field::VRFname("VRF 100".to_string().into()),
        Field::mplsVpnRouteDistinguisher(Box::new([1, 0, 0, 4, 3, 4, 3, 3])),
    ];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_vrf_type(record).unwrap();

    // Construct expected records vec
    let mut expected = Vec::new();

    let expected_scope = vec![Field::ingressVRFID(100), Field::observationPointId(42)];
    let expected_fields = vec![
        Field::NetGauze(netgauze::Field::ingressVRFname(
            "VRF 100".to_string().into(),
        )),
        Field::NetGauze(netgauze::Field::ingressMplsVpnRouteDistinguisher(Box::new(
            [1, 0, 0, 4, 3, 4, 3, 3],
        ))),
    ];
    expected.push(IndexedDataRecord::new(&expected_scope, &expected_fields));

    assert_eq!(normalized, expected);
}

#[test]
fn test_normalize_vrf_type_egress_only() {
    let scope_fields = vec![Field::egressVRFID(200)];
    let fields = vec![Field::VRFname("VRF 200".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_vrf_type(record).unwrap();

    // Construct expected records vec
    let mut expected = Vec::new();

    let expected_scope = vec![Field::egressVRFID(200)];
    let expected_fields = vec![Field::NetGauze(netgauze::Field::egressVRFname(
        "VRF 200".to_string().into(),
    ))];
    expected.push(IndexedDataRecord::new(&expected_scope, &expected_fields));

    assert_eq!(normalized, expected);
}

#[test]
fn test_normalize_vrf_type_different_vrfs() {
    let scope_fields = vec![Field::ingressVRFID(100), Field::egressVRFID(200)];
    let fields = vec![Field::VRFname("customer_a".to_string().into())];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_vrf_type(record);

    assert!(matches!(
        normalized,
        Err(OptionsDataRecordError::UnsupportedVrfType)
    ));
}

#[test]
fn test_normalize_vrf_type_empty_fields() {
    let scope_fields = vec![Field::ingressVRFID(100)];
    let fields: Vec<Field> = vec![];

    let record = IndexedDataRecord::new(&scope_fields, &fields);
    let normalized = OptionsDataRecord::normalize_vrf_type(record);

    assert_eq!(
        normalized,
        Err(OptionsDataRecordError::MissingRequiredFields {
            record_type: "VRF".to_string(),
        })
    );
}

#[test]
fn test_into_enrichment_operations_sampling() {
    let scope_fields = vec![Field::selectorId(42)];
    let fields = vec![Field::samplingInterval(1000)];

    let indexed_record = IndexedDataRecord::new(&scope_fields, &fields);
    let options_record = OptionsDataRecord::Sampling(indexed_record);

    let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let obs_id = 100;

    let ops = options_record
        .into_enrichment_operations(peer_ip, obs_id)
        .unwrap();

    let expected_ops = vec![EnrichmentOperation::Upsert {
        ip: peer_ip,
        scope: Scope::new(obs_id, Some(scope_fields)),
        weight: 16,
        fields,
    }];

    assert_eq!(ops, expected_ops);
}

#[test]
fn test_into_enrichment_operations_interface_matching_ids() {
    let scope_fields = vec![Field::ingressInterface(1), Field::egressInterface(1)];
    let fields = vec![Field::interfaceName("eth0".to_string().into())];

    let indexed_record = IndexedDataRecord::new(&scope_fields, &fields);
    let options_record = OptionsDataRecord::Interface(indexed_record);

    let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let obs_id = 200;

    let ops = options_record
        .into_enrichment_operations(peer_ip, obs_id)
        .unwrap();

    let expected_ops = vec![
        EnrichmentOperation::Upsert {
            ip: peer_ip,
            scope: Scope::new(obs_id, Some(vec![Field::ingressInterface(1)])),
            weight: 16,
            fields: vec![Field::NetGauze(netgauze::Field::ingressInterfaceName(
                "eth0".to_string().into(),
            ))],
        },
        EnrichmentOperation::Upsert {
            ip: peer_ip,
            scope: Scope::new(obs_id, Some(vec![Field::egressInterface(1)])),
            weight: 16,
            fields: vec![Field::NetGauze(netgauze::Field::egressInterfaceName(
                "eth0".to_string().into(),
            ))],
        },
    ];

    assert_eq!(ops, expected_ops);
}

#[test]
fn test_into_enrichment_operations_unclassified() {
    let scope_fields = vec![Field::selectorId(1)];
    let fields = vec![Field::octetDeltaCount(1000)];

    let indexed_record = IndexedDataRecord::new(&scope_fields, &fields);
    let options_record = OptionsDataRecord::Unclassified(indexed_record);

    let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let obs_id = 300;

    let ops = options_record
        .into_enrichment_operations(peer_ip, obs_id)
        .unwrap();

    let expected_ops = vec![EnrichmentOperation::Upsert {
        ip: peer_ip,
        scope: Scope::new(obs_id, Some(scope_fields)),
        weight: 10,
        fields,
    }];

    assert_eq!(ops, expected_ops);
}
