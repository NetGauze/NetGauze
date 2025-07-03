#[cfg(test)]
mod tests {
    use crate::flow::aggregation::aggregator::*;
    use chrono::DateTime;
    use netgauze_flow_pkt::{
        ie::{Field, *},
        ipfix::Set,
        DataSetId, FlowInfo,
    };
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr},
    };

    #[test]
    fn test_into_flowinfo_with_extra_fields() {
        // Create test data
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let shard_id = 5;
        let sequence_number = 42;
        let export_time = DateTime::parse_from_rfc3339("2025-07-02T10:00:00Z")
            .unwrap()
            .to_utc();
        let collection_time = DateTime::parse_from_rfc3339("2025-07-02T10:00:05Z")
            .unwrap()
            .to_utc();

        // Create key fields
        let key_fields = vec![
            Some(Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1))),
            Some(Field::destinationIPv4Address(Ipv4Addr::new(10, 0, 0, 2))),
        ]
        .into_boxed_slice();

        // Create aggregated fields
        let agg_fields = vec![
            Some(Field::octetDeltaCount(1000)),
            Some(Field::packetDeltaCount(10)),
        ]
        .into_boxed_slice();

        // Create AggFlowInfo instance
        let agg_flow_info = AggFlowInfo::from((
            FlowCacheKey::new(peer_ip, key_fields.clone()),
            FlowCacheRecord::new(
                HashSet::from([9995, 9996]),
                HashSet::from([1, 2]),
                HashSet::from([DataSetId::new(256).unwrap(), DataSetId::new(257).unwrap()]),
                export_time,
                export_time,
                collection_time,
                collection_time,
                agg_fields.clone(),
                3,
            ),
        ));

        // Extra fields to add
        let extra_fields = vec![
            Field::NetGauze(netgauze::Field::windowStart(
                DateTime::parse_from_rfc3339("2025-07-02T10:00:00Z")
                    .unwrap()
                    .to_utc(),
            )),
            Field::NetGauze(netgauze::Field::windowEnd(
                DateTime::parse_from_rfc3339("2025-07-02T10:01:00Z")
                    .unwrap()
                    .to_utc(),
            )),
        ];

        // Call into_flowinfo
        let result = agg_flow_info.into_flowinfo_with_extra_fields(
            shard_id,
            sequence_number,
            extra_fields.clone(),
        );

        // Create expected record
        let mut expected_fields = Vec::new();
        expected_fields.extend(key_fields.iter().flatten().cloned());
        expected_fields.extend(agg_fields.iter().flatten().cloned());
        expected_fields.extend([
            Field::originalFlowsPresent(3),
            Field::minExportSeconds(export_time),
            Field::maxExportSeconds(export_time),
            Field::collectionTimeMilliseconds(collection_time),
        ]);
        expected_fields.extend(extra_fields);
        expected_fields.extend([
            Field::NetGauze(netgauze::Field::originalExporterTransportPort(9995)),
            Field::NetGauze(netgauze::Field::originalExporterTransportPort(9996)),
        ]);
        expected_fields.extend([
            Field::originalObservationDomainId(1),
            Field::originalObservationDomainId(2),
        ]);
        expected_fields.extend([
            Field::NetGauze(netgauze::Field::originalTemplateId(256)),
            Field::NetGauze(netgauze::Field::originalTemplateId(257)),
        ]);

        // Compare expected with result
        assert_eq!(result.sequence_number(), sequence_number);
        assert_eq!(result.observation_domain_id(), shard_id as u32);

        if let FlowInfo::IPFIX(pkt) = result {
            let sets = pkt.sets();
            assert_eq!(sets.len(), 1);

            if let Set::Data { records, .. } = &sets[0] {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].scope_fields().len(), 0);

                let mut resulting_fields = records[0].fields().to_vec();

                // Necessary sorting since HashSet does not guarantee ordering
                resulting_fields.sort();
                expected_fields.sort();

                assert_eq!(resulting_fields, expected_fields)
            } else {
                panic!("Expected an IPFIX Data Set")
            }
        } else {
            panic!("Expected FlowInfo::IPFIX")
        }
    }
}
