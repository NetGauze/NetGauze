// Copyright (C) 2026-present The NetGauze Authors.
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
    use crate::bmp::pmacct_schema::*;
    use apache_avro::{Reader, Writer};

    use netgauze_bmp_pkt::BmpMessage;
    use netgauze_bmp_service::{AddrInfo, BmpRequest};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    #[test]
    fn test_pmacct_route_monitoring_serialization() {
        // Create a route monitoring message
        let msg = PmacctBmpMessage::RouteMonitoring(PmacctRouteMonitoringMessage {
            log_type: LogType::Update,
            seq: 8165641,
            timestamp: "1771423519.973399".to_string(),
            event_type: EventType::Log,
            writer_id: "devcolleft02nfacctdbmpleft06c 20251010.1.b58aa7d-1.el8".to_string(),
            tag: None,
            label: Some(HashMap::from([(
                "nkey".to_string(),
                "daisy-43".to_string(),
            )])),
            afi: 1,
            safi: 128,
            ip_prefix: Some("10.0.5.64/28".to_string()),
            rd: Some("2:4200137734:1003".to_string()),
            rd_origin: Some(RdOrigin::Bgp),
            bgp_nexthop: Some("10.3.72.2".to_string()),
            as_path: Some("4200136804 4200137732 4200073286 4200073286".to_string()),
            as_path_id: None,
            comms: Some("60633:204 60633:208 60633:1009 60633:1033".to_string()),
            ecomms: Some("RT:60663:60153 RT:60663:60154".to_string()),
            lcomms: Some("65002:0:998".to_string()),
            origin: Some(BgpOrigin::IGP),
            local_pref: None,
            med: None,
            aigp: None,
            psid_li: None,
            otc: None,
            mpls_label: Some("85147".to_string()),
            peer_ip: "0.0.0.0".to_string(),
            peer_asn: 4200137732,
            peer_type: 3,
            peer_type_str: Some("Loc-RIB Instance Peer".to_string()),
            peer_tcp_port: Some(0),
            timestamp_arrival: Some("1771423520.065485".to_string()),
            bmp_router: "100.71.14.43".to_string(),
            bmp_router_port: Some(40205),
            bmp_msg_type: BmpMsgType::RouteMonitor,
            bmp_rib_type: BmpRibType::LocRib,
            bgp_id: "10.71.14.43".to_string(),
            is_filtered: 0,
            is_in: None,
            is_loc: Some(1),
            is_post: None,
            is_out: None,
        });

        let expected_json = r#"{"log_type":"update","seq":8165641,"timestamp":"1771423519.973399","event_type":"log","writer_id":"devcolleft02nfacctdbmpleft06c 20251010.1.b58aa7d-1.el8","tag":null,"label":{"nkey":"daisy-43"},"afi":1,"safi":128,"ip_prefix":"10.0.5.64/28","rd":"2:4200137734:1003","rd_origin":"bgp","bgp_nexthop":"10.3.72.2","as_path":"4200136804 4200137732 4200073286 4200073286","as_path_id":null,"comms":"60633:204 60633:208 60633:1009 60633:1033","ecomms":"RT:60663:60153 RT:60663:60154","lcomms":"65002:0:998","origin":"i","local_pref":null,"med":null,"aigp":null,"psid_li":null,"otc":null,"mpls_label":"85147","peer_ip":"0.0.0.0","peer_asn":4200137732,"peer_type":3,"peer_type_str":"Loc-RIB Instance Peer","peer_tcp_port":0,"timestamp_arrival":"1771423520.065485","bmp_router":"100.71.14.43","bmp_router_port":40205,"bmp_msg_type":"route_monitor","bmp_rib_type":"Loc-Rib","bgp_id":"10.71.14.43","is_filtered":0,"is_in":null,"is_loc":1,"is_post":null,"is_out":null}"#;

        // JSON serialization
        let serialized_json = serde_json::to_string(&msg).expect("Failed to serialize msg");
        assert_eq!(serialized_json, expected_json);

        // JSON deserialization
        let deserialized_msg: PmacctBmpMessage =
            serde_json::from_str(&serialized_json).expect("Failed to deserialize msg");
        assert_eq!(deserialized_msg, msg);

        // Avro encode
        let schema = msg.get_avro_schema();
        let mut writer = Writer::new(&schema, Vec::new());

        let avro_val = msg
            .clone()
            .get_avro_value()
            .expect("Failed to convert to avro value");
        writer.append(avro_val).expect("Failed to append to writer");

        let encoded = writer.into_inner().expect("Failed to get inner buffer");

        // Avro decode
        let reader = Reader::new(&encoded[..]).expect("Failed to create reader");
        let mut decoded_msgs: Vec<PmacctBmpMessage> = Vec::new();
        for value in reader {
            let value = value.expect("Failed to read value");
            let decoded =
                PmacctBmpMessage::from_avro_value(&value).expect("Failed to resolve message");
            decoded_msgs.push(decoded);
        }

        assert_eq!(decoded_msgs.len(), 1);
        assert_eq!(decoded_msgs[0], msg);
    }

    #[test]
    fn test_pmacct_peer_up_avro_union_encode_decode() {
        let msg = PmacctBmpMessage::PeerUpNotification(PmacctPeerUpNotificationMessage {
            seq: 42,
            timestamp: "1771584618.100129".to_string(),
            timestamp_event: Some("1771584618.100129".to_string()),
            timestamp_arrival: Some("1771584618.200000".to_string()),
            event_type: EventType::Log,
            bmp_router: "2001:db8:90::1".to_string(),
            bmp_router_port: Some(33725),
            bmp_msg_type: BmpMsgType::PeerUp,
            writer_id: "test-writer 1.0".to_string(),
            tag: None,
            label: None,
            peer_ip: "203.0.113.44".to_string(),
            peer_asn: 64496,
            peer_type: 0,
            peer_type_str: Some("Global Instance Peer".to_string()),
            bmp_rib_type: BmpRibType::AdjRibInPre,
            is_filtered: 0,
            is_in: Some(1),
            is_loc: None,
            is_post: None,
            is_out: None,
            rd: None,
            rd_origin: None,
            bgp_id: "203.0.113.44".to_string(),
            local_port: 179,
            remote_port: 54321,
            local_ip: "10.0.0.1".to_string(),
            bmp_peer_up_info_string: Some("peer-up-info".to_string()),
            bmp_peer_up_info_vrf_table_name: Some("vrf-red".to_string()),
            bmp_peer_up_info_admin_label: None,
            bmp_peer_up_info_reserved: None,
        });

        // --- JSON round-trip ---
        let json = serde_json::to_string(&msg).expect("JSON serialization failed");
        let from_json: PmacctBmpMessage =
            serde_json::from_str(&json).expect("JSON deserialization failed");
        assert_eq!(from_json, msg);

        // --- Avro round-trip using the Union schema ---
        let schema = msg.get_avro_schema();

        let avro_val = msg
            .clone()
            .get_avro_value()
            .expect("Fail to convert to avro value");

        // Validate that PeerUpNotification is variant index 3 in the union.
        match &avro_val {
            apache_avro::types::Value::Union(idx, _) => assert_eq!(*idx, 3),
            other => panic!("expected Value::Union, got {other:?}"),
        }

        // Avro encode
        let mut writer = Writer::new(&schema, Vec::new());
        writer.append(avro_val).expect("Failed to append to writer");
        let encoded = writer.into_inner().expect("Failed to get inner buffer");

        // Avro decode
        let reader = Reader::new(&encoded[..]).expect("Failed to create reader");
        let mut decoded_msgs: Vec<PmacctBmpMessage> = Vec::new();
        for value in reader {
            let value = value.expect("Failed to read value");
            let decoded =
                PmacctBmpMessage::from_avro_value(&value).expect("Failed to decode value");
            decoded_msgs.push(decoded);
        }

        assert_eq!(decoded_msgs.len(), 1);
        assert_eq!(decoded_msgs[0], msg);
    }

    #[test]
    fn test_convert_route_monitoring_loc_rib_ipv6_mpls_vpn() {
        let bmp_json = r#"{"V3":{"RouteMonitoring":{"peer_header":{"peer_type":{"LocRibInstancePeer":{"filtered":false}},"rd":null,"address":null,"peer_as":4226809946,"bgp_id":"203.0.113.90","timestamp":"2026-02-20T10:50:18.100129Z"},"update_message":{"Update":{"withdrawn_routes":[],"path_attributes":[{"optional":true,"transitive":false,"partial":false,"extended_length":true,"value":{"MpReach":{"Ipv6MplsVpnUnicast":{"next_hop":{"Ipv6":{"rd":{"As2Administrator":{"asn2":0,"number":0}},"next_hop":"::ffff:203.0.113.24","next_hop_local":null}},"nlri":[{"path_id":null,"rd":{"As4Administrator":{"asn4":4226809946,"number":9010}},"label_stack":[[16,3,193]],"network":"2001:db8::24/128"}]}}}},{"optional":false,"transitive":true,"partial":false,"extended_length":false,"value":{"Origin":"IGP"}},{"optional":false,"transitive":true,"partial":false,"extended_length":false,"value":{"AsPath":{"As4PathSegments":[{"segment_type":"AsSequence","as_numbers":[64496,4226809880]}]}}},{"optional":false,"transitive":true,"partial":false,"extended_length":false,"value":{"LocalPreference":{"metric":100}}},{"optional":true,"transitive":true,"partial":false,"extended_length":false,"value":{"Communities":{"communities":[4226810155,4226810857,4226875393,4227006488]}}},{"optional":true,"transitive":true,"partial":false,"extended_length":false,"value":{"ExtendedCommunities":{"communities":[{"TransitiveTwoOctet":{"RouteTarget":{"global_admin":64497,"local_admin":1}}}]}}}],"nlri":[]}}}}}"#;

        let bmp_msg: BmpMessage =
            serde_json::from_str(bmp_json).expect("Failed to deserialize BmpMessage from JSON");

        let local_addr: SocketAddr = "[::]:1792".parse().unwrap();
        let peer_addr: SocketAddr = "[2001:db8:90::1]:33725".parse().unwrap();
        let addr_info = AddrInfo::new(local_addr, peer_addr);

        let request: BmpRequest = (addr_info, bmp_msg);

        let ctx = PmacctConversionContext {
            seq: 1,
            writer_id: "test-writer 1.0".to_string(),
            event_type: EventType::Log,
            timestamp_arrival: "1771584618.200000".to_string(),
            label: None,
            tag: Some(100),
        };

        let msgs = PmacctBmpMessage::try_from_bmp_request(&request, &ctx)
            .expect("conversion must succeed");

        let expected_msg = PmacctBmpMessage::RouteMonitoring(PmacctRouteMonitoringMessage {
            log_type: LogType::Update,
            seq: 1,
            timestamp: "1771584618.100129".to_string(),
            event_type: EventType::Log,
            writer_id: "test-writer 1.0".to_string(),
            tag: Some(100),
            label: None,
            afi: 2,
            safi: 128,
            ip_prefix: Some("2001:db8::24/128".to_string()),
            rd: Some("2:4226809946:9010".to_string()),
            rd_origin: Some(RdOrigin::Bgp),
            bgp_nexthop: Some("::ffff:203.0.113.24".to_string()),
            as_path: Some("64496 4226809880".to_string()),
            as_path_id: None,
            comms: Some("64496:299 64496:1001 64497:1 64499:24".to_string()),
            ecomms: Some("RT:64497:1".to_string()),
            lcomms: None,
            origin: Some(BgpOrigin::IGP),
            local_pref: Some(100),
            med: None,
            aigp: None,
            psid_li: None,
            otc: None,
            mpls_label: Some("65596".to_string()),
            peer_ip: "0.0.0.0".to_string(),
            peer_asn: 4226809946,
            peer_type: 3,
            peer_type_str: Some("Loc-RIB Instance Peer".to_string()),
            peer_tcp_port: None,
            timestamp_arrival: Some("1771584618.200000".to_string()),
            bmp_router: "2001:db8:90::1".to_string(),
            bmp_router_port: Some(33725),
            bmp_msg_type: BmpMsgType::RouteMonitor,
            bmp_rib_type: BmpRibType::LocRib,
            bgp_id: "203.0.113.90".to_string(),
            is_filtered: 0,
            is_in: None,
            is_loc: Some(1),
            is_post: None,
            is_out: None,
        });

        assert_eq!(msgs, vec![expected_msg]);

        // Avro encode
        let schema = PmacctBmpMessage::get_schema();
        let mut writer = Writer::new(&schema, Vec::new());

        for msg in &msgs {
            let avro_val = msg
                .clone()
                .get_avro_value()
                .expect("Failed to convert to avro value");
            writer.append(avro_val).expect("Failed to append to writer");
        }

        let encoded = writer.into_inner().expect("Failed to get inner buffer");

        // Avro decode
        let reader = Reader::new(&encoded[..]).expect("Failed to create reader");
        let mut decoded_msgs: Vec<PmacctBmpMessage> = Vec::new();
        for value in reader {
            let value = value.expect("Failed to read value");
            let decoded =
                PmacctBmpMessage::from_avro_value(&value).expect("Failed to resolve message");
            decoded_msgs.push(decoded);
        }

        assert_eq!(decoded_msgs, msgs);
    }

    #[test]
    fn test_convert_statistics_report_global_instance_peer() {
        let bmp_json = r#"{"V3":{"StatisticsReport":{"peer_header":{"peer_type":{"GlobalInstancePeer":{"ipv6":false,"post_policy":false,"asn2":false,"adj_rib_out":false}},"rd":null,"address":"203.0.113.44","peer_as":64496,"bgp_id":"203.0.113.44","timestamp":"2026-02-20T10:50:19.346838Z"},"counters":[{"NumberOfDuplicateWithdraws":51},{"NumberOfUpdatesInvalidatedDueToAsPathLoop":22},{"NumberOfRoutesInAdjRibIn":39},{"NumberOfRoutesInPerAfiSafiAdjRibIn":["Ipv4MplsLabeledVpn",30]},{"NumberOfRoutesInPerAfiSafiAdjRibIn":["Ipv6MplsLabeledVpn",9]},{"NumberOfRoutesInLocRib":34},{"NumberOfRoutesInPerAfiSafiLocRib":["Ipv4MplsLabeledVpn",25]},{"NumberOfRoutesInPerAfiSafiLocRib":["Ipv6MplsLabeledVpn",9]}]}}}"#;

        let bmp_msg: BmpMessage =
            serde_json::from_str(bmp_json).expect("Failed to deserialize BmpMessage from JSON");

        let local_addr: SocketAddr = "[::]:1792".parse().unwrap();
        let peer_addr: SocketAddr = "[2001:db8:90::1]:33725".parse().unwrap();
        let addr_info = AddrInfo::new(local_addr, peer_addr);

        let request: BmpRequest = (addr_info, bmp_msg);

        let ctx = PmacctConversionContext {
            seq: 2,
            writer_id: "test-writer 1.0".to_string(),
            event_type: EventType::Log,
            timestamp_arrival: "1771584619.400000".to_string(),
            label: None,
            tag: None,
        };

        let msgs = PmacctBmpMessage::try_from_bmp_request(&request, &ctx)
            .expect("conversion must succeed");

        // 8 counters → 8 messages
        assert_eq!(msgs.len(), 8);

        // Common fields shared by all 8 messages — build a helper closure to
        // avoid repeating every field 8 times.
        let base = |counter_type: u16,
                    counter_type_str: &str,
                    counter_value: i64,
                    afi: Option<u16>,
                    safi: Option<u8>| {
            PmacctBmpMessage::StatisticsReport(PmacctStatisticsReportMessage {
                seq: 2,
                timestamp: "1771584619.346838".to_string(),
                timestamp_event: Some("1771584619.346838".to_string()),
                timestamp_arrival: Some("1771584619.400000".to_string()),
                event_type: EventType::Log,
                bmp_router: "2001:db8:90::1".to_string(),
                bmp_router_port: Some(33725),
                bmp_msg_type: BmpMsgType::Stats,
                writer_id: "test-writer 1.0".to_string(),
                tag: None,
                label: None,
                peer_ip: "203.0.113.44".to_string(),
                peer_asn: 64496,
                peer_type: 0,
                peer_type_str: "Global Instance Peer".to_string(),
                bmp_rib_type: BmpRibType::AdjRibInPre,
                is_filtered: 0,
                is_in: Some(1),
                is_loc: None,
                is_post: None,
                is_out: None,
                rd: None,
                rd_origin: None,
                bgp_id: "203.0.113.44".to_string(),
                counter_type,
                counter_type_str: counter_type_str.to_string(),
                counter_value,
                afi,
                safi,
            })
        };

        let expected = vec![
            base(2, "Number of (known) duplicate withdraws", 51, None, None),
            base(
                4,
                "Number of updates invalidated due to AS_PATH loop",
                22,
                None,
                None,
            ),
            base(7, "Number of routes in Adj-RIBs-In", 39, None, None),
            base(
                9,
                "Number of routes in per-AFI/SAFI Adj-RIB-In",
                30,
                Some(1),
                Some(128),
            ),
            base(
                9,
                "Number of routes in per-AFI/SAFI Adj-RIB-In",
                9,
                Some(2),
                Some(128),
            ),
            base(8, "Number of routes in Loc-RIB", 34, None, None),
            base(
                10,
                "Number of routes in per-AFI/SAFI Loc-RIB",
                25,
                Some(1),
                Some(128),
            ),
            base(
                10,
                "Number of routes in per-AFI/SAFI Loc-RIB",
                9,
                Some(2),
                Some(128),
            ),
        ];

        assert_eq!(msgs, expected);

        // Avro encode/decode test for all statistics report messages
        let schema = PmacctBmpMessage::get_schema();
        let mut writer = Writer::new(&schema, Vec::new());

        for msg in &msgs {
            let avro_val = msg
                .clone()
                .get_avro_value()
                .expect("Failed to convert to avro value");
            writer.append(avro_val).expect("Failed to append to writer");
        }

        let encoded = writer.into_inner().expect("Failed to get inner buffer");

        // Avro decode
        let reader = Reader::new(&encoded[..]).expect("Failed to create reader");
        let mut decoded_msgs: Vec<PmacctBmpMessage> = Vec::new();
        for value in reader {
            let value = value.expect("Failed to read value");
            let decoded =
                PmacctBmpMessage::from_avro_value(&value).expect("Failed to resolve message");
            decoded_msgs.push(decoded);
        }

        assert_eq!(decoded_msgs, msgs);
    }
}
