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

use super::{decode_buffer, serialize_error, serialize_success};
use crate::protocol_handler::{DecodeOutcome, ProtocolHandler};
use bytes::BytesMut;
use netgauze_flow_pkt::{
    FlowInfo,
    codec::{FlowInfoCodec, FlowInfoCodecDecoderError},
};
use netgauze_pcap_reader::TransportProtocol;
use std::{collections::HashMap, io, net::IpAddr};

pub struct FlowProtocolHandler {
    ports: Vec<u16>,
}

impl FlowProtocolHandler {
    pub fn new(ports: Vec<u16>) -> Self {
        FlowProtocolHandler { ports }
    }
}

impl ProtocolHandler<FlowInfo, FlowInfoCodec, FlowInfoCodecDecoderError> for FlowProtocolHandler {
    fn decode(
        &self,
        flow_key: (IpAddr, u16, IpAddr, u16),
        protocol: TransportProtocol,
        packet_data: &[u8],
        exporter_peers: &mut HashMap<(IpAddr, u16, IpAddr, u16), (FlowInfoCodec, BytesMut)>,
    ) -> Option<Vec<DecodeOutcome<FlowInfo, FlowInfoCodecDecoderError>>> {
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::UDP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers
                .entry(flow_key)
                .or_insert((FlowInfoCodec::default(), BytesMut::new()));
            buffer.extend_from_slice(packet_data);

            let mut results = Vec::new();
            decode_buffer(buffer, codec, flow_key, &mut results);
            if !results.is_empty() {
                return Some(results);
            }
        }
        None
    }

    fn serialize(
        &self,
        decode_outcome: DecodeOutcome<FlowInfo, FlowInfoCodecDecoderError>,
    ) -> io::Result<serde_json::Value> {
        match decode_outcome {
            DecodeOutcome::Success(m) => {
                let (flow_key, flow_info) = m;
                serialize_success(flow_key, flow_info)
            }
            DecodeOutcome::Error(m) => serialize_error(m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ipfix::IpfixPacket;
    use netgauze_flow_pkt::{
        DataSetId, FlowInfo,
        ie::{Field, IE},
        ipfix,
        ipfix::{DataRecord, OptionsTemplateRecord, Set},
        wire::deserializer::ipfix::IpfixPacketParsingError,
    };
    use serde_json::json;
    use std::net::Ipv4Addr;

    #[test]
    fn test_flow_handler_decode_success() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            9991,
        );
        // A simple IPFIX options template
        let packet_data = [
            0x00, 0x0a, 0x00, 0x24, 0x65, 0xa1, 0x4f, 0x56, 0x00, 0x26, 0x10, 0xa0, 0x00, 0x00,
            0x82, 0x20, 0x00, 0x03, 0x00, 0x14, 0x01, 0x52, 0x00, 0x02, 0x00, 0x01, 0x00, 0x95,
            0x00, 0x04, 0x00, 0xa0, 0x00, 0x08, 0x00, 0x00,
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data,
            &mut exporter_peers,
        );

        assert_eq!(
            result,
            Some(vec![DecodeOutcome::Success((
                flow_key,
                FlowInfo::IPFIX(IpfixPacket::new(
                    Utc.with_ymd_and_hms(2024, 1, 12, 14, 40, 22).unwrap(),
                    2494624,
                    33312,
                    Box::new([Set::OptionsTemplate(Box::new([
                        OptionsTemplateRecord::new(
                            338,
                            Box::new([netgauze_flow_pkt::FieldSpecifier::new(
                                IE::observationDomainId,
                                4
                            )
                            .unwrap()]),
                            Box::new([netgauze_flow_pkt::FieldSpecifier::new(
                                IE::systemInitTimeMilliseconds,
                                8
                            )
                            .unwrap()]),
                        ),
                    ]))]),
                ))
            ))]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_flow_handler_decode_fragmented_success() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            9991,
        );
        let packet_data1 = &[0x00, 0x0a, 0x00, 0x24];
        let packet_data2 = &[
            0x65, 0xa1, 0x4f, 0x56, 0x00, 0x26, 0x10, 0xa0, 0x00, 0x00, 0x82, 0x20, 0x00, 0x03,
            0x00, 0x14, 0x01, 0x52, 0x00, 0x02, 0x00, 0x01, 0x00, 0x95, 0x00, 0x04, 0x00, 0xa0,
            0x00, 0x08, 0x00, 0x00,
        ];
        let mut exporter_peers = HashMap::new();

        let result1 = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            packet_data1,
            &mut exporter_peers,
        );
        assert!(result1.is_none());
        // The buffer for this flow key should now contain the first part, so not empty
        assert!(!exporter_peers.get(&flow_key).unwrap().1.is_empty());

        // Second packet completes it
        let result2 = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            packet_data2,
            &mut exporter_peers,
        );

        assert_eq!(
            result2,
            Some(vec![DecodeOutcome::Success((
                flow_key,
                FlowInfo::IPFIX(IpfixPacket::new(
                    Utc.with_ymd_and_hms(2024, 1, 12, 14, 40, 22).unwrap(),
                    2494624,
                    33312,
                    Box::new([Set::OptionsTemplate(Box::new([
                        OptionsTemplateRecord::new(
                            338,
                            Box::new([netgauze_flow_pkt::FieldSpecifier::new(
                                IE::observationDomainId,
                                4
                            )
                            .unwrap()]),
                            Box::new([netgauze_flow_pkt::FieldSpecifier::new(
                                IE::systemInitTimeMilliseconds,
                                8
                            )
                            .unwrap()]),
                        ),
                    ]))]),
                ))
            ))]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_flow_handler_decode_multiple_messages_success() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            9991,
        );
        // Two simple IPFIX options template
        let packet_data = [
            0x00, 0x0a, 0x00, 0x24, 0x65, 0xa1, 0x4f, 0x56, 0x00, 0x26, 0x10, 0xa0, 0x00, 0x00,
            0x82, 0x20, 0x00, 0x03, 0x00, 0x14, 0x01, 0x52, 0x00, 0x02, 0x00, 0x01, 0x00, 0x95,
            0x00, 0x04, 0x00, 0xa0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x24, 0x65, 0xa1,
            0x4f, 0x56, 0x00, 0x26, 0x10, 0xa0, 0x00, 0x00, 0x82, 0x20, 0x00, 0x03, 0x00, 0x14,
            0x01, 0x52, 0x00, 0x02, 0x00, 0x01, 0x00, 0x95, 0x00, 0x04, 0x00, 0xa0, 0x00, 0x08,
            0x00, 0x00,
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data,
            &mut exporter_peers,
        );

        let expected_flow = FlowInfo::IPFIX(IpfixPacket::new(
            Utc.with_ymd_and_hms(2024, 1, 12, 14, 40, 22).unwrap(),
            2494624,
            33312,
            Box::new([Set::OptionsTemplate(Box::new([
                OptionsTemplateRecord::new(
                    338,
                    Box::new([
                        netgauze_flow_pkt::FieldSpecifier::new(IE::observationDomainId, 4).unwrap(),
                    ]),
                    Box::new([netgauze_flow_pkt::FieldSpecifier::new(
                        IE::systemInitTimeMilliseconds,
                        8,
                    )
                    .unwrap()]),
                ),
            ]))]),
        ));
        assert_eq!(
            result,
            Some(vec![
                DecodeOutcome::Success((flow_key, expected_flow.clone())),
                DecodeOutcome::Success((flow_key, expected_flow))
            ]),
        );

        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_flow_handler_decode_failure() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            9991,
        );
        // Invalid flow packet, version not supported (0x03)
        let packet_data = [
            0x00, 0x03, 0x00, 0x24, 0x65, 0xa1, 0x4f, 0x56, 0x00, 0x26, 0x10, 0xa0, 0x00, 0x00,
            0x82, 0x20, 0x00, 0x03, 0x00, 0x14, 0x01, 0x52, 0x00, 0x02, 0x00, 0x01, 0x00, 0x95,
            0x00, 0x04, 0x00, 0xa0, 0x00, 0x08, 0x00, 0x00,
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data,
            &mut exporter_peers,
        );

        assert_eq!(
            result,
            Some(vec![DecodeOutcome::Error(
                FlowInfoCodecDecoderError::UnsupportedVersion(3)
            )]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_flow_handler_decode_ignore_wrong_port() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            123, // Wrong port
        );
        let packet_data = [0xff; 20];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data,
            &mut exporter_peers,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_bgp_handler_decode_ignore_wrong_protocol() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            9991,
        );
        let packet_data = [0xff; 20];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::TCP, // Wrong protocol
            &packet_data,
            &mut exporter_peers,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_flow_handler_serialize_success() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            9991,
        );
        let fields = vec![
            Field::sourceIPv4Address(Ipv4Addr::new(10, 0, 0, 1)),
            Field::octetDeltaCount(300),
        ];
        let record = DataRecord::new(Box::new([]), fields.into_boxed_slice());
        let set = Set::Data {
            id: DataSetId::new(600).unwrap(),
            records: Box::new([record]),
        };
        let export_time = Utc.with_ymd_and_hms(2025, 1, 1, 18, 0, 0).unwrap();
        let ipfix_pkt = IpfixPacket::new(export_time, 15, 400, Box::new([set]));
        let ipfix_message = FlowInfo::IPFIX(ipfix_pkt);
        let outcome = DecodeOutcome::Success((flow_key, ipfix_message));

        let result = handler.serialize(outcome);

        assert!(result.is_ok());
        let json = result.unwrap();
        let expected = json!({
          "source_address": "10.0.0.1:12345",
          "destination_address": "10.0.0.2:9991",
          "info": {
            "IPFIX": {
              "version": 10,
              "export_time": "2025-01-01T18:00:00Z",
              "sequence_number": 15,
              "observation_domain_id": 400,
              "sets": [
                {
                  "Data": {
                    "id": 600,
                    "records": [
                      {
                        "scope_fields": [],
                        "fields": [
                          {
                            "sourceIPv4Address": "10.0.0.1"
                          },
                          {
                            "octetDeltaCount": 300
                          }
                        ]
                      }
                    ]
                  }
                }
              ]
            }
          }
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn test_flow_handler_serialize_error() {
        let handler = FlowProtocolHandler::new(vec![9991]);
        let error = FlowInfoCodecDecoderError::IpfixParsingError(
            IpfixPacketParsingError::InvalidLength(10),
        );
        let outcome = DecodeOutcome::Error(error);

        let result = handler.serialize(outcome);

        assert!(result.is_ok());
        let json = result.unwrap();
        let expected = json!({
            "IpfixParsingError": {
                "InvalidLength": 10
            }
        });
        assert_eq!(json, expected);
    }
}
