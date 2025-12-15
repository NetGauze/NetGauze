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
use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmp_pkt::codec::{BmpCodec, BmpCodecDecoderError};
use netgauze_pcap_reader::TransportProtocol;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

pub struct BmpProtocolHandler {
    ports: Vec<u16>,
}

impl BmpProtocolHandler {
    pub fn new(ports: Vec<u16>) -> Self {
        BmpProtocolHandler { ports }
    }
}

impl ProtocolHandler<BmpMessage, BmpCodec, BmpCodecDecoderError> for BmpProtocolHandler {
    fn decode(
        &self,
        flow_key: (IpAddr, u16, IpAddr, u16),
        protocol: TransportProtocol,
        packet_data: &[u8],
        exporter_peers: &mut HashMap<(IpAddr, u16, IpAddr, u16), (BmpCodec, BytesMut)>,
    ) -> Option<Vec<DecodeOutcome<BmpMessage, BmpCodecDecoderError>>> {
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::TCP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers
                .entry(flow_key)
                .or_insert((BmpCodec::default(), BytesMut::new()));
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
        decode_outcome: DecodeOutcome<BmpMessage, BmpCodecDecoderError>,
    ) -> io::Result<serde_json::Value> {
        match decode_outcome {
            DecodeOutcome::Success(m) => {
                let (flow_key, bmp_message) = m;
                serialize_success(flow_key, bmp_message)
            }
            DecodeOutcome::Error(m) => serialize_error(m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_bmp_pkt::v3::{BmpMessageValue, InitiationInformation, InitiationMessage};
    use netgauze_bmp_pkt::wire::deserializer::BmpMessageParsingError;
    use serde_json::json;
    use std::net::Ipv4Addr;

    #[test]
    fn test_bmp_handler_decode_success() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1790,
        );
        // A simple BMP Initiation message
        let packet_data = [
            0x03, 0x00, 0x00, 0x00, 0x6c, 0x04, 0x00, 0x01, 0x00, 0x5b, 0x43, 0x69, 0x73, 0x63,
            0x6f, 0x20, 0x49, 0x4f, 0x53, 0x20, 0x58, 0x52, 0x20, 0x53, 0x6f, 0x66, 0x74, 0x77,
            0x61, 0x72, 0x65, 0x2c, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x35,
            0x2e, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61, 0x75,
            0x6c, 0x74, 0x5d, 0x0a, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20,
            0x28, 0x63, 0x29, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69,
            0x73, 0x63, 0x6f, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49,
            0x6e, 0x63, 0x2e, 0x00, 0x02, 0x00, 0x03, 0x78, 0x72, 0x33,
        ];

        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data,
            &mut exporter_peers,
        );

        assert_eq!(
            result,
            Some(vec![DecodeOutcome::Success((
                flow_key,
                BmpMessage::V3(BmpMessageValue::Initiation(InitiationMessage::new(vec![
                    InitiationInformation::SystemDescription(
                        "Cisco IOS XR Software, Version 5.2.2.21I[Default]\nCopyright (c) 2014 by Cisco Systems, Inc.".to_string()
                    ),
                    InitiationInformation::SystemName("xr3".to_string())
                ])))
            ))]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bmp_handler_decode_fragmented_success() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1790,
        );
        let packet_data1 = [
            0x03, 0x00, 0x00, 0x00, 0x6c, 0x04, 0x00, 0x01, 0x00, 0x5b, 0x43, 0x69, 0x73, 0x63,
            0x6f, 0x20,
        ];
        let packet_data2 = [
            0x49, 0x4f, 0x53, 0x20, 0x58, 0x52, 0x20, 0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72,
            0x65, 0x2c, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x35, 0x2e, 0x32,
            0x2e, 0x32, 0x2e, 0x32, 0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
            0x5d, 0x0a, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63,
            0x29, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69, 0x73, 0x63,
            0x6f, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63,
            0x2e, 0x00, 0x02, 0x00, 0x03, 0x78, 0x72, 0x33,
        ];
        let mut exporter_peers = HashMap::new();

        let result1 = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data1,
            &mut exporter_peers,
        );
        assert!(result1.is_none());
        // The buffer for this flow key should now contain the first part, so not empty
        assert!(!exporter_peers.get(&flow_key).unwrap().1.is_empty());

        let result2 = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data2,
            &mut exporter_peers,
        );

        assert_eq!(
            result2,
            Some(vec![DecodeOutcome::Success((
                flow_key,
                BmpMessage::V3(BmpMessageValue::Initiation(InitiationMessage::new(vec![
                    InitiationInformation::SystemDescription(
                        "Cisco IOS XR Software, Version 5.2.2.21I[Default]\nCopyright (c) 2014 by Cisco Systems, Inc.".to_string()
                    ),
                    InitiationInformation::SystemName("xr3".to_string())
                ])))
            ))]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bmp_decode_multiple_messages_success() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1790,
        );
        // Two simple BMP Initiation message
        let packet_data = [
            0x03, 0x00, 0x00, 0x00, 0x6c, 0x04, 0x00, 0x01, 0x00, 0x5b, 0x43, 0x69, 0x73, 0x63,
            0x6f, 0x20, 0x49, 0x4f, 0x53, 0x20, 0x58, 0x52, 0x20, 0x53, 0x6f, 0x66, 0x74, 0x77,
            0x61, 0x72, 0x65, 0x2c, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x35,
            0x2e, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61, 0x75,
            0x6c, 0x74, 0x5d, 0x0a, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20,
            0x28, 0x63, 0x29, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69,
            0x73, 0x63, 0x6f, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49,
            0x6e, 0x63, 0x2e, 0x00, 0x02, 0x00, 0x03, 0x78, 0x72, 0x33, 0x03, 0x00, 0x00, 0x00,
            0x6c, 0x04, 0x00, 0x01, 0x00, 0x5b, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20, 0x49, 0x4f,
            0x53, 0x20, 0x58, 0x52, 0x20, 0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x2c,
            0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x35, 0x2e, 0x32, 0x2e, 0x32,
            0x2e, 0x32, 0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5d, 0x0a,
            0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63, 0x29, 0x20,
            0x32, 0x30, 0x31, 0x34, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x00,
            0x02, 0x00, 0x03, 0x78, 0x72, 0x33,
        ];

        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data,
            &mut exporter_peers,
        );

        let expected_initiation = InitiationMessage::new(vec![
            InitiationInformation::SystemDescription(
                "Cisco IOS XR Software, Version 5.2.2.21I[Default]\nCopyright (c) 2014 by Cisco Systems, Inc.".to_string()
            ),
            InitiationInformation::SystemName("xr3".to_string())
        ]);

        assert_eq!(
            result,
            Some(vec![
                DecodeOutcome::Success((
                    flow_key,
                    BmpMessage::V3(BmpMessageValue::Initiation(expected_initiation.clone()))
                )),
                DecodeOutcome::Success((
                    flow_key,
                    BmpMessage::V3(BmpMessageValue::Initiation(expected_initiation))
                ))
            ]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bmp_handler_decode_failure() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1790,
        );
        // A simple BMP Initiation message, but with wrong version
        let packet_data = [
            0x01, 0x00, 0x00, 0x00, 0x6c, 0x04, 0x00, 0x01, 0x00, 0x5b, 0x43, 0x69, 0x73, 0x63,
            0x6f, 0x20, // wrong version, first byte
            0x49, 0x4f, 0x53, 0x20, 0x58, 0x52, 0x20, 0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72,
            0x65, 0x2c, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x35, 0x2e, 0x32,
            0x2e, 0x32, 0x2e, 0x32, 0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
            0x5d, 0x0a, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63,
            0x29, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69, 0x73, 0x63,
            0x6f, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63,
            0x2e, 0x00, 0x02, 0x00, 0x03, 0x78, 0x72, 0x33,
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data,
            &mut exporter_peers,
        );

        assert_eq!(
            result,
            Some(vec![DecodeOutcome::Error(
                BmpCodecDecoderError::BmpMessageParsingError(
                    BmpMessageParsingError::UndefinedBmpVersion(
                        netgauze_bmp_pkt::iana::UndefinedBmpVersion(1)
                    )
                )
            )]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bmp_handler_decode_ignore_wrong_port() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            123,
        );
        let packet_data = [0xff; 0xff];
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
    fn test_bmp_handler_decode_ignore_wrong_protocol() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1790,
        );
        let packet_data = [0xff; 0xff];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data,
            &mut exporter_peers,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_bmp_handler_serialize_success() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1790,
        );
        let bmp_message =
            BmpMessage::V3(BmpMessageValue::Initiation(InitiationMessage::new(vec![])));
        let outcome = DecodeOutcome::Success((flow_key, bmp_message));
        let result = handler.serialize(outcome);
        assert!(result.is_ok());
        let json = result.unwrap();
        let expected = json!({
          "source_address": "10.0.0.1:12345",
          "destination_address": "10.0.0.2:1790",
          "info": {
            "V3": {
              "Initiation": {
                "information": []
              }
            }
          }
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn test_bmp_handler_serialize_error() {
        let handler = BmpProtocolHandler::new(vec![1790]);
        let error = BmpCodecDecoderError::BmpMessageParsingError(
            BmpMessageParsingError::InvalidBmpLength(10),
        );
        let outcome = DecodeOutcome::Error(error);
        let result = handler.serialize(outcome);
        assert!(result.is_ok());
        let json = result.unwrap();
        let expected = json!({
            "BmpMessageParsingError": {
                "InvalidBmpLength": 10
            }
        });
        assert_eq!(json, expected);
    }
}
