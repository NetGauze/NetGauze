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
use netgauze_bgp_pkt::{
    codec::{BgpCodec, BgpCodecDecoderError},
    wire::deserializer::{BgpParsingContext, BgpParsingIgnoredErrors},
    BgpMessage,
};
use netgauze_pcap_reader::TransportProtocol;
use std::{collections::HashMap, io, net::IpAddr};

pub struct BgpProtocolHandler {
    ports: Vec<u16>,
}

impl BgpProtocolHandler {
    pub fn new(ports: Vec<u16>) -> Self {
        BgpProtocolHandler { ports }
    }
}

impl ProtocolHandler<(BgpMessage, BgpParsingIgnoredErrors), BgpCodec, BgpCodecDecoderError>
    for BgpProtocolHandler
{
    fn decode(
        &self,
        flow_key: (IpAddr, u16, IpAddr, u16),
        protocol: TransportProtocol,
        packet_data: &[u8],
        exporter_peers: &mut HashMap<(IpAddr, u16, IpAddr, u16), (BgpCodec, BytesMut)>,
    ) -> Option<Vec<DecodeOutcome<(BgpMessage, BgpParsingIgnoredErrors), BgpCodecDecoderError>>>
    {
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::TCP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers.entry(flow_key).or_insert((
                BgpCodec::new_from_ctx(
                    true,
                    BgpParsingContext::new(
                        true,
                        HashMap::new(),
                        HashMap::new(),
                        true,
                        true,
                        true,
                        true,
                    ),
                ),
                BytesMut::new(),
            ));
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
        decode_outcome: DecodeOutcome<(BgpMessage, BgpParsingIgnoredErrors), BgpCodecDecoderError>,
    ) -> io::Result<serde_json::Value> {
        match decode_outcome {
            DecodeOutcome::Success(m) => {
                let (flow_key, (bgp_message, bgp_parsing_error)) = m;
                if !bgp_parsing_error.eq(&BgpParsingIgnoredErrors::default()) {
                    // the bgp message was parsed with some ignored errors, we will not serialize it
                    // we will report that some ignored errors were found and that this behavior
                    // by the CLI tool is not expected
                    return Ok(serde_json::Value::String("Encountered BGP parsing errors that were ignored during the decoding of the bgp message, this behaviour is not expected, please file a bug report to the developers".to_string()));
                }
                serialize_success(flow_key, bgp_message)
            }
            DecodeOutcome::Error(m) => serialize_error(m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_bgp_pkt::{
        open::BgpOpenMessage,
        path_attribute::UndefinedOrigin,
        wire::deserializer::{
            path_attribute::{OriginParsingError, PathAttributeParsingError},
            update::BgpUpdateMessageParsingError,
            BgpMessageParsingError,
        },
    };
    use serde_json::json;
    use std::net::Ipv4Addr;

    #[test]
    fn test_bgp_handler_decode_success() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            179,
        );
        // A simple BGP OPEN message
        let packet_data = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x00, 0x01, 0x00, 0xb4, 0x01, 0x02, 0x03, 0x04,
            0x00,
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
                (
                    BgpMessage::Open(BgpOpenMessage::new(
                        1,
                        180,
                        Ipv4Addr::new(1, 2, 3, 4),
                        vec![],
                    )),
                    BgpParsingIgnoredErrors::default()
                )
            ))]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bgp_handler_decode_fragmented_success() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            179,
        );
        // A simple BGP OPEN message, split into two
        let packet_data1 = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x1d, 0x01,
        ];
        let packet_data2 = &[0x04, 0x00, 0x01, 0x00, 0xb4, 0x01, 0x02, 0x03, 0x04, 0x00];
        let mut exporter_peers = HashMap::new();

        // First packet is fragmented
        let result1 = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            packet_data1,
            &mut exporter_peers,
        );
        assert!(result1.is_none());
        // The buffer for this flow key should now contain the first part, so not empty
        assert!(!exporter_peers.get(&flow_key).unwrap().1.is_empty());

        // Second packet completes it
        let result2 = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            packet_data2,
            &mut exporter_peers,
        );

        assert_eq!(
            result2,
            Some(vec![DecodeOutcome::Success((
                flow_key,
                (
                    BgpMessage::Open(BgpOpenMessage::new(
                        1,
                        180,
                        Ipv4Addr::new(1, 2, 3, 4),
                        vec![],
                    )),
                    BgpParsingIgnoredErrors::default()
                )
            ))]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bgp_handler_decode_multiple_messages_success() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            179,
        );
        // Two simple BGP OPEN messages
        let packet_data = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x00, 0x01, 0x00, 0xb4, 0x01, 0x02, 0x03, 0x04,
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x00, 0x01, 0x00, 0xb4, 0x05, 0x06, 0x07,
            0x08, 0x00,
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
            Some(vec![
                DecodeOutcome::Success((
                    flow_key,
                    (
                        BgpMessage::Open(BgpOpenMessage::new(
                            1,
                            180,
                            Ipv4Addr::new(1, 2, 3, 4),
                            vec![],
                        )),
                        BgpParsingIgnoredErrors::default()
                    )
                )),
                DecodeOutcome::Success((
                    flow_key,
                    (
                        BgpMessage::Open(BgpOpenMessage::new(
                            1,
                            180,
                            Ipv4Addr::new(5, 6, 7, 8),
                            vec![],
                        )),
                        BgpParsingIgnoredErrors::default()
                    )
                ))
            ]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bgp_handler_decode_message_with_errors_that_should_not_be_ignored() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            179,
        );
        // The packet data contains a BGP message with some errors that can potentially
        // be ignored
        let packet_data = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x59, 0x02, 0x00, 0x00, 0x00, 0x30, 0x40, 0x01, 0x01,
            0x0ff, // Undefined origin type = 0xff
            0x40, 0x02, 0x06, 0x02, 0xff, 0x00, 0x00, 0xfb, 0xff, // Segment count is 0xff
            0x40, 0x03, 0xff, 0x0a, 0x00, 0x0e,
            0x01, // Next hop size is 0xff, rather than 0x04
            0x80, 0x04, 0xff, 0x00, 0x00, 0x00, 0x00, // MED length is 0xff, rather than 0x04
            0x40, 0x05, 0xff, 0x00, 0x00, 0x00,
            0x64, // LOCAL PREF length is 0xff, rather than 0x04
            0x80, 0x0a, 0x04, 0x0a, 0x00, 0x22, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x0f, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x20, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x01, 0x20,
            0xc0, 0xa8, 0x01, 0x05,
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data,
            &mut exporter_peers,
        );

        // Expecting an error due to the first byte being different
        assert_eq!(
            result,
            Some(vec![DecodeOutcome::Error(
                BgpCodecDecoderError::BgpMessageParsingError(
                    BgpMessageParsingError::BgpUpdateMessageParsingError(
                        BgpUpdateMessageParsingError::PathAttributeError(
                            PathAttributeParsingError::OriginError(
                                OriginParsingError::UndefinedOrigin(UndefinedOrigin(255))
                            )
                        )
                    )
                )
            )]),
        );
        // now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }
    #[test]
    fn test_bgp_handler_decode_failure() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            179,
        );
        // A simple BGP OPEN message
        let packet_data = [
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, // first byte differs
            0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x00, 0x01, 0x00, 0xb4, 0x01, 0x02, 0x03, 0x04,
            0x00,
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data,
            &mut exporter_peers,
        );

        assert!(result.is_some());
        // expecting an error due to the first byte being different
        assert_eq!(
            result,
            Some(vec![DecodeOutcome::Error(
                BgpCodecDecoderError::BgpMessageParsingError(
                    BgpMessageParsingError::ConnectionNotSynchronized(
                        1329227995784915872903807060280344575
                    )
                )
            )]),
        );
        // Now we should have an empty buffer for this flow key
        assert!(exporter_peers.get(&flow_key).unwrap().1.is_empty());
    }

    #[test]
    fn test_bgp_handler_decode_ignore_wrong_port() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            180, // Wrong port
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
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            179,
        );
        let packet_data = [0xff; 20];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::UDP, // Wrong protocol
            &packet_data,
            &mut exporter_peers,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_bgp_handler_serialize_success() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            179,
        );
        let open_message = BgpMessage::Open(BgpOpenMessage::new(
            1,
            180,
            Ipv4Addr::new(1, 1, 1, 1),
            vec![],
        ));
        let outcome =
            DecodeOutcome::Success((flow_key, (open_message, BgpParsingIgnoredErrors::default())));

        let result = handler.serialize(outcome);
        assert!(result.is_ok());
        let json = result.unwrap();
        let expected = json!({
          "source_address": "10.0.0.1:12345",
          "destination_address": "10.0.0.2:179",
          "info": {
            "Open": {
              "version": 4,
              "my_as": 1,
              "hold_time": 180,
              "bgp_id": "1.1.1.1",
              "params": []
            }
          }
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn test_bgp_handler_serialize_error() {
        let handler = BgpProtocolHandler::new(vec![179]);
        let error = BgpCodecDecoderError::BgpMessageParsingError(
            BgpMessageParsingError::BadMessageLength(10),
        );
        let outcome = DecodeOutcome::Error(error);

        let result = handler.serialize(outcome);
        assert!(result.is_ok());
        let json = result.unwrap();
        let expected = json!({
            "BgpMessageParsingError": {
                "BadMessageLength": 10
            }
        });
        assert_eq!(json, expected);
    }
}
