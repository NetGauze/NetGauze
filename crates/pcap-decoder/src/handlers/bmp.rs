use crate::protocol_handler::{DecodeOutcome, ProtocolHandler, SerializableInfo};
use bytes::{Buf, BytesMut};
use netgauze_bmp_pkt::{
    BmpMessage,
    codec::{BmpCodec, BmpCodecDecoderError},
};
use netgauze_pcap_reader::TransportProtocol;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use tokio_util::codec::Decoder;

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
    ) -> Option<DecodeOutcome<BmpMessage, BmpCodecDecoderError>> {
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::TCP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers
                .entry(flow_key)
                .or_insert((BmpCodec::default(), BytesMut::new()));
            buffer.extend_from_slice(packet_data);
            if buffer.has_remaining() {
                match codec.decode(buffer) {
                    Ok(Some(msg)) => {
                        return Some(DecodeOutcome::Success((flow_key, msg)));
                    }
                    Ok(None) => {
                        // packet is fragmented, need to read the next PDU first before attempting
                        // to deserialize it
                        return None;
                    }
                    Err(e) => return Some(DecodeOutcome::Error(e)),
                }
            }
        }
        None
    }

    fn serialize(
        &self,
        decode_outcome: DecodeOutcome<BmpMessage, BmpCodecDecoderError>,
    ) -> Result<String, std::io::Error> {
        match decode_outcome {
            DecodeOutcome::Success(m) => {
                let (flow_key, bmp_message) = m;
                let serializable_flow = SerializableInfo {
                    source_address: SocketAddr::new(flow_key.0, flow_key.1),
                    destination_address: SocketAddr::new(flow_key.2, flow_key.3),
                    info: bmp_message,
                };
                Ok(serde_json::to_string(&serializable_flow)?)
            }
            DecodeOutcome::Error(m) => Ok(serde_json::to_string(&m)?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_bmp_pkt::{
        v3::{BmpMessageValue, InitiationMessage},
        wire::deserializer::BmpMessageParsingError,
    };
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

        assert!(result.is_some());
        if let Some(DecodeOutcome::Success((_, msg))) = result {
            assert!(matches!(
                msg,
                BmpMessage::V3(BmpMessageValue::Initiation(_))
            ));
        } else {
            panic!("Unexpected decode outcome");
        }
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
        // A simple BMP Initiation message, but truncated
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

        assert!(result.is_some());
        if let Some(DecodeOutcome::Error(e)) = result {
            assert!(matches!(e, BmpCodecDecoderError::BmpMessageParsingError(_)));
        } else {
            panic!("Expected error decode");
        }
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
    fn test_bmp_handler_decode_fragmented() {
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

        let result2 = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            &packet_data2,
            &mut exporter_peers,
        );
        assert!(result2.is_some());
        if let Some(DecodeOutcome::Success((_, msg))) = result2 {
            assert!(matches!(
                msg,
                BmpMessage::V3(BmpMessageValue::Initiation(_))
            ));
        } else {
            panic!("Expected successful decode on second packet");
        }
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
        assert_eq!(
            json,
            r#"{"source_address":"10.0.0.1:12345","destination_address":"10.0.0.2:1790","info":{"V3":{"Initiation":{"information":[]}}}}"#
        );
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
        assert_eq!(
            json,
            r#"{"BmpMessageParsingError":{"InvalidBmpLength":10}}"#
        );
    }
}
