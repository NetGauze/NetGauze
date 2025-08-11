use crate::protocol_handler::{DecodeOutcome, ProtocolHandler, SerializableInfo};
use bytes::{Buf, BytesMut};
use netgauze_bgp_pkt::{
    BgpMessage,
    codec::{BgpCodec, BgpCodecDecoderError},
};
use netgauze_pcap_reader::TransportProtocol;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use tokio_util::codec::Decoder;

pub struct BgpProtocolHandler {
    ports: Vec<u16>,
}

impl BgpProtocolHandler {
    pub fn new(ports: Vec<u16>) -> Self {
        BgpProtocolHandler { ports }
    }
}

impl ProtocolHandler<BgpMessage, BgpCodec, BgpCodecDecoderError> for BgpProtocolHandler {
    fn decode(
        &self,
        flow_key: (IpAddr, u16, IpAddr, u16),
        protocol: TransportProtocol,
        packet_data: &[u8],
        exporter_peers: &mut HashMap<(IpAddr, u16, IpAddr, u16), (BgpCodec, BytesMut)>,
    ) -> Option<DecodeOutcome<BgpMessage, BgpCodecDecoderError>> {
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::TCP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers
                .entry(flow_key)
                .or_insert((BgpCodec::new(true), BytesMut::new()));
            buffer.extend_from_slice(packet_data);
            if buffer.has_remaining() {
                match codec.decode(buffer) {
                    Ok(Some((msg, _err))) => {
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
        decode_outcome: DecodeOutcome<BgpMessage, BgpCodecDecoderError>,
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
    use netgauze_bgp_pkt::{open::BgpOpenMessage, wire::deserializer::BgpMessageParsingError};
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

        assert!(result.is_some());
        if let Some(DecodeOutcome::Success((_, msg))) = result {
            assert!(matches!(msg, BgpMessage::Open(_)));
        } else {
            panic!("Expected successful decode");
        }
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
        if let Some(DecodeOutcome::Error(e)) = result {
            assert!(matches!(e, BgpCodecDecoderError::BgpMessageParsingError(_)));
        } else {
            panic!("Expected error decode");
        }
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
    fn test_bgp_handler_decode_fragmented() {
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

        // Second packet completes it
        let result2 = handler.decode(
            flow_key,
            TransportProtocol::TCP,
            packet_data2,
            &mut exporter_peers,
        );
        assert!(result2.is_some());
        if let Some(DecodeOutcome::Success((_, msg))) = result2 {
            assert!(matches!(msg, BgpMessage::Open(_)));
        } else {
            panic!("Expected successful decode on second packet");
        }
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
        let outcome = DecodeOutcome::Success((flow_key, open_message));

        let result = handler.serialize(outcome);
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(
            json,
            "{\"source_address\":\"10.0.0.1:12345\",\"destination_address\":\"10.0.0.2:179\",\"info\":{\"Open\":{\"version\":4,\"my_as\":1,\"hold_time\":180,\"bgp_id\":\"1.1.1.1\",\"params\":[]}}}"
        );
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
        assert_eq!(
            json,
            "{\"BgpMessageParsingError\":{\"BadMessageLength\":10}}"
        );
    }
}
