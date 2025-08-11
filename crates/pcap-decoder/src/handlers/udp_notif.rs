use crate::protocol_handler::{DecodeOutcome, ProtocolHandler, SerializableInfo};
use bytes::{Buf, BytesMut};
use netgauze_pcap_reader::TransportProtocol;
use netgauze_udp_notif_pkt::{
    MediaType, UdpNotifPacket,
    codec::{UdpPacketCodec, UdpPacketCodecError},
};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use tokio_util::codec::Decoder;

pub struct UdpNotifProtocolHandler {
    ports: Vec<u16>,
}

impl UdpNotifProtocolHandler {
    pub fn new(ports: Vec<u16>) -> Self {
        UdpNotifProtocolHandler { ports }
    }
}

impl ProtocolHandler<UdpNotifPacket, UdpPacketCodec, UdpPacketCodecError>
    for UdpNotifProtocolHandler
{
    fn decode(
        &self,
        flow_key: (IpAddr, u16, IpAddr, u16),
        protocol: TransportProtocol,
        packet_data: &[u8],
        exporter_peers: &mut HashMap<(IpAddr, u16, IpAddr, u16), (UdpPacketCodec, BytesMut)>,
    ) -> Option<DecodeOutcome<UdpNotifPacket, UdpPacketCodecError>> {
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::UDP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers
                .entry(flow_key)
                .or_insert((UdpPacketCodec::default(), BytesMut::new()));
            buffer.extend_from_slice(packet_data);
            if buffer.has_remaining() {
                match codec.decode(buffer) {
                    Ok(Some(udp_notif_packet)) => {
                        return Some(DecodeOutcome::Success((flow_key, udp_notif_packet))); // Return the FlowInfo
                    }
                    Ok(None) => {
                        return None;
                    }
                    Err(e) => {
                        // packet decoding error before the templates arrive
                        return Some(DecodeOutcome::Error(e));
                    }
                }
            }
        }
        None
    }

    fn serialize(
        &self,
        decode_outcome: DecodeOutcome<UdpNotifPacket, UdpPacketCodecError>,
    ) -> Result<String, std::io::Error> {
        match decode_outcome {
            DecodeOutcome::Success(m) => {
                let (flow_key, udp_notif_packet) = m;
                let mut value = serde_json::to_value(&udp_notif_packet)
                    .expect("Couldn't serialize UDP-Notif message to json");
                // Convert when possible inner payload into human-readable format
                match udp_notif_packet.media_type() {
                    MediaType::YangDataJson => {
                        let payload = serde_json::from_slice(udp_notif_packet.payload())
                            .expect("Couldn't deserialize JSON payload into a JSON object");
                        if let Value::Object(val) = &mut value {
                            val.insert("payload".to_string(), payload);
                        }
                    }
                    MediaType::YangDataXml => {
                        let payload = std::str::from_utf8(udp_notif_packet.payload())
                            .expect("Couldn't deserialize XML payload into an UTF-8 string");
                        if let Value::Object(val) = &mut value {
                            val.insert("payload".to_string(), Value::String(payload.to_string()));
                        }
                    }
                    MediaType::YangDataCbor => {
                        let payload: Value = ciborium::de::from_reader(std::io::Cursor::new(
                            udp_notif_packet.payload(),
                        ))
                        .expect("Couldn't deserialize CBOR payload into a CBOR object");
                        if let Value::Object(val) = &mut value {
                            val.insert("payload".to_string(), payload);
                        }
                    }
                    _ => {}
                }
                let serializable_flow = SerializableInfo {
                    source_address: SocketAddr::new(flow_key.0, flow_key.1),
                    destination_address: SocketAddr::new(flow_key.2, flow_key.3),
                    info: value,
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
    use bytes::Bytes;
    use std::net::Ipv4Addr;

    #[test]
    fn test_udp_notif_handler_decode_success() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
        );
        let packet_data = [
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x0c, // Header length
            0x00, 0x0e, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // dummy payload
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data,
            &mut exporter_peers,
        );

        assert!(result.is_some());
        if let Some(DecodeOutcome::Success((_, msg))) = result {
            assert_eq!(msg.message_id(), 0x02000002);
        } else {
            panic!("Unexpected decode outcome");
        }
    }

    #[test]
    fn test_udp_notif_handler_decode_failure() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
        );
        let packet_data = [
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x01, // Invalid Header length
            0x00, 0x0e, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // dummy payload
        ];
        let mut exporter_peers = HashMap::new();

        let result = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data,
            &mut exporter_peers,
        );

        assert!(result.is_some());
        if let Some(DecodeOutcome::Error(e)) = result {
            assert!(matches!(e, UdpPacketCodecError::InvalidHeaderLength(1)));
        } else {
            panic!("Expected error decode");
        }
    }

    #[test]
    fn test_udp_notif_handler_decode_ignore_wrong_port() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5678, // Wrong port
        );
        let packet_data = [0xff];
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
    fn test_udp_notif_handler_decode_ignore_wrong_protocol() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
        );
        let packet_data = [0xff];
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
    fn test_udp_notif_handler_decode_fragmented() {
        let handler = UdpNotifProtocolHandler::new(vec![4739]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            4739,
        );
        let packet_data1 = [
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x0c, // Header length
            0x00, 0x0e, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
        ];
        let packet_data2 = [
            0xff, 0xff, // dummy payload
        ];
        let mut exporter_peers = HashMap::new();

        let result1 = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data1,
            &mut exporter_peers,
        );
        // UDP is datagram oriented, so the codec will wait for the full datagram.
        // The test setup simulates fragmentation at a higher level.
        assert!(result1.is_none());

        let result2 = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            &packet_data2,
            &mut exporter_peers,
        );

        assert!(result2.is_some());
        if let Some(DecodeOutcome::Success((_, msg))) = result2 {
            assert_eq!(msg.message_id(), 0x02000002);
        } else {
            panic!("Expected successful decode on second packet");
        }
    }

    #[test]
    fn test_udp_notif_handler_serialize_success() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
        );
        let udp_notif_packet = UdpNotifPacket::new(
            MediaType::Unknown(0xee),
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(&[0xffu8, 0xffu8][..]),
        );
        let outcome = DecodeOutcome::Success((flow_key, udp_notif_packet));

        let result = handler.serialize(outcome);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(
            json,
            r#"{"source_address":"10.0.0.1:12345","destination_address":"10.0.0.2:1234","info":{"media_type":{"Unknown":238},"message_id":33554434,"options":{},"payload":[255,255],"publisher_id":16777217}}"#
        );
    }

    #[test]
    fn test_udp_notif_handler_serialize_error() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let error = UdpPacketCodecError::InvalidMessageLength(10);
        let outcome = DecodeOutcome::Error(error);

        let result = handler.serialize(outcome);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json, r#"{"InvalidMessageLength":10}"#);
    }

    #[test]
    fn test_udp_notif_handler_serialize_json_payload() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
        );
        let json_payload = serde_json::json!({"a": "b"});
        let udp_notif_packet = UdpNotifPacket::new(
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(serde_json::to_vec(&json_payload).unwrap()),
        );
        let outcome = DecodeOutcome::Success((flow_key, udp_notif_packet));

        let result = handler.serialize(outcome);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(
            json,
            r#"{"source_address":"10.0.0.1:12345","destination_address":"10.0.0.2:1234","info":{"media_type":"YangDataJson","message_id":33554434,"options":{},"payload":{"a":"b"},"publisher_id":16777217}}"#
        );
    }

    #[test]
    fn test_udp_notif_handler_serialize_xml_payload() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
        );
        let xml_payload = r#"<a b="c"/>"#;
        let udp_notif_packet = UdpNotifPacket::new(
            MediaType::YangDataXml,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(xml_payload),
        );
        let outcome = DecodeOutcome::Success((flow_key, udp_notif_packet));

        let result = handler.serialize(outcome);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(
            json,
            r#"{"source_address":"10.0.0.1:12345","destination_address":"10.0.0.2:1234","info":{"media_type":"YangDataXml","message_id":33554434,"options":{},"payload":"<a b=\"c\"/>","publisher_id":16777217}}"#
        );
    }

    #[test]
    fn test_udp_notif_handler_serialize_cbor_payload() {
        let handler = UdpNotifProtocolHandler::new(vec![1234]);
        let flow_key = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
        );
        let cbor_payload_map = serde_json::json!({"a": "b"});
        let mut cbor_payload = Vec::new();
        ciborium::ser::into_writer(&cbor_payload_map, &mut cbor_payload).unwrap();

        let udp_notif_packet = UdpNotifPacket::new(
            MediaType::YangDataCbor,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(cbor_payload),
        );
        let outcome = DecodeOutcome::Success((flow_key, udp_notif_packet));

        let result = handler.serialize(outcome);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(
            json,
            r#"{"source_address":"10.0.0.1:12345","destination_address":"10.0.0.2:1234","info":{"media_type":"YangDataCbor","message_id":33554434,"options":{},"payload":{"a":"b"},"publisher_id":16777217}}"#
        );
    }
}
