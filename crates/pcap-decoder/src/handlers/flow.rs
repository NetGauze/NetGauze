use crate::protocol_handler::{DecodeOutcome, ProtocolHandler, SerializableInfo};
use bytes::{Buf, BytesMut};
use netgauze_flow_pkt::{
    FlowInfo,
    codec::{FlowInfoCodec, FlowInfoCodecDecoderError},
};
use netgauze_pcap_reader::TransportProtocol;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use tokio_util::codec::Decoder;

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
    ) -> Option<DecodeOutcome<FlowInfo, FlowInfoCodecDecoderError>> {
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::UDP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers
                .entry(flow_key)
                .or_insert((FlowInfoCodec::default(), BytesMut::new()));
            buffer.extend_from_slice(packet_data);
            if buffer.has_remaining() {
                match codec.decode(buffer) {
                    Ok(Some(flow_info)) => {
                        return Some(DecodeOutcome::Success((flow_key, flow_info))); // Return the FlowInfo
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
        decode_outcome: DecodeOutcome<FlowInfo, FlowInfoCodecDecoderError>,
    ) -> Result<String, std::io::Error> {
        match decode_outcome {
            DecodeOutcome::Success(m) => {
                let (flow_key, flow_info) = m;
                let serializable_flow = SerializableInfo {
                    source_address: SocketAddr::new(flow_key.0, flow_key.1),
                    destination_address: SocketAddr::new(flow_key.2, flow_key.3),
                    info: flow_info,
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
    use chrono::{TimeZone, Utc};
    use ipfix::IpfixPacket;
    use netgauze_flow_pkt::{
        DataSetId, FlowInfo,
        ie::Field,
        ipfix,
        ipfix::{DataRecord, Set},
        wire::deserializer::ipfix::IpfixPacketParsingError,
    };
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
        // A simple IPFIX packet with a template and data record
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

        assert!(result.is_some());
        if let Some(DecodeOutcome::Success((_, flow_info))) = result {
            if let FlowInfo::IPFIX(packet) = flow_info {
                assert_eq!(packet.version(), 10);
                assert_eq!(packet.observation_domain_id(), 33312);
            } else {
                panic!("Wrong flow version");
            }
        } else {
            panic!("Expected successful decode");
        }
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

        assert!(result.is_some());
        if let Some(DecodeOutcome::Error(e)) = result {
            assert!(matches!(
                e,
                FlowInfoCodecDecoderError::UnsupportedVersion(3)
            ));
        } else {
            panic!("Expected an error due to unsupported version");
        }
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
    fn test_flow_handler_decode_fragmented() {
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

        // Second packet completes it
        let result2 = handler.decode(
            flow_key,
            TransportProtocol::UDP,
            packet_data2,
            &mut exporter_peers,
        );
        assert!(result2.is_some());
        if let Some(DecodeOutcome::Success((_, msg))) = result2 {
            if let FlowInfo::IPFIX(packet) = msg {
                assert_eq!(packet.version(), 10);
                assert_eq!(packet.observation_domain_id(), 33312);
            } else {
                panic!("Wrong flow version");
            }
        } else {
            panic!("Expected successful decode on second packet");
        }
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
        assert_eq!(
            json,
            r#"{"source_address":"10.0.0.1:12345","destination_address":"10.0.0.2:9991","info":{"IPFIX":{"version":10,"export_time":"2025-01-01T18:00:00Z","sequence_number":15,"observation_domain_id":400,"sets":[{"Data":{"id":600,"records":[{"scope_fields":[],"fields":[{"sourceIPv4Address":"10.0.0.1"},{"octetDeltaCount":300}]}]}}]}}}"#
        )
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
        assert_eq!(json, r#"{"IpfixParsingError":{"InvalidLength":10}}"#)
    }
}
