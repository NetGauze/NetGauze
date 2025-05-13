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
