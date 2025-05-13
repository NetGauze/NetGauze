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
