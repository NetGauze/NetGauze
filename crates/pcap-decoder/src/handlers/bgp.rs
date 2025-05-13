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
