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
        let src_ip: IpAddr = flow_key.0;
        let src_port: u16 = flow_key.1;
        let dst_port: u16 = flow_key.3;

        if protocol == TransportProtocol::UDP && self.ports.contains(&dst_port) {
            let (codec, buffer) = exporter_peers
                .entry(flow_key)
                .or_insert((FlowInfoCodec::default(), BytesMut::new()));
            buffer.extend_from_slice(packet_data);
            if buffer.has_remaining() {
                match codec.decode(buffer) {
                    Ok(Some(flow_info)) => {
                        return Some(DecodeOutcome::Success((
                            SocketAddr::new(src_ip, src_port),
                            flow_info,
                        ))); // Return the FlowInfo
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
                let (source_address, flow_info) = m;
                let serializable_flow = SerializableInfo {
                    info: flow_info,
                    source_address,
                };
                Ok(serde_json::to_string(&serializable_flow)?)
            }
            DecodeOutcome::Error(m) => Ok(serde_json::to_string(&m)?),
        }
    }
}
