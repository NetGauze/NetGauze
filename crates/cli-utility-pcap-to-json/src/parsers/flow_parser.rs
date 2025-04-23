use bytes::{Buf, BytesMut};
use netgauze_flow_pkt::codec::FlowInfoCodec;
use netgauze_pcap_reader::TransportProtocol;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio_util::codec::Decoder;

use crate::{PcapData, PeerCodec, send_pcap_data};

pub async fn parse_flow_data(
    flow_port1: u16,
    flow_port2: u16,
    flow_key: (IpAddr, u16, IpAddr, u16),
    protocol: TransportProtocol,
    packet_data: &Vec<u8>,
    exporter_peers: &mut HashMap<
        (std::net::IpAddr, u16, std::net::IpAddr, u16),
        (PeerCodec, BytesMut),
    >,
    tx: &async_channel::Sender<Arc<PcapData>>,
) {
    let src_ip: IpAddr = flow_key.0;
    let src_port: u16 = flow_key.1;
    let dst_port: u16 = flow_key.3;

    if protocol == TransportProtocol::UDP && (dst_port == flow_port1 || dst_port == flow_port2) {
        let (codec, buffer) = exporter_peers.entry(flow_key).or_insert((
            PeerCodec::FlowInfo(FlowInfoCodec::default()),
            BytesMut::new(),
        ));
        buffer.extend_from_slice(&packet_data);
        if let PeerCodec::FlowInfo(codec) = codec {
            while buffer.has_remaining() {
                match codec.decode(buffer) {
                    Ok(Some(flow_info)) => {
                        send_pcap_data(
                            &tx,
                            PcapData::Flow((SocketAddr::new(src_ip, src_port), flow_info)),
                        )
                        .await
                    }
                    Ok(None) => {}
                    Err(_) => {
                        // packet decoding error before the templates arrive
                    }
                }
            }
        }
    }
}
