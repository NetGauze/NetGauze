use bytes::{Buf, BytesMut};
use netgauze_pcap_reader::TransportProtocol;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use netgauze_udp_notif_pkt::codec::UdpPacketCodec;
use tokio_util::codec::Decoder;

use crate::{PcapData, PeerCodec, send_pcap_data};

pub async fn parse_udp_notif_data(
    flow_key: (IpAddr, u16, IpAddr, u16),
    protocol: TransportProtocol,
    packet_data: &Vec<u8>,
    exporter_peers: &mut HashMap<
        (std::net::IpAddr, u16, std::net::IpAddr, u16),
        (PeerCodec, BytesMut),
    >,
    tx: &async_channel::Sender<Arc<PcapData>>,
) {
    let src_port: u16 = flow_key.1;
    let dst_port: u16 = flow_key.3;

    if protocol == TransportProtocol::UDP && [10003, 57499].contains(&dst_port) {
        let (codec, buffer) = exporter_peers
            .entry(flow_key)
            .or_insert((PeerCodec::UDPNotif(UdpPacketCodec::default()), BytesMut::new()));
        buffer.extend_from_slice(&packet_data);
        if let PeerCodec::UDPNotif(codec) = codec {
            while buffer.has_remaining() {
                match codec.decode(buffer) {
                    Ok(Some(msg)) => send_pcap_data(&tx, PcapData::UDPNotif(msg)).await,
                    Ok(None) => {
                        // packet is fragmented, need to read the next PDU first before attempting to deserialize it
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    }
}
