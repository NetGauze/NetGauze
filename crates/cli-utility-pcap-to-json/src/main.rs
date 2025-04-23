mod serializer;
mod parsers;

use crate::parsers::bmp_parser::parse_bmp_data;
use crate::parsers::flow_parser::parse_flow_data;
use bytes::BytesMut;
use chrono::Utc;
use clap::Parser;
use clap::ValueEnum;
use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmp_pkt::codec::BmpCodec;
use netgauze_flow_pkt::codec::FlowInfoCodec;
use netgauze_flow_service::FlowRequest;
use netgauze_pcap_reader::PcapIter;
use pcap_parser::LegacyPcapReader;
use serde::Serialize;
use std::{
    cmp, collections::HashMap, fs::File, ops::Mul, path::PathBuf, sync::Arc, time::Duration,
};
use netgauze_udp_notif_pkt::codec::UdpPacketCodec;
use netgauze_udp_notif_pkt::UdpNotifPacket;
use crate::parsers::udp_notif_parser::parse_udp_notif_data;

// Define constants for magic numbers
const PCAP_BUFFER_SIZE: usize = 165536;
const SEND_CHANNEL_BUFFER: usize = 1000;
const SLEEP_DURATION_INITIAL_MS: u64 = 10;
const SLEEP_DURATION_MAX_SECS: u64 = 1;
const DEFAULT_FLOW_PORT_1: u16 = 9991;
const DEFAULT_FLOW_PORT_2: u16 = 9992;
const DEFAULT_BMP_PORT: u16 = 1790;

struct Config {
    flow_port1: u16,
    flow_port2: u16,
    bmp_port: u16,
    input_size: Option<usize>,
    protocol: ProtocolToParse,
    pcap_path: PathBuf,
    output_path: PathBuf,
}

async fn send_pcap_data(tx: &async_channel::Sender<Arc<PcapData>>, data: PcapData) {
    let mut sleep_duration = Duration::from_millis(SLEEP_DURATION_INITIAL_MS);
    while tx.is_full() {
        tokio::time::sleep(sleep_duration).await;
        sleep_duration = cmp::max(
            sleep_duration.mul(2),
            Duration::from_secs(SLEEP_DURATION_MAX_SECS),
        );
    }
    tx.send(Arc::new(data))
        .await
        .expect("Failed to send pcap data");
}

// TODO try to use generics
#[derive(Debug, Serialize, Clone)]
enum PcapData {
    Flow(FlowRequest),
    Bmp(BmpMessage),
    UDPNotif(UdpNotifPacket)
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ProtocolToParse {
    Flow,
    BMP,
    UDPNotif,
}

enum PeerCodec {
    FlowInfo(FlowInfoCodec),
    BMP(BmpCodec),
    UDPNotif(UdpPacketCodec)
}

async fn load_pcap(config: &Config, tx: async_channel::Sender<Arc<PcapData>>) {
    let start_time = Utc::now();

    let pcap_file = File::open(config.pcap_path.as_path()).expect("Failed to open pcap file");
    let pcap_reader = Box::new(LegacyPcapReader::new(PCAP_BUFFER_SIZE, pcap_file).unwrap());

    let mut exporter_peers: HashMap<
        (std::net::IpAddr, u16, std::net::IpAddr, u16),
        (PeerCodec, BytesMut),
    > = HashMap::new();

    let mut packet_counter = 0;
    for (src_ip, src_port, dst_ip, dst_port, protocol, packet_data) in PcapIter::new(pcap_reader) {
        packet_counter += 1;
        if let Some(max_packets) = config.input_size {
            if packet_counter >= max_packets {
                break;
            }
        }

        let flow_key = (src_ip, src_port, dst_ip, dst_port);
        match config.protocol {
            ProtocolToParse::Flow => {
                parse_flow_data(
                    config.flow_port1,
                    config.flow_port2,
                    flow_key,
                    protocol,
                    &packet_data,
                    &mut exporter_peers,
                    &tx,
                )
                .await
            }
            ProtocolToParse::BMP => {
                parse_bmp_data(
                    config.bmp_port,
                    flow_key,
                    protocol,
                    &packet_data,
                    &mut exporter_peers,
                    &tx,
                )
                .await
            }
            ProtocolToParse::UDPNotif => {
                parse_udp_notif_data(
                    flow_key,
                    protocol,
                    &packet_data,
                    &mut exporter_peers,
                    &tx,
                ).await
            }
        }
    }

    let end_load_time = Utc::now();
    let load_duration = end_load_time.signed_duration_since(start_time);
    println!(
        "Read {} packets from {} flow peers in {}",
        packet_counter,
        exporter_peers.len(),
        load_duration
    );
}

#[derive(Debug, Parser)]
#[command(long_about = None)]
struct Cli {
    /// Pcap input test file
    #[clap(long)]
    pcap: String,

    /// JSON output file path
    #[clap(short, long)]
    output: String,

    /// Specify the protocol to parse
    #[clap(long, value_enum)]
    protocol: ProtocolToParse,

    /// Max number of messages to load from the pcap test file
    /// if not set all messages will be loaded
    #[clap(short, long)]
    input_size: Option<usize>,

    /// Specify the first Flow Service port (default: 9991)
    #[clap(long, default_value_t = DEFAULT_FLOW_PORT_1)]
    flow_port1: u16,

    /// Specify the second Flow Service port (default: 9992)
    #[clap(long, default_value_t = DEFAULT_FLOW_PORT_2)]
    flow_port2: u16,

    /// Specify the BMP port (default: 1790)
    #[clap(long, default_value_t = DEFAULT_BMP_PORT)]
    bmp_port: u16,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = Config {
        pcap_path: cli
            .pcap
            .parse::<PathBuf>()
            .expect("Failed to parse pcap path"),
        output_path: cli
            .output
            .parse::<PathBuf>()
            .expect("Failed to parse output path"),
        input_size: cli.input_size,
        protocol: cli.protocol,
        flow_port1: cli.flow_port1,
        flow_port2: cli.flow_port2,
        bmp_port: cli.bmp_port,
    };

    // TODO print errors for IPFIX in case of decoding issue

    // TODO add BGP

    let (tx, rx): (async_channel::Sender<Arc<PcapData>>, _) =
        async_channel::bounded(SEND_CHANNEL_BUFFER);

    let handle = tokio::spawn(serializer::serialize_data_to_jsonl(
        rx,
        config.output_path.clone(),
    ));
    load_pcap(&config, tx).await;

    let _ = tokio::join!(handle);
    Ok(())
}
