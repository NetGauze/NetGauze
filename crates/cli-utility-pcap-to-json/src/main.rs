mod handlers;
mod protocol_handler;

use crate::{
    handlers::{
        bmp::BmpProtocolHandler, flow::FlowProtocolHandler, udp_notif::UdpNotifProtocolHandler,
    },
    protocol_handler::ProtocolHandler,
};
use clap::{Parser, ValueEnum};
use netgauze_pcap_reader::PcapIter;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    net::IpAddr,
    path::PathBuf,
};

// Define constants
const PCAP_BUFFER_SIZE: usize = 165536;

fn load_pcap_and_process<M, C, E, H>(
    config: &Config,
    handler: &H,
) -> Result<(), Box<dyn std::error::Error>>
where
    C: Send + Sync + Default + 'static,
    M: Send + Sync + 'static,
    E: Send + Sync + 'static,
    H: ProtocolHandler<M, C, E>,
{
    let pcap_file = File::open(config.pcap_path.as_path()).expect("Failed to open pcap file");
    let pcap_reader =
        Box::new(pcap_parser::LegacyPcapReader::new(PCAP_BUFFER_SIZE, pcap_file).unwrap());

    let mut exporter_peers: HashMap<(IpAddr, u16, IpAddr, u16), (C, bytes::BytesMut)> =
        HashMap::new();
    let mut packet_counter = 0;
    let output_file = File::create(config.output_path.as_path())?;
    let mut writer = BufWriter::new(output_file);

    for (src_ip, src_port, dst_ip, dst_port, protocol, packet_data) in PcapIter::new(pcap_reader) {
        packet_counter += 1;
        if let Some(max_packets) = config.input_size {
            if packet_counter >= max_packets {
                break;
            }
        }

        let flow_key = (src_ip, src_port, dst_ip, dst_port);
        if let Some(message) = handler.decode(flow_key, protocol, &packet_data, &mut exporter_peers)
        {
            let serialized_data = handler.serialize(message)?;
            writer.write_all(serialized_data.as_bytes())?;
            writer.write_all(b"\n")?;
        }
    }

    writer.flush()?;
    println!(
        "Read {} packets from {} flow peers",
        packet_counter,
        exporter_peers.len()
    );
    Ok(())
}

#[derive(Debug)]
struct Config {
    ports: Vec<u16>,
    input_size: Option<usize>,
    pcap_path: PathBuf,
    output_path: PathBuf,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ProtocolToDecode {
    Flow,
    BMP,
    UDPNotif,
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

    /// Specify the protocol to decode
    #[clap(long, value_enum)]
    protocol: ProtocolToDecode,

    /// Max number of messages to load from the pcap test file
    /// if not set all messages will be loaded
    #[clap(short, long)]
    input_size: Option<usize>,

    /// Specify the protocol ports (comma-separated, example: 9991,9992)
    #[clap(long, value_delimiter = ',', required = true)]
    ports: Vec<u16>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        ports: cli.ports,
    };

    match cli.protocol {
        ProtocolToDecode::Flow => {
            let flow_handler = FlowProtocolHandler::new(config.ports.clone());
            load_pcap_and_process(&config, &flow_handler)?;
        }
        ProtocolToDecode::BMP => {
            let bmp_handler = BmpProtocolHandler::new(config.ports.clone());
            load_pcap_and_process(&config, &bmp_handler)?;
        }
        ProtocolToDecode::UDPNotif => {
            let udp_notif_handler = UdpNotifProtocolHandler::new(config.ports.clone());
            load_pcap_and_process(&config, &udp_notif_handler)?;
        }
    }

    Ok(())
}
