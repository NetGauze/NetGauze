mod handlers;
mod protocol_handler;

use crate::{
    handlers::{
        bgp::BgpProtocolHandler, bmp::BmpProtocolHandler, flow::FlowProtocolHandler,
        udp_notif::UdpNotifProtocolHandler,
    },
    protocol_handler::ProtocolHandler,
};
use clap::{Parser, ValueEnum};
use netgauze_pcap_reader::PcapIter;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufWriter, Write},
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
    C: Default,
    H: ProtocolHandler<M, C, E>,
{
    let pcap_file = File::open(config.pcap_path.as_path()).expect("Failed to open pcap file");
    let pcap_reader =
        Box::new(pcap_parser::LegacyPcapReader::new(PCAP_BUFFER_SIZE, pcap_file).unwrap());

    let mut exporter_peers: HashMap<(IpAddr, u16, IpAddr, u16), (C, bytes::BytesMut)> =
        HashMap::new();
    let mut packet_counter = 0;

    let mut writer: Box<dyn Write> = if let Some(output_path_ref) = &config.output_path {
        // If an output path is provided, create/truncate the file and use it
        let output_file = File::create(output_path_ref).map_err(|e| {
            format!(
                "Failed to create output file '{}': {}",
                output_path_ref.display(),
                e
            )
        })?;
        Box::new(BufWriter::new(output_file))
    } else {
        // If no output path is provided, write to standard output
        Box::new(BufWriter::new(io::stdout()))
    };

    for (src_ip, src_port, dst_ip, dst_port, protocol, packet_data) in PcapIter::new(pcap_reader) {
        packet_counter += 1;
        if let Some(max_packets) = config.input_size && packet_counter >= max_packets {
            break;
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
    output_path: Option<PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ProtocolToDecode {
    BGP,
    BMP,
    Flow,
    UDPNotif,
}

#[derive(Debug, Parser)]
#[command(long_about = None)]
struct Cli {
    /// Input PCAP file path
    #[clap(short, long)]
    input: String,

    /// JSON Lines output file path, if not specified
    /// output will be directed to stdout
    #[clap(short, long)]
    output: Option<String>,

    /// Specify the protocol to decode
    #[clap(long, value_enum)]
    protocol: ProtocolToDecode,

    /// Specify the protocol ports that will be used to filter the PCAP file
    /// packets (comma-separated, example: 9991,9992)
    #[clap(long, value_delimiter = ',', required = true)]
    ports: Vec<u16>,

    /// Max number of messages to load from the PCAP input file,
    /// if not set all messages will be loaded
    #[clap(short = 'c', long)]
    input_count: Option<usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = Config {
        pcap_path: cli
            .input
            .parse::<PathBuf>()
            .expect("Failed to parse pcap path"),
        output_path: cli.output.map(PathBuf::from),
        input_size: cli.input_count,
        ports: cli.ports,
    };

    match cli.protocol {
        ProtocolToDecode::BGP => {
            let bgp_handler = BgpProtocolHandler::new(config.ports.clone());
            load_pcap_and_process(&config, &bgp_handler)?;
        }
        ProtocolToDecode::BMP => {
            let bmp_handler = BmpProtocolHandler::new(config.ports.clone());
            load_pcap_and_process(&config, &bmp_handler)?;
        }
        ProtocolToDecode::Flow => {
            let flow_handler = FlowProtocolHandler::new(config.ports.clone());
            load_pcap_and_process(&config, &flow_handler)?;
        }
        ProtocolToDecode::UDPNotif => {
            let udp_notif_handler = UdpNotifProtocolHandler::new(config.ports.clone());
            load_pcap_and_process(&config, &udp_notif_handler)?;
        }
    }

    Ok(())
}
