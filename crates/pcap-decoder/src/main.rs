// Copyright (C) 2025-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::{Parser, ValueEnum};
use netgauze_pcap_decoder::{
    BgpProtocolHandler, BmpProtocolHandler, Config, FlowProtocolHandler, UdpNotifProtocolHandler,
    load_pcap_and_process,
};
use std::path::PathBuf;

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

    /// Specify the protocol destination ports that will be used to filter the
    /// PCAP file packets (comma-separated, example: 9991,9992)
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
        dest_ports: cli.ports,
    };

    match cli.protocol {
        ProtocolToDecode::BGP => {
            let bgp_handler = BgpProtocolHandler::new(config.dest_ports.clone());
            load_pcap_and_process(&config, &bgp_handler)?;
        }
        ProtocolToDecode::BMP => {
            let bmp_handler = BmpProtocolHandler::new(config.dest_ports.clone());
            load_pcap_and_process(&config, &bmp_handler)?;
        }
        ProtocolToDecode::Flow => {
            let flow_handler = FlowProtocolHandler::new(config.dest_ports.clone());
            load_pcap_and_process(&config, &flow_handler)?;
        }
        ProtocolToDecode::UDPNotif => {
            let udp_notif_handler = UdpNotifProtocolHandler::new(config.dest_ports.clone());
            load_pcap_and_process(&config, &udp_notif_handler)?;
        }
    }

    Ok(())
}
