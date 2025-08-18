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

//! NetGauze PCAP Decoder Library
//!
//! This library provides functionality to decode various network protocols
//! (BGP, BMP, Flow, UDP-Notif) from PCAP files and serialize them to JSON.

pub mod handlers;
pub mod protocol_handler;

use crate::protocol_handler::ProtocolHandler;
use netgauze_pcap_reader::PcapIter;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufWriter, Write},
    net::IpAddr,
    path::PathBuf,
};

// Define constants
pub const PCAP_BUFFER_SIZE: usize = 165536;

/// Configuration for PCAP processing
#[derive(Debug, Clone)]
pub struct Config {
    pub dest_ports: Vec<u16>,
    pub input_size: Option<usize>,
    pub pcap_path: PathBuf,
    pub output_path: Option<PathBuf>,
}

/// Handlers re-export
pub use handlers::{
    bgp::BgpProtocolHandler, bmp::BmpProtocolHandler, flow::FlowProtocolHandler,
    udp_notif::UdpNotifProtocolHandler,
};

/// Load and process a PCAP file with the given configuration and handler.
///
/// This function reads packets from the specified PCAP file, decodes them using
/// the provided handler, and writes the results to a JSON Lines output file or
/// standard output.
///
/// # Arguments
/// * `config` - Configuration containing paths and options for processing:
///   destination ports on which the protocol handler will filter packets, input
///   size limit, PCAP file path, and optional output path.
/// * `handler` - Protocol handler that implements the `ProtocolHandler` trait
/// # Returns
/// * `Ok(())` if processing was successful
/// * `Err` if an error occurred during file operations or processing
pub fn load_pcap_and_process<M, C, E, H>(
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
        if let Some(max_packets) = config.input_size {
            if packet_counter > max_packets {
                break;
            }
        }

        let flow_key = (src_ip, src_port, dst_ip, dst_port);
        if let Some(message) = handler.decode(flow_key, protocol, &packet_data, &mut exporter_peers)
        {
            for result in message {
                let serialized_data = handler.serialize(result)?;
                writer.write_all(serde_json::to_string(&serialized_data)?.as_bytes())?;
                writer.write_all(b"\n")?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}
