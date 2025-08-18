# NetGauze PCAP Decoder

A Rust library and CLI utility to decode network protocols (BGP, BMP, NetFlow/IPFIX, UDP-Notif) from PCAP files and convert them to JSON Lines format.

## Features

- **Multiple Protocol Support**: Decode BGP, BMP, NetFlow/IPFIX, and UDP-Notif protocols
- **PCAP Processing**: Read packets from PCAP files with configurable filtering
- **JSON Lines Output**: Structured JSON output
- **Dual Interface**: Use as both a library and command-line tool
- **Port Filtering**: Filter packets by destination ports
- **Flexible Output**: Write to file or stdout

## Installation

### As a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
netgauze-pcap-decoder = "0.7.0"
```

### As a CLI Tool

```bash
cargo install netgauze-pcap-decoder
```

Or build from source:

```bash
git clone https://github.com/NetGauze/NetGauze.git
cd NetGauze/crates/pcap-decoder
cargo build --release
```

## CLI Usage

```bash
netgauze-pcap-decoder --input <PCAP_FILE> --protocol <PROTOCOL> --ports <PORTS> [OPTIONS]
```

### Arguments

- `--input <INPUT>` - Input PCAP file path
- `--protocol <PROTOCOL>` - Protocol to decode: `bgp`, `bmp`, `flow`, or `udp-notif`
- `--ports <PORTS>` - Destination ports to filter (comma-separated, e.g., `179,180`)

### Options

- `--output <OUTPUT>` - Output JSON Lines file path (defaults to stdout)
- `--input-count <COUNT>` - Maximum number of packets to process
- `--help` - Show help information

### Examples

**Decode BGP packets from a PCAP file:**
```bash
netgauze-pcap-decoder --input bgp_capture.pcap --protocol bgp --ports 179
```

**Decode BMP packets and save to file:**
```bash
netgauze-pcap-decoder --input bmp_capture.pcap --protocol bmp --ports 11019 --output bmp_messages.jsonl
```

**Decode NetFlow packets with packet limit:**
```bash
netgauze-pcap-decoder --input netflow_capture.pcap --protocol flow --ports 9995,2055 --input-count 1000
```

**Decode UDP-Notif packets from multiple ports:**
```bash
netgauze-pcap-decoder --input udp_notif_capture.pcap --protocol udp-notif --ports 9991,9992,9993
```

## Library Usage

The library provides a simple API for programmatic PCAP processing:

### Basic Example

```rust
use netgauze_pcap_decoder::{
    Config, BgpProtocolHandler, load_pcap_and_process
};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the decoder
    let config = Config {
        pcap_path: PathBuf::from("input.pcap"),
        dest_ports: vec![179], // BGP port
        output_path: Some(PathBuf::from("output.jsonl")),
        input_size: None, // Process all packets
    };

    // Create a BGP protocol handler
    let handler = BgpProtocolHandler::new(config.dest_ports.clone());

    // Process the PCAP file
    load_pcap_and_process(&config, &handler)?;

    Ok(())
}
```

### Protocol Handlers

The library provides handlers for different protocols:

```rust
use netgauze_pcap_decoder::{
    BgpProtocolHandler,
    BmpProtocolHandler,
    FlowProtocolHandler,
    UdpNotifProtocolHandler,
};

// BGP Handler
let bgp_handler = BgpProtocolHandler::new(vec![179]);

// BMP Handler
let bmp_handler = BmpProtocolHandler::new(vec![1790]);

// NetFlow/IPFIX Handler
let flow_handler = FlowProtocolHandler::new(vec![9991, 9992]);

// UDP-Notif Handler
let udp_notif_handler = UdpNotifProtocolHandler::new(vec![9991, 9992]);
```

## Output Format

The tool outputs JSON Lines format where each line contains a decoded message:

```jsonl
{"source_address":"192.168.1.1:179","destination_address":"192.168.1.2:179","info":{"Open":{"version":4,"asn":65001,"hold_time":180,"bgp_id":[192,168,1,1],"optional_parameters":[]}}}
{"source_address":"192.168.1.2:179","destination_address":"192.168.1.1:179","info":{"Open":{"version":4,"asn":65002,"hold_time":180,"bgp_id":[192,168,1,2],"optional_parameters":[]}}}
```
