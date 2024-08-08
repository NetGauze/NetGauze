# PCAP and PCAPNG helper library

Helper Reading pcap and pcap files for testing only
See [parse](examples/parse.rs) for a simple code to parse BMP packets from a pcapng file.

## Run example

```rust
use std::{collections::HashMap, fs::File};

use bytes::BytesMut;
use netgauze_bmp_pkt::codec::BmpCodec;
use netgauze_pcap_reader::{PcapIter, TransportProtocol};
use pcap_parser::PcapNGReader;
use tokio_util::codec::Decoder;

fn main() {
    let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
    path.push_str("/data/bmp.pcapng");
    let file = File::open(path).unwrap();
    let reader = PcapNGReader::new(165536, file).unwrap();
    let reader = Box::new(reader);
    let iter = PcapIter::new(reader);
    let mut peers = HashMap::new();
    for (src_ip, src_port, dst_ip, dst_port, protocol, value) in iter {
        if protocol != TransportProtocol::TCP {
            continue;
        }
        let key = (src_ip, src_port, dst_ip, dst_port);
        let (codec, buf) = peers
            .entry(key)
            .or_insert((BmpCodec::default(), BytesMut::new()));
        buf.extend_from_slice(value.as_slice());
        match codec.decode(buf) {
            Ok(Some(msg)) => println!("{}", serde_json::to_string(&msg).unwrap()),
            Ok(None) => {}
            Err(err) => println!("Error parsing BMP Message: {:?}", err),
        }
    }
}
```
