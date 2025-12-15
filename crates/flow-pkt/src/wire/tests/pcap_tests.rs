// Copyright (C) 2024-present The NetGauze Authors.
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

use crate::codec::FlowInfoCodec;
use bytes::{Buf, BytesMut};
use netgauze_pcap_reader::{PcapIter, TransportProtocol};
use pcap_parser::LegacyPcapReader;
use rstest::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use tokio_util::codec::Decoder;

#[rstest]
fn test_pmacct_flow(#[files("../../assets/pcaps/pmacct-tests/*/*.pcap")] path: PathBuf) {
    let overwrite = std::env::var("OVERWRITE")
        .to_owned()
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    test_flow_pcap(overwrite, path);
}

#[rstest]
fn test_pcap_flow(#[files("../../assets/pcaps/flow/*/*.pcap")] path: PathBuf) {
    let overwrite = std::env::var("OVERWRITE")
        .to_owned()
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    test_flow_pcap(overwrite, path);
}

// Rust is not smart enough to detect this method is used in rstest
#[allow(dead_code)]
fn test_flow_pcap(overwrite: bool, pcap_path: PathBuf) {
    let err_msg = format!("Couldn't extract parent directory name from path: {pcap_path:?}");
    let parent = pcap_path.parent().expect(&err_msg);
    let err_msg = format!("Couldn't extract filename from path: {pcap_path:?}");
    let filename = pcap_path
        .file_name()
        .expect(&err_msg)
        .to_str()
        .expect("Couldn't convert filename to string");
    let mut json_path = PathBuf::from(parent);
    json_path.push(format!(
        "{}-flow.json",
        filename.split(".pcap").next().unwrap()
    ));
    let pcap_file = File::open(pcap_path.as_path()).unwrap();
    let (mut json_file, mut lines) = if overwrite {
        let err_msg = format!("Couldn't create json file: {json_path:?}.\nDetailed Error");
        (Some(File::create(json_path.clone()).expect(&err_msg)), None)
    } else {
        let err_msg = format!(
            "Couldn't open json file: {json_path:?} for pcap trace: {:?}.\
            \nTry running with `OVERWRITE=true` to create new output.\
            \nDetailed Error",
            pcap_path.as_path(),
        );
        let reader = BufReader::new(File::open(json_path.clone()).expect(&err_msg));
        let lines = reader.lines();
        (None, Some(lines))
    };
    let pcap_reader = Box::new(LegacyPcapReader::new(165536, pcap_file).unwrap());
    let iter = PcapIter::new(pcap_reader);
    let mut peers = HashMap::new();
    for (src_ip, src_port, dst_ip, dst_port, protocol, value) in iter {
        if protocol != TransportProtocol::UDP
            || !(dst_port == 9991 || dst_port == 9992 || dst_port == 10088)
        {
            continue;
        }
        let key = (src_ip, src_port, dst_ip, dst_port);
        let (codec, buf) = peers
            .entry(key)
            .or_insert((FlowInfoCodec::default(), BytesMut::new()));
        buf.extend_from_slice(&value);
        while buf.has_remaining() {
            let serialized = match codec.decode(buf) {
                Ok(Some(msg)) => {
                    serde_json::to_string(&msg).expect("Couldn't serialize Flow message to json")
                }
                Ok(None) => {
                    // packet is fragmented, need to read the next PDU first before attempting to
                    // deserialize it
                    break;
                }
                Err(err) => serde_json::to_string(&err)
                    .expect("Couldn't serialize Flow error message to json"),
            };
            if let Some(file) = json_file.as_mut() {
                file.write_all(serialized.as_bytes())
                    .expect("Couldn't write json message");
                file.write_all(b"\n").expect("Couldn't write json message");
            }
            if let Some(lines) = lines.as_mut() {
                let err_msg = format!(
                    "PCAP PDU is not found in expected output file.\
                    \nPCAP PDU {serialized}.\
                    \nExpected output file: {json_path:?}",
                );
                let expected = lines.next().expect(&err_msg).expect("Error reading");
                assert_eq!(expected, serialized);
            }
        }
    }
}
