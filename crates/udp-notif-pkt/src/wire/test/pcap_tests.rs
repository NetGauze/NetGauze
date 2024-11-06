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

use crate::{codec::UdpPacketCodec, MediaType};
use bytes::{Buf, BytesMut};
use netgauze_pcap_reader::{PcapIter, TransportProtocol};
use pcap_parser::LegacyPcapReader;
use rstest::*;
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};
use tokio_util::codec::Decoder;

#[rstest]
fn test_pmacct_udp_notif(#[files("../../assets/pcaps/pmacct-tests/*/*.pcap")] path: PathBuf) {
    let overwrite = std::env::var("OVERWRITE")
        .to_owned()
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    test_udp_notif_pcap(overwrite, path);
}

#[rstest]
fn test_pcap_udp_notif(#[files("../../assets/pcaps/udp-notif/*/*.pcap")] path: PathBuf) {
    let overwrite = std::env::var("OVERWRITE")
        .to_owned()
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    test_udp_notif_pcap(overwrite, path);
}

// Rust is not smart enough to detect this method is used in rstest
#[allow(dead_code)]
fn test_udp_notif_pcap(overwrite: bool, pcap_path: PathBuf) {
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
        "{}-udp-notif.json",
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
        // The filter for 161 is included because n7-sa1_yang-push.pcap have some snmp
        // traffic
        if protocol != TransportProtocol::UDP
            || ![10003, 57499].contains(&dst_port)
            || src_port == 161
        {
            continue;
        }
        let key = (src_ip, src_port, dst_ip, dst_port);
        let (codec, buf) = peers
            .entry(key)
            .or_insert((UdpPacketCodec::default(), BytesMut::new()));
        buf.extend_from_slice(&value);
        while buf.has_remaining() {
            let serialized = match codec.decode(buf) {
                Ok(Some(msg)) => {
                    let mut value = serde_json::to_value(&msg)
                        .expect("Couldn't serialize UDP-Notif message to json");
                    // Convert when possible inner payload into human-readable format
                    match msg.header.media_type {
                        MediaType::YangDataJson => {
                            let payload = serde_json::from_slice(msg.payload())
                                .expect("Couldn't deserialize JSON payload into a JSON object");
                            if let Value::Object(ref mut val) = &mut value {
                                val.insert("payload".to_string(), payload);
                            }
                        }
                        MediaType::YangDataXml => {
                            let payload = std::str::from_utf8(msg.payload())
                                .expect("Couldn't deserialize XML payload into an UTF-8 string");
                            if let Value::Object(ref mut val) = &mut value {
                                val.insert(
                                    "payload".to_string(),
                                    Value::String(payload.to_string()),
                                );
                            }
                        }
                        _ => {}
                    }
                    serde_json::to_string(&value).unwrap()
                }
                Ok(None) => {
                    // packet is fragmented, need to read the next PDU first before attempting to
                    // deserialize it
                    break;
                }
                Err(err) => serde_json::to_string(&err)
                    .expect("Couldn't serialize UDP-Notif error message to json"),
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
