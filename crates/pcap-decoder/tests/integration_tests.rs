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

use std::process::Command;
use std::{env, fs};
use tempfile::NamedTempFile;

fn run_pcap_decoder_test(
    protocol: &str,
    ports: &str,
    pcap_path: &str,
    expected_json_path: &str,
    input_count: Option<usize>,
) {
    let overwrite = env::var("OVERWRITE").unwrap_or_else(|_| "false".to_string()) == "true";

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netgauze-pcap-decoder"));
    cmd.arg("--input")
        .arg(pcap_path)
        .arg("--protocol")
        .arg(protocol)
        .arg("--ports")
        .arg(ports);

    if let Some(count) = input_count {
        cmd.arg("--input-count").arg(count.to_string());
    }

    if overwrite {
        cmd.arg("--output").arg(expected_json_path);
        let status = cmd
            .status()
            .unwrap_or_else(|e| panic!("Failed to execute command: {e}"));
        assert!(
            status.success(),
            "pcap-decoder command failed with status: {status}",
        );
    } else {
        let output_file = NamedTempFile::new().unwrap();
        let output_path = output_file.path().to_str().unwrap();
        cmd.arg("--output").arg(output_path);

        let status = cmd
            .status()
            .unwrap_or_else(|e| panic!("Failed to execute command: {e}"));

        assert!(
            status.success(),
            "pcap-decoder command failed with status: {status}",
        );

        let output_json = fs::read_to_string(output_path)
            .unwrap_or_else(|e| panic!("Failed to read output file: {e}"));
        let expected_json = fs::read_to_string(expected_json_path)
            .unwrap_or_else(|e| panic!("Failed to read expected JSON file: {e}"));

        // Normalize line endings and compare
        let output_json_normalized = output_json.replace("\r\n", "\n");
        let expected_json_normalized = expected_json.replace("\r\n", "\n");

        assert_eq!(output_json_normalized, expected_json_normalized);
    }
}

#[test]
fn test_bgp_pcap_to_json() {
    run_pcap_decoder_test(
        "bgp",
        "179",
        "tests/data/502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms.pcap",
        "tests/data/502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms-bgp.jsonl",
        None,
    );
}

#[test]
fn test_bmp_pcap_to_json() {
    run_pcap_decoder_test(
        "bmp",
        "1790",
        "tests/data/203-BMP-HUAWEI-dump.pcap",
        "tests/data/203-BMP-HUAWEI-dump-bmp.jsonl",
        None,
    );
}

#[test]
fn test_flow_pcap_to_json() {
    run_pcap_decoder_test(
        "flow",
        "9991",
        "tests/data/502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms.pcap",
        "tests/data/502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms-flow.jsonl",
        None,
    );
}

#[test]
fn test_udp_notif_to_json() {
    run_pcap_decoder_test(
        "udp-notif",
        "10003",
        "tests/data/800-YANG-telemetry-HUAWEI-udp-notif.pcap",
        "tests/data/800-YANG-telemetry-HUAWEI-udp-notif.jsonl",
        None,
    );
}

#[test]
fn test_input_count_option() {
    run_pcap_decoder_test(
        "bgp",
        "179",
        "tests/data/502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms.pcap",
        "tests/data/502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms-bgp-10-packets.jsonl",
        Some(10),
    );
}
