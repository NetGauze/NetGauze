// Copyright (C) 2022-present The NetGauze Authors.
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

//! Microbenchmarks for UDP-Notif wire protocol encode/decode performance.
//!
//! Everything is driven through the public [`UdpPacketCodec`] (tokio's
//! `Decoder`/`Encoder`), which is the stable API for the YANG-Push receiver.
//!
//! Two flavors:
//!
//! 1. **Pcap-derived exemplars** UDP-Notif  datagram from each bundled pcap
//!    (different vendors and media types:  yang-data+json, yang-data+cbor),
//!    benched for single-message decode and encode.
//! 2. **Streaming**: every UDP-Notif datagram of a pcap fed through one shared
//!    codec (so message reassembly state is exercised), matching a receiver's
//!    real workload.

use bytes::BytesMut;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use netgauze_pcap_reader::{PcapIter, TransportProtocol};
use netgauze_udp_notif_pkt::codec::UdpPacketCodec;
use netgauze_udp_notif_pkt::raw::UdpNotifPacket;
use pcap_parser::LegacyPcapReader;
use std::hint::black_box;
use std::io::Cursor;
use tokio_util::codec::{Decoder, Encoder};

// -------------------------------------------------------------------------
// Pcap fixtures embedded at compile time
// -------------------------------------------------------------------------

const PCAP_6WIND_JSON: &[u8] = include_bytes!(
    "../../../assets/pcaps/udp-notif/ietf-122/6wind-vsr-yang-push-20250304-0811-receiver-json.pcap"
);
const PCAP_6WIND_CBOR: &[u8] = include_bytes!(
    "../../../assets/pcaps/udp-notif/ietf-122/6wind-vsr-yang-push-20250305-1133-receiver-cbor.pcap"
);
const PCAP_HUAWEI_NE8000: &[u8] = include_bytes!(
    "../../../assets/pcaps/udp-notif/ietf-122/huawei-NE8000-yang-push-20250315-1025-receiver.pcap"
);
const PCAP_N7_SA1: &[u8] =
    include_bytes!("../../../assets/pcaps/udp-notif/ietf-121/n7-sa1_yang-push.pcap");
const PCAP_PMACCT_HUAWEI: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/800-YANG-telemetry-HUAWEI-udp-notif/traffic-00.pcap"
);

/// UDP-Notif destination ports observed across the bundled pcaps (the rest
/// is syslog/snmp noise). Mirrors the filter used by the crate's pcap tests.
const UDP_NOTIF_PORTS: &[u16] = &[10003, 10100, 57499];

/// An example `application/yang-data+xml` YANG-Push notification payload.
/// None of the bundled pcaps carry the XML media type, so this synthetic
/// exemplar keeps the XML decode/encode path covered by the benchmark.
const XML_PAYLOAD: &[u8] = concat!(
    r#"<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">"#,
    r#"<eventTime>2025-03-15T10:25:00.0Z</eventTime>"#,
    r#"<push-update xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">"#,
    r#"<id>1</id><datastore-contents>"#,
    r#"<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">"#,
    r#"<interface><name>GigabitEthernet0/0/0</name><oper-status>up</oper-status>"#,
    r#"<statistics><in-octets>184467440737</in-octets><out-octets>92233720368</out-octets></statistics>"#,
    r#"</interface></interfaces></datastore-contents></push-update></notification>"#,
)
.as_bytes();

/// Build a version-1, no-options UDP-Notif datagram carrying `payload` with
/// the given media type nibble (2 = yang-data+xml). Header layout:
/// `[ver<<5|media (1)][header_len (1)][message_length (2)][publisher_id (4)]
///  [message_id (4)][payload...]`.
fn build_udp_notif(media_type: u8, publisher_id: u32, message_id: u32, payload: &[u8]) -> Vec<u8> {
    const HEADER_LEN: u8 = 12; // no options
    let message_length = HEADER_LEN as usize + payload.len();
    let mut out = Vec::with_capacity(message_length);
    out.push((1 << 5) | (media_type & 0x0f)); // version 1, S=0
    out.push(HEADER_LEN);
    out.extend_from_slice(&(message_length as u16).to_be_bytes());
    out.extend_from_slice(&publisher_id.to_be_bytes());
    out.extend_from_slice(&message_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// -------------------------------------------------------------------------
// Pcap helpers
// -------------------------------------------------------------------------

/// Extract every UDP-Notif datagram payload (one entry per UDP packet on a
/// UDP-Notif port), preserving on-wire order.
fn udp_notif_datagrams(pcap_bytes: &'static [u8]) -> Vec<Vec<u8>> {
    let reader = LegacyPcapReader::new(165_536, Cursor::new(pcap_bytes))
        .expect("couldn't create pcap reader");
    let iter = PcapIter::new(Box::new(reader));
    let mut out = Vec::new();
    for (_src_ip, src_port, _dst_ip, dst_port, protocol, value) in iter {
        if protocol != TransportProtocol::UDP
            || !UDP_NOTIF_PORTS.contains(&dst_port)
            || src_port == 161
        {
            continue;
        }
        out.push(value);
    }
    out
}

/// The first datagram of `datagrams` that decodes cleanly to a single
/// (unsegmented) UDP-Notif packet, returned as `(wire_bytes, packet)`.
fn first_decodable(datagrams: &[Vec<u8>]) -> Option<(Vec<u8>, UdpNotifPacket)> {
    for dg in datagrams {
        let mut codec = UdpPacketCodec::default();
        let mut buf = BytesMut::from(&dg[..]);
        if let Ok(Some(pkt)) = codec.decode(&mut buf) {
            return Some((dg.clone(), pkt));
        }
    }
    None
}

// -------------------------------------------------------------------------
// Per-message decode / encode benches
// -------------------------------------------------------------------------

/// Register a decode + encode bench pair for a single exemplar datagram.
///
/// A one-time decode → encode → decode round-trip check runs at
/// registration so a broken fixture fails fast instead of producing
/// misleading throughput numbers. (The wire bytes are not byte-compared
/// directly: some vendors emit option/padding layouts the encoder
/// normalizes, but the decoded packet must be stable across a round trip.)
fn bench_exemplar(c: &mut Criterion, name: &str, wire: &[u8], pkt: &UdpNotifPacket) {
    // round-trip sanity check
    {
        let mut enc = BytesMut::with_capacity(wire.len());
        let mut codec = UdpPacketCodec::default();
        codec
            .encode(pkt.clone(), &mut enc)
            .expect("re-encode failed");
        let mut codec2 = UdpPacketCodec::default();
        let reparsed = codec2
            .decode(&mut enc)
            .expect("re-decode failed")
            .expect("re-decode produced no message");
        assert_eq!(&reparsed, pkt, "round-trip mismatch for '{name}'");
    }

    let decode_name = format!("decode {name}");
    let wire_owned = wire.to_vec();
    c.bench_function(&decode_name, |b| {
        let mut codec = UdpPacketCodec::default();
        b.iter_batched_ref(
            || BytesMut::from(&wire_owned[..]),
            |buf| {
                let msg = codec.decode(buf).expect("decode failed");
                black_box(msg);
            },
            BatchSize::SmallInput,
        )
    });

    let encode_name = format!("encode {name}");
    c.bench_function(&encode_name, |b| {
        let mut codec = UdpPacketCodec::default();
        let mut dst = BytesMut::with_capacity(wire.len());
        b.iter(|| {
            dst.clear();
            // `encode` consumes the packet; the clone is cheap — options are
            // normally empty and the payload is a CoW `Bytes` handle.
            codec
                .encode(black_box(pkt).clone(), &mut dst)
                .expect("encode failed");
            black_box(&dst);
        })
    });
}

fn bench_pcap_exemplar(c: &mut Criterion, name: &str, pcap_bytes: &'static [u8]) {
    let datagrams = udp_notif_datagrams(pcap_bytes);
    match first_decodable(&datagrams) {
        Some((wire, pkt)) => bench_exemplar(c, name, &wire, &pkt),
        None => eprintln!("exemplar '{name}': no decodable UDP-Notif datagram found, skipping"),
    }
}

// -------------------------------------------------------------------------
// Streaming benchmark — full pcap through UdpPacketCodec
// -------------------------------------------------------------------------

/// Feed every datagram of a pcap through a single shared codec (so
/// multi-segment reassembly state is exercised), counting decoded
/// messages. Errors are skipped, matching a receiver that keeps going past
/// a malformed datagram.
fn drive_stream(datagrams: &[Vec<u8>]) -> usize {
    let mut codec = UdpPacketCodec::default();
    let mut total = 0usize;
    for dg in datagrams {
        let mut buf = BytesMut::from(&dg[..]);
        match codec.decode(&mut buf) {
            Ok(Some(msg)) => {
                total += 1;
                black_box(msg);
            }
            Ok(None) => {} // fragment buffered for reassembly
            Err(_) => {}
        }
    }
    total
}

fn bench_pcap_stream(c: &mut Criterion, name: &str, pcap_bytes: &'static [u8]) {
    let datagrams = udp_notif_datagrams(pcap_bytes);
    let total_bytes: u64 = datagrams.iter().map(|d| d.len() as u64).sum();
    let total_msgs = drive_stream(&datagrams);
    assert!(
        total_msgs > 0,
        "stream bench '{name}' decoded 0 messages — wrong pcap or port filter?",
    );
    eprintln!(
        "stream/{name}: datagrams={} bytes={} msgs={}",
        datagrams.len(),
        total_bytes,
        total_msgs,
    );

    let mut group = c.benchmark_group("stream");
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function(format!("{name} bytes"), |b| {
        b.iter(|| black_box(drive_stream(&datagrams)));
    });
    group.throughput(Throughput::Elements(total_msgs as u64));
    group.bench_function(format!("{name} msgs"), |b| {
        b.iter(|| black_box(drive_stream(&datagrams)));
    });
    group.finish();
}

fn exemplar_benches(c: &mut Criterion) {
    bench_pcap_exemplar(c, "6wind json (pcap)", PCAP_6WIND_JSON);
    bench_pcap_exemplar(c, "6wind cbor (pcap)", PCAP_6WIND_CBOR);
    bench_pcap_exemplar(c, "huawei ne8000 (pcap)", PCAP_HUAWEI_NE8000);
    bench_pcap_exemplar(c, "n7-sa1 (pcap)", PCAP_N7_SA1);
    bench_pcap_exemplar(c, "pmacct huawei (pcap)", PCAP_PMACCT_HUAWEI);

    // Synthetic yang-data+xml exemplar (media type not present in any pcap).
    let xml_wire = build_udp_notif(2, 1, 100, XML_PAYLOAD);
    let mut codec = UdpPacketCodec::default();
    let pkt = codec
        .decode(&mut BytesMut::from(&xml_wire[..]))
        .expect("synthetic XML datagram failed to decode")
        .expect("synthetic XML datagram produced no message");
    bench_exemplar(c, "yang-data+xml (synthetic)", &xml_wire, &pkt);
}

fn stream_benches(c: &mut Criterion) {
    bench_pcap_stream(c, "6wind-json", PCAP_6WIND_JSON);
    bench_pcap_stream(c, "6wind-cbor", PCAP_6WIND_CBOR);
    bench_pcap_stream(c, "huawei-ne8000", PCAP_HUAWEI_NE8000);
    bench_pcap_stream(c, "n7-sa1", PCAP_N7_SA1);
    bench_pcap_stream(c, "pmacct-huawei", PCAP_PMACCT_HUAWEI);
}

criterion_group!(benches, exemplar_benches, stream_benches);
criterion_main!(benches);
