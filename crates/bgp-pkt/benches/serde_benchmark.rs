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

//! Microbenchmarks for BGP wire protocol encode/decode performance.
//!
//! Three flavors:
//!
//! 1. **Legacy synthetic fixtures** — the original hand-built OPEN and UPDATE
//!    wires kept here so historical bench comparisons keep working. Bench names
//!    ("open no params", "open complex", "Update MPLS", "Update SRV6") are
//!    preserved.
//! 2. **Pcap-derived exemplars** — first messages of distinct categories pulled
//!    from `assets/pcaps/bgp/*` and selected pmacct-tests pcaps. Covers
//!    real-vendor encodings of OPEN with rich capabilities, plain IPv6 UNICAST
//!    UPDATE, IPv4/IPv6 MPLS-VPN UPDATE, SRv6 service-TLV UPDATE and extended
//!    next-hop UPDATE. The decode bench restores the [`BgpParsingContext`] to
//!    the state observed just before each message (asn4 + add-path +
//!    multi-label capabilities tracked across the flow) so capability-dependent
//!    decoding is faithful.
//! 3. **Whole-pcap streaming benches** — feed each pcap through a fresh
//!    [`BgpCodec`] end-to-end and report both bytes/s and msgs/s, matching the
//!    workload of a BGP speaker / collector on the wire.
//!
//! Synthetic bench names are unchanged; new ones use a `"(pcap)"` suffix
//! and the streaming ones live under the `stream/` group.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::capabilities::BgpCapability;
use netgauze_bgp_pkt::codec::BgpCodec;
use netgauze_bgp_pkt::iana::BgpMessageType;
use netgauze_bgp_pkt::path_attribute::PathAttributeValue;
use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePdu};
use netgauze_pcap_reader::{PcapIter, TransportProtocol};
use pcap_parser::LegacyPcapReader;
use std::collections::HashMap;
use std::hint::black_box;
use std::io::Cursor;
use tokio_util::codec::Decoder;

// -------------------------------------------------------------------------
// Legacy synthetic fixtures (kept for historical comparison)
// -------------------------------------------------------------------------

const OPEN_COMPLEX_NO_PARAMS: [u8; 29] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x1d, 0x01, 0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, 0x00,
];

const OPEN_COMPLEX_RAW: [u8; 123] = [
    // BGP Marker
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Message Length
    0x00, 0x7b, // Message type
    0x01, // Version
    0x04, // My As number
    0x00, 0x64, // Hold Time
    0x00, 0xb4, // BGP ID
    0x0a, 0x12, 0xa0, 0x7a, // Opt Param Len
    0x5e, // First and only parameter
    0x02, // Param length
    0x5c, // Capability: Support for 4-octet AS number
    0x41, // Capability 1: length
    0x04, // Capability 1: As number
    0x00, 0x00, 0x00, 0x64, // Capability 2: BGP Extended Message
    0x06, 0x00, // Capability 3: Route Refresh
    0x02, 0x00, // Capability 4: add path
    0x45, // Capability4 : length
    0x08, // Capability 4: AFI Ipv4
    0x00, 0x01, // Capability 4: SAFI Unicast
    0x01, // Send/Receive
    0x03, // Capability 4: Afi IPv6
    0x00, 0x02, // Capability 4: unicast
    0x01, // Capability 4: send receive
    0x03, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x01, 0x04, 0x40,
    0x04, 0x00, 0x47, 0x01, 0x04, 0x00, 0x01, 0x00, 0x85, 0x01, 0x04, 0x00, 0x02, 0x00, 0x85, 0x01,
    0x04, 0x00, 0x01, 0x00, 0x86, 0x01, 0x04, 0x00, 0x02, 0x00, 0x86, 0x01, 0x04, 0x00, 0x01, 0x00,
    0x04, 0x01, 0x04, 0x00, 0x02, 0x00, 0x04, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80, 0x01, 0x04, 0x00,
    0x02, 0x00, 0x80, 0x01, 0x04, 0x00, 0x19, 0x00, 0x46,
];

#[rustfmt::skip]
const OPEN_FOR_UPDATE_SRV6: [u8; 97] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x61, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
    0xcb, 0x00, 0x71, 0x5a, 0x44, 0x02, 0x06, 0x01,
    0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x06, 0x01,
    0x04, 0x00, 0x02, 0x00, 0x80, 0x02, 0x02, 0x80,
    0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41,
    0x04, 0xfb, 0xf0, 0x00, 0x5a, 0x02, 0x0c, 0x40,
    0x0a, 0x00, 0x78, 0x00, 0x01, 0x80, 0x00, 0x00,
    0x02, 0x80, 0x00, 0x02, 0x14, 0x05, 0x12, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00,
    0x02
];

#[rustfmt::skip]
const UPDATE_SRV6: [u8; 222] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0xde, 0x02, 0x00, 0x00, 0x00, 0xc7, 0x90,
    0x0e, 0x00, 0x39, 0x00, 0x02, 0x80, 0x18, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    0x01, 0x0d, 0xb8, 0x00, 0x91, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xd8, 0xe0, 0x03, 0x01, 0x00, 0x02, 0xfb, 0xf0,
    0x00, 0x5b, 0x00, 0x0d, 0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x13, 0x40, 0x01, 0x01, 0x00,
    0x40, 0x02, 0x12, 0x02, 0x04, 0xfb, 0xf0, 0x00,
    0x5a, 0x00, 0x00, 0xfb, 0xf0, 0xfb, 0xf0, 0x00,
    0x5b, 0x00, 0x00, 0xfd, 0xe8, 0xc0, 0x08, 0x14,
    0xfb, 0xf0, 0x01, 0x2b, 0xfb, 0xf0, 0x03, 0xe9,
    0xfb, 0xf0, 0x04, 0x09, 0xfb, 0xf1, 0x00, 0x01,
    0xfb, 0xf3, 0x00, 0x0d, 0xc0, 0x20, 0x24, 0x00,
    0x00, 0xfb, 0xf0, 0x00, 0x00, 0x01, 0x39, 0x00,
    0x00, 0x01, 0x39, 0x00, 0x00, 0xfb, 0xf0, 0x00,
    0x00, 0x01, 0xc8, 0x00, 0x00, 0x02, 0x8e, 0x00,
    0x00, 0xfb, 0xf0, 0x00, 0x00, 0x04, 0x09, 0x00,
    0x00, 0x00, 0x5b, 0xc0, 0x10, 0x08, 0x00, 0x02,
    0xfb, 0xf1, 0x00, 0x00, 0x00, 0x01, 0xc0, 0x28,
    0x25, 0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e,
    0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x91, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x06,
    0x20, 0x10, 0x10, 0x00, 0x10, 0x30
];

#[rustfmt::skip]
const OPEN_FOR_UPDATE_MPLS: [u8; 97] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x61, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4,
    0xcb, 0x00, 0x71, 0x5a, 0x44, 0x02, 0x06, 0x01,
    0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x06, 0x01,
    0x04, 0x00, 0x02, 0x00, 0x80, 0x02, 0x02, 0x80,
    0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41,
    0x04, 0xfb, 0xf0, 0x00, 0x5a, 0x02, 0x0c, 0x40,
    0x0a, 0x00, 0x78, 0x00, 0x01, 0x80, 0x00, 0x00,
    0x02, 0x80, 0x00, 0x02, 0x14, 0x05, 0x12, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00,
    0x02
];

#[rustfmt::skip]
const UPDATE_MPLS: [u8; 143] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x8f, 0x02, 0x00, 0x00, 0x00, 0x78, 0x90,
    0x0e, 0x00, 0x39, 0x00, 0x02, 0x80, 0x18, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcb,
    0x00, 0x71, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xd8, 0x10, 0x05, 0x41, 0x00, 0x02, 0xfb, 0xf0,
    0x00, 0x18, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x16, 0x40, 0x01, 0x01, 0x00,
    0x40, 0x02, 0x12, 0x02, 0x04, 0xfb, 0xf0, 0x00,
    0x5a, 0x00, 0x00, 0xfb, 0xf0, 0xfb, 0xf0, 0x00,
    0x18, 0x00, 0x00, 0xfd, 0xe8, 0xc0, 0x08, 0x14,
    0xfb, 0xf0, 0x01, 0x2b, 0xfb, 0xf0, 0x03, 0xe9,
    0xfb, 0xf0, 0x04, 0x09, 0xfb, 0xf1, 0x00, 0x01,
    0xfb, 0xf3, 0x00, 0x10, 0xc0, 0x10, 0x08, 0x00,
    0x02, 0xfb, 0xf1, 0x00, 0x00, 0x00, 0x01,
];

// -------------------------------------------------------------------------
// Pcap fixtures embedded at compile time
// -------------------------------------------------------------------------

const PCAP_MULTI_SESSIONS: &[u8] =
    include_bytes!("../../../assets/pcaps/bgp/multiple-sessions/traffic.pcap");
const PCAP_EXT_NEXT_HOP: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/300-BGP-IPv6-CISCO-extNH_enc/traffic-00.pcap"
);
const PCAP_MPLS_VPN: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/501-IPFIXv10-BGP-IPv6-CISCO-MPLS/traffic-00.pcap"
);
const PCAP_SRV6_LCOMMS: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms/traffic-00.pcap"
);
const PCAP_STREAM_LARGE: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/305-BGP-mem-leak-test/bgp-multi-sources-update-keepalive.pcap"
);

/// BGP runs on TCP/179. Same filter used by
/// `crates/bgp-pkt/src/wire/tests/pcap_tests.rs`.
const BGP_PORT: u16 = 179;

// -------------------------------------------------------------------------
// Pcap walking & exemplar extraction
// -------------------------------------------------------------------------

/// A single message extracted from a pcap with the parsing context as it
/// stood immediately before this message was decoded. The decode bench
/// restores `ctx_before` on every iteration so capability-dependent
/// decoding (asn4, add-path, multi-label MPLS) is exercised faithfully.
struct Exemplar {
    name: String,
    wire: Vec<u8>,
    ctx_before: BgpParsingContext,
}

/// Reassemble each TCP flow in a pcap into a single byte buffer keyed by
/// the 4-tuple. Order within a flow is preserved (pcap order). Only flows
/// whose destination port is BGP/179 are kept — matching the existing
/// pcap test filter.
fn pcap_tcp_flows(pcap_bytes: &'static [u8]) -> Vec<Vec<u8>> {
    let reader = LegacyPcapReader::new(165_536, Cursor::new(pcap_bytes)).unwrap();
    let iter = PcapIter::new(Box::new(reader));
    let mut flows: HashMap<_, Vec<u8>> = HashMap::new();
    for (src_ip, src_port, dst_ip, dst_port, protocol, value) in iter {
        if protocol != TransportProtocol::TCP || dst_port != BGP_PORT {
            continue;
        }
        let key = (src_ip, src_port, dst_ip, dst_port);
        flows.entry(key).or_default().extend_from_slice(&value);
    }
    flows.into_values().collect()
}

/// Track capability negotiation on a [`BgpParsingContext`] using the
/// capabilities of an inbound OPEN. The codec's built-in handling only
/// covers `FourOctetAs`; ADD-PATH and Multiple-Labels need to be applied
/// to the parsing context explicitly so subsequent UPDATEs are framed
/// correctly.
fn apply_open_caps(ctx: &mut BgpParsingContext, msg: &BgpMessage) {
    let open = match msg {
        BgpMessage::Open(o) => o,
        _ => return,
    };
    let mut has_asn4 = false;
    for cap in open.capabilities() {
        if let BgpCapability::FourOctetAs(_) = cap {
            has_asn4 = true;
        }
        // adj_rib_out=false: pcaps captured at port 179 are the receive
        // side of the session, so we want the receive ADD-PATH semantics.
        ctx.update_capabilities(cap, false);
    }
    ctx.set_asn4(has_asn4);
}

/// Walk every BGP message in a reassembled flow, invoking `picker` once
/// per successfully decoded message. The running [`BgpParsingContext`]
/// is updated after each OPEN with the capabilities it carries so
/// later UPDATEs decode with the correct semantics.
fn pick_from_flow<F>(flow: &[u8], picker: &mut F) -> Vec<Exemplar>
where
    F: FnMut(&BgpMessage, usize) -> Option<String>,
{
    let mut out = Vec::new();
    // Mirror `BgpCodec::new(true)`: pre-asn4 capability negotiation we
    // optimistically assume both sides will speak it, and the codec
    // narrows it down once a real OPEN is seen.
    let mut ctx = BgpParsingContext::default();
    let mut pos = 0usize;
    let mut idx = 0usize;
    while pos + 19 <= flow.len() {
        // BGP header: 16-byte marker + 2-byte length (big-endian) +
        // 1-byte type. The length field covers the whole message.
        let length = u16::from_be_bytes(flow[pos + 16..pos + 18].try_into().unwrap()) as usize;
        if length < 19 || pos + length > flow.len() {
            break;
        }
        let wire = &flow[pos..pos + length];
        let ctx_before = ctx.clone();
        let mut working = ctx.clone();
        // Skip past unparseable messages: real-vendor pcaps occasionally
        // carry capability-gated routes we can't decode with default
        // context. The BGP length field still lets us advance to the
        // next frame.
        if let Ok((_, msg)) = BgpMessage::from_wire(Span::new(wire), &mut working) {
            if let Some(name) = picker(&msg, idx) {
                out.push(Exemplar {
                    name,
                    wire: wire.to_vec(),
                    ctx_before,
                });
            }
            apply_open_caps(&mut working, &msg);
            ctx = working;
            idx += 1;
        }
        pos += length;
    }
    out
}

/// Walk all flows in a pcap, applying `picker` to each decoded message.
fn pick_exemplars<F>(pcap_bytes: &'static [u8], mut picker: F) -> Vec<Exemplar>
where
    F: FnMut(&BgpMessage, usize) -> Option<String>,
{
    let mut out = Vec::new();
    for flow in pcap_tcp_flows(pcap_bytes) {
        out.extend(pick_from_flow(&flow, &mut picker));
    }
    out
}

// -------------------------------------------------------------------------
// Helpers for picking specific exemplars
// -------------------------------------------------------------------------

/// AFI/SAFI of the first MP-REACH on this UPDATE, if any.
fn update_mp_reach_address_type(msg: &BgpMessage) -> Option<AddressType> {
    let update = match msg {
        BgpMessage::Update(u) => u,
        _ => return None,
    };
    for attr in update.path_attributes() {
        if let PathAttributeValue::MpReach(mp) = attr.value() {
            return mp.address_type().ok();
        }
    }
    None
}

/// True if any path attribute on this UPDATE is a `PrefixSegmentIdentifier`
/// (BGP-SR / SRv6 service TLVs).
fn update_has_prefix_sid(msg: &BgpMessage) -> bool {
    let update = match msg {
        BgpMessage::Update(u) => u,
        _ => return false,
    };
    update
        .path_attributes()
        .iter()
        .any(|a| matches!(a.value(), PathAttributeValue::PrefixSegmentIdentifier(_)))
}

/// True if this UPDATE has at least one IPv4 unicast NLRI directly in the
/// update body (i.e. a "plain" Ipv4Unicast NLRI, not MP-REACH).
fn update_has_ipv4_unicast_nlri(msg: &BgpMessage) -> bool {
    matches!(msg, BgpMessage::Update(u) if !u.nlri().is_empty())
}

// -------------------------------------------------------------------------
// Bench plumbing
// -------------------------------------------------------------------------

#[inline(always)]
fn decode_with_ctx(buf: &[u8], ctx: &mut BgpParsingContext) -> BgpMessage {
    let (_, msg) = BgpMessage::from_wire(Span::new(buf), ctx).unwrap();
    msg
}

/// Register a decode + encode bench pair for a single exemplar with a
/// one-time round-trip correctness check at registration so a broken
/// fixture fails fast instead of producing misleading throughput numbers.
fn bench_exemplar(c: &mut Criterion, ex: &Exemplar) {
    let mut warmup_ctx = ex.ctx_before.clone();
    let msg = decode_with_ctx(&ex.wire, &mut warmup_ctx);
    let mut warmup_buf = Vec::with_capacity(msg.len());
    msg.write(&mut warmup_buf).unwrap();
    assert_eq!(
        warmup_buf.as_slice(),
        ex.wire.as_slice(),
        "round-trip mismatch for fixture '{}'",
        ex.name,
    );

    let decode_name = format!("decode {}", ex.name);
    let wire = ex.wire.clone();
    let ctx_template = ex.ctx_before.clone();
    c.bench_function(&decode_name, |b| {
        let mut ctx = ctx_template.clone();
        b.iter(|| {
            let msg = decode_with_ctx(black_box(&wire), &mut ctx);
            black_box(msg);
        })
    });

    let encode_name = format!("encode {}", ex.name);
    c.bench_function(&encode_name, |b| {
        let mut buf = Vec::with_capacity(msg.len());
        b.iter(|| {
            buf.clear();
            black_box(&msg).write(&mut buf).unwrap();
            black_box(&buf);
        })
    });
}

// -------------------------------------------------------------------------
// Streaming benchmark — full pcap through BgpCodec
// -------------------------------------------------------------------------

/// Number of BGP messages successfully decoded by feeding every TCP flow
/// in `flows` through a fresh [`BgpCodec`]. Used both to set the
/// throughput element count and to sanity-check the run.
fn drive_stream(flows: &[Vec<u8>]) -> usize {
    let mut total = 0usize;
    for flow in flows {
        // Mirror the BGP pcap-test setup: optimistic asn4=true to start,
        // narrowed by the codec once a real OPEN is observed.
        let mut codec = BgpCodec::new(true);
        let mut buf = BytesMut::with_capacity(flow.len());
        buf.extend_from_slice(flow);
        // Keep going past a decode error: BgpCodec advances past the
        // failed frame, so subsequent frames can still be processed.
        while !buf.is_empty() {
            match codec.decode(&mut buf) {
                Ok(Some(msg)) => {
                    total += 1;
                    black_box(msg);
                }
                Ok(None) => break, // need more bytes from a future packet
                Err(_) => {}
            }
        }
    }
    total
}

fn bench_pcap_stream(c: &mut Criterion, name: &str, pcap_bytes: &'static [u8]) {
    let flows = pcap_tcp_flows(pcap_bytes);
    let total_bytes: u64 = flows.iter().map(|f| f.len() as u64).sum();
    let total_msgs = drive_stream(&flows);
    assert!(
        total_msgs > 0,
        "stream bench '{name}' decoded 0 messages — wrong pcap or bad TCP port filter?",
    );
    eprintln!(
        "stream/{name}: flows={} bytes={} msgs={}",
        flows.len(),
        total_bytes,
        total_msgs,
    );

    let mut group = c.benchmark_group("stream");
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function(format!("{name} bytes"), |b| {
        b.iter(|| {
            let n = drive_stream(black_box(&flows));
            black_box(n);
        })
    });
    group.throughput(Throughput::Elements(total_msgs as u64));
    group.bench_function(format!("{name} msgs"), |b| {
        b.iter(|| {
            let n = drive_stream(black_box(&flows));
            black_box(n);
        })
    });
    group.finish();
}

// -------------------------------------------------------------------------
// Legacy synthetic benches
// -------------------------------------------------------------------------

pub fn legacy_synthetic_benches(c: &mut Criterion) {
    let mut ctx = BgpParsingContext::default();
    let no_params_span = Span::new(&OPEN_COMPLEX_NO_PARAMS);
    let complex_span = Span::new(&OPEN_COMPLEX_RAW);
    c.bench_function("open no params", |b| {
        b.iter(|| {
            let (_, msg) = BgpMessage::from_wire(no_params_span, &mut ctx).unwrap();
            black_box(msg);
        })
    });
    c.bench_function("open complex", |b| {
        b.iter(|| {
            let (_, msg) = BgpMessage::from_wire(complex_span, &mut ctx).unwrap();
            black_box(msg);
        })
    });

    // Setup the context to parse the Update BGP message with MPLS data.
    let mut ctx = BgpParsingContext::default();
    let open_mpls_span = Span::new(&OPEN_FOR_UPDATE_MPLS);
    let _ = BgpMessage::from_wire(open_mpls_span, &mut ctx).unwrap();
    let update_mpls_span = Span::new(&UPDATE_MPLS);
    c.bench_function("Update MPLS", |b| {
        b.iter(|| {
            let (_, msg) = BgpMessage::from_wire(update_mpls_span, &mut ctx).unwrap();
            black_box(msg);
        })
    });

    // Setup the context to parse the Update BGP message with SRv6 data.
    let mut ctx = BgpParsingContext::default();
    let open_srv6_span = Span::new(&OPEN_FOR_UPDATE_SRV6);
    let _ = BgpMessage::from_wire(open_srv6_span, &mut ctx).unwrap();
    let update_srv6_span = Span::new(&UPDATE_SRV6);
    c.bench_function("Update SRV6", |b| {
        b.iter(|| {
            let (_, msg) = BgpMessage::from_wire(update_srv6_span, &mut ctx).unwrap();
            black_box(msg);
        })
    });
}

// -------------------------------------------------------------------------
// Pcap-derived exemplar selection
// -------------------------------------------------------------------------

/// First OPEN and first plain-IPv4-Unicast UPDATE / IPv6 MP-REACH UPDATE
/// from the multi-session pcap. The OPEN here exercises a realistic
/// capability set from a live router.
fn exemplars_multi_sessions() -> Vec<Exemplar> {
    let mut got_open = false;
    let mut got_ipv4_unicast = false;
    let mut got_ipv6_unicast = false;
    pick_exemplars(PCAP_MULTI_SESSIONS, |msg, _| {
        if !got_open && msg.get_type() == BgpMessageType::Open {
            got_open = true;
            return Some("bgp open multi-session (pcap)".to_owned());
        }
        if !got_ipv4_unicast && update_has_ipv4_unicast_nlri(msg) {
            got_ipv4_unicast = true;
            return Some("bgp update ipv4 unicast (pcap)".to_owned());
        }
        if !got_ipv6_unicast
            && matches!(
                update_mp_reach_address_type(msg),
                Some(AddressType::Ipv6Unicast)
            )
        {
            got_ipv6_unicast = true;
            return Some("bgp update ipv6 unicast (pcap)".to_owned());
        }
        None
    })
}

/// First IPv4 / IPv6 MPLS-VPN UPDATE from the extended-next-hop pcap.
/// These carry IPv6 next-hops on IPv4 NLRI (per RFC 5549).
fn exemplars_ext_next_hop() -> Vec<Exemplar> {
    let mut want = vec![
        (
            AddressType::Ipv4MplsLabeledVpn,
            "bgp update ipv4 mpls vpn extnh (pcap)",
        ),
        (
            AddressType::Ipv6MplsLabeledVpn,
            "bgp update ipv6 mpls vpn extnh (pcap)",
        ),
    ];
    pick_exemplars(PCAP_EXT_NEXT_HOP, |msg, _| {
        let addr = update_mp_reach_address_type(msg)?;
        if let Some(pos) = want.iter().position(|(a, _)| *a == addr) {
            let (_, name) = want.remove(pos);
            return Some(name.to_owned());
        }
        None
    })
}

/// First IPv4 / IPv6 MPLS-VPN UPDATE from a plain-MPLS pcap (no SRv6).
fn exemplars_mpls_vpn() -> Vec<Exemplar> {
    let mut want = vec![
        (
            AddressType::Ipv4MplsLabeledVpn,
            "bgp update ipv4 mpls vpn (pcap)",
        ),
        (
            AddressType::Ipv6MplsLabeledVpn,
            "bgp update ipv6 mpls vpn (pcap)",
        ),
    ];
    pick_exemplars(PCAP_MPLS_VPN, |msg, _| {
        let addr = update_mp_reach_address_type(msg)?;
        if let Some(pos) = want.iter().position(|(a, _)| *a == addr) {
            let (_, name) = want.remove(pos);
            return Some(name.to_owned());
        }
        None
    })
}

/// First MPLS-VPN UPDATEs carrying SRv6 PrefixSegmentIdentifier path
/// attributes from the SRv6 pcap, both AFIs.
fn exemplars_srv6() -> Vec<Exemplar> {
    let mut got_v4 = false;
    let mut got_v6 = false;
    pick_exemplars(PCAP_SRV6_LCOMMS, |msg, _| {
        if !update_has_prefix_sid(msg) {
            return None;
        }
        match update_mp_reach_address_type(msg) {
            Some(AddressType::Ipv4MplsLabeledVpn) if !got_v4 => {
                got_v4 = true;
                Some("bgp update ipv4 mpls vpn srv6 (pcap)".to_owned())
            }
            Some(AddressType::Ipv6MplsLabeledVpn) if !got_v6 => {
                got_v6 = true;
                Some("bgp update ipv6 mpls vpn srv6 (pcap)".to_owned())
            }
            _ => None,
        }
    })
}

pub fn pcap_exemplar_benches(c: &mut Criterion) {
    let mut all = Vec::new();
    all.extend(exemplars_multi_sessions());
    all.extend(exemplars_ext_next_hop());
    all.extend(exemplars_mpls_vpn());
    all.extend(exemplars_srv6());

    // Surface missing exemplars loudly so a bad pcap or parser regression
    // doesn't silently shrink the bench suite.
    let expected = [
        "bgp open multi-session (pcap)",
        "bgp update ipv4 unicast (pcap)",
        "bgp update ipv6 unicast (pcap)",
        "bgp update ipv4 mpls vpn extnh (pcap)",
        "bgp update ipv6 mpls vpn extnh (pcap)",
        "bgp update ipv4 mpls vpn (pcap)",
        "bgp update ipv6 mpls vpn (pcap)",
        "bgp update ipv4 mpls vpn srv6 (pcap)",
        "bgp update ipv6 mpls vpn srv6 (pcap)",
    ];
    for name in expected {
        assert!(
            all.iter().any(|e| e.name == name),
            "missing pcap-derived exemplar '{name}'",
        );
    }

    for ex in &all {
        bench_exemplar(c, ex);
    }
}

pub fn pcap_stream_benches(c: &mut Criterion) {
    bench_pcap_stream(c, "multi-sessions", PCAP_MULTI_SESSIONS);
    bench_pcap_stream(c, "ext-next-hop", PCAP_EXT_NEXT_HOP);
    bench_pcap_stream(c, "mpls-vpn", PCAP_MPLS_VPN);
    bench_pcap_stream(c, "srv6-lcomms", PCAP_SRV6_LCOMMS);
    bench_pcap_stream(c, "305-update-keepalive", PCAP_STREAM_LARGE);
}

criterion_group!(
    benches,
    legacy_synthetic_benches,
    pcap_exemplar_benches,
    pcap_stream_benches,
);
criterion_main!(benches);
