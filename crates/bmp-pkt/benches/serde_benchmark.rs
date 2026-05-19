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

//! Microbenchmarks for BMP wire protocol encode/decode performance.
//!
//! Two flavors:
//!
//! 1. **Synthetic exemplars** — hand-built wire fixtures targeting message
//!    types or TLV combinations that the bundled pcaps don't exercise
//!    (Experimental messages, Path Marking, Group TLV, large Statistics Report
//!    with many per-AFI/SAFI counters, unaligned-prefix MPLS, Route Mirroring,
//!    BMPv4 Peer Down).
//! 2. **Pcap-derived exemplars** — first messages of distinct categories pulled
//!    from the curated pcaps in `assets/pcaps/bmp/` and from a selected
//!    pmacct-tests pcap. These cover real-vendor encodings of Initiation, rich
//!    Peer Up, Peer Down with BGP NOTIFICATION PDU, Route Monitoring (VPNv4,
//!    VPNv6, EVPN, ADD-PATH, VPNv4 withdraw via BMPv4 stateless parsing) and
//!    Statistics Report.
//!
//! Pcap-derived decode benches restore the [`BmpParsingContext`] to the
//! exact state observed immediately before that message in the original
//! stream, so capability-dependent decoding (ADD-PATH, multi-label MPLS)
//! is exercised faithfully.
//!
//! In addition to per-message benchmarks, [`pcap_stream_benches`] runs
//! whole-pcap throughput benches that drive the full
//! TCP-reassembly + [`BmpCodec`] decode path, matching the workload of a
//! BMP collector.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use netgauze_bgp_pkt::path_attribute::PathAttributeValue;
use netgauze_bmp_pkt::codec::BmpCodec;
use netgauze_bmp_pkt::iana::BmpMessageType;
use netgauze_bmp_pkt::wire::deserializer::BmpParsingContext;
use netgauze_bmp_pkt::{BmpMessage, v3, v4};
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePdu};
use netgauze_pcap_reader::{PcapIter, TransportProtocol};
use pcap_parser::LegacyPcapReader;
use std::collections::HashMap;
use std::hint::black_box;
use std::io::Cursor;
use tokio_util::codec::Decoder;

// -------------------------------------------------------------------------
// Synthetic wire-format fixtures
//
// Each fixture below is byte-for-byte identical to a wire payload that
// `crates/bmp-pkt/src/wire/tests/*.rs` already validates. They are kept
// here only for message variants that the bundled pcaps do not cover.
// -------------------------------------------------------------------------

/// BMPv3 Termination with String + Reason TLVs. No pcap in the repo carries
/// a Termination message. Source: `test_bmp_termination_with_reason`.
#[rustfmt::skip]
const BMP_V3_TERMINATION_WITH_REASON: &[u8] = &[
    0x03, 0x00, 0x00, 0x00, 0x1e, 0x05, 0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f,
    0x6e, 0x66, 0x69, 0x67, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x64,
    0x00, 0x01, 0x00, 0x02, 0x00, 0x00,
];

/// BMPv3 Route Monitoring from a Loc-RIB peer with MP-REACH IPv4 MPLS
/// labels NLRI exercising unaligned prefix decoding. No pcap in the repo
/// has this combination. Source: `test_bmp_route_monitoring_unaligned_prefix`.
#[rustfmt::skip]
const BMP_V3_ROUTE_MONITORING_MPLS_UNALIGNED: &[u8] = &[
    0x03, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x03, 0x80, 0x00, 0x00, 0xfb, 0xf3,
    0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
    0xc0, 0x00, 0x02, 0x3d, 0x64, 0x28, 0xc4, 0x47, 0x00, 0x03, 0x8a, 0xe5,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x79, 0x02, 0x00, 0x00, 0x00, 0x62, 0x40,
    0x01, 0x01, 0x00, 0x40, 0x02, 0x0e, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0xfd, 0xe8, 0x80, 0x04, 0x04, 0x00,
    0x00, 0x3b, 0x60, 0x40, 0x05, 0x04, 0x00, 0x00, 0x3f, 0x48, 0xc0, 0x08,
    0x14, 0xfb, 0xf0, 0x01, 0x2b, 0xfb, 0xf0, 0x03, 0xe9, 0xfb, 0xf0, 0x04,
    0x09, 0xfb, 0xf1, 0x00, 0x01, 0xfb, 0xf3, 0x00, 0x14, 0xc0, 0x10, 0x10,
    0x00, 0x02, 0xfb, 0xf1, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x03, 0xfb, 0xf1,
    0x00, 0x00, 0x00, 0x2a, 0x90, 0x0e, 0x00, 0x11, 0x00, 0x01, 0x04, 0x04,
    0xc6, 0x33, 0x64, 0x47, 0x00, 0x37, 0x10, 0x03, 0x31, 0xcb, 0x00, 0x71,
    0xfe,
];

/// BMPv3 Route Mirroring (single mirrored KEEPALIVE). No pcap in the repo
/// has Route Mirroring. Source: `test_bmp_router_mirroring`.
#[rustfmt::skip]
const BMP_V3_ROUTE_MIRRORING: &[u8] = &[
    0x03, 0x00, 0x00, 0x00, 0x47, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xac, 0x10, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc8,
    0xac, 0x10, 0x00, 0x14, 0x63, 0x3c, 0x98, 0x8b, 0x00, 0x04, 0x5a, 0xae,
    0x00, 0x00, 0x00, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04,
];

/// BMPv3 Statistics Report with 26 entries across many counter types. The
/// stats message in our pcaps are typically much shorter. Source:
/// `test_bmp_stats`.
#[rustfmt::skip]
const BMP_V3_STATISTICS_REPORT_LARGE: &[u8] = &[
    0x03, 0x00, 0x00, 0x01, 0x79, 0x01, 0x01, 0x80, 0x00, 0x00, 0xff, 0xdb,
    0x00, 0x00, 0x00, 0x21, 0x20, 0x01, 0x01, 0x23, 0x00, 0x45, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x19, 0x00, 0x01, 0x00, 0x13,
    0xc0, 0x38, 0x01, 0xd2, 0x64, 0x01, 0xfc, 0x76, 0x00, 0x0a, 0x41, 0xf9,
    0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0b, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, 0x00, 0x0b,
    0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x09, 0x00, 0x0b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x0b, 0x00, 0x01, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x0b,
    0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x0b, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x01, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b,
    0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x0b, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x11, 0x00, 0x0b, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x0b, 0x00, 0x02, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x0b,
    0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x00, 0x0b, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x11, 0x00, 0x0b, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
];

/// BMPv3 Experimental251 message. Pcaps don't carry experimental codes.
#[rustfmt::skip]
const BMP_V3_EXPERIMENTAL: &[u8] = &[
    0x03, 0x00, 0x00, 0x00, 0x0c, 0xfb, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
];

/// BMPv4 Route Monitoring with a Group TLV that references three other
/// TLVs. Source: `test_bmp_v4_route_monitoring_with_groups`.
#[rustfmt::skip]
const BMP_V4_ROUTE_MONITORING_GROUPS: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x34, 0x00, 0x01, 0x00, 0x00,
    0xc0, 0x00, 0x02, 0x34, 0x64, 0x91, 0xa6, 0xa2, 0x00, 0x0d, 0x51, 0x52,
    0x00, 0x02, 0x00, 0x08, 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
    0x00, 0x04, 0x00, 0x03, 0x00, 0x06, 0x00, 0x00, 0x67, 0x6c, 0x6f, 0x62,
    0x61, 0x6c, 0x00, 0x09, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x04, 0x00, 0x32, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x32,
    0x02, 0x00, 0x00, 0x00, 0x16, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00,
    0x0e, 0x02, 0x03, 0x00, 0x01, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x13, 0x20, 0xc6, 0x33, 0x64, 0x13,
];

/// BMPv4 Peer Down Notification with an Unknown PeerDown TLV. No BMPv4
/// peer-down in the pcaps. Source: `test_bmp_v4_peer_down_notification`.
#[rustfmt::skip]
const BMP_V4_PEER_DOWN: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x3f, 0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xfc, 0x00,
    0x0a, 0x00, 0x00, 0x01, 0x63, 0x3b, 0x2a, 0x53, 0x00, 0x07, 0x71, 0xe3,
    0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07,
];

/// BMPv4 Route Monitoring with a Path Marking TLV (BEST|PRIMARY). Source:
/// `test_bmp_v4_path_marking`.
#[rustfmt::skip]
const BMP_V4_PATH_MARKING: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x7e, 0x00, 0x03, 0x00, 0x00, 0x00, 0xfb, 0xf3,
    0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x38,
    0xc0, 0x00, 0x1f, 0x9c, 0x64, 0x91, 0xa6, 0xda, 0x00, 0x0d, 0x51, 0x52,
    0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x43, 0x31, 0x30, 0x00, 0x05, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x35, 0x00,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x35, 0x02, 0x00, 0x00, 0x00, 0x16,
    0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x00, 0x40, 0x03, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x18, 0x01, 0x01, 0x01,
];

/// BMPv4 Route Monitoring with a Path Marking TLV marking the path as
/// invalid with a reason code. Source:
/// `test_bmp_v4_path_marking_invalid_with_reason`.
#[rustfmt::skip]
const BMP_V4_PATH_MARKING_INVALID: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0xfb, 0xf3,
    0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x38,
    0xc0, 0x00, 0x1f, 0x9c, 0x64, 0x91, 0xa6, 0xda, 0x00, 0x0d, 0x51, 0x52,
    0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x43, 0x31, 0x30, 0x00, 0x05, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00,
    0x35, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x35, 0x02, 0x00, 0x00,
    0x00, 0x16, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x00, 0x40, 0x03,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01, 0x01,
];

/// BMPv4 Experimental251 message. Pcaps don't carry experimental codes.
#[rustfmt::skip]
const BMP_V4_EXPERIMENTAL: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x0c, 0xfb, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
];

// -------------------------------------------------------------------------
// Pcap fixtures embedded at compile time. Paths are relative to this
// benchmark source file.
// -------------------------------------------------------------------------

const PCAP_EVPN: &[u8] = include_bytes!("../../../assets/pcaps/bmp/evpn/evpn.pcap");
const PCAP_PEERS_CAPS: &[u8] =
    include_bytes!("../../../assets/pcaps/bmp/peers-with-different-caps/example.pcap");
const PCAP_ADD_PATH: &[u8] =
    include_bytes!("../../../assets/pcaps/bmp/stateless-with-add-path/ipv4_unicast_all.pcap");
const PCAP_VPNV4_WITHDRAW: &[u8] = include_bytes!(
    "../../../assets/pcaps/bmp/vpnv4-stateless-with-withdraw/vpnv4-stateless-with-withdraw.pcap"
);
const PCAP_PEER_DOWN_FRR: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/205-BMP-6wind-FRR-peer_down/traffic-00.pcap"
);
const PCAP_STREAM_ROUTE_MONITORING: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/208-BMP-mem-leak-test/bmp-multi-sources-route-monitoring.pcap"
);
const PCAP_STREAM_STATS: &[u8] = include_bytes!(
    "../../../assets/pcaps/pmacct-tests/208-BMP-mem-leak-test/bmp-multi-sources-stats.pcap"
);

/// BMP listening ports observed across the bundled pcaps. Mirrors the list
/// used by `crates/bmp-pkt/src/wire/tests/pcap_tests.rs`.
const BMP_PORTS: &[u16] = &[1790, 1791, 10000, 10240];

// -------------------------------------------------------------------------
// Pcap walking & exemplar extraction
// -------------------------------------------------------------------------

/// A single message extracted from a pcap with the parsing context as it
/// stood immediately before this message was decoded. The decode bench
/// restores `ctx_before` on every iteration so capability-dependent
/// decoding (ADD-PATH, multi-label MPLS) is exercised faithfully.
struct Exemplar {
    name: String,
    wire: Vec<u8>,
    ctx_before: BmpParsingContext,
}

/// Reassemble each TCP flow in a pcap into a single byte buffer keyed by
/// the 4-tuple. Order within a flow is preserved (pcap order). Only TCP
/// flows whose destination port is in [`BMP_PORTS`] are kept.
fn pcap_tcp_flows(pcap_bytes: &'static [u8]) -> Vec<Vec<u8>> {
    let reader = LegacyPcapReader::new(165_536, Cursor::new(pcap_bytes)).unwrap();
    let iter = PcapIter::new(Box::new(reader));
    let mut flows: HashMap<_, Vec<u8>> = HashMap::new();
    for (src_ip, src_port, dst_ip, dst_port, protocol, value) in iter {
        if protocol != TransportProtocol::TCP || !BMP_PORTS.contains(&dst_port) {
            continue;
        }
        let key = (src_ip, src_port, dst_ip, dst_port);
        flows.entry(key).or_default().extend_from_slice(&value);
    }
    flows.into_values().collect()
}

/// Walk every BMP message in a reassembled flow, invoking `picker` once
/// per successfully decoded message. The picker returns `Some(name)` to
/// capture an exemplar. The flow's running [`BmpParsingContext`] is
/// updated after each message exactly as [`BmpCodec`] would do it so
/// capability-bearing Peer Up messages affect later route-monitoring
/// decodes.
fn pick_from_flow<F>(flow: &[u8], picker: &mut F) -> Vec<Exemplar>
where
    F: FnMut(&BmpMessage, usize) -> Option<String>,
{
    let mut out = Vec::new();
    let mut ctx = BmpParsingContext::default();
    let mut pos = 0usize;
    let mut idx = 0usize;
    while pos + 5 <= flow.len() {
        let length = u32::from_be_bytes(flow[pos + 1..pos + 5].try_into().unwrap()) as usize;
        if length < 5 || pos + length > flow.len() {
            break;
        }
        let wire = &flow[pos..pos + length];
        let ctx_before = ctx.clone();
        let mut working = ctx.clone();
        // Skip past unparseable messages instead of stopping: real BMP
        // pcaps sometimes contain vendor quirks or capability-gated routes
        // we can't decode with default context, but the BMP length field
        // still lets us advance to the next frame.
        if let Ok((_, msg)) = BmpMessage::from_wire(Span::new(wire), &mut working) {
            if let Some(name) = picker(&msg, idx) {
                out.push(Exemplar {
                    name,
                    wire: wire.to_vec(),
                    ctx_before,
                });
            }
            ctx = working;
            ctx.update(&msg);
            idx += 1;
        }
        pos += length;
    }
    out
}

/// Walk all flows in a pcap, applying `picker` to each decoded message.
fn pick_exemplars<F>(pcap_bytes: &'static [u8], mut picker: F) -> Vec<Exemplar>
where
    F: FnMut(&BmpMessage, usize) -> Option<String>,
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

/// Return the [`AddressType`] of the first MP-REACH attribute on a Route
/// Monitoring message, if any.
fn route_monitoring_mp_reach_address_type(msg: &BmpMessage) -> Option<AddressType> {
    let bgp = match msg {
        BmpMessage::V3(v3::BmpMessageValue::RouteMonitoring(rm)) => rm.update_message(),
        BmpMessage::V4(v4::BmpMessageValue::RouteMonitoring(rm)) => rm.update_message(),
        _ => return None,
    };
    let update = match bgp {
        netgauze_bgp_pkt::BgpMessage::Update(u) => u,
        _ => return None,
    };
    for attr in update.path_attributes() {
        if let PathAttributeValue::MpReach(mp) = attr.value() {
            return mp.address_type().ok();
        }
    }
    None
}

/// Does the BMPv4 Route Monitoring have at least one withdrawn route or
/// an MP-UNREACH attribute?
fn v4_route_monitoring_has_withdraw(msg: &BmpMessage) -> bool {
    let rm = match msg {
        BmpMessage::V4(v4::BmpMessageValue::RouteMonitoring(rm)) => rm,
        _ => return false,
    };
    let update = match rm.update_message() {
        netgauze_bgp_pkt::BgpMessage::Update(u) => u,
        _ => return false,
    };
    if !update.withdraw_routes().is_empty() {
        return true;
    }
    update
        .path_attributes()
        .iter()
        .any(|a| matches!(a.value(), PathAttributeValue::MpUnreach(_)))
}

/// Has at least one NLRI with a non-`None` path_id (i.e. ADD-PATH wire
/// format) been observed on this BMPv4 Route Monitoring?
fn v4_route_monitoring_has_add_path(msg: &BmpMessage) -> bool {
    let rm = match msg {
        BmpMessage::V4(v4::BmpMessageValue::RouteMonitoring(rm)) => rm,
        _ => return false,
    };
    let update = match rm.update_message() {
        netgauze_bgp_pkt::BgpMessage::Update(u) => u,
        _ => return false,
    };
    update.nlri().iter().any(|n| n.path_id().is_some())
}

// -------------------------------------------------------------------------
// Bench plumbing
// -------------------------------------------------------------------------

#[inline(always)]
fn decode_with_ctx(buf: &[u8], ctx: &mut BmpParsingContext) -> BmpMessage {
    let (_, msg) = BmpMessage::from_wire(Span::new(buf), ctx).unwrap();
    msg
}

/// Register a decode + encode bench pair for a synthetic fixture (decode
/// is always done with a fresh default context).
fn bench_synthetic(c: &mut Criterion, name: &str, wire: &'static [u8]) {
    bench_exemplar(
        c,
        &Exemplar {
            name: name.to_owned(),
            wire: wire.to_vec(),
            ctx_before: BmpParsingContext::default(),
        },
    );
}

/// Register a decode + encode bench pair for a single exemplar.
///
/// A one-time decode → encode → compare round-trip check runs at
/// registration so a broken fixture fails fast instead of producing
/// misleading throughput numbers.
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
// Streaming benchmark — full pcap through BmpCodec
// -------------------------------------------------------------------------

/// Number of BMP messages successfully decoded by feeding every TCP flow
/// in `pcap_bytes` through a fresh [`BmpCodec`]. Used both to set the
/// throughput element count and to sanity-check the run.
fn drive_stream(flows: &[Vec<u8>]) -> usize {
    let mut total = 0usize;
    for flow in flows {
        let mut codec = BmpCodec::default();
        let mut buf = BytesMut::with_capacity(flow.len());
        buf.extend_from_slice(flow);
        // Keep going past a decode error: `BmpCodec::decode` already
        // advances the buffer past the failed frame, so subsequent frames
        // can still be processed (closer to a real collector's behavior
        // than bailing on the first vendor quirk).
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
    // Print once per stream so the user can sanity-check the bench scope
    // against the source pcap (criterion's bench output otherwise hides
    // these numbers).
    eprintln!(
        "stream/{name}: flows={} bytes={} msgs={}",
        flows.len(),
        total_bytes,
        total_msgs,
    );

    let mut group = c.benchmark_group("stream");
    // Report both bytes/s (decode throughput) and elements/s (msgs/s).
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
// Exemplar selection from each pcap
// -------------------------------------------------------------------------

/// One Initiation and one rich Peer Up (carries Multi-Protocol, ADD-PATH,
/// FourOctetAs and ExtendedNextHopEncoding capabilities) from the
/// peers-with-different-caps pcap.
fn exemplars_peers_caps() -> Vec<Exemplar> {
    let mut got_init = false;
    let mut got_peer_up = false;
    pick_exemplars(PCAP_PEERS_CAPS, |msg, _| {
        if !got_init && msg.get_type() == BmpMessageType::Initiation {
            got_init = true;
            return Some("bmp v3 initiation (pcap)".to_owned());
        }
        if !got_peer_up && msg.get_type() == BmpMessageType::PeerUpNotification {
            got_peer_up = true;
            return Some("bmp v3 peer up rich caps (pcap)".to_owned());
        }
        None
    })
}

/// One Peer Down carrying a real BGP NOTIFICATION PDU and one Stats Report
/// from the 6wind/FRR peer-down pcap.
fn exemplars_peer_down_frr() -> Vec<Exemplar> {
    let mut got_down = false;
    let mut got_stats = false;
    pick_exemplars(PCAP_PEER_DOWN_FRR, |msg, _| {
        if !got_down
            && let BmpMessage::V3(v3::BmpMessageValue::PeerDownNotification(pd)) = msg
            && matches!(
                pd.reason(),
                v3::PeerDownNotificationReason::RemoteSystemClosedNotificationPduFollows(_)
            )
        {
            got_down = true;
            return Some("bmp v3 peer down with notification (pcap)".to_owned());
        }
        if !got_stats && msg.get_type() == BmpMessageType::StatisticsReport {
            got_stats = true;
            return Some("bmp v3 statistics report (pcap)".to_owned());
        }
        None
    })
}

/// One representative Route Monitoring per AFI/SAFI that the evpn pcap
/// carries (VPNv4, VPNv6, EVPN).
fn exemplars_evpn() -> Vec<Exemplar> {
    let mut want = vec![
        (
            AddressType::Ipv4MplsLabeledVpn,
            "bmp v3 route monitoring vpnv4 (pcap)",
        ),
        (
            AddressType::Ipv6MplsLabeledVpn,
            "bmp v3 route monitoring vpnv6 (pcap)",
        ),
        (
            AddressType::L2VpnBgpEvpn,
            "bmp v3 route monitoring evpn (pcap)",
        ),
    ];
    pick_exemplars(PCAP_EVPN, |msg, _| {
        let addr = route_monitoring_mp_reach_address_type(msg)?;
        if let Some(pos) = want.iter().position(|(a, _)| *a == addr) {
            let (_, name) = want.remove(pos);
            return Some(name.to_owned());
        }
        None
    })
}

/// One BMPv4 Route Monitoring whose UPDATE actually carries ADD-PATH
/// encoded NLRI (path_id present), from the stateless-with-add-path pcap.
fn exemplars_add_path() -> Vec<Exemplar> {
    let mut taken = false;
    pick_exemplars(PCAP_ADD_PATH, |msg, _| {
        if !taken && v4_route_monitoring_has_add_path(msg) {
            taken = true;
            return Some("bmp v4 route monitoring add-path (pcap)".to_owned());
        }
        None
    })
}

/// One BMPv4 Route Monitoring carrying a VPNv4 withdraw, from the
/// vpnv4-stateless-with-withdraw pcap.
fn exemplars_vpnv4_withdraw() -> Vec<Exemplar> {
    let mut taken = false;
    pick_exemplars(PCAP_VPNV4_WITHDRAW, |msg, _| {
        if !taken && v4_route_monitoring_has_withdraw(msg) {
            taken = true;
            return Some("bmp v4 route monitoring vpnv4 withdraw (pcap)".to_owned());
        }
        None
    })
}

// -------------------------------------------------------------------------
// Entry points
// -------------------------------------------------------------------------

pub fn synthetic_benches(c: &mut Criterion) {
    bench_synthetic(
        c,
        "bmp v3 termination with reason",
        BMP_V3_TERMINATION_WITH_REASON,
    );
    bench_synthetic(
        c,
        "bmp v3 route monitoring mpls unaligned",
        BMP_V3_ROUTE_MONITORING_MPLS_UNALIGNED,
    );
    bench_synthetic(c, "bmp v3 route mirroring", BMP_V3_ROUTE_MIRRORING);
    bench_synthetic(
        c,
        "bmp v3 statistics report large",
        BMP_V3_STATISTICS_REPORT_LARGE,
    );
    bench_synthetic(c, "bmp v3 experimental", BMP_V3_EXPERIMENTAL);
    bench_synthetic(
        c,
        "bmp v4 route monitoring with groups",
        BMP_V4_ROUTE_MONITORING_GROUPS,
    );
    bench_synthetic(c, "bmp v4 peer down", BMP_V4_PEER_DOWN);
    bench_synthetic(c, "bmp v4 path marking", BMP_V4_PATH_MARKING);
    bench_synthetic(
        c,
        "bmp v4 path marking invalid",
        BMP_V4_PATH_MARKING_INVALID,
    );
    bench_synthetic(c, "bmp v4 experimental", BMP_V4_EXPERIMENTAL);
}

pub fn pcap_exemplar_benches(c: &mut Criterion) {
    let mut all = Vec::new();
    all.extend(exemplars_peers_caps());
    all.extend(exemplars_peer_down_frr());
    all.extend(exemplars_evpn());
    all.extend(exemplars_add_path());
    all.extend(exemplars_vpnv4_withdraw());

    // Surface missing exemplars loudly: a bad pcap or a parser regression
    // would otherwise silently shrink the bench suite.
    let expected = [
        "bmp v3 initiation (pcap)",
        "bmp v3 peer up rich caps (pcap)",
        "bmp v3 peer down with notification (pcap)",
        "bmp v3 statistics report (pcap)",
        "bmp v3 route monitoring vpnv4 (pcap)",
        "bmp v3 route monitoring vpnv6 (pcap)",
        "bmp v3 route monitoring evpn (pcap)",
        "bmp v4 route monitoring add-path (pcap)",
        "bmp v4 route monitoring vpnv4 withdraw (pcap)",
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
    bench_pcap_stream(c, "evpn", PCAP_EVPN);
    bench_pcap_stream(c, "peers-with-different-caps", PCAP_PEERS_CAPS);
    bench_pcap_stream(c, "stateless-with-add-path", PCAP_ADD_PATH);
    bench_pcap_stream(c, "vpnv4-stateless-with-withdraw", PCAP_VPNV4_WITHDRAW);
    bench_pcap_stream(c, "peer-down-frr", PCAP_PEER_DOWN_FRR);
    bench_pcap_stream(c, "208-route-monitoring", PCAP_STREAM_ROUTE_MONITORING);
    bench_pcap_stream(c, "208-stats", PCAP_STREAM_STATS);
}

criterion_group!(
    benches,
    synthetic_benches,
    pcap_exemplar_benches,
    pcap_stream_benches,
);
criterion_main!(benches);
