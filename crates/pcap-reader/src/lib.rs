// Copyright (C) 2023-present The NetGauze Authors.
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

//! Helper library to read pcap files, this library is not meant for production
//! use but rather for testing purposes.
//!
//! Example:
//! ```rust,ignore
//! use std::{collections::HashMap, fs::File};
//!
//! use bytes::BytesMut;
//! use pcap_parser::PcapNGReader;
//! use tokio_util::codec::Decoder;
//!
//! use netgauze_bmp_pkt::codec::BmpCodec;
//! use netgauze_pcap_reader::{PcapIter, TransportProtocol};
//!
//! let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
//! path.push_str("/data/bmp.pcapng");
//! let file = File::open(path).unwrap();
//! let reader = PcapNGReader::new(165536, file).unwrap();
//! let reader = Box::new(reader);
//! let iter = PcapIter::new(reader);
//! let mut peers = HashMap::new();
//! for (src_ip, src_port, dst_ip, dst_port, protocol, value) in iter {
//!     if protocol != TransportProtocol::TCP {
//!         continue;
//!     }
//!     let key = (src_ip, src_port, dst_ip, dst_port);
//!     let (codec, buf) = peers
//!         .entry(key)
//!         .or_insert((BmpCodec::default(), BytesMut::new()));
//!     buf.extend_from_slice(value.as_slice());
//!     match codec.decode(buf) {
//!         Ok(Some(msg)) => println!("{}", serde_json::to_string(&msg).unwrap()),
//!         Ok(None) => {}
//!         Err(err) => println!("Error parsing BMP Message: {:?}", err),
//!     }
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use pdu::{Ethernet, Ipv4, Ipv4Pdu, Ipv6, Ipv6Pdu, Tcp, Udp};

/// Transport Protocol
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

/// EtherType values we dispatch on.
///
/// See the [IANA IEEE 802 numbers registry](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml).
mod ether_type {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    /// IEEE 802.1Q customer VLAN tag (C-TAG).
    pub const VLAN: u16 = 0x8100;
    /// IEEE 802.1ad service VLAN tag (S-TAG, "QinQ").
    pub const VLAN_QINQ: u16 = 0x88A8;
    /// Pre-standard QinQ TPID still emitted by some vendors.
    pub const VLAN_LEGACY_QINQ: u16 = 0x9100;

    pub const fn is_vlan(ether_type: u16) -> bool {
        ether_type == VLAN || ether_type == VLAN_QINQ || ether_type == VLAN_LEGACY_QINQ
    }
}

/// Octets a VLAN tag occupies *after* the EtherType that introduced it has
/// already been consumed: 2 octets of Tag Control Information (PCP/DEI/VID)
/// followed by 2 octets carrying the EtherType of whatever it encapsulates,
/// which may be another tag, for stacked VLANs / QinQ.
const VLAN_TAG_REMAINDER_LEN: usize = 4;

/// Upper bound on stacked VLAN tags, so a malformed frame claiming an endless
/// chain of tags can't spin here. Double tagging (QinQ) is the deepest stack
/// seen in practice; the extra headroom costs nothing.
const MAX_VLAN_TAGS: usize = 4;

/// Walk past any 802.1Q/802.1ad VLAN tags, returning the EtherType of the
/// encapsulated protocol and the payload positioned at its first octet.
///
/// `ether_type` is the EtherType *preceding* `payload`, so on entry `payload`
/// starts at the tag's TCI when `ether_type` is a VLAN TPID.
///
/// Returns `None` if the frame is truncated mid-tag or stacks more tags than
/// [`MAX_VLAN_TAGS`].
fn strip_vlan_tags(mut ether_type: u16, mut payload: &[u8]) -> Option<(u16, &[u8])> {
    for _ in 0..=MAX_VLAN_TAGS {
        if !ether_type::is_vlan(ether_type) {
            return Some((ether_type, payload));
        }
        if payload.len() < VLAN_TAG_REMAINDER_LEN {
            return None;
        }
        ether_type = u16::from_be_bytes([payload[2], payload[3]]);
        payload = &payload[VLAN_TAG_REMAINDER_LEN..];
    }
    None
}

/// Iterator over pcap files
pub struct PcapIter<'a> {
    reader: Box<dyn PcapReaderIterator + 'a>,
    link_types: Vec<Linktype>,
    frame_counter: usize,
}

impl<'a> PcapIter<'a> {
    pub const fn new(reader: Box<dyn PcapReaderIterator + 'a>) -> Self {
        Self {
            reader,
            link_types: vec![],
            frame_counter: 0,
        }
    }

    /// Return the current frame counter
    pub const fn frame_counter(&self) -> usize {
        self.frame_counter
    }
}

impl Iterator for PcapIter<'_> {
    type Item = (IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(legacy_packet) => {
                            self.frame_counter += 1;
                            let link_type = self.link_types[0];
                            let packet_data = data::get_packetdata(
                                legacy_packet.data,
                                link_type,
                                legacy_packet.caplen as usize,
                            );
                            let result = PcapIter::parse_packet(packet_data);
                            self.reader.consume(offset);
                            // A frame we don't extract from (ARP, ICMP, a
                            // non-IP EtherType, ...) must not end iteration
                            // skip it and keep reading.
                            if result.is_some() {
                                return result;
                            }
                            continue;
                        }
                        PcapBlockOwned::LegacyHeader(header) => {
                            self.reader.consume(offset);
                            self.link_types.push(header.network);
                            continue;
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(description)) => {
                            // Memorize link type for that given interface
                            self.link_types.push(description.linktype);
                            self.reader.consume(offset);
                            continue;
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                            self.frame_counter += 1;
                            let link_type = self.link_types[packet.if_id as usize];
                            let packet_data = data::get_packetdata(
                                packet.data,
                                link_type,
                                packet.caplen as usize,
                            );
                            let result = PcapIter::parse_packet(packet_data);
                            self.reader.consume(offset);
                            // See the legacy-block arm above: skipped frames
                            // must not terminate iteration.
                            if result.is_some() {
                                return result;
                            }
                            continue;
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(_)) => {
                            todo!()
                        }
                        PcapBlockOwned::NG(_) => {
                            self.reader.consume(offset);
                            continue;
                        }
                    };
                }
                Err(PcapError::Incomplete(_)) => {
                    self.reader.refill().unwrap();
                }
                Err(PcapError::Eof) => return None,
                Err(PcapError::ReadError) => todo!(),
                Err(PcapError::HeaderNotRecognized) => todo!(),
                Err(PcapError::NomError(_, _)) => {
                    todo!()
                }
                Err(PcapError::OwnedNomError(_, _)) => todo!(),
                Err(PcapError::BufferTooSmall) => todo!(),
                Err(PcapError::UnexpectedEof) => todo!(),
            }
        }
    }
}

impl<'a> PcapIter<'a> {
    fn parse_packet(
        data: Option<PacketData<'a>>,
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        match data {
            None => None,
            Some(PacketData::L2(l2_pkt)) => Self::parse_ethernet(l2_pkt),
            // Link types that hand us a bare L3 payload plus its EtherType;
            // notably Linux cooked capture (LINKTYPE_LINUX_SLL), where a
            // VLAN-tagged frame surfaces as EtherType 0x8100 with the tag
            // still in front of the IP header.
            Some(PacketData::L3(ether_type, data)) => {
                let (ether_type, data) = strip_vlan_tags(ether_type, data)?;
                Self::parse_l3(ether_type, data)
            }
            // Anything else (raw L4, or a link type pcap-parser can't
            // classify) is skipped rather than aborting the whole capture.
            Some(PacketData::L4(_, _)) | Some(PacketData::Unsupported(_)) => None,
        }
    }

    /// Dispatch an L3 payload on its EtherType. Non-IP frames (ARP, LLDP, …)
    /// and malformed IP headers are skipped, matching how the Ethernet path
    /// already treats ARP.
    fn parse_l3(
        ether_type: u16,
        data: &'a [u8],
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        match ether_type {
            ether_type::IPV4 => Ipv4Pdu::new(data).ok().and_then(Self::parse_ipv4),
            ether_type::IPV6 => Ipv6Pdu::new(data).ok().and_then(Self::parse_ipv6),
            _ => None,
        }
    }

    fn parse_ethernet(
        l2_pkt: &'a [u8],
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        let eth_pdu = pdu::EthernetPdu::new(l2_pkt).ok()?;
        // Captured before `into_inner` consumes the PDU; only needed for the
        // `Raw` arm below.
        let outer_ether_type = eth_pdu.ethertype();
        match eth_pdu.into_inner() {
            Err(_) => None,
            Ok(Ethernet::Arp(_)) => None,
            Ok(Ethernet::Ipv4(ipv4_pdu)) => Self::parse_ipv4(ipv4_pdu),
            Ok(Ethernet::Ipv6(ipv6_pdu)) => Self::parse_ipv6(ipv6_pdu),
            // `pdu` transparently unwraps a single 802.1Q tag, but leaves
            // stacked/QinQ tags (and anything non-IP) as `Raw`. `ethertype()`
            // is then the outermost unhandled TPID and `payload` starts at its
            // TCI, which is exactly what `strip_vlan_tags` expects.
            Ok(Ethernet::Raw(payload)) => {
                let (ether_type, payload) = strip_vlan_tags(outer_ether_type, payload)?;
                Self::parse_l3(ether_type, payload)
            }
        }
    }

    fn parse_ipv4(
        ipv4_pdu: Ipv4Pdu<'_>,
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        let src_ip = IpAddr::V4(Ipv4Addr::from(ipv4_pdu.source_address()));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(ipv4_pdu.destination_address()));
        match ipv4_pdu.inner() {
            Err(_) => None,
            Ok(ipv4) => match ipv4 {
                Ipv4::Raw(_) => None,
                Ipv4::Tcp(tcp) => {
                    let src_port = tcp.source_port();
                    let dst_port = tcp.destination_port();
                    match tcp.inner() {
                        Err(_) => None,
                        Ok(Tcp::Raw(payload)) => Some((
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            TransportProtocol::TCP,
                            payload.to_vec(),
                        )),
                    }
                }
                Ipv4::Udp(udp) => {
                    let src_port = udp.source_port();
                    let dst_port = udp.destination_port();
                    // UDP payload length, to avoiding parsing any padding
                    // bytes.
                    let len = udp.length() as usize - 8;
                    match udp.inner() {
                        Err(_) => None,
                        Ok(Udp::Raw(payload)) => {
                            assert!(
                                len <= payload.len(),
                                "Invalid UDP payload length calculation"
                            );
                            Some((
                                src_ip,
                                src_port,
                                dst_ip,
                                dst_port,
                                TransportProtocol::UDP,
                                payload[..len].to_vec(),
                            ))
                        }
                    }
                }
                Ipv4::Icmp(_) => None,
                Ipv4::Gre(_) => unimplemented!("GRE Protocol is not supported!"),
                Ipv4::Esp(_) => unimplemented!("ESP Protocol is not supported!"),
            },
        }
    }

    fn parse_ipv6(
        ipv6_pdu: Ipv6Pdu<'_>,
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        let src_ip = IpAddr::V6(Ipv6Addr::from(ipv6_pdu.source_address()));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(ipv6_pdu.destination_address()));
        match ipv6_pdu.inner() {
            Err(_) => None,
            Ok(ipv6) => match ipv6 {
                Ipv6::Raw(_) => None,
                Ipv6::Tcp(tcp) => {
                    let src_port = tcp.source_port();
                    let dst_port = tcp.destination_port();
                    match tcp.inner() {
                        Err(_) => None,
                        Ok(Tcp::Raw(payload)) => Some((
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            TransportProtocol::TCP,
                            payload.to_vec(),
                        )),
                    }
                }
                Ipv6::Udp(udp) => {
                    let src_port = udp.source_port();
                    let dst_port = udp.destination_port();
                    match udp.inner() {
                        Err(_) => None,
                        Ok(Udp::Raw(payload)) => Some((
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            TransportProtocol::UDP,
                            payload.to_vec(),
                        )),
                    }
                }
                Ipv6::Icmp(_) => None,
                Ipv6::Gre(_) => unimplemented!("GRE Protocol is not supported!"),
                Ipv6::Esp(_) => unimplemented!("ESP Protocol is not supported!"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Cursor;

    use super::*;

    /// LINKTYPE_LINUX_SLL: Linux "cooked" capture, what you get from
    /// `tcpdump -i any`. Hands us an L3 payload plus an EtherType, so a
    /// VLAN-tagged frame arrives with the tag still in front of the IP header.
    const LINKTYPE_LINUX_SLL: u32 = 113;
    const LINKTYPE_ETHERNET: u32 = 1;

    /// Minimal IPv4 + UDP datagram carrying `payload`. Checksums are left
    /// zero; nothing in the read path verifies them.
    fn ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&[0x45, 0x00]);
        out.extend_from_slice(&(total_len as u16).to_be_bytes());
        out.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 17, 0x00, 0x00]);
        out.extend_from_slice(&[10, 0, 0, 1]); // src
        out.extend_from_slice(&[10, 0, 0, 2]); // dst
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&(udp_len as u16).to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00]); // checksum
        out.extend_from_slice(payload);
        out
    }

    /// One 802.1Q/802.1ad tag: TCI then the EtherType it encapsulates.
    fn vlan_tag(vid: u16, inner_ether_type: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&vid.to_be_bytes());
        out.extend_from_slice(&inner_ether_type.to_be_bytes());
        out
    }

    /// Linux cooked-capture header whose protocol field is `ether_type`.
    fn sll_header(ether_type: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&[0x00, 0x00]); // packet type
        out.extend_from_slice(&[0x00, 0x01]); // ARPHRD
        out.extend_from_slice(&[0x00, 0x06]); // address length
        out.extend_from_slice(&[0xcc, 0xed, 0x4d, 0xaf, 0x01, 0x80, 0x00, 0x00]); // address
        out.extend_from_slice(&ether_type.to_be_bytes());
        out
    }

    fn ethernet_header(ether_type: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(14);
        out.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // dst MAC
        out.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // src MAC
        out.extend_from_slice(&ether_type.to_be_bytes());
        out
    }

    /// Wrap `frames` into an in-memory legacy pcap with the given link type.
    fn build_pcap(link_type: u32, frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&link_type.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(i as u32).to_le_bytes()); // ts_sec
            out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            out.extend_from_slice(&(f.len() as u32).to_le_bytes()); // incl_len
            out.extend_from_slice(&(f.len() as u32).to_le_bytes()); // orig_len
            out.extend_from_slice(f);
        }
        out
    }

    fn collect(pcap: &[u8]) -> Vec<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        let reader = LegacyPcapReader::new(165_536, Cursor::new(pcap)).unwrap();
        PcapIter::new(Box::new(reader)).collect()
    }

    #[test]
    fn sll_vlan_tagged_is_parsed() {
        let mut frame = sll_header(ether_type::VLAN);
        frame.extend_from_slice(&vlan_tag(100, ether_type::IPV4));
        frame.extend_from_slice(&ipv4_udp(4444, 10100, b"hello"));
        let results = collect(&build_pcap(LINKTYPE_LINUX_SLL, &[frame]));
        assert_eq!(results.len(), 1, "VLAN-tagged SLL frame should be parsed");
        assert_eq!(results[0].3, 10100);
        assert_eq!(results[0].4, TransportProtocol::UDP);
        assert_eq!(results[0].5, b"hello");
    }

    #[test]
    fn sll_untagged_still_parsed() {
        let mut frame = sll_header(ether_type::IPV4);
        frame.extend_from_slice(&ipv4_udp(4444, 10100, b"plain"));
        let results = collect(&build_pcap(LINKTYPE_LINUX_SLL, &[frame]));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].5, b"plain");
    }

    #[test]
    fn sll_qinq_double_tagged_is_parsed() {
        let mut frame = sll_header(ether_type::VLAN_QINQ);
        frame.extend_from_slice(&vlan_tag(10, ether_type::VLAN)); // S-TAG
        frame.extend_from_slice(&vlan_tag(20, ether_type::IPV4)); // C-TAG
        frame.extend_from_slice(&ipv4_udp(4444, 10100, b"qinq"));
        let results = collect(&build_pcap(LINKTYPE_LINUX_SLL, &[frame]));
        assert_eq!(
            results.len(),
            1,
            "QinQ double-tagged frame should be parsed"
        );
        assert_eq!(results[0].5, b"qinq");
    }

    #[test]
    fn ethernet_qinq_double_tagged_is_parsed() {
        // `pdu` unwraps a single 802.1Q tag itself, but leaves QinQ as `Raw`.
        let mut frame = ethernet_header(ether_type::VLAN_QINQ);
        frame.extend_from_slice(&vlan_tag(10, ether_type::VLAN));
        frame.extend_from_slice(&vlan_tag(20, ether_type::IPV4));
        frame.extend_from_slice(&ipv4_udp(4444, 10100, b"eth-qinq"));
        let results = collect(&build_pcap(LINKTYPE_ETHERNET, &[frame]));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].5, b"eth-qinq");
    }

    #[test]
    fn non_ip_ether_type_is_skipped_not_panic() {
        // 0x0806 = ARP. Previously any non-IP EtherType hit `unimplemented!()`
        // and took down the whole capture.
        let mut frame = sll_header(0x0806);
        frame.extend_from_slice(&[0u8; 28]);
        let mut ok_frame = sll_header(ether_type::IPV4);
        ok_frame.extend_from_slice(&ipv4_udp(4444, 10100, b"after-arp"));
        let results = collect(&build_pcap(LINKTYPE_LINUX_SLL, &[frame, ok_frame]));
        assert_eq!(results.len(), 1, "ARP skipped, following frame still read");
        assert_eq!(results[0].5, b"after-arp");
    }

    #[test]
    fn truncated_vlan_tag_is_skipped() {
        let mut frame = sll_header(ether_type::VLAN);
        frame.extend_from_slice(&[0x00, 0x64]); // TCI only, EtherType missing
        let results = collect(&build_pcap(LINKTYPE_LINUX_SLL, &[frame]));
        assert!(results.is_empty(), "truncated tag should be skipped");
    }

    #[test]
    fn strip_vlan_tags_bounds_stacked_tags() {
        // A frame claiming an endless chain of tags must terminate.
        let mut payload = Vec::new();
        for _ in 0..(MAX_VLAN_TAGS + 2) {
            payload.extend_from_slice(&vlan_tag(1, ether_type::VLAN));
        }
        assert_eq!(strip_vlan_tags(ether_type::VLAN, &payload), None);
    }

    #[test]
    fn strip_vlan_tags_passes_through_untagged() {
        let payload = [0x45u8, 0x00, 0x00, 0x14];
        assert_eq!(
            strip_vlan_tags(ether_type::IPV4, &payload),
            Some((ether_type::IPV4, &payload[..]))
        );
    }

    #[test]
    fn it_pcap() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
        path.push_str("/data/bgp.pcap");
        let file = File::open(path).unwrap();
        let reader = LegacyPcapReader::new(165536, file).unwrap();
        let results: Vec<_> = PcapIter::new(Box::new(reader)).collect();
        assert_eq!(results.len(), 20)
    }

    #[test]
    fn it_pcapng() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
        path.push_str("/data/bmp.pcapng");
        let file = File::open(path).unwrap();
        let reader = PcapNGReader::new(165536, file).unwrap();
        let results: Vec<_> = PcapIter::new(Box::new(reader)).collect();
        assert_eq!(results.len(), 9)
    }
}
