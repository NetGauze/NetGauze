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

use pcap_parser::{data::PacketData, traits::PcapReaderIterator, *};
use pdu::{Ethernet, Ipv4, Ipv4Pdu, Ipv6, Ipv6Pdu, Tcp, Udp};

/// Transport Protocol
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

/// Iterator over pcap files
pub struct PcapIter<'a> {
    reader: Box<dyn PcapReaderIterator + 'a>,
    link_types: Vec<Linktype>,
}

impl<'a> PcapIter<'a> {
    pub const fn new(reader: Box<dyn PcapReaderIterator + 'a>) -> Self {
        Self {
            reader,
            link_types: vec![],
        }
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
                            let link_type = self.link_types[0];
                            let packet_data = data::get_packetdata(
                                legacy_packet.data,
                                link_type,
                                legacy_packet.caplen as usize,
                            );
                            let result = PcapIter::parse_packet(packet_data);
                            self.reader.consume(offset);
                            return result;
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
                            let link_type = self.link_types[packet.if_id as usize];
                            let packet_data = data::get_packetdata(
                                packet.data,
                                link_type,
                                packet.caplen as usize,
                            );
                            let result = PcapIter::parse_packet(packet_data);
                            self.reader.consume(offset);
                            return result;
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
            Some(PacketData::L3(ether_type, data)) => {
                match ether_type {
                    // See for ethernet numbers https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
                    0x0800 => Self::parse_ipv4(Ipv4Pdu::new(data).expect("Invalid IPv4")),
                    0x86DD => Self::parse_ipv6(Ipv6Pdu::new(data).expect("Invalid IPv6")),
                    _ => unimplemented!("Only IPv4 and IPv6 packets are supported"),
                }
            }
            Some(PacketData::L4(_, _)) => unimplemented!("Only Ethernet packets are supported"),
            Some(PacketData::Unsupported(_)) => {
                unimplemented!("Only Ethernet and L3 packets are supported")
            }
        }
    }

    fn parse_ethernet(
        l2_pkt: &'a [u8],
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        pdu::EthernetPdu::new(l2_pkt)
            .map(|eth_pdu| match eth_pdu.inner() {
                Err(_) => None,
                Ok(Ethernet::Raw(_)) => unimplemented!(),
                Ok(Ethernet::Arp(_)) => None,
                Ok(Ethernet::Ipv4(ipv4_pdu)) => Self::parse_ipv4(ipv4_pdu),
                Ok(Ethernet::Ipv6(ipv6_pdu)) => Self::parse_ipv6(ipv6_pdu),
            })
            .unwrap()
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
                    // UDP payload length, to avoiding parsing any padding bytes.
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
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    #[allow(clippy::while_let_on_iterator)]
    #[test]
    fn it_pcap() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
        path.push_str("/data/bgp.pcap");
        let file = File::open(path).unwrap();
        let reader = LegacyPcapReader::new(165536, file).unwrap();
        let reader = Box::new(reader);
        let mut iter = PcapIter::new(reader);
        let mut results = vec![];
        while let Some(val) = iter.next() {
            results.push(val);
        }
        assert_eq!(results.len(), 20)
    }

    #[allow(clippy::while_let_on_iterator)]
    #[test]
    fn it_pcapng() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
        path.push_str("/data/bmp.pcapng");
        let file = File::open(path).unwrap();
        let reader = PcapNGReader::new(165536, file).unwrap();
        let reader = Box::new(reader);
        let mut iter = PcapIter::new(reader);
        let mut results = vec![];
        while let Some(val) = iter.next() {
            results.push(val);
        }
        assert_eq!(results.len(), 9)
    }
}
