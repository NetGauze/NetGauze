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

//! Codecs to decode and encode BMP Protocol messages from byte streams

use crate::iana::BmpVersion;
use crate::wire::deserializer::BmpMessageParsingError;
use crate::wire::serializer::BmpMessageWritingError;
use crate::{BmpMessage, BmpPeerType, PeerKey, v3, v4};
use bytes::{Buf, BufMut, BytesMut};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::capabilities::BgpCapability;
use netgauze_iana::address_family::AddressType;
use std::collections::{HashMap, HashSet};

use crate::wire::deserializer::BmpParsingContext;
use netgauze_bgp_pkt::capabilities::{AddPathCapability, MultipleLabel};
use netgauze_parse_utils::WritablePdu;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::ParseFromWithOneInput;
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// Min length for a valid BMP Message: 1-octet version + 4-octet length
pub const BMP_MESSAGE_MIN_LENGTH: usize = 5;

#[derive(Debug, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum BmpCodecDecoderError {
    #[error("IO error while reading BMP stream: {0}")]
    IoError(String),

    #[error("incomplete BMP message, awaiting more data{}",
            match .0 { Some(n) => format!(" ({n} more byte(s) needed)"), None => String::new() })]
    Incomplete(Option<usize>),

    #[error("{0}")]
    BmpMessageParsingError(BmpMessageParsingError),
}

impl From<std::io::Error> for BmpCodecDecoderError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

/// Encoder and Decoder for [`BmpMessage`]
#[derive(Debug, Default)]
pub struct BmpCodec {
    /// Helper to track in the decoder if we are inside a BMP message or not
    in_message: bool,
    ctx: BmpParsingContext,
}

#[inline]
fn get_caps(
    capabilities: Vec<&BgpCapability>,
) -> (Vec<AddPathCapability>, Vec<Vec<MultipleLabel>>) {
    let add_path_caps = capabilities
        .iter()
        .flat_map(|cap| {
            if let BgpCapability::AddPath(add_path) = cap {
                Some(add_path)
            } else {
                None
            }
        })
        .cloned()
        .collect::<Vec<AddPathCapability>>();
    let multiple_labels_caps = capabilities
        .iter()
        .flat_map(|cap| {
            if let BgpCapability::MultipleLabels(value) = cap {
                Some(value)
            } else {
                None
            }
        })
        .cloned()
        .collect::<Vec<Vec<MultipleLabel>>>();
    (add_path_caps, multiple_labels_caps)
}

impl BmpCodec {
    pub fn update_parsing_ctx(&mut self, msg: &BmpMessage) {
        self.ctx.update(msg)
    }
}

impl BmpParsingContext {
    /// Update the parsing context based on information presented in the payload
    /// of BMP message. It updates BGP parsing flags such as: Add Path and
    /// Multi label MPLS capabilities
    pub fn update(&mut self, msg: &BmpMessage) {
        fn handle_peer_up(ctx: &mut BmpParsingContext, peer_up: &v3::PeerUpNotificationMessage) {
            let (sent_open, received_open) =
                match (peer_up.sent_message(), peer_up.received_message()) {
                    (BgpMessage::Open(sent_open), BgpMessage::Open(received_open)) => {
                        (sent_open, received_open)
                    }
                    _ => return,
                };

            let send_caps = sent_open.capabilities();
            let received_caps = received_open.capabilities();
            let (sent_add_path_caps, sent_multiple_labels_caps) = get_caps(send_caps);
            let (received_add_path_caps, received_multiple_labels_caps) = get_caps(received_caps);

            // ADD-PATH is directional: per [RFC 7911 Section 4](https://datatracker.ietf.org/doc/html/rfc7911#section-4)
            // a speaker only puts Path Identifiers on the wire for an address
            // family when it advertised "Send" *and* its peer advertised
            // "Receive". The two OPEN messages must therefore be matched up
            // flag-by-flag; intersecting the capabilities and then reading a
            // single flag is wrong in both directions. It reports ADD-PATH as
            // enabled when both peers advertise the same receive-only flags
            // (nobody sends Path Identifiers, yet the parser expects them), and
            // reports it disabled whenever the flags legitimately differ
            // between the two sides, which is the normal negotiated case.
            let add_path_flags =
                |caps: &[AddPathCapability]| -> HashMap<AddressType, (bool, bool)> {
                    caps.iter()
                        .flat_map(|cap| cap.address_families())
                        .map(|af| (af.address_type(), (af.send(), af.receive())))
                        .collect()
                };
            let local_add_path = add_path_flags(&sent_add_path_caps);
            let remote_add_path = add_path_flags(&received_add_path_caps);

            // Multi-Label carries a per-family count rather than a direction, so
            // agreeing on the same value on both sides is the right test here.
            let sent_multiple_labels_caps: HashSet<MultipleLabel> =
                HashSet::from_iter(sent_multiple_labels_caps.into_iter().flatten());
            let received_multiple_labels_caps: HashSet<MultipleLabel> =
                HashSet::from_iter(received_multiple_labels_caps.into_iter().flatten());
            let common_multiple_labels_caps: Vec<&MultipleLabel> = Vec::from_iter(
                sent_multiple_labels_caps.intersection(&received_multiple_labels_caps),
            );

            // Add Key for the router announcing BMP to the collector
            let peer_key = PeerKey::from_peer_header(peer_up.peer_header());
            let bgp_ctx = ctx.entry(peer_key).or_default();
            // According to [RFC 9069 Section 6.1.1](https://datatracker.ietf.org/doc/html/rfc9069#name-multiple-loc-rib-peers)
            // In some implementations, it might be required to have more than one emulated
            // peer for Loc-RIB to convey different address families for the
            // same Loc-RIB. In this case, the peer distinguisher and BGP ID
            // should be the same since they represent the same Loc-RIB
            // instance. Each emulated peer instance MUST send a Peer Up with
            // the OPEN message indicating the address family capabilities.
            // A BMP receiver MUST process these capabilities to know which peer belongs to
            // which address family.
            if !matches!(peer_key.peer_type(), BmpPeerType::LocRibInstancePeer { .. }) {
                bgp_ctx.add_path_mut().clear();
                bgp_ctx.multiple_labels_mut().clear();
            }
            // Determine if we need to track Adj-RIB-Out based on Peer Type,
            // which is useful to select ADD-Path behavior for either sending or receive
            let adj_rib_out = match peer_up.peer_header().peer_type() {
                BmpPeerType::GlobalInstancePeer { adj_rib_out, .. }
                | BmpPeerType::RdInstancePeer { adj_rib_out, .. }
                | BmpPeerType::LocalInstancePeer { adj_rib_out, .. } => adj_rib_out,
                _ => false,
            };

            // adj-rib-out: we send to the peer  -> we must Send, peer must Receive
            // adj-rib-in : the peer sent to us  -> peer must Send, we must Receive
            for (address_type, (local_send, local_receive)) in &local_add_path {
                let Some((remote_send, remote_receive)) = remote_add_path.get(address_type) else {
                    continue;
                };
                let in_use = if adj_rib_out {
                    *local_send && *remote_receive
                } else {
                    *remote_send && *local_receive
                };
                bgp_ctx.add_path_mut().insert(*address_type, in_use);
            }
            bgp_ctx.update_capabilities(
                &BgpCapability::MultipleLabels(
                    common_multiple_labels_caps
                        .iter()
                        .copied()
                        .cloned()
                        .collect(),
                ),
                adj_rib_out,
            );

            // Add a key for the BGP Peer of the first router
            // In Loc-Rib the bgp open message is duplicated, no need to go through it
            // again.
            if !matches!(peer_key.peer_type(), BmpPeerType::LocRibInstancePeer { .. }) {
                let peer_key = PeerKey::new(
                    peer_up.peer_header().address(),
                    peer_up.peer_header().peer_type(),
                    peer_up.peer_header().rd(),
                    peer_up.peer_header().peer_as(),
                    received_open.bgp_id(),
                );
                let bgp_ctx = ctx.entry(peer_key).or_default();
                // Determine if we need to track Adj-RIB-Out based on Peer Type,
                // which is useful to select ADD-Path behavior for either sending or receive
                let adj_rib_out = match peer_up.peer_header().peer_type() {
                    BmpPeerType::GlobalInstancePeer { adj_rib_out, .. }
                    | BmpPeerType::RdInstancePeer { adj_rib_out, .. }
                    | BmpPeerType::LocalInstancePeer { adj_rib_out, .. } => adj_rib_out,
                    _ => false,
                };
                for (address_type, (local_send, local_receive)) in &local_add_path {
                    let Some((remote_send, remote_receive)) = remote_add_path.get(address_type)
                    else {
                        continue;
                    };
                    let in_use = if adj_rib_out {
                        *local_send && *remote_receive
                    } else {
                        *remote_send && *local_receive
                    };
                    bgp_ctx.add_path_mut().insert(*address_type, in_use);
                }
                bgp_ctx.update_capabilities(
                    &BgpCapability::MultipleLabels(
                        common_multiple_labels_caps
                            .iter()
                            .copied()
                            .cloned()
                            .collect(),
                    ),
                    adj_rib_out,
                );
            }
        }

        match msg {
            BmpMessage::V3(value) => match value {
                v3::BmpMessageValue::PeerDownNotification(peer_down) => {
                    let peer_key = PeerKey::from_peer_header(peer_down.peer_header());
                    self.remove(&peer_key);
                }
                v3::BmpMessageValue::Termination(_) => {
                    self.clear();
                }
                v3::BmpMessageValue::PeerUpNotification(peer_up) => {
                    handle_peer_up(self, peer_up);
                }
                _ => {}
            },
            BmpMessage::V4(value) => match value {
                v4::BmpMessageValue::PeerDownNotification(notif) => {
                    let peer_key = PeerKey::from_peer_header(notif.peer_header());
                    self.remove(&peer_key);
                }
                v4::BmpMessageValue::PeerUpNotification(peer_up) => handle_peer_up(self, peer_up),
                v4::BmpMessageValue::Termination(_) => {
                    self.clear();
                }
                _ => {}
            },
        }
    }
}

impl Encoder<BmpMessage> for BmpCodec {
    type Error = BmpMessageWritingError;

    fn encode(&mut self, bmp_msg: BmpMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(bmp_msg.len());
        let mut writer = dst.writer();
        bmp_msg.write(&mut writer)?;
        Ok(())
    }
}

impl Decoder for BmpCodec {
    type Item = BmpMessage;
    type Error = BmpCodecDecoderError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.in_message || buf.len() >= BMP_MESSAGE_MIN_LENGTH {
            let version: u8 = buf[0];
            // Fail early if the version is invalid
            if BmpVersion::try_from(version).is_err() {
                buf.advance(1);
                return Err(BmpCodecDecoderError::BmpMessageParsingError(
                    BmpMessageParsingError::UndefinedBmpVersion {
                        offset: 0,
                        value: version,
                    },
                ));
            }
            // Read the length, starting form after the version
            let length = u32::from_be_bytes(
                buf[1..BMP_MESSAGE_MIN_LENGTH]
                    .try_into()
                    .expect("the 4-octet length field spans buf[1..BMP_MESSAGE_MIN_LENGTH]"),
            ) as usize;
            // BMP has no synchronization marker (RFC 7854 §4.1). If the length
            // is too small to even cover the common header, advance past the
            // header so we resync on the next bytes rather than getting stuck
            // re-reading the same bad header.
            if length < BMP_MESSAGE_MIN_LENGTH {
                self.in_message = false;
                buf.advance(BMP_MESSAGE_MIN_LENGTH);
                return Err(BmpCodecDecoderError::BmpMessageParsingError(
                    BmpMessageParsingError::InvalidBmpLength {
                        offset: 1,
                        length: length as u32,
                    },
                ));
            }
            if buf.len() < length {
                // We still didn't read all the bytes for the message yet
                self.in_message = true;
                Ok(None)
            } else {
                self.in_message = false;
                let frame = buf.split_to(length);
                // SliceReader receives the full BMP message: version + length + payload.
                let mut reader = SliceReader::new(&frame[..]);
                let msg = match BmpMessage::parse(&mut reader, &mut self.ctx) {
                    Ok(msg) => {
                        self.update_parsing_ctx(&msg);
                        msg
                    }
                    Err(error) => {
                        // `split_to(length)` already advanced `buf` past this
                        // frame, so we don't need an extra advance here.
                        let err = BmpCodecDecoderError::BmpMessageParsingError(error);
                        return Err(err);
                    }
                };
                Ok(Some(msg))
            }
        } else {
            // We don't have enough data yet to start processing
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::{InitiationInformation, PeerDownNotificationReason, TerminationInformation};
    use crate::*;
    use chrono::TimeZone;
    use netgauze_bgp_pkt::capabilities::{
        ExtendedNextHopEncoding, ExtendedNextHopEncodingCapability, FourOctetAsCapability,
        MultiProtocolExtensionsCapability,
    };
    use netgauze_bgp_pkt::open::{BgpOpenMessage, BgpOpenMessageParameter};
    use netgauze_iana::address_family::{AddressFamily, AddressType};
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    /// Build a valid 14-byte BMP v3 Termination message carrying the string
    /// "test" — used as a known-good marker for resync tests.
    fn good_termination_wire() -> ([u8; 14], BmpMessage) {
        let wire = [3, 0, 0, 0, 14, 5, 0, 0, 0, 4, b't', b'e', b's', b't'];
        let msg = BmpMessage::V3(v3::BmpMessageValue::Termination(
            v3::TerminationMessage::new(vec![TerminationInformation::String("test".to_string())]),
        ));
        (wire, msg)
    }

    /// Length values 0..BMP_MESSAGE_MIN_LENGTH are all invalid because they
    /// can't even hold the common header. Each should produce
    /// `InvalidBmpLength` and advance the buffer by BMP_MESSAGE_MIN_LENGTH so
    /// the codec doesn't get stuck on the bad header.
    #[test]
    fn test_invalid_length_below_min() {
        for bad_length in 0u32..BMP_MESSAGE_MIN_LENGTH as u32 {
            let mut codec = BmpCodec::default();
            let mut buf = BytesMut::new();
            // Common header with a deliberately too-small length, plus one
            // extra trailing byte so we can verify the advance amount.
            buf.extend_from_slice(&[3u8]);
            buf.extend_from_slice(&bad_length.to_be_bytes());
            buf.extend_from_slice(&[0xAAu8]);
            assert_eq!(buf.len(), BMP_MESSAGE_MIN_LENGTH + 1);

            let result = codec.decode(&mut buf);
            assert_eq!(
                result,
                Err(BmpCodecDecoderError::BmpMessageParsingError(
                    BmpMessageParsingError::InvalidBmpLength {
                        offset: 1,
                        length: bad_length,
                    },
                )),
                "unexpected result for length={bad_length}",
            );
            // We should have advanced past the whole bad header (5 bytes),
            // leaving the single trailing sentinel byte.
            assert_eq!(
                &buf[..],
                &[0xAAu8],
                "buffer not properly advanced for length={bad_length}",
            );
        }
    }

    /// After hitting an invalid length, the codec must resync so a subsequent
    /// well-formed message in the same buffer parses correctly.
    #[test]
    fn test_invalid_length_resync_to_next_good_message() {
        let (good_wire, good_msg) = good_termination_wire();
        let bad_wire = [0x03u8, 0x00, 0x00, 0x00, 0x01]; // version=3, length=1
        let mut codec = BmpCodec::default();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&bad_wire);
        buf.extend_from_slice(&good_wire);

        // First decode reports the bad length and advances past the bad header.
        assert_eq!(
            codec.decode(&mut buf),
            Err(BmpCodecDecoderError::BmpMessageParsingError(
                BmpMessageParsingError::InvalidBmpLength {
                    offset: 1,
                    length: 1,
                },
            )),
        );
        // Second decode picks up the good message that immediately followed.
        assert_eq!(codec.decode(&mut buf), Ok(Some(good_msg)));
        assert!(buf.is_empty(), "buffer should be fully consumed");
    }

    /// A header with `length == BMP_MESSAGE_MIN_LENGTH` (5) has no room for
    /// the message-type byte or any payload. The codec must hand the full
    /// 5-byte frame to the deserializer (so its own checks can run) and not
    /// panic.
    #[test]
    fn test_length_equal_to_min_is_handed_to_parser() {
        let mut codec = BmpCodec::default();
        let mut buf = BytesMut::from(&[0x03u8, 0x00, 0x00, 0x00, 0x05][..]);
        let result = codec.decode(&mut buf);
        // The codec doesn't reject length == MIN itself (it's >= the header
        // size); the deserializer is what fails when it tries to read the
        // message-type byte from an empty payload.
        assert!(result.is_err(), "expected parser error, got {result:?}");
        // The full 5-byte frame should have been split off the buffer.
        assert!(buf.is_empty(), "frame should have been split off");
    }

    /// If `length` is valid but the buffer doesn't yet have all the bytes,
    /// decode must return `Ok(None)` so the caller knows to read more, and
    /// must mark itself as in-message so the next call retries even if the
    /// buffer is shorter than BMP_MESSAGE_MIN_LENGTH at entry.
    #[test]
    fn test_partial_message_waits_for_more_data() {
        let (good_wire, good_msg) = good_termination_wire();
        let mut codec = BmpCodec::default();
        let mut buf = BytesMut::new();
        // Feed only the first 10 bytes of a 14-byte message.
        buf.extend_from_slice(&good_wire[..10]);

        assert_eq!(codec.decode(&mut buf), Ok(None));
        // Buffer is preserved untouched while we wait for more data.
        assert_eq!(&buf[..], &good_wire[..10]);

        // Deliver the remaining 4 bytes; the next decode should yield the message.
        buf.extend_from_slice(&good_wire[10..]);
        assert_eq!(codec.decode(&mut buf), Ok(Some(good_msg)));
        assert!(buf.is_empty());
    }

    /// A length value larger than what the BMP spec can ever produce
    /// (e.g. `u32::MAX`) is structurally legal in the header but the codec
    /// must not allocate or split anything until enough bytes arrive — it
    /// just keeps waiting.
    #[test]
    fn test_extreme_length_does_not_split_prematurely() {
        let mut codec = BmpCodec::default();
        let mut buf = BytesMut::new();
        // version=3, length=u32::MAX, plus a couple of payload bytes.
        buf.extend_from_slice(&[0x03u8, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01]);
        let before_len = buf.len();
        assert_eq!(codec.decode(&mut buf), Ok(None));
        assert_eq!(
            buf.len(),
            before_len,
            "decode must not consume bytes while waiting for the rest of the message",
        );
    }

    #[test]
    fn test_codec() -> Result<(), BmpMessageWritingError> {
        let msg = BmpMessage::V3(v3::BmpMessageValue::Initiation(v3::InitiationMessage::new(
            vec![
                InitiationInformation::SystemDescription("test11".to_string()),
                InitiationInformation::SystemName("PE2".to_string()),
            ],
        )));
        let mut code = BmpCodec::default();
        let mut buf = BytesMut::with_capacity(msg.len());
        let mut empty_buf = BytesMut::with_capacity(msg.len());
        let mut error_buf = BytesMut::from(&[0xffu8, 0x00u8, 0x00u8, 0x00u8, 0x01u8, 0xffu8][..]);

        code.encode(msg.clone(), &mut buf)?;
        let decode = code.decode(&mut buf);
        let decode_empty = code.decode(&mut empty_buf);
        let decode_error = code.decode(&mut error_buf);

        assert!(decode.is_ok());
        assert_eq!(decode.unwrap(), Some(msg));
        assert!(decode_empty.is_ok());
        assert_eq!(decode_empty.unwrap(), None);
        assert!(decode_error.is_err());
        Ok(())
    }

    #[test]
    fn test_peer_key_add_remove() -> Result<(), BmpMessageWritingError> {
        let peer_header = PeerHeader::new(
            BmpPeerType::GlobalInstancePeer {
                ipv6: true,
                post_policy: false,
                asn2: false,
                adj_rib_out: false,
            },
            None,
            Some(IpAddr::V6(Ipv6Addr::from_str("fc00::1").unwrap())),
            64512,
            Ipv4Addr::new(10, 0, 0, 1),
            Some(Utc.timestamp_opt(1664821826, 645593000).unwrap()),
        );

        let peer_up = BmpMessage::V3(v3::BmpMessageValue::PeerUpNotification(
            v3::PeerUpNotificationMessage::build(
                peer_header.clone(),
                Some(IpAddr::V6(Ipv6Addr::from_str("fc00::3").unwrap())),
                Some(179),
                Some(29834),
                BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    Ipv4Addr::new(10, 0, 0, 3),
                    Box::new([
                        BgpOpenMessageParameter::Capabilities(Box::new([
                            BgpCapability::MultiProtocolExtensions(
                                MultiProtocolExtensionsCapability::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                ),
                            ),
                        ])),
                        BgpOpenMessageParameter::Capabilities(Box::new([
                            BgpCapability::FourOctetAs(FourOctetAsCapability::new(64512)),
                        ])),
                        BgpOpenMessageParameter::Capabilities(Box::new([
                            BgpCapability::ExtendedNextHopEncoding(
                                ExtendedNextHopEncodingCapability::new(vec![
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Unicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Multicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4MplsLabeledVpn,
                                        AddressFamily::IPv6,
                                    ),
                                ]),
                            ),
                        ])),
                    ]),
                )),
                BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    Ipv4Addr::new(10, 0, 0, 1),
                    vec![
                        BgpOpenMessageParameter::Capabilities(Box::new([
                            BgpCapability::MultiProtocolExtensions(
                                MultiProtocolExtensionsCapability::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                ),
                            ),
                        ])),
                        BgpOpenMessageParameter::Capabilities(Box::new([
                            BgpCapability::FourOctetAs(FourOctetAsCapability::new(64512)),
                        ])),
                        BgpOpenMessageParameter::Capabilities(Box::new([
                            BgpCapability::ExtendedNextHopEncoding(
                                ExtendedNextHopEncodingCapability::new(vec![
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Unicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Multicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4MplsLabeledVpn,
                                        AddressFamily::IPv6,
                                    ),
                                ]),
                            ),
                        ])),
                    ]
                    .into_boxed_slice(),
                )),
                vec![],
            )
            .unwrap(),
        ));

        let peer_down = BmpMessage::V3(v3::BmpMessageValue::PeerDownNotification(
            v3::PeerDownNotificationMessage::build(
                peer_header.clone(),
                PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(2),
            )
            .unwrap(),
        ));

        let terminate = BmpMessage::V3(v3::BmpMessageValue::Termination(
            v3::TerminationMessage::new(vec![TerminationInformation::String("test".to_string())]),
        ));

        let mut codec = BmpCodec::default();
        let peer_key = PeerKey::from_peer_header(&peer_header);
        // Check initially empty
        assert!(!codec.ctx.contains_key(&peer_key));

        // Check peer registered correctly
        codec.update_parsing_ctx(&peer_up);
        assert!(codec.ctx.contains_key(&peer_key));

        // Check peer removed after a Peer Down Message
        codec.update_parsing_ctx(&peer_down);
        assert!(!codec.ctx.contains_key(&peer_key));

        // Register again
        codec.update_parsing_ctx(&peer_up);
        assert!(codec.ctx.contains_key(&peer_key));

        // Check peer removed after a terminate message
        codec.update_parsing_ctx(&terminate);
        assert!(!codec.ctx.contains_key(&peer_key));
        Ok(())
    }

    #[test]
    fn test_multiple_peer_up_for_loc_rib() {
        // announces add path for IPv4
        let up1_wire = vec![
            0x04, 0x00, 0x00, 0x00, 0xa6, 0x03, 0x03, 0x80, 0x00, 0x02, 0xfb, 0xf0, 0x00, 0x30,
            0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x30, 0xcb, 0x00, 0x71, 0x30, 0x68, 0x9a,
            0xf6, 0x17, 0x00, 0x07, 0xf7, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02,
            0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x45,
            0x04, 0x00, 0x01, 0x01, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00,
            0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02, 0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30,
            0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x45, 0x04, 0x00, 0x01, 0x01, 0x03,
        ];

        // announces add path for IPv6
        let up2_wire = vec![
            0x04, 0x00, 0x00, 0x00, 0xa6, 0x03, 0x03, 0x80, 0x00, 0x02, 0xfb, 0xf0, 0x00, 0x30,
            0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x30, 0xcb, 0x00, 0x71, 0x30, 0x68, 0x9a,
            0xf6, 0x17, 0x00, 0x07, 0xf7, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02,
            0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x45,
            0x04, 0x00, 0x02, 0x01, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00,
            0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02, 0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30,
            0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x45, 0x04, 0x00, 0x02, 0x01, 0x03,
        ];

        let peer_key = PeerKey::new(
            None,
            BmpPeerType::LocRibInstancePeer { filtered: true },
            Some(RouteDistinguisher::As4Administrator {
                asn4: 4226809904,
                number: 23,
            }),
            4226809904,
            Ipv4Addr::new(203, 0, 113, 48),
        );
        let mut codec = BmpCodec::default();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&up1_wire);
        buf.extend_from_slice(&up2_wire);

        // check after each decoded BGP open the ADD Path ctx is including the new
        // address family
        let _ = codec
            .decode(&mut buf)
            .expect("decode up1_wire failed")
            .expect("no message decoded from up1");
        // Only IPv4 add path is added to the BGP decoding context for the first peer up
        // message
        let add_path1 = codec
            .ctx
            .get_peer(&peer_key)
            .expect("peer lookup failed")
            .add_path();
        assert_eq!(
            add_path1,
            &HashMap::from([(AddressType::Ipv4Unicast, true)])
        );
        let _ = codec
            .decode(&mut buf)
            .expect("decode up1_wire failed")
            .expect("no message decoded from up2");
        // IPv6 add path is added to the BGP decoding context without deleting the add
        // path for IPv4
        let add_path2 = codec
            .ctx
            .get_peer(&peer_key)
            .expect("peer lookup failed")
            .add_path();
        assert_eq!(
            add_path2,
            &HashMap::from([
                (AddressType::Ipv4Unicast, true),
                (AddressType::Ipv6Unicast, true)
            ])
        );
    }
}

#[cfg(test)]
mod add_path_negotiation_tests {
    use super::*;
    use crate::PeerHeader;

    use netgauze_bgp_pkt::capabilities::{AddPathAddressFamily, AddPathCapability};
    use netgauze_bgp_pkt::open::{BgpOpenMessage, BgpOpenMessageParameter};
    use netgauze_iana::address_family::AddressType;
    use std::net::{IpAddr, Ipv4Addr};

    /// Same as [`negotiated_add_path`] but wrapped in a v4 message.
    fn negotiated_add_path_v4(
        local: (bool, bool),
        remote: (bool, bool),
        adj_rib_out: bool,
    ) -> bool {
        let (peer_up, key) = build_peer_up(local, remote, adj_rib_out);
        let mut ctx = BmpParsingContext::default();
        ctx.update(&BmpMessage::V4(v4::BmpMessageValue::PeerUpNotification(
            peer_up,
        )));
        ctx.get_peer(&key)
            .and_then(|c| c.add_path().get(&AddressType::Ipv4Unicast).copied())
            .unwrap_or(false)
    }

    /// Reports what the parsing context concludes for a v3 Peer Up.
    fn negotiated_add_path(local: (bool, bool), remote: (bool, bool), adj_rib_out: bool) -> bool {
        let (peer_up, key) = build_peer_up(local, remote, adj_rib_out);
        let mut ctx = BmpParsingContext::default();
        ctx.update(&BmpMessage::V3(v3::BmpMessageValue::PeerUpNotification(
            peer_up,
        )));
        ctx.get_peer(&key)
            .and_then(|c| c.add_path().get(&AddressType::Ipv4Unicast).copied())
            .unwrap_or(false)
    }

    /// Builds a Peer Up where both OPENs advertise ADD-PATH with the given
    /// send/receive flags.
    fn build_peer_up(
        local: (bool, bool),
        remote: (bool, bool),
        adj_rib_out: bool,
    ) -> (v3::PeerUpNotificationMessage, PeerKey) {
        let mk = |asn: u32, id: Ipv4Addr, (send, receive): (bool, bool)| {
            BgpOpenMessage::new(
                asn as u16,
                180,
                id,
                Box::new([BgpOpenMessageParameter::Capabilities(Box::new([
                    BgpCapability::AddPath(AddPathCapability::new(vec![
                        AddPathAddressFamily::new(AddressType::Ipv4Unicast, send, receive),
                    ])),
                ]))]),
            )
        };
        let peer_header = PeerHeader::new(
            BmpPeerType::GlobalInstancePeer {
                ipv6: false,
                post_policy: false,
                asn2: false,
                adj_rib_out,
            },
            None,
            Some(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 12))),
            65002,
            Ipv4Addr::new(2, 2, 2, 2),
            None,
        );
        let peer_up = v3::PeerUpNotificationMessage::build(
            peer_header,
            Some(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 11))),
            Some(179),
            Some(51652),
            BgpMessage::Open(mk(65001, Ipv4Addr::new(1, 1, 1, 1), local)),
            BgpMessage::Open(mk(65002, Ipv4Addr::new(2, 2, 2, 2), remote)),
            vec![],
        )
        .expect("valid peer up");

        let key = PeerKey::from_peer_header(peer_up.peer_header());
        (peer_up, key)
    }

    /// v4 Peer Up messages share `handle_peer_up` with v3, so the directional
    /// negotiation must hold for them too.
    #[test]
    fn v4_peer_up_uses_the_same_directional_negotiation() {
        assert!(
            !negotiated_add_path_v4((false, true), (false, true), false),
            "ADD-PATH must be off for a v4 peer that advertised send=false"
        );
        assert!(
            negotiated_add_path_v4((false, true), (true, false), false),
            "ADD-PATH must be on when the v4 peer sends and we receive"
        );
    }

    /// Exactly the FRR case: both routers advertise "I can receive additional
    /// paths, I cannot send them". Neither side ever puts a Path Identifier on
    /// the wire, so the parser must NOT expect one.
    #[test]
    fn both_receive_only_means_add_path_is_not_in_use() {
        // adj-rib-in: the UPDATE came *from* the remote peer, which advertised
        // send=false, so there are no Path Identifiers to parse.
        assert!(
            !negotiated_add_path((false, true), (false, true), false),
            "ADD-PATH must be off for adj-rib-in when the remote peer cannot send"
        );
        // adj-rib-out: we send to the peer; we advertised send=false.
        assert!(
            !negotiated_add_path((false, true), (false, true), true),
            "ADD-PATH must be off for adj-rib-out when we cannot send"
        );
    }

    #[test]
    fn add_path_in_use_only_when_sender_can_send_and_receiver_can_receive() {
        // adj-rib-in: remote sends, we receive -> in use
        assert!(negotiated_add_path((false, true), (true, false), false));
        // adj-rib-in: remote sends but we did not ask to receive -> not in use
        assert!(!negotiated_add_path((false, false), (true, false), false));
        // adj-rib-out: we send, remote receives -> in use
        assert!(negotiated_add_path((true, false), (false, true), true));
        // adj-rib-out: we cannot send -> not in use
        assert!(!negotiated_add_path((false, true), (false, true), true));
    }
}
