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

use crate::{
    iana::BmpVersion,
    wire::{deserializer::BmpMessageParsingError, serializer::BmpMessageWritingError},
    BmpMessage, BmpMessageValue, PeerKey, PeerUpNotificationMessage,
};
use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use netgauze_bgp_pkt::{capabilities::BgpCapability, BgpMessage};
use std::collections::HashSet;

use crate::{v4::BmpV4MessageValue, wire::deserializer::BmpParsingContext};
use netgauze_bgp_pkt::capabilities::{AddPathCapability, MultipleLabel};
use netgauze_parse_utils::{LocatedParsingError, ReadablePduWithOneInput, Span, WritablePdu};
use nom::Needed;
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// Min length for a valid BMP Message: 1-octet version + 4-octet length
pub const BMP_MESSAGE_MIN_LENGTH: usize = 5;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum BmpCodecDecoderError {
    IoError(String),
    Incomplete(Option<usize>),
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
        fn handle_peer_up(ctx: &mut BmpParsingContext, peer_up: &PeerUpNotificationMessage) {
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

            // Only enable the intersection of enabled AddPath and Multi-Label
            let sent_add_path_caps: HashSet<AddPathCapability> =
                HashSet::from_iter(sent_add_path_caps);
            let received_add_path_caps: HashSet<AddPathCapability> =
                HashSet::from_iter(received_add_path_caps);
            let sent_multiple_labels_caps: HashSet<MultipleLabel> =
                HashSet::from_iter(sent_multiple_labels_caps.into_iter().flatten());
            let received_multiple_labels_caps: HashSet<MultipleLabel> =
                HashSet::from_iter(received_multiple_labels_caps.into_iter().flatten());

            let common_add_path_caps: Vec<&AddPathCapability> =
                Vec::from_iter(sent_add_path_caps.intersection(&received_add_path_caps));
            let common_multiple_labels_caps: Vec<&MultipleLabel> = Vec::from_iter(
                sent_multiple_labels_caps.intersection(&received_multiple_labels_caps),
            );

            // Add Key for the router announcing BMP to the collector
            let peer_key = PeerKey::from_peer_header(peer_up.peer_header());
            let bgp_ctx = ctx.entry(peer_key).or_default();
            bgp_ctx.add_path_mut().clear();
            bgp_ctx.multiple_labels_mut().clear();
            for add_path in &common_add_path_caps {
                bgp_ctx.update_add_path(add_path);
            }
            bgp_ctx.update_multiple_labels(common_multiple_labels_caps.iter().copied());

            // Add a key for the BGP Peer of the first router
            let peer_key = PeerKey::new(
                peer_up.peer_header().address(),
                peer_up.peer_header().peer_type(),
                peer_up.peer_header().rd(),
                peer_up.peer_header().peer_as(),
                received_open.bgp_id(),
            );
            let bgp_ctx = ctx.entry(peer_key).or_default();
            bgp_ctx.add_path_mut().clear();
            bgp_ctx.multiple_labels_mut().clear();
            for add_path in common_add_path_caps {
                bgp_ctx.update_add_path(add_path)
            }
            bgp_ctx.update_multiple_labels(common_multiple_labels_caps.iter().copied())
        }

        match msg {
            BmpMessage::V3(value) => match value {
                BmpMessageValue::PeerDownNotification(peer_down) => {
                    let peer_key = PeerKey::from_peer_header(peer_down.peer_header());
                    self.remove(&peer_key);
                }
                BmpMessageValue::Termination(_) => {
                    self.clear();
                }
                BmpMessageValue::PeerUpNotification(peer_up) => {
                    handle_peer_up(self, peer_up);
                }
                _ => {}
            },
            BmpMessage::V4(value) => match value {
                BmpV4MessageValue::PeerDownNotification { v3_notif, .. } => {
                    let peer_key = PeerKey::from_peer_header(v3_notif.peer_header());
                    self.remove(&peer_key);
                }
                BmpV4MessageValue::PeerUpNotification(peer_up) => handle_peer_up(self, peer_up),
                BmpV4MessageValue::Termination(_) => {
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
            if let Err(e) = BmpVersion::try_from(version) {
                buf.advance(1);
                return Err(BmpCodecDecoderError::BmpMessageParsingError(
                    BmpMessageParsingError::UndefinedBmpVersion(e),
                ));
            }
            // Read the length, starting form after the version
            let length = NetworkEndian::read_u32(&buf[1..BMP_MESSAGE_MIN_LENGTH]) as usize;
            if buf.len() < length {
                // We still didn't read all the bytes for the message yet
                self.in_message = true;
                Ok(None)
            } else {
                self.in_message = false;
                let msg = match BmpMessage::from_wire(Span::new(buf), &mut self.ctx) {
                    Ok((span, msg)) => {
                        self.update_parsing_ctx(&msg);
                        buf.advance(span.location_offset());
                        msg
                    }
                    Err(error) => {
                        let err = match error {
                            nom::Err::Incomplete(needed) => {
                                let needed = match needed {
                                    Needed::Unknown => None,
                                    Needed::Size(size) => Some(size.get()),
                                };
                                BmpCodecDecoderError::Incomplete(needed)
                            }
                            nom::Err::Error(error) | nom::Err::Failure(error) => {
                                BmpCodecDecoderError::BmpMessageParsingError(error.error().clone())
                            }
                        };
                        // Make sure we advance the buffer far enough, so we don't get stuck on an
                        // error value.
                        // Unfortunately, BMP doesn't have synchronization values like in BGP
                        // to understand we are in a new message.
                        buf.advance(if length < 5 { 5 } else { length });
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
    use crate::{
        v3::{InitiationInformation, PeerDownNotificationReason, TerminationInformation},
        *,
    };
    use netgauze_bgp_pkt::{
        capabilities::{
            ExtendedNextHopEncoding, ExtendedNextHopEncodingCapability, FourOctetAsCapability,
            MultiProtocolExtensionsCapability,
        },
        open::{BgpOpenMessage, BgpOpenMessageParameter},
    };
    use netgauze_iana::address_family::AddressFamily;
    use std::{net::Ipv6Addr, str::FromStr};

    #[test]
    fn test_codec() -> Result<(), BmpMessageWritingError> {
        let msg = BmpMessage::V3(BmpMessageValue::Initiation(InitiationMessage::new(vec![
            InitiationInformation::SystemDescription("test11".to_string()),
            InitiationInformation::SystemName("PE2".to_string()),
        ])));
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

        let peer_up = BmpMessage::V3(BmpMessageValue::PeerUpNotification(
            PeerUpNotificationMessage::build(
                peer_header.clone(),
                Some(IpAddr::V6(Ipv6Addr::from_str("fc00::3").unwrap())),
                Some(179),
                Some(29834),
                BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    Ipv4Addr::new(10, 0, 0, 3),
                    vec![
                        BgpOpenMessageParameter::Capabilities(vec![
                            BgpCapability::MultiProtocolExtensions(
                                MultiProtocolExtensionsCapability::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                ),
                            ),
                        ]),
                        BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                            FourOctetAsCapability::new(64512),
                        )]),
                        BgpOpenMessageParameter::Capabilities(vec![
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
                        ]),
                    ],
                )),
                BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    Ipv4Addr::new(10, 0, 0, 1),
                    vec![
                        BgpOpenMessageParameter::Capabilities(vec![
                            BgpCapability::MultiProtocolExtensions(
                                MultiProtocolExtensionsCapability::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                ),
                            ),
                        ]),
                        BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                            FourOctetAsCapability::new(64512),
                        )]),
                        BgpOpenMessageParameter::Capabilities(vec![
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
                        ]),
                    ],
                )),
                vec![],
            )
            .unwrap(),
        ));

        let peer_down = BmpMessage::V3(BmpMessageValue::PeerDownNotification(
            PeerDownNotificationMessage::build(
                peer_header.clone(),
                PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(2),
            )
            .unwrap(),
        ));

        let terminate =
            BmpMessage::V3(BmpMessageValue::Termination(TerminationMessage::new(vec![
                TerminationInformation::String("test".to_string()),
            ])));

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
}
