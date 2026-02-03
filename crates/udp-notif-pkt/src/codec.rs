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

use crate::raw::{MediaType, UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket};
use crate::wire::deserialize::{LocatedUdpNotifPacketParsingError, UdpNotifPacketParsingError};
use crate::wire::serialize::UdpNotifPacketWritingError;
use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use netgauze_parse_utils::{LocatedParsingError, ReadablePdu, Span, WritablePdu};
use nom::error::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::time::{Duration, Instant};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, strum_macros::Display, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum ReassemblyBufferError {
    #[strum(
        to_string = "UDP-Notif packet with last segment marker is not received fot the packet with \
         media-type={media_type}, publisher-id={publisher_id}, and message-id={message_id} and the \
         total number of segments received are {received}"
    )]
    LastSegmentIsNotReceived {
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        received: usize,
    },

    #[strum(
        to_string = "UDP-Notif packet with incomplete number of segments, media-type={media_type}, \
        publisher-id={publisher_id}, and message-id={message_id} and the total number of segments \
        received are {received}"
    )]
    IncompleteSegments {
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        needed: u16,
        received: u16,
    },

    #[strum(
        to_string = "UDP-Notif packet with incorrect segment sequence, media-type={media_type}, \
        publisher-id={publisher_id}, and message-id={message_id} received {received} segments in \
        total and is missing a packet with sequence number {missing_segment_number}"
    )]
    MissingSegment {
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        received: usize,
        missing_segment_number: u16,
    },
}

impl std::error::Error for ReassemblyBufferError {}

#[derive(Debug)]
struct ReassemblyBuffer {
    timestamp: Instant,
    has_last: bool,
    expected_count: u16,
    segments: BTreeMap<u16, UdpNotifPacket>,
}

impl ReassemblyBuffer {
    fn is_timed_out(&self, timeout_duration: Duration) -> bool {
        Instant::now().duration_since(self.timestamp) > timeout_duration
    }

    fn add_segment(&mut self, segment_number: u16, packet: UdpNotifPacket, is_last: bool) {
        if is_last {
            self.expected_count = segment_number + 1;
            self.has_last = true;
        }
        self.segments.insert(segment_number, packet);
    }

    #[inline]
    fn ready_to_reassemble(&self) -> bool {
        self.has_last && self.segments.len() == self.expected_count as usize
    }

    fn reassemble(
        mut self,
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
    ) -> Result<UdpNotifPacket, ReassemblyBufferError> {
        if !self.has_last {
            let number_of_received_segments = self.segments.len();
            return Err(ReassemblyBufferError::LastSegmentIsNotReceived {
                media_type,
                publisher_id,
                message_id,
                received: number_of_received_segments,
            });
        }
        if self.expected_count as usize != self.segments.len() {
            return Err(ReassemblyBufferError::IncompleteSegments {
                media_type,
                publisher_id,
                message_id,
                needed: self.expected_count,
                received: self.segments.len() as u16,
            });
        }
        for (expected_number, (seg_no, _)) in self.segments.iter().enumerate() {
            if expected_number != *seg_no as usize {
                let received = self.segments.len();
                return Err(ReassemblyBufferError::MissingSegment {
                    media_type,
                    publisher_id,
                    message_id,
                    received,
                    missing_segment_number: *seg_no,
                });
            }
        }
        let (_, first_segment) = self.segments.pop_first().unwrap();
        let mut assembled_payload = BytesMut::from(first_segment.payload());
        let mut options = HashMap::new();
        self.segments.into_iter().for_each(|(_, pkt)| {
            for (k, opt) in pkt.options() {
                if k != &UdpNotifOptionCode::Segment {
                    options.insert(k.clone(), opt.clone());
                }
            }
            assembled_payload.unsplit(BytesMut::from(pkt.payload()))
        });
        Ok(UdpNotifPacket::new(
            first_segment.media_type(),
            first_segment.publisher_id(),
            first_segment.message_id(),
            options,
            assembled_payload.freeze(),
        ))
    }
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            has_last: false,
            expected_count: 1,
            segments: BTreeMap::new(),
        }
    }
}

#[derive(Debug, strum_macros::Display, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum UdpPacketCodecError {
    #[strum(to_string = "I/O error {0}")]
    IoError(String),

    #[strum(to_string = "Invalid UDP-Notif header length {0}")]
    InvalidHeaderLength(u8),

    #[strum(to_string = "Invalid UDP-Notif message length {0}")]
    InvalidMessageLength(u16),

    #[strum(to_string = "UDP-Notif packet parsing error: {0}")]
    UdpNotifError(UdpNotifPacketParsingError),

    #[strum(to_string = "segments reassembly error: {0}")]
    ReassemblyError(ReassemblyBufferError),

    #[strum(to_string = "UDP-Notif serialization error: {0}")]
    WritingError(UdpNotifPacketWritingError),
}

impl<'a> From<nom::Err<LocatedUdpNotifPacketParsingError<'a>>> for UdpPacketCodecError {
    fn from(err: nom::Err<LocatedUdpNotifPacketParsingError<'a>>) -> Self {
        match err {
            nom::Err::Incomplete(_) => {
                Self::UdpNotifError(UdpNotifPacketParsingError::NomError(ErrorKind::Eof))
            }
            nom::Err::Error(err) | nom::Err::Failure(err) => {
                Self::UdpNotifError(err.error().clone())
            }
        }
    }
}

impl From<ReassemblyBufferError> for UdpPacketCodecError {
    fn from(value: ReassemblyBufferError) -> Self {
        Self::ReassemblyError(value)
    }
}

impl std::error::Error for UdpPacketCodecError {}

impl From<io::Error> for UdpPacketCodecError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<UdpNotifPacketWritingError> for UdpPacketCodecError {
    fn from(e: UdpNotifPacketWritingError) -> Self {
        Self::WritingError(e)
    }
}

#[derive(Debug, Default)]
pub struct UdpPacketCodec {
    in_message: bool,
    incomplete_messages: HashMap<(u32, u32), ReassemblyBuffer>,
}

impl UdpPacketCodec {
    pub fn cleanup_timed_out_messages(&mut self, duration: Duration) {
        self.incomplete_messages
            .retain(|_, buf| !buf.is_timed_out(duration));
    }

    pub fn clean_timed_out_packets(&mut self, duration: Duration) {
        self.incomplete_messages
            .retain(|_, buf| !buf.is_timed_out(duration));
    }

    #[inline]
    fn check_len(&mut self, buf: &BytesMut) -> Result<Option<(u8, u16)>, UdpPacketCodecError> {
        let min_header_length = 12;
        if !self.in_message && buf.len() < min_header_length as usize {
            // Not enough data yet to read even the header
            return Ok(None);
        }
        let header_len = buf[1];
        if header_len < min_header_length {
            return Err(UdpPacketCodecError::InvalidHeaderLength(header_len));
        }
        if buf.len() < header_len as usize {
            // Not enough data to read the header yet
            self.in_message = true;
            return Ok(None);
        }
        let message_length = NetworkEndian::read_u16(&buf[2..4]);
        if message_length < header_len as u16 {
            return Err(UdpPacketCodecError::InvalidMessageLength(message_length));
        }
        if buf.len() < message_length as usize {
            // Not enough data to read the full message yet
            self.in_message = true;
            return Ok(None);
        }
        Ok(Some((header_len, message_length)))
    }

    #[inline]
    fn extract_segment_info(options: &HashMap<UdpNotifOptionCode, UdpNotifOption>) -> (u16, bool) {
        options
            .get(&UdpNotifOptionCode::Segment)
            .map(|opt| {
                if let UdpNotifOption::Segment { number, last } = opt {
                    (*number, *last)
                } else {
                    unreachable!()
                }
            })
            .unwrap_or((0, options.is_empty()))
    }

    #[inline]
    fn try_reassemble_segments(
        &mut self,
        pkt: UdpNotifPacket,
    ) -> Result<Option<UdpNotifPacket>, UdpPacketCodecError> {
        let (seg_no, is_last) = Self::extract_segment_info(pkt.options());
        let media_type = pkt.media_type();
        let publisher_id = pkt.publisher_id();
        let message_id = pkt.message_id();

        // Short-circuit for unsegmented or single-segment messages
        if seg_no == 0 && is_last {
            return Ok(Some(pkt));
        }

        let message_key = (pkt.publisher_id(), pkt.message_id());
        let reassembly_buf = self.incomplete_messages.entry(message_key).or_default();
        reassembly_buf.add_segment(seg_no, pkt, is_last);
        if !reassembly_buf.ready_to_reassemble() {
            return Ok(None);
        }

        let reassembled = self.incomplete_messages.remove(&message_key).unwrap();
        Ok(Some(reassembled.reassemble(
            media_type,
            publisher_id,
            message_id,
        )?))
    }
}

impl Decoder for UdpPacketCodec {
    type Item = UdpNotifPacket;
    type Error = UdpPacketCodecError;

    #[inline]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (_, msg_len) = match self.check_len(buf)? {
            None => return Ok(None),
            Some(val) => val,
        };
        // consume the entire UDP packet before parsing the message
        // to avoid the parsing errors to continue if one message is corrupted
        let pkt_buf = buf.split_to(buf.len());
        match UdpNotifPacket::from_wire(Span::new(pkt_buf.chunk())) {
            Ok((span, pkt)) => {
                self.in_message = false;
                // Check that the message length matches the actual length of the message
                if span.location_offset() != msg_len as usize || !span.is_empty() {
                    return Err(UdpPacketCodecError::InvalidMessageLength(msg_len));
                }
                self.try_reassemble_segments(pkt)
            }
            Err(err) => {
                self.in_message = false;
                Err(err)?
            }
        }
    }
}

impl Encoder<UdpNotifPacket> for UdpPacketCodec {
    type Error = UdpPacketCodecError;

    fn encode(&mut self, pkt: UdpNotifPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut writer = dst.writer();
        pkt.write(&mut writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::MediaType;
    use bytes::Bytes;
    #[test]
    fn test_decode() {
        let mut codec = UdpPacketCodec::default();
        let value: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x0c, // Header length
            0x00, 0x0e, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // dummy payload
        ];
        let pkt = UdpNotifPacket::new(
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(&[0xff, 0xff][..]),
        );
        let mut buf = BytesMut::from(&value[..]);

        let value = codec.decode(&mut buf);
        assert_eq!(value, Ok(Some(pkt)))
    }

    #[test]
    fn test_encode() {
        let mut codec = UdpPacketCodec::default();
        let expected: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x0c, // Header length
            0x00, 0x0e, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // dummy payload
        ];
        let pkt = UdpNotifPacket::new(
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(&[0xff, 0xff][..]),
        );
        let mut buf = BytesMut::new();
        codec.encode(pkt, &mut buf).expect("encode failed");
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_decode_segmented() {
        let mut codec = UdpPacketCodec::default();
        let value_wire1: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x14, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not the last segment
            0xff, 0xff, 0xff, 0xff, // dummy payload
        ];
        let value_wire2: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x18, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x03, // segment 1, last segment
            0xee, 0xee, 0xee, 0xee, // dummy payload
            0xdd, 0xdd, 0xdd, 0xdd, // dummy payload
        ];

        let mut buf = BytesMut::from(&value_wire1[..]);
        let value1 = codec.decode(&mut buf);
        buf.extend_from_slice(&value_wire2[..]);
        let value2 = codec.decode(&mut buf);

        assert!(matches!(value1, Ok(None)));
        assert_eq!(
            value2,
            Ok(Some(UdpNotifPacket::new(
                MediaType::YangDataJson,
                0x01000001,
                0x02000002,
                HashMap::new(),
                Bytes::from(
                    &[
                        0xff, 0xff, 0xff, 0xff, // payload from the first segment
                        0xee, 0xee, 0xee, 0xee, // payload from the second segment
                        0xdd, 0xdd, 0xdd, 0xdd,
                    ][..]
                ),
            )))
        )
    }

    #[test]
    fn test_decode_unordered_segmented() {
        let mut codec = UdpPacketCodec::default();
        let value_wire1: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x18, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x03, // segment 1, last segment
            0xee, 0xee, 0xee, 0xee, // dummy payload
            0xdd, 0xdd, 0xdd, 0xdd, // dummy payload
        ];
        let value_wire2: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x14, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not the last segment
            0xff, 0xff, 0xff, 0xff, // dummy payload
        ];

        let mut buf = BytesMut::from(&value_wire1[..]);

        let value1 = codec.decode(&mut buf);

        buf.extend_from_slice(&value_wire2[..]);
        let value2 = codec.decode(&mut buf);

        assert!(matches!(value1, Ok(None)));
        assert_eq!(
            value2,
            Ok(Some(UdpNotifPacket::new(
                MediaType::YangDataJson,
                0x01000001,
                0x02000002,
                HashMap::new(),
                Bytes::from(
                    &[
                        0xff, 0xff, 0xff, 0xff, // payload from the first segment
                        0xee, 0xee, 0xee, 0xee, // payload from the second segment
                        0xdd, 0xdd, 0xdd, 0xdd,
                    ][..]
                ),
            )))
        )
    }
}
