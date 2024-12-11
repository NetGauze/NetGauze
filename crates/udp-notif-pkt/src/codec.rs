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

use crate::{
    wire::deserialize::{LocatedUdpNotifPacketParsingError, UdpNotifPacketParsingError},
    UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket,
};
use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BytesMut};
use netgauze_parse_utils::{LocatedParsingError, ReadablePdu, Span};
use nom::error::ErrorKind;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    time::{Duration, Instant},
};
use tokio_util::codec::Decoder;

#[derive(Debug, strum_macros::Display, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum ReassemblyBufferError {
    LastSegmentIsNotReceived,
    NotEnoughSegments { needed: u16, received: u16 },
    IncorrectSegments,
}

impl std::error::Error for ReassemblyBufferError {}

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

    fn reassemble(mut self) -> Result<UdpNotifPacket, ReassemblyBufferError> {
        if !self.has_last {
            return Err(ReassemblyBufferError::LastSegmentIsNotReceived);
        }
        if self.expected_count as usize != self.segments.len() {
            return Err(ReassemblyBufferError::NotEnoughSegments {
                needed: self.expected_count,
                received: self.segments.len() as u16,
            });
        }
        let mismatch = self
            .segments
            .iter()
            .enumerate()
            .any(|(i, (seg_no, _))| i != *seg_no as usize);
        if mismatch {
            return Err(ReassemblyBufferError::IncorrectSegments);
        }
        let (_, first_segment) = self.segments.pop_first().unwrap();
        let mut assembled_payload = BytesMut::from(first_segment.payload);
        let mut options = HashMap::new();
        self.segments.into_iter().for_each(|(_, pkt)| {
            for (k, opt) in pkt.options() {
                if k != &UdpNotifOptionCode::Segment {
                    options.insert(k.clone(), opt.clone());
                }
            }
            assembled_payload.unsplit(BytesMut::from(pkt.payload))
        });
        Ok(UdpNotifPacket::new(
            first_segment.s_flag,
            first_segment.media_type,
            first_segment.publisher_id,
            first_segment.message_id,
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
    IoError(String),
    InvalidHeaderLength(u8),
    InvalidMessageLength(u16),
    UdpNotifError(UdpNotifPacketParsingError),
    ReassemblyError(ReassemblyBufferError),
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

#[derive(Default)]
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
        Ok(Some(reassembled.reassemble()?))
    }
}

impl Decoder for UdpPacketCodec {
    type Item = UdpNotifPacket;
    type Error = UdpPacketCodecError;

    #[inline]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let _ = match self.check_len(buf)? {
            None => return Ok(None),
            Some(val) => val,
        };
        // Parse the header
        let (span, pkt) = UdpNotifPacket::from_wire(Span::new(buf))?;
        // Advance the offset to consume the entire packet
        buf.advance(span.location_offset());
        self.in_message = false;
        self.try_reassemble_segments(pkt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MediaType;
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
            false,
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
    fn test_decode_segmented() {
        let mut codec = UdpPacketCodec::default();
        let value: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x14, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not last segment
            0xff, 0xff, 0xff, 0xff, // dummy payload
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x18, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x03, // segment 1, last segment
            0xee, 0xee, 0xee, 0xee, // dummy payload
            0xdd, 0xdd, 0xdd, 0xdd, // dummy payload
        ];

        let mut buf = BytesMut::from(&value[..]);

        let value1 = codec.decode(&mut buf);
        let value2 = codec.decode(&mut buf);

        eprintln!("Decoded {value1:?}");
        assert!(matches!(value1, Ok(None)));
        assert_eq!(
            value2,
            Ok(Some(UdpNotifPacket::new(
                false,
                MediaType::YangDataJson,
                0x01000001,
                0x02000002,
                HashMap::new(),
                Bytes::from(
                    &[
                        0xff, 0xff, 0xff, 0xff, // payload from first segment
                        0xee, 0xee, 0xee, 0xee, // payload from second segment
                        0xdd, 0xdd, 0xdd, 0xdd,
                    ][..]
                ),
            )))
        )
    }
}
