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

use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use netgauze_bmp_pkt::{
    iana::BmpVersion,
    wire::{deserializer::BmpMessageParsingError, serializer::BmpMessageWritingError},
    BmpMessage,
};
use netgauze_parse_utils::{LocatedParsingError, ReadablePDU, Span, WritablePDU};
use nom::Needed;
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// Min length for a valid BMP Message: 1-octet version + 4-octet length
pub(crate) const BMP_MESSAGE_MIN_LENGTH: usize = 5;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
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

/// Encoder and Decoder for [BmpMessage]
#[derive(Debug, Default)]
pub struct BmpCodec {
    /// Helper to track in the decoder if we are inside a BMP message or not
    in_message: bool,
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
                let msg = match BmpMessage::from_wire(Span::new(buf)) {
                    Ok((span, msg)) => {
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
    use netgauze_bmp_pkt::*;

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
}
