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

use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use netgauze_bmp_pkt::{
    serde::{deserializer::BmpMessageParsingError, serializer::BmpMessageWritingError},
    BmpMessage,
};
use netgauze_parse_utils::{LocatedParsingError, ReadablePDU, Span, WritablePDU};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug)]
pub enum BmpCodecDecoderError {
    IoError(std::io::Error),
    Incomplete(nom::Needed),
    BmpMessageParsingError(BmpMessageParsingError),
}

impl From<std::io::Error> for BmpCodecDecoderError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error)
    }
}

/// Encoder and Decoder for [BmpMessage]
#[derive(Debug)]
pub struct BmpCodec;

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
        if buf.len() >= 5 {
            let length = NetworkEndian::read_u32(&buf[1..5]) as usize;
            if buf.len() < length {
                Ok(None)
            } else {
                let (span, msg) = match BmpMessage::from_wire(Span::new(buf)) {
                    Ok((span, msg)) => (span, msg),
                    Err(error) => {
                        let tmp = match error {
                            nom::Err::Incomplete(_needed) => todo!(),
                            nom::Err::Error(error) => error.error().clone(),
                            nom::Err::Failure(error) => error.error().clone(),
                        };
                        return Err(BmpCodecDecoderError::BmpMessageParsingError(tmp));
                    }
                };
                buf.advance(span.location_offset());
                Ok(Some(msg))
            }
        } else {
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
        let mut code = BmpCodec;
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
