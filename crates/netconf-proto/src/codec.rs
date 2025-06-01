// Copyright (C) 2025-present The NetGauze Authors.
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
    protocol::{Hello, NetConfMessage},
    xml_parser::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
};
use quick_xml::NsReader;
use std::fmt::Display;
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::{Decoder, Encoder},
};

const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
const HELLO_TERMINATOR: &str = "]]>]]>";
const CHUNK_START: &str = "\n#";
const MESSAGE_TERMINATOR: &str = "\n##\n";
const MAX_CHUNK_SIZE: usize = 4294967295; // Maximum chunk size as per RFC 6242
const MAX_CHUNK_SIZE_LEN: usize = 10; // Maximum length of chunk size in characters

#[derive(Debug)]
pub struct SshCodec {
    in_hello: bool,
    buf: BytesMut,
}

impl SshCodec {
    pub fn new() -> Self {
        Self {
            in_hello: true,
            buf: BytesMut::new(),
        }
    }
}

impl Default for SshCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum SshCodecError {
    IO(std::io::Error),
    Utf(std::str::Utf8Error),
    Int(std::num::ParseIntError),
    Parsing(ParsingError),
}

impl From<std::io::Error> for SshCodecError {
    fn from(err: std::io::Error) -> SshCodecError {
        SshCodecError::IO(err)
    }
}

impl Display for SshCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IO(err) => write!(f, "{err}"),
            Self::Utf(err) => write!(f, "{err}"),
            Self::Int(err) => write!(f, "{err}"),
            Self::Parsing(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SshCodecError {}

impl From<std::str::Utf8Error> for SshCodecError {
    fn from(value: std::str::Utf8Error) -> Self {
        Self::Utf(value)
    }
}

impl From<std::num::ParseIntError> for SshCodecError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::Int(value)
    }
}

impl From<ParsingError> for SshCodecError {
    fn from(value: ParsingError) -> Self {
        Self::Parsing(value)
    }
}

impl Decoder for SshCodec {
    type Item = NetConfMessage;
    type Error = SshCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.in_hello {
            let pos = src
                .windows(HELLO_TERMINATOR.len())
                .position(|w| w == HELLO_TERMINATOR.as_bytes());
            if let Some(pos) = pos {
                let data = src.split_to(pos + HELLO_TERMINATOR.len());
                let data = &data[..pos];
                let reader = NsReader::from_reader(data);
                let mut xml_parser = XmlParser::new(reader)?;
                let hello = Hello::xml_deserialize(&mut xml_parser)?;
                self.in_hello = false;
                return Ok(Some(NetConfMessage::Hello(hello)));
            }
            return Ok(None);
        }

        loop {
            // Check if we have enough data for chunk start
            if src.len() < CHUNK_START.len() + MAX_CHUNK_SIZE_LEN + 1 {
                return Ok(None);
            }

            // Verify the chunk start sequence
            if !src.starts_with(CHUNK_START.as_bytes()) {
                return Err(SshCodecError::IO(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected chunk start sequence or message terminator",
                )));
            }

            // Find the end of chunk size field
            let size_start = CHUNK_START.len();
            // Look for the new line character after the chunk size
            // RFC 6242 specifies that max size is 4294967295, so we can safely assume
            // the size field will not exceed 11 characters (including the newline).
            let size_end = src[size_start..size_start + MAX_CHUNK_SIZE_LEN + 1]
                .iter()
                .position(|&b| b == b'\n');
            let size_end = match size_end {
                Some(pos) => size_start + pos,
                None => {
                    return Err(SshCodecError::IO(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Chunk size is not properly terminated with a newline",
                    )))
                }
            };

            // Parse chunk size
            let chunk_size_slice = &src[size_start..size_end];
            let chunk_size_str = std::str::from_utf8(chunk_size_slice)?;
            let chunk_size = chunk_size_str.parse::<usize>()?;

            // Validate chunk size per RFC 6242
            if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
                return Err(SshCodecError::IO(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid chunk size: {chunk_size}"),
                )));
            }

            // Check if we have the complete chunk
            let chunk_start_pos = size_end + 1; // +1 for the LF after size
            if src.len() < chunk_start_pos + chunk_size {
                return Ok(None); // Need more data
            }

            // Extract chunk data
            let chunk_data = &src[chunk_start_pos..chunk_start_pos + chunk_size];

            self.buf.extend_from_slice(chunk_data);

            // Advance past this chunk
            src.advance(chunk_start_pos + chunk_size);

            // Check for message terminator
            if src.starts_with(MESSAGE_TERMINATOR.as_bytes()) {
                let data = self.buf.split();
                let reader = NsReader::from_reader(data.reader());
                let mut xml_parser = XmlParser::new(reader)?;
                let parsed = NetConfMessage::xml_deserialize(&mut xml_parser)?;
                src.advance(MESSAGE_TERMINATOR.len());
                return Ok(Some(parsed));
            }
        }
    }
}

impl Encoder<NetConfMessage> for SshCodec {
    type Error = SshCodecError;
    fn encode(&mut self, item: NetConfMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let buf = std::io::Cursor::new(Vec::new());
        let writer = quick_xml::writer::Writer::new_with_indent(buf, b' ', 2);
        let mut xml_writer = XmlWriter::new(writer);
        item.xml_serialize(&mut xml_writer).unwrap();
        let buf = xml_writer.inner.into_inner().into_inner();
        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::debug!("Serialized payload: `{}`", std::str::from_utf8(&buf)?);
        }
        log::info!("Serialized payload: `{}`", std::str::from_utf8(&buf)?);
        if let NetConfMessage::Hello(_) = item {
            dst.extend_from_slice(XML_HEADER.as_bytes());
            dst.extend_from_slice(&buf);
            dst.extend_from_slice(HELLO_TERMINATOR.as_bytes());
        } else {
            let size = buf.len();
            dst.extend_from_slice(format!("{CHUNK_START}{size}\n").as_bytes());
            dst.extend_from_slice(&buf);
            dst.extend_from_slice(MESSAGE_TERMINATOR.as_bytes());
        }
        log::info!(
            "Packaged Serialized payload:\n{}",
            std::str::from_utf8(dst)?
        );
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::Rpc;

    #[test]
    fn test_chunks_decoding() {
        let input = r#"
#4
<rpc
#18
 message-id="102"

#79
     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <close-session/>
</rpc>
##
"#;
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();
        codec.in_hello = false;

        let result = codec.decode(&mut buf);
        assert!(
            matches!(result, Ok(Some(_))),
            "fourth chunk should be Some, found {result:?}"
        );
        assert_eq!(
            result.unwrap().unwrap(),
            NetConfMessage::Rpc(Rpc {
                message_id: "102".to_string(),
                operation: "\n  <close-session/>\n".to_string(),
            })
        );
    }
}
