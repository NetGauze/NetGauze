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

//! Codec to read NETCONF in accordance with [RFC 6242](https://datatracker.ietf.org/doc/html/rfc6242).
//!
//! This codec IS NOT backward compatible with the obsoleted [RFC 4742](https://datatracker.ietf.org/doc/html/rfc4742).

use crate::{
    capabilities::{Capability, NetconfVersion},
    protocol::{Hello, NetConfMessage},
    xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
};
use quick_xml::NsReader;
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::{Decoder, Encoder},
};

const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
const HELLO_TERMINATOR: &str = "]]>]]>";
const CHUNK_START: &str = "\n#";
const MESSAGE_TERMINATOR: &str = "\n##\n";

/// Maximum chunk size as per RFC 6242
const MAX_CHUNK_SIZE: usize = 4294967295;

/// Maximum length of chunk size in characters
const MAX_CHUNK_SIZE_LEN: usize = 10;

/// SshCodec is a codec for encoding and decoding NETCONF messages over SSH as
/// per [RFC 6242](https://datatracker.ietf.org/doc/html/rfc6242).
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

#[derive(Debug, strum_macros::Display)]
pub enum SshCodecError {
    #[strum(to_string = "std::io:Error: `{0}`")]
    IO(std::io::Error),

    #[strum(to_string = "UTF decoding error: `{0}`")]
    Utf(std::str::Utf8Error),

    #[strum(to_string = "Integer decoding error: `{0}`")]
    Int(std::num::ParseIntError),

    #[strum(to_string = "NETCONF XML parsing error: `{0}`")]
    Parsing(ParsingError),

    #[strum(to_string = "XML encoding error: `{0}`")]
    Serialization(quick_xml::Error),
}

impl From<std::io::Error> for SshCodecError {
    fn from(err: std::io::Error) -> SshCodecError {
        SshCodecError::IO(err)
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

impl From<quick_xml::Error> for SshCodecError {
    fn from(value: quick_xml::Error) -> Self {
        Self::Serialization(value)
    }
}

impl PartialEq for SshCodecError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::IO(_), Self::IO(_)) => true,
            (Self::Utf(v1), Self::Utf(v2)) => v1.eq(v2),
            (Self::Int(v1), Self::Int(v2)) => v1.eq(v2),
            (Self::Parsing(v1), Self::Parsing(v2)) => v1.eq(v2),
            _ => false,
        }
    }
}

impl Decoder for SshCodec {
    type Item = NetConfMessage;
    type Error = SshCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.in_hello && src.len() >= HELLO_TERMINATOR.len() {
            let pos = src
                .windows(HELLO_TERMINATOR.len())
                .position(|w| w == HELLO_TERMINATOR.as_bytes());
            if let Some(pos) = pos {
                let data = src.split_to(pos + HELLO_TERMINATOR.len());
                let data = &data[..pos];
                if tracing::enabled!(tracing::Level::TRACE) {
                    tracing::trace!("Parsing hello message: `{:?}`", std::str::from_utf8(data));
                }
                let reader = NsReader::from_reader(data);
                let mut xml_parser = XmlParser::new(reader)?;
                let hello = Hello::xml_deserialize(&mut xml_parser)?;
                if !hello
                    .capabilities()
                    .contains(&Capability::NetconfBase(NetconfVersion::V1_1))
                {
                    return Err(SshCodecError::IO(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Hello message does not contain required base:1.1 capability, only NETCONF 1.1 as per RFC 6242 is supported",
                    )));
                }
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
                if tracing::enabled!(tracing::Level::TRACE) {
                    tracing::trace!(
                        "Parsing netconf message: `{:?}`",
                        std::str::from_utf8(&data)
                    );
                }
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
        let mut xml_writer = XmlWriter::new(
            writer,
            vec![(
                "xmlns".into(),
                "urn:ietf:params:xml:ns:netconf:base:1.0".to_string(),
            )],
        );
        item.xml_serialize(&mut xml_writer)?;
        let buf = xml_writer.into_inner().into_inner();
        if tracing::enabled!(tracing::Level::TRACE) {
            tracing::trace!("Serialized payload: `{}`", std::str::from_utf8(&buf)?);
        }
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
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        capabilities::StandardCapability,
        protocol::{Rpc, RpcOperation},
    };
    use std::collections::HashSet;

    #[test]
    fn test_hello_netconf_1_0() {
        let hello_str = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.0
    </capability>
    <capability>
      urn:ietf:params:netconf:capability:startup:1.0
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>
]]>]]>"#;
        let mut buf = BytesMut::from(hello_str);
        let mut codec = SshCodec::new();
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));
    }

    #[test]
    fn test_hello_netconf_1_1() {
        let hello_str = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.1
    </capability>
    <capability>
      urn:ietf:params:netconf:capability:startup:1.0
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>
]]>]]>"#;
        let expected = NetConfMessage::Hello(Hello::new(
            Some(4),
            HashSet::from([
                Capability::NetconfBase(NetconfVersion::V1_1),
                Capability::Standard(StandardCapability::Startup),
            ]),
        ));
        let mut buf = BytesMut::from(hello_str);
        let mut codec = SshCodec::new();
        let result = codec.decode(&mut buf);
        assert_eq!(result, Ok(Some(expected)));
    }

    #[test]
    fn test_hello_transition_with_chunks_decoding() {
        let input = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.1
    </capability>
    <capability>
      urn:ietf:params:netconf:capability:startup:1.0
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>
]]>]]>
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
        let hello_expected = Ok(Some(NetConfMessage::Hello(Hello::new(
            Some(4),
            HashSet::from([
                Capability::NetconfBase(NetconfVersion::V1_1),
                Capability::Standard(StandardCapability::Startup),
            ]),
        ))));
        let rpc_expected = Ok(Some(NetConfMessage::Rpc(Rpc::new(
            "102".into(),
            RpcOperation::Raw("\n  <close-session/>\n".into()),
        ))));
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();

        let hello_parsed = codec.decode(&mut buf);
        assert_eq!(hello_parsed, hello_expected);

        let rpc_parsed = codec.decode(&mut buf);
        assert_eq!(rpc_parsed, rpc_expected);

        let eof_parsed = codec.decode(&mut buf);
        assert_eq!(eof_parsed, Ok(None));
    }

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
        let expected = Ok(Some(NetConfMessage::Rpc(Rpc::new(
            "102".into(),
            RpcOperation::Raw("\n  <close-session/>\n".into()),
        ))));
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();
        // manually advance the codec beyond parsing the hello message
        codec.in_hello = false;

        let rpc_result = codec.decode(&mut buf);
        assert_eq!(rpc_result, expected);

        let eof_result = codec.decode(&mut buf);
        assert_eq!(eof_result, Ok(None));
    }
}
