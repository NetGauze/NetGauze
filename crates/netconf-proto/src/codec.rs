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

use crate::capabilities::{Capability, NetconfVersion};
use crate::protocol::{Hello, NetConfMessage};
use crate::xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
use quick_xml::NsReader;
use tokio_util::bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::trace;

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
                    trace!("Parsing hello message: `{:?}`", std::str::from_utf8(data));
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
            // The message terminator MUST be tested first, and at the top
            // of the loop: it may arrive in a read of its own, after the
            // last chunk was already consumed and buffered. This allows the loop
            // work across TCP/SSH segementation boundaries.
            if src.starts_with(MESSAGE_TERMINATOR.as_bytes()) {
                src.advance(MESSAGE_TERMINATOR.len());
                let data = self.buf.split();
                if tracing::enabled!(tracing::Level::TRACE) {
                    trace!(
                        "Parsing netconf message: `{:?}`",
                        std::str::from_utf8(&data)
                    );
                }
                let reader = NsReader::from_reader(data.reader());
                let mut xml_parser = XmlParser::new(reader)?;
                let parsed = NetConfMessage::xml_deserialize(&mut xml_parser)?;
                return Ok(Some(parsed));
            }
            // Below this point a chunk header is expected. Distinguishing
            // it from the terminator needs MESSAGE_TERMINATOR.len() bytes
            // which is NOT a maximal size field: demanding the theoretical
            // maximum stalls complete-but-short frames forever.
            if src.len() < MESSAGE_TERMINATOR.len() {
                // Bail out now on bytes that can become neither, instead
                // of waiting for data that would only error later.
                if !MESSAGE_TERMINATOR.as_bytes().starts_with(src)
                    && !src.starts_with(CHUNK_START.as_bytes())
                {
                    return Err(SshCodecError::IO(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Expected chunk start sequence or message terminator",
                    )));
                }
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
            // Look for the new line character after the chunk size.
            // RFC 6242 caps the size at 4294967295, so the field is at
            // most MAX_CHUNK_SIZE_LEN digits plus its newline; search no
            // further than that, and no further than what has arrived.
            let search_end = src.len().min(size_start + MAX_CHUNK_SIZE_LEN + 1);
            let size_end = src[size_start..search_end].iter().position(|&b| b == b'\n');
            let size_end = match size_end {
                Some(pos) => size_start + pos,
                // No newline yet: only an error once the whole maximal
                // field has been seen without one; otherwise incomplete.
                None if search_end < size_start + MAX_CHUNK_SIZE_LEN + 1 => {
                    return Ok(None);
                }
                None => {
                    return Err(SshCodecError::IO(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Chunk size is not properly terminated with a newline",
                    )));
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
        }
    }
}

impl Encoder<NetConfMessage> for SshCodec {
    type Error = SshCodecError;
    fn encode(&mut self, item: NetConfMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let buf = std::io::Cursor::new(Vec::new());
        let writer = quick_xml::writer::Writer::new_with_indent(buf, b' ', 2);
        let mut xml_writer = XmlWriter::new(writer);
        item.xml_serialize(&mut xml_writer)?;
        let buf = xml_writer.into_inner().into_inner();
        if tracing::enabled!(tracing::Level::TRACE) {
            trace!("Serialized payload: `{}`", std::str::from_utf8(&buf)?);
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
    use crate::capabilities::StandardCapability;
    use crate::protocol::{Rpc, RpcOperation, WellKnownOperation};
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
            RpcOperation::WellKnown(WellKnownOperation::CloseSession),
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
            RpcOperation::WellKnown(WellKnownOperation::CloseSession),
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

    /// Build a single-chunk 1.1 frame WITHOUT the trailing terminator.
    fn one_chunk_no_terminator(body: &str) -> Vec<u8> {
        format!("\n#{}\n{}", body.len(), body).into_bytes()
    }

    /// The `\n##\n` terminator may arrive in a SEPARATE read from the
    /// last chunk which is an ordinary TCP/SSH segmentation; not a hostile
    /// peer. The completed message must still be delivered.
    #[test]
    fn test_terminator_in_separate_read_is_delivered() {
        let body = r#"<rpc message-id="102" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><close-session/></rpc>"#;
        let mut codec = SshCodec::new();
        codec.in_hello = false;

        // Read 1: the whole chunk, but the terminator hasn't arrived yet.
        let mut buf = BytesMut::from(&one_chunk_no_terminator(body)[..]);
        let r1 = codec.decode(&mut buf).expect("no error");
        assert_eq!(r1, None, "chunk without terminator: correctly needs more");

        // Read 2: the 4-byte terminator arrives on its own.
        buf.extend_from_slice(b"\n##\n");
        let r2 = codec.decode(&mut buf).expect("no error");
        assert!(
            r2.is_some(),
            "the completed message MUST be delivered once the terminator arrives; \
             got None -> the RPC is stuck in self.buf forever and rpc_reply() hangs"
        );
    }

    /// A complete chunked frame shorter than a maximal chunk header must
    /// still be acted upon: the decoder may not demand bytes for a
    /// theoretical 10-digit size field that this frame does not use.
    /// Before the fix this returned `Ok(None)` and stalled forever; now
    /// the frame is parsed (and here rejected as invalid XML, which is
    /// the point; the decoder makes progress instead of hanging).
    #[test]
    fn test_short_complete_frame_is_acted_on() {
        let mut codec = SshCodec::new();
        codec.in_hello = false;
        // "\n#1\nx\n##\n" -- 9 bytes, complete, under the old 13-byte gate.
        let mut buf = BytesMut::from(&b"\n#1\nx\n##\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(
            result.is_err(),
            "complete short frame must be decoded (and rejected as bad XML), \
             not silently stalled with Ok(None); got {result:?}"
        );
    }

    /// The decoder must tolerate ARBITRARY segmentation: a peer's message
    /// can be split anywhere, including mid-chunk-header and immediately
    /// before the terminator. Feeding one byte at a time is the strongest
    /// form of that guarantee.
    #[test]
    fn test_message_delivered_when_fed_one_byte_at_a_time() {
        let body = r#"<rpc message-id="102" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><close-session/></rpc>"#;
        let frame = format!("\n#{}\n{}\n##\n", body.len(), body).into_bytes();
        let expected = NetConfMessage::Rpc(Rpc::new(
            "102".into(),
            RpcOperation::WellKnown(WellKnownOperation::CloseSession),
        ));

        let mut codec = SshCodec::new();
        codec.in_hello = false;
        let mut buf = BytesMut::new();
        for (i, byte) in frame.iter().enumerate() {
            buf.extend_from_slice(&[*byte]);
            let result = codec.decode(&mut buf).expect("no decode error");
            if i + 1 == frame.len() {
                assert_eq!(
                    result,
                    Some(expected.clone()),
                    "final byte must complete it"
                );
            } else {
                assert_eq!(result, None, "incomplete at byte {}/{}", i + 1, frame.len());
            }
        }
        assert!(buf.is_empty(), "the whole frame must be consumed");
    }
    /// Two messages arriving in one read must both decode: after the
    /// first terminator is consumed, the next message's chunk header is
    /// handled by the same top-of-loop dispatch.
    #[test]
    fn test_two_pipelined_messages_in_one_read() {
        let body = r#"<rpc message-id="102" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><close-session/></rpc>"#;
        let one = format!("\n#{}\n{}\n##\n", body.len(), body);
        let expected = NetConfMessage::Rpc(Rpc::new(
            "102".into(),
            RpcOperation::WellKnown(WellKnownOperation::CloseSession),
        ));
        let mut codec = SshCodec::new();
        codec.in_hello = false;
        let mut buf = BytesMut::from(format!("{one}{one}").as_str());

        assert_eq!(codec.decode(&mut buf), Ok(Some(expected.clone())));
        assert_eq!(codec.decode(&mut buf), Ok(Some(expected)));
        assert_eq!(codec.decode(&mut buf), Ok(None));
        assert!(buf.is_empty());
    }
}
