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
    xml_parser::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
    protocol::{Hello, NetConfMessage},
};
use quick_xml::NsReader;
use std::fmt::Display;
use tokio_util::{
    bytes::{Buf, BufMut, BytesMut},
    codec::{Decoder, Encoder},
};

const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
const HELLO_TERMINATOR: &str = "]]>]]>";
const MESSAGE_START: &str = "\n#";
const MESSAGE_TERMINATOR: &str = "\n##\n";

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
            Self::IO(err) => write!(f, "{}", err),
            Self::Utf(err) => write!(f, "{}", err),
            Self::Int(err) => write!(f, "{}", err),
            Self::Parsing(err) => write!(f, "{}", err),
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
                let data = src.limit(pos).into_inner().reader();
                let reader = NsReader::from_reader(data);
                let mut xml_parser = XmlParser::new(reader)?;
                let hello = Hello::xml_deserialize(&mut xml_parser)?;
                self.in_hello = false;
                return Ok(Some(NetConfMessage::Hello(hello)));
            }
            return Ok(None);
        }
        if src.len() > MESSAGE_START.len() + 1 {
            if let Some(position) = src[MESSAGE_START.len()..]
                .windows(1)
                .position(|w| w == b"\n")
            {
                let size_slice = &src[MESSAGE_START.len()..position + MESSAGE_START.len()];
                let len = std::str::from_utf8(size_slice)?.parse::<usize>()?;
                if src.len() > len + size_slice.len() + 6 {
                    let range = position + 3..len + position + 3;
                    self.buf.extend_from_slice(&src[range.clone()]);
                    src.advance(range.end);
                    if src.len() >= 2 && src.ends_with(MESSAGE_TERMINATOR.as_bytes()) {
                        let reader = self.buf.split().reader();
                        let reader = NsReader::from_reader(reader);
                        let mut xml_parser = XmlParser::new(reader)?;
                        // let reply = RpcReply::xml_deserialize(&mut xml_parser)?;
                        let parsed = NetConfMessage::xml_deserialize(&mut xml_parser)?;
                        src.advance(b"\n##\n".len());
                        return Ok(Some(parsed));
                    }
                }
            }
        }
        Ok(None)
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
            tracing::debug!(
                "Serialized payload: `{}`",
                std::str::from_utf8(&buf)?
            );
        }
        if let NetConfMessage::Hello(_) = item {
            dst.extend_from_slice(XML_HEADER.as_bytes());
            dst.extend_from_slice(&buf);
            dst.extend_from_slice(HELLO_TERMINATOR.as_bytes());
        } else {
            let size = buf.len();
            dst.extend_from_slice(format!("{MESSAGE_START}{size}\n").as_bytes());
            dst.extend_from_slice(&buf);
            dst.extend_from_slice(MESSAGE_TERMINATOR.as_bytes());
        }
        Ok(())
    }
}
