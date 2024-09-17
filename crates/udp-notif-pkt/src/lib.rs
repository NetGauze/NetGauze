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

pub mod codec;
pub mod wire;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum MediaType {
    Reserved,
    YangDataJson,
    YangDataXml,
    YangDataCbor,
    Unknown(u8),
}

impl From<u8> for MediaType {
    fn from(value: u8) -> Self {
        match value {
            0 => MediaType::Reserved,
            1 => MediaType::YangDataJson,
            2 => MediaType::YangDataXml,
            3 => MediaType::YangDataCbor,
            value => MediaType::Unknown(value),
        }
    }
}

impl From<MediaType> for u8 {
    fn from(value: MediaType) -> Self {
        match value {
            MediaType::Reserved => 0,
            MediaType::YangDataJson => 1,
            MediaType::YangDataXml => 2,
            MediaType::YangDataCbor => 3,
            MediaType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UdpNotifHeader {
    version: u8,
    s_flag: bool,
    media_type: MediaType,
    publisher_id: u32,
    message_id: u32,
    options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
}

impl UdpNotifHeader {
    pub const fn new(
        version: u8,
        s_flag: bool,
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
    ) -> Self {
        Self {
            version,
            s_flag,
            media_type,
            publisher_id,
            message_id,
            options,
        }
    }

    pub const fn version(&self) -> u8 {
        self.version
    }

    pub const fn s_flag(&self) -> bool {
        self.s_flag
    }

    pub const fn media_type(&self) -> MediaType {
        self.media_type
    }

    pub const fn publisher_id(&self) -> u32 {
        self.publisher_id
    }

    pub const fn message_id(&self) -> u32 {
        self.message_id
    }

    pub const fn options(&self) -> &HashMap<UdpNotifOptionCode, UdpNotifOption> {
        &self.options
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum UdpNotifOptionCode {
    Segment = 1,
    PrivateEncoding = 2,
    Unknown(u8),
}

impl From<u8> for UdpNotifOptionCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Segment,
            2 => Self::PrivateEncoding,
            v => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum UdpNotifOption {
    Segment { number: u16, last: bool },
    PrivateEncoding(Vec<u8>),
    Unknown { typ: u8, value: Vec<u8> },
}

impl UdpNotifOption {
    pub const fn code(&self) -> UdpNotifOptionCode {
        match self {
            Self::Segment { .. } => UdpNotifOptionCode::Segment,
            Self::PrivateEncoding(_) => UdpNotifOptionCode::PrivateEncoding,
            Self::Unknown { typ, .. } => UdpNotifOptionCode::Unknown(*typ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UdpNotifPacket {
    header: UdpNotifHeader,
    payload: Bytes,
}

impl UdpNotifPacket {
    pub const fn new(header: UdpNotifHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }

    pub const fn header(&self) -> &UdpNotifHeader {
        &self.header
    }

    pub const fn payload(&self) -> &Bytes {
        &self.payload
    }
}
