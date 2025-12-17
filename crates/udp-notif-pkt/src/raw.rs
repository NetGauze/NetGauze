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

//! Low-level representation of [draft-ietf-netconf-udp-notif](https://datatracker.ietf.org/doc/html/draft-ietf-netconf-udp-notif).
//!
//! This module provides the foundational data structures for UDP-based
//! notifications as defined in the IETF draft. The payload is represented as a
//! raw [`Bytes`] buffer, allowing higher-level transport layers to perform
//! additional processing, parsing, or deserialization as needed.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::Display;

pub const UDP_NOTIF_V1: u8 = 1;

/// Media Type of the UDP Notif paylaod
#[derive(
    Display,
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    Hash,
    strum_macros::EnumDiscriminants,
)]
#[strum_discriminants(name(MediaTypeNames))]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum MediaType {
    Reserved,
    /// media type application/yang-data+json
    YangDataJson,

    /// media type application/yang-data+xml
    YangDataXml,

    /// media type application/yang-data+cbor
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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

/// Raw UDP Notif Packe without processing the payload
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UdpNotifPacket {
    media_type: MediaType,
    publisher_id: u32,
    message_id: u32,
    pub(crate) options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_bytes))]
    payload: Bytes,
}

impl UdpNotifPacket {
    pub const fn new(
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
        payload: Bytes,
    ) -> Self {
        Self {
            media_type,
            publisher_id,
            message_id,
            options,
            payload,
        }
    }

    pub const fn version(&self) -> u8 {
        UDP_NOTIF_V1
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

    pub fn payload(&self) -> Bytes {
        // Bytes package has cheap CoW clones
        Bytes::clone(&self.payload)
    }
}
