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

//! Serialize/Deserialize BGP wire protocol

#![allow(unsafe_code)]
pub mod deserializer;
pub mod serializer;

/// Enhanced route refresh have fixed length as per RFC2918
pub(crate) const ROUTE_REFRESH_CAPABILITY_LENGTH: u8 = 0;

/// Enhanced route refresh have fixed length as per RFC7313
pub(crate) const ENHANCED_ROUTE_REFRESH_CAPABILITY_LENGTH: u8 = 0;

/// Multi Protocol extension have fixed length as per RFC4760
pub(crate) const MULTI_PROTOCOL_EXTENSIONS_CAPABILITY_LENGTH: u8 = 4;

/// Four octet as capability have fixed length as per RFC6793
pub(crate) const FOUR_OCTET_AS_CAPABILITY_LENGTH: u8 = 4;

/// BGP Extended Message capability have fixed length as per RFC8654
pub(crate) const EXTENDED_MESSAGE_CAPABILITY_LENGTH: u8 = 0;

/// 2-octet NLRI AFI + 2-octet NLRI SAFI + 2-octet `NextHop` AFI as per RFC8950
pub(crate) const EXTENDED_NEXT_HOP_ENCODING_LENGTH: u8 = 6;

/// 2-octet NLRI AFI + 1-octet NLRI SAFI + 1-octet flags as per RFC4724
pub(crate) const GRACEFUL_RESTART_ADDRESS_FAMILY_LENGTH: u8 = 4;

/// 1-octet length as defined by RFC9234
pub(crate) const BGP_ROLE_CAPABILITY_LENGTH: u8 = 1;

/// Accumulated IGP Metric Length as defined in RFC7311
pub(crate) const ACCUMULATED_IGP_METRIC: u16 = 11;

#[cfg(test)]
mod tests;
