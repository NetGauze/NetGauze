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

pub mod bgp;
pub mod bmp;
pub mod flow;
pub mod udp_notif;

use crate::protocol_handler::{DecodeOutcome, SerializableInfo};
use bytes::{Buf, BytesMut};
use serde::Serialize;
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
use tokio_util::codec::Decoder;

/// Decodes a buffer and pushes the results into a vector.
///
/// This function will continue to decode from the buffer until it is empty or
/// an incomplete frame is found.
/// If a decoding error occurs, the buffer is cleared, and the error is pushed
/// to the results.
///
/// This function is only available within the handlers module.
fn decode_buffer<T, E, C>(
    buffer: &mut BytesMut,
    codec: &mut C,
    flow_key: (IpAddr, u16, IpAddr, u16),
    results: &mut Vec<DecodeOutcome<T, E>>,
) where
    C: Decoder<Item = T, Error = E>,
{
    while buffer.has_remaining() {
        match codec.decode(buffer) {
            Ok(Some(msg)) => {
                results.push(DecodeOutcome::Success((flow_key, msg)));
            }
            Ok(None) => {
                // no more data to decode or incomplete frame
                break;
            }
            Err(e) => {
                // malformed bytes in the buffer, will clean it
                buffer.clear();
                results.push(DecodeOutcome::Error(e));
            }
        }
    }
}

/// Helper function to serialize a successful decode outcome.
/// Only available within the handlers module.
fn serialize_success<T: Serialize>(
    flow_key: (IpAddr, u16, IpAddr, u16),
    info: T,
) -> io::Result<serde_json::Value> {
    let serializable_flow = SerializableInfo {
        source_address: SocketAddr::new(flow_key.0, flow_key.1),
        destination_address: SocketAddr::new(flow_key.2, flow_key.3),
        info,
    };
    Ok(serde_json::to_value(&serializable_flow)?)
}

/// Helper function to serialize an error outcome.
/// Only available within the handlers module.
fn serialize_error<E: Serialize>(error: E) -> io::Result<serde_json::Value> {
    Ok(serde_json::to_value(&error)?)
}
