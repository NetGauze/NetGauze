pub mod bgp;
pub mod bmp;
pub mod flow;
pub mod udp_notif;
use crate::protocol_handler::DecodeOutcome;

use bytes::{Buf, BytesMut};
use std::net::IpAddr;
use tokio_util::codec::Decoder;

/// Decodes a buffer and pushes the results into a vector.
///
/// This function will continue to decode from the buffer until it is empty or
/// an incomplete frame is found.
/// If a decoding error occurs, the buffer is cleared, and the error is pushed
/// to the results.
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
