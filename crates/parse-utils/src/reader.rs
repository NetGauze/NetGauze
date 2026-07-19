// Copyright (C) 2026-present The NetGauze Authors.
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

use crate::error::ParseError;

/// A zero-copy, forward-only reader over a borrowed byte slice.
///
/// `SliceReader` is `Copy`, and that is deliberate and load-bearing: copying
/// the reader is a zero-cost checkpoint for speculative parsing / backtracking.
///
/// ```ignore
/// let save = reader;                     // checkpoint: just a pointer + usize
/// if try_parse(&mut reader).is_err() {
///     reader = save;                     // rewind; nothing was consumed
/// }
/// ```
///
/// `offset` is the absolute position from the start of the *original* buffer,
/// so errors and sub-readers report positions that stay meaningful across
/// nested parses.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SliceReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    #[cfg(test)]
    pub fn new_with_offset(offset: usize, buf: &'a [u8]) -> Self {
        Self { buf, offset }
    }

    #[inline(always)]
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline(always)]
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The remaining, not-yet-read bytes.
    #[inline(always)]
    pub fn as_slice(&self) -> &'a [u8] {
        self.buf
    }

    #[inline(always)]
    pub fn read_u8(&mut self) -> Result<u8, ParseError> {
        match self.buf.split_first() {
            Some((&v, rest)) => {
                self.buf = rest;
                self.offset += 1;
                Ok(v)
            }
            None => Err(ParseError::eof(self.offset, 1, 0)),
        }
    }

    /// Read a fixed-size array.
    #[inline(always)]
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        match self.buf.split_first_chunk::<N>() {
            Some((chunk, rest)) => {
                self.buf = rest;
                self.offset += N;
                Ok(*chunk)
            }
            None => Err(ParseError::eof(self.offset, N, self.buf.len())),
        }
    }

    #[inline(always)]
    pub fn read_u16_be(&mut self) -> Result<u16, ParseError> {
        self.read_array::<2>().map(u16::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_u32_be(&mut self) -> Result<u32, ParseError> {
        self.read_array::<4>().map(u32::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_u64_be(&mut self) -> Result<u64, ParseError> {
        self.read_array::<8>().map(u64::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_u128_be(&mut self) -> Result<u128, ParseError> {
        self.read_array::<16>().map(u128::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_i32_be(&mut self) -> Result<i32, ParseError> {
        self.read_array::<4>().map(i32::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_i64_be(&mut self) -> Result<i64, ParseError> {
        self.read_array::<8>().map(i64::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_f32_be(&mut self) -> Result<f32, ParseError> {
        self.read_array::<4>().map(f32::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_f64_be(&mut self) -> Result<f64, ParseError> {
        self.read_array::<8>().map(f64::from_be_bytes)
    }

    /// Read `len` bytes as a borrowed slice.
    ///
    /// Non-panicking even for an attacker-controlled `len`: `split_at_checked`
    /// returns `None` on overrun rather than panicking or overflowing. Callers
    /// needing owned, zero-copy data should `slice_ref` the result off the
    /// parent `Bytes`; callers needing an owned copy can `.to_vec()`.
    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        match self.buf.split_at_checked(len) {
            Some((head, tail)) => {
                self.buf = tail;
                self.offset += len;
                Ok(head)
            }
            None => Err(ParseError::eof(self.offset, len, self.buf.len())),
        }
    }

    /// Zero-copy sub-reader over the next `len` bytes, with the correct
    /// absolute offset carried into it for nested error reporting.
    #[inline]
    pub fn take_slice(&mut self, len: usize) -> Result<SliceReader<'a>, ParseError> {
        let start = self.offset;
        self.read_bytes(len)
            .map(|buf| SliceReader { buf, offset: start })
    }

    #[inline(always)]
    pub fn peek_u8(&mut self) -> Result<u8, ParseError> {
        match self.buf.split_first() {
            Some((&v, _rest)) => Ok(v),
            None => Err(ParseError::eof(self.offset, 1, 0)),
        }
    }

    #[inline(always)]
    pub fn peek_u16_be(&self) -> Result<u16, ParseError> {
        self.peek_array::<2>().map(u16::from_be_bytes)
    }

    #[inline(always)]
    pub fn peek_u32_be(&self) -> Result<u32, ParseError> {
        self.peek_array::<4>().map(u32::from_be_bytes)
    }

    /// Peek a fixed-size array without advancing. Takes `&self`.
    #[inline(always)]
    pub fn peek_array<const N: usize>(&self) -> Result<[u8; N], ParseError> {
        self.buf
            .first_chunk::<N>()
            .copied()
            .ok_or_else(|| ParseError::eof(self.offset, N, self.buf.len()))
    }

    /// Read `len` bytes and left-align them into a zero-padded `[u8; N]`.
    #[inline]
    pub fn read_padded<const N: usize>(&mut self, len: usize) -> Result<[u8; N], ParseError> {
        if len > N {
            return Err(ParseError::invalid_padding_length(self.offset, len, N));
        }
        let src = self.read_bytes(len)?;
        let mut out = [0u8; N];
        out[..len].copy_from_slice(src);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_advance_and_track_offset() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04];
        let mut r = SliceReader::new(&data);
        assert_eq!(r.read_u8(), Ok(0x00));
        assert_eq!(r.read_u16_be(), Ok(0x0102));
        assert_eq!(r.offset(), 3);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn eof_reports_offset_needed_available() {
        let data = [0xAA, 0xBB];
        let mut r = SliceReader::new(&data);
        let _ = r.read_u8().unwrap();
        let err = r.read_u32_be();
        assert_eq!(err, Err(ParseError::eof(1, 4, 1)));
        assert_eq!(err.map_err(|x| x.is_incomplete()), Err(true));
    }

    #[test]
    fn copy_gives_free_checkpoint() {
        let data = [1, 2, 3, 4];
        let mut r = SliceReader::new(&data);
        let save = r; // checkpoint
        let _ = r.read_u16_be().unwrap();
        assert_eq!(r.offset(), 2);
        r = save; // rewind
        assert_eq!(r.offset(), 0);
    }

    #[test]
    fn peek_does_not_advance() {
        let data = [0x12, 0x34];
        let r = SliceReader::new(&data);
        assert_eq!(r.peek_u16_be(), Ok(0x1234));
        assert_eq!(r.offset(), 0);
    }

    #[test]
    fn take_slice_carries_absolute_offset() {
        let data = [0, 1, 2, 3, 4, 5];
        let mut r = SliceReader::new(&data);
        let _ = r.read_u16_be().unwrap();
        let sub = r.take_slice(3);
        assert_eq!(sub, Ok(SliceReader::new_with_offset(2, &[2, 3, 4])));
    }

    #[test]
    fn len_equal_to_n_reads_full_no_padding() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut r = SliceReader::new(&data);
        let out = r.read_padded::<4>(4);
        assert_eq!(out, Ok([0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(r.offset(), 4);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn short_len_left_aligns_and_zero_pads_tail() {
        let data = [0xAA, 0xBB, 0xCC];
        let mut r = SliceReader::new(&data);
        let out = r.read_padded::<4>(2);
        assert_eq!(out, Ok([0xAA, 0xBB, 0x00, 0x00]));
        // advances by `len`, NOT by N — the untouched byte is still readable
        assert_eq!(r.offset(), 2);
        assert_eq!(r.as_slice(), &[0xCC]);
    }

    #[test]
    fn zero_len_yields_all_zeros_without_advancing() {
        let data = [0x11, 0x22];
        let mut r = SliceReader::new(&data);
        let out = r.read_padded::<4>(0);
        assert_eq!(out, Ok([0, 0, 0, 0]));
        assert_eq!(r.offset(), 0);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn len_within_n_but_buffer_too_short_is_eof() {
        let data = [0xAA]; // only one byte available
        let mut r = SliceReader::new(&data);
        let err = r.read_padded::<4>(3);
        assert_eq!(err, Err(ParseError::eof(0, 3, 1)));
        assert_eq!(r.offset(), 0); // read_bytes failed before advancing
    }

    #[test]
    fn capacity_error_reports_current_offset() {
        let data = [0x00, 0x00, 0xAA, 0xBB, 0xCC];
        let mut r = SliceReader::new(&data);
        let _ = r.read_u16_be().unwrap(); // advance to offset 2
        let err = r.read_padded::<2>(5);
        assert_eq!(err, Err(ParseError::invalid_padding_length(2, 5, 2)));
        assert_eq!(r.offset(), 2); // read_bytes failed before advancing
    }
}
