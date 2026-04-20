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
/// `SliceReader` is `Copy` — sub-readers from [`Self::take_slice`] are
/// just pointer arithmetic with zero overhead, identical to nom's `Span`.
///
/// `offset` tracks the absolute byte position for error reporting.
#[derive(Debug, Copy, Clone)]
pub struct SliceReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    #[inline(always)]
    pub fn new_with_offset(buf: &'a [u8], offset: usize) -> Self {
        Self { buf, offset }
    }

    /// Create a sub-reader covering the next `len` bytes — zero-copy.
    /// Just splits the slice reference; no allocation or ref-counting.
    #[inline(always)]
    pub fn take_slice(&mut self, len: usize) -> Result<SliceReader<'a>, ParseError> {
        if self.buf.len() < len {
            return Err(ParseError::eof(self.offset, len, self.buf.len()));
        }
        let (head, tail) = self.buf.split_at(len);
        let sub = SliceReader {
            buf: head,
            offset: self.offset,
        };
        self.buf = tail;
        self.offset += len;
        Ok(sub)
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

    /// Returns the remaining unread bytes as a slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &'a [u8] {
        self.buf
    }

    #[inline(always)]
    pub fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.buf.is_empty() {
            return Err(ParseError::eof(self.offset, 1, 0));
        }
        let v = self.buf[0];
        self.buf = &self.buf[1..];
        self.offset += 1;
        Ok(v)
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
    pub fn read_f32_be(&mut self) -> Result<f32, ParseError> {
        self.read_array::<4>().map(f32::from_be_bytes)
    }

    #[inline(always)]
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        if self.buf.len() < N {
            return Err(ParseError::eof(self.offset, N, self.buf.len()));
        }
        let arr: [u8; N] = self.buf[..N].try_into().unwrap();
        self.buf = &self.buf[N..];
        self.offset += N;
        Ok(arr)
    }

    /// Read `len` bytes and return them as a borrowed slice.
    /// Callers that need owned data can call `.to_vec()` on the result.
    #[inline(always)]
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        if self.buf.len() < len {
            return Err(ParseError::eof(self.offset, len, self.buf.len()));
        }
        let (head, tail) = self.buf.split_at(len);
        self.buf = tail;
        self.offset += len;
        Ok(head)
    }
}
