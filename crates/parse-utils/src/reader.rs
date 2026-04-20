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
use bytes::{Buf, BytesMut};

/// A zero-copy, forward-only reader backed by a reference-counted `Bytes`
/// buffer.
///
/// Unlike `ByteReader<'a>` (which borrows `&'a [u8]`), `BytesReader` owns a
/// `Bytes` handle so parsed PDU fields of type `Bytes` can outlive the decode
/// call.
///
/// `offset` is the same absolute-offset invariant as `ByteReader<'a>`.
#[derive(Debug, Clone)]
pub struct BytesReader {
    buf: BytesMut,
    offset: usize,
}

impl BytesReader {
    pub fn new(buf: BytesMut) -> Self {
        Self { buf, offset: 0 }
    }

    pub fn new_with_offset(buf: BytesMut, offset: usize) -> Self {
        Self { buf, offset }
    }

    /// Create a sub-reader covering the next `len` bytes — zero-copy.
    /// `Bytes::split_to` is O(1) and increments the Arc refcount once.
    #[inline(always)]
    pub fn take_slice(&mut self, len: usize) -> Result<BytesReader, ParseError> {
        if self.buf.len() < len {
            return Err(ParseError::eof(self.offset, len, self.buf.len()));
        }
        let sub_buf = self.buf.split_to(len); // O(1), no copy
        let sub = BytesReader {
            buf: sub_buf,
            offset: self.offset,
        };
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

    #[inline(always)]
    pub fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.buf.is_empty() {
            return Err(ParseError::eof(self.offset, 1, 0));
        }
        let v = self.buf[0];
        self.buf.advance(1);
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
        self.buf.advance(N);
        self.offset += N;
        Ok(arr)
    }

    /// Returns a `Bytes` sub-slice — zero-copy, reference-counted.
    /// The returned `Bytes` keeps the underlying data alive independently of
    /// `self`.
    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> Result<BytesMut, ParseError> {
        if self.buf.len() < len {
            return Err(ParseError::eof(self.offset, len, self.buf.len()));
        }
        let chunk = self.buf.split_to(len); // O(1), single Arc refcount bump
        self.offset += len;
        Ok(chunk)
    }
}
