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

use serde::{Deserialize, Serialize};

/// Infrastructure-level parsing error.
/// Represents only *structural* failures — buffer exhausted or value out of
/// range. Domain-specific validation lives in per-PDU error enums.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ParseError {
    #[error(
        "unexpected end of buffer at byte offset {offset} (needed {needed}, available {available})"
    )]
    UnexpectedEof {
        offset: usize,
        needed: usize,
        available: usize,
    },

    #[error(
        "padded read exceeds capacity at byte offset {offset} (requested {requested}, capacity {ret_len})"
    )]
    InvalidPaddingLength {
        offset: usize,
        requested: usize,
        ret_len: usize,
    },
}

impl ParseError {
    #[cold]
    #[inline(never)]
    pub fn eof(offset: usize, needed: usize, available: usize) -> Self {
        Self::UnexpectedEof {
            offset,
            needed,
            available,
        }
    }
    #[cold]
    #[inline(never)]
    pub fn invalid_padding_length(offset: usize, requested: usize, ret_len: usize) -> Self {
        Self::InvalidPaddingLength {
            offset,
            requested,
            ret_len,
        }
    }
    #[inline]
    pub fn offset(&self) -> usize {
        match self {
            Self::UnexpectedEof { offset, .. } | Self::InvalidPaddingLength { offset, .. } => {
                *offset
            }
        }
    }

    #[inline]
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::UnexpectedEof { .. })
    }
}
