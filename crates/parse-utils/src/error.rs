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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ParseError {
    #[error("end of buffer at offset {offset}: needed {needed} bytes, had {available}")]
    UnexpectedEof {
        offset: usize,
        needed: usize,
        available: usize,
    },

    #[error("{context} at offset {offset}")]
    InvalidValue { offset: usize, context: Box<str> },
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
    pub fn invalid(offset: usize, context: Box<str>) -> Self {
        Self::InvalidValue { offset, context }
    }
    pub fn offset(&self) -> usize {
        match self {
            Self::UnexpectedEof { offset, .. } | Self::InvalidValue { offset, .. } => *offset,
        }
    }
}
