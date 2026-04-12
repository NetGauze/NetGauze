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

use bytes::BufMut;

/// Serialize `Self` into any `BufMut` destination.
pub trait WriteTo {
    type Error;

    /// Return the exact number of bytes this PDU will occupy on the wire.
    /// Callers use this to `reserve()` or pre-allocate the destination before
    /// writing.
    fn wire_len(&self) -> usize;

    fn write_to<W: BufMut>(&self, w: &mut W) -> Result<(), Self::Error>;
}

/// Context-parameterized variant (e.g., the ASN4 flag changes AS_PATH encoding
/// length).
pub trait WriteToWith<Ctx> {
    type Error;
    fn wire_len(&self, ctx: Ctx) -> usize;
    fn write_to<W: BufMut>(&self, w: &mut W, ctx: Ctx) -> Result<(), Self::Error>;
}
