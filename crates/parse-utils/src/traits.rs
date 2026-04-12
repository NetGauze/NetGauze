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

use crate::reader::BytesReader;

/// Parse `Self` from the cursor with no additional context.
pub trait ParseFrom<'a>: Sized {
    type Error;
    fn parse(cur: &mut BytesReader) -> Result<Self, Self::Error>;
}

/// Parse `Self` from the cursor with one immutable context argument.
pub trait ParseFromWithOneInput<'a, I1>: Sized {
    type Error;
    fn parse(cur: &mut BytesReader, i1: I1) -> Result<Self, Self::Error>;
}

/// Parse `Self` from the cursor with two immutable context arguments.
pub trait ParseFromWithTwoInputs<'a, I1, I2>: Sized {
    type Error;
    fn parse(cur: &mut BytesReader, i1: I1, i2: I2) -> Result<Self, Self::Error>;
}

/// Parse `Self` from the cursor with three immutable context arguments.
pub trait ParseFromWithThreeInputs<'a, I1, I2, I3>: Sized {
    type Error;
    fn parse(cur: &mut BytesReader, i1: I1, i2: I2, i3: I3) -> Result<Self, Self::Error>;
}

/// Parse `Self` from the cursor with a **mutable** context.
/// Used for stateful protocols (e.g. BGP, where capabilities update the
/// context).
pub trait ParseFromWithMut<'a, Ctx>: Sized {
    type Error;
    fn parse(cur: &mut BytesReader, ctx: &mut Ctx) -> Result<Self, Self::Error>;
}
