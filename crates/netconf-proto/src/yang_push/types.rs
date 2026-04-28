// Copyright (C) 2026-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Primitive newtypes used across the YANG-Push subscription model.
//!
//! * [`CentiSeconds`] – a thin wrapper around `u32` representing time intervals
//!   in 1/100-second units as defined by the `centiseconds` YANG typedef.
//! * [`SubscriptionId`] – type alias for `u32` subscription identifiers
//!   ([RFC 8639 §2.4.1](https://datatracker.ietf.org/doc/html/rfc8639#section-2.4.1)).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CentiSeconds(u32);

impl CentiSeconds {
    pub const fn new(value: u32) -> Self {
        CentiSeconds(value)
    }

    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    pub const fn to_milliseconds(&self) -> u32 {
        self.0 * 10
    }
}

/// Subscription ID defined as uint32 in [RFC 8639](https://datatracker.ietf.org/doc/html/rfc8639)
pub type SubscriptionId = u32;
