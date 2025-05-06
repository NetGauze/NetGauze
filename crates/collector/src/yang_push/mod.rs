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
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use notification::Notification;

pub mod enrichment;
pub mod notification;
pub mod telemetry;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UdpNotifPayload {
    #[serde(rename = "ietf-notification:notification")]
    Notification(Notification),

    Unknown(Bytes),
}

pub type SubscriptionId = u32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CentiSeconds(u32);

impl CentiSeconds {
    /// Creates a new `CentiSeconds` instance.
    pub fn new(value: u32) -> Self {
        CentiSeconds(value)
    }

    /// Returns the value in centiseconds.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Converts the centiseconds to milliseconds.
    pub fn to_milliseconds(&self) -> u32 {
        self.0 * 10
    }
}

#[cfg(test)]
mod tests {
    use super::CentiSeconds;

    #[test]
    fn test_new() {
        let centi = CentiSeconds::new(150);
        assert_eq!(centi.as_u32(), 150);
    }

    #[test]
    fn test_to_milliseconds() {
        let centi = CentiSeconds::new(123);
        assert_eq!(centi.to_milliseconds(), 1230);
    }
}
