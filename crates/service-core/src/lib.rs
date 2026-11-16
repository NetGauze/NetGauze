// Copyright (C) 2022-present The NetGauze Authors.
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

//! Shared-nothing, thread-per-core collection service scaffolding, shared
//! by every NetGauze protocol service (flow, BMP, UDP-Notif): the
//! [`worker::Worker`] trait, the supervising
//! [`supervisor::CollectionSupervisor`] (pinned spawn, panic detection,
//! budgeted respawn, graceful shutdown, concurrent admin plane), CPU
//! [`affinity`] strategies with environment auto-detection, NUMA-aware
//! core [`assignment`], and the drain-loop [`batch`] knobs.
//!
//! Protocol crates implement [`worker::Worker`] for their own I/O loop and
//! command enum; everything else, e.g., spawning, pinning, restart policy,
//! metrics lifecycle, is identical across protocols and lives here.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod affinity;
pub mod assignment;
pub mod batch;
pub mod supervisor;
pub mod worker;

/// Milliseconds on the process's monotonic clock, counted from the
/// first call. What liveness beats are stamped with: a wall-clock step
/// (an NTP correction, a VM migration) neither fakes a stall nor hides
/// one. Never zero, so a beat that reads zero was never stamped.
#[inline(always)]
pub fn mono_ms_now() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    u64::try_from(
        EPOCH
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
    .saturating_add(1)
}

#[inline(always)]
pub(crate) fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
