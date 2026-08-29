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

use crate::affinity::CoreId;
use opentelemetry::metrics::Meter;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Worker index slot identity: used to, e.g., route, respawn, labels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkerIndex(usize);

impl WorkerIndex {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }
    pub const fn get(&self) -> usize {
        self.0
    }
}

impl std::fmt::Display for WorkerIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait Worker: Sized + 'static {
    /// Admin commands. Must be `Send`: crosses from the control-plane
    /// runtime into this core's thread.
    type Command: Send + 'static;

    /// User provided configuration that moved into the thread, one clone per
    /// core.
    type Config: Clone + Send + 'static;

    /// Per-slot metrics state: created once by [`Worker::build_stats`],
    /// shared with the OTel observable callbacks, and REUSED by every
    /// respawn of the slot; even in case of panics. It
    /// therefore crosses the supervisor's `catch_unwind` boundary and
    /// MUST be panic-tolerant: lock-free atomics / `ArcSwap` mirrors,
    /// never a poisoning `std::sync::Mutex` (a panic while holding one
    /// would make every subsequent incarnation fail on lock()).
    type Stats: Send + Sync + 'static;

    type Error: std::error::Error + Send + Sync + 'static;

    /// For thread names, log fields and metric attributes.
    const NAME: &'static str;

    /// Called ONCE per worker slot, on the control-plane runtime thread,
    /// at supervisor start; never again on respawn.
    /// Creates the atomics for metrics AND registers every observable callback
    /// over them.
    fn build_stats(
        worker_index: WorkerIndex,
        config: &Self::Config,
        meter: &Meter,
    ) -> Arc<Self::Stats>;

    /// Called on the pinned thread *after* affinity is set, so first-touch
    /// NUMA allocation (if configured) lands on this core's node.
    /// `stats` is the per-slot instance from `build_stats`: the same one
    /// across every respawn of this slot, so WORKER-SCOPED monotonic
    /// counters (fields directly on the stats struct) continue rather
    /// than resetting.
    ///
    /// Continuity does NOT extend to RCU mirrors of
    /// per-entity handles (peers, pipelines) an implementation may hold
    /// inside its stats: a respawned worker typically resets and
    /// repopulates those with fresh atomics, and backends see an
    /// ordinary counter restart for the affected series: that is
    /// implementation-defined, not forbidden by this contract.
    fn build(
        ctx: &WorkerContext,
        config: Self::Config,
        stats: Arc<Self::Stats>,
    ) -> Result<Self, Self::Error>;

    /// Runs until the command channel closes or a fatal error occurs.
    /// Deliberately `impl Future` without a `Send` bound — this future is
    /// driven by a `current_thread` runtime and never migrates.
    fn run(
        self,
        cmd_rx: mpsc::Receiver<Self::Command>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

pub struct WorkerContext {
    worker_index: WorkerIndex,
    core_id: Option<CoreId>,
    meter: Meter,
}

impl WorkerContext {
    pub const fn new(worker_index: WorkerIndex, core_id: Option<CoreId>, meter: Meter) -> Self {
        Self {
            worker_index,
            core_id,
            meter,
        }
    }

    /// This worker's position in `CoreAssignment`'s list (0..worker_count).
    /// Distinct from `core_id` because `CoreAssignment::explicit` may list
    /// non-contiguous physical cores: `worker_index` is what admin surfaces
    /// like `CollectionSupervisor::route(worker_index, ..)` address by;
    /// `core_id` is what respawn-on-the-same-core and metric labels use
    pub const fn worker_index(&self) -> WorkerIndex {
        self.worker_index
    }

    /// The physical core this thread is pinned to if it's pinned according to
    /// the `AffinityConfig`.
    pub const fn core_id(&self) -> Option<CoreId> {
        self.core_id
    }

    pub const fn meter(&self) -> &Meter {
        &self.meter
    }
}
