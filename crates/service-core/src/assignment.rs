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

//! Utils for assigning worker to specific CPU cores based on the
//! [crate::affinity::AffinityStrategy].
//!
//! These Utils are meant to be used within a
//! [crate::supervisor::CollectionSupervisor] context.

use crate::affinity::CoreId;
use crate::worker::WorkerIndex;
use hwlocality::Topology;
use hwlocality::object::types::ObjectType;
use tracing::warn;

/// Which physical core each worker thread pins to, indexed by worker_index:
/// `cores.core_id(0)` is worker 0's core, `cores.core_id(1)` is worker 1's,
/// etc.
///
/// [crate::supervisor::CollectionSupervisor::start] spawns exactly
/// `cores.len()` workers.
pub struct CoreAssignment(Box<[CoreId]>);

impl CoreAssignment {
    /// Explicit Operator-supplied worker assignment: a config value, not
    /// discovered. No validation: an out-of-range core id does NOT fail
    /// the spawn since the [crate::affinity::AffinityStrategy::apply] reports
    /// [crate::affinity::PinOutcome::Failed], the supervisor can choose
    /// what policy to apply on failure there.
    pub fn explicit(cores: impl Into<Box<[usize]>>) -> Self {
        Self(
            cores
                .into()
                .into_iter()
                .map(CoreId::new)
                .collect::<Box<[CoreId]>>(),
        )
    }

    /// NUMA-aware assignment that DEGRADES instead of failing, so callers
    /// never need a fallback path of their own:
    ///
    /// 1. Preferred: hwloc topology discovery: one PU per PHYSICAL core (never
    ///    SMT siblings of one core, which would silently halve per-worker
    ///    capacity), cores ordered by the NUMA node whose cpuset contains them
    ///    (node 0's cores first, then node 1's, ...).
    /// 2. Fallback (topology discovery failed or reported fewer cores than
    ///    requested: e.g. a container without host topology visibility): assume
    ///    ONE NUMA node and take the first `count` schedulable CPUs from the
    ///    process affinity mask, or sequential ids `0..count` as the last
    ///    resort. The fallback cannot distinguish SMT siblings; a warning is
    ///    logged so a surprising throughput profile is diagnosable from the
    ///    logs.
    ///
    /// Always returns exactly `count` entries. Oversubscription (asking
    /// for more cores than the machine has) is therefore NOT an error
    /// here: the surplus ids simply fail to pin at spawn
    /// (`PinOutcome::Failed`, warned per worker, worker runs unpinned);
    /// the same degrade-don't-abort contract as
    /// [`CoreAssignment::explicit`].
    pub fn numa_ordered(count: usize) -> Self {
        match Self::hwloc_physical_cores(count) {
            Ok(cores) => Self(cores.into_boxed_slice()),
            Err(reason) => {
                warn!(
                    count,
                    reason, "NUMA-aware core discovery unavailable; assuming a single NUMA node"
                );
                let mut ids: Vec<usize> = core_affinity::get_core_ids()
                    .map(|v| v.into_iter().map(|c| c.id).collect())
                    .unwrap_or_default();
                if ids.len() < count {
                    // Affinity mask unavailable or too small: sequential
                    // ids; unpinnable ones degrade to unpinned workers.
                    ids = (0..count).collect();
                }
                ids.truncate(count);
                Self(ids.into_iter().map(CoreId::new).collect())
            }
        }
    }

    /// The hwloc half of [`CoreAssignment::numa_ordered`]: (node rank,
    /// first PU os-index) per physical core; cores outside every reported
    /// NUMA node (possible on odd topologies) sort last -- which also
    /// means a topology with NO NUMA nodes degrades naturally to a flat
    /// physical-core list ("one numa").
    fn hwloc_physical_cores(count: usize) -> Result<Vec<CoreId>, String> {
        let topology = Topology::new().map_err(|e| e.to_string())?;
        let node_cpusets: Vec<_> = topology
            .objects_with_type(ObjectType::NUMANode)
            .filter_map(|n| n.cpuset().map(|c| c.clone_target()))
            .collect();
        let mut ranked: Vec<(usize, usize)> = topology
            .objects_with_type(ObjectType::Core)
            .filter_map(|core| {
                let cpuset = core.cpuset()?;
                let first_pu = cpuset.first_set()?;
                let rank = node_cpusets
                    .iter()
                    .position(|n| n.includes(cpuset))
                    .unwrap_or(usize::MAX);
                Some((rank, usize::from(first_pu)))
            })
            .collect();
        ranked.sort_unstable();
        if ranked.len() < count {
            return Err(format!(
                "requested {count} cores, hwloc only reports {} physical cores",
                ranked.len()
            ));
        }
        let mut cores: Vec<CoreId> = ranked.into_iter().map(|(_, pu)| CoreId::new(pu)).collect();
        cores.truncate(count);
        Ok(cores)
    }

    pub fn core_id(&self, worker_index: WorkerIndex) -> Option<CoreId> {
        self.0.get(worker_index.get()).copied()
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (WorkerIndex, CoreId)> + '_ {
        self.0
            .iter()
            .copied()
            .enumerate()
            .map(|(i, c)| (WorkerIndex::new(i), c)) // (worker_index, core_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_maps_indices() {
        let cores = CoreAssignment::explicit(vec![3usize, 7, 1]);
        assert_eq!(cores.len(), 3);
        assert_eq!(cores.core_id(WorkerIndex::new(0)), Some(CoreId::new(3)));
        assert_eq!(cores.core_id(WorkerIndex::new(2)), Some(CoreId::new(1)));
        // Out of range: None, not a panic.
        assert_eq!(cores.core_id(WorkerIndex::new(3)), None);
        let collected: Vec<_> = cores.iter().collect();
        assert_eq!(collected[1], (WorkerIndex::new(1), CoreId::new(7)));
    }

    #[test]
    fn numa_ordered_is_infallible_and_exact() {
        // The contract: exactly `count` entries, always -- discovery
        // failures and oversubscription degrade (fallback ids that later
        // fail to pin), they never error.
        let small = CoreAssignment::numa_ordered(2);
        assert_eq!(small.len(), 2);
        let a = small.core_id(WorkerIndex::new(0)).expect("first core");
        let b = small.core_id(WorkerIndex::new(1)).expect("second core");
        // Whichever path produced them (hwloc physical cores, affinity
        // mask, or sequential), two workers never share one id.
        assert_ne!(a, b);

        // Absurd oversubscription still yields exactly count ids (the
        // one-numa fallback), not an error.
        let big = CoreAssignment::numa_ordered(1_000);
        assert_eq!(big.len(), 1_000);
    }
}
