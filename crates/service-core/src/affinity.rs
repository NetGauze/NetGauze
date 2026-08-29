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

//! Utils to detect and specify the CPU core affinity.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

/// Core ID identify physical CPU core placement; see [AffinityStrategy],
/// [crate::assignment::CoreAssignment]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoreId(usize);

impl CoreId {
    /// Core ID can be created only by this crate for safety.
    /// Everything else has a read-only access.
    pub(crate) const fn new(id: usize) -> Self {
        Self(id)
    }
    pub const fn get(&self) -> usize {
        self.0
    }
}

impl std::fmt::Display for CoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The result of [`AffinityStrategy::apply`]: distinguishes "deliberately
/// unpinned" from "tried to pin and failed", because only the latter
/// requires the caller (e.g., supervisor) to take an action such as warning or
/// retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// The thread is actually pinned to this core; becomes
    /// `WorkerContext.core_id = Some(..)`.
    Pinned(CoreId),
    /// The strategy deliberately does not pin (e.g. [`NoAffinity`]). Not
    /// a failure; nothing is logged.
    Unpinned,
    /// The strategy TRIED to pin and could not (invalid core id,
    /// restricted cpuset); the supervisor logs a warning and the worker
    /// runs unpinned.
    Failed,
}

/// How, or whether, a worker thread claims a specific physical core.
pub trait AffinityStrategy: Send + Sync {
    /// Strategy name for logging and debugging purposes
    fn name(&self) -> &str;

    /// Called as the FIRST statement on the spawned thread, before the
    /// runtime or any allocation.
    fn apply(&self, core_id: CoreId) -> PinOutcome;
}

/// Strategy that pins the worker thread into a specific CPU core.
/// When successful, it returns the [CoreId] for the pinned core,
/// or `None`
pub struct PinnedAffinity;

impl AffinityStrategy for PinnedAffinity {
    fn name(&self) -> &str {
        "pinned"
    }

    fn apply(&self, core_id: CoreId) -> PinOutcome {
        // core_affinity::set_for_current returns bool. An invalid core id or a
        // restricted cpu-set can make even PinnedAffinity fail to pin; that
        // failure reaches WorkerContext as None.
        if core_affinity::set_for_current(core_affinity::CoreId { id: core_id.get() }) {
            PinOutcome::Pinned(core_id)
        } else {
            PinOutcome::Failed
        }
    }
}

/// For `Burstable`/shared-node k8s, or anywhere pinning cannot deliver real
/// isolation, there's no need for CPU Core pinning.
pub struct NoAffinity;

impl AffinityStrategy for NoAffinity {
    fn name(&self) -> &str {
        "unpinned"
    }

    fn apply(&self, _core_id: CoreId) -> PinOutcome {
        PinOutcome::Unpinned
    }
}

/// Configure which Affinity strategy to use.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AffinityConfig {
    /// `Auto` detects the deployment environment at startup
    #[default]
    Auto,

    /// Pin workers to a fixed set of CPU cores
    Pinned,

    /// No pinning, the OS is free to schedule the workers
    Unpinned,
}

impl AffinityConfig {
    pub fn resolve(self) -> Arc<dyn AffinityStrategy> {
        match self {
            Self::Pinned => Arc::new(PinnedAffinity),
            Self::Unpinned => Arc::new(NoAffinity),
            Self::Auto => {
                let env = detect_environment();
                let strategy = env.recommended_strategy();
                info!(
                    virtualized = env.virtualized,
                    containerized = env.containerized,
                    exclusive_cpuset = env.exclusive_cpuset,
                    decision = strategy.name(),
                );
                strategy
            }
        }
    }
}

/// Helper struct to carry information about the auto detection of the
/// environment, in which the services are running.
#[derive(Debug, Clone, Copy)]
pub struct DetectedEnvironment {
    /// Diagnostic only, does not feed the decision below: hypervisor bit
    /// in `/proc/cpuinfo`'s `flags` line (kernel-exposed, no need to read
    /// raw CPUID ourselves), or a DMI `sys_vendor`/`product_name` match
    /// (`/sys/class/dmi/id/*`) against known cloud/hypervisor strings.
    pub virtualized: bool,
    /// Diagnostic only: `KUBERNETES_SERVICE_HOST` (injected into every pod
    /// by k8s itself -- the single most reliable signal available, no
    /// filesystem parsing needed), `/.dockerenv`, or a `kubepods`/`docker`/
    /// `containerd` path segment in `/proc/self/cgroup`.
    pub containerized: bool,
    /// Is true when CPU core pinning can be used (e.g., bare-metal)
    pub exclusive_cpuset: bool,
    /// Load-bearing with `containerized`: the affinity mask is strictly
    /// narrower than the host's online CPUs; the visible signature of a
    /// dedicated cpuset grant (k8s static CPU Manager) as opposed to a
    /// shared-everything container that simply has no limits set.
    pub exclusive_grant: bool,
}

impl DetectedEnvironment {
    pub const fn should_pin(&self) -> bool {
        self.exclusive_cpuset && (!self.containerized || self.exclusive_grant)
    }

    pub fn recommended_strategy(&self) -> Arc<dyn AffinityStrategy> {
        if self.should_pin() {
            Arc::new(PinnedAffinity)
        } else {
            Arc::new(NoAffinity)
        }
    }
}

/// Detect what type of environment this process is running at.
///
/// Any error anywhere degrades to the "don't pin" answer and never a failure,
/// since the user can always configure a fixed strategy.
fn detect_environment() -> DetectedEnvironment {
    // Affinity-mask size WITHOUT quota mixed in, as the comparison's other
    // side. core_affinity::get_core_ids() wraps sched_getaffinity; the
    // same crate already used by PinnedAffinity, no new dependency.
    let affinity_mask_size = core_affinity::get_core_ids()
        .map(|ids| ids.len())
        .unwrap_or(0);

    // Quota-aware count from std (min of quota and affinity, per above).
    let effective = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    // Both sides zero/errored => can't tell => don't pin.
    let exclusive_cpuset = affinity_mask_size > 0 && effective >= affinity_mask_size;

    // Host online-CPU count from sysfs ("0-47" ranges). In containers
    // this shows the HOST, which is the point: a mask as wide as the host
    // inside a container is shared capacity, not an exclusive grant. On
    // read/parse failure degrade to "not exclusive" (don't pin).
    let host_online = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|s| parse_cpu_list_count(s.trim()));

    let exclusive_grant = match host_online {
        Some(host) => affinity_mask_size > 0 && affinity_mask_size < host,
        None => false,
    };
    // Diagnostic-only fields (see struct docs). x86: the `raw-cpuid` crate
    // reads the hypervisor CPUID bit + vendor leaf, giving "KVM"/"Xen"/
    // "VMware" for the startup log rather than a bare bool; non-x86 falls
    // back to the DMI read. Neither is worth failing over.
    #[cfg(target_arch = "x86_64")]
    let virtualized = raw_cpuid::CpuId::new()
        .get_feature_info()
        .is_some_and(|f| f.has_hypervisor());
    #[cfg(not(target_arch = "x86_64"))]
    let virtualized = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .map(|v| {
            [
                "QEMU",
                "KVM",
                "VMware",
                "Xen",
                "Microsoft",
                "Amazon EC2",
                "Google",
            ]
            .iter()
            .any(|s| v.contains(s))
        })
        .unwrap_or(false);

    let containerized = std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
        || std::path::Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/self/cgroup")
            .map(|c| {
                ["kubepods", "docker", "containerd", "crio"]
                    .iter()
                    .any(|s| c.contains(s))
            })
            .unwrap_or(false);

    DetectedEnvironment {
        virtualized,
        containerized,
        exclusive_cpuset,
        exclusive_grant,
    }
}

/// Count of CPUs in a sysfs cpu-list string like "0-47" or "0-3,8-11".
fn parse_cpu_list_count(s: &str) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut count = 0usize;
    for part in s.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (usize, usize) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
                count += b.checked_sub(a)?.checked_add(1)?;
            }
            None => {
                let _: usize = part.trim().parse().ok()?;
                count += 1;
            }
        }
    }
    Some(count)
}
