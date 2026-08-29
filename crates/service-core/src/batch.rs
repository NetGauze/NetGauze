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

use serde::{Deserialize, Serialize};

/// Headroom reserved before every receive so a maximum-size UDP
/// datagram can never be truncated; the arena must exceed a full
/// cycle by at least this much.
pub(crate) const MAX_DATAGRAM_SIZE: usize = 65_536;
/// Default per-datagram arena budget: comfortable margin over the
/// jumbo 9216 B MTU typical for flow export traffic.
pub(crate) const DEFAULT_ARENA_PER_DATAGRAM: usize = 9_216;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BatchConfig {
    /// BATCH_CAP: max datagrams drained per readiness wakeup.
    /// Default 1024: at ~1us/packet decode that is ~1ms of
    /// worst-case monopoly.
    #[serde(default = "default_batch_capacity")]
    pub cap: usize,

    #[serde(default = "default_yield_every")]
    pub yield_every: usize,

    /// Initial reserve of receive arena, so build() faults the
    /// pages in on the worker's core. Default ~9.5 MiB
    /// (~cap x a jumbo ~9216 B datagram, rounded); reserve() converges
    /// it to the real working size regardless, so this only tunes the
    /// first cycles.
    #[serde(default = "default_initial_arean_size")]
    pub initial_arena: usize,
}

const fn default_batch_capacity() -> usize {
    1024
}

const fn default_yield_every() -> usize {
    64
}

const fn default_initial_arean_size() -> usize {
    default_batch_capacity()
        .saturating_mul(DEFAULT_ARENA_PER_DATAGRAM)
        .saturating_add(MAX_DATAGRAM_SIZE)
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            cap: default_batch_capacity(),
            yield_every: default_yield_every(),
            initial_arena: default_initial_arean_size(),
        }
    }
}

impl BatchConfig {
    /// Admission-time check (config load), reject
    /// early with a named error, never re-validate per cycle.
    /// cap >= 1; 1 <= yield_every <= cap.
    pub const fn validate(&self) -> Result<(), BatchConfigError> {
        if self.cap == 0 {
            return Err(BatchConfigError::ZeroCap);
        }
        if self.yield_every == 0 {
            return Err(BatchConfigError::ZeroYieldEvery);
        }
        if self.yield_every > self.cap {
            return Err(BatchConfigError::YieldEveryExceedsCap {
                yield_every: self.yield_every,
                cap: self.cap,
            });
        }
        // 1500 B floor: the smallest per-datagram budget that keeps MTU
        // traffic allocation-free for a full cycle (see `initial_arena`).
        // Saturating: an absurd `cap` must be REJECTED here, not wrap to
        // a tiny minimum that then dies in Vec::with_capacity.
        let minimum = self
            .cap
            .saturating_mul(1500)
            .saturating_add(MAX_DATAGRAM_SIZE);
        let resolved = self.initial_arena;
        if resolved < minimum {
            return Err(BatchConfigError::ArenaTooSmallForCap {
                initial_arena: resolved,
                cap: self.cap,
                minimum,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatchConfigError {
    #[error("batch.cap must be >= 1: a zero cap makes the drain loop's batch bound unreachable")]
    ZeroCap,

    #[error(
        "batch.yield_every must be >= 1: computed as `i % yield_every`,\
         and `% 0` panics on the hot path"
    )]
    ZeroYieldEvery,

    #[error(
        "batch.yield_every ({yield_every}) must be <= batch.cap ({cap}): \
        a cadence beyond the cap never fires within a batch, \
        silently disabling cooperative yielding"
    )]
    YieldEveryExceedsCap { yield_every: usize, cap: usize },

    #[error(
        "batch.initial_arena ({initial_arena}) is too small for batch.cap ({cap}): \
        one cycle's datagrams pin the arena until cycle end, \
        so it needs at least cap x 1500 B + 64 KiB ({minimum}); \
        undersized, the drain loop silently allocates per packet;\
         the exact cost the arena exists to avoid"
    )]
    ArenaTooSmallForCap {
        initial_arena: usize,
        cap: usize,
        minimum: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert_eq!(BatchConfig::default().validate(), Ok(()));
    }

    #[test]
    fn zero_cap_rejected() {
        let config = BatchConfig {
            cap: 0,
            ..Default::default()
        };
        assert_eq!(config.validate(), Err(BatchConfigError::ZeroCap));
    }

    #[test]
    fn zero_yield_every_rejected() {
        let config = BatchConfig {
            yield_every: 0,
            ..Default::default()
        };
        assert_eq!(config.validate(), Err(BatchConfigError::ZeroYieldEvery));
    }

    #[test]
    fn yield_every_beyond_cap_rejected() {
        let config = BatchConfig {
            cap: 64,
            yield_every: 65,
            ..Default::default()
        };
        assert_eq!(
            config.validate(),
            Err(BatchConfigError::YieldEveryExceedsCap {
                yield_every: 65,
                cap: 64,
            })
        );
    }

    #[test]
    fn arena_undersized_for_cap_rejected() {
        // Default is self-consistent.
        assert_eq!(BatchConfig::default().validate(), Ok(()));

        // The default arena is sized for the DEFAULT cap, so raising cap
        // alone eventually outgrows it is rejected loudly, with the minimum
        // named, rather than silently allocating per packet mid-cycle.
        let outgrown = BatchConfig {
            cap: 8192,
            ..Default::default()
        };
        assert!(matches!(
            outgrown.validate(),
            Err(BatchConfigError::ArenaTooSmallForCap { .. })
        ));

        // Raising cap within the default arena's headroom stays valid
        // (default covers cap <= (1024*9216)/1500 ~= 6291).
        let within = BatchConfig {
            cap: 4096,
            ..Default::default()
        };
        assert_eq!(within.validate(), Ok(()));

        // Sizing the arena with the cap is what an operator must do.
        let sized = BatchConfig {
            cap: 8192,
            initial_arena: 8192 * DEFAULT_ARENA_PER_DATAGRAM + MAX_DATAGRAM_SIZE,
            ..Default::default()
        };
        assert_eq!(sized.validate(), Ok(()));
    }

    #[test]
    fn boundary_yield_every_equals_cap_accepted() {
        let config = BatchConfig {
            cap: 64,
            yield_every: 64,
            ..Default::default()
        };
        assert_eq!(config.validate(), Ok(()));
    }
}
