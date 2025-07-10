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

//! Configuration structures and validation for flow aggregation.
//!
//! Defines aggregation configuration including window duration, lateness
//! tolerance, field transformations, and operation types. Provides validation
//! for operation compatibility with different Information Element (IE) types
//! and converts user-facing configuration into internal unified format for
//! efficient processing.

use indexmap::IndexMap;
use netgauze_flow_pkt::ie::IE;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use strum_macros::Display;

#[derive(Debug, Clone)]
pub enum ConfigurationError {
    InvalidWorkerCount,
    InvalidWindowDuration,
    LatenessExceedsWindowDuration,
    InvalidOperation { ie: IE, op: Op, reason: String },
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWorkerCount => write!(f, "workers must be greater than 0"),
            Self::InvalidWindowDuration => write!(f, "window_duration must be greater than 0"),
            Self::LatenessExceedsWindowDuration => {
                write!(f, "lateness cannot exceed window_duration")
            }
            Self::InvalidOperation { ie, op, reason } => {
                write!(f, "invalid operation \"{op}\" for \"{ie:?}\" [{reason}]")
            }
        }
    }
}

impl std::error::Error for ConfigurationError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    pub workers: usize,
    pub window_duration: Duration,
    pub lateness: Duration,
    pub transform: IndexMap<IE, Transform>,
}

impl AggregationConfig {
    pub fn workers(&self) -> usize {
        self.workers
    }
    pub fn window_duration(&self) -> Duration {
        self.window_duration
    }
    pub fn lateness(&self) -> Duration {
        self.lateness
    }
    pub fn transform(&self) -> &IndexMap<IE, Transform> {
        &self.transform
    }
}

impl Default for AggregationConfig {
    fn default() -> Self {
        AggregationConfig {
            workers: 1,
            window_duration: Duration::from_secs(60),
            lateness: Duration::from_secs(10),
            transform: IndexMap::new(),
        }
    }
}

impl AggregationConfig {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.workers == 0 {
            return Err(ConfigurationError::InvalidWorkerCount);
        }

        if self.window_duration.is_zero() {
            return Err(ConfigurationError::InvalidWindowDuration);
        }

        if self.lateness > self.window_duration {
            return Err(ConfigurationError::LatenessExceedsWindowDuration);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Transform {
    Single(Op),
    Multi(IndexMap<usize, Op>),
}

#[derive(Display, Clone, Copy, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum Op {
    Key,
    Add,
    Min,
    Max,
    BoolMapOr,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub(crate) enum AggOp {
    Add,
    Min,
    Max,
    BoolMapOr,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FieldRef {
    ie: IE,
    index: usize,
}
impl FieldRef {
    pub(crate) fn new(ie: IE, index: usize) -> Self {
        Self { ie, index }
    }
    pub(crate) fn ie(&self) -> IE {
        self.ie
    }
    pub(crate) fn index(&self) -> usize {
        self.index
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AggFieldRef {
    field_ref: FieldRef,
    op: AggOp,
}
impl AggFieldRef {
    #[cfg(test)]
    pub(crate) fn new(ie: IE, index: usize, op: AggOp) -> Self {
        Self {
            field_ref: FieldRef { ie, index },
            op,
        }
    }
    pub(crate) fn field_ref(&self) -> FieldRef {
        self.field_ref
    }
    pub(crate) fn op(&self) -> AggOp {
        self.op
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct UnifiedConfig {
    window_duration: Duration,
    lateness: Duration,
    key_select: Box<[FieldRef]>,
    agg_select: Box<[AggFieldRef]>,
}
impl UnifiedConfig {
    #[cfg(test)]
    pub(crate) fn new(
        window_duration: Duration,
        lateness: Duration,
        key_select: Box<[FieldRef]>,
        agg_select: Box<[AggFieldRef]>,
    ) -> Self {
        Self {
            window_duration,
            lateness,
            key_select,
            agg_select,
        }
    }
    pub(crate) fn window_duration(&self) -> Duration {
        self.window_duration
    }
    pub(crate) fn lateness(&self) -> Duration {
        self.lateness
    }
    pub(crate) fn key_select(&self) -> &[FieldRef] {
        &self.key_select
    }
    pub(crate) fn agg_select(&self) -> &[AggFieldRef] {
        &self.agg_select
    }
}

/// Validates that the given aggregation operation is compatible with the IE
/// field's capabilities
fn validate_operation_compatibility(ie: &IE, op: &Op) -> Result<(), ConfigurationError> {
    match op {
        Op::Key => Ok(()), // Key operations are allowed for all IEs
        Op::Add => {
            if ie.supports_arithmetic_ops() {
                Ok(())
            } else {
                Err(ConfigurationError::InvalidOperation {
                    ie: *ie,
                    op: *op,
                    reason: "field does not support arithmetic operations".to_string(),
                })
            }
        }
        Op::Min | Op::Max => {
            if ie.supports_comparison_ops() {
                Ok(())
            } else {
                Err(ConfigurationError::InvalidOperation {
                    ie: *ie,
                    op: *op,
                    reason: "field does not support comparison operations".to_string(),
                })
            }
        }
        Op::BoolMapOr => {
            if ie.supports_bitwise_ops() {
                Ok(())
            } else {
                Err(ConfigurationError::InvalidOperation {
                    ie: *ie,
                    op: *op,
                    reason: "field does not support bitwise operations".to_string(),
                })
            }
        }
    }
}

impl TryInto<UnifiedConfig> for AggregationConfig {
    type Error = ConfigurationError;

    fn try_into(self) -> Result<UnifiedConfig, Self::Error> {
        // Validate basic knobs
        self.validate()?;

        let mut key_select = Vec::new();
        let mut agg_select = Vec::new();

        for (ie, transform) in self.transform {
            match transform {
                Transform::Single(aggr_op) => {
                    validate_operation_compatibility(&ie, &aggr_op)?;

                    match aggr_op {
                        Op::Key => {
                            key_select.push(FieldRef { ie, index: 0 });
                        }
                        Op::Add => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::Add,
                            });
                        }
                        Op::Min => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::Min,
                            });
                        }
                        Op::Max => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::Max,
                            });
                        }
                        Op::BoolMapOr => {
                            agg_select.push(AggFieldRef {
                                field_ref: FieldRef { ie, index: 0 },
                                op: AggOp::BoolMapOr,
                            });
                        }
                    }
                }
                Transform::Multi(index_map) => {
                    for (index, aggr_op) in index_map {
                        validate_operation_compatibility(&ie, &aggr_op)?;

                        match aggr_op {
                            Op::Key => {
                                key_select.push(FieldRef { ie, index });
                            }
                            Op::Add => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::Add,
                                });
                            }
                            Op::Min => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::Min,
                                });
                            }
                            Op::Max => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::Max,
                                });
                            }
                            Op::BoolMapOr => {
                                agg_select.push(AggFieldRef {
                                    field_ref: FieldRef { ie, index },
                                    op: AggOp::BoolMapOr,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(UnifiedConfig {
            window_duration: self.window_duration,
            lateness: self.lateness,
            key_select: key_select.into_boxed_slice(),
            agg_select: agg_select.into_boxed_slice(),
        })
    }
}
