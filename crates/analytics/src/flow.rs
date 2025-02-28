// Copyright (C) 2023-present The NetGauze Authors.
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

use std::error::Error;
use strum_macros::Display;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum AggrOp {
    Key(Option<Vec<usize>>),
    Add,
    Min,
    Max,
    BoolMapOr,
}

#[derive(Debug, Clone, Display)]
pub enum AggregationError {
    FlatSetIsNotData,
    FlatFlowInfoNFv9NotSupported,
    OperationNotSupported,
}

impl Error for AggregationError {}

// Flow Aggregation Generic Helper Functions
#[inline]
pub fn reduce_num<T: Copy + std::ops::AddAssign + Ord>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    op: &AggrOp,
) -> Result<(), AggregationError> {
    match op {
        AggrOp::Key(indices) => set_field(lhs, rhs, indices),
        AggrOp::Add => aggr_add(lhs, rhs),
        AggrOp::Min => aggr_min(lhs, rhs),
        AggrOp::Max => aggr_max(lhs, rhs),
        AggrOp::BoolMapOr => Err(AggregationError::OperationNotSupported),
    }
}

#[inline]
pub fn reduce_boolmap<T: Copy + std::ops::BitOrAssign>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    op: &AggrOp,
) -> Result<(), AggregationError> {
    match op {
        AggrOp::Key(indices) => set_field(lhs, rhs, indices),
        AggrOp::Add => Err(AggregationError::OperationNotSupported),
        AggrOp::Min => Err(AggregationError::OperationNotSupported),
        AggrOp::Max => Err(AggregationError::OperationNotSupported),
        AggrOp::BoolMapOr => aggr_bitor(lhs, rhs),
    }
}

#[inline]
pub fn reduce_misc<T: Copy>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    op: &AggrOp,
) -> Result<(), AggregationError> {
    match op {
        AggrOp::Key(indices) => set_field(lhs, rhs, indices),
        AggrOp::Add => Err(AggregationError::OperationNotSupported),
        AggrOp::Min => Err(AggregationError::OperationNotSupported),
        AggrOp::Max => Err(AggregationError::OperationNotSupported),
        AggrOp::BoolMapOr => Err(AggregationError::OperationNotSupported),
    }
}

#[inline]
pub fn reduce_misc_clone<T: Clone>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    op: &AggrOp,
) -> Result<(), AggregationError> {
    match op {
        AggrOp::Key(indices) => set_field_clone(lhs, rhs, indices),
        AggrOp::Add => Err(AggregationError::OperationNotSupported),
        AggrOp::Min => Err(AggregationError::OperationNotSupported),
        AggrOp::Max => Err(AggregationError::OperationNotSupported),
        AggrOp::BoolMapOr => Err(AggregationError::OperationNotSupported),
    }
}

#[inline]
fn set_field<T: Copy>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    indices: &Option<Vec<usize>>,
) -> Result<(), AggregationError> {
    if let Some(idxs) = indices {
        if let Some(rhs_vec) = rhs {
            let res: Vec<T> = idxs
                .iter()
                .filter_map(|&idx| rhs_vec.get(idx).copied())
                .collect();
            *lhs = if res.is_empty() { None } else { Some(res) };
        }
    } else if let Some(rhs_vec) = rhs {
        *lhs = Some(rhs_vec.to_vec());
    } else {
        *lhs = None;
    }
    Ok(())
}

#[inline]
fn set_field_clone<T: Clone>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    indices: &Option<Vec<usize>>,
) -> Result<(), AggregationError> {
    if let Some(idxs) = indices {
        if let Some(rhs_vec) = rhs {
            let res: Vec<T> = idxs
                .iter()
                .filter_map(|&idx| rhs_vec.get(idx).cloned())
                .collect();
            *lhs = if res.is_empty() { None } else { Some(res) };
        }
    } else {
        *lhs = rhs.clone();
    }
    Ok(())
}

#[inline]
fn aggr_add<T: Copy + std::ops::AddAssign>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
) -> Result<(), AggregationError> {
    match (lhs.as_mut(), rhs) {
        (None, _) => *lhs = rhs.clone(),
        (Some(_), None) => {
            // Incoming doesn't have any value
        }
        (Some(lhs), Some(rhs)) => {
            lhs.iter_mut().zip(rhs.iter()).for_each(|(a, b)| *a += *b);

            // If the other value is longer, just append to the vector
            if rhs.len() > lhs.len() {
                for i in &rhs[lhs.len()..] {
                    lhs.push(*i);
                }
            }
        }
    }
    Ok(())
}

#[inline]
fn aggr_min<T: Copy + std::cmp::Ord>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
) -> Result<(), AggregationError> {
    match (lhs.as_mut(), rhs) {
        (None, _) => *lhs = rhs.clone(),
        (Some(_), None) => {
            // Incoming doesn't have any value
        }
        (Some(lhs), Some(rhs)) => {
            lhs.iter_mut()
                .zip(rhs.iter())
                .for_each(|(a, b)| *a = std::cmp::min(*a, *b));

            // If the other value is longer, just append to the vector
            if rhs.len() > lhs.len() {
                for i in &rhs[lhs.len()..] {
                    lhs.push(*i);
                }
            }
        }
    }
    Ok(())
}

#[inline]
fn aggr_max<T: Copy + std::cmp::Ord>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
) -> Result<(), AggregationError> {
    match (lhs.as_mut(), rhs) {
        (None, _) => *lhs = rhs.clone(),
        (Some(_), None) => {
            // Incoming doesn't have any value
        }
        (Some(lhs), Some(rhs)) => {
            lhs.iter_mut()
                .zip(rhs.iter())
                .for_each(|(a, b)| *a = std::cmp::max(*a, *b));

            // If the other value is longer, just append to the vector
            if rhs.len() > lhs.len() {
                for i in &rhs[lhs.len()..] {
                    lhs.push(*i);
                }
            }
        }
    }
    Ok(())
}

#[inline]
fn aggr_bitor<T: Copy + std::ops::BitOrAssign>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
) -> Result<(), AggregationError> {
    match (lhs.as_mut(), rhs) {
        (None, _) => *lhs = rhs.clone(),
        (Some(_), None) => {
            // Incoming doesn't have any value
        }
        (Some(lhs), Some(rhs)) => {
            lhs.iter_mut().zip(rhs.iter()).for_each(|(a, b)| *a |= *b);

            // If the other value is longer, just append to the vector
            if rhs.len() > lhs.len() {
                for i in &rhs[lhs.len()..] {
                    lhs.push(*i);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce_num_add_lhs_longer() {
        let mut lhs = Some(vec![1, 1, 1]);
        let rhs = Some(vec![1, 1]);
        let op = AggrOp::Add;
        reduce_num(&mut lhs, &rhs, &op).unwrap();
        assert_eq!(lhs, Some(vec![2, 2, 1]));
    }

    #[test]
    fn test_reduce_num_add_rhs_longer() {
        let mut lhs = Some(vec![1, 1]);
        let rhs = Some(vec![1, 1, 1]);
        let op = AggrOp::Add;
        reduce_num(&mut lhs, &rhs, &op).unwrap();
        assert_eq!(lhs, Some(vec![2, 2, 1]));
    }

    #[test]
    fn test_reduce_num_min() {
        let mut lhs = Some(vec![5, 6, 7]);
        let rhs = Some(vec![4, 7, 6]);
        let op = AggrOp::Min;
        reduce_num(&mut lhs, &rhs, &op).unwrap();
        assert_eq!(lhs, Some(vec![4, 6, 6]));
    }

    #[test]
    fn test_reduce_num_max() {
        let mut lhs = Some(vec![1, 2, 3]);
        let rhs = Some(vec![4, 1, 5]);
        let op = AggrOp::Max;
        reduce_num(&mut lhs, &rhs, &op).unwrap();
        assert_eq!(lhs, Some(vec![4, 2, 5]));
    }

    #[test]
    fn test_reduce_boolmap_bitor() {
        let mut lhs = Some(vec![0b001, 0b001, 0b010]);
        let rhs = Some(vec![0b001, 0b0100, 0b100]);
        let op = AggrOp::BoolMapOr;
        reduce_boolmap(&mut lhs, &rhs, &op).unwrap();
        assert_eq!(lhs, Some(vec![0b001, 0b101, 0b110]));
    }

    #[test]
    fn test_reduce_misc() {
        let mut lhs = None;
        let rhs = Some(vec![1, 2, 3, 4, 5]);
        let op = AggrOp::Key(Some(vec![0, 2, 4]));
        reduce_misc(&mut lhs, &rhs, &op).unwrap();
        assert_eq!(lhs, Some(vec![1, 3, 5]));
    }

    #[test]
    fn test_reduce_misc_clone() {
        let mut lhs = None;
        let rhs = Some(vec![
            String::from("a"),
            String::from("b"),
            String::from("c"),
        ]);
        let op = AggrOp::Key(Some(vec![0, 2]));
        reduce_misc_clone(&mut lhs, &rhs, &op).unwrap();
        assert_eq!(lhs, Some(vec![String::from("a"), String::from("c")]));
    }
}
