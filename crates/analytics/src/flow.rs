#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum AggrOp {
    Key(Option<Vec<usize>>),
    Add,
    Min,
    Max,
    BoolMapOr,
}

// Flow Aggregation Generic Helper Functions
#[inline]
pub fn reduce_num_vec<T: Copy + std::ops::AddAssign + Ord>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    op: &AggrOp,
) {
    match op {
        AggrOp::Key(indices) => set_field_vec(lhs, rhs, indices),
        AggrOp::Add => addup_num_vec(lhs, rhs),
        AggrOp::Min => minup_num_vec(lhs, rhs),
        AggrOp::Max => maxup_num_vec(lhs, rhs),
        AggrOp::BoolMapOr => {}
    }
}

#[inline]
pub fn reduce_boolmap_vec<T: Copy + std::ops::BitOrAssign>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    op: &AggrOp,
) {
    match op {
        AggrOp::Key(indices) => set_field_vec(lhs, rhs, indices),
        AggrOp::Add => {}
        AggrOp::Min => {}
        AggrOp::Max => {}
        AggrOp::BoolMapOr => bmoup_map_vec(lhs, rhs),
    }
}

#[inline]
pub fn reduce_misc_vec<T: Copy>(lhs: &mut Option<Vec<T>>, rhs: &Option<Vec<T>>, op: &AggrOp) {
    match op {
        AggrOp::Key(indices) => set_field_vec(lhs, rhs, indices),
        AggrOp::Add => {}
        AggrOp::Min => {}
        AggrOp::Max => {}
        AggrOp::BoolMapOr => {}
    }
}

#[inline]
pub fn reduce_misc_vec_clone<T: Clone>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    op: &AggrOp,
) {
    match op {
        AggrOp::Key(indices) => set_field_vec_clone(lhs, rhs, indices),
        AggrOp::Add => {}
        AggrOp::Min => {}
        AggrOp::Max => {}
        AggrOp::BoolMapOr => {}
    }
}

#[inline]
pub fn set_field_vec<T: Copy>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    indices: &Option<Vec<usize>>,
) {
    if let Some(idxs) = indices {
        if let Some(rhs_vec) = rhs {
            let res: Vec<T> = idxs
                .iter()
                .filter_map(|&idx| rhs_vec.get(idx).copied())
                .collect();
            *lhs = if res.is_empty() { None } else { Some(res) };
        }
    } else if let Some(rhs_vec) = rhs {
        *lhs = Some(rhs_vec.iter().copied().collect());
    } else {
        *lhs = None;
    }
}

#[inline]
pub fn set_field_vec_clone<T: Clone>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
    indices: &Option<Vec<usize>>,
) {
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
}

#[inline]
pub fn addup_num_vec<T: Copy + std::ops::AddAssign>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
) {
    match (lhs.as_mut(), rhs) {
        (None, _) => *lhs = rhs.clone(),
        (Some(_), None) => {
            // Incoming doesn't have any value
        }
        (Some(lhs), Some(rhs)) => {
            lhs.iter_mut().zip(rhs.iter()).for_each(|(a, b)| *a += *b);

            // If the other value is longer, just append to the vector
            if rhs.len() > lhs.len() {
                for i in rhs[lhs.len()..].iter() {
                    lhs.push(*i);
                }
            }
        }
    }
}

#[inline]
pub fn minup_num_vec<T: Copy + std::cmp::Ord>(lhs: &mut Option<Vec<T>>, rhs: &Option<Vec<T>>) {
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
                for i in rhs[lhs.len()..].iter() {
                    lhs.push(*i);
                }
            }
        }
    }
}

#[inline]
pub fn maxup_num_vec<T: Copy + std::cmp::Ord>(lhs: &mut Option<Vec<T>>, rhs: &Option<Vec<T>>) {
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
                for i in rhs[lhs.len()..].iter() {
                    lhs.push(*i);
                }
            }
        }
    }
}

#[inline]
pub fn bmoup_map_vec<T: Copy + std::ops::BitOrAssign>(
    lhs: &mut Option<Vec<T>>,
    rhs: &Option<Vec<T>>,
) {
    match (lhs.as_mut(), rhs) {
        (None, _) => *lhs = rhs.clone(),
        (Some(_), None) => {
            // Incoming doesn't have any value
        }
        (Some(lhs), Some(rhs)) => {
            lhs.iter_mut().zip(rhs.iter()).for_each(|(a, b)| *a |= *b);

            // If the other value is longer, just append to the vector
            if rhs.len() > lhs.len() {
                for i in rhs[lhs.len()..].iter() {
                    lhs.push(*i);
                }
            }
        }
    }
}
