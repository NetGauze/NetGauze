#[cfg(test)]
mod tests;

use nom::{AsBytes, Compare, CompareResult, InputIter, InputLength, InputTake, Offset, Slice};
use std::ops::{RangeFrom, RangeTo};

/// Cloned from the crate `nom_locate` but with the omission of computing
/// the line & column number since we don't care about them in binary protocols,
/// and they do make using the `LocateSpan` slower.
#[derive(Debug, Clone, Copy)]
pub struct BinarySpan<T> {
    offset: usize,
    fragment: T,
}

impl<T> BinarySpan<T> {
    pub const fn new(buffer: T) -> Self {
        Self {
            offset: 0,
            fragment: buffer,
        }
    }

    /// Similar to `new_extra`, but allows overriding offset.
    /// # Safety
    /// This is unsafe, because giving an offset too large may result in
    /// undefined behavior, as some methods move back along the fragment
    /// assuming any negative index within the offset is valid.
    pub const unsafe fn new_from_raw_offset(offset: usize, fragment: T) -> Self {
        Self { offset, fragment }
    }

    pub const fn new_extra(program: T) -> BinarySpan<T> {
        BinarySpan {
            offset: 0,
            fragment: program,
        }
    }

    #[inline]
    pub const fn location_offset(&self) -> usize {
        self.offset
    }

    #[inline]
    pub const fn fragment(&self) -> &T {
        &self.fragment
    }
}

impl<T, R> Slice<R> for BinarySpan<T>
where
    T: Slice<R> + Offset + AsBytes + Slice<RangeTo<usize>>,
{
    #[inline]
    fn slice(&self, range: R) -> Self {
        let next_fragment = self.fragment.slice(range);
        let consumed_len = self.fragment.offset(&next_fragment);
        if consumed_len == 0 {
            return BinarySpan {
                offset: self.offset,
                fragment: next_fragment,
            };
        }

        BinarySpan {
            offset: self.offset + consumed_len,
            fragment: next_fragment,
        }
    }
}

impl<T> InputIter for BinarySpan<T>
where
    T: InputIter,
{
    type Item = T::Item;
    type Iter = T::Iter;
    type IterElem = T::IterElem;
    #[inline]
    fn iter_indices(&self) -> Self::Iter {
        self.fragment.iter_indices()
    }
    #[inline]
    fn iter_elements(&self) -> Self::IterElem {
        self.fragment.iter_elements()
    }
    #[inline]
    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.fragment.position(predicate)
    }
    #[inline]
    fn slice_index(&self, count: usize) -> Result<usize, nom::Needed> {
        self.fragment.slice_index(count)
    }
}

impl<T: InputLength> InputLength for BinarySpan<T> {
    #[inline]
    fn input_len(&self) -> usize {
        self.fragment.input_len()
    }
}

impl<T> InputTake for BinarySpan<T>
where
    Self: Slice<RangeFrom<usize>> + Slice<RangeTo<usize>>,
{
    #[inline]
    fn take(&self, count: usize) -> Self {
        self.slice(..count)
    }

    #[inline]
    fn take_split(&self, count: usize) -> (Self, Self) {
        (self.slice(count..), self.slice(..count))
    }
}

impl<T> core::ops::Deref for BinarySpan<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.fragment
    }
}

impl<T: AsBytes> AsBytes for BinarySpan<T> {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.fragment.as_bytes()
    }
}

impl<T: AsBytes + PartialEq> PartialEq for BinarySpan<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset && self.fragment == other.fragment
    }
}

impl<T: AsBytes + Eq> Eq for BinarySpan<T> {}

impl<A: Compare<B>, B: Into<BinarySpan<B>>> Compare<B> for BinarySpan<A> {
    #[inline(always)]
    fn compare(&self, t: B) -> CompareResult {
        self.fragment.compare(t.into().fragment)
    }

    #[inline(always)]
    fn compare_no_case(&self, t: B) -> CompareResult {
        self.fragment.compare_no_case(t.into().fragment)
    }
}

impl<T: AsBytes> From<T> for BinarySpan<T> {
    #[inline]
    fn from(i: T) -> Self {
        Self::new_extra(i)
    }
}
