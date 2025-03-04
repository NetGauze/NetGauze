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

//! A module that provides functionality for time-series data aggregation using
//! a windowing system.
//!
//! The main components are:
//! - `TimeSeriesData`: A trait that defines required methods for time-series
//!   data points
//! - `Aggregator`: A trait defining how data should be aggregated within
//!   windows
//! - `WindowAggregator`: Core struct that manages the windowing and aggregation
//!   logic
//! - `WindowedAggregationAdaptor`: Iterator adapter providing an ergonomic API
//!   over WindowAggregator
//!
//! The windowing system features:
//! - Fixed-sized time windows defined by start and end timestamps
//! - Support for late-arriving data with configurable lateness thresholds
//! - Generic aggregation logic via the Aggregator trait
//! - Key-based partitioning of data streams
//!
//! Example usage:
//! ```text
//! use std::time::Duration;
//! use netgauze_analytics::aggregation::TimeSeriesData;
//!
//! let data_stream = get_time_series_data_iterator();
//! let results = data_stream
//!     .window_aggregate(
//!         Duration::from_secs(60), // 1 minute windows
//!         Duration::from_secs(10), // 10 seconds lateness allowed
//!         MyAggregator::init()
//!     )
//!     .filter_map(|x| x.left()) // Keep only successful aggregations
//!     .collect::<Vec<_>>();
//! ```

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use futures_core::Stream;
use pin_project::pin_project;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    hash::Hash,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// A time window defined by a start and (noninclusive) end timestamp
pub type Window = (DateTime<Utc>, DateTime<Utc>);

/// A trait for defining time-series data points
pub trait TimeSeriesData<K> {
    fn get_key(&self) -> K;
    fn get_ts(&self) -> DateTime<Utc>;
}

/// A trait for defining aggregation logic
pub trait Aggregator<Init, Input, Output> {
    fn init(init: Init) -> Self;
    fn push(&mut self, item: Input);
    fn flush(self) -> Output;
}

/// Helper function to return the start of the window containing the given
/// timestamp
pub(crate) fn get_window_start(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(
        timestamp.year(),
        timestamp.month(),
        timestamp.day(),
        timestamp.hour(),
        timestamp.minute(),
        0,
    )
    .unwrap()
}

/// A struct for window-based aggregation of time-series data.
///
/// The struct maintains a set of active windows per key and aggregates data
/// within those windows per key. It also handles out-of-order data and
/// late-arriving events.
#[derive(Clone, Debug)]
pub struct WindowAggregator<Key, AggInit, AggregatorImpl> {
    /// Active windows being aggregated
    active_windows: HashMap<Key, BTreeMap<DateTime<Utc>, AggregatorImpl>>,
    /// Current event-time for the aggregator, i.e., the max timestamp of all
    /// events observed so far for each key
    current_time: HashMap<Key, DateTime<Utc>>,
    /// Duration of the aggregation window
    window_duration: Duration,
    /// Allowed lateness for out-of-order events
    lateness: Duration,
    agg_init: AggInit,
}

impl<Key: Eq + Hash + Clone, AggInit: Clone, AggregatorImpl>
    WindowAggregator<Key, AggInit, AggregatorImpl>
{
    /// Create a new `WindowAggregator` with the given window duration and
    /// lateness threshold
    fn new(window_duration: Duration, lateness: Duration, agg_init: AggInit) -> Self {
        Self {
            active_windows: HashMap::new(),
            current_time: HashMap::new(),
            window_duration,
            lateness,
            agg_init,
        }
    }
    fn process_item<Input, AggValue>(
        &mut self,
        item: Input,
    ) -> (
        impl Iterator<Item = (Window, AggValue)> + '_,
        impl Iterator<Item = Input>,
    )
    where
        Input: TimeSeriesData<Key>,
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
    {
        let ts = item.get_ts();
        let key = item.get_key();
        let mut late_items = Vec::with_capacity(1);
        let mut split = BTreeMap::new();
        let current_time = self.current_time.entry(key.clone()).or_insert_with(|| ts);
        if ts < *current_time - self.lateness {
            late_items.push(item);
        } else {
            *current_time = (*current_time).max(ts);
            let window_start = get_window_start(ts);
            let active_windows = self.active_windows.entry(key).or_default();
            // Aggregates the value in the current window (or create new one if needed)

            active_windows
                .entry(window_start)
                .or_insert_with(|| AggregatorImpl::init(self.agg_init.clone()))
                .push(item);

            let cutoff_time: DateTime<Utc> =
                get_window_start((*current_time) - self.lateness) - self.window_duration;

            split = active_windows.split_off(&cutoff_time);
            std::mem::swap(&mut split, active_windows);
            if let Some(entry) = active_windows.remove(&cutoff_time) {
                split.insert(cutoff_time, entry);
            }
        }
        (
            split.into_iter().map(|(window_start, agg)| {
                (
                    (window_start, window_start + self.window_duration),
                    agg.flush(),
                )
            }),
            late_items.into_iter(),
        )
    }

    /// Flushes the current state of the aggregator, returning the aggregated
    /// results for all active windows
    fn flush<Input, AggValue>(&mut self) -> impl Iterator<Item = (Window, AggValue)> + '_
    where
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
    {
        let active_windows = std::mem::take(&mut self.active_windows);
        self.current_time.clear();
        active_windows
            .into_values()
            .flat_map(|x| x.into_iter())
            .map(move |(ts, agg)| ((ts, ts + self.window_duration), agg.flush()))
    }
}

/// An iterator adaptor that provides an ergonomic API for window-based
/// aggregation
///
/// The adaptor takes an iterator of time-series data points and aggregates them
/// into fixed-size time windows using the provided aggregation function.
pub struct WindowedAggregationAdaptor<
    Key,
    Input,
    AggInit: Clone,
    AggValue,
    AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
    I: Iterator<Item = Input>,
> {
    source: I,
    aggregator: WindowAggregator<Key, AggInit, AggregatorImpl>,
    buffer: VecDeque<(Window, AggValue)>,
    late_buffer: VecDeque<Input>,
    /// _agg_fn is not needed per-say, but it makes rust typing much easier
    _agg_fn: AggregatorImpl,
    _phantom1: PhantomData<Key>,
    _phantom2: PhantomData<AggInit>,
}

impl<
        Key: Eq + Hash + Clone,
        Input,
        AggInit: Clone,
        AggValue,
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
        I: Iterator<Item = Input>,
    > WindowedAggregationAdaptor<Key, Input, AggInit, AggValue, AggregatorImpl, I>
{
    fn new(
        source: I,
        duration: Duration,
        lateness: Duration,
        agg_init: AggInit,
        agg_fn: AggregatorImpl,
    ) -> Self {
        Self {
            source,
            aggregator: WindowAggregator::new(duration, lateness, agg_init),
            buffer: VecDeque::new(),
            late_buffer: VecDeque::new(),
            _agg_fn: agg_fn,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        }
    }

    #[inline]
    fn get_next(&mut self) -> Option<either::Either<(Window, AggValue), Input>> {
        if let Some(late) = self.late_buffer.pop_front() {
            return Some(either::Right(late));
        }
        if let Some(agg_value) = self.buffer.pop_front() {
            return Some(either::Left(agg_value));
        }
        None
    }
}

impl<
        Key: Eq + Hash + Clone,
        Input: TimeSeriesData<Key>,
        AggInit: Clone,
        AggValue,
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
        I: Iterator<Item = Input>,
    > Iterator for WindowedAggregationAdaptor<Key, Input, AggInit, AggValue, AggregatorImpl, I>
{
    type Item = either::Either<(Window, AggValue), Input>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // First, return any buffered results
            if let Some(next) = self.get_next() {
                return Some(next);
            }
            // Get next item from source
            match self.source.next() {
                Some(item) => {
                    // Process the item and collect any completed windows
                    let (results, late) = self.aggregator.process_item(item);
                    self.buffer.extend(results);
                    self.late_buffer.extend(late);
                    // If we have late data or results, return the first one
                    if let Some(next) = self.get_next() {
                        return Some(next);
                    }
                }
                None => {
                    // Source is exhausted, flush remaining windows
                    if self.buffer.is_empty() {
                        self.buffer.extend(self.aggregator.flush());
                    }
                    return self.get_next();
                }
            }
        }
    }
}

pub trait AggregationWindowingExt<
    Key: Eq + Hash + Clone,
    Input: TimeSeriesData<Key>,
    AggInit: Clone,
    AggValue,
    AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
>: Iterator<Item = Input> + Sized
{
    fn window_aggregate(
        self,
        window_duration: Duration,
        lateness: Duration,
        agg_init: AggInit,
        agg_fn: AggregatorImpl,
    ) -> WindowedAggregationAdaptor<Key, Input, AggInit, AggValue, AggregatorImpl, Self> {
        WindowedAggregationAdaptor::new(self, window_duration, lateness, agg_init, agg_fn)
    }
}

impl<
        Key: Eq + Hash + Clone,
        Input: TimeSeriesData<Key>,
        AggInit: Clone,
        AggValue,
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
        I: Iterator<Item = Input>,
    > AggregationWindowingExt<Key, Input, AggInit, AggValue, AggregatorImpl> for I
{
}

#[pin_project]
pub struct WindowedAggregationStreamAdaptor<
    Key,
    Input,
    AggInit: Clone,
    AggValue,
    AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
    I: Stream<Item = Input>,
> {
    #[pin]
    source: I,
    #[pin]
    aggregator: WindowAggregator<Key, AggInit, AggregatorImpl>,
    #[pin]
    buffer: VecDeque<(Window, AggValue)>,
    #[pin]
    late_buffer: VecDeque<Input>,
    /// _agg_fn is not needed per-say, but it makes rust typing much easier
    _agg_fn: AggregatorImpl,
    _phantom: PhantomData<(Key, AggInit)>,
}

impl<
        Key: Eq + Hash + Clone,
        Input,
        AggInit: Clone,
        AggValue,
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
        I: Stream<Item = Input>,
    > WindowedAggregationStreamAdaptor<Key, Input, AggInit, AggValue, AggregatorImpl, I>
{
    pub fn new(
        source: I,
        duration: Duration,
        lateness: Duration,
        agg_init: AggInit,
        agg_fn: AggregatorImpl,
    ) -> Self {
        Self {
            source,
            aggregator: WindowAggregator::new(duration, lateness, agg_init),
            buffer: VecDeque::new(),
            late_buffer: VecDeque::new(),
            _agg_fn: agg_fn,
            _phantom: PhantomData,
        }
    }
}

impl<
        Key: Eq + Hash + Clone + Unpin,
        Input: TimeSeriesData<Key> + Unpin,
        AggInit: Clone + Unpin,
        AggValue: Unpin,
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
        I: Stream<Item = Input>,
    > Stream
    for WindowedAggregationStreamAdaptor<Key, Input, AggInit, AggValue, AggregatorImpl, I>
{
    type Item = either::Either<(Window, AggValue), Input>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            // First, return any buffered results
            if let Some(late) = this.late_buffer.pop_front() {
                return Poll::Ready(Some(either::Right(late)));
            }
            if let Some(agg_value) = this.buffer.pop_front() {
                return Poll::Ready(Some(either::Left(agg_value)));
            }
            // Get next item from source
            match this.source.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    // Process the item and collect any completed windows
                    let (results, late) = this.aggregator.process_item(item);
                    this.buffer.extend(results);
                    this.late_buffer.extend(late);
                    // If we have late data or results, return the first one
                    if let Some(late) = this.late_buffer.pop_front() {
                        return Poll::Ready(Some(either::Right(late)));
                    }
                    if let Some(agg_value) = this.buffer.pop_front() {
                        return Poll::Ready(Some(either::Left(agg_value)));
                    }
                }
                Poll::Ready(None) => {
                    // Source is exhausted, flush remaining windows
                    if this.buffer.is_empty() {
                        this.buffer.extend(this.aggregator.flush());
                    }
                    if let Some(late) = this.late_buffer.pop_front() {
                        return Poll::Ready(Some(either::Right(late)));
                    }
                    if let Some(agg_value) = this.buffer.pop_front() {
                        return Poll::Ready(Some(either::Left(agg_value)));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub trait AggregationWindowStreamExt<
    Key: Eq + Hash + Clone + Unpin,
    Input: TimeSeriesData<Key> + Unpin,
    AggInit: Clone + Unpin,
    AggValue,
    AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
>: Stream<Item = Input>
{
    fn window_aggregate(
        self,
        window_duration: Duration,
        lateness: Duration,
        agg_init: AggInit,
        agg_fn: AggregatorImpl,
    ) -> WindowedAggregationStreamAdaptor<Key, Input, AggInit, AggValue, AggregatorImpl, Self>
    where
        Self: Sized,
    {
        WindowedAggregationStreamAdaptor::new(self, window_duration, lateness, agg_init, agg_fn)
    }
}

impl<
        Key: Eq + Hash + Clone + Unpin,
        Input: TimeSeriesData<Key> + Unpin,
        AggInit: Clone + Unpin,
        AggValue,
        AggregatorImpl: Aggregator<AggInit, Input, AggValue>,
        I: Stream<Item = Input>,
    > AggregationWindowStreamExt<Key, Input, AggInit, AggValue, AggregatorImpl> for I
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use futures::{stream, StreamExt};
    use std::ops::Add;

    // Test item that can be time-windowed
    #[derive(Debug, Clone, PartialEq)]
    struct TestItem {
        key: String,
        ts: DateTime<Utc>,
        value: i32,
    }

    impl TimeSeriesData<String> for TestItem {
        fn get_key(&self) -> String {
            self.key.clone()
        }
        fn get_ts(&self) -> DateTime<Utc> {
            self.ts
        }
    }

    // Aggregator that sums the values of the items
    #[derive(Debug, Clone)]
    struct TestAggregator {
        sum: i32,
    }

    impl Aggregator<(), TestItem, i32> for TestAggregator {
        fn init(_: ()) -> Self {
            Self { sum: 0 }
        }
        fn push(&mut self, item: TestItem) {
            self.sum += item.value;
        }
        fn flush(self) -> i32 {
            self.sum
        }
    }

    #[allow(clippy::type_complexity)]
    fn get_test_input() -> (Vec<TestItem>, Vec<either::Either<(Window, i32), TestItem>>) {
        let input = vec![
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                value: 1,
            },
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 0).unwrap(),
                value: 3,
            },
            // Out-of-order event, but still within the allowed lateness of 10 seconds
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 55).unwrap(),
                value: 2,
            },
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 30).unwrap(),
                value: 4,
            },
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 2, 10).unwrap(),
                value: 5,
            },
            // Out-of-order event, but not within the allowed lateness of 10 seconds
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 40).unwrap(),
                value: 5,
            },
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 3, 10).unwrap(),
                value: 5,
            },
        ];
        let expected_results_with_late = vec![
            either::Left((
                (
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 0).unwrap(),
                ),
                3, // The sum of values at 2025-01-01:00:00:00 2025-01-01:00:00:55
            )),
            either::Left((
                (
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 0).unwrap(),
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 2, 0).unwrap(),
                ),
                7, // The sum of values at 2025-01-01:00:01:00 2025-01-01:00:01:30
            )),
            // The late event which is dropped
            either::Right(TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 40).unwrap(),
                value: 5,
            }),
            either::Left((
                (
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 2, 0).unwrap(),
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 3, 0).unwrap(),
                ),
                5, // The sum of values at 2025-01-01:00:02:10
            )),
            either::Left((
                (
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 3, 0).unwrap(),
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 4, 0).unwrap(),
                ),
                5, // The sum of values at 2025-01-01:00:03:10
            )),
        ];
        (input, expected_results_with_late)
    }

    #[test]
    fn test_window_aggregator() {
        let mut window_aggregator = WindowAggregator::<String, (), TestAggregator>::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            (),
        );
        let (items, expected_results) = get_test_input();
        // Note this doesn't include the final event since the window doesn't close
        // without a new event with a timestamp greater than the current time + lateness
        let expected_on_time: Vec<_> = expected_results[0..expected_results.len() - 1]
            .iter()
            .cloned()
            .flat_map(|i| i.left())
            .collect();
        let expected_flush: Vec<_> = expected_results
            [expected_results.len() - 1..expected_results.len()]
            .iter()
            .cloned()
            .flat_map(|i| i.left())
            .collect();
        let expected_late: Vec<_> = expected_results
            .iter()
            .cloned()
            .flat_map(|i| i.right())
            .collect();
        let mut results = vec![];
        let mut late_values = vec![];
        for item in items {
            let (processed, late) = window_aggregator.process_item(item);
            results.extend(processed);
            late_values.extend(late);
        }
        let flushed: Vec<_> = window_aggregator.flush().collect();
        assert_eq!(results, expected_on_time);
        assert_eq!(flushed, expected_flush);
        assert_eq!(late_values, expected_late);
    }

    #[test]
    fn test_window_aggregator_iterator() {
        let (items, expected_results) = get_test_input();
        let expected_on_time: Vec<_> = expected_results
            .iter()
            .cloned()
            .flat_map(|i| i.left())
            .collect();
        let results_with_late: Vec<_> = items
            .clone()
            .into_iter()
            .window_aggregate(
                Duration::from_secs(60),
                Duration::from_secs(10),
                (),
                TestAggregator::init(()),
            )
            .collect();
        // we can also look only at the successful items
        let results_without_late: Vec<_> = items
            .into_iter()
            .window_aggregate(
                Duration::from_secs(60),
                Duration::from_secs(10),
                (),
                TestAggregator::init(()),
            )
            .filter_map(|x| x.left())
            .collect();
        assert_eq!(results_with_late, expected_results);
        assert_eq!(results_without_late, expected_on_time);
    }

    #[tokio::test]
    async fn test_window_aggregator_stream() {
        let (items, expected_results) = get_test_input();
        let expected_on_time: Vec<_> = expected_results
            .iter()
            .cloned()
            .flat_map(|i| i.left())
            .collect();
        let results_with_late: Vec<_> = stream::iter(items.clone())
            .window_aggregate(
                Duration::from_secs(60),
                Duration::from_secs(10),
                (),
                TestAggregator::init(()),
            )
            .collect()
            .await;
        // we can also look only at the successful items
        let results_without_late: Vec<_> = stream::iter(items)
            .window_aggregate(
                Duration::from_secs(60),
                Duration::from_secs(10),
                (),
                TestAggregator::init(()),
            )
            .flat_map(move |x| match x {
                either::Left(l) => stream::iter(vec![l]),
                either::Right(_) => stream::iter(vec![]),
            })
            .collect()
            .await;
        assert_eq!(results_with_late, expected_results);
        assert_eq!(results_without_late, expected_on_time);
    }

    #[test]
    fn test_buffer_order() {
        let base_time = chrono::DateTime::from_timestamp_millis(1738671601000).unwrap();
        let start = get_window_start(base_time);
        let items = vec![
            TestItem {
                key: "key1".to_string(),
                ts: base_time,
                value: 1,
            },
            TestItem {
                key: "key1".to_string(),
                ts: base_time.add(chrono::Duration::seconds(30)),
                value: 2,
            },
            TestItem {
                key: "key1".to_string(),
                ts: base_time.add(chrono::Duration::seconds(30)),
                value: 3,
            },
            TestItem {
                key: "key1".to_string(),
                ts: base_time.add(chrono::Duration::minutes(1)),
                value: 4,
            },
            TestItem {
                key: "key1".to_string(),
                ts: base_time.add(chrono::Duration::minutes(3)),
                value: 5,
            },
        ];
        let expected_results = vec![
            ((start, start.add(chrono::Duration::minutes(1))), 6),
            (
                (
                    start.add(chrono::Duration::minutes(1)),
                    start.add(chrono::Duration::minutes(2)),
                ),
                4,
            ),
            (
                (
                    start.add(chrono::Duration::minutes(3)),
                    start.add(chrono::Duration::minutes(4)),
                ),
                5,
            ),
        ];
        let results_without_late: Vec<_> = items
            .into_iter()
            .window_aggregate(
                Duration::from_secs(60),
                Duration::from_secs(10),
                (),
                TestAggregator::init(()),
            )
            .filter_map(|x| x.left())
            .collect();
        assert_eq!(results_without_late, expected_results);
    }

    #[test]
    fn test_empty_windows() {
        let items = vec![
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                value: 1,
            },
            TestItem {
                key: "key1".to_string(),
                ts: Utc.with_ymd_and_hms(2025, 1, 1, 0, 2, 0).unwrap(),
                value: 2,
            },
        ];
        // Assert that the empty window between events is handled correctly
        let expected_results = vec![
            (
                (
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 0).unwrap(),
                ),
                1,
            ),
            (
                (
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 2, 0).unwrap(),
                    Utc.with_ymd_and_hms(2025, 1, 1, 0, 3, 0).unwrap(),
                ),
                2,
            ),
        ];
        let results_without_late: Vec<_> = items
            .into_iter()
            .window_aggregate(
                Duration::from_secs(60),
                Duration::from_secs(10),
                (),
                TestAggregator::init(()),
            )
            .filter_map(|x| x.left())
            .collect();
        assert_eq!(results_without_late, expected_results);
    }
}
