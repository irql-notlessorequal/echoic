// echoic, a recursive DNS resolver.
// Copyright (C) IRQL_NOT_LESS_OR_EQUAL
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use std::sync::Arc;

use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit};

use crate::stats::Stats;

pub struct EchoicMetricsRecorder {
    stats: Arc<Stats>,
}

impl EchoicMetricsRecorder {
    pub fn new(stats: Arc<Stats>) -> Self {
        Self { stats }
    }
}

struct StatCounter {
    stats: Arc<Stats>,
    hit: bool,
}

impl metrics::CounterFn for StatCounter {
    fn increment(&self, value: u64) {
        if self.hit {
            self.stats.record_cache_hit(value);
        } else {
            self.stats.record_cache_miss(value);
        }
    }

    fn absolute(&self, _value: u64) {}
}

struct NoopCounter;

impl metrics::CounterFn for NoopCounter {
    fn increment(&self, _value: u64) {}
    fn absolute(&self, _value: u64) {}
}

struct NoopGauge;

impl metrics::GaugeFn for NoopGauge {
    fn increment(&self, _value: f64) {}
    fn decrement(&self, _value: f64) {}
    fn set(&self, _value: f64) {}
}

struct NoopHistogram;

impl metrics::HistogramFn for NoopHistogram {
    fn record(&self, _value: f64) {}
}

impl Recorder for EchoicMetricsRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        if key.name() == "hickory_recursor_cache_hit_total" {
            Counter::from_arc(Arc::new(StatCounter {
                stats: self.stats.clone(),
                hit: true,
            }))
        } else if key.name() == "hickory_recursor_cache_miss_total" {
            Counter::from_arc(Arc::new(StatCounter {
                stats: self.stats.clone(),
                hit: false,
            }))
        } else {
            Counter::from_arc(Arc::new(NoopCounter))
        }
    }

    fn register_gauge(&self, _key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(NoopGauge))
    }

    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(NoopHistogram))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::stats::Stats;

    #[test]
    fn maps_hickory_cache_counters_to_stats() {
        let stats = Arc::new(Stats::default());
        let recorder = EchoicMetricsRecorder::new(stats.clone());

        metrics::with_local_recorder(&recorder, || {
            let hit = metrics::counter!("hickory_recursor_cache_hit_total");
            let miss = metrics::counter!("hickory_recursor_cache_miss_total");
            let unrelated = metrics::counter!("echoic_unrelated_metric");

            hit.increment(2);
            miss.increment(1);
            unrelated.increment(10);
        });

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_hits, 2);
        assert_eq!(snapshot.cache_misses, 1);
    }
}
