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
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::Protocol;

#[derive(Debug, Default)]
pub struct Stats {
    udp: AtomicU64,
    tcp: AtomicU64,
    dot: AtomicU64,
    doh: AtomicU64,
    acl_denied: AtomicU64,
    rate_limited: AtomicU64,
    overloaded: AtomicU64,
    servfail: AtomicU64,
    blocked: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    latency_count: AtomicU64,
    latency_nanos: AtomicU64,
    upstream_failures: AtomicU64,
    upstream_sent: AtomicU64,
    upstream_rejected: AtomicU64,
    upstream_pending: AtomicU64,
    upstream_waits: AtomicU64,
    upstream_wait_nanos: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub udp: u64,
    pub tcp: u64,
    pub dot: u64,
    pub doh: u64,
    pub acl_denied: u64,
    pub rate_limited: u64,
    pub overloaded: u64,
    pub servfail: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total: u64,
}

impl Stats {
    pub fn record(&self, protocol: Protocol) {
        match protocol {
            Protocol::Udp => self.udp.fetch_add(1, Ordering::Relaxed),
            Protocol::Tcp => self.tcp.fetch_add(1, Ordering::Relaxed),
            Protocol::Dot => self.dot.fetch_add(1, Ordering::Relaxed),
            Protocol::Doh => self.doh.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_acl_denied(&self) {
        self.acl_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_overloaded(&self) {
        self.overloaded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_servfail(&self) {
        self.servfail.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self, value: u64) {
        self.cache_hits.fetch_add(value, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self, value: u64) {
        self.cache_misses.fetch_add(value, Ordering::Relaxed);
    }

    pub fn record_latency(&self, elapsed: std::time::Duration) {
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_nanos.fetch_add(
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    pub fn record_upstream_failure(&self) {
        self.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_upstream_sent(&self) {
        self.upstream_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_upstream_rejected(&self) {
        self.upstream_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn upstream_pending(&self, added: bool) {
        if added {
            self.upstream_pending.fetch_add(1, Ordering::Relaxed);
        } else {
            self.upstream_pending.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_upstream_wait(&self, elapsed: std::time::Duration) {
        self.upstream_waits.fetch_add(1, Ordering::Relaxed);
        self.upstream_wait_nanos.fetch_add(
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    pub fn prometheus(&self, available_permits: usize) -> String {
        use std::fmt::Write;
        let snapshot = self.snapshot();
        let mut output = String::new();
        for (name, value) in [
            (
                "echoic_upstream_sent_total",
                self.upstream_sent.load(Ordering::Relaxed),
            ),
            (
                "echoic_upstream_pacing_rejected_total",
                self.upstream_rejected.load(Ordering::Relaxed),
            ),
            ("echoic_requests_total", snapshot.total),
            ("echoic_udp_requests_total", snapshot.udp),
            ("echoic_tcp_requests_total", snapshot.tcp),
            ("echoic_dot_requests_total", snapshot.dot),
            ("echoic_doh_requests_total", snapshot.doh),
            ("echoic_acl_denied_total", snapshot.acl_denied),
            ("echoic_rate_limited_total", snapshot.rate_limited),
            ("echoic_overloaded_total", snapshot.overloaded),
            ("echoic_servfail_total", snapshot.servfail),
            ("echoic_blocked_total", snapshot.blocked),
            ("echoic_cache_hits_total", snapshot.cache_hits),
            ("echoic_cache_misses_total", snapshot.cache_misses),
            (
                "echoic_upstream_failures_total",
                self.upstream_failures.load(Ordering::Relaxed),
            ),
        ] {
            writeln!(output, "# TYPE {name} counter\n{name} {value}").unwrap();
        }
        writeln!(
            output,
            "# TYPE echoic_upstream_pending gauge\nechoic_upstream_pending {}",
            self.upstream_pending.load(Ordering::Relaxed)
        )
        .unwrap();
        writeln!(output, "# TYPE echoic_upstream_wait_seconds summary\nechoic_upstream_wait_seconds_count {}\nechoic_upstream_wait_seconds_sum {}",
            self.upstream_waits.load(Ordering::Relaxed),
            self.upstream_wait_nanos.load(Ordering::Relaxed) as f64 / std::time::Duration::from_secs(1).as_nanos() as f64,
        ).unwrap();
        writeln!(output, "# TYPE echoic_query_duration_seconds summary\nechoic_query_duration_seconds_count {}\nechoic_query_duration_seconds_sum {}",
            self.latency_count.load(Ordering::Relaxed),
            self.latency_nanos.load(Ordering::Relaxed) as f64 / std::time::Duration::from_secs(1).as_nanos() as f64,
        ).unwrap();
        writeln!(output, "# TYPE echoic_query_permits_available gauge\nechoic_query_permits_available {available_permits}").unwrap();
        output
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let udp = self.udp.load(Ordering::Relaxed);
        let tcp = self.tcp.load(Ordering::Relaxed);
        let dot = self.dot.load(Ordering::Relaxed);
        let doh = self.doh.load(Ordering::Relaxed);

        StatsSnapshot {
            udp,
            tcp,
            dot,
            doh,
            acl_denied: self.acl_denied.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            overloaded: self.overloaded.load(Ordering::Relaxed),
            servfail: self.servfail.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            total: udp + tcp + dot + doh,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_per_protocol_and_total() {
        let stats = Stats::default();

        stats.record(Protocol::Udp);
        stats.record(Protocol::Tcp);
        stats.record(Protocol::Udp);
        stats.record(Protocol::Doh);

        stats.record_acl_denied();
        stats.record_rate_limited();
        stats.record_overloaded();
        stats.record_servfail();

        assert_eq!(
            stats.snapshot(),
            StatsSnapshot {
                udp: 2,
                tcp: 1,
                dot: 0,
                doh: 1,
                acl_denied: 1,
                rate_limited: 1,
                overloaded: 1,
                servfail: 1,
                blocked: 0,
                cache_hits: 0,
                cache_misses: 0,
                total: 4,
            }
        );
    }
}
