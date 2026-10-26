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
