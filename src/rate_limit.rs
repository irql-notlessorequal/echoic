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
use std::net::{IpAddr, Ipv4Addr};

use crate::net::normalize_ip;
use std::num::NonZeroU32;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateKey {
    V4(Ipv4Addr),
    V6(u64),
}

impl From<IpAddr> for RateKey {
    fn from(address: IpAddr) -> Self {
        match normalize_ip(address) {
            IpAddr::V4(address) => Self::V4(address),
            IpAddr::V6(address) => {
                let octets = address.octets();
                Self::V6(u64::from_be_bytes([
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
                    octets[7],
                ]))
            }
        }
    }
}

pub type KeyedRateLimiter = RateLimiter<RateKey, DefaultKeyedStateStore<RateKey>, DefaultClock>;

pub fn keyed_limiter(qps: u32, burst: u32) -> KeyedRateLimiter {
    let qps = NonZeroU32::new(qps).expect("validated qps must be greater than zero");
    let burst = NonZeroU32::new(burst).expect("validated burst must be greater than zero");
    RateLimiter::keyed(Quota::per_second(qps).allow_burst(burst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ipv4_mapped_ipv6() {
        assert_eq!(
            RateKey::from("::ffff:192.0.2.1".parse::<IpAddr>().unwrap()),
            RateKey::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    #[test]
    fn groups_ipv6_by_prefix() {
        let first = RateKey::from("2001:db8::1".parse::<IpAddr>().unwrap());
        let second = RateKey::from("2001:db8::2".parse::<IpAddr>().unwrap());

        assert_eq!(first, second);
    }

    #[test]
    fn limiter_allows_burst_then_denies() {
        let limiter = keyed_limiter(1, 2);
        let key = RateKey::V4(Ipv4Addr::LOCALHOST);

        assert!(limiter.check_key(&key).is_ok());
        assert!(limiter.check_key(&key).is_ok());
        assert!(limiter.check_key(&key).is_err());
    }
}
