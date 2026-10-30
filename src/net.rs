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
use std::net::IpAddr;

pub fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn normalizes_ipv4_mapped_ipv6() {
        let mapped = Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped();
        assert_eq!(
            normalize_ip(IpAddr::V6(mapped)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    #[test]
    fn preserves_native_ipv6() {
        let address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(normalize_ip(address), address);
    }
}
