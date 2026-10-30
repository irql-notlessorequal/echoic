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
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;

use socket2::SockRef;

pub(crate) const MAX_DSCP: u8 = 63;
const DSCP_SHIFT: u32 = 2;

pub fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn dscp_traffic_class(dscp: u8) -> u32 {
    u32::from(dscp) << DSCP_SHIFT
}

pub(crate) fn apply_dscp(socket: &impl AsFd, address: SocketAddr, dscp: u8) -> io::Result<()> {
    let traffic_class = dscp_traffic_class(dscp);
    let socket = SockRef::from(socket);
    if address.is_ipv4() {
        socket.set_tos_v4(traffic_class)
    } else {
        socket.set_tclass_v6(traffic_class)
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

    #[test]
    fn maps_dscp_to_traffic_class() {
        assert_eq!(dscp_traffic_class(0), 0);
        assert_eq!(dscp_traffic_class(40), 160);
        assert_eq!(dscp_traffic_class(45), 180);
        assert_eq!(dscp_traffic_class(63), 252);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn applies_dscp_to_ipv4_udp_socket() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind socket");
        let address = socket.local_addr().expect("socket address");
        apply_dscp(&socket, address, 45).expect("set DSCP");
        assert_eq!(
            socket2::SockRef::from(&socket).tos_v4().expect("read TOS"),
            180
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn applies_dscp_to_ipv6_udp_socket_when_supported() {
        let result = tokio::net::UdpSocket::bind("[::1]:0").await;
        let socket = match result {
            Ok(s) => s,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::AddrNotAvailable
                    || error.raw_os_error() == Some(libc::EAFNOSUPPORT)
                {
                    return;
                }
                panic!("bind IPv6 UDP socket: {error}");
            }
        };
        let address = socket.local_addr().expect("socket address");
        match apply_dscp(&socket, address, 45) {
            Ok(()) => {
                assert_eq!(
                    socket2::SockRef::from(&socket)
                        .tclass_v6()
                        .expect("read traffic class"),
                    180
                );
            }
            Err(error)
                if error.raw_os_error() == Some(libc::EPERM)
                    || error.raw_os_error() == Some(libc::ENOPROTOOPT) => {}
            Err(error) => panic!("set DSCP: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn applies_dscp_to_ipv4_tcp_listener_and_accepted_stream_inherits() {
        use tokio::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let bound_address = listener.local_addr().expect("listener address");
        apply_dscp(&listener, bound_address, 45).expect("set listener DSCP");
        assert_eq!(
            socket2::SockRef::from(&listener)
                .tos_v4()
                .expect("read listener TOS"),
            180
        );
        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(bound_address).await.expect("connect");
            stream
        });
        let (stream, _) = listener.accept().await.expect("accept connection");
        let client_stream = client.await.expect("client completed");
        drop(client_stream);
        assert_eq!(
            socket2::SockRef::from(&stream)
                .tos_v4()
                .expect("read stream TOS"),
            180
        );
    }
}
