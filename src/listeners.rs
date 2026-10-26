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
pub use crate::doh::start_doh_listener;
pub use crate::dot::start_dot_listener;

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use std::time::Duration;

use anyhow::{Context, bail};
use hickory_server::net::NetError;
use hickory_server::server::Server;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{ListenerConfig, Protocol};
use crate::query::{ListenerQueryState, QueryService};

const TCP_RESPONSE_BUFFER_SIZE: usize = 32;

pub struct ListenerRuntime {
    pub name: String,
    pub protocol: Protocol,
    pub address: SocketAddr,
    pub bound_address: SocketAddr,
    pub token: CancellationToken,
    pub query_state: Arc<ArcSwap<ListenerQueryState>>,
    pub tls_state: Arc<ArcSwap<Option<Arc<crate::tls::TlsState>>>>,
    pub dot_max_connections: Option<Arc<ArcSwap<Arc<tokio::sync::Semaphore>>>>,
    pub doh_runtime: Option<Arc<ArcSwap<crate::doh::DohRuntimeState>>>,
    pub doh_max_connections: Option<Arc<ArcSwap<Arc<tokio::sync::Semaphore>>>>,
    pub task: JoinHandle<Result<(), NetError>>,
}

pub async fn start_listener(
    listener: &ListenerConfig,
    service: QueryService,
    request_timeout: Duration,
) -> anyhow::Result<ListenerRuntime> {
    let query_state = service.state();
    let mut server = Server::new(service);
    let token = server.shutdown_token().clone();

    let bound_address = match listener.protocol {
        Protocol::Udp => {
            let socket = UdpSocket::bind(listener.address).await.with_context(|| {
                format!(
                    "listener {:?}: failed to bind UDP socket {}",
                    listener.name, listener.address
                )
            })?;
            let bound_address = socket.local_addr().with_context(|| {
                format!(
                    "listener {:?}: failed to inspect UDP socket {}",
                    listener.name, listener.address
                )
            })?;
            server.register_socket(socket);
            bound_address
        }
        Protocol::Tcp => {
            let socket = TcpListener::bind(listener.address).await.with_context(|| {
                format!(
                    "listener {:?}: failed to bind TCP socket {}",
                    listener.name, listener.address
                )
            })?;
            let bound_address = socket.local_addr().with_context(|| {
                format!(
                    "listener {:?}: failed to inspect TCP socket {}",
                    listener.name, listener.address
                )
            })?;
            server.register_listener(socket, request_timeout, TCP_RESPONSE_BUFFER_SIZE);
            bound_address
        }
        Protocol::Dot | Protocol::Doh => {
            bail!(
                "listener {:?}: {} listeners are not implemented yet",
                listener.name,
                listener.protocol.as_str()
            );
        }
    };

    tracing::info!(
        listener = %listener.name,
        protocol = listener.protocol.as_str(),
        address = %bound_address,
        "listener started"
    );

    let task = tokio::spawn(async move { server.block_until_done().await });

    Ok(ListenerRuntime {
        name: listener.name.clone(),
        protocol: listener.protocol,
        address: listener.address,
        bound_address,
        token,
        query_state,
        tls_state: Arc::new(ArcSwap::from_pointee(None)),
        dot_max_connections: None,
        doh_runtime: None,
        doh_max_connections: None,
        task,
    })
}
