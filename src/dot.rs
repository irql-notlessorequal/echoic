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
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::stream::StreamExt;
use hickory_net::runtime::TokioTime;
use hickory_net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_net::tls::tls_from_stream;
use hickory_server::net::xfer::Protocol as HickoryProtocol;
use hickory_server::proto::op::Header;
use hickory_server::proto::serialize::binary::{BinDecodable, BinDecoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandle};
use hickory_server::zone_handler::Queries;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::{ListenerConfig, Protocol};
use crate::listeners::ListenerRuntime;
use crate::query::QueryService;
use crate::tls::TlsState;

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

pub async fn start_dot_listener(
    listener: &ListenerConfig,
    service: QueryService,
    tls_state: Arc<TlsState>,
) -> Result<ListenerRuntime> {
    let max_connections = listener
        .limits
        .effective(listener.protocol)
        .max_connections
        .unwrap_or(512) as usize;

    let query_state = service.state();
    let max_connections_state = Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(
        max_connections,
    ))));
    let tls_state_swap = Arc::new(ArcSwap::from_pointee(Some(tls_state.clone())));
    let service = Arc::new(service);

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

    tracing::info!(
        listener = %listener.name,
        protocol = "dot",
        address = %bound_address,
        "listener started"
    );

    let token = CancellationToken::new();
    let task_token = token.clone();
    let service_for_task = service.clone();
    let tls_state_for_task = tls_state_swap.clone();
    let max_connections_for_task = max_connections_state.clone();
    let listener_name = listener.name.clone();

    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = task_token.cancelled() => break,
                accept = socket.accept() => {
                    let (tcp_stream, src_addr) = match accept {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::debug!(listener = %listener_name, error = %error, "error accepting DoT connection");
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                            continue;
                        }
                    };

                    let semaphore = max_connections_for_task.load();
                    let permit = match semaphore.as_ref().clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::debug!(listener = %listener_name, src = %src_addr, "DoT connection cap reached");
                            drop(tcp_stream);
                            continue;
                        }
                    };

                    let service = service_for_task.clone();
                    let tls_state = tls_state_for_task.load();
                    let tls_state = tls_state.as_ref().clone().expect("tls state");
                    let token = task_token.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        handle_connection(tcp_stream, src_addr, service, tls_state, token).await;
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::debug!(listener = %listener_name, error = %error, "DoT connection task failed");
                    }
                }
            }
        }

        while connections.join_next().await.is_some() {}

        Ok(())
    });

    Ok(ListenerRuntime {
        name: listener.name.clone(),
        protocol: Protocol::Dot,
        address: listener.address,
        bound_address,
        token,
        query_state,
        tls_state: tls_state_swap,
        dot_max_connections: Some(max_connections_state),
        doh_max_connections: None,
        doh_runtime: None,
        task,
    })
}

fn empty_queries() -> Queries {
    Queries::read(&mut BinDecoder::new(&[]), 0).expect("empty query set decodes")
}

async fn handle_connection(
    tcp_stream: TcpStream,
    src_addr: SocketAddr,
    service: Arc<QueryService>,
    tls_state: Arc<TlsState>,
    token: CancellationToken,
) {
    let tls_stream = match tokio::time::timeout(
        service.query_timeout(),
        tls_state.acceptor().accept(tcp_stream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(src = %src_addr, error = %error, "DoT TLS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(src = %src_addr, "DoT TLS handshake timed out");
            return;
        }
    };

    let require_dot_alpn = service.state().load().require_dot_alpn;
    match tls_stream.get_ref().1.alpn_protocol() {
        Some(b"dot") => {}
        None if !require_dot_alpn => {}
        other => {
            tracing::debug!(
                src = %src_addr,
                alpn = ?other,
                require_dot_alpn,
                "DoT connection rejected due to ALPN"
            );
            return;
        }
    }

    let (mut buf_stream, stream_handle) = tls_from_stream(AsyncIoTokioAsStd(tls_stream), src_addr);

    loop {
        if token.is_cancelled() {
            break;
        }

        let next = tokio::time::timeout(service.idle_timeout(), buf_stream.next()).await;
        let message = match next {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(error))) => {
                tracing::debug!(src = %src_addr, error = %error, "DoT stream error");
                break;
            }
            Ok(None) => break,
            Err(_) => {
                tracing::debug!(src = %src_addr, "DoT idle timeout");
                break;
            }
        };

        let (message_bytes, message_src) = message.into_parts();
        let started = std::time::Instant::now();

        match Request::from_bytes(
            message_bytes.to_vec(),
            message_src,
            hickory_server::net::xfer::Protocol::Tls,
        ) {
            Ok(request) => {
                let response_handle =
                    ResponseHandle::new(message_src, stream_handle.clone(), HickoryProtocol::Tls);
                service
                    .handle_request::<_, TokioTime>(&request, response_handle)
                    .await;
            }
            Err(_) => {
                let mut decoder = BinDecoder::new(&message_bytes);
                if let Ok(header) = Header::read(&mut decoder) {
                    let queries = Queries::read(&mut decoder, header.counts.queries as usize)
                        .unwrap_or_else(|_| empty_queries());
                    let response_handle = ResponseHandle::new(
                        message_src,
                        stream_handle.clone(),
                        HickoryProtocol::Tls,
                    );
                    service
                        .handle_malformed(message_src, header, queries, response_handle, started)
                        .await;
                } else {
                    tracing::debug!(src = %src_addr, "DoT message too short to parse");
                }
            }
        }
    }
}
