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
use hickory_net::runtime::TokioTime;
use hickory_server::net::NetError;
use hickory_server::net::xfer::Protocol as HickoryProtocol;
use hickory_server::proto::op::Header;
use hickory_server::proto::rr::Record;
use hickory_server::proto::serialize::binary::{BinDecodable, BinDecoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use hickory_server::zone_handler::Queries;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::{ListenerConfig, Protocol};
use crate::listeners::ListenerRuntime;
use crate::net::apply_dscp;
use crate::query::QueryService;
use crate::tls::TlsState;

const MAX_CONNECTION_QUERIES: usize = 32;
const RESPONSE_QUEUE_CAPACITY: usize = MAX_CONNECTION_QUERIES;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

pub async fn start_dot_listener(
    listener: &ListenerConfig,
    service: QueryService,
    tls_state: Arc<TlsState>,
) -> Result<ListenerRuntime> {
    anyhow::ensure!(
        listener.protocol == Protocol::Dot,
        "DoT listener requires dot protocol"
    );
    start_stream_listener(listener, service, Some(tls_state)).await
}

pub(crate) async fn start_stream_listener(
    listener: &ListenerConfig,
    service: QueryService,
    tls_state: Option<Arc<TlsState>>,
) -> Result<ListenerRuntime> {
    let max_connections = listener
        .limits
        .effective(listener.protocol)
        .max_connections
        .expect("stream connection limit") as usize;

    let query_state = service.state();
    let max_connections_state = Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(
        max_connections,
    ))));
    let tls_state_swap = Arc::new(ArcSwap::from_pointee(tls_state.clone()));
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
    crate::listeners::apply_listener_dscp(listener, &socket, bound_address);

    tracing::info!(
        listener = %listener.name,
        protocol = listener.protocol.as_str(),
        address = %bound_address,
        "listener started"
    );

    let token = CancellationToken::new();
    let task_token = token.clone();
    let service_for_task = service.clone();
    let tls_state_for_task = tls_state_swap.clone();
    let max_connections_for_task = max_connections_state.clone();
    let listener_name = listener.name.clone();
    let listener_dscp = listener.dscp;
    let protocol = listener.protocol;

    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let mut connection_dscp_enabled = true;
        loop {
            tokio::select! {
                _ = task_token.cancelled() => break,
                accept = socket.accept() => {
                    let (tcp_stream, src_addr) = match accept {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::debug!(listener = %listener_name, error = %error, "error accepting DNS stream connection");
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                            continue;
                        }
                    };

                    let semaphore = max_connections_for_task.load();
                    let permit = match semaphore.as_ref().clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::debug!(listener = %listener_name, src = %src_addr, "DNS stream connection cap reached");
                            drop(tcp_stream);
                            continue;
                        }
                    };

                    if connection_dscp_enabled
                        && let Some(dscp) = listener_dscp
                        && let Err(error) = apply_dscp(&tcp_stream, src_addr, dscp)
                    {
                        connection_dscp_enabled = false;
                        tracing::warn!(
                            listener = %listener_name,
                            src = %src_addr,
                            dscp,
                            error = %error,
                            "failed to set DNS stream connection DSCP; disabling it for this listener"
                        );
                    }

                    let service = service_for_task.clone();
                    let tls_state = tls_state_for_task.load();
                    let tls_state = tls_state.as_ref().clone();
                    let token = task_token.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        if let Some(tls_state) = tls_state {
                            handle_connection(tcp_stream, src_addr, service, tls_state, token).await;
                        } else {
                            handle_dns_stream(tcp_stream, src_addr, service, token, HickoryProtocol::Tcp).await;
                        }
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::debug!(listener = %listener_name, error = %error, "DNS stream connection task failed");
                    }
                }
            }
        }

        while connections.join_next().await.is_some() {}

        Ok(())
    });

    Ok(ListenerRuntime {
        name: listener.name.clone(),
        protocol,
        address: listener.address,
        bound_address,
        token,
        query_state,
        tls_state: tls_state_swap,
        dscp: listener.dscp,
        configured_dscp: listener.dscp,
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
    let handshake = tokio::time::timeout(
        service.query_timeout(),
        tls_state.acceptor().accept(tcp_stream),
    );
    let tls_stream = match tokio::select! {
        _ = token.cancelled() => return,
        result = handshake => result,
    } {
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

    handle_dns_stream(tls_stream, src_addr, service, token, HickoryProtocol::Tls).await;
}

#[derive(Clone)]
struct StreamResponseHandler {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl ResponseHandler for StreamResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut bytes = Vec::new();
        let mut encoder = hickory_server::proto::serialize::binary::BinEncoder::new(&mut bytes);
        encoder.set_max_size(u16::MAX);
        let info = response.destructive_emit(&mut encoder)?;
        self.sender.send(bytes).await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "DNS connection closed")
        })?;
        Ok(info)
    }
}

async fn handle_dns_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    src_addr: SocketAddr,
    service: Arc<QueryService>,
    token: CancellationToken,
    protocol: HickoryProtocol,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (sender, mut responses) = tokio::sync::mpsc::channel::<Vec<u8>>(RESPONSE_QUEUE_CAPACITY);
    let response_handle = StreamResponseHandler { sender };
    let writer_service = service.clone();
    let mut writers = JoinSet::new();
    writers.spawn(async move {
        while let Some(bytes) = responses.recv().await {
            let length = u16::try_from(bytes.len()).expect("encoded DNS message length");
            let result = tokio::time::timeout(writer_service.query_timeout(), async {
                writer.write_u16(length).await?;
                writer.write_all(&bytes).await?;
                writer.flush().await
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                return;
            }
        }
        let _ = writer.shutdown().await;
    });
    let mut queries = JoinSet::new();
    'connection: loop {
        let read = async {
            let length = reader.read_u16().await?;
            let mut bytes = vec![0; usize::from(length)];
            reader.read_exact(&mut bytes).await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let read = tokio::time::timeout(service.idle_timeout(), read);
        tokio::pin!(read);
        let bytes = loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break 'connection,
                _ = writers.join_next(), if !writers.is_empty() => break 'connection,
                result = queries.join_next(), if !queries.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::warn!(%src_addr, %error, "DNS query task failed");
                    }
                }
                result = &mut read, if queries.len() < MAX_CONNECTION_QUERIES => {
                    match result {
                        Ok(Ok(bytes)) => break bytes,
                        _ => break 'connection,
                    }
                }
            }
        };
        let service = service.clone();
        let response_handle = response_handle.clone();
        queries.spawn(async move {
            let started = std::time::Instant::now();
            match Request::from_bytes(bytes.clone(), src_addr, protocol) {
                Ok(request) => {
                    service
                        .handle_request::<_, TokioTime>(&request, response_handle)
                        .await;
                }
                Err(_) => {
                    let mut decoder = BinDecoder::new(&bytes);
                    if let Ok(header) = Header::read(&mut decoder) {
                        let queries = Queries::read(&mut decoder, header.counts.queries as usize)
                            .unwrap_or_else(|_| empty_queries());
                        service
                            .handle_malformed(src_addr, header, queries, response_handle, started)
                            .await;
                    }
                }
            }
        });
    }
    while queries.join_next().await.is_some() {}
    drop(response_handle);
    while writers.join_next().await.is_some() {}
}
