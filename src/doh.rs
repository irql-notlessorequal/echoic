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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

use axum::Router;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, HOST};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::alphabet;
use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};
use hickory_server::net::xfer::Protocol as HickoryProtocol;
use hickory_server::server::Request;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::{ListenerConfig, Protocol};
use crate::listeners::ListenerRuntime;
use crate::query::QueryService;
use crate::rate_limit::RateKey;
use crate::tls::TlsState;

#[derive(Clone)]
pub struct DohRuntimeState {
    pub hostname: String,
    pub max_concurrent_requests: usize,
    pub max_doh_body: usize,
    pub max_doh_uri: usize,
    pub tcp_notsent_lowat: u32,
    pub concurrency: Arc<Semaphore>,
    pub landing_html: Option<String>,
    pub landing_css: Option<String>,
}

#[derive(Clone)]
pub struct DohState {
    pub service: Arc<QueryService>,
    pub runtime: Arc<ArcSwap<DohRuntimeState>>,
    pub ready: Arc<AtomicBool>,
}

#[derive(Clone)]
struct BufferResponseHandler {
    bytes: Arc<tokio::sync::Mutex<Option<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl hickory_server::server::ResponseHandler for BufferResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: hickory_server::zone_handler::MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a hickory_server::proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_server::proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_server::proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_server::proto::rr::Record> + Send + 'a,
        >,
    ) -> Result<hickory_server::server::ResponseInfo, hickory_server::net::NetError> {
        let mut bytes = Vec::new();
        let mut encoder = hickory_server::proto::serialize::binary::BinEncoder::new(&mut bytes);
        encoder.set_max_size(u16::MAX);
        let info = response.destructive_emit(&mut encoder)?;
        *self.bytes.lock().await = Some(bytes);
        Ok(info)
    }
}

const URL_SAFE_OPTIONAL_PAD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const MAX_DOH_BODY_LIMIT: usize = 65535;

#[allow(clippy::too_many_arguments)]
pub async fn start_doh_listener(
    listener: &ListenerConfig,
    service: QueryService,
    tls_state: Arc<TlsState>,
    max_concurrent_requests: usize,
    max_doh_body: usize,
    max_doh_uri: usize,
    hostname: String,
    landing_html: Option<String>,
    landing_css: Option<String>,
    ready: Arc<AtomicBool>,
    _handshake_timeout: Duration,
    _query_timeout: Duration,
) -> anyhow::Result<ListenerRuntime> {
    let max_connections = listener
        .limits
        .effective(listener.protocol)
        .max_connections
        .unwrap_or(512) as usize;

    let query_state = service.state();
    let service = Arc::new(service);
    let doh_runtime = Arc::new(ArcSwap::from_pointee(DohRuntimeState {
        hostname: hostname.clone(),
        max_concurrent_requests,
        max_doh_body,
        max_doh_uri,
        tcp_notsent_lowat: listener.tcp_notsent_lowat(),
        concurrency: Arc::new(Semaphore::new(max_concurrent_requests)),
        landing_html: landing_html.clone(),
        landing_css: landing_css.clone(),
    }));

    let socket = tokio::net::TcpListener::bind(listener.address)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "listener {:?}: failed to bind TCP socket {}: {}",
                listener.name,
                listener.address,
                error
            )
        })?;
    let bound_address = socket.local_addr().map_err(|error| {
        anyhow::anyhow!(
            "listener {:?}: failed to inspect TCP socket {}: {}",
            listener.name,
            listener.address,
            error
        )
    })?;

    tracing::info!(
        listener = %listener.name,
        protocol = "doh",
        address = %bound_address,
        "listener started"
    );

    let state = DohState {
        service: service.clone(),
        runtime: doh_runtime.clone(),
        ready: ready.clone(),
    };

    let app = Router::new()
        .route("/dns-query", get(dns_query).post(dns_query))
        .route("/", get(landing))
        .route("/assets/landing.css", get(landing_stylesheet))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_DOH_BODY_LIMIT))
        .layer(axum::middleware::from_fn(security_headers));

    let token = CancellationToken::new();
    let task_token = token.clone();
    let tls_state_swap = Arc::new(ArcSwap::from_pointee(Some(tls_state.clone())));
    let tls_state_for_task = tls_state_swap.clone();
    let max_connections_state = Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(
        max_connections,
    ))));
    let max_connections_state_for_task = max_connections_state.clone();
    let service_for_task = service.clone();
    let doh_runtime_for_task = doh_runtime.clone();
    let listener_name = listener.name.clone();
    let app_for_task = app.clone();

    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let mut tcp_notsent_lowat_disabled = false;
        loop {
            tokio::select! {
                _ = task_token.cancelled() => break,
                accept = socket.accept() => {
                    let (tcp_stream, src_addr) = match accept {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::debug!(listener = %listener_name, error = %error, "error accepting DoH connection");
                            continue;
                        }
                    };

                    let semaphore = max_connections_state_for_task.load();
                    let permit = match semaphore.as_ref().clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::debug!(listener = %listener_name, src = %src_addr, "DoH connection cap reached");
                            drop(tcp_stream);
                            continue;
                        }
                    };

                    let tls_state = tls_state_for_task.load();
                    let tls_state = tls_state.as_ref().clone().expect("tls state");
                    let service = service_for_task.clone();
                    let handshake_timeout = service.query_timeout();
                    let token = task_token.clone();
                    let app = app_for_task.clone();
                    let doh_runtime = doh_runtime_for_task.load();
                    let max_streams = doh_runtime.max_concurrent_requests as u32;
                    let tcp_notsent_lowat = doh_runtime.tcp_notsent_lowat;
                    drop(doh_runtime);
                    if tcp_notsent_lowat != 0
                        && !tcp_notsent_lowat_disabled
                        && let Err(error) =
                            apply_tcp_notsent_lowat(&tcp_stream, tcp_notsent_lowat)
                    {
                        tcp_notsent_lowat_disabled = true;
                        tracing::warn!(
                            listener = %listener_name,
                            src = %src_addr,
                            value = tcp_notsent_lowat,
                            error = %error,
                            "failed to set DoH TCP_NOTSENT_LOWAT; disabling it for this listener until restart"
                        );
                    }
                    connections.spawn(async move {
                        let _permit = permit;
                        let tls_stream = match tokio::time::timeout(handshake_timeout, tls_state.acceptor().accept(tcp_stream)).await {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                tracing::debug!(src = %src_addr, error = %error, "DoH TLS handshake failed");
                                return;
                            }
                            Err(_) => {
                                tracing::debug!(src = %src_addr, "DoH TLS handshake timed out");
                                return;
                            }
                        };

                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        let peer = src_addr;
                        let base_service = app.clone().into_service::<hyper::body::Incoming>();
                        let tower_service = PeerTowerService {
                            inner: base_service,
                            peer,
                        };
                        let service = hyper_util::service::TowerToHyperService::new(tower_service);
                        let mut builder = AutoBuilder::new(TokioExecutor::new());
                        builder.http2().max_concurrent_streams(max_streams);
                        let conn = builder.serve_connection(io, service);
                        tokio::pin!(conn);
                        tokio::select! {
                            result = &mut conn => {
                                if let Err(error) = result {
                                    tracing::debug!(src = %src_addr, error = %error, "DoH connection error");
                                }
                            }
                            _ = token.cancelled() => {
                                conn.as_mut().graceful_shutdown();
                                let _ = (&mut conn).await;
                            }
                        }
                    });
                }
            }

            while connections.try_join_next().is_some() {}
        }

        while connections.join_next().await.is_some() {}

        Ok(())
    });

    Ok(ListenerRuntime {
        name: listener.name.clone(),
        protocol: Protocol::Doh,
        address: listener.address,
        bound_address,
        token,
        query_state,
        tls_state: tls_state_swap,
        dot_max_connections: None,
        doh_runtime: Some(doh_runtime),
        doh_max_connections: Some(max_connections_state),
        task,
    })
}

async fn dns_query(
    State(state): State<DohState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let runtime = state.runtime.load();
    let hostname = runtime.hostname.clone();
    let max_doh_body = runtime.max_doh_body;
    let max_doh_uri = runtime.max_doh_uri;
    let concurrency = runtime.concurrency.clone();
    if let Err(status) = validate_host(&headers, &uri, &hostname) {
        return status.into_response();
    }

    let source = normalize_ip(peer.ip());
    if !state.service.acl().is_allowed(source, Protocol::Doh) {
        state.service.stats().record_acl_denied();
        return StatusCode::FORBIDDEN.into_response();
    }
    if state
        .service
        .rate_limiter()
        .check_key(&RateKey::from(source))
        .is_err()
    {
        state.service.stats().record_rate_limited();
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
        return response;
    }
    let inflight_permit = match state.service.inflight().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            state.service.stats().record_overloaded();
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let doh_permit = match concurrency.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            state.service.stats().record_overloaded();
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let dns_bytes = match method {
        Method::GET => {
            let query = uri.query().unwrap_or("");
            let value = match query_param(query, "dns") {
                Some(value) => value,
                None => return StatusCode::BAD_REQUEST.into_response(),
            };
            match decode_dns(&value, max_doh_uri) {
                Ok(bytes) => bytes,
                Err(status) => return status.into_response(),
            }
        }
        Method::POST => {
            if !valid_content_type(&headers) {
                return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
            }
            if body.is_empty() {
                return StatusCode::BAD_REQUEST.into_response();
            }
            if body.len() > max_doh_body {
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }
            body.to_vec()
        }
        _ => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };

    let request = match Request::from_bytes(dns_bytes, peer, HickoryProtocol::Tcp) {
        Ok(request) => request,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let buffer = Arc::new(tokio::sync::Mutex::new(None));
    let response_handle = BufferResponseHandler {
        bytes: buffer.clone(),
    };

    let request_result = tokio::time::timeout(
        state.service.query_timeout(),
        state
            .service
            .handle_admitted_request::<_, hickory_net::runtime::TokioTime>(
                &request,
                response_handle,
                Instant::now(),
            ),
    )
    .await;

    let bytes = match request_result {
        Ok(_) => buffer.lock().await.take().unwrap_or_default(),
        Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    if bytes.is_empty() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_TYPE, "application/dns-message")
        .header("x-content-type-options", "nosniff")
        .body(axum::body::Body::from(bytes))
        .unwrap();

    let _ = (inflight_permit, doh_permit);
    add_security_headers(&mut response);
    response
}

async fn landing(State(state): State<DohState>, uri: Uri, headers: HeaderMap) -> Response {
    let runtime = state.runtime.load();
    if let Err(status) = validate_host(&headers, &uri, &runtime.hostname) {
        return status.into_response();
    }

    let snapshot = state.service.stats().snapshot();
    let hostname = runtime.hostname.clone();
    let html = if let Some(template) = &runtime.landing_html {
        render_landing_template(template, &hostname, &snapshot)
    } else {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Echoic</title>
  <link rel="stylesheet" href="/assets/landing.css">
</head>
<body>
  <h1>Echoic</h1>
  <p>Recursive DNS resolver with DNSSEC.</p>
  <h2>DoH</h2>
  <p>Endpoint: <code>https://{hostname}/dns-query</code></p>
  <h2>DoT</h2>
  <p>Use TLS on port 853 with ALPN <code>dot</code>.</p>
  <h2>Statistics</h2>
  <h3>Requests by protocol</h3>
  <table>
    <tr><th>Protocol</th><th>Requests</th></tr>
    <tr><td>UDP</td><td>{udp}</td></tr>
    <tr><td>TCP</td><td>{tcp}</td></tr>
    <tr><td>DoT</td><td>{dot}</td></tr>
    <tr><td>DoH</td><td>{doh}</td></tr>
    <tr><td>Total</td><td>{total}</td></tr>
  </table>
  <h3>Miscellaneous</h3>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Blocked requests</td><td>{blocked}</td></tr>
    <tr><td>Cache hit rate</td><td>{cache_hit_rate}</td></tr>
  </table>
</body>
</html>"#,
            hostname = hostname,
            udp = snapshot.udp,
            tcp = snapshot.tcp,
            dot = snapshot.dot,
            doh = snapshot.doh,
            total = snapshot.total,
            blocked = snapshot.blocked,
            cache_hit_rate = cache_hit_rate(&snapshot),
        )
    };
    let mut response = Html(html).into_response();
    add_security_headers(&mut response);
    response
}

async fn landing_stylesheet(
    State(state): State<DohState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let runtime = state.runtime.load();
    if let Err(status) = validate_host(&headers, &uri, &runtime.hostname) {
        return status.into_response();
    }
    let body = runtime
        .landing_css
        .clone()
        .unwrap_or_else(|| include_str!("../assets/landing.css").to_owned());
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap();
    add_security_headers(&mut response);
    response
}

fn cache_hit_rate(snapshot: &crate::stats::StatsSnapshot) -> String {
    let cache_total = snapshot.cache_hits + snapshot.cache_misses;
    if cache_total == 0 {
        "0.0%".to_owned()
    } else {
        format!(
            "{:.1}%",
            snapshot.cache_hits as f64 / cache_total as f64 * 100.0
        )
    }
}

fn render_landing_template(
    template: &str,
    hostname: &str,
    snapshot: &crate::stats::StatsSnapshot,
) -> String {
    let cache_hit_rate = cache_hit_rate(snapshot);
    let values = [
        ("hostname", hostname.to_owned()),
        ("udp", snapshot.udp.to_string()),
        ("tcp", snapshot.tcp.to_string()),
        ("dot", snapshot.dot.to_string()),
        ("doh", snapshot.doh.to_string()),
        ("total", snapshot.total.to_string()),
        ("acl_denied", snapshot.acl_denied.to_string()),
        ("rate_limited", snapshot.rate_limited.to_string()),
        ("overloaded", snapshot.overloaded.to_string()),
        ("servfail", snapshot.servfail.to_string()),
        ("blocked", snapshot.blocked.to_string()),
        ("cache_hits", snapshot.cache_hits.to_string()),
        ("cache_misses", snapshot.cache_misses.to_string()),
        ("cache_hit_rate", cache_hit_rate),
    ];

    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        rendered.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find("}}") {
            let raw = &after[..end];
            let key = raw.trim();
            if let Some((_, value)) = values.iter().find(|(name, _)| *name == key) {
                rendered.push_str(value);
            } else {
                rendered.push_str("{{");
                rendered.push_str(raw);
                rendered.push_str("}}");
            }
            rest = &after[end + 2..];
        } else {
            rendered.push_str(&rest[start..]);
            rest = "";
        }
    }
    rendered.push_str(rest);
    rendered
}

async fn healthz(State(state): State<DohState>, uri: Uri, headers: HeaderMap) -> Response {
    let runtime = state.runtime.load();
    if let Err(status) = validate_host(&headers, &uri, &runtime.hostname) {
        return status.into_response();
    }
    let mut response = (StatusCode::OK, "ok\n").into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    add_security_headers(&mut response);
    response
}

async fn readyz(State(state): State<DohState>, uri: Uri, headers: HeaderMap) -> Response {
    let runtime = state.runtime.load();
    if let Err(status) = validate_host(&headers, &uri, &runtime.hostname) {
        return status.into_response();
    }
    let ready = state.ready.load(Ordering::Relaxed);
    let (status, body) = if ready {
        (StatusCode::OK, "ok\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    };
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    add_security_headers(&mut response);
    response
}

async fn security_headers(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    add_security_headers(&mut response);
    response
}

fn add_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers
        .entry("strict-transport-security")
        .or_insert(HeaderValue::from_static("max-age=31536000"));
    headers
        .entry("content-security-policy")
        .or_insert(HeaderValue::from_static(
            "default-src 'none'; style-src 'self'",
        ));
    headers
        .entry("referrer-policy")
        .or_insert(HeaderValue::from_static("no-referrer"));
    headers
        .entry("x-frame-options")
        .or_insert(HeaderValue::from_static("DENY"));
    headers
        .entry("x-content-type-options")
        .or_insert(HeaderValue::from_static("nosniff"));
}

fn validate_host(headers: &HeaderMap, uri: &Uri, expected: &str) -> Result<(), StatusCode> {
    let authority = uri.authority().map(|value| value.as_str().to_string());
    let host_header = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    if authority.is_some() && host_header.is_some() && authority != host_header {
        return Err(StatusCode::BAD_REQUEST);
    }

    let raw = authority.or(host_header).ok_or(StatusCode::BAD_REQUEST)?;
    let (name, _) = split_host_port(&raw);
    let name = name.strip_suffix('.').unwrap_or(name);
    if !name.eq_ignore_ascii_case(expected) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

fn split_host_port(value: &str) -> (&str, Option<&str>) {
    if let Some(rest) = value.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = &value[..=end];
        let remainder = &value[end + 1..];
        if let Some(port) = remainder.strip_prefix(':')
            && !port.is_empty()
            && port.chars().all(|ch| ch.is_ascii_digit())
        {
            return (host, Some(port));
        }
        return (host, None);
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.chars().all(|ch| ch.is_ascii_digit())
    {
        return (host, Some(port));
    }
    (value, None)
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let name = parts.next()?;
        if name == key {
            return parts.next().map(str::to_string);
        }
    }
    None
}

fn decode_dns(value: &str, max: usize) -> Result<Vec<u8>, StatusCode> {
    if value.chars().any(char::is_whitespace) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = URL_SAFE_OPTIONAL_PAD
        .decode(value)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if bytes.len() > max {
        return Err(StatusCode::URI_TOO_LONG);
    }
    Ok(bytes)
}

fn valid_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().eq_ignore_ascii_case("application/dns-message"))
        .unwrap_or(false)
}

fn normalize_ip(address: std::net::IpAddr) -> std::net::IpAddr {
    match address {
        std::net::IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(address)),
        address => address,
    }
}

#[derive(Clone)]
struct PeerTowerService<S> {
    inner: S,
    peer: SocketAddr,
}

impl<S> tower::Service<hyper::Request<hyper::body::Incoming>> for PeerTowerService<S>
where
    S: tower::Service<hyper::Request<hyper::body::Incoming>> + Clone,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(self.peer));
        self.inner.call(request)
    }
}

fn apply_tcp_notsent_lowat(stream: &tokio::net::TcpStream, value: u32) -> std::io::Result<()> {
    socket2::SockRef::from(stream).set_tcp_notsent_lowat(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Protocol;
    use crate::stats::Stats;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn applies_tcp_notsent_lowat_to_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let client = tokio::spawn(async move {
            tokio::net::TcpStream::connect(address)
                .await
                .expect("connect")
        });
        let (stream, _) = listener.accept().await.expect("accept");
        let _client = client.await.expect("client task");

        match apply_tcp_notsent_lowat(&stream, 32_768) {
            Ok(()) => {
                let socket = socket2::SockRef::from(&stream);
                assert_eq!(socket.tcp_notsent_lowat().expect("read option"), 32_768);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => {}
            Err(error) => panic!("set option: {error}"),
        }
    }

    #[test]
    fn landing_template_replaces_placeholders() {
        let stats = Stats::default();
        stats.record(Protocol::Udp);
        let snapshot = stats.snapshot();
        let rendered = render_landing_template(
            "{{hostname}} {{  udp  }} {{cache_hit_rate}} {{blocked}} {{unknown}}",
            "example.com",
            &snapshot,
        );
        assert_eq!(rendered, "example.com 1 0.0% 0 {{unknown}}");
    }
}
