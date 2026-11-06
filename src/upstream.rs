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
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use hickory_server::net::NetError;
use hickory_server::net::runtime::{DnsTcpStream, DnsUdpSocket};
use hickory_server::net::xfer::DnsHandle;
use hickory_server::proto::op::{DnsRequest, DnsResponse, Message};
use hickory_server::proto::rr::{DNSClass, LowerName, RecordType};
use hickory_server::resolver::config::ConnectionConfig;
use hickory_server::resolver::{ConnectionProvider, PoolContext};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::{UpstreamLimits, UpstreamQuota};
use crate::net::normalize_ip;
use crate::stats::Stats;

pub(crate) const PACING_EXHAUSTED: &str = "upstream pacing capacity exhausted";
const BUCKET_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const DNS_LENGTH_BYTES: usize = size_of::<u16>();
type PermitFuture = Pin<Box<dyn Future<Output = Option<SendPermit>> + Send + Sync>>;

tokio::task_local! {
    pub(crate) static RESOLUTION: Arc<Resolution>;
}

pub(crate) struct Resolution {
    pub rejected: CancellationToken,
    pub finished: CancellationToken,
}

impl Resolution {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            rejected: CancellationToken::new(),
            finished: CancellationToken::new(),
        })
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct RequestKey {
    ip: IpAddr,
    name: LowerName,
    kind: RecordType,
    class: DNSClass,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn new(quota: &UpstreamQuota, now: Instant) -> Self {
        Self {
            tokens: f64::from(quota.burst),
            updated: now,
        }
    }

    fn refill(&mut self, quota: &UpstreamQuota, now: Instant) {
        self.tokens = (self.tokens
            + now.duration_since(self.updated).as_secs_f64() * f64::from(quota.qps))
        .min(f64::from(quota.burst));
        self.updated = now;
    }

    fn wait(&self, quota: &UpstreamQuota) -> Duration {
        const MIN_WAIT: Duration = Duration::from_nanos(1);
        if self.tokens >= 1.0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64((1.0 - self.tokens) / f64::from(quota.qps)).max(MIN_WAIT)
    }
}

struct State {
    limits: Option<UpstreamLimits>,
    global: Option<Bucket>,
    servers: HashMap<IpAddr, Bucket>,
    pending: usize,
    epoch: u64,
    cleanup: Instant,
}

pub(crate) struct UpstreamPacer {
    state: Mutex<State>,
    changed: Notify,
    requests: Mutex<HashMap<RequestKey, Vec<Weak<Resolution>>>>,
    pub stats: Arc<Stats>,
}

impl UpstreamPacer {
    pub fn new(limits: Option<UpstreamLimits>, stats: Arc<Stats>) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            state: Mutex::new(State {
                global: limits
                    .as_ref()
                    .map(|limits| Bucket::new(&limits.global, now)),
                limits,
                servers: HashMap::new(),
                pending: 0,
                epoch: 0,
                cleanup: now,
            }),
            changed: Notify::new(),
            requests: Mutex::new(HashMap::new()),
            stats,
        })
    }

    pub fn reconfigure(&self, limits: Option<UpstreamLimits>) {
        let mut state = self.state.lock().unwrap();
        if state.limits == limits {
            return;
        }
        let now = Instant::now();
        if state.limits.is_some() != limits.is_some() {
            state.epoch += 1;
        }
        if let Some(old) = state.limits.clone() {
            if let Some(global) = &mut state.global {
                global.refill(&old.global, now);
            }
            for bucket in state.servers.values_mut() {
                bucket.refill(&old.per_server, now);
            }
        }
        if let Some(new) = &limits {
            if let Some(global) = &mut state.global {
                global.tokens = global.tokens.min(f64::from(new.global.burst));
            } else {
                state.global = Some(Bucket::new(&new.global, now));
            }
            for bucket in state.servers.values_mut() {
                bucket.tokens = bucket.tokens.min(f64::from(new.per_server.burst));
            }
        } else {
            state.global = None;
            state.servers.clear();
        }
        state.limits = limits;
        drop(state);
        self.changed.notify_waiters();
    }

    fn register(self: &Arc<Self>, ip: IpAddr, message: &Message) -> Registration {
        let resolution = RESOLUTION.try_with(Arc::clone).ok();
        let keys = message
            .queries
            .iter()
            .map(|query| RequestKey {
                ip: normalize_ip(ip),
                name: LowerName::new(query.name()),
                kind: query.query_type(),
                class: query.query_class(),
            })
            .collect::<Vec<_>>();
        if let Some(resolution) = &resolution {
            let mut requests = self.requests.lock().unwrap();
            for key in &keys {
                requests
                    .entry(key.clone())
                    .or_default()
                    .push(Arc::downgrade(resolution));
            }
        }
        Registration {
            pacer: self.clone(),
            resolution,
            keys,
        }
    }

    fn contexts(&self, ip: IpAddr, bytes: &[u8]) -> Vec<Arc<Resolution>> {
        let Ok(message) = Message::from_vec(bytes) else {
            return Vec::new();
        };
        let requests = self.requests.lock().unwrap();
        message
            .queries
            .iter()
            .flat_map(|query| {
                requests
                    .get(&RequestKey {
                        ip: normalize_ip(ip),
                        name: LowerName::new(query.name()),
                        kind: query.query_type(),
                        class: query.query_class(),
                    })
                    .into_iter()
                    .flatten()
                    .filter_map(Weak::upgrade)
            })
            .collect()
    }

    fn gate(self: &Arc<Self>, ip: IpAddr, bytes: &[u8]) -> PermitFuture {
        let contexts = self.contexts(ip, bytes);
        Box::pin(self.clone().acquire_for(ip, contexts))
    }

    async fn acquire_for(
        self: Arc<Self>,
        ip: IpAddr,
        contexts: Vec<Arc<Resolution>>,
    ) -> Option<SendPermit> {
        let cancelled = async {
            if contexts.is_empty() {
                std::future::pending::<()>().await;
            }
            for context in &contexts {
                tokio::select! { _ = context.finished.cancelled() => {}, _ = context.rejected.cancelled() => {} }
            }
        };
        tokio::select! {
            biased;
            _ = cancelled => None,
            permit = self.acquire(ip) => {
                if permit.is_none() {
                    for context in contexts { context.rejected.cancel(); }
                }
                permit
            }
        }
    }

    async fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<SendPermit> {
        let ip = normalize_ip(ip);
        let started = Instant::now();
        let mut pending = None;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let (wait, deadline) = {
                let mut state = self.state.lock().unwrap();
                let Some(limits) = state.limits.clone() else {
                    return Some(SendPermit {
                        pacer: self.clone(),
                        ip,
                        epoch: state.epoch,
                        charged: false,
                        sent: false,
                    });
                };
                let now = Instant::now();
                if now.duration_since(state.cleanup) >= BUCKET_CLEANUP_INTERVAL {
                    state.servers.retain(|_, bucket| {
                        bucket.refill(&limits.per_server, now);
                        bucket.tokens < f64::from(limits.per_server.burst)
                    });
                    state.cleanup = now;
                }
                let global = state.global.as_mut().expect("configured upstream bucket");
                global.refill(&limits.global, now);
                let global_wait = global.wait(&limits.global);
                let server = state
                    .servers
                    .entry(ip)
                    .or_insert_with(|| Bucket::new(&limits.per_server, now));
                server.refill(&limits.per_server, now);
                let wait = global_wait.max(server.wait(&limits.per_server));
                let deadline = started + limits.max_wait;
                if pending.is_some() && now >= deadline {
                    self.stats.record_upstream_rejected();
                    return None;
                }
                if state.global.as_ref().unwrap().tokens >= 1.0 && state.servers[&ip].tokens >= 1.0
                {
                    state.global.as_mut().unwrap().tokens -= 1.0;
                    state.servers.get_mut(&ip).unwrap().tokens -= 1.0;
                    return Some(SendPermit {
                        pacer: self.clone(),
                        ip,
                        epoch: state.epoch,
                        charged: true,
                        sent: false,
                    });
                }
                if pending.is_none() {
                    if limits.max_wait.is_zero() || state.pending >= limits.max_pending {
                        self.stats.record_upstream_rejected();
                        return None;
                    }
                    state.pending += 1;
                    self.stats.upstream_pending(true);
                    pending = Some(Pending {
                        pacer: self.clone(),
                        started,
                    });
                }
                (wait, deadline)
            };
            tokio::select! {
                _ = &mut changed => {}
                _ = tokio::time::sleep_until((Instant::now() + wait).min(deadline)) => {}
            }
        }
    }
}

struct Pending {
    pacer: Arc<UpstreamPacer>,
    started: Instant,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.pacer.state.lock().unwrap().pending -= 1;
        self.pacer.stats.upstream_pending(false);
        self.pacer
            .stats
            .record_upstream_wait(self.started.elapsed());
    }
}

struct SendPermit {
    pacer: Arc<UpstreamPacer>,
    ip: IpAddr,
    epoch: u64,
    charged: bool,
    sent: bool,
}

impl SendPermit {
    fn current(&self) -> bool {
        self.sent || self.epoch == self.pacer.state.lock().unwrap().epoch
    }

    fn sent(&mut self) {
        if !self.sent {
            self.pacer.stats.record_upstream_sent();
            self.sent = true;
        }
    }
}

impl Drop for SendPermit {
    fn drop(&mut self) {
        if self.charged && !self.sent {
            let mut state = self.pacer.state.lock().unwrap();
            if self.epoch == state.epoch
                && let Some(limits) = state.limits.clone()
            {
                if let Some(global) = &mut state.global {
                    global.tokens = (global.tokens + 1.0).min(f64::from(limits.global.burst));
                }
                if let Some(server) = state.servers.get_mut(&self.ip) {
                    server.tokens = (server.tokens + 1.0).min(f64::from(limits.per_server.burst));
                }
            }
            drop(state);
            self.pacer.changed.notify_waiters();
        }
    }
}

struct Registration {
    pacer: Arc<UpstreamPacer>,
    resolution: Option<Arc<Resolution>>,
    keys: Vec<RequestKey>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(resolution) = &self.resolution {
            let mut requests = self.pacer.requests.lock().unwrap();
            for key in &self.keys {
                if let Some(contexts) = requests.get_mut(key) {
                    if let Some(index) = contexts
                        .iter()
                        .position(|weak| weak.ptr_eq(&Arc::downgrade(resolution)))
                    {
                        contexts.swap_remove(index);
                    }
                    if contexts.is_empty() {
                        requests.remove(key);
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct PacedProvider<P> {
    pub inner: P,
    pub pacer: Arc<UpstreamPacer>,
    pub gate_requests: bool,
}

impl<P: ConnectionProvider> ConnectionProvider for PacedProvider<P> {
    type Conn = PacedHandle<P::Conn>;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send>>;
    type RuntimeProvider = P::RuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let future = self.inner.new_connection(ip, config, cx)?;
        let pacer = self.pacer.clone();
        let gate = self.gate_requests;
        Ok(Box::pin(async move {
            Ok(PacedHandle {
                inner: future.await?,
                pacer,
                ip,
                gate,
            })
        }))
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        self.inner.runtime_provider()
    }
}

#[derive(Clone)]
pub(crate) struct PacedHandle<H> {
    inner: H,
    pacer: Arc<UpstreamPacer>,
    ip: IpAddr,
    gate: bool,
}

impl<H: DnsHandle> DnsHandle for PacedHandle<H> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = H::Runtime;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let registration = self.pacer.register(self.ip, &request);
        let inner = self.inner.clone();
        let pacer = self.pacer.clone();
        let ip = self.ip;
        let gate = self.gate;
        let future = async move {
            let allowed = if gate {
                if let Some(mut permit) = pacer
                    .clone()
                    .acquire_for(ip, registration.resolution.iter().cloned().collect())
                    .await
                {
                    permit.sent();
                    true
                } else {
                    false
                }
            } else {
                true
            };
            let response = allowed.then(|| inner.send(request));
            (response, registration)
        };
        Box::pin(
            futures_util::stream::once(future).flat_map(|(mut response, registration)| {
                let mut ended = false;
                futures_util::stream::poll_fn(move |cx| {
                    if ended {
                        return Poll::Ready(None);
                    }
                    let cancelled = || {
                        registration.resolution.as_ref().is_some_and(|context| {
                            context.rejected.is_cancelled() || context.finished.is_cancelled()
                        })
                    };
                    if cancelled() || response.is_none() {
                        ended = true;
                        return Poll::Ready(Some(Err(NetError::Busy)));
                    }
                    let result = Pin::new(response.as_mut().unwrap()).poll_next(cx);
                    if cancelled() {
                        ended = true;
                        Poll::Ready(Some(Err(NetError::Busy)))
                    } else {
                        result
                    }
                })
            }),
        )
    }

    fn is_using_edns(&self) -> bool {
        self.inner.is_using_edns()
    }
    fn is_verifying_dnssec(&self) -> bool {
        self.inner.is_verifying_dnssec()
    }
}

pub(crate) struct PacedUdp<U> {
    pub inner: U,
    pub pacer: Arc<UpstreamPacer>,
    pending: Mutex<Option<DatagramSend>>,
}

struct DatagramSend {
    target: SocketAddr,
    bytes: Vec<u8>,
    future: PermitFuture,
    permit: Option<SendPermit>,
}

impl<U> PacedUdp<U> {
    pub fn new(inner: U, pacer: Arc<UpstreamPacer>) -> Self {
        Self {
            inner,
            pacer,
            pending: Mutex::new(None),
        }
    }
}

impl DatagramSend {
    fn new(pacer: &Arc<UpstreamPacer>, target: SocketAddr, bytes: &[u8]) -> Self {
        Self {
            target,
            bytes: bytes.to_vec(),
            future: pacer.gate(target.ip(), bytes),
            permit: None,
        }
    }
}

impl<U: DnsUdpSocket> PacedUdp<U> {
    fn poll_datagram(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
        send: &mut DatagramSend,
    ) -> Poll<io::Result<usize>> {
        if send.permit.as_ref().is_some_and(|permit| !permit.current()) {
            send.permit = None;
            send.future = self.pacer.gate(target.ip(), buf);
        }
        if send.permit.is_none() {
            match send.future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(acquired)) => send.permit = Some(acquired),
                Poll::Ready(None) => return Poll::Ready(Ok(buf.len())),
            }
        }
        match self.inner.poll_send_to(cx, buf, target) {
            Poll::Pending => {
                send.permit = None;
                send.future = self.pacer.gate(target.ip(), buf);
                Poll::Pending
            }
            Poll::Ready(result) => {
                if result.is_ok() {
                    send.permit.as_mut().unwrap().sent();
                }
                Poll::Ready(result)
            }
        }
    }
}

#[async_trait::async_trait]
impl<U: DnsUdpSocket> DnsUdpSocket for PacedUdp<U> {
    type Time = U::Time;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.inner.poll_recv_from(cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut pending = self.pending.lock().unwrap();
        if pending
            .as_ref()
            .is_some_and(|send| send.target != target || send.bytes != buf)
        {
            *pending = None;
        }
        let send = pending.get_or_insert_with(|| DatagramSend::new(&self.pacer, target, buf));
        let result = self.poll_datagram(cx, buf, target, send);
        if result.is_ready() {
            *pending = None;
        }
        result
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let mut send = DatagramSend::new(&self.pacer, target, buf);
        futures_util::future::poll_fn(|cx| self.poll_datagram(cx, buf, target, &mut send)).await
    }
}

pub(crate) struct PacedTcp<T> {
    pub inner: T,
    pacer: Arc<UpstreamPacer>,
    ip: IpAddr,
    frame: Vec<u8>,
    expected: Option<usize>,
    written: usize,
    gate: Option<PermitFuture>,
    permit: Option<SendPermit>,
}

impl<T> PacedTcp<T> {
    pub fn new(inner: T, pacer: Arc<UpstreamPacer>, ip: IpAddr) -> Self {
        Self {
            inner,
            pacer,
            ip,
            frame: Vec::new(),
            expected: None,
            written: 0,
            gate: None,
            permit: None,
        }
    }
}

impl<T: DnsTcpStream> DnsTcpStream for PacedTcp<T> {
    type Time = T::Time;
}

impl<T: futures_util::io::AsyncRead + Unpin> futures_util::io::AsyncRead for PacedTcp<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: futures_util::io::AsyncWrite + Unpin> PacedTcp<T> {
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.expected != Some(self.frame.len()) {
            return Poll::Ready(Ok(()));
        }
        if self.permit.as_ref().is_some_and(|permit| !permit.current()) {
            self.permit = None;
            self.gate = None;
        }
        if self.gate.is_none() {
            self.gate = Some(self.pacer.gate(self.ip, &self.frame[DNS_LENGTH_BYTES..]));
        }
        if self.permit.is_none() {
            match self.gate.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(permit)) => self.permit = Some(permit),
                Poll::Ready(None) => {
                    self.frame.clear();
                    self.expected = None;
                    self.gate = None;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        while self.written < self.frame.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.frame[self.written..]) {
                Poll::Pending => {
                    if self.written == 0 {
                        self.permit = None;
                        self.gate = None;
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(size)) => {
                    self.permit.as_mut().unwrap().sent();
                    self.written += size;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        self.frame.clear();
        self.expected = None;
        self.written = 0;
        self.gate = None;
        self.permit = None;
        Poll::Ready(Ok(()))
    }
}

impl<T: futures_util::io::AsyncWrite + Unpin> futures_util::io::AsyncWrite for PacedTcp<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::task::ready!(self.poll_frame(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let missing = self.expected.unwrap_or(DNS_LENGTH_BYTES) - self.frame.len();
        let size = missing.min(buf.len());
        self.frame.extend_from_slice(&buf[..size]);
        if self.expected.is_none() && self.frame.len() == DNS_LENGTH_BYTES {
            self.expected = Some(
                DNS_LENGTH_BYTES
                    + usize::from(u16::from_be_bytes(
                        self.frame[..DNS_LENGTH_BYTES].try_into().unwrap(),
                    )),
            );
        }
        Poll::Ready(Ok(size))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_frame(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_frame(cx))?;
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{FutureExt, io::AsyncWriteExt};
    use hickory_server::net::runtime::TokioTime;
    use hickory_server::proto::op::Query;
    use hickory_server::proto::rr::Name;
    use std::sync::atomic::{AtomicBool, Ordering};

    const SERVER_A: &str = "192.0.2.1";
    const SERVER_B: &str = "192.0.2.2";

    fn limits() -> UpstreamLimits {
        UpstreamLimits {
            global: UpstreamQuota { qps: 2, burst: 2 },
            per_server: UpstreamQuota { qps: 1, burst: 1 },
            max_pending: 1,
            max_wait: Duration::from_secs(2),
        }
    }

    fn message() -> Message {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_ascii("test.example.").unwrap(),
            RecordType::A,
        ));
        message
    }

    #[tokio::test(start_paused = true)]
    async fn fractional_token_intervals_advance_and_disabled_limits_wake_waiters() {
        let quota = UpstreamQuota { qps: 3, burst: 1 };
        let config = UpstreamLimits {
            global: quota.clone(),
            per_server: quota,
            max_pending: 1,
            max_wait: Duration::from_secs(1),
        };
        let pacer = UpstreamPacer::new(Some(config), Arc::new(Stats::default()));
        pacer
            .acquire(SERVER_A.parse().unwrap())
            .await
            .unwrap()
            .sent();
        let mut waiting = Box::pin(pacer.acquire(SERVER_A.parse().unwrap()));
        assert!(waiting.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_nanos(333_333_333)).await;
        assert!(waiting.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_nanos(1)).await;
        waiting.await.unwrap().sent();
        let mut waiting = Box::pin(pacer.acquire(SERVER_A.parse().unwrap()));
        assert!(waiting.as_mut().now_or_never().is_none());
        pacer.reconfigure(None);
        assert!(waiting.await.is_some());
        assert_eq!(pacer.state.lock().unwrap().pending, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn server_waits_leave_global_capacity_for_other_servers() {
        let pacer = UpstreamPacer::new(Some(limits()), Arc::new(Stats::default()));
        pacer
            .acquire(SERVER_A.parse().unwrap())
            .await
            .unwrap()
            .sent();
        let waiting = pacer.acquire(SERVER_A.parse().unwrap());
        tokio::pin!(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        pacer
            .acquire(SERVER_B.parse().unwrap())
            .await
            .unwrap()
            .sent();
        assert_eq!(pacer.state.lock().unwrap().pending, 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        waiting.await.unwrap().sent();
        assert_eq!(pacer.state.lock().unwrap().pending, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn queue_capacity_and_wait_deadline_are_bounded() {
        let mut config = limits();
        config.max_wait = Duration::from_millis(100);
        let pacer = UpstreamPacer::new(Some(config), Arc::new(Stats::default()));
        pacer
            .acquire(SERVER_A.parse().unwrap())
            .await
            .unwrap()
            .sent();
        let mut waiting = Box::pin(pacer.acquire(SERVER_A.parse().unwrap()));
        assert!(waiting.as_mut().now_or_never().is_none());
        assert!(pacer.acquire(SERVER_A.parse().unwrap()).await.is_none());
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(waiting.await.is_none());
        assert_eq!(pacer.state.lock().unwrap().pending, 0);
        assert!(
            pacer
                .stats
                .prometheus(0)
                .contains("echoic_upstream_pacing_rejected_total 2")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_waits_release_queue_capacity_and_reserved_tokens() {
        let pacer = UpstreamPacer::new(Some(limits()), Arc::new(Stats::default()));
        pacer
            .acquire(SERVER_A.parse().unwrap())
            .await
            .unwrap()
            .sent();
        let mut waiting = Box::pin(pacer.acquire(SERVER_A.parse().unwrap()));
        assert!(waiting.as_mut().now_or_never().is_none());
        drop(waiting);
        assert_eq!(pacer.state.lock().unwrap().pending, 0);
        let permit = pacer.acquire(SERVER_B.parse().unwrap()).await.unwrap();
        drop(permit);
        assert!(
            pacer
                .acquire(SERVER_B.parse().unwrap())
                .now_or_never()
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reloads_preserve_debt_and_invalidate_unpaced_permits() {
        let pacer = UpstreamPacer::new(None, Arc::new(Stats::default()));
        let unpaced = pacer.acquire(SERVER_A.parse().unwrap()).await.unwrap();
        let mut config = limits();
        config.max_wait = Duration::ZERO;
        pacer.reconfigure(Some(config.clone()));
        assert!(!unpaced.current());
        pacer
            .acquire(SERVER_A.parse().unwrap())
            .await
            .unwrap()
            .sent();
        pacer.reconfigure(Some(config.clone()));
        assert!(pacer.acquire(SERVER_A.parse().unwrap()).await.is_none());
        config.per_server.burst = 10;
        pacer.reconfigure(Some(config));
        assert!(pacer.acquire(SERVER_A.parse().unwrap()).await.is_none());
    }

    #[derive(Default)]
    struct WireUdp {
        packets: Mutex<Vec<Vec<u8>>>,
        blocked: AtomicBool,
        writer: Mutex<Option<std::task::Waker>>,
    }

    #[async_trait::async_trait]
    impl DnsUdpSocket for WireUdp {
        type Time = TokioTime;
        fn poll_recv_from(
            &self,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr)>> {
            Poll::Pending
        }
        fn poll_send_to(
            &self,
            _cx: &mut Context<'_>,
            buf: &[u8],
            _target: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            if self.blocked.load(Ordering::Relaxed) {
                *self.writer.lock().unwrap() = Some(_cx.waker().clone());
                return Poll::Pending;
            }
            self.packets.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn udp_retransmissions_consume_budget_and_rejections_cancel_the_resolution() {
        let mut config = limits();
        config.max_wait = Duration::ZERO;
        let pacer = UpstreamPacer::new(Some(config), Arc::new(Stats::default()));
        let socket = PacedUdp::new(WireUdp::default(), pacer.clone());
        let context = Resolution::new();
        RESOLUTION
            .scope(context.clone(), async {
                let target: SocketAddr = format!("{SERVER_A}:53").parse().unwrap();
                let message = message();
                let _registration = pacer.register(target.ip(), &message);
                let bytes = message.to_vec().unwrap();
                socket.send_to(&bytes, target).await.unwrap();
                socket.send_to(&bytes, target).await.unwrap();
                assert_eq!(socket.inner.packets.lock().unwrap().len(), 1);
                assert!(context.rejected.is_cancelled());
                assert!(
                    pacer
                        .stats
                        .prometheus(0)
                        .contains("echoic_upstream_sent_total 1")
                );
            })
            .await;
        assert!(pacer.requests.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_resolutions_discard_waiting_datagrams() {
        let pacer = UpstreamPacer::new(Some(limits()), Arc::new(Stats::default()));
        let socket = PacedUdp::new(WireUdp::default(), pacer.clone());
        let context = Resolution::new();
        RESOLUTION
            .scope(context.clone(), async {
                let target: SocketAddr = format!("{SERVER_A}:53").parse().unwrap();
                let message = message();
                let _registration = pacer.register(target.ip(), &message);
                let bytes = message.to_vec().unwrap();
                socket.send_to(&bytes, target).await.unwrap();
                let mut waiting = Box::pin(socket.send_to(&bytes, target));
                assert!(waiting.as_mut().now_or_never().is_none());
                context.finished.cancel();
                waiting.await.unwrap();
                assert_eq!(pacer.state.lock().unwrap().pending, 0);
                assert_eq!(socket.inner.packets.lock().unwrap().len(), 1);
                assert!(!context.rejected.is_cancelled());
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn udp_write_backpressure_releases_unused_budget() {
        let mut config = limits();
        config.global = UpstreamQuota { qps: 1, burst: 1 };
        let pacer = UpstreamPacer::new(Some(config), Arc::new(Stats::default()));
        let socket = PacedUdp::new(WireUdp::default(), pacer.clone());
        socket.inner.blocked.store(true, Ordering::Relaxed);
        let bytes = message().to_vec().unwrap();
        let target = format!("{SERVER_A}:53").parse().unwrap();
        let mut sending = Box::pin(socket.send_to(&bytes, target));
        assert!(sending.as_mut().now_or_never().is_none());
        pacer
            .acquire(SERVER_B.parse().unwrap())
            .now_or_never()
            .unwrap()
            .unwrap()
            .sent();
        socket.inner.blocked.store(false, Ordering::Relaxed);
        socket.inner.writer.lock().unwrap().take().unwrap().wake();
        assert!(sending.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        sending.await.unwrap();
        assert_eq!(socket.inner.packets.lock().unwrap().len(), 1);
        assert_eq!(pacer.state.lock().unwrap().pending, 0);
    }

    #[derive(Default)]
    struct WireTcp {
        bytes: Vec<u8>,
        blocked: bool,
    }

    impl futures_util::io::AsyncWrite for WireTcp {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.blocked {
                return Poll::Pending;
            }
            const PARTIAL_WRITE: usize = 3;
            let size = buf.len().min(PARTIAL_WRITE);
            self.bytes.extend_from_slice(&buf[..size]);
            Poll::Ready(Ok(size))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_write_backpressure_releases_unused_budget() {
        let mut config = limits();
        config.global = UpstreamQuota { qps: 1, burst: 1 };
        let pacer = UpstreamPacer::new(Some(config), Arc::new(Stats::default()));
        let mut stream = PacedTcp::new(
            WireTcp {
                bytes: Vec::new(),
                blocked: true,
            },
            pacer.clone(),
            SERVER_A.parse().unwrap(),
        );
        let bytes = message().to_vec().unwrap();
        let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&bytes);
        stream.write_all(&frame).await.unwrap();
        let mut flushing = Box::pin(stream.flush());
        assert!(flushing.as_mut().now_or_never().is_none());
        drop(flushing);
        pacer
            .acquire(SERVER_B.parse().unwrap())
            .now_or_never()
            .unwrap()
            .unwrap()
            .sent();
        stream.inner.blocked = false;
        let mut flushing = Box::pin(stream.flush());
        assert!(flushing.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        flushing.await.unwrap();
        assert_eq!(stream.inner.bytes, frame);
        assert_eq!(pacer.state.lock().unwrap().pending, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_paces_each_frame_and_discards_rejected_frames_without_partial_headers() {
        let mut config = limits();
        config.max_wait = Duration::ZERO;
        let pacer = UpstreamPacer::new(Some(config), Arc::new(Stats::default()));
        let mut stream =
            PacedTcp::new(WireTcp::default(), pacer.clone(), SERVER_A.parse().unwrap());
        let context = Resolution::new();
        RESOLUTION
            .scope(context.clone(), async {
                let message = message();
                let _registration = pacer.register(SERVER_A.parse().unwrap(), &message);
                let bytes = message.to_vec().unwrap();
                let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&bytes);
                stream.write_all(&frame[..1]).await.unwrap();
                stream.write_all(&frame[1..]).await.unwrap();
                stream.flush().await.unwrap();
                stream.write_all(&frame).await.unwrap();
                stream.flush().await.unwrap();
                assert_eq!(stream.inner.bytes, frame);
                assert!(context.rejected.is_cancelled());
                context.finished.cancel();
                let retry = Resolution::new();
                tokio::time::advance(Duration::from_secs(1)).await;
                RESOLUTION
                    .scope(retry, async {
                        let _retry_registration =
                            pacer.register(SERVER_A.parse().unwrap(), &message);
                        stream.write_all(&frame).await.unwrap();
                        stream.flush().await.unwrap();
                        assert_eq!(stream.inner.bytes.len(), frame.len() * 2);
                        assert!(
                            pacer
                                .stats
                                .prometheus(0)
                                .contains("echoic_upstream_sent_total 2")
                        );
                    })
                    .await;
            })
            .await;
    }
}
