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
use std::fs;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use async_trait::async_trait;
use hickory_server::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_server::net::runtime::{RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime};
use hickory_server::net::{DnsError, NetError};
use hickory_server::proto::dnssec::TrustAnchors;
use hickory_server::proto::op::{Message, Query};
use hickory_server::proto::rr::{Name, RData, RecordSet};
use hickory_server::proto::serialize::txt::Parser;
use hickory_server::resolver::ConnectionProvider;
use hickory_server::resolver::recursor::{
    DnssecConfig as HickoryDnssecConfig, DnssecPolicy, QNameMinimization, Recursor, RecursorError,
    RecursorOptions,
};
use tokio::net::{TcpSocket, TcpStream};

use crate::config::{Config, QNameMinimization as ConfigQNameMinimization};
use crate::net::apply_dscp;
use crate::stats::Stats;
use crate::upstream::{
    PACING_EXHAUSTED, PacedProvider, PacedTcp, PacedUdp, RESOLUTION, Resolution, UpstreamPacer,
};

const EMBEDDED_ROOT_HINTS: &str = include_str!("../assets/root.hints");
const EMBEDDED_ROOT_HINTS_NAME: &str = "assets/root.hints";
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct ResolvedResponse {
    pub message: Message,
    pub stale: bool,
    pub cache_hit: bool,
}

#[async_trait]
pub trait RecursiveResolver: Send + Sync {
    async fn resolve(&self, query: Query, dnssec_ok: bool) -> Result<Message, RecursorError>;

    async fn resolve_cached(
        &self,
        query: Query,
        dnssec_ok: bool,
    ) -> Result<ResolvedResponse, RecursorError> {
        self.resolve(query, dnssec_ok)
            .await
            .map(|message| ResolvedResponse {
                message,
                stale: false,
                cache_hit: false,
            })
    }

    async fn stale_cached_response(&self, _query: Query, _dnssec_ok: bool) -> Option<Message> {
        None
    }

    fn is_validating(&self) -> bool;
}

#[async_trait]
impl<P: ConnectionProvider> RecursiveResolver for Recursor<P> {
    async fn resolve(&self, query: Query, dnssec_ok: bool) -> Result<Message, RecursorError> {
        Recursor::<P>::resolve(self, query, Instant::now(), dnssec_ok).await
    }

    fn is_validating(&self) -> bool {
        Recursor::<P>::is_validating(self)
    }
}

#[derive(Clone)]
pub struct RecursorHandle {
    inner: Arc<ArcSwap<Arc<dyn RecursiveResolver>>>,
}

impl RecursorHandle {
    pub fn new(resolver: Arc<dyn RecursiveResolver>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(resolver)),
        }
    }

    pub fn current(&self) -> Arc<dyn RecursiveResolver> {
        Arc::clone(&*self.inner.load())
    }

    pub fn store(&self, resolver: Arc<dyn RecursiveResolver>) {
        self.inner.store(Arc::new(resolver));
    }

    pub fn is_validating(&self) -> bool {
        self.current().is_validating()
    }
}

pub struct CachedRecursiveResolver {
    inner: Arc<dyn RecursiveResolver>,
    cache: Option<Arc<crate::persistent_cache::PersistentDnsCache>>,
}

impl CachedRecursiveResolver {
    pub fn new(
        inner: Arc<dyn RecursiveResolver>,
        cache: Arc<arc_swap::ArcSwap<Option<Arc<crate::persistent_cache::PersistentDnsCache>>>>,
    ) -> Self {
        Self {
            inner,
            cache: cache.load_full().as_ref().clone(),
        }
    }
}

#[async_trait]
impl RecursiveResolver for CachedRecursiveResolver {
    async fn resolve(&self, query: Query, dnssec_ok: bool) -> Result<Message, RecursorError> {
        self.resolve_cached(query, dnssec_ok)
            .await
            .map(|response| response.message)
    }

    async fn resolve_cached(
        &self,
        query: Query,
        dnssec_ok: bool,
    ) -> Result<ResolvedResponse, RecursorError> {
        use crate::persistent_cache::CacheKey;
        use std::time::SystemTime;

        let Some(cache) = self.cache.as_ref() else {
            return self
                .inner
                .resolve(query.clone(), dnssec_ok)
                .await
                .map(|message| ResolvedResponse {
                    message,
                    stale: false,
                    cache_hit: false,
                });
        };

        let key = CacheKey {
            name: query.name().clone().to_lowercase(),
            qtype: query.query_type(),
            qclass: query.query_class(),
            dnssec_ok,
        };

        let now = SystemTime::now();
        if let Some((message, false)) = cache.get(&key, now) {
            return Ok(ResolvedResponse {
                message,
                stale: false,
                cache_hit: true,
            });
        }

        match self.inner.resolve(query.clone(), dnssec_ok).await {
            Ok(message) => {
                cache.insert(key, message.clone(), SystemTime::now());
                Ok(ResolvedResponse {
                    message,
                    stale: false,
                    cache_hit: false,
                })
            }
            Err(error) if cache.config().serve_stale && !is_negative_recursor_error(&error) => {
                if let Some((message, true)) = cache.get(&key, SystemTime::now()) {
                    return Ok(ResolvedResponse {
                        message,
                        stale: true,
                        cache_hit: true,
                    });
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn stale_cached_response(&self, query: Query, _dnssec_ok: bool) -> Option<Message> {
        use crate::persistent_cache::CacheKey;
        use std::time::SystemTime;

        let cache = self.cache.as_ref()?;
        let key = CacheKey {
            name: query.name().clone().to_lowercase(),
            qtype: query.query_type(),
            qclass: query.query_class(),
            dnssec_ok: _dnssec_ok,
        };
        let now = SystemTime::now();
        cache
            .get(&key, now)
            .and_then(|(message, stale)| if stale { Some(message) } else { None })
    }

    fn is_validating(&self) -> bool {
        self.inner.is_validating()
    }
}

fn is_negative_recursor_error(error: &RecursorError) -> bool {
    matches!(
        error,
        RecursorError::Negative(_) | RecursorError::Net(NetError::Dns(DnsError::NoRecordsFound(_)))
    )
}

#[derive(Clone)]
struct UpstreamRuntimeProvider {
    pacer: Arc<UpstreamPacer>,
    inner: TokioRuntimeProvider,
    dscp: Option<u8>,
    warned: Arc<AtomicBool>,
}

impl UpstreamRuntimeProvider {
    fn new(dscp: Option<u8>, pacer: Arc<UpstreamPacer>) -> Self {
        Self {
            pacer,
            inner: TokioRuntimeProvider::new(),
            dscp,
            warned: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl RuntimeProvider for UpstreamRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = PacedUdp<tokio::net::UdpSocket>;
    type Tcp = PacedTcp<AsyncIoTokioAsStd<TcpStream>>;

    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let dscp = self.dscp;
        let warned = self.warned.clone();
        let pacer = self.pacer.clone();
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }

            socket.set_nodelay(true)?;
            if let Some(dscp) = dscp
                && let Err(error) = apply_dscp(&socket, server_addr, dscp)
                && !warned.swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    dscp,
                    transport = "tcp",
                    error = %error,
                    "failed to set upstream DSCP; continuing without it"
                );
            }

            let wait_for = wait_for.unwrap_or(UPSTREAM_CONNECT_TIMEOUT);
            match tokio::time::timeout(wait_for, socket.connect(server_addr)).await {
                Ok(Ok(socket)) => Ok(PacedTcp::new(
                    AsyncIoTokioAsStd(socket),
                    pacer,
                    server_addr.ip(),
                )),
                Ok(Err(error)) => Err(error),
                Err(_) => {
                    tracing::debug!(%server_addr, "TCP connect timeout");
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TCP connect timed out",
                    ))
                }
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        let dscp = self.dscp;
        let warned = self.warned.clone();
        let pacer = self.pacer.clone();
        Box::pin(async move {
            let socket = tokio::net::UdpSocket::bind(local_addr).await?;
            if let Some(dscp) = dscp
                && let Err(error) = apply_dscp(&socket, local_addr, dscp)
                && !warned.swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    dscp,
                    transport = "udp",
                    error = %error,
                    "failed to set upstream DSCP; continuing without it"
                );
            }
            Ok(PacedUdp::new(socket, pacer))
        })
    }
}

pub fn build_recursor(config: &Config) -> anyhow::Result<Arc<dyn RecursiveResolver>> {
    let pacer = UpstreamPacer::new(
        config.recursor.upstream_limits.clone(),
        Arc::new(Stats::default()),
    );
    build_recursor_with_pacer(config, pacer)
}

pub(crate) fn build_recursor_with_pacer(
    config: &Config,
    pacer: Arc<UpstreamPacer>,
) -> anyhow::Result<Arc<dyn RecursiveResolver>> {
    let runtime = UpstreamRuntimeProvider::new(config.recursor.dscp, pacer.clone());
    build_with_provider(
        config,
        PacedProvider {
            inner: runtime,
            pacer,
            gate_requests: false,
        },
    )
}

pub fn build_recursor_with_provider<P: ConnectionProvider>(
    config: &Config,
    provider: P,
) -> anyhow::Result<Arc<dyn RecursiveResolver>> {
    let pacer = UpstreamPacer::new(
        config.recursor.upstream_limits.clone(),
        Arc::new(Stats::default()),
    );
    build_with_provider(
        config,
        PacedProvider {
            inner: provider,
            pacer,
            gate_requests: true,
        },
    )
}

struct PacedResolver<P: ConnectionProvider> {
    inner: Recursor<P>,
    pacer: Arc<UpstreamPacer>,
}

#[async_trait]
impl<P: ConnectionProvider> RecursiveResolver for PacedResolver<P> {
    async fn resolve(&self, query: Query, dnssec_ok: bool) -> Result<Message, RecursorError> {
        let context = Resolution::new();
        let _finished = context.finished.clone().drop_guard();
        let result = RESOLUTION.scope(context.clone(), async {
            tokio::select! {
                biased;
                _ = context.rejected.cancelled() => Err(RecursorError::Message(PACING_EXHAUSTED)),
                result = self.inner.resolve(query, Instant::now(), dnssec_ok) => result,
            }
        }).await;
        let result = if context.rejected.is_cancelled() {
            Err(RecursorError::Message(PACING_EXHAUSTED))
        } else {
            result
        };
        if result.as_ref().is_err_and(|error| {
            !is_negative_recursor_error(error)
                && !matches!(error, RecursorError::Message(PACING_EXHAUSTED))
        }) {
            self.pacer.stats.record_upstream_failure();
        }
        result
    }

    fn is_validating(&self) -> bool {
        self.inner.is_validating()
    }
}

fn build_with_provider<P: ConnectionProvider>(
    config: &Config,
    provider: PacedProvider<P>,
) -> anyhow::Result<Arc<dyn RecursiveResolver>> {
    let pacer = provider.pacer.clone();
    let roots = load_roots(&config.recursor)?;
    let mut options = RecursorOptions {
        ns_cache_size: config.recursor.ns_cache_size,
        response_cache_size: config.recursor.response_cache_size,
        recursion_limit: config.recursor.recursion_limit,
        ns_recursion_limit: config.recursor.ns_recursion_limit,
        allow_server: config.recursor.allow_server.clone(),
        deny_answers: config.recursor.deny_answers.clone(),
        case_randomization: config.recursor.case_randomization,
        edns_payload_len: config.recursor.edns_payload_len,
        qname_minimization: match config.recursor.qname_minimization {
            ConfigQNameMinimization::Strict => QNameMinimization::Strict,
            ConfigQNameMinimization::Relaxed => QNameMinimization::Relaxed,
        },
        ..Default::default()
    };
    if let Some(deny_server) = &config.recursor.deny_server {
        options.deny_server = deny_server.clone();
    }

    let dnssec_policy = if !config.dnssec.enabled {
        tracing::warn!("DNSSEC validation is disabled");
        DnssecPolicy::SecurityUnaware
    } else if !config.dnssec.validate {
        tracing::warn!(
            "DNSSEC validation is disabled by configuration; responses may be unsigned or bogus"
        );
        DnssecPolicy::ValidationDisabled
    } else {
        #[allow(clippy::field_reassign_with_default)]
        let mut dnssec = HickoryDnssecConfig::default();
        if let Some(path) = &config.dnssec.trust_anchor {
            let anchors = TrustAnchors::from_file(path).with_context(|| {
                format!("failed to read DNSSEC trust anchor {}", path.display())
            })?;
            dnssec.trust_anchor = Some(Arc::new(anchors));
        }
        dnssec.nsec3_soft_iteration_limit = config.dnssec.nsec3_soft_iteration_limit;
        dnssec.nsec3_hard_iteration_limit = config.dnssec.nsec3_hard_iteration_limit;
        dnssec.validation_cache_size = config.dnssec.validation_cache_size;
        DnssecPolicy::ValidateWithStaticKey(dnssec)
    };

    let recursor = Recursor::new(&roots, dnssec_policy, None, options, provider)
        .map_err(|error| anyhow::anyhow!("failed to build recursor: {error}"))?;

    if config.dnssec.enabled && config.dnssec.validate && !recursor.is_validating() {
        bail!("recursor was configured without DNSSEC validation");
    }

    Ok(Arc::new(PacedResolver {
        inner: recursor,
        pacer,
    }))
}

fn load_roots(config: &crate::config::RecursorConfig) -> anyhow::Result<Vec<IpAddr>> {
    let (contents, path) = match &config.root_hints {
        Some(path) => (
            fs::read_to_string(path)
                .with_context(|| format!("failed to read root hints {}", path.display()))?,
            path.clone(),
        ),
        None => (
            EMBEDDED_ROOT_HINTS.to_owned(),
            PathBuf::from(EMBEDDED_ROOT_HINTS_NAME),
        ),
    };

    let (_, roots) = Parser::new(contents, Some(path), Some(Name::root()))
        .parse()
        .map_err(|error| anyhow::anyhow!("failed to parse root hints: {error}"))?;

    let addresses = roots
        .values()
        .flat_map(RecordSet::records_without_rrsigs)
        .map(|record| &record.data)
        .filter_map(RData::ip_addr)
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        bail!("root hints did not contain any addresses");
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecursorConfig;

    struct CacheOnlyResolver;

    #[async_trait]
    impl RecursiveResolver for CacheOnlyResolver {
        async fn resolve(&self, _query: Query, _dnssec_ok: bool) -> Result<Message, RecursorError> {
            Err(RecursorError::Message("unexpected upstream lookup"))
        }

        fn is_validating(&self) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn resolver_keeps_its_cache_when_the_shared_handle_is_replaced() {
        use crate::persistent_cache::{CacheKey, PersistentDnsCache};
        use hickory_server::proto::rr::{DNSClass, RecordType};
        let config = crate::config::CacheConfig::default();
        let original = Arc::new(PersistentDnsCache::new(&config));
        let handle = Arc::new(ArcSwap::from_pointee(Some(original.clone())));
        let resolver = CachedRecursiveResolver::new(Arc::new(CacheOnlyResolver), handle.clone());
        let name = Name::from_ascii("example.com.").unwrap();
        let key = CacheKey {
            name: name.clone(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        let mut message = Message::response(41, hickory_server::proto::op::OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        original.insert(key.clone(), message, std::time::SystemTime::now());
        let replacement = Arc::new(PersistentDnsCache::new(&config));
        handle.store(Arc::new(Some(replacement.clone())));
        let response = resolver
            .resolve_cached(Query::query(name, RecordType::A), false)
            .await
            .unwrap();
        assert!(response.cache_hit);
        assert_eq!(response.message.metadata.id, 41);
        assert!(
            replacement
                .get(&key, std::time::SystemTime::now())
                .is_none()
        );
    }

    #[derive(Clone)]
    struct PortProvider {
        runtime: UpstreamRuntimeProvider,
        port: u16,
    }

    impl ConnectionProvider for PortProvider {
        type Conn = <UpstreamRuntimeProvider as ConnectionProvider>::Conn;
        type FutureConn = <UpstreamRuntimeProvider as ConnectionProvider>::FutureConn;
        type RuntimeProvider = UpstreamRuntimeProvider;

        fn new_connection(
            &self,
            ip: IpAddr,
            config: &hickory_server::resolver::config::ConnectionConfig,
            cx: &hickory_server::resolver::PoolContext,
        ) -> Result<Self::FutureConn, NetError> {
            let mut config = config.clone();
            config.port = self.port;
            self.runtime.new_connection(ip, &config, cx)
        }
        fn runtime_provider(&self) -> &Self::RuntimeProvider {
            &self.runtime
        }
    }

    #[tokio::test]
    async fn wire_pacing_counts_tcp_fallback_and_recovers_without_caching_local_failures() {
        use crate::config::{UpstreamLimits, UpstreamQuota};
        use hickory_server::proto::op::OpCode;
        use hickory_server::proto::rr::{
            Record, RecordType,
            rdata::{A, NS},
        };
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        crate::tls::install_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::bind(address).await.unwrap();
        let udp_count = Arc::new(AtomicU64::new(0));
        let tcp_count = Arc::new(AtomicU64::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn({
            let count = udp_count.clone();
            async move {
                let mut buffer = vec![0; u16::MAX as usize];
                loop {
                    let (size, source) = socket.recv_from(&mut buffer).await.unwrap();
                    let request = Message::from_vec(&buffer[..size]).unwrap();
                    count.fetch_add(1, Ordering::Relaxed);
                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                    response.queries = request.queries;
                    response.metadata.truncation = true;
                    socket
                        .send_to(&response.to_vec().unwrap(), source)
                        .await
                        .unwrap();
                }
            }
        });
        tasks.spawn({
            let count = tcp_count.clone();
            async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut stream, _) = accepted.unwrap();
                            let count = count.clone();
                            connections.spawn(async move {
                                while let Ok(length) = stream.read_u16().await {
                                    let mut bytes = vec![0; usize::from(length)];
                                    stream.read_exact(&mut bytes).await.unwrap();
                                    let request = Message::from_vec(&bytes).unwrap();
                                    count.fetch_add(1, Ordering::Relaxed);
                                    let query = request.queries[0].clone();
                                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                                    response.add_query(query.clone());
                                    response.metadata.authoritative = true;
                                    if query.query_type() == RecordType::NS {
                                        let server = Name::from_ascii("ns.example.").unwrap();
                                        response.add_answer(Record::from_rdata(query.name().clone(), 60, RData::NS(NS(server.clone()))));
                                        response.add_additional(Record::from_rdata(server, 60, RData::A(A::new(127,0,0,1))));
                                    } else {
                                        response.add_answer(Record::from_rdata(query.name().clone(), 60, RData::A(A::new(192,0,2,10))));
                                    }
                                    let bytes = response.to_vec().unwrap();
                                    stream.write_u16(bytes.len() as u16).await.unwrap();
                                    stream.write_all(&bytes).await.unwrap();
                                }
                            });
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {}
                    }
                }
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let hints = directory.path().join("root.hints");
        fs::write(&hints, ". 60 NS ns.example.\nns.example. 60 A 127.0.0.1\n").unwrap();
        let mut config = Config::from_toml_str("[dnssec]\nenabled=false\n[[listeners]]\nname='test'\nprotocol='udp'\naddress='127.0.0.1:0'").unwrap();
        config.recursor.root_hints = Some(hints);
        config.recursor.deny_server = Some(Vec::new());
        let quota = UpstreamLimits {
            global: UpstreamQuota { qps: 20, burst: 1 },
            per_server: UpstreamQuota { qps: 20, burst: 1 },
            max_pending: 8,
            max_wait: Duration::from_secs(1),
        };
        let stats = Arc::new(Stats::default());
        let pacer = UpstreamPacer::new(Some(quota.clone()), stats.clone());
        let provider = PortProvider {
            runtime: UpstreamRuntimeProvider::new(None, pacer.clone()),
            port: address.port(),
        };
        let resolver = build_with_provider(
            &config,
            PacedProvider {
                inner: provider,
                pacer: pacer.clone(),
                gate_requests: false,
            },
        )
        .unwrap();
        let query = Query::query(Name::from_ascii("example.").unwrap(), RecordType::A);
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            resolver.resolve(query.clone(), false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!response.answers.is_empty());
        let sent = udp_count.load(Ordering::Relaxed) + tcp_count.load(Ordering::Relaxed);
        assert!(tcp_count.load(Ordering::Relaxed) > 0);
        assert!(
            stats
                .prometheus(0)
                .contains(&format!("echoic_upstream_sent_total {sent}\n"))
        );
        resolver.resolve(query, false).await.unwrap();
        assert_eq!(
            sent,
            udp_count.load(Ordering::Relaxed) + tcp_count.load(Ordering::Relaxed)
        );
        let mut tight = quota;
        tight.max_wait = Duration::ZERO;
        tight.global.qps = 1;
        tight.per_server.qps = 1;
        pacer.reconfigure(Some(tight));
        let uncached = Query::query(Name::from_ascii("other.example.").unwrap(), RecordType::A);
        let error = tokio::time::timeout(
            Duration::from_millis(500),
            resolver.resolve(uncached.clone(), false),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(
            matches!(error, RecursorError::Message(PACING_EXHAUSTED)),
            "{error:?}"
        );
        let cache_config = crate::config::CacheConfig {
            max_ttl: Duration::from_secs(1),
            serve_stale: true,
            stale_ttl: Duration::from_secs(60),
            ..Default::default()
        };
        let cache = Arc::new(crate::persistent_cache::PersistentDnsCache::new(
            &cache_config,
        ));
        let mut saved = Message::response(0, OpCode::Query);
        saved.add_answer(Record::from_rdata(
            uncached.name().clone(),
            1,
            RData::A(A::new(192, 0, 2, 99)),
        ));
        cache.insert(
            crate::persistent_cache::CacheKey {
                name: uncached.name().clone(),
                qtype: uncached.query_type(),
                qclass: uncached.query_class(),
                dnssec_ok: false,
            },
            saved,
            std::time::SystemTime::now() - Duration::from_secs(2),
        );
        let cached = CachedRecursiveResolver::new(
            resolver.clone(),
            Arc::new(ArcSwap::from_pointee(Some(cache))),
        );
        let stale = cached
            .resolve_cached(uncached.clone(), false)
            .await
            .unwrap();
        assert!(stale.stale);
        assert!(stale.cache_hit);
        assert_eq!(stale.message.answers[0].ttl, 0);
        pacer.reconfigure(None);
        let response =
            tokio::time::timeout(Duration::from_secs(3), resolver.resolve(uncached, false))
                .await
                .unwrap()
                .unwrap();
        assert!(!response.answers.is_empty());
        assert!(
            stats
                .prometheus(0)
                .contains("echoic_upstream_failures_total 0\n")
        );
    }

    #[test]
    fn embedded_root_hints_contain_addresses() {
        let addresses = load_roots(&RecursorConfig::default()).expect("root hints parse");

        assert!(!addresses.is_empty());
        assert!(addresses.iter().any(|address| address.is_ipv4()));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dscp_provider_applies_udp_socket_class() {
        let provider = UpstreamRuntimeProvider::new(
            Some(45),
            UpstreamPacer::new(None, Arc::new(Stats::default())),
        );
        let udp = provider
            .bind_udp(
                "127.0.0.1:0".parse().unwrap(),
                "192.0.2.1:53".parse().unwrap(),
            )
            .await
            .expect("bind udp");
        assert_eq!(
            socket2::SockRef::from(&udp.inner)
                .tos_v4()
                .expect("read tos"),
            180
        );
        drop(udp);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dscp_provider_applies_tcp_socket_class_before_connect() {
        use std::time::Duration;
        let listener: tokio::net::TcpListener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr: std::net::SocketAddr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let provider = UpstreamRuntimeProvider::new(
            Some(45),
            UpstreamPacer::new(None, Arc::new(Stats::default())),
        );
        let result = provider
            .connect_tcp(addr, None, Some(Duration::from_secs(2)))
            .await;
        assert!(result.is_ok(), "connect failed");
        let stream = result.unwrap();
        assert_eq!(
            socket2::SockRef::from(&stream.inner.0)
                .tos_v4()
                .expect("read tos"),
            180
        );
        server.await.unwrap();
    }
}
