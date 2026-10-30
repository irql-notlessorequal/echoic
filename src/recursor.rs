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
    cache: Arc<arc_swap::ArcSwap<Option<Arc<crate::persistent_cache::PersistentDnsCache>>>>,
}

impl CachedRecursiveResolver {
    pub fn new(
        inner: Arc<dyn RecursiveResolver>,
        cache: Arc<arc_swap::ArcSwap<Option<Arc<crate::persistent_cache::PersistentDnsCache>>>>,
    ) -> Self {
        Self { inner, cache }
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

        let cache = self.cache.load_full();
        let Some(cache) = cache.as_ref() else {
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
                cache.insert(key, message.clone(), now);
                Ok(ResolvedResponse {
                    message,
                    stale: false,
                    cache_hit: false,
                })
            }
            Err(error) if cache.config().serve_stale && !is_negative_recursor_error(&error) => {
                if let Some((message, true)) = cache.get(&key, now) {
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

        let loaded = self.cache.load_full();
        let Some(cache) = loaded.as_ref() else {
            return None;
        };
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
struct DscpRuntimeProvider {
    inner: TokioRuntimeProvider,
    dscp: u8,
    warned: Arc<AtomicBool>,
}

impl DscpRuntimeProvider {
    fn new(dscp: u8) -> Self {
        Self {
            inner: TokioRuntimeProvider::new(),
            dscp,
            warned: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl RuntimeProvider for DscpRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = tokio::net::UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

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
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }

            socket.set_nodelay(true)?;
            if let Err(error) = apply_dscp(&socket, server_addr, dscp)
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
                Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
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
        Box::pin(async move {
            let socket = tokio::net::UdpSocket::bind(local_addr).await?;
            if let Err(error) = apply_dscp(&socket, local_addr, dscp)
                && !warned.swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    dscp,
                    transport = "udp",
                    error = %error,
                    "failed to set upstream DSCP; continuing without it"
                );
            }
            Ok(socket)
        })
    }
}

pub fn build_recursor(config: &Config) -> anyhow::Result<Arc<dyn RecursiveResolver>> {
    match config.recursor.dscp {
        Some(dscp) => build_recursor_with_provider(config, DscpRuntimeProvider::new(dscp)),
        None => build_recursor_with_provider(config, TokioRuntimeProvider::new()),
    }
}

pub fn build_recursor_with_provider<P: ConnectionProvider>(
    config: &Config,
    provider: P,
) -> anyhow::Result<Arc<dyn RecursiveResolver>> {
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

    Ok(Arc::new(recursor))
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

    #[test]
    fn embedded_root_hints_contain_addresses() {
        let addresses = load_roots(&RecursorConfig::default()).expect("root hints parse");

        assert!(!addresses.is_empty());
        assert!(addresses.iter().any(|address| address.is_ipv4()));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dscp_provider_applies_udp_socket_class() {
        let provider = DscpRuntimeProvider::new(45);
        let udp = provider
            .bind_udp(
                "127.0.0.1:0".parse().unwrap(),
                "192.0.2.1:53".parse().unwrap(),
            )
            .await
            .expect("bind udp");
        assert_eq!(
            socket2::SockRef::from(&udp).tos_v4().expect("read tos"),
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
        let provider = DscpRuntimeProvider::new(45);
        let result = provider
            .connect_tcp(addr, None, Some(Duration::from_secs(2)))
            .await;
        assert!(result.is_ok(), "connect failed");
        let stream = result.unwrap();
        assert_eq!(
            socket2::SockRef::from(&stream.0)
                .tos_v4()
                .expect("read tos"),
            180
        );
        server.await.unwrap();
    }
}
