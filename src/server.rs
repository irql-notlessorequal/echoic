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
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, EffectiveListenerLimits, Protocol};
use crate::doh::{DohRuntimeState, start_doh_listener};
use crate::dot::start_dot_listener;
use crate::listeners::{ListenerRuntime, start_listener};
use crate::persistent_cache::PersistentDnsCache;
use crate::query::{ListenerQueryState, QueryService};
use crate::rate_limit::{KeyedRateLimiter, keyed_limiter};
use crate::recursor::{CachedRecursiveResolver, RecursorHandle, build_recursor};
use crate::rpz::RpzPolicy;
use crate::stats::Stats;
use crate::tls::{TlsState, install_crypto_provider};

pub type ReloadHandle = tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>;

const RATE_LIMITER_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
enum ReloadTrigger {
    File(Event),
    Signal,
}

struct ReloadContext {
    config: Arc<ArcSwap<Config>>,
    config_path: Option<PathBuf>,
    resolver: RecursorHandle,
    cache_handle: Arc<ArcSwap<Option<Arc<PersistentDnsCache>>>>,
    inflight: Arc<ArcSwap<Arc<Semaphore>>>,
    runtimes: Arc<Mutex<Vec<ListenerRuntime>>>,
    logging_reload: Option<ReloadHandle>,
    limiters: Arc<ArcSwap<Vec<Arc<KeyedRateLimiter>>>>,
}

struct ListenerUpdate {
    name: String,
    protocol: Protocol,
    address: std::net::SocketAddr,
    query_state: Arc<ListenerQueryState>,
    tls_state: Option<Arc<TlsState>>,
    dot_max_connections: Option<Arc<ArcSwap<Arc<Semaphore>>>>,
    doh_runtime: Option<Arc<ArcSwap<DohRuntimeState>>>,
    doh_max_connections: Option<Arc<ArcSwap<Arc<Semaphore>>>>,
    dscp: Option<u8>,
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    run_with_logging(config, None, None).await
}

pub async fn run_with_logging(
    config: Config,
    config_path: Option<PathBuf>,
    logging_reload: Option<ReloadHandle>,
) -> anyhow::Result<()> {
    install_crypto_provider();

    let config_store = Arc::new(ArcSwap::from_pointee(config.clone()));
    let stats = Arc::new(Stats::default());
    metrics::set_global_recorder(crate::metrics::EchoicMetricsRecorder::new(stats.clone()))
        .map_err(|error| anyhow::anyhow!("failed to install metrics recorder: {error}"))?;
    let cache_handle = Arc::new(ArcSwap::from_pointee(
        if config.cache.persistent || config.cache.serve_stale {
            Some(Arc::new(PersistentDnsCache::open(&config.cache).await))
        } else {
            None
        },
    ));
    let base_resolver = build_recursor(&config)?;
    let cached_resolver = Arc::new(CachedRecursiveResolver::new(
        base_resolver,
        cache_handle.clone(),
    ));
    let resolver_handle = RecursorHandle::new(cached_resolver);
    let inflight = Arc::new(Semaphore::new(config.server_limits.max_inflight_queries));
    let inflight_store = Arc::new(ArcSwap::from_pointee(inflight));
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let blocklist = RpzPolicy::load(
        &config.blocklist.rpz_paths,
        config.blocklist.rpz_origin.as_deref(),
    )?;

    let mut runtimes: Vec<ListenerRuntime> = Vec::new();
    for listener in &config.listeners {
        let service = QueryService::new(
            resolver_handle.clone(),
            listener,
            stats.clone(),
            inflight_store.clone(),
            &config.server_limits,
            config.policy.refuse_any,
            config.logging.query_names,
            blocklist.clone(),
        );

        let runtime = if listener.protocol == Protocol::Dot {
            let tls_name = listener.tls.as_deref().expect("validated tls");
            let tls_config = config
                .tls
                .iter()
                .find(|tls| tls.name == tls_name)
                .expect("validated tls");
            let tls_state = TlsState::load(&tls_config.cert, &tls_config.key, listener.protocol)
                .with_context(|| format!("listener {:?}: failed to load TLS", listener.name))?;
            let tls_state = Arc::new(tls_state);
            match start_dot_listener(listener, service, tls_state.clone()).await {
                Ok(runtime) => runtime,
                Err(error) => {
                    for runtime in &runtimes {
                        runtime.token.cancel();
                        runtime.task.abort();
                    }
                    return Err(
                        error.context(format!("listener {:?}: failed to start DoT", listener.name))
                    );
                }
            }
        } else if listener.protocol == Protocol::Doh {
            let tls_name = listener.tls.as_deref().expect("validated tls");
            let tls_config = config
                .tls
                .iter()
                .find(|tls| tls.name == tls_name)
                .expect("validated tls");
            let tls_state = TlsState::load(&tls_config.cert, &tls_config.key, listener.protocol)
                .with_context(|| format!("listener {:?}: failed to load TLS", listener.name))?;
            let tls_state = Arc::new(tls_state);
            let max_concurrent_requests = listener
                .limits
                .effective(listener.protocol)
                .max_concurrent_requests
                .unwrap_or(128) as usize;
            let landing_html = config
                .landing_page
                .read_html()
                .with_context(|| "failed to read landing page HTML")?;
            let landing_css = config
                .landing_page
                .read_css()
                .with_context(|| "failed to read landing page CSS")?;
            match start_doh_listener(
                listener,
                service,
                tls_state.clone(),
                max_concurrent_requests,
                config.server_limits.max_doh_body,
                config.server_limits.max_doh_uri,
                listener.hostname.clone().expect("validated hostname"),
                landing_html,
                landing_css,
                ready.clone(),
            )
            .await
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    for runtime in &runtimes {
                        runtime.token.cancel();
                        runtime.task.abort();
                    }
                    return Err(
                        error.context(format!("listener {:?}: failed to start DoH", listener.name))
                    );
                }
            }
        } else {
            match start_listener(listener, service, config.server_limits.query_timeout).await {
                Ok(runtime) => runtime,
                Err(error) => {
                    for runtime in &runtimes {
                        runtime.token.cancel();
                        runtime.task.abort();
                    }
                    return Err(error);
                }
            }
        };

        runtimes.push(runtime);
    }

    let runtimes = Arc::new(Mutex::new(runtimes));
    let limiters = Arc::new(ArcSwap::from_pointee(
        runtimes
            .lock()
            .unwrap()
            .iter()
            .map(|runtime| runtime.query_state.load().rate_limiter.clone())
            .collect::<Vec<_>>(),
    ));
    let cleanup_token = CancellationToken::new();
    let cleanup_task = spawn_rate_limiter_cleanup(cleanup_token.clone(), limiters.clone());

    let cache_flush_token = CancellationToken::new();
    let cache_flush_task = tokio::spawn({
        let token = cache_flush_token.clone();
        let config_store = config_store.clone();
        let cache_handle = cache_handle.clone();
        async move {
            loop {
                let delay = config_store.load().cache.flush_interval;
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(delay) => {}
                }
                if let Some(cache) = cache_handle.load_full().as_ref().clone()
                    && let Err(error) = cache.flush_async().await
                {
                    tracing::warn!(error = %error, "failed to flush persistent cache");
                }
            }
        }
    });

    let (trigger_tx, trigger_rx) = mpsc::unbounded_channel();
    let watched_paths = config_path
        .as_ref()
        .map(|path| watched_paths(&config, path))
        .unwrap_or_default();
    let (watcher, watched_paths) = if config_path.is_some() {
        let (watcher, watched) = build_watcher(&watched_paths, trigger_tx.clone())?;
        (Some(watcher), watched)
    } else {
        (None, HashSet::new())
    };

    #[cfg(unix)]
    let sighup_task = Some(tokio::spawn({
        let tx = trigger_tx.clone();
        async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut signal = match signal(SignalKind::hangup()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
            loop {
                signal.recv().await;
                let _ = tx.send(ReloadTrigger::Signal);
            }
        }
    }));
    #[cfg(not(unix))]
    let sighup_task: Option<JoinHandle<()>> = None;

    let reload_context = Arc::new(ReloadContext {
        config: config_store.clone(),
        config_path: config_path.clone(),
        resolver: resolver_handle.clone(),
        cache_handle: cache_handle.clone(),
        inflight: inflight_store.clone(),
        runtimes: runtimes.clone(),
        logging_reload: logging_reload.clone(),
        limiters: limiters.clone(),
    });

    let reload_task = tokio::spawn(reload_loop(
        reload_context.clone(),
        watcher,
        watched_paths,
        trigger_tx.clone(),
        trigger_rx,
    ));

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listeners = runtimes.lock().unwrap().len(),
        "echoic started"
    );

    ready.store(true, Ordering::Relaxed);

    shutdown_signal().await?;
    tracing::info!("shutdown requested");
    cleanup_token.cancel();
    cleanup_task.abort();
    let _ = cleanup_task.await;
    cache_flush_token.cancel();
    cache_flush_task.abort();
    let _ = cache_flush_task.await;
    if let Some(cache) = cache_handle.load_full().as_ref().clone()
        && let Err(error) = cache.flush_async().await
    {
        tracing::warn!(error = %error, "failed to flush persistent cache");
    }
    reload_task.abort();
    let _ = reload_task.await;
    if let Some(task) = sighup_task {
        task.abort();
        let _ = task.await;
    }

    for runtime in runtimes.lock().unwrap().iter() {
        runtime.token.cancel();
    }

    let shutdown_grace = config_store.load().server_limits.shutdown_grace;
    let deadline = tokio::time::Instant::now() + shutdown_grace;
    let runtimes = std::mem::take(&mut *runtimes.lock().unwrap());
    for runtime in runtimes {
        let ListenerRuntime {
            name, token, task, ..
        } = runtime;
        token.cancel();
        let abort = task.abort_handle();
        match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                tracing::warn!(listener = %name, error = %error, "listener stopped with an error");
            }
            Ok(Err(error)) => {
                tracing::warn!(listener = %name, error = %error, "listener task failed");
            }
            Err(_) => {
                abort.abort();
                tracing::warn!(
                    listener = %name,
                    grace_ms = shutdown_grace.as_millis(),
                    "listener did not stop within shutdown grace"
                );
            }
        }
    }

    let snapshot = stats.snapshot();
    tracing::info!(?snapshot, "echoic stopped");

    Ok(())
}

fn spawn_rate_limiter_cleanup(
    token: CancellationToken,
    limiters: Arc<ArcSwap<Vec<Arc<KeyedRateLimiter>>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RATE_LIMITER_CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = interval.tick() => {
                    let limiters = limiters.load();
                    for limiter in limiters.iter() {
                        limiter.retain_recent();
                    }
                }
            }
        }
    })
}

async fn reload_loop(
    ctx: Arc<ReloadContext>,
    mut watcher: Option<RecommendedWatcher>,
    mut watched: HashSet<PathBuf>,
    tx: mpsc::UnboundedSender<ReloadTrigger>,
    mut rx: mpsc::UnboundedReceiver<ReloadTrigger>,
) {
    let mut dirty = false;
    loop {
        if !dirty {
            match rx.recv().await {
                Some(_) => dirty = true,
                None => break,
            }
            continue;
        }

        tokio::select! {
            Some(trigger) = rx.recv() => {
                let watched_now = watched.clone();
                if matches!(trigger, ReloadTrigger::File(ref event) if is_watched_event(event, &watched_now))
                    || matches!(trigger, ReloadTrigger::Signal)
                {
                    dirty = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                dirty = false;
                if watcher.is_some() {
                    match reload_once(&ctx, tx.clone()).await {
                        Ok((new_watcher, new_watched)) => {
                            watcher = Some(new_watcher);
                            watched = new_watched;
                        }
                        Err(error) => {
                            tracing::error!(error = %error, "reload failed");
                        }
                    }
                }
            }
        }
    }
}

async fn reload_once(
    ctx: &ReloadContext,
    tx: mpsc::UnboundedSender<ReloadTrigger>,
) -> anyhow::Result<(RecommendedWatcher, HashSet<PathBuf>)> {
    let config_path = ctx
        .config_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no configuration path"))?;

    let current_config = ctx.config.load_full();
    let new_config = Config::load(config_path)?;
    let new_filter = build_filter(&new_config.logging)?;

    let recursor_settings_changed =
        recursor_signature(&current_config) != recursor_signature(&new_config);
    let cache_changed = current_config.cache != new_config.cache;
    let recursor_changed = recursor_settings_changed || cache_changed;

    let new_cache = if cache_changed {
        if new_config.cache.persistent || new_config.cache.serve_stale {
            Some(Arc::new(PersistentDnsCache::open(&new_config.cache).await))
        } else {
            None
        }
    } else {
        None
    };
    let new_cache_handle =
        cache_changed.then(|| Arc::new(ArcSwap::from_pointee(new_cache.as_ref().map(Arc::clone))));

    let new_resolver = if recursor_changed {
        let base = build_recursor(&new_config)?;
        let cache_handle = new_cache_handle
            .clone()
            .unwrap_or_else(|| ctx.cache_handle.clone());
        Some(Arc::new(CachedRecursiveResolver::new(base, cache_handle)))
    } else {
        None
    };

    let new_blocklist = RpzPolicy::load(
        &new_config.blocklist.rpz_paths,
        new_config.blocklist.rpz_origin.as_deref(),
    )?;

    let has_doh = new_config
        .listeners
        .iter()
        .any(|listener| listener.protocol == Protocol::Doh);
    let (landing_html, landing_css) = if has_doh {
        (
            new_config
                .landing_page
                .read_html()
                .with_context(|| "failed to read landing page HTML")?,
            new_config
                .landing_page
                .read_css()
                .with_context(|| "failed to read landing page CSS")?,
        )
    } else {
        (None, None)
    };

    let new_paths = watched_paths(&new_config, config_path);
    let (new_watcher, new_watched) = build_watcher(&new_paths, tx)?;

    let (updates, mut listener_changes) = {
        let old_runtimes = ctx.runtimes.lock().unwrap();
        let mut listener_changes = false;
        let mut updates = Vec::new();
        let mut tls_states: HashMap<(String, Protocol), Arc<TlsState>> = HashMap::new();

        for new_listener in &new_config.listeners {
            let old_runtime = old_runtimes.iter().find(|runtime| {
                runtime.name == new_listener.name
                    && runtime.protocol == new_listener.protocol
                    && runtime.address == new_listener.address
            });
            let Some(old_runtime) = old_runtime else {
                tracing::warn!(
                    listener = %new_listener.name,
                    "listener added or identity changed; restart required"
                );
                listener_changes = true;
                continue;
            };

            let old_listener = current_config.listeners.iter().find(|listener| {
                listener.name == new_listener.name
                    && listener.protocol == new_listener.protocol
                    && listener.address == new_listener.address
            });
            let old_limits =
                old_listener.map(|listener| listener.limits.effective(listener.protocol));
            let limits = new_listener.limits.effective(new_listener.protocol);

            let rate_limiter = select_rate_limiter(
                old_limits,
                Some(old_runtime.query_state.load().rate_limiter.clone()),
                &limits,
            );

            let state = ListenerQueryState {
                acl: Arc::new(new_listener.acl.clone()),
                rate_limiter,
                refuse_any: new_config.policy.refuse_any,
                max_udp_payload: new_config.server_limits.max_udp_payload,
                query_timeout: new_config.server_limits.query_timeout,
                idle_timeout: new_config.server_limits.idle_timeout,
                query_names: new_config.logging.query_names,
                require_dot_alpn: new_listener.require_dot_alpn,
                edns_padding_block_size: new_listener.edns_padding_block_size(),
                blocklist: new_blocklist.clone(),
            };

            let tls_state = if let Some(tls_name) = &new_listener.tls {
                let key = (tls_name.clone(), new_listener.protocol);
                if let Some(state) = tls_states.get(&key) {
                    Some(state.clone())
                } else {
                    let tls_config = new_config
                        .tls
                        .iter()
                        .find(|tls| tls.name == *tls_name)
                        .expect("validated tls");
                    let state = Arc::new(
                        TlsState::load(&tls_config.cert, &tls_config.key, new_listener.protocol)
                            .with_context(|| {
                                format!("listener {:?}: failed to load TLS", new_listener.name)
                            })?,
                    );
                    tls_states.insert(key, state.clone());
                    Some(state)
                }
            } else {
                None
            };

            let dot_max_connections = if new_listener.protocol == Protocol::Dot
                && old_limits.is_none_or(|old| old.max_connections != limits.max_connections)
            {
                let max_connections = limits.max_connections.unwrap_or(512) as usize;
                Some(Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(
                    max_connections,
                )))))
            } else {
                None
            };

            let doh_runtime = if new_listener.protocol == Protocol::Doh {
                let max_concurrent_requests =
                    limits.max_concurrent_requests.unwrap_or(128) as usize;
                let concurrency = old_runtime
                    .doh_runtime
                    .as_ref()
                    .map(|runtime| runtime.load_full())
                    .filter(|runtime| {
                        old_limits.is_some_and(|old| {
                            old.max_concurrent_requests == limits.max_concurrent_requests
                        }) && runtime.max_concurrent_requests == max_concurrent_requests
                    })
                    .map(|runtime| runtime.concurrency.clone())
                    .unwrap_or_else(|| Arc::new(Semaphore::new(max_concurrent_requests)));
                Some(Arc::new(ArcSwap::from_pointee(DohRuntimeState {
                    hostname: new_listener.hostname.clone().unwrap_or_default(),
                    max_concurrent_requests,
                    max_doh_body: new_config.server_limits.max_doh_body,
                    max_doh_uri: new_config.server_limits.max_doh_uri,
                    tcp_notsent_lowat: new_listener.tcp_notsent_lowat(),
                    concurrency,
                    landing_html: landing_html.clone(),
                    landing_css: landing_css.clone(),
                })))
            } else {
                None
            };

            let doh_max_connections = if new_listener.protocol == Protocol::Doh
                && old_limits.is_none_or(|old| old.max_connections != limits.max_connections)
            {
                let max_connections = limits.max_connections.unwrap_or(512) as usize;
                Some(Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(
                    max_connections,
                )))))
            } else {
                None
            };

            updates.push(ListenerUpdate {
                name: new_listener.name.clone(),
                protocol: new_listener.protocol,
                address: new_listener.address,
                query_state: Arc::new(state),
                tls_state,
                dot_max_connections,
                doh_runtime,
                doh_max_connections,
                dscp: new_listener.dscp,
            });
        }

        for old_listener in &current_config.listeners {
            let still_present = new_config.listeners.iter().any(|listener| {
                listener.name == old_listener.name
                    && listener.protocol == old_listener.protocol
                    && listener.address == old_listener.address
            });
            if !still_present {
                tracing::warn!(
                    listener = %old_listener.name,
                    "listener removed or identity changed; restart required"
                );
                listener_changes = true;
            }
        }

        (updates, listener_changes)
    };

    let new_inflight = if new_config.server_limits.max_inflight_queries
        != current_config.server_limits.max_inflight_queries
    {
        Some(Arc::new(Semaphore::new(
            new_config.server_limits.max_inflight_queries,
        )))
    } else {
        None
    };

    if let Some(handle) = &ctx.logging_reload {
        handle
            .reload(new_filter)
            .map_err(|error| anyhow::anyhow!("failed to reload logging: {error}"))?;
    }

    if cache_changed {
        if let Some(cache) = &new_cache
            && let Err(error) = cache.clear_async().await
        {
            tracing::warn!(error = %error, "failed to clear persistent cache");
        }
        ctx.cache_handle.store(Arc::new(new_cache));
    } else if recursor_settings_changed
        && let Some(cache) = ctx.cache_handle.load_full().as_ref().clone()
        && let Err(error) = cache.clear_async().await
    {
        tracing::warn!(error = %error, "failed to clear persistent cache");
    }

    if let Some(resolver) = new_resolver {
        ctx.resolver.store(resolver);
    }
    if let Some(inflight) = new_inflight {
        ctx.inflight.store(Arc::new(inflight));
    }

    ctx.config.store(Arc::new(new_config));

    let mut old_runtimes = ctx.runtimes.lock().unwrap();
    for update in &updates {
        if let Some(runtime) = old_runtimes.iter_mut().find(|runtime| {
            runtime.name == update.name
                && runtime.protocol == update.protocol
                && runtime.address == update.address
        }) {
            runtime.query_state.store(update.query_state.clone());
            runtime.tls_state.store(Arc::new(update.tls_state.clone()));
            if runtime.observe_dscp(update.dscp) {
                tracing::warn!(listener = %update.name, "listener dscp changed; restart required");
                listener_changes = true;
            }
            if let Some(max_connections) = &update.dot_max_connections
                && let Some(existing) = &runtime.dot_max_connections
            {
                existing.store(max_connections.load().clone());
            }
            if let Some(doh_runtime) = &update.doh_runtime
                && let Some(existing) = &runtime.doh_runtime
            {
                existing.store(doh_runtime.load_full());
            }
            if let Some(max_connections) = &update.doh_max_connections
                && let Some(existing) = &runtime.doh_max_connections
            {
                existing.store(max_connections.load().clone());
            }
        }
    }
    let new_limiters: Vec<_> = old_runtimes
        .iter()
        .map(|runtime| runtime.query_state.load().rate_limiter.clone())
        .collect();
    drop(old_runtimes);
    ctx.limiters.store(Arc::new(new_limiters));

    if listener_changes {
        tracing::warn!("listener changes require a restart");
    }
    tracing::info!("configuration reloaded");
    Ok((new_watcher, new_watched))
}

fn select_rate_limiter(
    old_limits: Option<EffectiveListenerLimits>,
    old_limiter: Option<Arc<KeyedRateLimiter>>,
    new_limits: &EffectiveListenerLimits,
) -> Arc<KeyedRateLimiter> {
    if let (Some(old_limits), Some(old_limiter)) = (old_limits, old_limiter)
        && old_limits.qps == new_limits.qps
        && old_limits.burst == new_limits.burst
    {
        return old_limiter;
    }
    Arc::new(keyed_limiter(new_limits.qps, new_limits.burst))
}

pub fn build_filter(logging: &crate::config::LoggingConfig) -> anyhow::Result<EnvFilter> {
    let mut directives = vec![logging.level.clone()];
    if logging.level != "off" {
        let hickory_level = if logging.query_names { "info" } else { "warn" };
        for target in ["hickory_server", "hickory_proto", "hickory_net"] {
            directives.push(format!("{target}={hickory_level}"));
        }
        let resolver_level = if logging.query_names { "info" } else { "error" };
        directives.push(format!("hickory_resolver={resolver_level}"));
    }

    EnvFilter::try_new(directives.join(","))
        .map_err(|error| anyhow::anyhow!("failed to build logging filter: {error}"))
}

fn recursor_signature(config: &Config) -> String {
    let root_bytes = config
        .recursor
        .root_hints
        .as_ref()
        .map(|path| fs::read(path).unwrap_or_default());
    let trust_bytes = config
        .dnssec
        .trust_anchor
        .as_ref()
        .map(|path| fs::read(path).unwrap_or_default());

    format!(
        "{:?}{:?}{:?}{:?}",
        config.recursor, config.dnssec, root_bytes, trust_bytes
    )
}

fn watched_paths(config: &Config, config_path: &Path) -> HashSet<PathBuf> {
    let mut paths = HashSet::new();
    paths.insert(config_path.to_path_buf());
    for tls in &config.tls {
        paths.insert(tls.cert.clone());
        paths.insert(tls.key.clone());
    }
    if let Some(path) = &config.recursor.root_hints {
        paths.insert(path.clone());
    }
    if let Some(path) = &config.dnssec.trust_anchor {
        paths.insert(path.clone());
    }
    for path in &config.blocklist.rpz_paths {
        paths.insert(path.clone());
    }
    paths
}

fn build_watcher(
    paths: &HashSet<PathBuf>,
    tx: mpsc::UnboundedSender<ReloadTrigger>,
) -> anyhow::Result<(RecommendedWatcher, HashSet<PathBuf>)> {
    let watched = paths.clone();
    let watched_for_callback = watched.clone();
    let mut watcher = RecommendedWatcher::new(
        move |result: notify::Result<Event>| {
            if let Ok(event) = result
                && is_reload_event(&event)
                && event
                    .paths
                    .iter()
                    .any(|path| watched_for_callback.contains(path))
            {
                let _ = tx.send(ReloadTrigger::File(event));
            }
        },
        NotifyConfig::default(),
    )?;

    let mut parents = HashSet::new();
    for path in paths {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        parents.insert(parent);
    }
    for parent in parents {
        watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    }

    Ok((watcher, watched))
}

fn is_watched_event(event: &Event, watched: &HashSet<PathBuf>) -> bool {
    is_reload_event(event) && event.paths.iter().any(|path| watched.contains(path))
}

fn is_reload_event(event: &Event) -> bool {
    use notify::EventKind;
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    )
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use arc_swap::ArcSwap;
    use hickory_server::proto::op::Message;
    use hickory_server::proto::rr::{DNSClass, Name, RecordType};
    use tempfile::tempdir;
    use tokio::sync::Semaphore;

    use crate::persistent_cache::{CacheKey, PersistentDnsCache};

    #[tokio::test]
    async fn reload_rebuilds_recursor_and_clears_persistent_cache() {
        let directory = tempdir().expect("temporary directory");
        let config_path = directory.path().join("echoic.toml");
        let cache_path = directory.path().join("cache.json");

        let initial = format!(
            r#"
[logging]
level = "off"

[dnssec]
enabled = true
validate = false

[cache]
persistent = true
path = "{}"
max_entries = 100
flush_interval = "1h"
max_ttl = "1h"
stale_ttl = "1h"

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
            cache_path.display()
        );
        std::fs::write(&config_path, &initial).expect("write configuration");
        let config = Config::load(&config_path).expect("load configuration");

        let cache_handle = Arc::new(ArcSwap::from_pointee(Some(Arc::new(
            PersistentDnsCache::new(&config.cache),
        ))));
        let base = build_recursor(&config).expect("build recursor");
        let resolver = RecursorHandle::new(Arc::new(CachedRecursiveResolver::new(
            base,
            cache_handle.clone(),
        )));
        assert!(!resolver.is_validating());

        let loaded = cache_handle.load_full();
        let cache = loaded.as_ref().as_ref().expect("cache");
        let key = CacheKey {
            name: Name::from_ascii("example.com.").expect("name"),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        cache.insert(key.clone(), Message::query(), SystemTime::now());
        cache.flush().expect("flush cache");
        assert!(cache.get(&key, SystemTime::now()).is_some());

        let inflight = Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(1))));
        let runtimes = Arc::new(Mutex::new(Vec::new()));
        let limiters = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let ctx = ReloadContext {
            config: Arc::new(ArcSwap::from_pointee(config.clone())),
            config_path: Some(config_path.clone()),
            resolver: resolver.clone(),
            cache_handle: cache_handle.clone(),
            inflight: inflight.clone(),
            runtimes: runtimes.clone(),
            logging_reload: None,
            limiters: limiters.clone(),
        };

        let updated = initial.replace("validate = false", "validate = true");
        std::fs::write(&config_path, updated).expect("write configuration");

        reload_once(&ctx, tx).await.expect("reload");

        assert!(resolver.is_validating());
        let reloaded_loaded = cache_handle.load_full();
        let reloaded_cache = reloaded_loaded.as_ref().as_ref().expect("cache");
        assert!(reloaded_cache.get(&key, SystemTime::now()).is_none());
        assert!(!cache_path.exists());
    }

    #[tokio::test]
    async fn failed_reload_preserves_old_state() {
        let directory = tempdir().expect("temporary directory");
        let config_path = directory.path().join("echoic.toml");
        let cache_path = directory.path().join("cache.json");
        let rpz_path = directory.path().join("missing.rpz");

        let initial = format!(
            r#"
[logging]
level = "off"

[dnssec]
enabled = true
validate = false

[cache]
persistent = true
path = "{}"
max_entries = 100
flush_interval = "1h"
max_ttl = "1h"
stale_ttl = "1h"

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
            cache_path.display()
        );
        std::fs::write(&config_path, &initial).expect("write configuration");
        let config = Config::load(&config_path).expect("load configuration");

        let cache_handle = Arc::new(ArcSwap::from_pointee(Some(Arc::new(
            PersistentDnsCache::new(&config.cache),
        ))));
        let base = build_recursor(&config).expect("build recursor");
        let resolver = RecursorHandle::new(Arc::new(CachedRecursiveResolver::new(
            base,
            cache_handle.clone(),
        )));
        let key = CacheKey {
            name: Name::from_ascii("example.com.").expect("name"),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        {
            let loaded = cache_handle.load_full();
            let cache = loaded.as_ref().as_ref().expect("cache");
            cache.insert(key.clone(), Message::query(), SystemTime::now());
            cache.flush().expect("flush cache");
        }

        let inflight = Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(1))));
        let runtimes = Arc::new(Mutex::new(Vec::new()));
        let limiters = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let ctx = ReloadContext {
            config: Arc::new(ArcSwap::from_pointee(config.clone())),
            config_path: Some(config_path.clone()),
            resolver: resolver.clone(),
            cache_handle: cache_handle.clone(),
            inflight: inflight.clone(),
            runtimes: runtimes.clone(),
            logging_reload: None,
            limiters: limiters.clone(),
        };

        let updated = format!(
            r#"
[logging]
level = "off"

[dnssec]
enabled = true
validate = true

[cache]
persistent = true
path = "{}"
max_entries = 101
flush_interval = "1h"
max_ttl = "1h"
stale_ttl = "1h"

[blocklist]
rpz_paths = ["{}"]

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
            cache_path.display(),
            rpz_path.display()
        );
        std::fs::write(&config_path, updated).expect("write configuration");

        let before_cache = cache_handle.load_full();
        let error = reload_once(&ctx, tx).await.expect_err("reload must fail");
        let _ = error;
        assert!(!resolver.is_validating());
        assert!(!ctx.config.load().dnssec.validate);
        assert!(Arc::ptr_eq(&before_cache, &cache_handle.load_full()));
        let loaded = cache_handle.load_full();
        let cache = loaded.as_ref().as_ref().expect("cache");
        assert!(cache.get(&key, SystemTime::now()).is_some());
        assert!(cache_path.exists());
    }

    #[tokio::test]
    async fn disabling_cache_replaces_the_cache_handle() {
        let directory = tempdir().expect("temporary directory");
        let config_path = directory.path().join("echoic.toml");
        let cache_path = directory.path().join("cache.json");

        let initial = format!(
            r#"
[logging]
level = "off"

[dnssec]
enabled = true
validate = false

[cache]
persistent = true
path = "{}"
max_entries = 100
flush_interval = "1h"
max_ttl = "1h"
stale_ttl = "1h"

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
            cache_path.display()
        );
        std::fs::write(&config_path, &initial).expect("write configuration");
        let config = Config::load(&config_path).expect("load configuration");

        let cache_handle = Arc::new(ArcSwap::from_pointee(Some(Arc::new(
            PersistentDnsCache::new(&config.cache),
        ))));
        let base = build_recursor(&config).expect("build recursor");
        let resolver = RecursorHandle::new(Arc::new(CachedRecursiveResolver::new(
            base,
            cache_handle.clone(),
        )));
        let inflight = Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(1))));
        let runtimes = Arc::new(Mutex::new(Vec::new()));
        let limiters = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let ctx = ReloadContext {
            config: Arc::new(ArcSwap::from_pointee(config)),
            config_path: Some(config_path.clone()),
            resolver: resolver.clone(),
            cache_handle: cache_handle.clone(),
            inflight,
            runtimes,
            logging_reload: None,
            limiters,
        };
        assert!(cache_handle.load().is_some());

        let updated = r#"
[logging]
level = "off"

[dnssec]
enabled = true
validate = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#;
        std::fs::write(&config_path, updated).expect("write configuration");

        reload_once(&ctx, tx).await.expect("reload");

        assert!(ctx.cache_handle.load().is_none());
    }

    #[test]
    fn logging_filter_matches_startup_policy() {
        let mut logging = crate::config::LoggingConfig {
            level: "info".to_owned(),
            query_names: false,
        };
        let filter = build_filter(&logging).expect("filter");
        let rendered = filter.to_string();
        assert!(rendered.contains("hickory_resolver=error"), "{rendered}");
        assert!(rendered.contains("hickory_server=warn"), "{rendered}");

        logging.query_names = true;
        let filter = build_filter(&logging).expect("filter");
        let rendered = filter.to_string();
        assert!(rendered.contains("hickory_resolver=info"), "{rendered}");
        assert!(rendered.contains("hickory_server=info"), "{rendered}");
    }

    #[test]
    fn unchanged_limits_reuse_rate_limiter() {
        let old_limits =
            crate::config::ListenerLimits::default().effective(crate::config::Protocol::Udp);
        let limiter = Arc::new(keyed_limiter(old_limits.qps, old_limits.burst));
        let reused = select_rate_limiter(Some(old_limits), Some(limiter.clone()), &old_limits);
        assert!(Arc::ptr_eq(&limiter, &reused));

        let changed = crate::config::EffectiveListenerLimits {
            qps: old_limits.qps + 1,
            ..old_limits
        };
        let replaced = select_rate_limiter(Some(old_limits), Some(limiter.clone()), &changed);
        assert!(!Arc::ptr_eq(&limiter, &replaced));
    }
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("failed to wait for interrupt signal")?;
            }
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to wait for interrupt signal")?;
    }

    Ok(())
}
