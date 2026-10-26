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

use crate::config::{Config, Protocol};
use crate::doh::{DohRuntimeState, start_doh_listener};
use crate::dot::start_dot_listener;
use crate::listeners::{ListenerRuntime, start_listener};
use crate::persistent_cache::PersistentDnsCache;
use crate::query::{ListenerQueryState, QueryService};
use crate::rate_limit::{KeyedRateLimiter, keyed_limiter};
use crate::recursor::{CachedRecursiveResolver, RecursorHandle, build_recursor};
use crate::rpz::RpzPolicy;
use crate::stats::Stats;
use crate::tls::TlsState;

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
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    run_with_logging(config, None, None).await
}

pub async fn run_with_logging(
    config: Config,
    config_path: Option<PathBuf>,
    logging_reload: Option<ReloadHandle>,
) -> anyhow::Result<()> {
    install_ring_provider();

    let config_store = Arc::new(ArcSwap::from_pointee(config.clone()));
    let cache_handle = Arc::new(ArcSwap::from_pointee(
        if config.cache.persistent || config.cache.serve_stale {
            Some(Arc::new(PersistentDnsCache::new(&config.cache)))
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
    let stats = Arc::new(Stats::default());
    metrics::set_global_recorder(crate::metrics::EchoicMetricsRecorder::new(stats.clone()))
        .map_err(|error| anyhow::anyhow!("failed to install metrics recorder: {error}"))?;
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
            resolver_handle.current(),
            listener,
            stats.clone(),
            inflight_store.clone(),
            &config.server_limits,
            config.policy.refuse_any,
            config.logging.query_names,
            config.policy.edns_client_subnet_v4_prefix,
            config.policy.edns_client_subnet_v6_prefix,
            blocklist.clone(),
        );

        let runtime = if listener.protocol == Protocol::Dot {
            let tls_name = listener.tls.as_deref().expect("validated tls");
            let tls_config = config
                .tls
                .iter()
                .find(|tls| tls.name == tls_name)
                .expect("validated tls");
            let tls_state = TlsState::load(&tls_config.cert, &tls_config.key)
                .with_context(|| format!("listener {:?}: failed to load TLS", listener.name))?;
            let tls_state = Arc::new(tls_state);
            match start_dot_listener(
                listener,
                service,
                tls_state.clone(),
                config.server_limits.query_timeout,
                config.server_limits.idle_timeout,
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
            let tls_state = TlsState::load_doh(&tls_config.cert, &tls_config.key)
                .with_context(|| format!("listener {:?}: failed to load TLS", listener.name))?;
            let tls_state = Arc::new(tls_state);
            let max_concurrent_requests = listener
                .limits
                .effective(listener.protocol)
                .max_concurrent_requests
                .unwrap_or(128) as usize;
            match start_doh_listener(
                listener,
                service,
                tls_state.clone(),
                max_concurrent_requests,
                config.server_limits.max_doh_body,
                config.server_limits.max_doh_uri,
                listener.hostname.clone().expect("validated hostname"),
                ready.clone(),
                config.server_limits.query_timeout,
                config.server_limits.query_timeout,
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
                if let Some(cache) = cache_handle.load_full().as_deref() {
                    cache.flush();
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
    if let Some(cache) = cache_handle.load_full().as_deref() {
        cache.flush();
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

fn install_ring_provider() {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider was already installed");
    }
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
    let new_filter = build_filter(&new_config)?;

    let recursor_settings_changed =
        recursor_signature(&current_config) != recursor_signature(&new_config);
    let cache_changed = current_config.cache != new_config.cache;
    let recursor_changed = recursor_settings_changed || cache_changed;

    if (cache_changed || recursor_settings_changed)
        && let Some(cache) = ctx.cache_handle.load_full().as_deref()
    {
        cache.clear();
    }

    if cache_changed {
        let new_cache = if new_config.cache.persistent || new_config.cache.serve_stale {
            Some(Arc::new(PersistentDnsCache::new(&new_config.cache)))
        } else {
            None
        };
        ctx.cache_handle.store(Arc::new(new_cache));
    }

    let new_resolver = if recursor_changed {
        let base = build_recursor(&new_config)?;
        Some(Arc::new(CachedRecursiveResolver::new(
            base,
            ctx.cache_handle.clone(),
        )))
    } else {
        None
    };

    let new_blocklist = RpzPolicy::load(
        &new_config.blocklist.rpz_paths,
        new_config.blocklist.rpz_origin.as_deref(),
    )?;

    let mut new_tls_states = HashMap::new();
    for tls in &new_config.tls {
        new_tls_states.insert(
            tls.name.clone(),
            Arc::new(TlsState::load_with_alpn(
                &tls.cert,
                &tls.key,
                vec![b"dot".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()],
            )?),
        );
    }

    let old_listeners = current_config.listeners.clone();
    let old_runtimes = ctx.runtimes.lock().unwrap();
    let mut listener_changes = false;
    let mut updates = Vec::new();

    for new_listener in &new_config.listeners {
        let old_runtime = old_runtimes.iter().find(|runtime| {
            runtime.name == new_listener.name
                && runtime.protocol == new_listener.protocol
                && runtime.address == new_listener.address
        });

        if old_runtime.is_none() {
            tracing::warn!(
                listener = %new_listener.name,
                "listener added or identity changed; restart required"
            );
            listener_changes = true;
            continue;
        }

        let limits = new_listener.limits.effective(new_listener.protocol);
        let rate_limiter = keyed_limiter(limits.qps, limits.burst);
        let state = ListenerQueryState {
            acl: Arc::new(new_listener.acl.clone()),
            rate_limiter: Arc::new(rate_limiter),
            refuse_any: new_config.policy.refuse_any,
            max_udp_payload: new_config.server_limits.max_udp_payload,
            query_timeout: new_config.server_limits.query_timeout,
            idle_timeout: new_config.server_limits.idle_timeout,
            query_names: new_config.logging.query_names,
            edns_padding_block_size: new_listener.edns_padding_block_size(),
            client_subnet_v4_prefix: new_config.policy.edns_client_subnet_v4_prefix,
            client_subnet_v6_prefix: new_config.policy.edns_client_subnet_v6_prefix,
            blocklist: new_blocklist.clone(),
        };
        let query_state = Arc::new(state);

        let tls_state = new_listener
            .tls
            .as_ref()
            .and_then(|name| new_tls_states.get(name).cloned());

        let dot_max_connections = if new_listener.protocol == Protocol::Dot {
            let max_connections = limits.max_connections.unwrap_or(512) as usize;
            Some(Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(
                max_connections,
            )))))
        } else {
            None
        };

        let doh_runtime = if new_listener.protocol == Protocol::Doh {
            let max_concurrent_requests = limits.max_concurrent_requests.unwrap_or(128) as usize;
            Some(Arc::new(ArcSwap::from_pointee(DohRuntimeState {
                hostname: new_listener.hostname.clone().unwrap_or_default(),
                max_concurrent_requests,
                max_doh_body: new_config.server_limits.max_doh_body,
                max_doh_uri: new_config.server_limits.max_doh_uri,
                concurrency: Arc::new(Semaphore::new(max_concurrent_requests)),
            })))
        } else {
            None
        };

        let doh_max_connections = if new_listener.protocol == Protocol::Doh {
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
            query_state,
            tls_state,
            dot_max_connections,
            doh_runtime,
            doh_max_connections,
        });
    }

    for old_listener in &old_listeners {
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

    let new_paths = watched_paths(
        &new_config,
        ctx.config_path.as_ref().expect("configuration path"),
    );
    let (new_watcher, new_watched) = build_watcher(&new_paths, tx.clone())?;

    ctx.config.store(Arc::new(new_config.clone()));
    if let Some(resolver) = new_resolver {
        ctx.resolver.store(resolver);
    }
    if let Some(inflight) = new_inflight {
        ctx.inflight.store(Arc::new(inflight));
    }
    drop(old_runtimes);
    let mut old_runtimes = ctx.runtimes.lock().unwrap();
    for update in &updates {
        if let Some(runtime) = old_runtimes.iter_mut().find(|runtime| {
            runtime.name == update.name
                && runtime.protocol == update.protocol
                && runtime.address == update.address
        }) {
            runtime.query_state.store(update.query_state.clone());
            runtime.tls_state.store(Arc::new(update.tls_state.clone()));
            if let Some(max_connections) = &update.dot_max_connections {
                if let Some(existing) = &runtime.dot_max_connections {
                    existing.store(max_connections.load().clone());
                } else {
                    runtime.dot_max_connections = Some(max_connections.clone());
                }
            }
            if let Some(doh_runtime) = &update.doh_runtime {
                if let Some(existing) = &runtime.doh_runtime {
                    existing.store(doh_runtime.load().clone());
                } else {
                    runtime.doh_runtime = Some(doh_runtime.clone());
                }
            }
            if let Some(max_connections) = &update.doh_max_connections {
                if let Some(existing) = &runtime.doh_max_connections {
                    existing.store(max_connections.load().clone());
                } else {
                    runtime.doh_max_connections = Some(max_connections.clone());
                }
            }
        }
    }
    drop(old_runtimes);

    let new_limiters: Vec<_> = ctx
        .runtimes
        .lock()
        .unwrap()
        .iter()
        .map(|runtime| runtime.query_state.load().rate_limiter.clone())
        .collect();
    ctx.limiters.store(Arc::new(new_limiters));

    if listener_changes {
        tracing::warn!("listener changes require a restart");
    }
    tracing::info!("configuration reloaded");
    Ok((new_watcher, new_watched))
}

fn build_filter(config: &Config) -> anyhow::Result<EnvFilter> {
    let mut directives = vec![config.logging.level.clone()];
    if config.logging.level != "off" {
        let hickory_level = if config.logging.query_names {
            "info"
        } else {
            "warn"
        };
        for target in [
            "hickory_server",
            "hickory_resolver",
            "hickory_proto",
            "hickory_net",
        ] {
            directives.push(format!("{target}={hickory_level}"));
        }
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
