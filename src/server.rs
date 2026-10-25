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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Protocol};
use crate::doh::start_doh_listener;
use crate::dot::start_dot_listener;
use crate::listeners::{ListenerRuntime, start_listener};
use crate::query::QueryService;
use crate::rate_limit::KeyedRateLimiter;
use crate::recursor::build_recursor;
use crate::stats::Stats;
use crate::tls::TlsState;

const RATE_LIMITER_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub async fn run(config: Config) -> anyhow::Result<()> {
    install_ring_provider();

    let resolver = build_recursor(&config)?;
    let stats = Arc::new(Stats::default());
    let inflight = Arc::new(Semaphore::new(config.server_limits.max_inflight_queries));

    let ready = Arc::new(AtomicBool::new(false));
    let mut runtimes: Vec<ListenerRuntime> = Vec::new();
    for listener in &config.listeners {
        let service = QueryService::new(
            resolver.clone(),
            listener,
            stats.clone(),
            inflight.clone(),
            &config.server_limits,
            config.policy.refuse_any,
            config.logging.query_names,
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
            match start_dot_listener(
                listener,
                service,
                std::sync::Arc::new(tls_state),
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
            let max_concurrent_requests = listener
                .limits
                .effective(listener.protocol)
                .max_concurrent_requests
                .unwrap_or(128) as usize;
            match start_doh_listener(
                listener,
                service,
                std::sync::Arc::new(tls_state),
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

    let limiters = runtimes
        .iter()
        .map(|runtime| runtime.rate_limiter.clone())
        .collect::<Vec<_>>();
    let cleanup_token = CancellationToken::new();
    spawn_rate_limiter_cleanup(cleanup_token.clone(), limiters);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listeners = runtimes.len(),
        "echoic started"
    );

    ready.store(true, Ordering::Relaxed);

    shutdown_signal().await?;
    tracing::info!("shutdown requested");
    cleanup_token.cancel();

    for runtime in &runtimes {
        runtime.token.cancel();
    }

    let deadline = tokio::time::Instant::now() + config.server_limits.shutdown_grace;
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
                    grace_ms = config.server_limits.shutdown_grace.as_millis(),
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
    limiters: Vec<Arc<KeyedRateLimiter>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RATE_LIMITER_CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = interval.tick() => {
                    for limiter in &limiters {
                        limiter.retain_recent();
                    }
                }
            }
        }
    })
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
