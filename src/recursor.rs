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
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use std::time::Instant;

use anyhow::{Context, bail};
use async_trait::async_trait;
use hickory_server::net::runtime::TokioRuntimeProvider;
use hickory_server::proto::dnssec::TrustAnchors;
use hickory_server::proto::op::{Message, Query};
use hickory_server::proto::rr::{Name, RData, RecordSet};
use hickory_server::proto::serialize::txt::Parser;
use hickory_server::resolver::ConnectionProvider;
use hickory_server::resolver::recursor::{
    DnssecConfig as HickoryDnssecConfig, DnssecPolicy, QNameMinimization, Recursor, RecursorError,
    RecursorOptions,
};

use crate::config::{Config, QNameMinimization as ConfigQNameMinimization};

const EMBEDDED_ROOT_HINTS: &str = include_str!("../assets/root.hints");
const EMBEDDED_ROOT_HINTS_NAME: &str = "assets/root.hints";

#[async_trait]
pub trait RecursiveResolver: Send + Sync {
    async fn resolve(&self, query: Query, dnssec_ok: bool) -> Result<Message, RecursorError>;

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

pub fn build_recursor(config: &Config) -> anyhow::Result<Arc<dyn RecursiveResolver>> {
    build_recursor_with_provider(config, TokioRuntimeProvider::new())
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

    let dnssec_policy = if config.dnssec.enabled {
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
    } else {
        tracing::warn!("DNSSEC validation is disabled");
        DnssecPolicy::SecurityUnaware
    };

    let recursor = Recursor::new(&roots, dnssec_policy, None, options, provider)
        .map_err(|error| anyhow::anyhow!("failed to build recursor: {error}"))?;

    if config.dnssec.enabled && !recursor.is_validating() {
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
}
