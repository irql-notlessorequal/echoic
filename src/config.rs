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
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use tracing_subscriber::filter::LevelFilter;

use crate::error::ConfigError;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/echoic/echoic.toml";

const DEFAULT_MAX_CONNECTIONS: u32 = 512;
const DEFAULT_MAX_DOH_CONCURRENT_REQUESTS: u32 = 128;
const DEFAULT_ENCRYPTED_QPS: u32 = 50;
const DEFAULT_ENCRYPTED_BURST: u32 = 100;
const DEFAULT_PLAIN_QPS: u32 = 100;
const DEFAULT_PLAIN_BURST: u32 = 200;
const DEFAULT_RESPONSE_CACHE_SIZE: u64 = 1_048_576;
const DEFAULT_NS_CACHE_SIZE: usize = 1_024;
const DEFAULT_RECURSION_LIMIT: u8 = 24;
const DEFAULT_EDNS_PAYLOAD_LEN: u16 = 1232;
const DEFAULT_MAX_UDP_PAYLOAD: u16 = 1232;
const DEFAULT_MAX_DOH_BODY: usize = 65_535;
const DEFAULT_MAX_DOH_URI: usize = 8_192;
const DEFAULT_MAX_INFLIGHT_QUERIES: usize = 2_048;
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

const PRIVATE_NETWORKS: &[&str] = &[
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub tls: Vec<TlsConfig>,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub recursor: RecursorConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
    #[serde(default)]
    pub server_limits: ServerLimits,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config = Self::parse(&contents, path)?;
        let base = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        config.resolve_paths(base);
        config.validate()?;
        Ok(config)
    }

    pub fn from_toml_str(contents: &str) -> Result<Self, ConfigError> {
        let mut config = Self::parse(contents, Path::new("<inline>"))?;
        config.resolve_paths(Path::new("."));
        config.validate()?;
        Ok(config)
    }

    fn parse(contents: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    fn resolve_paths(&mut self, base: &Path) {
        for tls in &mut self.tls {
            tls.cert = resolve_path(base, &tls.cert);
            tls.key = resolve_path(base, &tls.key);
        }
        if let Some(path) = &mut self.recursor.root_hints {
            *path = resolve_path(base, path);
        }
        if let Some(path) = &mut self.dnssec.trust_anchor {
            *path = resolve_path(base, path);
        }
        for path in &mut self.blocklist.rpz_paths {
            *path = resolve_path(base, path);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        if self.listeners.is_empty() {
            errors.push("at least one listener is required".to_owned());
        }

        self.validate_tls(&mut errors);
        self.validate_listeners(&mut errors);
        self.validate_logging(&mut errors);
        self.validate_recursor(&mut errors);
        self.validate_dnssec(&mut errors);
        self.validate_server_limits(&mut errors);
        self.validate_policy(&mut errors);
        self.validate_blocklist(&mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation(errors.join("\n")))
        }
    }

    fn validate_tls(&self, errors: &mut Vec<String>) {
        let mut names = HashSet::new();
        for tls in &self.tls {
            if tls.name.is_empty() {
                errors.push("tls entry name must not be empty".to_owned());
            }
            if !names.insert(tls.name.as_str()) {
                errors.push(format!("duplicate TLS entry name {:?}", tls.name));
            }
            if tls.cert.as_os_str().is_empty() {
                errors.push(format!(
                    "tls entry {:?}: cert path must not be empty",
                    tls.name
                ));
            }
            if tls.key.as_os_str().is_empty() {
                errors.push(format!(
                    "tls entry {:?}: key path must not be empty",
                    tls.name
                ));
            }
        }
    }

    fn validate_listeners(&self, errors: &mut Vec<String>) {
        let mut names = HashSet::new();
        let mut endpoints = HashSet::new();

        for listener in &self.listeners {
            if listener.name.is_empty() {
                errors.push("listener name must not be empty".to_owned());
            }
            if !names.insert(listener.name.as_str()) {
                errors.push(format!("duplicate listener name {:?}", listener.name));
            }
            if !endpoints.insert((listener.protocol, listener.address)) {
                errors.push(format!(
                    "duplicate listener endpoint {} {}",
                    listener.protocol.as_str(),
                    listener.address
                ));
            }

            if let Some(tls_name) = &listener.tls
                && !self.tls.iter().any(|tls| tls.name == *tls_name)
            {
                errors.push(format!(
                    "listener {:?}: TLS entry {:?} does not exist",
                    listener.name, tls_name
                ));
            }

            match listener.protocol {
                Protocol::Udp => {
                    if listener.tls.is_some() {
                        errors.push(format!(
                            "listener {:?}: udp listeners must not set tls",
                            listener.name
                        ));
                    }
                    if listener.hostname.is_some() {
                        errors.push(format!(
                            "listener {:?}: udp listeners must not set hostname",
                            listener.name
                        ));
                    }
                    if listener.limits.max_connections.is_some() {
                        errors.push(format!(
                            "listener {:?}: udp listeners must not set limits.max_connections",
                            listener.name
                        ));
                    }
                    if listener.limits.max_concurrent_requests.is_some() {
                        errors.push(format!(
                            "listener {:?}: udp listeners must not set limits.max_concurrent_requests",
                            listener.name
                        ));
                    }
                }
                Protocol::Tcp => {
                    if listener.tls.is_some() {
                        errors.push(format!(
                            "listener {:?}: tcp listeners must not set tls",
                            listener.name
                        ));
                    }
                    if listener.hostname.is_some() {
                        errors.push(format!(
                            "listener {:?}: tcp listeners must not set hostname",
                            listener.name
                        ));
                    }
                    if listener.limits.max_concurrent_requests.is_some() {
                        errors.push(format!(
                            "listener {:?}: tcp listeners must not set limits.max_concurrent_requests",
                            listener.name
                        ));
                    }
                }
                Protocol::Dot => {
                    if listener.tls.is_none() {
                        errors.push(format!(
                            "listener {:?}: dot listeners require tls",
                            listener.name
                        ));
                    }
                    if listener.hostname.is_some() {
                        errors.push(format!(
                            "listener {:?}: dot listeners must not set hostname",
                            listener.name
                        ));
                    }
                    if listener.limits.max_concurrent_requests.is_some() {
                        errors.push(format!(
                            "listener {:?}: dot listeners must not set limits.max_concurrent_requests",
                            listener.name
                        ));
                    }
                }
                Protocol::Doh => {
                    if listener.tls.is_none() {
                        errors.push(format!(
                            "listener {:?}: doh listeners require tls",
                            listener.name
                        ));
                    }
                    match &listener.hostname {
                        Some(hostname) => {
                            if !is_valid_hostname(hostname) {
                                errors.push(format!(
                                    "listener {:?}: hostname {:?} is not a valid DNS name",
                                    listener.name, hostname
                                ));
                            }
                        }
                        None => errors.push(format!(
                            "listener {:?}: doh listeners require hostname",
                            listener.name
                        )),
                    }
                }
            }

            validate_listener_limits(listener, errors);
            if let Some(value) = listener.edns_padding_block_size
                && value != 0
                && !(16..=4096).contains(&value)
            {
                errors.push(format!(
                    "listener {:?}: edns_padding_block_size must be 0 or between 16 and 4096",
                    listener.name
                ));
            }
        }
    }

    fn validate_logging(&self, errors: &mut Vec<String>) {
        if parse_level(&self.logging.level).is_none() {
            errors.push(format!(
                "logging.level {:?} must be one of off, error, warn, info, debug, trace",
                self.logging.level
            ));
        }
    }

    fn validate_recursor(&self, errors: &mut Vec<String>) {
        if self.recursor.response_cache_size == 0 {
            errors.push("recursor.response_cache_size must be greater than zero".to_owned());
        }
        if self.recursor.ns_cache_size == 0 {
            errors.push("recursor.ns_cache_size must be greater than zero".to_owned());
        }
        if self.recursor.recursion_limit == 0 {
            errors.push("recursor.recursion_limit must be greater than zero".to_owned());
        }
        if self.recursor.ns_recursion_limit == 0 {
            errors.push("recursor.ns_recursion_limit must be greater than zero".to_owned());
        }
        if self.recursor.ns_recursion_limit == 0 {
            errors.push("recursor.ns_recursion_limit must be greater than zero".to_owned());
        }
        if !(512..=4096).contains(&self.recursor.edns_payload_len) {
            errors.push("recursor.edns_payload_len must be between 512 and 4096".to_owned());
        }
        if let Some(path) = &self.recursor.root_hints
            && path.as_os_str().is_empty()
        {
            errors.push("recursor.root_hints must not be empty".to_owned());
        }
    }

    fn validate_dnssec(&self, errors: &mut Vec<String>) {
        if let Some(path) = &self.dnssec.trust_anchor
            && path.as_os_str().is_empty()
        {
            errors.push("dnssec.trust_anchor must not be empty".to_owned());
        }
        if let Some(size) = self.dnssec.validation_cache_size
            && size == 0
        {
            errors.push("dnssec.validation_cache_size must be greater than zero".to_owned());
        }
        if let (Some(soft), Some(hard)) = (
            self.dnssec.nsec3_soft_iteration_limit,
            self.dnssec.nsec3_hard_iteration_limit,
        ) && soft > hard
        {
            errors.push(
                "dnssec.nsec3_soft_iteration_limit must not exceed nsec3_hard_iteration_limit"
                    .to_owned(),
            );
        }
    }

    fn validate_policy(&self, errors: &mut Vec<String>) {
        if let Some(prefix) = self.policy.edns_client_subnet_v4_prefix
            && !(1..=32).contains(&prefix)
        {
            errors.push("policy.edns_client_subnet_v4_prefix must be between 1 and 32".to_owned());
        }
        if let Some(prefix) = self.policy.edns_client_subnet_v6_prefix
            && !(1..=128).contains(&prefix)
        {
            errors.push("policy.edns_client_subnet_v6_prefix must be between 1 and 128".to_owned());
        }
    }

    fn validate_blocklist(&self, errors: &mut Vec<String>) {
        if let Some(origin) = &self.blocklist.rpz_origin
            && origin
                .parse::<hickory_server::proto::rr::Name>()
                .map(|name| !name.is_fqdn())
                .unwrap_or(true)
        {
            errors.push("blocklist.rpz_origin must be a fully qualified domain name".to_owned());
        }
    }

    fn validate_server_limits(&self, errors: &mut Vec<String>) {
        if !(512..=4096).contains(&self.server_limits.max_udp_payload) {
            errors.push("server_limits.max_udp_payload must be between 512 and 4096".to_owned());
        }
        if !(1..=65_535).contains(&self.server_limits.max_doh_body) {
            errors.push("server_limits.max_doh_body must be between 1 and 65535".to_owned());
        }
        if self.server_limits.max_doh_uri == 0 {
            errors.push("server_limits.max_doh_uri must be greater than zero".to_owned());
        }
        if self.server_limits.max_inflight_queries == 0 {
            errors.push("server_limits.max_inflight_queries must be greater than zero".to_owned());
        }
        if self.server_limits.query_timeout.is_zero() {
            errors.push("server_limits.query_timeout must be greater than zero".to_owned());
        }
        if self.server_limits.idle_timeout.is_zero() {
            errors.push("server_limits.idle_timeout must be greater than zero".to_owned());
        }
        if self.server_limits.shutdown_grace.is_zero() {
            errors.push("server_limits.shutdown_grace must be greater than zero".to_owned());
        }
    }
}

fn validate_listener_limits(listener: &ListenerConfig, errors: &mut Vec<String>) {
    if listener.limits.qps == Some(0) {
        errors.push(format!(
            "listener {:?}: limits.qps must be greater than zero",
            listener.name
        ));
    }
    if listener.limits.burst == Some(0) {
        errors.push(format!(
            "listener {:?}: limits.burst must be greater than zero",
            listener.name
        ));
    }
    if listener.limits.max_connections == Some(0) {
        errors.push(format!(
            "listener {:?}: limits.max_connections must be greater than zero",
            listener.name
        ));
    }
    if listener.limits.max_concurrent_requests == Some(0) {
        errors.push(format!(
            "listener {:?}: limits.max_concurrent_requests must be greater than zero",
            listener.name
        ));
    }
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }
    if hostname.parse::<IpAddr>().is_ok() {
        return false;
    }
    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn parse_level(level: &str) -> Option<LevelFilter> {
    level.parse::<LevelFilter>().ok()
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.as_os_str().is_empty() || path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn private_networks() -> &'static [IpNet] {
    static NETWORKS: OnceLock<Vec<IpNet>> = OnceLock::new();
    NETWORKS.get_or_init(|| {
        PRIVATE_NETWORKS
            .iter()
            .map(|network| network.parse().expect("private network CIDR is valid"))
            .collect()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Udp,
    Tcp,
    Dot,
    Doh,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Dot => "dot",
            Self::Doh => "doh",
        }
    }

    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Dot | Self::Doh)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclConfig {
    #[serde(default)]
    pub allow: Vec<IpNet>,
    #[serde(default)]
    pub deny: Vec<IpNet>,
}

impl AclConfig {
    pub fn is_allowed(&self, address: IpAddr, protocol: Protocol) -> bool {
        let address = match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        };
        if self.deny.iter().any(|network| network.contains(&address)) {
            return false;
        }
        if self.allow.is_empty() {
            if self.deny.is_empty() && !protocol.is_encrypted() {
                return private_networks()
                    .iter()
                    .any(|network| network.contains(&address));
            }
            return true;
        }
        self.allow.iter().any(|network| network.contains(&address))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerLimits {
    #[serde(default)]
    pub qps: Option<u32>,
    #[serde(default)]
    pub burst: Option<u32>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub max_concurrent_requests: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveListenerLimits {
    pub qps: u32,
    pub burst: u32,
    pub max_connections: Option<u32>,
    pub max_concurrent_requests: Option<u32>,
}

impl ListenerLimits {
    pub fn effective(&self, protocol: Protocol) -> EffectiveListenerLimits {
        let (default_qps, default_burst) = if protocol.is_encrypted() {
            (DEFAULT_ENCRYPTED_QPS, DEFAULT_ENCRYPTED_BURST)
        } else {
            (DEFAULT_PLAIN_QPS, DEFAULT_PLAIN_BURST)
        };

        EffectiveListenerLimits {
            qps: self.qps.unwrap_or(default_qps),
            burst: self.burst.unwrap_or(default_burst),
            max_connections: if protocol == Protocol::Udp {
                None
            } else {
                Some(self.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS))
            },
            max_concurrent_requests: if protocol == Protocol::Doh {
                Some(
                    self.max_concurrent_requests
                        .unwrap_or(DEFAULT_MAX_DOH_CONCURRENT_REQUESTS),
                )
            } else {
                None
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub query_names: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            query_names: false,
        }
    }
}

impl LoggingConfig {
    pub fn level_filter(&self) -> Result<LevelFilter, ConfigError> {
        parse_level(&self.level).ok_or_else(|| {
            ConfigError::Validation(format!(
                "logging.level {:?} must be one of off, error, warn, info, debug, trace",
                self.level
            ))
        })
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub refuse_any: bool,
    #[serde(default)]
    pub edns_client_subnet_v4_prefix: Option<u8>,
    #[serde(default)]
    pub edns_client_subnet_v6_prefix: Option<u8>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            refuse_any: true,
            edns_client_subnet_v4_prefix: None,
            edns_client_subnet_v6_prefix: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub name: String,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    pub protocol: Protocol,
    pub address: SocketAddr,
    #[serde(default)]
    pub acl: AclConfig,
    #[serde(default)]
    pub limits: ListenerLimits,
    #[serde(default)]
    pub tls: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub edns_padding_block_size: Option<usize>,
}

impl ListenerConfig {
    pub fn edns_padding_block_size(&self) -> usize {
        self.edns_padding_block_size.unwrap_or(128)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursorConfig {
    #[serde(default)]
    pub root_hints: Option<PathBuf>,
    #[serde(default)]
    pub deny_server: Option<Vec<IpNet>>,
    #[serde(default)]
    pub allow_server: Vec<IpNet>,
    #[serde(default)]
    pub deny_answers: Vec<IpNet>,
    #[serde(default = "default_response_cache_size")]
    pub response_cache_size: u64,
    #[serde(default = "default_ns_cache_size")]
    pub ns_cache_size: usize,
    #[serde(default = "default_recursion_limit")]
    pub recursion_limit: u8,
    #[serde(default = "default_ns_recursion_limit")]
    pub ns_recursion_limit: u8,
    #[serde(default)]
    pub qname_minimization: QNameMinimization,
    #[serde(default = "default_true")]
    pub case_randomization: bool,
    #[serde(default = "default_edns_payload_len")]
    pub edns_payload_len: u16,
}

impl Default for RecursorConfig {
    fn default() -> Self {
        Self {
            root_hints: None,
            deny_server: None,
            allow_server: Vec::new(),
            deny_answers: Vec::new(),
            response_cache_size: DEFAULT_RESPONSE_CACHE_SIZE,
            ns_cache_size: DEFAULT_NS_CACHE_SIZE,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            ns_recursion_limit: DEFAULT_RECURSION_LIMIT,
            qname_minimization: QNameMinimization::Strict,
            case_randomization: true,
            edns_payload_len: DEFAULT_EDNS_PAYLOAD_LEN,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QNameMinimization {
    #[default]
    Strict,
    Relaxed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub trust_anchor: Option<PathBuf>,
    #[serde(default)]
    pub nsec3_soft_iteration_limit: Option<u16>,
    #[serde(default)]
    pub nsec3_hard_iteration_limit: Option<u16>,
    #[serde(default)]
    pub validation_cache_size: Option<usize>,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trust_anchor: None,
            nsec3_soft_iteration_limit: None,
            nsec3_hard_iteration_limit: None,
            validation_cache_size: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub rpz_paths: Vec<PathBuf>,
    #[serde(default)]
    pub rpz_origin: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerLimits {
    #[serde(default = "default_max_udp_payload")]
    pub max_udp_payload: u16,
    #[serde(default = "default_max_doh_body")]
    pub max_doh_body: usize,
    #[serde(default = "default_max_doh_uri")]
    pub max_doh_uri: usize,
    #[serde(default = "default_max_inflight_queries")]
    pub max_inflight_queries: usize,
    #[serde(default = "default_query_timeout", with = "humantime_serde")]
    pub query_timeout: Duration,
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    #[serde(default = "default_shutdown_grace", with = "humantime_serde")]
    pub shutdown_grace: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
            max_doh_body: DEFAULT_MAX_DOH_BODY,
            max_doh_uri: DEFAULT_MAX_DOH_URI,
            max_inflight_queries: DEFAULT_MAX_INFLIGHT_QUERIES,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_response_cache_size() -> u64 {
    DEFAULT_RESPONSE_CACHE_SIZE
}

fn default_ns_cache_size() -> usize {
    DEFAULT_NS_CACHE_SIZE
}

fn default_recursion_limit() -> u8 {
    DEFAULT_RECURSION_LIMIT
}

fn default_ns_recursion_limit() -> u8 {
    DEFAULT_RECURSION_LIMIT
}

fn default_edns_payload_len() -> u16 {
    DEFAULT_EDNS_PAYLOAD_LEN
}

fn default_max_udp_payload() -> u16 {
    DEFAULT_MAX_UDP_PAYLOAD
}

fn default_max_doh_body() -> usize {
    DEFAULT_MAX_DOH_BODY
}

fn default_max_doh_uri() -> usize {
    DEFAULT_MAX_DOH_URI
}

fn default_max_inflight_queries() -> usize {
    DEFAULT_MAX_INFLIGHT_QUERIES
}

fn default_query_timeout() -> Duration {
    DEFAULT_QUERY_TIMEOUT
}

fn default_idle_timeout() -> Duration {
    DEFAULT_IDLE_TIMEOUT
}

fn default_shutdown_grace() -> Duration {
    DEFAULT_SHUTDOWN_GRACE
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CONFIG: &str = r#"
[[listeners]]
name = "lan"
protocol = "udp"
address = "127.0.0.1:5353"
"#;

    fn validation_message(config: &str) -> String {
        Config::from_toml_str(config)
            .expect_err("configuration should be rejected")
            .to_string()
    }

    #[test]
    fn accepts_example_configuration() {
        let config = Config::from_toml_str(include_str!("../deploy/echoic.toml.example"))
            .expect("example configuration should be valid");

        assert_eq!(config.listeners.len(), 4);
        assert_eq!(config.tls.len(), 1);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let config = format!("bogus = true\n{MINIMAL_CONFIG}");
        assert!(matches!(
            Config::from_toml_str(&config),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn rejects_unknown_listener_field() {
        let config = r#"
[[listeners]]
name = "lan"
protocol = "udp"
address = "127.0.0.1:5353"
bogus = true
"#;
        assert!(matches!(
            Config::from_toml_str(config),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_listener_names() {
        let config = r#"
[[listeners]]
name = "lan"
protocol = "udp"
address = "127.0.0.1:5353"

[[listeners]]
name = "lan"
protocol = "tcp"
address = "127.0.0.1:5353"
"#;
        assert!(validation_message(config).contains("duplicate listener name"));
    }

    #[test]
    fn rejects_duplicate_protocol_and_address() {
        let config = r#"
[[listeners]]
name = "lan-a"
protocol = "udp"
address = "127.0.0.1:5353"

[[listeners]]
name = "lan-b"
protocol = "udp"
address = "127.0.0.1:5353"
"#;
        assert!(validation_message(config).contains("duplicate listener endpoint"));
    }

    #[test]
    fn rejects_tls_on_plain_listener() {
        let config = r#"
[[tls]]
name = "public"
cert = "cert.pem"
key = "key.pem"

[[listeners]]
name = "lan"
protocol = "udp"
address = "127.0.0.1:5353"
tls = "public"
"#;
        assert!(validation_message(config).contains("must not set tls"));
    }

    #[test]
    fn rejects_connection_limit_on_udp_listener() {
        let config = r#"
[[listeners]]
name = "lan"
protocol = "udp"
address = "127.0.0.1:5353"
limits = { max_connections = 10 }
"#;
        assert!(
            validation_message(config)
                .contains("udp listeners must not set limits.max_connections")
        );
    }

    #[test]
    fn rejects_dot_without_tls() {
        let config = r#"
[[listeners]]
name = "dot"
protocol = "dot"
address = "0.0.0.0:853"
"#;
        assert!(validation_message(config).contains("dot listeners require tls"));
    }

    #[test]
    fn rejects_doh_without_tls_and_hostname() {
        let config = r#"
[[listeners]]
name = "doh"
protocol = "doh"
address = "0.0.0.0:443"
"#;
        let message = validation_message(config);
        assert!(message.contains("doh listeners require tls"));
        assert!(message.contains("doh listeners require hostname"));
    }

    #[test]
    fn rejects_invalid_doh_hostname() {
        let config = r#"
[[tls]]
name = "public"
cert = "cert.pem"
key = "key.pem"

[[listeners]]
name = "doh"
protocol = "doh"
address = "0.0.0.0:443"
tls = "public"
hostname = "bad_host"
"#;
        assert!(validation_message(config).contains("is not a valid DNS name"));
    }

    #[test]
    fn rejects_missing_tls_reference() {
        let config = r#"
[[listeners]]
name = "doh"
protocol = "doh"
address = "0.0.0.0:443"
tls = "missing"
hostname = "dns.example.com"
"#;
        assert!(validation_message(config).contains("TLS entry \"missing\" does not exist"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        let config = r#"
[[listeners]]
name = "lan"
protocol = "udp"
address = "127.0.0.1:5353"
acl = { allow = ["not-a-cidr"] }
"#;
        assert!(matches!(
            Config::from_toml_str(config),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn rejects_zero_listener_limits() {
        let config = r#"
[[listeners]]
name = "lan"
protocol = "tcp"
address = "127.0.0.1:5353"
limits = { qps = 0, burst = 0, max_connections = 0 }
"#;
        let message = validation_message(config);
        assert!(message.contains("limits.qps must be greater than zero"));
        assert!(message.contains("limits.burst must be greater than zero"));
        assert!(message.contains("limits.max_connections must be greater than zero"));
    }

    #[test]
    fn rejects_invalid_log_level() {
        let config = format!("[logging]\nlevel = \"verbose\"\n{MINIMAL_CONFIG}");
        assert!(validation_message(&config).contains("logging.level"));
    }

    #[test]
    fn rejects_out_of_range_server_limits() {
        let config =
            format!("[server_limits]\nmax_doh_body = 0\nmax_udp_payload = 100\n{MINIMAL_CONFIG}");
        let message = validation_message(&config);
        assert!(message.contains("server_limits.max_doh_body"));
        assert!(message.contains("server_limits.max_udp_payload"));
    }

    #[test]
    fn resolves_relative_paths_against_config_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let config_path = directory.path().join("echoic.toml");
        let config = r#"
[[tls]]
name = "public"
cert = "tls/cert.pem"
key = "tls/key.pem"

[[listeners]]
name = "doh"
protocol = "doh"
address = "0.0.0.0:443"
tls = "public"
hostname = "dns.example.com"
"#;
        fs::write(&config_path, config).expect("write configuration");

        let config = Config::load(&config_path).expect("configuration should load");

        assert_eq!(config.tls[0].cert, directory.path().join("tls/cert.pem"));
        assert_eq!(config.tls[0].key, directory.path().join("tls/key.pem"));
    }

    #[test]
    fn applies_private_acl_defaults_to_plain_listeners() {
        let acl = AclConfig::default();

        assert!(acl.is_allowed("127.0.0.1".parse().expect("IPv4"), Protocol::Udp));
        assert!(acl.is_allowed("192.168.1.1".parse().expect("IPv4"), Protocol::Tcp));
        assert!(!acl.is_allowed("8.8.8.8".parse().expect("IPv4"), Protocol::Udp));
        assert!(acl.is_allowed("8.8.8.8".parse().expect("IPv4"), Protocol::Doh));
    }

    #[test]
    fn deny_acl_entries_win() {
        let acl = AclConfig {
            allow: vec!["0.0.0.0/0".parse().expect("CIDR")],
            deny: vec!["192.0.2.0/24".parse().expect("CIDR")],
        };

        assert!(acl.is_allowed("198.51.100.1".parse().expect("IPv4"), Protocol::Doh));
        assert!(!acl.is_allowed("192.0.2.1".parse().expect("IPv4"), Protocol::Doh));
    }

    #[test]
    fn applies_per_protocol_limit_defaults() {
        let limits = ListenerLimits::default();

        assert_eq!(
            limits.effective(Protocol::Udp),
            EffectiveListenerLimits {
                qps: DEFAULT_PLAIN_QPS,
                burst: DEFAULT_PLAIN_BURST,
                max_connections: None,
                max_concurrent_requests: None,
            }
        );
        assert_eq!(
            limits.effective(Protocol::Dot),
            EffectiveListenerLimits {
                qps: DEFAULT_ENCRYPTED_QPS,
                burst: DEFAULT_ENCRYPTED_BURST,
                max_connections: Some(DEFAULT_MAX_CONNECTIONS),
                max_concurrent_requests: None,
            }
        );
        assert_eq!(
            limits.effective(Protocol::Doh),
            EffectiveListenerLimits {
                qps: DEFAULT_ENCRYPTED_QPS,
                burst: DEFAULT_ENCRYPTED_BURST,
                max_connections: Some(DEFAULT_MAX_CONNECTIONS),
                max_concurrent_requests: Some(DEFAULT_MAX_DOH_CONCURRENT_REQUESTS),
            }
        );
    }
}
