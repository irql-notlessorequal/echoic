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
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_server::proto::op::Message;
use hickory_server::proto::rr::Name;
use hickory_server::proto::rr::{DNSClass, RecordType};
use moka::Expiry;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::CacheConfig;

const MAGIC: &[u8; 8] = b"ECHCACHE";
const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub dnssec_ok: bool,
}

#[derive(Clone)]
struct CacheEntry {
    response: Message,
    original_time: SystemTime,
    valid_until: SystemTime,
    stale_until: SystemTime,
}

#[derive(Serialize, Deserialize)]
struct PersistedEntry {
    key: CacheKey,
    response: Message,
    original_unix: u64,
    original_nanos: u32,
    valid_unix: u64,
    valid_nanos: u32,
    stale_unix: u64,
    stale_nanos: u32,
}

#[derive(Serialize, Deserialize)]
struct PersistedCache {
    entries: Vec<PersistedEntry>,
}

struct CacheExpiry;

impl Expiry<CacheKey, CacheEntry> for CacheExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _current_time: std::time::Instant,
    ) -> Option<Duration> {
        value
            .stale_until
            .duration_since(SystemTime::now())
            .ok()
            .or(Some(Duration::ZERO))
    }

    fn expire_after_read(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _current_time: std::time::Instant,
        _last_modified: Option<Duration>,
        _last_accessed: std::time::Instant,
    ) -> Option<Duration> {
        value
            .stale_until
            .duration_since(SystemTime::now())
            .ok()
            .or(Some(Duration::ZERO))
    }

    fn expire_after_update(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _current_time: std::time::Instant,
        _last_modified: Option<Duration>,
    ) -> Option<Duration> {
        value
            .stale_until
            .duration_since(SystemTime::now())
            .ok()
            .or(Some(Duration::ZERO))
    }
}

pub struct PersistentDnsCache {
    memory: Cache<CacheKey, CacheEntry>,
    config: CacheConfig,
    path: Option<PathBuf>,
    dirty: AtomicBool,
}

impl PersistentDnsCache {
    pub fn new(config: &CacheConfig) -> Self {
        let memory = Cache::builder()
            .max_capacity(config.max_entries)
            .expire_after(CacheExpiry)
            .build();

        let cache = Self {
            memory,
            config: config.clone(),
            path: config.path.clone(),
            dirty: AtomicBool::new(false),
        };

        if config.persistent {
            cache.load();
        }

        cache
    }

    pub fn get(&self, key: &CacheKey, now: SystemTime) -> Option<(Message, bool)> {
        let entry = self.memory.get(key)?;

        if now <= entry.valid_until {
            let elapsed = now
                .duration_since(entry.original_time)
                .unwrap_or(Duration::ZERO);
            return Some((decrement_message(&entry.response, elapsed), false));
        }

        if self.config.serve_stale && now <= entry.stale_until {
            return Some((zero_ttl_message(&entry.response), true));
        }

        self.memory.invalidate(key);
        None
    }

    pub fn insert(&self, key: CacheKey, message: Message, now: SystemTime) {
        let ttl = response_ttl(&message, self.config.max_ttl);
        let valid_for = ttl.min(self.config.max_ttl).max(Duration::from_secs(1));
        let stale_for = if self.config.serve_stale {
            self.config.stale_ttl
        } else {
            Duration::ZERO
        };

        let entry = CacheEntry {
            response: message,
            original_time: now,
            valid_until: now + valid_for,
            stale_until: now + valid_for + stale_for,
        };

        self.memory.insert(key, entry);
        if self.config.persistent {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn clear(&self) {
        self.memory.invalidate_all();
        self.dirty.store(false, Ordering::Relaxed);
        if self.config.persistent
            && let Some(path) = &self.path
        {
            let _ = fs::remove_file(path);
        }
    }

    pub fn config(&self) -> &crate::config::CacheConfig {
        &self.config
    }

    pub fn flush(&self) {
        if !self.config.persistent || !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }

        let Some(path) = &self.path else {
            return;
        };

        let mut entries = Vec::new();
        for (key, entry) in self.memory.iter() {
            entries.push(PersistedEntry {
                key: key.as_ref().clone(),
                response: entry.response.clone(),
                original_unix: unix_seconds(entry.original_time),
                original_nanos: unix_nanos(entry.original_time),
                valid_unix: unix_seconds(entry.valid_until),
                valid_nanos: unix_nanos(entry.valid_until),
                stale_unix: unix_seconds(entry.stale_until),
                stale_nanos: unix_nanos(entry.stale_until),
            });
        }

        let payload = match serde_json::to_vec(&PersistedCache { entries }) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(error = %error, "failed to serialize persistent cache");
                return;
            }
        };

        let mut bytes = Vec::with_capacity(MAGIC.len() + 4 + 8 + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&payload);

        let temp_path = path.with_extension("tmp");
        if let Err(error) = fs::write(&temp_path, bytes) {
            warn!(error = %error, "failed to write persistent cache");
            return;
        }
        if let Err(error) = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600)) {
            warn!(error = %error, "failed to set persistent cache permissions");
        }
        if let Err(error) = fs::rename(&temp_path, path) {
            warn!(error = %error, "failed to replace persistent cache");
        }
    }

    fn load(&self) {
        let Some(path) = &self.path else {
            return;
        };

        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };

        if bytes.len() < MAGIC.len() + 4 + 8 {
            warn!("persistent cache file is too short");
            quarantine_corrupt(path);
            return;
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            warn!("persistent cache file has an invalid magic header");
            quarantine_corrupt(path);
            return;
        }

        let version = u32::from_le_bytes(bytes[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap());
        if version != FORMAT_VERSION {
            warn!(version, "unsupported persistent cache format version");
            quarantine_corrupt(path);
            return;
        }

        let payload_len =
            u64::from_le_bytes(bytes[MAGIC.len() + 4..MAGIC.len() + 12].try_into().unwrap())
                as usize;
        if bytes.len() != MAGIC.len() + 12 + payload_len {
            warn!("persistent cache file length does not match its header");
            quarantine_corrupt(path);
            return;
        }

        let payload = &bytes[MAGIC.len() + 12..];
        let persisted: PersistedCache = match serde_json::from_slice(payload) {
            Ok(cache) => cache,
            Err(error) => {
                warn!(error = %error, "failed to deserialize persistent cache");
                quarantine_corrupt(path);
                return;
            }
        };

        let now = SystemTime::now();
        for entry in persisted.entries {
            if now > entry.stale_system_time() {
                continue;
            }
            let original_time = entry.original_system_time();
            let valid_until = entry.valid_system_time();
            let stale_until = entry.stale_system_time();
            self.memory.insert(
                entry.key,
                CacheEntry {
                    response: entry.response,
                    original_time,
                    valid_until,
                    stale_until,
                },
            );
        }
    }
}

impl PersistedEntry {
    fn original_system_time(&self) -> SystemTime {
        UNIX_EPOCH
            + Duration::from_secs(self.original_unix)
            + Duration::from_nanos(u64::from(self.original_nanos))
    }

    fn valid_system_time(&self) -> SystemTime {
        UNIX_EPOCH
            + Duration::from_secs(self.valid_unix)
            + Duration::from_nanos(u64::from(self.valid_nanos))
    }

    fn stale_system_time(&self) -> SystemTime {
        UNIX_EPOCH
            + Duration::from_secs(self.stale_unix)
            + Duration::from_nanos(u64::from(self.stale_nanos))
    }
}
fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn unix_nanos(time: SystemTime) -> u32 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .subsec_nanos()
}

fn response_ttl(message: &Message, max_ttl: Duration) -> Duration {
    let mut min_ttl = None;
    for records in [&message.answers, &message.authorities, &message.additionals] {
        for record in records {
            let ttl = Duration::from_secs(u64::from(record.ttl));
            min_ttl = Some(min_ttl.map_or(ttl, |current: Duration| current.min(ttl)));
        }
    }
    min_ttl
        .unwrap_or(max_ttl)
        .min(max_ttl)
        .max(Duration::from_secs(1))
}

fn decrement_message(message: &Message, elapsed: Duration) -> Message {
    let mut message = message.clone();
    let elapsed = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
    for records in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        for record in records {
            record.decrement_ttl(elapsed);
        }
    }
    message
}

fn zero_ttl_message(message: &Message) -> Message {
    let mut message = message.clone();
    for records in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        for record in records {
            record.ttl = 0;
        }
    }
    message
}

fn quarantine_corrupt(path: &std::path::Path) {
    let corrupt = path.with_extension("corrupt");
    let _ = std::fs::remove_file(&corrupt);
    let _ = std::fs::rename(path, corrupt);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    use hickory_server::proto::op::{Message, MessageType, OpCode};
    use tempfile::tempdir;

    fn message() -> Message {
        Message::new(0, MessageType::Response, OpCode::Query)
    }

    fn config(persistent: bool, serve_stale: bool, path: Option<PathBuf>) -> CacheConfig {
        CacheConfig {
            persistent,
            path,
            max_entries: 10,
            flush_interval: Duration::from_secs(1),
            max_ttl: Duration::from_secs(10),
            serve_stale,
            stale_ttl: Duration::from_secs(2),
        }
    }

    #[test]
    fn fresh_entry_is_returned() {
        let cache = PersistentDnsCache::new(&config(false, false, None));
        let key = CacheKey {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        let now = SystemTime::now();
        cache.insert(key.clone(), message(), now);

        let (cached, stale) = cache.get(&key, now).unwrap();
        assert!(!stale);
        assert!(cached.answers.is_empty());
    }

    #[test]
    fn expired_entry_becomes_stale_when_enabled() {
        let key = CacheKey {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        let now = SystemTime::now();
        let mut short_config = config(false, true, None);
        short_config.max_ttl = Duration::from_secs(1);
        let cache = PersistentDnsCache::new(&short_config);
        cache.insert(key.clone(), message(), now);

        thread::sleep(Duration::from_millis(1100));
        let (cached, stale) = cache.get(&key, SystemTime::now()).unwrap();
        assert!(stale);
        assert!(cached.answers.is_empty());
    }

    #[test]
    fn stale_entry_expires_after_stale_window() {
        let mut short_config = config(false, true, None);
        short_config.max_ttl = Duration::from_secs(1);
        short_config.stale_ttl = Duration::from_secs(1);
        let cache = PersistentDnsCache::new(&short_config);
        let key = CacheKey {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        cache.insert(key.clone(), message(), SystemTime::now());

        thread::sleep(Duration::from_millis(2200));
        assert!(cache.get(&key, SystemTime::now()).is_none());
    }

    #[test]
    fn persistent_cache_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let cfg = config(true, true, Some(path.clone()));
        let cache = PersistentDnsCache::new(&cfg);
        let key = CacheKey {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        cache.insert(key.clone(), message(), SystemTime::now());
        cache.flush();

        let reloaded = PersistentDnsCache::new(&cfg);
        let (cached, stale) = reloaded.get(&key, SystemTime::now()).unwrap();
        assert!(!stale);
        assert!(cached.answers.is_empty());
    }

    #[test]
    fn corrupt_cache_is_quarantined() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.json");
        std::fs::write(&path, b"not json").unwrap();

        let cfg = config(true, false, Some(path.clone()));
        let cache = PersistentDnsCache::new(&cfg);
        let key = CacheKey {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        assert!(cache.get(&key, SystemTime::now()).is_none());
        assert!(path.with_extension("corrupt").exists());
    }
}
