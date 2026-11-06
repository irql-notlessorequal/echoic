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
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_server::proto::op::Message;
use hickory_server::proto::rr::Name;
use hickory_server::proto::rr::{DNSClass, RecordType};
use moka::Expiry;
use moka::sync::Cache;
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::CacheConfig;

const MAGIC: &[u8; 8] = b"ECHCACHE";
const FORMAT_VERSION: u32 = 2;
const PAYLOAD_LENGTH_OFFSET: u64 = (MAGIC.len() + size_of::<u32>()) as u64;
const HEADER_LENGTH: usize = MAGIC.len() + size_of::<u32>() + size_of::<u64>();

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
    policy: String,
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
    policy: String,
    generation: AtomicU64,
    flushed: AtomicU64,
    io_lock: Mutex<()>,
}

struct CacheSnapshot<'a>(&'a PersistentDnsCache);

impl Serialize for CacheSnapshot<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PersistedCache", 2)?;
        state.serialize_field("policy", &self.0.policy)?;
        state.serialize_field("entries", &CacheEntries(self.0))?;
        state.end()
    }
}

struct CacheEntries<'a>(&'a PersistentDnsCache);

impl Serialize for CacheEntries<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut entries = serializer.serialize_seq(None)?;
        for (key, entry) in self.0.memory.iter() {
            entries.serialize_element(&PersistedEntry {
                key: key.as_ref().clone(),
                response: entry.response,
                original_unix: unix_seconds(entry.original_time),
                original_nanos: unix_nanos(entry.original_time),
                valid_unix: unix_seconds(entry.valid_until),
                valid_nanos: unix_nanos(entry.valid_until),
                stale_unix: unix_seconds(entry.stale_until),
                stale_nanos: unix_nanos(entry.stale_until),
            })?;
        }
        entries.end()
    }
}

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl PersistentDnsCache {
    pub async fn open(config: &CacheConfig) -> Self {
        let config = config.clone();
        tokio::task::spawn_blocking(move || Self::new(&config))
            .await
            .expect("persistent cache load task failed")
    }

    pub async fn open_for_policy(config: &CacheConfig, policy: String, load: bool) -> Self {
        let config = config.clone();
        tokio::task::spawn_blocking(move || {
            let mut unloaded = config.clone();
            unloaded.persistent = false;
            let mut cache = Self::new(&unloaded);
            cache.config = config;
            cache.policy = policy;
            if load && cache.config.persistent {
                cache.load();
            }
            cache
        })
        .await
        .expect("persistent cache load task failed")
    }

    pub fn new(config: &CacheConfig) -> Self {
        let memory = Cache::builder()
            .max_capacity(config.max_entries)
            .expire_after(CacheExpiry)
            .build();

        let cache = Self {
            memory,
            config: config.clone(),
            path: config.path.clone(),
            policy: String::new(),
            generation: AtomicU64::new(0),
            flushed: AtomicU64::new(0),
            io_lock: Mutex::new(()),
        };

        if config.persistent {
            cache.load();
        }

        cache
    }

    pub fn get(&self, key: &CacheKey, now: SystemTime) -> Option<(Message, bool)> {
        let entry = self.memory.get(key)?;

        if now < entry.valid_until {
            let elapsed = now
                .duration_since(entry.original_time)
                .unwrap_or(Duration::ZERO);
            return Some((decrement_message(entry.response, elapsed), false));
        }

        if self.config.serve_stale && now <= entry.stale_until {
            let mut message = zero_ttl_message(entry.response);
            message.metadata.authentic_data = false;
            for record in message
                .answers
                .iter_mut()
                .chain(&mut message.authorities)
                .chain(&mut message.additionals)
            {
                if record.proof.is_secure() {
                    record.proof = hickory_server::proto::dnssec::Proof::Indeterminate;
                }
            }
            return Some((message, true));
        }

        self.memory.invalidate(key);
        None
    }

    pub fn insert(&self, key: CacheKey, message: Message, now: SystemTime) {
        let ttl = response_ttl(&message, self.config.max_ttl);
        let valid_for = ttl.min(self.config.max_ttl);
        if valid_for.is_zero() {
            return;
        }
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
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn clear(&self) -> io::Result<()> {
        let _guard = self
            .io_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.memory.invalidate_all();
        let result = if self.config.persistent
            && let Some(path) = &self.path
            && path.exists()
        {
            fs::remove_file(path)
        } else {
            Ok(())
        };
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        if result.is_ok() {
            self.flushed.store(generation, Ordering::Relaxed);
        }
        result
    }

    pub fn config(&self) -> &crate::config::CacheConfig {
        &self.config
    }

    pub fn flush(&self) -> io::Result<()> {
        if !self.config.persistent {
            return Ok(());
        }

        let _guard = self
            .io_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let generation = self.generation.load(Ordering::Relaxed);
        if generation == self.flushed.load(Ordering::Relaxed) {
            return Ok(());
        }

        let Some(path) = &self.path else {
            return Ok(());
        };

        let temp_path = unique_sibling(path, "tmp");
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp_path)?;
            file.write_all(MAGIC)?;
            file.write_all(&FORMAT_VERSION.to_le_bytes())?;
            file.write_all(&0u64.to_le_bytes())?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, &CacheSnapshot(self)).map_err(io::Error::other)?;
            writer.flush()?;
            let mut file = writer.into_inner().map_err(io::Error::other)?;
            let payload_len = file.stream_position()? - HEADER_LENGTH as u64;
            file.seek(SeekFrom::Start(PAYLOAD_LENGTH_OFFSET))?;
            file.write_all(&payload_len.to_le_bytes())?;
            file.sync_all()?;
            fs::rename(&temp_path, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result?;
        self.flushed.store(generation, Ordering::Relaxed);
        Ok(())
    }

    pub async fn flush_async(self: &Arc<Self>) -> io::Result<()> {
        let cache = self.clone();
        tokio::task::spawn_blocking(move || cache.flush())
            .await
            .map_err(io::Error::other)?
    }

    pub async fn clear_async(self: &Arc<Self>) -> io::Result<()> {
        let cache = self.clone();
        tokio::task::spawn_blocking(move || cache.clear())
            .await
            .map_err(io::Error::other)?
    }

    fn load(&self) {
        let Some(path) = &self.path else {
            return;
        };

        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };

        if bytes.len() < HEADER_LENGTH {
            warn!("persistent cache file is too short");
            quarantine_corrupt(path);
            return;
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            warn!("persistent cache file has an invalid magic header");
            quarantine_corrupt(path);
            return;
        }

        let version = u32::from_le_bytes(
            bytes[MAGIC.len()..PAYLOAD_LENGTH_OFFSET as usize]
                .try_into()
                .unwrap(),
        );
        if version != FORMAT_VERSION {
            warn!(version, "unsupported persistent cache format version");
            quarantine_corrupt(path);
            return;
        }

        let payload_len = u64::from_le_bytes(
            bytes[PAYLOAD_LENGTH_OFFSET as usize..HEADER_LENGTH]
                .try_into()
                .unwrap(),
        );
        let Ok(payload_len) = usize::try_from(payload_len) else {
            warn!("persistent cache payload is too large");
            quarantine_corrupt(path);
            return;
        };
        if HEADER_LENGTH.checked_add(payload_len) != Some(bytes.len()) {
            warn!("persistent cache file length does not match its header");
            quarantine_corrupt(path);
            return;
        }

        let payload = &bytes[HEADER_LENGTH..];
        let persisted: PersistedCache = match serde_json::from_slice(payload) {
            Ok(cache) => cache,
            Err(error) => {
                warn!(error = %error, "failed to deserialize persistent cache");
                quarantine_corrupt(path);
                return;
            }
        };

        if persisted.policy != self.policy {
            tracing::info!("persistent cache policy changed; discarding saved entries");
            return;
        }
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
    min_ttl.unwrap_or(max_ttl).min(max_ttl)
}

fn decrement_message(mut message: Message, elapsed: Duration) -> Message {
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

fn zero_ttl_message(mut message: Message) -> Message {
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

fn unique_sibling(path: &Path, extension: &str) -> PathBuf {
    let counter = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "cache".to_string());
    path.with_file_name(format!(
        "{name}.{}.{}.{}",
        std::process::id(),
        counter,
        extension
    ))
}

fn quarantine_corrupt(path: &Path) {
    let corrupt = unique_sibling(path, "corrupt");
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
    fn zero_ttl_answers_are_excluded_from_fresh_and_stale_cache() {
        let cache = PersistentDnsCache::new(&config(false, true, None));
        let name = Name::from_ascii("example.com.").unwrap();
        let key = CacheKey {
            name: name.clone(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        let mut answer = message();
        answer.add_answer(hickory_server::proto::rr::Record::from_rdata(
            name,
            0,
            hickory_server::proto::rr::RData::A(hickory_server::proto::rr::rdata::A::new(
                192, 0, 2, 1,
            )),
        ));
        let now = SystemTime::now();
        cache.insert(key.clone(), answer, now);
        assert!(cache.get(&key, now).is_none());
        assert!(cache.get(&key, now + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn stale_answers_clear_authentication() {
        use hickory_server::proto::dnssec::Proof;
        use hickory_server::proto::rr::{RData, Record, rdata::A};
        let mut cfg = config(false, true, None);
        cfg.max_ttl = Duration::from_secs(1);
        let cache = PersistentDnsCache::new(&cfg);
        let name = Name::from_ascii("example.com.").unwrap();
        let key = CacheKey {
            name: name.clone(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: true,
        };
        let mut answer = message();
        answer.metadata.authentic_data = true;
        let mut record = Record::from_rdata(name, 1, RData::A(A::new(192, 0, 2, 1)));
        record.proof = Proof::Secure;
        answer.add_answer(record);
        let now = SystemTime::now();
        cache.insert(key.clone(), answer, now - Duration::from_secs(2));
        let (answer, stale) = cache.get(&key, now).unwrap();
        assert!(stale);
        assert!(!answer.metadata.authentic_data);
        assert!(!answer.answers[0].proof.is_secure());
        assert_eq!(answer.answers[0].ttl, 0);
    }

    #[tokio::test]
    async fn persisted_entries_require_the_original_resolver_policy() {
        let directory = tempdir().unwrap();
        let cfg = config(true, false, Some(directory.path().join("cache.json")));
        let key = CacheKey {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        let cache = PersistentDnsCache::open_for_policy(&cfg, "initial policy".into(), true).await;
        cache.insert(key.clone(), message(), SystemTime::now());
        cache.flush().unwrap();
        let matching =
            PersistentDnsCache::open_for_policy(&cfg, "initial policy".into(), true).await;
        assert!(matching.get(&key, SystemTime::now()).is_some());
        let changed =
            PersistentDnsCache::open_for_policy(&cfg, "stricter policy".into(), true).await;
        assert!(changed.get(&key, SystemTime::now()).is_none());
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
        cache.flush().unwrap();

        let reloaded = PersistentDnsCache::new(&cfg);
        let (cached, stale) = reloaded.get(&key, SystemTime::now()).unwrap();
        assert!(!stale);
        assert!(cached.answers.is_empty());
    }

    #[test]
    fn flush_failure_keeps_data_retryable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.json");
        std::fs::create_dir(&path).unwrap();
        let cfg = config(true, true, Some(path.clone()));
        let cache = PersistentDnsCache::new(&cfg);
        let key = CacheKey {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
        };
        cache.insert(key.clone(), message(), SystemTime::now());

        assert!(cache.flush().is_err());
        std::fs::remove_dir(&path).unwrap();
        cache.flush().unwrap();

        let reloaded = PersistentDnsCache::new(&cfg);
        assert!(reloaded.get(&key, SystemTime::now()).is_some());
    }

    #[test]
    fn clear_removes_flushed_entries() {
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
        cache.flush().unwrap();

        cache.clear().unwrap();
        assert!(!path.exists());
        assert!(cache.get(&key, SystemTime::now()).is_none());
        assert!(cache.flush().is_ok());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn persistent_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let cfg = config(true, false, Some(path.clone()));
        let cache = PersistentDnsCache::new(&cfg);
        cache.insert(
            CacheKey {
                name: Name::from_ascii("example.com.").unwrap(),
                qtype: RecordType::A,
                qclass: DNSClass::IN,
                dnssec_ok: false,
            },
            message(),
            SystemTime::now(),
        );
        cache.flush().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
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
        let quarantined: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".corrupt"))
            .collect();
        assert_eq!(quarantined.len(), 1);
        assert!(!path.exists());
    }

    #[test]
    fn repeated_corruption_keeps_each_quarantined_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let cfg = config(true, false, Some(path.clone()));

        for _ in 0..2 {
            std::fs::write(&path, b"not json").unwrap();
            let _cache = PersistentDnsCache::new(&cfg);
        }

        let quarantined = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".corrupt")
            })
            .count();
        assert_eq!(quarantined, 2);
    }
}
