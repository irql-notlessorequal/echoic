# Echoic operations

## Firewall

Expose 853/tcp and 443/tcp publicly. Restrict 53/udp and 53/tcp to the LAN or trusted clients.

Docker published ports bypass UFW and similar host firewalls. Apply equivalent rules at the host or edge firewall.

## Certificates

Certificates are loaded from the paths in the TLS configuration. Use a certbot deploy hook to copy renewed files and run `systemctl reload echoic` or send `SIGHUP` to the process. Certificate reload keeps the old certificate if the new files are invalid.

## Root hints and trust anchor

Omit `recursor.root_hints` to use the embedded root hints. Omit `dnssec.trust_anchor` to use Hickory's built-in root trust anchor. Changing either setting or the referenced file contents rebuilds the recursor and replaces its cache.

DNSSEC validation is enabled by default. Bogus records in the answer or authority section return SERVFAIL; bogus records in the additional section are removed from the response. Set `dnssec.validate = false` only when unsigned or invalid data must be accepted; DNSSEC records are still requested, but responses are not validated and the AD bit is never set.

## systemd-resolved

On hosts where systemd-resolved binds port 53, disable or reconfigure it before starting Echoic.

## IPv6

Use `[::]` listeners where IPv6 service is required. Docker IPv6 must be enabled in the daemon and network configuration before publishing IPv6 ports.

## Monitoring

Monitor certificate expiry externally. Echoic reloads certificates on `SIGHUP`; it does not renew them automatically.

## Access and connection limits

Plain DNS listeners use the private-network allow list whenever `acl.allow` is empty, including when `acl.deny` contains exclusions. Set an explicit allow range to expose plain DNS publicly. Deny entries take precedence.

TCP and DoT enforce `limits.max_connections` and process up to 32 concurrent queries per connection, subject to the global query limit. `server_limits.idle_timeout` bounds idle stream connections and incomplete DNS frames. DoH uses the same idle setting for HTTP connections; `query_timeout` also bounds reading a POST body. `max_doh_uri` counts the entire URI path and query string before parameter decoding. `max_doh_body` bounds decoded DNS messages for GET and POST.

## Persistent cache

Relative `cache.path` values resolve against the configuration directory. With the supplied systemd service, use `/var/lib/echoic/cache.json`; systemd creates the private writable state directory. Container deployments need a writable volume for persistent storage.

Saved entries carry the resolver configuration, cache configuration, root-hint contents, trust-anchor contents and application version that produced them. A policy change discards saved entries. Cache format version 2 replaces version 1; existing version 1 files are quarantined and the cache starts empty.

Zero-TTL responses are excluded from caching. Stale answers have zero TTLs and clear authentication status. Resolver reloads allocate separate caches so requests using the previous resolver cannot populate the replacement cache. Shutdown drains listeners before the final cache flush.

## Configuration checks and reloads

`echoic --check-config --check-files --config /etc/echoic/echoic.toml` also loads TLS certificates and keys, root hints, trust anchors used by validation, and RPZ files. `--check-config` alone validates the configuration without requiring those files.

Custom landing HTML and CSS files reload automatically when changed. Listener address and protocol changes continue to require a restart. Reload and shutdown signal handlers are installed before listeners start accepting connections.

## Metrics and readiness

DoH listeners expose Prometheus text metrics at `/metrics`, using the listener's hostname and ACL rules. Metrics include served requests by protocol, admission rejections, SERVFAILs, blocked requests, cache operations, upstream failures, query duration sum and count, and available global query permits. Cache counters include internal resolver operations and complete-response cache hits.

`/readyz` becomes unavailable during shutdown. Echoic monitors listener tasks and exits with an error if a listener stops unexpectedly, allowing the service manager to restart it.

## Rust API compatibility

The `RecursiveResolver` trait and listener startup signatures are unchanged. `CachedRecursiveResolver::new` captures the cache present at construction; create a replacement resolver to adopt a replacement cache. `ListenerRuntime.dot_max_connections` provides the shared connection limit for TCP and DoT. `Cli` adds `check_files`; callers constructing it with struct literals must supply that field. Echoic exposes no stable C ABI.
