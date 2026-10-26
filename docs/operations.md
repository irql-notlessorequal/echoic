# Echoic operations

## Firewall

Expose 853/tcp and 443/tcp publicly. Restrict 53/udp and 53/tcp to the LAN or trusted clients.

Docker published ports bypass UFW and similar host firewalls. Apply equivalent rules at the host or edge firewall.

## Certificates

Certificates are loaded from the paths in the TLS configuration. Use a certbot deploy hook to copy renewed files and run `systemctl reload echoic` or send `SIGHUP` to the process. Certificate reload keeps the old certificate if the new files are invalid.

## Root hints and trust anchor

Omit `recursor.root_hints` to use the embedded root hints. Omit `dnssec.trust_anchor` to use Hickory's built-in root trust anchor. Changing either setting rebuilds the recursor and clears its cache.

## systemd-resolved

On hosts where systemd-resolved binds port 53, disable or reconfigure it before starting Echoic.

## IPv6

Use `[::]` listeners where IPv6 service is required. Docker IPv6 must be enabled in the daemon and network configuration before publishing IPv6 ports.

## Monitoring

Monitor certificate expiry externally. Echoic reloads certificates on `SIGHUP`; it does not renew them automatically.
