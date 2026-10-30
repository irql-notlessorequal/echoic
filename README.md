# Echoic

A recursive DNS resolver written in Rust.

Supporting features like...

- DNS over TLS
- DNS over HTTPS
- DNSSEC
- EDNS TCP Keepalive (RFC 7828)
- EDNS Padding (RFC 7830)
- Extended DNS Errors (RFC 8914)
- Memory caching
- Persistent file caching
- Case randomization for responses
- QNAME minimization
- RPZ-based blocklists
- A customizable landing page for DoH

## Should I use this?

This project was mostly vibecoded out of rage from other DNS recursors
having varying limitations and flaws that annoyed the hell out of me.

The code in theory works but I wouldn't attest to it's quality.

Only a fool would use this in production.

## Build

```sh
cargo build
```

## Validate configuration

```sh
cargo run -- --check-config --config deploy/echoic.toml.example
cargo run -- --check-config --config deploy/echoic.container.toml.example
```

## License

echoic temporarily contains vendored code that includes additional fixes
for the libraries that it uses, those folders are licensed under their
respective terms, the rest of the codebase uses GNU AGPL v3.

```
echoic, a recursive DNS resolver.
Copyright (C) IRQL_NOT_LESS_OR_EQUAL

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```