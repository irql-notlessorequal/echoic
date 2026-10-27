# hickory-net backport

This directory contains the crates.io `hickory-net` 0.26.3 source with the
DNSSEC insecure-delegation fix from upstream applied.

- Issue: https://github.com/hickory-dns/hickory-dns/issues/3974
- Upstream fix: https://github.com/hickory-dns/hickory-dns/pull/3976
- Release/0.26 backport: https://github.com/hickory-dns/hickory-dns/pull/4007
- Backport merge commit: `d09187944928d39efc72922ff8b55d754dff2732`

Only `src/dnssec/mod.rs` differs from the published crate. The change prevents
a validation loop when an authoritative server answers a DS query with the
child zone's own SOA record, and accepts empty DS responses from insecure
parents without treating them as bogus.

Remove this directory and the `[patch.crates-io]` entry in `Cargo.toml` once a
release containing the fix is available and pinned.

This folder is licensed under the Apache License 2.0 or MIT license.