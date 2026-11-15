# hickory-net backport

This directory contains the crates.io `hickory-net` 0.26.3 source with two
DNSSEC fixes from upstream applied.

## Insecure-delegation fix

- Issue: https://github.com/hickory-dns/hickory-dns/issues/3974
- Upstream fix: https://github.com/hickory-dns/hickory-dns/pull/3976
- Release/0.26 backport: https://github.com/hickory-dns/hickory-dns/pull/4007
- Backport merge commit: `d09187944928d39efc72922ff8b55d754dff2732`

The change prevents a validation loop when an authoritative server answers a DS
query with the child zone's own SOA record, and accepts empty DS responses from
insecure parents without treating them as bogus.

## Zone cut search fix

- Issue: https://github.com/hickory-dns/hickory-dns/issues/4063
- Upstream fix: https://github.com/hickory-dns/hickory-dns/pull/4064

`find_ds_records` walks the ancestors of an unsigned name with unvalidated NS
queries to locate the zone cut. The walk only continued on NODATA or NXDOMAIN;
any other failure, such as a REFUSED or SERVFAIL answer from an ancestor
nameserver, was reported as `Proof::Bogus` immediately. Names under a
delegation that refuses queries were therefore marked bogus even though a
validated insecure delegation exists higher up.

The backport treats a failed ancestor NS lookup like NODATA and continues the
walk to the parent. If every lookup fails the walk reaches the root and the
result stays bogus.

Only `src/dnssec/mod.rs` differs from the published crate.

Remove this directory and the `[patch.crates-io]` entry in `Cargo.toml` once a
release containing the fixes is available and pinned.

This folder is licensed under the Apache License 2.0 or MIT license.
