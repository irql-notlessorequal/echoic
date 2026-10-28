# hickory-resolver CNAME negative-response fix

This directory contains the crates.io `hickory-resolver` 0.26.3 source with a
local fix for CNAME chains that terminate in NODATA or NXDOMAIN.

The recursor previously discarded the accumulated CNAME answers when the target
lookup returned a negative `RecursorError`. The result was a NODATA or NXDOMAIN
response with no CNAME and an unrelated SOA, which Android rejects as
`UnknownHostException`.

Changed files:

- `src/recursor/handle.rs`: `resolve_cnames` merges the accumulated CNAME
  answers with the negative authorities and SOA, and sets the response code to
  NXDOMAIN or NOERROR.
- `src/recursor/mod.rs`: the validating recursor returns NXDOMAIN responses
  with CNAME answers instead of converting them to an error that cannot carry
  answers.

No upstream fix was identified for 0.26.3. Remove this directory and the
`[patch.crates-io]` entry in `Cargo.toml` once an upstream release includes the
fix and is pinned.

This folder is licensed under the Apache License 2.0 or MIT license.
