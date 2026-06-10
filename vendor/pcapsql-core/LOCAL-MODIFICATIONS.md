# Local modifications

This directory is a **vendored, locally-modified copy** of
[`pcapsql-core`](https://github.com/mtottenh/pcapsql) version **0.3.1** (as
published on crates.io). ARCTracker Sync uses it as a `path` dependency, so it is
**not** byte-for-byte identical to the published crate.

The local changes are in the TLS decryption and protocol-registration code, in
support of the traffic parsing ARCTracker Sync relies on. To see exactly which
files changed and the full diff, compare this `src/` tree against the published
`pcapsql-core 0.3.1` source (downloadable from <https://crates.io/crates/pcapsql-core>).

## Licensing

The upstream library is MIT-licensed (see [`LICENSE`](LICENSE)), and that license
is retained here. The local modifications are likewise made available under the
same MIT terms.
