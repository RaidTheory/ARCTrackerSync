# Third-Party Notices

ARCTracker Sync is distributed under the PolyForm Noncommercial License 1.0.0
(see [`LICENSE`](LICENSE)). It includes and/or links the third-party software
listed below, each of which remains under its own license.

## Bundled source

- **pcapsql-core** — `vendor/pcapsql-core/`
  - License: MIT (see [`vendor/pcapsql-core/LICENSE`](vendor/pcapsql-core/LICENSE))
  - Copyright (c) 2024-2025 Max Tottenham
  - Upstream: <https://github.com/mtottenh/pcapsql>
  - **Locally modified** from the published `pcapsql-core 0.3.1` (changes in the
    TLS decryption and protocol-registration code). See
    [`vendor/pcapsql-core/LOCAL-MODIFICATIONS.md`](vendor/pcapsql-core/LOCAL-MODIFICATIONS.md).

## Optional runtime dependency (not distributed)

- **Npcap** — <https://npcap.com>
  - An optional packet-capture driver the user can select in Settings as an
    alternative to the built-in raw-socket capture. ARCTracker Sync never
    bundles, downloads, or installs Npcap (its free license does not permit
    redistribution); when selected, the app loads the user's own installed
    `wpcap.dll` at runtime. Npcap remains under its own license.

## Statically linked dependencies

The compiled `arctracker-sync.exe` statically links a number of open-source Rust
crates (for example `eframe`/`egui`, `ureq`, `serde`, `tray-icon`, `ring`, and
their transitive dependencies). These are distributed under permissive licenses,
predominantly MIT and Apache-2.0, with some BSD-style and other permissive terms.
Each crate's own license applies to that crate.

### Regenerating a complete dependency license report

For an exhaustive, auto-generated list of every dependency and its license, run
one of:

```
cargo install cargo-about
cargo about init
cargo about generate about.hbs > THIRD-PARTY-FULL.html
```

(or `cargo-bundle-licenses` / `cargo-license`). The authoritative set of
dependencies and versions is recorded in `Cargo.lock`.
