# ARCTracker Sync

ARCTracker Sync keeps your [ARCTracker](https://arctracker.io) inventory up to
date while you play ARC Raiders. It signs you into ARCTracker, helps you start
the game from Steam or Epic, and then connects your game account so ARCTracker
can sync your inventory automatically in the background.

It runs as a small Windows desktop app with a tray icon. Once it's set up, you
mostly leave it alone — open it, start your game, and play.

> **License:** ARCTracker Sync is **free for noncommercial use** under the
> PolyForm Noncommercial License 1.0.0. **Commercial use requires a separate
> license** — contact matt@arctracker.io. See [License](#license) below.

## Installing

1. Download the latest `arctracker-sync-<version>-windows-x64.zip` from the
   [Releases](https://github.com/RaidTheory/ARCTrackerSync/releases) page.
2. Unzip it anywhere and run `arctracker-sync.exe`.

The app is currently unsigned, so Windows SmartScreen may warn you the first time
you run it. It also asks for **Administrator** permission on launch (see
[Why it needs Administrator](#why-it-needs-administrator)).

Once installed, ARCTracker Sync updates itself: it checks for new releases on
GitHub and, when you approve, downloads and installs them. Each download is
verified against a published checksum before it's applied.

### Requirements

- Windows 10 or 11, 64-bit.
- ARC Raiders on **Steam** or the **Epic Games Store**.
- An ARCTracker account.

## Using it

1. **Sign in to ARCTracker.** The app opens your browser to sign in, then
   remembers you using Windows Credential Manager so you don't have to sign in
   every time.
2. **Choose your launcher.** Pick Steam or Epic. Steam can launch ARC Raiders
   directly; for Epic you may need to point the app at the game once.
3. **Prepare and launch.** The app gets your launcher ready, then you start ARC
   Raiders from Steam or Epic as usual.
4. **Play.** While you play, ARCTracker Sync connects your game account and
   ARCTracker keeps your inventory in sync. The main screen shows your sign-in,
   game selection, launch, connection, and sync status at a glance.

Troubleshooting details are tucked away by default — you can open them if you
need to dig into what's happening. For more help, see
<https://arctracker.io/help/sync>.

### Your privacy

ARCTracker Sync does **not** store your ARC Raiders / game-account credentials on
your machine. Setup data stays local, and the only thing it sends to ARCTracker
is the account-connection update needed to keep your inventory in sync. Your
ARCTracker sign-in is kept in Windows Credential Manager.

### Why it needs Administrator

To notice your game account connecting, ARCTracker Sync watches your own
computer's network traffic using Windows raw sockets, which Windows only allows
with Administrator rights. There's no kernel driver, bundled network library, or
extra capture tool to install — and it only ever looks at traffic on your own
machine.

---

## Building from source

You don't need to build the app to use it — grab a release above. To build it
yourself:

Prerequisites:

- A stable Rust toolchain on the MSVC target (install via [rustup](https://rustup.rs/)).
- Windows 10 or 11, x64.

From the repository root:

```powershell
cargo build --release
cargo run
```

The app ships a manifest that requests elevation, so it runs as Administrator
(required for the raw-socket capture described above). No kernel driver or
external tooling is needed.

## Contributing

Bug reports, feature ideas, and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to get started and for the
contribution license terms.

To report a security vulnerability, please follow [SECURITY.md](SECURITY.md)
rather than opening a public issue.

## License

ARCTracker Sync is source-available under the
[PolyForm Noncommercial License 1.0.0](LICENSE).

- **Noncommercial use is free.** Personal use, hobby projects, research,
  education, and other noncommercial purposes are permitted at no charge.
- **Commercial use requires a separate license.** Contact matt@arctracker.io to
  arrange one.

This is a source-available license, not an OSI-approved "open source" license,
because it restricts commercial use.

The bundled `vendor/pcapsql-core` library is third-party software under the MIT
License. Other dependencies retain their own licenses. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for details.

Copyright 2026 RaidTheory LLC · <https://arctracker.io>
