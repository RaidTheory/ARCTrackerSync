# Running on Linux (ARC Raiders via Proton)

ARCTracker Sync was written Windows-only; this is a native Linux port of the
platform layer (packet capture, process inspection, launcher control, token
storage). The TLS-decryption core (`vendor/pcapsql-core`) is unchanged.

## Build & run

```bash
./scripts/run-linux.sh
```

That builds `target/release/arctracker-sync`, grants it `CAP_NET_RAW` with a
one-time `sudo setcap cap_net_raw+ep`, and launches the GUI unprivileged. You
can also run it as root instead of using `setcap`.

## How sync works here

1. The app owns a TLS keylog file (`SSLKEYLOGFILE`) under its data dir.
2. When you launch the game **through the app** (Steam button), it starts
   `steam` with `SSLKEYLOGFILE` in the environment. Steam passes that env to the
   Proton game, whose HTTPS stack writes session keys to the file.
3. The app captures port-443 traffic on your interface with an `AF_PACKET`
   socket, decrypts the game↔Embark gateway TLS using those keys, extracts your
   sync key, and posts it to ARCTracker.

**Important:** the game only inherits `SSLKEYLOGFILE` if Steam is (re)started by
the app *after* the env is set. If Steam was already running, use the app's
prepare/restart so it relaunches Steam with the keylog env. If you launch the
game manually, set `SSLKEYLOGFILE` yourself as a Steam launch option, e.g.:

```
SSLKEYLOGFILE=$HOME/.local/share/Sync/sync-key.log %command%
```

## Verifying capture works

```bash
cargo build --release --example capture_smoke
sudo ./target/release/examples/capture_smoke        # or after setcap, no sudo
```

It lists interfaces, opens the first one, and reports captured frames and
TCP/443 segments over 5 seconds. Non-zero TCP/443 while browsing = capture works.

## What was ported

| File | Linux implementation |
|---|---|
| `rawsock.rs` | `AF_PACKET`/`SOCK_RAW` capture, full Ethernet frames (`DLT_EN10MB`), `poll`-based non-busy read |
| `elevation.rs` | `is_elevated` = root or a probe `AF_PACKET` open (CAP_NET_RAW); `relaunch_elevated` via `pkexec` |
| `process_env.rs` | process discovery + env via `/proc/<pid>/{comm,exe,stat,environ}` |
| `launch.rs` | `steam` on `PATH` (or Flatpak), `steam -shutdown`, `SIGKILL` force-close |
| `config.rs` | Steam path from `~/.steam/steam`, `~/.local/share/Steam`, Flatpak |
| `credential_store.rs` | session token in a `0600` file in the data dir |

## Caveats

- Epic Games Launcher is not supported on Linux; use Steam.
- The tray icon and single-instance lock are no-ops on Linux (GUI still runs).

## Verified end-to-end

ARC Raiders under Proton **does** honor `SSLKEYLOGFILE`, and a full sync has
been confirmed on Linux (CachyOS, kernel 7.1.6, Wayland, Proton
`cachyos-11.0-20260703-slr`): the app
captured the gateway connection, decrypted it, and ARCTracker acknowledged the
account. Three things were checked rather than assumed:

- `lsof` on the key log shows the game's own `GameThread` holding write
  descriptors on it, so `PioneerGame.exe` writes to the file itself rather than
  something upstream of it doing so on its behalf. Proton's `python3` wrapper
  and wineserver hold descriptors too, and the header line is the one CPython
  writes, so they open it as well — which of them wrote any given secret was
  not established, only that the game is among the writers.
- The file accumulates TLS 1.3 secrets (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
  `SERVER_TRAFFIC_SECRET_0`, …) and keeps growing across a play session.
- With capture running, the app reached its synced state and reported the
  ARCTracker account name.

Note that capture only decrypts handshakes it actually saw: keys written before
the capture started are useless. Start the app first, then the game.

## Injecting the key log per game instead of per launcher

Steam's per-game **launch options** are an alternative to letting the app
restart Steam, and they avoid killing a running Steam session:

```
SSLKEYLOGFILE=/home/you/keylog.txt %command%
```

Launch the app with the same path in its environment and it resolves the source
as `ProcessEnv` and leaves the file alone:

```bash
SSLKEYLOGFILE=/home/you/keylog.txt ./target/release/arctracker-sync
```

Caveat: `launcher_readiness` confirms setup by reading `SSLKEYLOGFILE` out of
the *Steam* process, and launch options never reach it — only the game inherits
them. So the launcher step still asks to prepare Steam even though the setup is
already working. Selecting **Direct** in Settings skips that check.

A user-set key log is never truncated or deleted by the app (unlike the
app-owned one), so remember to remove it yourself: its contents decrypt every
TLS session the game made while it existed.
