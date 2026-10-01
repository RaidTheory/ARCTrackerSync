# ARCTracker Sync

> **Retired.** ARC Tracker Link replaces ARCTracker Sync.
> Get it at https://arctracker.io/app#link.
> The final release (0.3.0; 0.2.0 was the last syncing release) only shows a retirement screen with a link to ARC Tracker Link; it no longer syncs anything or checks for updates.

Windows-first desktop helper for ARCTracker inventory sync.

ARCTracker Sync signs you into ARCTracker, prepares your game launcher, watches locally for the game account connection, and lets ARCTracker resume inventory updates.

The app does not save game account credentials locally. It keeps setup data local and only sends ARCTracker the account connection update required for sync.

## Runtime behavior

- Choose your launcher. Steam can launch ARC Raiders without selecting the game file.
- Epic Games support can remember the selected game file when needed.
- ARCTracker sign-in is remembered with Windows Credential Manager.
- Prepare your launcher, then start ARC Raiders from Steam or Epic. ARCTracker Sync connects your game account automatically while you play.
- The main screen shows sign-in, game selection, launch, account connection, and inventory sync status.
- Support details are hidden by default and can be opened when troubleshooting is needed.
- The ARCTracker API base URL is `https://arctracker.io`.

## Development

```powershell
cargo build --manifest-path apps\arctracker-sync\Cargo.toml
cargo run --manifest-path apps\arctracker-sync\Cargo.toml
```

Network monitoring uses Windows raw sockets (`SIO_RCVALL`), so the app must run as Administrator (it ships with a manifest that requests elevation). No kernel driver, bundled network library, or external analyzer tools are required.

Desktop sign-in requires the ARCTracker web deployment to have matching bridge signing keys:

- `AUTH_BRIDGE_PRIVATE_KEY_PEM` on the web runtime
- `AUTH_BRIDGE_PUBLIC_KEY_PEM` on the web runtime
