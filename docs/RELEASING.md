# Releasing & code signing (maintainers)

Official releases are code-signed with **Azure Artifact Signing** (formerly
Trusted Signing). Signing is done internally by maintainers with access to the
Azure signing account — **contributors never need any of this** to build, test,
or submit changes.

## How releases work

Push a tag matching `v*.*.*` (or run the Release workflow manually). The
workflow in `.github/workflows/release.yml`:

1. Builds `arctracker-sync.exe` with `cargo build --release --locked`
2. Signs the exe via `azure/artifact-signing-action@v2`
3. Stages and zips the release, then writes `SHA256SUMS`

Signing happens **before** zipping/hashing because the in-app self-updater
verifies the zip against `SHA256SUMS` — the hash must cover the signed exe.

## CI configuration (GitHub repo settings)

Secrets (Settings → Secrets and variables → Actions → Secrets):

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_CLIENT_ID` | App registration (service principal) client ID |
| `AZURE_CLIENT_SECRET` | Client secret for that app registration |

Variables (same page → Variables):

| Variable | Value |
|---|---|
| `SIGNING_ACCOUNT_NAME` | Artifact Signing account name |
| `SIGNING_CERT_PROFILE_NAME` | Certificate profile name |

Azure side: the service principal needs the **"Artifact Signing Certificate
Profile Signer"** role on the signing account (Access control / IAM), and the
account's identity validation must show **Completed** — signing returns 403
otherwise. The endpoint in the workflow (`https://wus2.codesigning.azure.net`)
must match the account's region (West US 2).

## Signing locally

One-time setup:

1. Install the client tools (signtool, the Azure dlib, .NET 8 runtime,
   VC++ redistributable):

   ```powershell
   winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
   ```

2. Make sure your own Azure account has the **"Artifact Signing Certificate
   Profile Signer"** role on the signing account, then sign in:

   ```powershell
   az login
   ```

3. Copy `scripts/sign-metadata.example.json` to `scripts/sign-metadata.json`
   (gitignored) and fill in the account and certificate profile names from the
   signing account's Overview page in the Azure portal.

Then, after a release build:

```powershell
cargo build --release --locked
pwsh scripts/sign.ps1
```

The script signs `target\release\arctracker-sync.exe`, timestamps it, and
verifies the result. Check manually with:

```powershell
Get-AuthenticodeSignature target\release\arctracker-sync.exe
```

Status should be `Valid` with a chain under "Microsoft ID Verified Code
Signing PCA 2021".

## Troubleshooting

- **Timestamping is not optional.** Artifact Signing certificates are valid
  for ~3 days and rotate automatically; only the RFC 3161 timestamp
  (`http://timestamp.acs.microsoft.com`) keeps signatures valid afterward.
  Both the script and the workflow always timestamp.
- **signtool "succeeds" but the file is unsigned** — the x64 .NET 8 runtime is
  missing (signtool fails silently without it). The winget package installs it.
- **"No certificates were found that met all the given criteria"** — signtool
  is too old (needs Windows SDK ≥ 10.0.2261x) or the dlib path is wrong.
- **403 from the service** — check the signer role assignment, the
  endpoint-region match, the exact account/profile names, and the account's
  identity validation status.
- **SmartScreen still warns** — reputation accrues per release; signing removes
  "Unknown publisher" but brand-new binaries can prompt until download history
  builds. Persistent warnings: submit the signed file to Microsoft Security
  Intelligence.
