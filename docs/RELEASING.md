# Releasing and code signing

Official Windows releases are code-signed with **Azure Artifact Signing**.
Signing is maintainer-only; contributors do not need Azure access to build,
test, or submit changes.

## What the release workflow does

Push a tag matching `v*.*.*` or run the Release workflow manually. The workflow
in `.github/workflows/release.yml`:

1. Builds `arctracker-sync.exe` with `cargo build --release --locked`.
2. Authenticates to Azure with GitHub OIDC through the `release` environment.
3. Signs the exe with `azure/artifact-signing-action@v2`.
4. Stages and zips the release, then writes `SHA256SUMS`.

Signing must happen before zipping and hashing. The in-app updater verifies the
zip against `SHA256SUMS`, so the hash must cover the already-signed exe.

## Values needed from Azure

From the Artifact Signing account / certificate profile:

| Value | Where it goes |
|---|---|
| Artifact Signing endpoint, for example `https://wus2.codesigning.azure.net` | GitHub variable `SIGNING_ENDPOINT`; local `scripts/sign-metadata.json` |
| Artifact Signing account name | GitHub variable `SIGNING_ACCOUNT_NAME`; local `scripts/sign-metadata.json` |
| Certificate profile name | GitHub variable `SIGNING_CERT_PROFILE_NAME`; local `scripts/sign-metadata.json` |
| Entra tenant ID | GitHub secret `AZURE_TENANT_ID` |
| Azure subscription ID | GitHub secret `AZURE_SUBSCRIPTION_ID` |
| App registration / service principal client ID | GitHub secret `AZURE_CLIENT_ID` |

No PFX, private key, or GitHub-stored client secret is required.

## GitHub Actions setup

Create a GitHub environment named `release`.

In repository settings, add these Actions secrets:

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID containing the signing account |
| `AZURE_CLIENT_ID` | App registration / service principal client ID |

Add these Actions variables:

| Variable | Value |
|---|---|
| `SIGNING_ENDPOINT` | Region endpoint for the Artifact Signing account |
| `SIGNING_ACCOUNT_NAME` | Artifact Signing account name |
| `SIGNING_CERT_PROFILE_NAME` | Certificate profile name |

In Azure, configure the app registration / service principal:

1. Add a federated credential for this repository's GitHub `release`
   environment. The subject is:

   ```text
   repo:RaidTheory/ARCTrackerSync:environment:release
   ```

2. Assign the service principal the **Artifact Signing Certificate Profile
   Signer** role on the signing account or certificate profile.
3. Confirm the Artifact Signing identity validation shows **Completed**.

The endpoint must match the Azure region where the Artifact Signing account and
certificate profile were created. A region mismatch commonly fails with 403.

Common US endpoints:

| Region | Endpoint |
|---|---|
| East US | `https://eus.codesigning.azure.net` |
| Central US | `https://cus.codesigning.azure.net` |
| West US | `https://wus.codesigning.azure.net` |
| West US 2 | `https://wus2.codesigning.azure.net` |
| West US 3 | `https://wus3.codesigning.azure.net` |

## Signing locally

One-time setup:

1. Install the client tools:

   ```powershell
   winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
   ```

   This installs SignTool, the Artifact Signing dlib, .NET 8 runtime, and the
   VC++ redistributable needed by SignTool.

2. Make sure your Azure user has the **Artifact Signing Certificate Profile
   Signer** role on the signing account or certificate profile.

3. Sign in locally:

   ```powershell
   az login
   ```

4. Copy `scripts/sign-metadata.example.json` to
   `scripts/sign-metadata.json`. The local metadata file is gitignored. Fill in:

   ```json
   {
     "Endpoint": "https://<region>.codesigning.azure.net",
     "CodeSigningAccountName": "<account name>",
     "CertificateProfileName": "<certificate profile name>"
   }
   ```

After a release build:

```powershell
cargo build --release --locked
powershell -ExecutionPolicy Bypass -File .\scripts\sign.ps1
```

The script signs `target\release\arctracker-sync.exe`, timestamps it, and runs
`signtool verify`.

You can also inspect the signature with:

```powershell
Get-AuthenticodeSignature target\release\arctracker-sync.exe
```

Expected status: `Valid`.

## Troubleshooting

- **Timestamping is not optional.** Artifact Signing certificates are short
  lived. The RFC 3161 timestamp keeps signatures valid after certificate
  rotation.
- **403 from the service** usually means the signer role is missing, the
  endpoint does not match the account region, the account/profile names are
  wrong, or identity validation is not completed.
- **No certificates were found that met all the given criteria** usually means
  SignTool is too old or the dlib path is wrong.
- **The file is still unsigned after SignTool runs** usually means the matching
  x64 .NET 8 runtime is missing.
- **SmartScreen still warns** can happen while reputation builds. Signing
  removes "Unknown publisher", but very new binaries can still prompt.
