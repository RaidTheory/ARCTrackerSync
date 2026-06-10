<#
.SYNOPSIS
    Signs release binaries with Azure Artifact Signing (signtool + Azure dlib).

.DESCRIPTION
    Maintainer-only tool; contributors never need this. One-time setup and
    troubleshooting live in docs/RELEASING.md. Authentication comes from your
    Azure CLI session (run `az login` first).

    Tool discovery can be overridden with environment variables:
      SIGNTOOL_PATH   full path to signtool.exe (Windows SDK >= 10.0.2261x)
      AZURE_SIGN_DLIB full path to Azure.CodeSigning.Dlib.dll

.PARAMETER Files
    Files to sign. Defaults to target\release\arctracker-sync.exe.

.EXAMPLE
    pwsh scripts/sign.ps1
.EXAMPLE
    pwsh scripts/sign.ps1 -Files target\release\arctracker-sync.exe
#>
[CmdletBinding()]
param(
    [string[]]$Files = @((Join-Path $PSScriptRoot '..\target\release\arctracker-sync.exe'))
)

$ErrorActionPreference = 'Stop'

$metadata = Join-Path $PSScriptRoot 'sign-metadata.json'
if (-not (Test-Path $metadata)) {
    throw ("Missing $metadata`n" +
        "Copy scripts\sign-metadata.example.json to scripts\sign-metadata.json and fill in " +
        "your signing account and certificate profile names (shown on the Artifact Signing " +
        "account's Overview page in the Azure portal). The file is gitignored.")
}

$Files = $Files | ForEach-Object {
    if (-not (Test-Path $_)) {
        throw "File not found: $_ (run 'cargo build --release --locked' first?)"
    }
    (Resolve-Path $_).Path
}

# Returns the best match for a tool: wildcard patterns first (newest version
# dir wins via descending path sort), then a recursive search of install roots.
function Find-Tool {
    param(
        [string[]]$WildcardPatterns,
        [string[]]$SearchRoots,
        [string]$FileName
    )
    foreach ($pattern in $WildcardPatterns) {
        $hits = @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending)
        if ($hits.Count -gt 0) { return $hits[0].FullName }
    }
    foreach ($rootPattern in $SearchRoots) {
        foreach ($root in @(Resolve-Path $rootPattern -ErrorAction SilentlyContinue)) {
            $hits = @(Get-ChildItem -Path $root -Recurse -Filter $FileName -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\' } |
                Sort-Object FullName -Descending)
            if ($hits.Count -gt 0) { return $hits[0].FullName }
        }
    }
    return $null
}

# Install roots used by `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`
# (exact folder name has shifted across the Trusted Signing -> Artifact Signing rename).
$clientToolsRoots = @(
    "$env:ProgramFiles\Microsoft*Artifact*Signing*",
    "$env:ProgramFiles\Microsoft*Trusted*Signing*",
    "${env:ProgramFiles(x86)}\Microsoft*Artifact*Signing*",
    "$env:LOCALAPPDATA\Microsoft*Artifact*Signing*"
)

$signtool = $env:SIGNTOOL_PATH
if (-not $signtool) {
    $signtool = Find-Tool -FileName 'signtool.exe' -WildcardPatterns @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.*\x64\signtool.exe",
        "$env:USERPROFILE\.nuget\packages\microsoft.windows.sdk.buildtools\*\bin\10.0.*\x64\signtool.exe"
    ) -SearchRoots $clientToolsRoots
}
if (-not $signtool -or -not (Test-Path $signtool)) {
    throw ("signtool.exe not found. Install the Artifact Signing client tools:`n" +
        "  winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`n" +
        "or install a Windows SDK >= 10.0.2261x, or set SIGNTOOL_PATH.")
}

$dlib = $env:AZURE_SIGN_DLIB
if (-not $dlib) {
    $dlib = Find-Tool -FileName 'Azure.CodeSigning.Dlib.dll' -WildcardPatterns @(
        "$env:USERPROFILE\.nuget\packages\microsoft.artifactsigning.client\*\bin\x64\Azure.CodeSigning.Dlib.dll",
        "$env:USERPROFILE\.nuget\packages\microsoft.trusted.signing.client\*\bin\x64\Azure.CodeSigning.Dlib.dll"
    ) -SearchRoots $clientToolsRoots
}
if (-not $dlib -or -not (Test-Path $dlib)) {
    throw ("Azure.CodeSigning.Dlib.dll not found. Install the Artifact Signing client tools:`n" +
        "  winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`n" +
        "or `nuget install Microsoft.ArtifactSigning.Client`, or set AZURE_SIGN_DLIB.")
}

Write-Host "signtool: $signtool"
Write-Host "dlib:     $dlib"
Write-Host "metadata: $metadata"

# Timestamping is mandatory: Artifact Signing certificates live ~3 days and
# rotate automatically; only the timestamp keeps signatures valid after that.
& $signtool sign /v /fd SHA256 `
    /tr 'http://timestamp.acs.microsoft.com' /td SHA256 `
    /dlib $dlib /dmdf $metadata @Files
if ($LASTEXITCODE -ne 0) {
    throw ("signtool sign failed (exit $LASTEXITCODE). Check: az login session, " +
        "'Artifact Signing Certificate Profile Signer' role, account/profile names in " +
        "sign-metadata.json, and that the x64 .NET 8 runtime is installed.")
}

foreach ($f in $Files) {
    & $signtool verify /pa /v $f
    if ($LASTEXITCODE -ne 0) {
        throw "Signature verification failed for $f (exit $LASTEXITCODE)."
    }
}

Write-Host ''
Write-Host "Signed and verified:`n  $($Files -join "`n  ")"
