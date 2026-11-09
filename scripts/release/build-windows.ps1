[CmdletBinding()]
param(
    [string]$OutDir = "target/dist"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$OutPath = Join-Path $RepoRoot $OutDir
$TargetPath = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $RepoRoot "target" }
$Separator = [char]0x1f

$env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1"
$env:CARGO_PROFILE_RELEASE_DEBUG = "0"
$env:CARGO_PROFILE_RELEASE_INCREMENTAL = "false"
$env:CARGO_PROFILE_RELEASE_LTO = "true"
$env:CARGO_PROFILE_RELEASE_STRIP = "symbols"
$env:CARGO_ENCODED_RUSTFLAGS = "--remap-path-prefix=$RepoRoot=C:\src\fail2commit${Separator}--remap-path-prefix=$TargetPath=C:\src\fail2commit-target"

New-Item -ItemType Directory -Force -Path $OutPath | Out-Null
Push-Location $RepoRoot
try {
    cargo build --release --locked -p fail2commit
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    Copy-Item -Force (Join-Path $TargetPath "release/fail2commit.exe") (Join-Path $OutPath "fail2commit-windows-x86_64.exe")
    # The standalone binary ships with the notices its licenses require.
    foreach ($n in "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.md") {
        Copy-Item -Force (Join-Path $RepoRoot $n) (Join-Path $OutPath $n)
    }
}
finally {
    Pop-Location
}
