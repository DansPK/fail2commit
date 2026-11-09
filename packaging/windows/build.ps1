<#
.SYNOPSIS
  Builds the per-user fail2commit Setup.exe with NSIS (T-009, FR-009).

.DESCRIPTION
  1. cargo build --release for the CLI and the tray (skip with -SkipCargo).
  2. Stage the files the installer ships under target\dist\stage.
  3. Run makensis. Looks for -Makensis, then a portable copy under
     target\nsis\nsis-*\makensis.exe, then makensis on PATH.

  Nothing is installed system-wide. A portable NSIS can be unpacked from the
  official SourceForge zip into target\nsis (see docs\windows.md for the
  recorded SHA-256).
#>
param(
  [string]$Version = "0.1.0",
  [string]$Makensis = "",
  [switch]$SkipCargo
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $root

if (-not $SkipCargo) {
  cargo build --release -p fail2commit -p fail2commit-tray
  if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
}

if (-not $Makensis) {
  $portable = Get-ChildItem -Path (Join-Path $root "target\nsis") -Filter makensis.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch "\\Bin\\" } | Select-Object -First 1
  if ($portable) { $Makensis = $portable.FullName }
  else {
    $cmd = Get-Command makensis -ErrorAction SilentlyContinue
    if ($cmd) { $Makensis = $cmd.Source }
  }
}
if (-not $Makensis -or -not (Test-Path $Makensis)) {
  throw "makensis not found: pass -Makensis, unpack NSIS under target\nsis, or put makensis on PATH"
}

$dist = Join-Path $root "target\dist"
$stage = Join-Path $dist "stage"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force (Join-Path $stage "docs") | Out-Null
$rel = Join-Path $root "target\release"
foreach ($f in "fail2commit.exe", "fail2commit-tray.exe") {
  Copy-Item (Join-Path $rel $f) $stage
}
# The binaries carry third-party code whose licenses require these notices.
Copy-Item (Join-Path $root "LICENSE") $stage
Copy-Item (Join-Path $root "NOTICE") $stage
Copy-Item (Join-Path $root "asset\logo.ico") $stage
Copy-Item (Join-Path $root "THIRD-PARTY-NOTICES.md") (Join-Path $stage "THIRD-PARTY-NOTICES.txt")
Copy-Item (Join-Path $root "docs\windows.md") (Join-Path $stage "docs")

$out = Join-Path $dist "fail2commit-$Version-setup.exe"
& $Makensis /V2 "/DVERSION=$Version" "/DSTAGE=$stage" "/DOUTFILE=$out" (Join-Path $PSScriptRoot "fail2commit.nsi")
if ($LASTEXITCODE -ne 0) { throw "makensis failed ($LASTEXITCODE)" }

$hash = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLower()
Write-Output "built $out"
Write-Output "sha256 $hash"
