<#
.SYNOPSIS
  Windows resource benchmarks for fail2commit (T-012, NFR-012, SPEC-012, TC-012).
.DESCRIPTION
  Builds release binaries (cargo -j 2) and measures: binary size, CLI startup
  cold/warm, guarded secret-scan, `scan` against a loopback OSV stub (empty vs
  warm cache), advisory cache size, and tray idle RAM after 60 s (working set
  and private bytes). Windows sandbox build memory is Pending until T-007b
  lands: bench.py probes `sandbox status` and records Pending while the
  AppContainer backend is unavailable, so a rerun needs no edits.
  Everything runs in disposable FAIL2COMMIT_HOME dirs and temp repos; the only
  network is loopback. Results: target/bench/windows.json and tray.json.
  Requires python 3 on PATH. Linux numbers: scripts/bench/run.sh.
.EXAMPLE
  powershell -File scripts/bench/run.ps1 -Runs 20
#>
param(
    [int]$Runs = 20,
    [int]$TraySeconds = 60,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$out = Join-Path $repo 'target\bench'
New-Item -ItemType Directory -Force $out | Out-Null
Write-Host "tested sha: $(git -C $repo rev-parse HEAD)"

if (-not $SkipBuild) {
    cargo build --release -j 2 -p fail2commit -p fail2commit-tray --manifest-path (Join-Path $repo 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit $LASTEXITCODE" }
}
$bin = Join-Path $repo 'target\release'
python -I (Join-Path $PSScriptRoot 'bench.py') measure --bin-dir $bin --out (Join-Path $out 'windows.json') --runs $Runs
if ($LASTEXITCODE -ne 0) { throw "bench.py failed with exit $LASTEXITCODE" }

# Tray idle RAM: temp FAIL2COMMIT_HOME, always closed afterwards.
$home_ = Join-Path ([IO.Path]::GetTempPath()) ("f2c-bench-tray-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $home_ | Out-Null
$env:FAIL2COMMIT_HOME = $home_
$tray = $null
try {
    $tray = Start-Process (Join-Path $bin 'fail2commit-tray.exe') -PassThru
    Start-Sleep -Seconds 5
    $early = Get-Process -Id $tray.Id
    $e = @{ working_set_bytes = $early.WorkingSet64; private_bytes = $early.PrivateMemorySize64 }
    Start-Sleep -Seconds ($TraySeconds - 5)
    $tray.Refresh()
    if ($tray.HasExited) { throw "tray exited early with code $($tray.ExitCode)" }
    $p = Get-Process -Id $tray.Id
    $res = [ordered]@{
        idle_seconds     = $TraySeconds
        at_5s            = $e
        at_idle          = @{ working_set_bytes = $p.WorkingSet64; private_bytes = $p.PrivateMemorySize64 }
        threads          = $p.Threads.Count
        handles          = $p.HandleCount
    }
    $res | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $out 'tray.json')
    $res | ConvertTo-Json -Depth 4
}
finally {
    if ($tray -and -not $tray.HasExited) { Stop-Process -Id $tray.Id -Force }
    Remove-Item Env:FAIL2COMMIT_HOME -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $home_ -ErrorAction SilentlyContinue
}
Write-Host "windows bench done: $out"
