<#
.SYNOPSIS
  Linux build and real-sandbox test harness for fail2commit (T-007a, FR-007).
.DESCRIPTION
  container : fmt, clippy and `cargo test --workspace` in the rust:1 Docker
              image (named target volume), then bundle every test binary
              plus the fail2commit CLI into target/linux-bundle/bundle.
  wsl       : run the bundle in WSL (real bwrap and user namespaces; no
              cargo or gcc needed there).
  privileged: run the bundle in a privileged rust:1 container with
              bubblewrap installed, as an unprivileged user.
  See docs/sandbox-linux.md.
.EXAMPLE
  powershell -File scripts/linux/test.ps1 -Volume f2c-t007a -Stage container,wsl -Gcc -Filter '^(sandbox_linux|run_)'
#>
param(
    [string]$Volume = 'f2c-shared',
    # container, wsl, privileged; comma-separated also works with -File.
    [string[]]$Stage = @('container', 'wsl'),
    [string]$Distro = 'Ubuntu',
    # Regex on test binary names for the wsl/privileged stages; empty = all.
    [string]$Filter = '',
    # Stage a relocatable gcc sysroot for the native build test in WSL.
    [switch]$Gcc,
    # Skip fmt/clippy/test in the container; only build the bundle.
    [switch]$NoCheck
)
$ErrorActionPreference = 'Stop'
$Stage = @($Stage | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
foreach ($s in $Stage) {
    if ($s -notin @('container', 'wsl', 'privileged')) { throw "unknown stage '$s'" }
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$out = Join-Path $repo 'target\linux-bundle'
New-Item -ItemType Directory -Force $out | Out-Null
Write-Host "tested sha: $(git -C $repo rev-parse HEAD)"

function Invoke-Rust([string[]]$DockerArgs, [string[]]$Command) {
    $common = @('run', '--rm',
        '-v', "${repo}:/src", '-v', "${Volume}-target:/target",
        '-v', 'f2c-rustup:/usr/local/rustup', '-v', 'f2c-cargo-registry:/usr/local/cargo/registry',
        '-v', "${out}:/out", '-e', 'CARGO_TARGET_DIR=/target', '-e', 'CARGO_BUILD_JOBS=2', '-w', '/src')
    & docker @($common + $DockerArgs + @('rust:1') + $Command)
    if ($LASTEXITCODE -ne 0) { throw "docker step failed with exit $LASTEXITCODE" }
}

$filterArgs = @()
if ($Filter) { $filterArgs = @($Filter) }

if ($Stage -contains 'container') {
    $opts = @()
    if ($NoCheck) { $opts += '--no-check' }
    if ($Gcc) { $opts += '--gcc' }
    Invoke-Rust @() (@('bash', 'scripts/linux/container.sh', '/out') + $opts)
}
if ($Stage -contains 'wsl') {
    $bundle = (& wsl -d $Distro -- wslpath -a ($out -replace '\\', '/')).Trim() + '/bundle'
    $runner = (& wsl -d $Distro -- wslpath -a ((Join-Path $repo 'scripts\linux\run-bundle.sh') -replace '\\', '/')).Trim()
    # --exec: no shell in between, so the filter regex arrives verbatim.
    & wsl -d $Distro --exec bash $runner $bundle @filterArgs
    if ($LASTEXITCODE -ne 0) { throw "WSL bundle run failed with exit $LASTEXITCODE" }
}
if ($Stage -contains 'privileged') {
    Invoke-Rust @('--privileged') (@('bash', 'scripts/linux/privileged.sh', '/out/bundle') + $filterArgs)
}
Write-Host 'linux harness: all requested stages passed'
