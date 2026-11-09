# Supply-chain attack simulation on the disposable Windows VM, as the normal
# signed-in user. Plants synthetic secrets, runs four malicious installs
# through fail2commit, checks every side effect, then runs the worm without
# fail2commit as a positive control (the VM is reverted afterwards).
$ErrorActionPreference = 'Continue'
$A = 'C:\f2c\atk'; $H = $env:USERPROFILE; $S = 'C:\f2c\atk-state'; $V = "$H\victim"
$env:Path = 'C:\f2c\mingit\cmd;' + [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')
function Kv($k, $v) { Write-Output ("{0}={1}" -f $k, $v) }
Remove-Item -Recurse -Force $S, $V, "$H\victim-remote.git" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $S, "$H\.ssh", "$H\.aws", "$H\AppData\Roaming\GitHub CLI", "$env:APPDATA\fail2commit" | Out-Null
# synthetic secrets (never real)
Set-Content "$H\.npmrc" '//registry.npmjs.org/:_authToken=npm_F2CSYNTHETICTOKEN000000000000000000' -Encoding ascii
Set-Content "$H\.ssh\id_ed25519" "-----BEGIN OPENSSH PRIVATE KEY-----`nF2C-SYNTHETIC-KEY`n-----END OPENSSH PRIVATE KEY-----" -Encoding ascii
Set-Content "$H\.aws\credentials" "[default]`naws_access_key_id = AKIAF2CSYNTHETIC0000`naws_secret_access_key = f2cSyntheticSecret" -Encoding ascii
Set-Content "$H\.git-credentials" 'https://dev:ghp_F2CSYNTHETIC000000000000000000000000@github.com' -Encoding ascii
Set-Content "$H\AppData\Roaming\GitHub CLI\hosts.yml" "github.com:`n  oauth_token: gho_F2CSYNTHETIC" -Encoding ascii
Set-Content "$env:APPDATA\fail2commit\npmrc" 'registry=http://127.0.0.1:4873/' -Encoding ascii
Set-Content "$env:APPDATA\fail2commit\settings.toml" "[advisories]`nosv_url = `"http://127.0.0.1:4874`"" -Encoding ascii
# the user's real project with a remote
git init -q --bare "$H\victim-remote.git"; git init -q $V; Set-Location $V
git config user.email dev@example.test; git config user.name dev
Set-Content package.json '{"name":"victim","version":"1.0.0"}' -Encoding ascii; Set-Content index.js 'console.log("app")' -Encoding ascii
git add -A; git commit -qm init; git remote add origin "$H\victim-remote.git"; git push -q origin HEAD:main 2>&1 | Out-Null
$startup = "$H\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
function Snap {
    $b = if (Test-Path "$H\.bashrc") { (Get-FileHash "$H\.bashrc").Hash.Substring(0, 12) } else { 'absent' }
    $run = [bool](Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).f2cAttackSim
    "bashrc=$b startup=$((Get-ChildItem $startup -Name -ErrorAction SilentlyContinue) -join ',') runkey=$run index=$((Get-FileHash "$V\index.js").Hash.Substring(0, 12)) workflow=$(Test-Path "$V\.github") remote=$(git --git-dir "$H\victim-remote.git" rev-parse main)"
}
$before = Snap
$world = Start-Process python -ArgumentList '-I', "$A\attack_world.py", $S, $H, $V -PassThru -WindowStyle Hidden
for ($i = 0; $i -lt 50 -and -not (Test-Path "$S\ready"); $i++) { Start-Sleep -Milliseconds 200 }
$env:NPM_TOKEN = 'npm_F2CSYNTHETICENV'; $env:GITHUB_TOKEN = 'ghp_F2CSYNTHETICENV'; $env:AWS_SECRET_ACCESS_KEY = 'f2cSyntheticEnv'
$f2c = "$env:LOCALAPPDATA\Programs\fail2commit\fail2commit.exe"
foreach ($p in 'lodahs', 'deploy-helper', 'ua-parse-lite', 'color-utils-pro') {
    $out = & $f2c --json --approver none npm install $p 2>&1 | Out-String
    Kv "${p}_exit" $LASTEXITCODE
    try { $j = $out | ConvertFrom-Json; Kv "${p}_result" ("{0} | {1} | {2}" -f $j.code, ($j.message -replace '\s+', ' ').Substring(0, [Math]::Min(160, $j.message.Length)), (($j.findings | ForEach-Object { "$($_.kind)/$($_.action)" }) -join ',')) } catch { Kv "${p}_result" ($out -replace '\s+', ' ') }
    $rp = "$V\node_modules\$p\build\report.json"
    Kv "${p}_report" $(if (Test-Path $rp) { Get-Content $rp -Raw } else { 'none' })
}
Kv 'lodahs_api_approve' (& python -I "$A\approve.py" $V approve_once npm install lodahs)
$after = Snap
Kv 'before' $before
Kv 'after' $after
Kv 'host_unchanged' $(if ($before -eq $after) { 'yes' } else { 'NO' })
Kv 'canary_connections' $(if (Test-Path "$S\canary-conns.txt") { Get-Content "$S\canary-conns.txt" } else { 0 })
Kv 'installed' ((Get-ChildItem "$V\node_modules" -Name -ErrorAction SilentlyContinue) -join ' ')
# Positive control: the worm without fail2commit.
New-Item -ItemType Directory -Force "$S\control" | Out-Null
curl.exe -s -o "$S\control\w.tgz" http://127.0.0.1:4873/tarballs/color-utils-pro-1.0.0.tgz
tar -xzf "$S\control\w.tgz" -C "$S\control"
Push-Location "$S\control\package"; & node bundle.js 2>&1 | Out-Null; Pop-Location
Kv 'control_unguarded_report' $(if (Test-Path "$S\control\package\build\report.json") { Get-Content "$S\control\package\build\report.json" -Raw } else { 'none' })
Kv 'control_after' (Snap)
Kv 'control_canary_connections' $(if (Test-Path "$S\canary-conns.txt") { Get-Content "$S\canary-conns.txt" } else { 0 })
Stop-Process -Id $world.Id -Force -ErrorAction SilentlyContinue
