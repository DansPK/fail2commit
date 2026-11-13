param(
    [Parameter(Mandatory=$true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $DiagnosticServiceBinary,
    [Parameter(Mandatory=$true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $WindowsTestBinary
)
$ErrorActionPreference='Stop'
$serviceName='fail2commit-hardened'
$expectedExe=Join-Path $env:ProgramFiles 'fail2commit-hardened\fail2commit.exe'
$dataDir=Join-Path $env:ProgramData 'fail2commit-hardened'
$statePath=Join-Path $dataDir 'install.json'
$fixtureDir=Join-Path $env:LOCALAPPDATA ('Temp\fr027-win10-diagnostic-'+[Guid]::NewGuid().ToString('N'))
$filter='sandbox::hardened::service::tests::disposable_win10_authenticated_service_lpac_launcher_diagnostic'
$evidenceDir=Join-Path $env:LOCALAPPDATA 'Temp\fr027-20261114'
function Assert-NoLiveLaunch {
    if (Test-Path -LiteralPath (Join-Path $dataDir 'active-launch.json')) { throw 'Active launch marker exists; refusing swap/restore.' }
    $jobs=Join-Path $dataDir 'jobs'
    if ((Test-Path -LiteralPath $jobs) -and @(Get-ChildItem -LiteralPath $jobs -Force).Count) { throw 'Snapshot jobs remain; refusing swap/restore.' }
    if (@(Get-CimInstance Win32_Process -Filter "Name='fail2commit.exe'" | Where-Object {$_.CommandLine -match '\bsandbox\s+launch\b'}).Count) { throw 'Launcher process remains; refusing swap/restore.' }
}
function Wait-Service([string]$Wanted) {
    $until=[DateTime]::UtcNow.AddSeconds(20)
    do { if ((Get-Service $serviceName).Status.ToString() -eq $Wanted) { return }; Start-Sleep -Milliseconds 100 } while ([DateTime]::UtcNow -lt $until)
    throw "Service did not reach $Wanted."
}
function Wait-ServicePipe {
    $name='fail2commit-hardened-'+$state.installer_sid
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    do {
        if ((Get-Service $serviceName).Status.ToString() -ne 'Running') { break }
        $pipe=$null
        try {
            $pipe=[IO.Pipes.NamedPipeClientStream]::new('.', $name, [IO.Pipes.PipeDirection]::InOut)
            $pipe.Connect(250)
            $pipe.ReadTimeout=1000
            $writer=[IO.StreamWriter]::new($pipe,[Text.Encoding]::ASCII,1024,$true)
            $reader=[IO.StreamReader]::new($pipe,[Text.Encoding]::ASCII,$false,1024,$true)
            $writer.AutoFlush=$true
            $writer.WriteLine('{"op":"STATUS"}')
            $reply=$reader.ReadLine() | ConvertFrom-Json
            if ($reply.service_running -and $reply.containment_confirmed) { return }
        } catch {
        } finally {
            if ($pipe) { $pipe.Dispose() }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Authenticated service pipe did not answer STATUS before its 20 second deadline.'
}
function Get-AceSidValue($Identity) {
    $value=$Identity.Value
    if ($value -match '^S-\d-') { return $value }
    $known=@{
        'Everyone'='S-1-1-0'
        'NT AUTHORITY\Authenticated Users'='S-1-5-11'
        'BUILTIN\Users'='S-1-5-32-545'
        'NT AUTHORITY\SYSTEM'='S-1-5-18'
        'BUILTIN\Administrators'='S-1-5-32-544'
        'CREATOR OWNER'='S-1-3-0'
    }
    if ($known.ContainsKey($value)) { return $known[$value] }
    try { return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { return "UNMAPPED:$value" }
}
$who=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated in disposable Win10.' }
$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.version -ne 1 -or $state.account -ne 'f2c-sandbox' -or $state.executable -ne $expectedExe -or -not $state.installer_sid -or -not $state.sandbox_sid) { throw 'Install state identity/path does not match.' }
$svc=Get-CimInstance Win32_Service | Where-Object {$_.Name -eq $serviceName}
$expectedCommand='"'+$expectedExe+'" sandbox serve'
if (-not $svc -or $svc.PathName -ne $expectedCommand -or $svc.StartMode -ne 'Auto' -or $svc.State -ne 'Running') { throw 'SCM path/config/state precondition failed.' }
$wasRunning=$svc.State -eq 'Running'
Assert-NoLiveLaunch
$exeAcl=Get-Acl -LiteralPath $expectedExe
$dirAcl=Get-Acl -LiteralPath (Split-Path -Parent $expectedExe)
$programFilesAcl=Get-Acl -LiteralPath $env:ProgramFiles
$stateAcl=Get-Acl -LiteralPath $statePath
$dataAcl=Get-Acl -LiteralPath $dataDir
foreach ($acl in @($stateAcl,$dataAcl)) {
    $owners=@($acl.Access | Where-Object {$_.AccessControlType -eq 'Allow'} | ForEach-Object {Get-AceSidValue $_.IdentityReference})
    if (-not ($owners -contains 'S-1-5-18') -or -not ($owners -contains 'S-1-5-32-544')) { throw 'Trusted install state/data ACL lacks SYSTEM or Administrators.' }
    if ($owners | Where-Object {$_ -notin @('S-1-5-18','S-1-5-32-544')}) { throw 'Trusted install state/data ACL grants an unexpected identity.' }
}
if ($exeAcl.Owner -notin @('BUILTIN\Administrators','NT AUTHORITY\SYSTEM')) { throw "Untrusted installed binary owner: $($exeAcl.Owner)" }
foreach ($acl in @($programFilesAcl,$dirAcl,$exeAcl)) {
    foreach ($ace in $acl.Access) {
        $sid=Get-AceSidValue $ace.IdentityReference
        if ($ace.AccessControlType -eq 'Allow' -and $sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')) {
            $bits=[int][Security.AccessControl.FileSystemRights]::WriteData -bor [int][Security.AccessControl.FileSystemRights]::AppendData -bor [int][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [int][Security.AccessControl.FileSystemRights]::WriteAttributes -bor [int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [int][Security.AccessControl.FileSystemRights]::Delete -bor [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor [int][Security.AccessControl.FileSystemRights]::TakeOwnership
            if (([int]$ace.FileSystemRights -band $bits) -ne 0) { throw 'Unprivileged write/delete/ACL-owner ACE on protected service path.' }
        }
    }
}
$oldHash=(Get-FileHash -LiteralPath $expectedExe -Algorithm SHA256).Hash
$newHash=(Get-FileHash -LiteralPath $DiagnosticServiceBinary -Algorithm SHA256).Hash
$started=$false
$restored=$false
$made=$false
$testExit=$null
try {
    New-Item -ItemType Directory -Path $fixtureDir | Out-Null
    $made=$true
    & "$env:SystemRoot\System32\icacls.exe" $fixtureDir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect fixture backup directory.' }
    $backup=Join-Path $fixtureDir 'original-service.exe'
    Copy-Item -LiteralPath $expectedExe -Destination $backup
    if ((Get-FileHash $backup -Algorithm SHA256).Hash -ne $oldHash) { throw 'Backup hash mismatch.' }
    [ordered]@{original_sha256=$oldHash; incoming_sha256=$newHash; executable=$expectedExe; owner=$exeAcl.Owner; sddl=$exeAcl.Sddl; directory_owner=$dirAcl.Owner; directory_sddl=$dirAcl.Sddl; service_command=$svc.PathName; start_mode=$svc.StartMode; installer_sid=$state.installer_sid; sandbox_sid=$state.sandbox_sid} | ConvertTo-Json -Compress | Set-Content (Join-Path $fixtureDir 'fixture.json') -Encoding ascii
    Stop-Service $serviceName -Force
    Wait-Service 'Stopped'
    Assert-NoLiveLaunch
    $stage=Join-Path (Split-Path -Parent $expectedExe) 'fail2commit.exe.fr027-new'
    Copy-Item -LiteralPath $DiagnosticServiceBinary -Destination $stage
    Set-Acl -LiteralPath $stage -AclObject $exeAcl
    if ((Get-FileHash $stage -Algorithm SHA256).Hash -ne $newHash) { throw 'Staging binary hash mismatch.' }
    $started=$true
    $swapBackup=Join-Path $fixtureDir 'swap-original.exe'
    [IO.File]::Replace($stage,$expectedExe,$swapBackup)
    $after=Get-Acl $expectedExe
    if ((Get-FileHash $expectedExe -Algorithm SHA256).Hash -ne $newHash -or $after.Owner -ne $exeAcl.Owner -or $after.Sddl -ne $exeAcl.Sddl) { throw 'Feature binary hash/owner/DACL mismatch.' }
    $afterSvc=Get-CimInstance Win32_Service | Where-Object {$_.Name -eq $serviceName}
    if ($afterSvc.PathName -ne $expectedCommand -or $afterSvc.StartMode -ne 'Auto') { throw 'SCM config changed.' }
    Start-Service $serviceName
    Wait-Service 'Running'
    Wait-ServicePipe
    $testLog=Join-Path $fixtureDir 'test-output.txt'
    $testError=Join-Path $fixtureDir 'test-error.txt'
    $testProcess=Start-Process -FilePath $WindowsTestBinary -ArgumentList @($filter,'--exact','--ignored','--nocapture') -Wait -PassThru -NoNewWindow -RedirectStandardOutput $testLog -RedirectStandardError $testError
    $testExit=$testProcess.ExitCode
    if ($testExit -ne 0) { throw "Service diagnostic test exited $testExit; see bounded fixture test output." }
    Assert-NoLiveLaunch
}
finally {
    if ($made -and $started) {
        if ((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Stopped') { Stop-Service $serviceName -Force; Wait-Service 'Stopped' }
        Assert-NoLiveLaunch
        $restore=Join-Path (Split-Path -Parent $expectedExe) 'fail2commit.exe.fr027-restore'
        Copy-Item -LiteralPath $backup -Destination $restore
        Set-Acl -LiteralPath $restore -AclObject $exeAcl
        $replacedDiagnostic=Join-Path $fixtureDir 'replaced-diagnostic.exe'
        [IO.File]::Replace($restore,$expectedExe,$replacedDiagnostic)
        $after=Get-Acl $expectedExe
        if ((Get-FileHash $expectedExe -Algorithm SHA256).Hash -ne $oldHash -or $after.Owner -ne $exeAcl.Owner -or $after.Sddl -ne $exeAcl.Sddl) { throw 'Restore verification failed; protected backup retained.' }
        $restored=$true
    }
    if ($wasRunning -and ($restored -or -not $started)) { Start-Service $serviceName; Wait-Service 'Running'; Wait-ServicePipe }
    if ($made -and ($restored -or -not $started)) {
        if ($restored -and (Test-Path -LiteralPath (Join-Path $fixtureDir 'test-output.txt'))) {
            Copy-Item -LiteralPath (Join-Path $fixtureDir 'test-output.txt') -Destination (Join-Path $evidenceDir 'diagnostic-output.txt') -Force
        }
        if ($restored -and (Test-Path -LiteralPath (Join-Path $fixtureDir 'test-error.txt'))) {
            Copy-Item -LiteralPath (Join-Path $fixtureDir 'test-error.txt') -Destination (Join-Path $evidenceDir 'diagnostic-error.txt') -Force
        }
        Remove-Item -LiteralPath $fixtureDir -Recurse -Force
    }
}
$summary=[pscustomobject]@{result='restored'; test_exit_code=$testExit; diagnostic_service_sha256=$newHash; restored_service_sha256=$oldHash; installer_sid=$state.installer_sid; sandbox_sid=$state.sandbox_sid; fixture_backup_removed=(-not (Test-Path $fixtureDir))}
$summary | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $evidenceDir 'diagnostic-result.json') -Encoding ascii
$summary | ConvertTo-Json -Compress
