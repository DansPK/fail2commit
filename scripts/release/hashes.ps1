[CmdletBinding()]
param(
    [string]$Dist = "target/dist"
)

$ErrorActionPreference = "Stop"
$DistPath = (Resolve-Path $Dist).Path
$Lines = Get-ChildItem -LiteralPath $DistPath -File -Recurse |
    Where-Object { $_.Name -ne "SHA256SUMS" } |
    Sort-Object { $_.FullName.Substring($DistPath.Length + 1).Replace('\', '/') } |
    ForEach-Object {
        $Relative = $_.FullName.Substring($DistPath.Length + 1).Replace('\', '/')
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
        "$Hash  $Relative"
    }
[System.IO.File]::WriteAllLines((Join-Path $DistPath "SHA256SUMS"), $Lines, [System.Text.UTF8Encoding]::new($false))
