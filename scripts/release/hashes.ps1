[CmdletBinding()]
param(
    [string]$Dist = "target/dist"
)

$ErrorActionPreference = "Stop"
$DistPath = (Resolve-Path $Dist).Path
$RelativePaths = @(Get-ChildItem -LiteralPath $DistPath -File -Recurse |
    Where-Object { $_.Name -ne "SHA256SUMS" } |
    ForEach-Object {
        $_.FullName.Substring($DistPath.Length + 1).Replace('\', '/')
    })
[Array]::Sort($RelativePaths, [StringComparer]::Ordinal)
$Lines = @($RelativePaths | ForEach-Object {
        $FilePath = Join-Path $DistPath $_.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FilePath).Hash.ToLowerInvariant()
        "$Hash  $_"
    })
$Content = if ($Lines.Count -gt 0) { ($Lines -join "`n") + "`n" } else { "" }
[System.IO.File]::WriteAllText((Join-Path $DistPath "SHA256SUMS"), $Content, [System.Text.UTF8Encoding]::new($false))
