#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pesterManifest = Get-Module -ListAvailable Pester |
    Where-Object Version -GE '5.0.0' |
    Sort-Object Version -Descending |
    Select-Object -First 1
if (-not $pesterManifest) {
    $pesterManifest = Get-ChildItem -LiteralPath (Join-Path $root '.test-runtime/Modules/Pester') `
        -Recurse -Filter Pester.psd1 -ErrorAction SilentlyContinue |
        Where-Object { [version]$_.Directory.Name -ge [version]'5.0.0' } |
        Sort-Object { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
}
if (-not $pesterManifest) { throw 'Pester 5 or newer is required to run the unit suite.' }

$pesterPath = if ($pesterManifest -is [IO.FileInfo]) { $pesterManifest.FullName } else { $pesterManifest.Path }
Import-Module $pesterPath -Force
$result = Invoke-Pester -Path (Join-Path $root 'tests') -PassThru
if ($result.FailedCount -or $result.FailedContainersCount) {
    throw "$($result.FailedCount) Pester test(s) failed under PowerShell $($PSVersionTable.PSVersion)."
}
Write-Host "PowerShell $($PSVersionTable.PSVersion) passed $($result.PassedCount) Pester tests." -ForegroundColor Green
