#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'This compatibility check requires Windows PowerShell 5.1 or newer.' }

$testRoot = Join-Path ([IO.Path]::GetTempPath()) "fastpas-ps51-test-$([guid]::NewGuid().ToString('N'))"
$previousDataRoot = $env:FASTPAS_DATA_ROOT
try {
    $env:FASTPAS_DATA_ROOT = Join-Path $testRoot 'data'

    $manifest = Import-PowerShellDataFile (Join-Path $root 'FastPAS.PowerShell.psd1')
    if ([version]$manifest.PowerShellVersion -gt [version]'5.1') {
        throw "The module manifest requires PowerShell $($manifest.PowerShellVersion) instead of 5.1."
    }
    $entryScript = Get-Content -LiteralPath (Join-Path $root 'FastPAS.ps1') -Raw
    if ($entryScript -match '#requires\s+-Version\s+7' -or $entryScript -match 'requires PowerShell 7') {
        throw 'FastPAS.ps1 still contains a PowerShell 7 startup gate.'
    }
    $launcher = Get-Content -LiteralPath (Join-Path $root 'Run-FastPAS.cmd') -Raw
    if ($launcher -notmatch 'WindowsPowerShell\\v1\.0\\powershell\.exe') {
        throw 'Run-FastPAS.cmd does not contain the Windows PowerShell 5.1 fallback.'
    }

    $runtimeFiles = @(
        (Join-Path $root 'FastPAS.ps1')
        (Join-Path $root 'FastPAS.PowerShell.psm1')
        (Get-ChildItem -LiteralPath (Join-Path $root 'Commands') -Filter '*.ps1' -File -Recurse | Select-Object -ExpandProperty FullName)
        (Get-ChildItem -LiteralPath (Join-Path $root 'ui') -Filter '*.ps1' -File -Recurse | Select-Object -ExpandProperty FullName)
    )
    foreach ($runtimeFile in $runtimeFiles) {
        $tokens = $null
        $parseErrors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($runtimeFile, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count) {
            throw "Windows PowerShell 5.1 cannot parse $runtimeFile`: $($parseErrors[0].Message)"
        }
    }

    Import-Module (Join-Path $root 'FastPAS.PowerShell.psd1') -Force

    $commands = @(Get-FastPASCommand)
    if ($commands.Count -ne 47) { throw "PowerShell 5.1 loaded $($commands.Count) commands instead of 47." }

    $profile = New-FastPASProfile -Name PS51Compatibility -DeploymentType onprem `
        -PVWAUrl 'https://pvwa.example.invalid' -AuthType cyberark -Username compatibility-user
    if ($profile.VaultApiBaseUrl -ne 'https://pvwa.example.invalid/PasswordVault/API') {
        throw 'PowerShell 5.1 profile URL normalization failed.'
    }

    $context = [pscustomobject]@{
        Profile = $profile
        DeploymentType = 'onprem'
        PlatformToken = 'compatibility-test-token'
        ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(5)
        CorrelationId = 'ps51-compatibility'
        NonInteractive = $true
        Disconnected = $false
    }
    $result = Invoke-FastPASCommand -Id troubleshooting.dependencies -Context $context `
        -OutputPath (Join-Path $testRoot 'output') -NonInteractive
    if (-not $result.Success -or -not (Test-Path -LiteralPath $result.Artifacts[0])) {
        throw 'PowerShell 5.1 command execution or report export failed.'
    }

    $secretComparison = & (Get-Module FastPAS.PowerShell) {
        [pscustomobject]@{
            Equal = Test-FastPASSecretMatch 'same-value' 'same-value'
            Different = Test-FastPASSecretMatch 'same-value' 'different-value'
        }
    }
    if (-not $secretComparison.Equal -or $secretComparison.Different) {
        throw 'PowerShell 5.1 fixed-time secret comparison failed.'
    }

    Write-Host "Windows PowerShell $($PSVersionTable.PSVersion) compatibility passed for $($commands.Count) commands." -ForegroundColor Green
}
finally {
    Remove-Module FastPAS.PowerShell -Force -ErrorAction SilentlyContinue
    if ($null -eq $previousDataRoot) { Remove-Item Env:FASTPAS_DATA_ROOT -ErrorAction SilentlyContinue }
    else { $env:FASTPAS_DATA_ROOT = $previousDataRoot }

    $fullTestRoot = [IO.Path]::GetFullPath($testRoot)
    $fullTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($fullTestRoot.StartsWith($fullTempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $fullTestRoot)) {
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
    }
}
