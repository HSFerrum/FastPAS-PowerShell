#requires -Version 7.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$allParseIssues = @(Get-ChildItem -LiteralPath $root -Recurse -File -Include *.ps1, *.psm1, *.psd1 |
        Where-Object { $_.FullName -notlike "$(Join-Path $root '.test-runtime')*" } |
        ForEach-Object {
            $errors = $null;
            $tokens = $null
            [void][Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
            foreach ($parseIssue in @($errors)) {
                "$($_.FullName):$($parseIssue.Extent.StartLineNumber): $($parseIssue.Message)"
            }
        })
if ($allParseIssues.Count) {
    $allParseIssues | ForEach-Object { Write-Error $_ }
    throw 'PowerShell parser validation failed.'
}
Import-Module (Join-Path $root 'FastPAS.PowerShell.psd1') -Force
$commands = @(Get-FastPASCommand)
$expectedSections = @('Telemetry and Reports', 'Bulk Actions', 'Safe Management', 'Account Management', 'Platform Management', 'Troubleshooting and Tools')
if ((@(Get-FastPASMenuSection) -join '|') -ne ($expectedSections -join '|')) { throw 'Main-menu section order does not match the expected catalog.' }
if ($commands.Count -ne 46) { throw "Expected 46 cataloged commands, but found $($commands.Count)." }
if (@($commands.Id | Group-Object | Where-Object Count -GT 1).Count) { throw 'The command catalog contains duplicate command IDs.' }
foreach ($command in $commands) {
    $path = Join-Path $root $command.Script
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Catalog entry '$($command.Id)' points to missing script '$path'." }
    if ([string]::IsNullOrWhiteSpace($command.Description)) { throw "Catalog entry '$($command.Id)' does not have an operator description." }
    if ($command.RiskLevel -notin @('Read', 'Write')) { throw "Catalog entry '$($command.Id)' has an invalid risk level." }
    if (-not @($command.Deployments).Count -or @($command.Deployments | Where-Object { $_ -notin @('ispss', 'onprem', 'standalone') }).Count) { throw "Catalog entry '$($command.Id)' has invalid deployment compatibility metadata." }
    if ($command.Category -notin $command.Sections) { throw "Catalog entry '$($command.Id)' is not listed in its primary category." }
    if ($command.MenuGroup -ne $(if ($command.RiskLevel -eq 'Write') { 'Changes and repair actions' } else { 'Read-only reports and inspection' })) { throw "Catalog entry '$($command.Id)' is in the wrong risk menu." }
    foreach ($parameterName in @($command.Parameters)) {
        if ([string]::IsNullOrWhiteSpace([string]$command.ParameterHelp[$parameterName])) { throw "Catalog entry '$($command.Id)' has no help for parameter '$parameterName'." }
    }
    foreach ($requiredName in @($command.RequiredParameters)) {
        if ([string]::IsNullOrWhiteSpace([string]$requiredName)) { continue }
        if ($requiredName -notin $command.Parameters) { throw "Catalog entry '$($command.Id)' marks unknown parameter '$requiredName' as required." }
    }
    if ($command.Template -and -not (Test-Path -LiteralPath (Join-Path $root "templates/csv/$($command.Template)") -PathType Leaf)) { throw "Catalog entry '$($command.Id)' points to missing template '$($command.Template)'." }
    $scriptText = Get-Content -LiteralPath $path -Raw
    foreach ($contractParameter in 'Context', 'Arguments', 'OutputPath', 'NonInteractive', 'Force') {
        $parameterPattern = [regex]::Escape("`$$contractParameter") + '\b'
        if ($scriptText -notmatch $parameterPattern) { throw "Command script '$($command.Script)' is missing orchestration parameter '$contractParameter'." }
    }
    if ($command.RiskLevel -eq 'Write' -and $scriptText -notmatch '\$PSCmdlet\.ShouldProcess') { throw "Write command '$($command.Id)' does not guard its mutations with ShouldProcess." }
    $scriptLines = @(Get-Content -LiteralPath $path)
    if (@($scriptLines | Where-Object Length -GT 240).Count) { throw "Command script '$($command.Script)' contains a line longer than 240 characters." }
    if (@($scriptLines | Where-Object { $_ -match '[ \t]+$' }).Count) { throw "Command script '$($command.Script)' contains trailing whitespace." }
}
$catalogPaths = @($commands.Script | ForEach-Object { (Join-Path $root $_).ToLowerInvariant() })
$orphanScripts = @(Get-ChildItem -LiteralPath (Join-Path $root 'Commands') -Recurse -Filter *.ps1 | Where-Object { $_.FullName.ToLowerInvariant() -notin $catalogPaths })
if ($orphanScripts.Count) { throw "Command scripts are not reachable from the menu: $($orphanScripts.FullName -join ', ')" }
foreach ($section in $expectedSections) { if (-not @($commands | Where-Object { $_.Sections -contains $section }).Count) { throw "Menu section '$section' has no commands." } }
foreach ($telemetryId in 'telemetry.components', 'telemetry.active-users', 'telemetry.account-failures') { if (-not(Get-FastPASCommand -Id $telemetryId)) { throw "Original FastPAS telemetry command '$telemetryId' is missing." } }
foreach ($runnerId in 'telemetry.psm-users', 'bulk.safe-members.import-compatible', 'safe.cpm.export', 'safe.cpm.apply', 'platform.pmterminal.audit') { if (-not(Get-FastPASCommand -Id $runnerId)) { throw "CyberArk API Runner command '$runnerId' is missing." } }
$expandedIds = 'compliance.posture', 'onboarding.discovered', 'onboarding.discovered.apply', 'relationships.report', 'relationships.apply', 'governance.entitlements', 'telemetry.system-health', 'platform.drift', 'platform.drift.apply', 'psm.sessions', 'psm.sessions.action', 'aam.exposure', 'aam.exposure.apply', 'request.queue', 'request.action', 'safe.migration.plan', 'safe.migration.apply', 'account.safe-transfer'
foreach ($expandedId in $expandedIds) { if (-not(Get-FastPASCommand -Id $expandedId)) { throw "Expanded operations command '$expandedId' is missing." } }
$launcher = Get-Content -LiteralPath (Join-Path $root 'FastPAS.ps1') -Raw
$profileDialogPath = Join-Path $root 'ui/Show-FastPASProfileDialog.ps1'
if (-not (Test-Path -LiteralPath $profileDialogPath -PathType Leaf) -or $launcher -notmatch 'Show-FastPASProfileDialog' -or $launcher -notmatch 'Choose deployment type') { throw 'Deployment-aware GUI/text profile creation is not wired into the launcher.' }
if (@([regex]::Matches($launcher, "DisplayName\s*=\s*'Previous page'")).Count -lt 2 -or $launcher -notmatch 'Previous page \(profiles\)') { throw 'Previous-page navigation is missing from one or more interactive menu levels.' }
if ((Get-FastPASCommand -Id 'compliance.posture').Sections -ne 'Telemetry and Reports') { throw 'Compliance posture must remain in Telemetry and Reports.' }
if ((Get-FastPASCommand -Id 'safe.migration.plan').Sections -contains 'Telemetry and Reports') { throw 'Safe migration planning does not belong in Telemetry and Reports.' }
if ((Get-FastPASCommand -Id 'aam.exposure').Sections -contains 'Safe Management') { throw 'Application exposure does not belong in Safe Management.' }
$templateRoot = Join-Path $root 'templates/csv'
foreach ($template in 'bulk-safes.csv', 'bulk-safe-members.csv', 'safe-member-permissions.csv', 'safe-cpm-assignments.csv', 'bulk-accounts.csv', 'platform-account-moves.csv', 'local-to-domain-accounts.csv', 'outbound-endpoints.csv', 'discovered-account-decisions.csv', 'account-links.csv', 'platform-changes.csv', 'psm-session-actions.csv', 'access-request-actions.csv', 'application-authentication-changes.csv', 'safe-account-migrations.csv', 'account-safe-transfers.csv') { if (-not(Test-Path -LiteralPath (Join-Path $templateRoot $template))) { throw "Bulk template '$template' is missing." } }
Write-Host 'Expanded operations catalog, templates, and previous-page navigation validation passed.' -ForegroundColor Green
Write-Host "Parser and catalog validation passed for $($commands.Count) commands." -ForegroundColor Green
$compatibilityCheck = & (Get-Module FastPAS.PowerShell) {
    $permissions = New-FastPASPermissionsFromCsvRow ([pscustomobject]@{ListAccounts = 'TRUE';
            RequestsAuthorizationLevel = '2'
        })
    $safe = [pscustomobject]@{safeName = 'A';
        safeUrlId = '1';
        managingCPM = 'CPM';
        description = 'x';
        olacEnabled = $false;
        numberOfVersionsRetention = 5
    }
    $hash = Get-FastPASSafeSnapshotHash $safe;
    $safe.description = 'changed'
    [pscustomobject]@{Permissions = $permissions;
        HashChanged = ((Get-FastPASSafeSnapshotHash $safe) -ne $hash);
        MatchCount = @(Find-FastPASStringMatch ([pscustomobject]@{command = 'PMTerminal.exe' }) '(?i)pmterminal(?:\.exe)?').Count
    }
}
if (-not $compatibilityCheck.Permissions.listAccounts -or -not $compatibilityCheck.Permissions.requestsAuthorizationLevel2 -or -not $compatibilityCheck.HashChanged -or $compatibilityCheck.MatchCount -ne 1) { throw 'CyberArk API Runner compatibility helper validation failed.' }
Write-Host 'CyberArk API Runner permission, snapshot, and platform-audit validation passed.' -ForegroundColor Green
$previousDataRoot = $env:FASTPAS_DATA_ROOT
$profileTestRoot = Join-Path ([IO.Path]::GetTempPath()) "fastpas-profile-test-$([guid]::NewGuid().ToString('N'))"
try {
    $env:FASTPAS_DATA_ROOT = $profileTestRoot
    $first = New-FastPASProfile -Name alpha -Subdomain example -IdentityHost example.id.cyberark.cloud -AuthType interactive -Username alpha@example.invalid
    $second = New-FastPASProfile -Name beta -Subdomain example -IdentityHost example.id.cyberark.cloud -AuthType federated -Username beta@example.invalid
    if (@(Get-FastPASProfile).Count -ne 2) { throw 'Multiple profile persistence validation failed.' }
    if ((Get-FastPASProfile -Name alpha).Id -ne $first.Id -or (Get-FastPASProfile -Id $second.Id).Name -ne 'beta') { throw 'Profile name/ID selection validation failed.' }
    $storedConfig = Get-Content -LiteralPath (Join-Path $profileTestRoot 'profiles.json') -Raw | ConvertFrom-Json
    $prohibitedNames = @('password', 'clientSecret', 'secretStored')
    foreach ($storedProfile in @($storedConfig.profiles)) {
        if (@($storedProfile.PSObject.Properties.Name | Where-Object { $_ -in $prohibitedNames }).Count) { throw 'Profile persistence contains a prohibited secret field.' }
    }
    Write-Host 'Multiple profile and metadata-only persistence validation passed.' -ForegroundColor Green
    [ordered]@{
        schemaVersion = 1;
        activeProfileId = 'legacy-id';
        profiles = @([ordered]@{
                id = 'legacy-id';
                name = 'legacy';
                authType = 'interactive';
                subdomain = 'example';
                identityHost = 'example.id.cyberark.cloud'
                vaultApiBaseUrl = 'https://example.invalid/PasswordVault/API';
                username = 'legacy@example.invalid';
                secretStored = $true
            })
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $profileTestRoot 'profiles.json')
    $legacyProfile = Get-FastPASProfile -Name legacy
    $migratedConfig = Get-Content -LiteralPath (Join-Path $profileTestRoot 'profiles.json') -Raw | ConvertFrom-Json
    if ($migratedConfig.schemaVersion -ne 3 -or $legacyProfile.PSObject.Properties.Name -contains 'secretStored' -or $legacyProfile.deploymentType -ne 'ispss') { throw 'Legacy profile migration validation failed.' }
    Write-Host 'Legacy saved-credential migration validation passed.' -ForegroundColor Green
}
finally {
    if ($null -eq $previousDataRoot) { Remove-Item Env:FASTPAS_DATA_ROOT -ErrorAction SilentlyContinue }else { $env:FASTPAS_DATA_ROOT = $previousDataRoot }
    $fullProfileTestRoot = [IO.Path]::GetFullPath($profileTestRoot)
    $fullTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($fullProfileTestRoot.StartsWith($fullTempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $fullProfileTestRoot)) {
        Remove-Item -LiteralPath $fullProfileTestRoot -Recurse -Force
    }
}
$pesterManifest = Get-Module -ListAvailable Pester | Where-Object Version -GE '5.0.0' | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pesterManifest) {
    $pesterManifest = Get-ChildItem -LiteralPath (Join-Path $root '.test-runtime/Modules/Pester') -Recurse -Filter Pester.psd1 -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
}
if ($pesterManifest) {
    $pesterPath = if ($pesterManifest -is [IO.FileInfo]) { $pesterManifest.FullName } else { $pesterManifest.Path }
    Import-Module $pesterPath -Force
    $result = Invoke-Pester -Path (Join-Path $root 'tests') -PassThru
    if ($result.FailedCount -or $result.FailedContainersCount) { throw "$($result.FailedCount) Pester test(s) failed." }
}
else { Write-Warning 'Pester 5 is not installed; unit tests were skipped.' }
$analyzerManifest = Get-Module -ListAvailable PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1
if (-not $analyzerManifest) {
    $analyzerManifest = Get-ChildItem -LiteralPath (Join-Path $root '.test-runtime/Modules/PSScriptAnalyzer') -Recurse -Filter PSScriptAnalyzer.psd1 -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
}
if ($analyzerManifest) {
    $analyzerPath = if ($analyzerManifest -is [IO.FileInfo]) { $analyzerManifest.FullName } else { $analyzerManifest.Path }
    Import-Module $analyzerPath -Force
    $analyzerTargets = @('FastPAS.ps1', 'FastPAS.PowerShell.psm1', 'Commands', 'tools', 'tests')
    $findings = @($analyzerTargets | ForEach-Object { Invoke-ScriptAnalyzer -Path (Join-Path $root $_) -Recurse -Severity Error })
    if ($findings.Count) {
        $findings | Format-Table -AutoSize | Out-Host;
        throw 'PSScriptAnalyzer reported errors.'
    }
}
else { Write-Warning 'PSScriptAnalyzer is not installed; static analysis was skipped.' }
