[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    $Context,
    [hashtable]$Arguments = @{},
    [string]$OutputPath,
    [switch]$NonInteractive,
    [switch]$Force
)

$csvPath = if ($Arguments.ContainsKey('CsvPath')) { [string]$Arguments.CsvPath } else { '' }
if (-not $csvPath -or -not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
    throw 'CsvPath must identify an existing CSV with exactly two columns: OldSafe and NewSafe.'
}
$concurrency = if ($Arguments.ContainsKey('Concurrency') -and [string]$Arguments.Concurrency) { [int]$Arguments.Concurrency } else { 12 }
$detailMode = if ($Arguments.ContainsKey('DetailMode') -and $Arguments.DetailMode) { [string]$Arguments.DetailMode } else { 'Always' }
$maxGetRetries = if ($Arguments.ContainsKey('MaxGetRetries') -and [string]$Arguments.MaxGetRetries) { [int]$Arguments.MaxGetRetries } else { 5 }
$reason = if ($Arguments.ContainsKey('Reason') -and $Arguments.Reason) { [string]$Arguments.Reason } else { 'FastPAS high-volume current-secret-only safe transfer' }
$resumePath = if ($Arguments.ContainsKey('ResumePath')) { [string]$Arguments.ResumePath } else { '' }
$relationshipMode = if ($Arguments.ContainsKey('RelationshipMode') -and $Arguments.RelationshipMode) { [string]$Arguments.RelationshipMode } else { 'Block' }
$cpmOperationalState = if ($Arguments.ContainsKey('CpmOperationalState') -and $Arguments.CpmOperationalState) { [string]$Arguments.CpmOperationalState } else { 'Unknown' }
if ($concurrency -lt 1 -or $concurrency -gt 32) { throw 'Concurrency must be between 1 and 32. Start with 12 and tune only after observing PVWA health.' }
if ($detailMode -notin @('Always', 'Inventory')) { throw "DetailMode must be 'Always' or 'Inventory'. Always is the security-first default." }
if ($maxGetRetries -lt 0 -or $maxGetRetries -gt 10) { throw 'MaxGetRetries must be between 0 and 10.' }
if ([string]::IsNullOrWhiteSpace($reason)) { throw 'Reason cannot be empty because password retrieval must be attributable.' }
if ($relationshipMode -notin @('Block', 'FullFidelity')) { throw "RelationshipMode must be 'Block' or 'FullFidelity'." }
if ($cpmOperationalState -notin @('Unknown', 'Paused', 'Active')) { throw "CpmOperationalState must be 'Unknown', 'Paused', or 'Active'." }
if ($relationshipMode -eq 'FullFidelity') {
    if ($cpmOperationalState -ne 'Paused') {
        throw "FullFidelity mode requires CpmOperationalState='Paused'. Stop or pause CPM/reconcile activity for the affected accounts and explicitly attest that state."
    }
    if ($detailMode -ne 'Always') { throw "FullFidelity mode requires DetailMode='Always'." }
}

$mappings = @(Import-Csv -LiteralPath $csvPath)
if (-not $mappings.Count) { throw 'The CSV contains no safe mappings.' }
if ($mappings.Count -gt 250) { throw 'Safe mapping files are limited to 250 rows per run.' }
$headers = @($mappings[0].PSObject.Properties.Name)
if ($headers.Count -ne 2 -or $headers -inotcontains 'OldSafe' -or $headers -inotcontains 'NewSafe') {
    throw 'The CSV must contain exactly two columns named OldSafe and NewSafe.'
}
$normalizedMappings = @($mappings | ForEach-Object {
        [pscustomobject]@{
            OldSafe = (Get-FastPASRowString $_ @('OldSafe'))
            NewSafe = (Get-FastPASRowString $_ @('NewSafe'))
        }
    })
foreach ($mapping in $normalizedMappings) {
    if (-not $mapping.OldSafe -or -not $mapping.NewSafe) { throw 'Every row requires both OldSafe and NewSafe.' }
    if ($mapping.OldSafe -ieq $mapping.NewSafe) { throw "OldSafe and NewSafe cannot both be '$($mapping.OldSafe)'." }
}
$duplicateSources = @($normalizedMappings | Group-Object OldSafe | Where-Object Count -GT 1)
if ($duplicateSources.Count) { throw "Each OldSafe may appear once. Duplicate(s): $($duplicateSources.Name -join ', ')." }
$sourceNames = @($normalizedMappings.OldSafe)
$chainedTargets = @($normalizedMappings.NewSafe | Where-Object { $_ -iin $sourceNames } | Sort-Object -Unique)
if ($chainedTargets.Count) {
    throw "Chained mappings are not allowed because processing order could move an account twice. These destinations also appear as OldSafe: $($chainedTargets -join ', ')."
}

$profileId = Get-FastPASObjectString $Context.Profile @('id', 'Id', 'name', 'Name')
$deploymentType = if ($Context.DeploymentType) { [string]$Context.DeploymentType } else { 'ispss' }
$inputHash = (Get-FileHash -LiteralPath $csvPath -Algorithm SHA256).Hash.ToLowerInvariant()
$outputDirectory = Get-FastPASOutputDirectory $OutputPath
if ($resumePath) {
    $runDirectory = [IO.Path]::GetFullPath($resumePath)
    if (-not (Test-Path -LiteralPath $runDirectory -PathType Container)) { throw "ResumePath is not an existing migration run directory: $runDirectory" }
} else {
    $runDirectory = Join-Path $outputDirectory ("account_safe_transfer_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
    $null = New-Item -ItemType Directory -Path $runDirectory -Force -WhatIf:$false
}
$manifestPath = Join-Path $runDirectory 'manifest.json'
$attempt = 1
$existingManifest = $null
if (Test-Path -LiteralPath $manifestPath) {
    $existingManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([string]$existingManifest.InputHash -ne $inputHash) { throw 'Resume refused: the mapping CSV does not match the original run input hash.' }
    if ([string]$existingManifest.ProfileId -ne $profileId) { throw 'Resume refused: the selected FastPAS profile differs from the original run.' }
    if ([string]$existingManifest.DeploymentType -ne $deploymentType) { throw 'Resume refused: the deployment type differs from the original run.' }
    $existingRelationshipMode = if ($existingManifest.PSObject.Properties['RelationshipMode']) { [string]$existingManifest.RelationshipMode } else { 'Block' }
    if ($existingRelationshipMode -ne $relationshipMode) { throw 'Resume refused: RelationshipMode differs from the original run.' }
    $existingCpmState = if ($existingManifest.PSObject.Properties['CpmOperationalState']) { [string]$existingManifest.CpmOperationalState } else { 'Unknown' }
    if ($existingCpmState -ne $cpmOperationalState) { throw 'Resume refused: CpmOperationalState differs from the original run.' }
    $attempt = [int]$existingManifest.Attempt + 1
}
$runId = if ($existingManifest -and $existingManifest.RunId) { [string]$existingManifest.RunId } else { [guid]::NewGuid().ToString() }
$startedAt = [DateTimeOffset]::UtcNow
$manifest = [ordered]@{
    SchemaVersion = 1; RunId = $runId; InputFile = [IO.Path]::GetFileName($csvPath); InputHash = $inputHash
    ProfileId = $profileId; DeploymentType = $deploymentType; Attempt = $attempt; Concurrency = $concurrency
    DetailMode = $detailMode; MaxGetRetries = $maxGetRetries; RelationshipMode = $relationshipMode
    CpmOperationalState = $cpmOperationalState; StartedAt = $startedAt.ToString('o'); Status = 'Preflight'
}
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM -WhatIf:$false

function New-TransferRow {
    param(
        [string]$OldSafe, [string]$NewSafe, [string]$SourceAccountId = '', [string]$DestinationAccountId = '',
        [string]$AccountName = '', [string]$PlatformId = '', [string]$Stage, [string]$Status,
        [bool]$Retryable = $false, [string]$Issue = '', [string]$RecommendedAction = '', [long]$DurationMs = 0,
        [string]$WorkerId = 'preflight'
    )
    [pscustomobject][ordered]@{
        Timestamp = [DateTimeOffset]::UtcNow.ToString('o'); RunId = $runId; Attempt = $attempt; WorkerId = $WorkerId
        OldSafe = $OldSafe; NewSafe = $NewSafe; SourceAccountId = $SourceAccountId
        DestinationAccountId = $DestinationAccountId; AccountName = $AccountName; PlatformId = $PlatformId
        PreservedDirectLinks = 0; PreservedDependents = 0; PreservedDependentLinks = 0
        Stage = $Stage; Status = $Status; Retryable = $Retryable; DurationMs = $DurationMs
        Issue = $Issue; RecommendedAction = $RecommendedAction
    }
}

$inventoryCache = @{}
function Get-SafeInventory {
    param([string]$SafeName, [switch]$Refresh)
    $key = $SafeName.ToLowerInvariant()
    if ($Refresh -or -not $inventoryCache.ContainsKey($key)) {
        $inventoryCache[$key] = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -Query @{filter = "safeName eq $SafeName" } -CollectionNames @('value', 'Accounts'))
    }
    return @($inventoryCache[$key])
}

$preflightRows = [Collections.Generic.List[object]]::new()
$plans = [Collections.Generic.List[object]]::new()
$destinationKeys = @{}
$safeValidation = @{}
$allSafeNames = @(@($normalizedMappings.OldSafe) + @($normalizedMappings.NewSafe) | Sort-Object -Unique)
foreach ($safeName in $allSafeNames) {
    try {
        $null = Resolve-FastPASSafe -Context $Context -SafeName $safeName
        $safeValidation[$safeName.ToLowerInvariant()] = $true
    } catch { $safeValidation[$safeName.ToLowerInvariant()] = $_.Exception.Message }
}
foreach ($mapping in $normalizedMappings) {
    $oldSafe = $mapping.OldSafe
    $newSafe = $mapping.NewSafe
    $oldValidation = $safeValidation[$oldSafe.ToLowerInvariant()]
    $newValidation = $safeValidation[$newSafe.ToLowerInvariant()]
    if ($oldValidation -isnot [bool] -or $newValidation -isnot [bool]) {
        $issue = @(@($oldValidation, $newValidation) | Where-Object { $_ -isnot [bool] }) -join ' '
        $preflightRows.Add((New-TransferRow -OldSafe $oldSafe -NewSafe $newSafe -Stage 'Preflight' -Status 'SafeValidationFailed' -Issue $issue -RecommendedAction 'Correct safe names or permissions, then resume with the same mapping CSV.'))
        continue
    }
    try {
        $destinationAccounts = @(Get-SafeInventory -SafeName $newSafe)
        foreach ($destination in $destinationAccounts) {
            $destinationName = Get-FastPASObjectString $destination @('name', 'Name')
            if ($destinationName) { $destinationKeys[("{0}`0{1}" -f $newSafe, $destinationName).ToLowerInvariant()] = $destination }
        }
        $sourceAccounts = @(Get-SafeInventory -SafeName $oldSafe)
    } catch {
        $preflightRows.Add((New-TransferRow -OldSafe $oldSafe -NewSafe $newSafe -Stage 'Preflight' -Status 'InventoryFailed' -Retryable $true -Issue $_.Exception.Message -RecommendedAction 'Restore API access and resume the run.'))
        continue
    }
    if (-not $sourceAccounts.Count) {
        $preflightRows.Add((New-TransferRow -OldSafe $oldSafe -NewSafe $newSafe -Stage 'Preflight' -Status 'NoAccounts' -RecommendedAction 'No action required; the source safe is empty.'))
        continue
    }
    foreach ($account in $sourceAccounts) {
        $sourceId = Get-FastPASObjectString $account @('id', 'ID', 'accountId')
        $accountName = Get-FastPASObjectString $account @('name', 'Name')
        $platformId = Get-FastPASObjectString $account @('platformId', 'PlatformID')
        if (-not $sourceId -or -not $accountName -or -not $platformId) {
            $rowParameters = @{
                OldSafe = $oldSafe; NewSafe = $newSafe; SourceAccountId = $sourceId; AccountName = $accountName
                PlatformId = $platformId; Stage = 'Preflight'; Status = 'InvalidSourceMetadata'
                Issue = 'The source inventory omitted account ID, name, or platform ID.'
                RecommendedAction = 'Inspect the source account and correct incomplete metadata before retrying.'
            }
            $preflightRows.Add((New-TransferRow @rowParameters))
            continue
        }
        $destinationKey = ("{0}`0{1}" -f $newSafe, $accountName).ToLowerInvariant()
        if ($destinationKeys.ContainsKey($destinationKey)) {
            $existingId = Get-FastPASObjectString $destinationKeys[$destinationKey] @('id', 'ID', 'accountId')
            $rowParameters = @{
                OldSafe = $oldSafe; NewSafe = $newSafe; SourceAccountId = $sourceId; DestinationAccountId = $existingId
                AccountName = $accountName; PlatformId = $platformId; Stage = 'Preflight'; Status = 'DestinationCollision'
                Issue = "The destination already contains an account named '$accountName'."
                RecommendedAction = 'Compare both accounts and resolve the collision manually; FastPAS will not overwrite or delete either account.'
            }
            $preflightRows.Add((New-TransferRow @rowParameters))
            continue
        }
        $plans.Add([pscustomobject]@{
                OldSafe = $oldSafe; NewSafe = $newSafe; SourceAccountId = $sourceId; AccountName = $accountName
                PlatformId = $platformId; Account = $account; DestinationKey = $destinationKey
            })
    }
}

$duplicateIncoming = @($plans | Group-Object DestinationKey | Where-Object Count -GT 1)
foreach ($duplicate in $duplicateIncoming) {
    foreach ($plan in @($duplicate.Group)) {
        $rowParameters = @{
            OldSafe = $plan.OldSafe; NewSafe = $plan.NewSafe; SourceAccountId = $plan.SourceAccountId
            AccountName = $plan.AccountName; PlatformId = $plan.PlatformId; Stage = 'Preflight'
            Status = 'DuplicateIncomingName'; Issue = 'Multiple source accounts would create the same destination safe/name pair.'
            RecommendedAction = 'Split or rename the conflicting accounts before retrying.'
        }
        $preflightRows.Add((New-TransferRow @rowParameters))
        $null = $plans.Remove($plan)
    }
}

$priorCheckpointPaths = @(Get-ChildItem -LiteralPath $runDirectory -Filter 'attempt-*-worker-*.csv' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
$attemptsPath = Join-Path $runDirectory 'all-attempts.csv'
if (Test-Path -LiteralPath $attemptsPath) {
    $priorRows = @(Import-Csv -LiteralPath $attemptsPath)
} else {
    $priorRows = @($priorCheckpointPaths | ForEach-Object { Import-Csv -LiteralPath $_ })
}
$alreadyReconciledIds = @($priorRows | Where-Object Status -EQ 'Reconciled' | Select-Object -ExpandProperty SourceAccountId -Unique)
if ($alreadyReconciledIds.Count) {
    $plans = [Collections.Generic.List[object]]@($plans | Where-Object SourceAccountId -NotIn $alreadyReconciledIds)
}

$planPath = Join-Path $runDirectory ("attempt-{0:D3}-plan.csv" -f $attempt)
@($plans | Select-Object OldSafe, NewSafe, SourceAccountId, AccountName, PlatformId) |
    Export-Csv -LiteralPath $planPath -NoTypeInformation -Encoding utf8BOM -WhatIf:$false
$manifest.PlannedAccounts = $plans.Count
$manifest.PreflightIssues = @($preflightRows | Where-Object Status -NotIn @('NoAccounts')).Count
$manifest.Status = 'Executing'
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM -WhatIf:$false

$workerRows = @()
if ($plans.Count -and -not $PSCmdlet.ShouldProcess("$($plans.Count) accounts across $($normalizedMappings.Count) safe mapping(s)", "Transfer current secrets using $concurrency worker(s)")) {
    $workerRows = @($plans | ForEach-Object {
            $rowParameters = @{
                OldSafe = $_.OldSafe; NewSafe = $_.NewSafe; SourceAccountId = $_.SourceAccountId
                AccountName = $_.AccountName; PlatformId = $_.PlatformId; Stage = 'WhatIf'; Status = 'WhatIf'
                RecommendedAction = 'Run without WhatIf after reviewing the plan.'
            }
            New-TransferRow @rowParameters
        })
} elseif ($plans.Count) {
    if ($concurrency -gt 1) {
        $authType = Get-FastPASObjectString $Context.Profile @('authType', 'AuthType')
        $renewableAuth = ($deploymentType -eq 'ispss' -and $authType -eq 'oauth') -or
            ($deploymentType -in @('onprem', 'standalone') -and $authType -in @('cyberark', 'ldap', 'windows'))
        if (-not $renewableAuth -or -not $Context.RuntimeSecret) {
            throw 'Parallel transfer requires a renewable OAuth or direct PVWA profile and its current-run secret. Federated, interactive, and RADIUS sessions must use Concurrency=1.'
        }
    }
    $actualConcurrency = [Math]::Min($concurrency, $plans.Count)
    $movingAccountLookup = @{}
    foreach ($movingAccount in @($plans)) {
        $movingAccountLookup["id:$($movingAccount.SourceAccountId)"] = $true
        $movingAccountLookup[("name:{0}`0{1}" -f $movingAccount.OldSafe, $movingAccount.AccountName).ToLowerInvariant()] = $true
    }
    $partitions = [object[]]::new($actualConcurrency)
    for ($index = 0; $index -lt $actualConcurrency; $index++) {
        $partitions[$index] = [Collections.Generic.List[object]]::new()
    }
    for ($index = 0; $index -lt $plans.Count; $index++) { $partitions[$index % $actualConcurrency].Add($plans[$index]) }
    $workerSpecs = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $actualConcurrency; $index++) {
        $workerId = "worker-{0:D3}" -f ($index + 1)
        $spec = [pscustomobject]@{
            ExistingContext = $(if ($actualConcurrency -eq 1) { $Context } else { $null })
            ProfileId = $profileId
            RuntimeSecret = $(if ($actualConcurrency -gt 1) { $Context.RuntimeSecret.Copy() } else { $null })
            Accounts = @($partitions[$index])
            CheckpointPath = Join-Path $runDirectory ("attempt-{0:D3}-{1}.csv" -f $attempt, $workerId)
            RunId = $runId; Attempt = $attempt; WorkerId = $workerId; DetailMode = $detailMode
            MaxGetRetries = $maxGetRetries; Reason = $reason; StartupDelayMilliseconds = (750 * $index)
            RelationshipMode = $relationshipMode; DeploymentType = $deploymentType
            MovingAccountLookup = $movingAccountLookup
        }
        if ($spec.RuntimeSecret) { $spec.RuntimeSecret.MakeReadOnly() }
        $workerSpecs.Add($spec)
    }
    try {
        if ($actualConcurrency -eq 1) {
            $workerRows = @(Invoke-FastPASAccountTransferWorker -WorkerSpec $workerSpecs[0])
        } else {
            $modulePath = Join-Path $PSScriptRoot '..\..\FastPAS.PowerShell.psd1'
            $workerRows = @($workerSpecs | ForEach-Object -Parallel {
                    Import-Module $using:modulePath -Force
                    & (Get-Module FastPAS.PowerShell) {
                        param($Spec)
                        Invoke-FastPASAccountTransferWorker -WorkerSpec $Spec
                    } $_
                } -ThrottleLimit $actualConcurrency)
        }
    } finally {
        foreach ($spec in $workerSpecs) {
            if ($spec.RuntimeSecret) { $spec.RuntimeSecret.Dispose(); $spec.RuntimeSecret = $null }
        }
    }
}

$allCurrentRows = @($preflightRows) + @($workerRows)
$allRowsForReconciliation = @($priorRows) + @($allCurrentRows)
$reconciliationErrors = @{}
$inventoryCache = @{}
$visibleAccountIds = @{}
$visibleAccountNames = @{}
foreach ($safeName in $allSafeNames) {
    try {
        $reconciledInventory = @(Get-SafeInventory -SafeName $safeName -Refresh)
        foreach ($account in $reconciledInventory) {
            $accountId = Get-FastPASObjectString $account @('id', 'ID', 'accountId')
            $accountName = Get-FastPASObjectString $account @('name', 'Name')
            if ($accountId) { $visibleAccountIds[("{0}`0{1}" -f $safeName, $accountId).ToLowerInvariant()] = $true }
            if ($accountName) { $visibleAccountNames[("{0}`0{1}" -f $safeName, $accountName).ToLowerInvariant()] = $true }
        }
    }
    catch { $reconciliationErrors[$safeName.ToLowerInvariant()] = $_.Exception.Message }
}
foreach ($row in $allRowsForReconciliation) {
    if (-not $row.SourceAccountId -or $row.Status -in @('WhatIf', 'NoAccounts', 'SafeValidationFailed', 'InventoryFailed', 'InvalidSourceMetadata', 'DuplicateIncomingName')) { continue }
    $sourceError = $reconciliationErrors[$row.OldSafe.ToLowerInvariant()]
    $destinationError = $reconciliationErrors[$row.NewSafe.ToLowerInvariant()]
    if ($sourceError -or $destinationError) {
        if ($row.Status -eq 'Completed') {
            $row.Status = 'ReconciliationUnavailable'; $row.Retryable = $false
            $row.Issue = "Could not complete final inventory reconciliation. $sourceError $destinationError".Trim()
            $row.RecommendedAction = 'Do not retry automatically. Inspect both safes, then resume after API access is restored.'
        }
        continue
    }
    $sourceKey = ("{0}`0{1}" -f $row.OldSafe, $row.SourceAccountId).ToLowerInvariant()
    $destinationIdKey = ("{0}`0{1}" -f $row.NewSafe, $row.DestinationAccountId).ToLowerInvariant()
    $destinationNameKey = ("{0}`0{1}" -f $row.NewSafe, $row.AccountName).ToLowerInvariant()
    $sourcePresent = $visibleAccountIds.ContainsKey($sourceKey)
    $destinationPresent = ($row.DestinationAccountId -and $visibleAccountIds.ContainsKey($destinationIdKey)) -or
        $visibleAccountNames.ContainsKey($destinationNameKey)
    if (-not $sourcePresent -and $destinationPresent) {
        $row.Status = 'Reconciled'; $row.Stage = 'Reconciliation'; $row.Retryable = $false; $row.Issue = ''
        $row.RecommendedAction = 'No action required. The source is absent and the destination is present.'
    } elseif ($sourcePresent -and $destinationPresent) {
        $row.Status = 'DuplicateNeedsCleanup'; $row.Stage = 'Reconciliation'; $row.Retryable = $false
        $reconciliationIssue = 'Both source and destination accounts exist after the attempt.'
        $row.Issue = if ($row.Issue) { "$($row.Issue) $reconciliationIssue" } else { $reconciliationIssue }
        $row.RecommendedAction = 'Compare both accounts and remove the source only after confirming the destination secret and metadata.'
    } elseif (-not $sourcePresent -and -not $destinationPresent) {
        $row.Status = 'CriticalMissing'; $row.Stage = 'Reconciliation'; $row.Retryable = $false
        $row.Issue = 'Neither the source account nor a matching destination account was visible during reconciliation.'
        $row.RecommendedAction = 'Escalate immediately; inspect Vault audit and deleted-account recovery options before any retry.'
    } elseif ($row.Status -in @('Completed', 'CreateUncertain', 'DestinationCreatedSourceRetained', 'DuplicateNeedsCleanup')) {
        $row.Status = 'SourceRetainedDestinationMissing'; $row.Stage = 'Reconciliation'; $row.Retryable = $true
        $row.Issue = 'The source exists, but no matching destination account was found.'
        $row.RecommendedAction = 'Review the create failure and retry this account after correcting the issue.'
    }
}

$allAttemptRows = @($allRowsForReconciliation)
@($allAttemptRows) | Export-Csv -LiteralPath $attemptsPath -NoTypeInformation -Encoding utf8BOM -WhatIf:$false
$latestRows = @($allAttemptRows | Group-Object { if ($_.SourceAccountId) { $_.SourceAccountId } else { "$($_.Attempt)|$($_.OldSafe)|$($_.NewSafe)|$($_.Status)" } } | ForEach-Object {
        $_.Group | Sort-Object { [int]$_.Attempt }, Timestamp | Select-Object -Last 1
    })
$resultsPath = Join-Path $runDirectory 'results.csv'
$latestRows | Export-Csv -LiteralPath $resultsPath -NoTypeInformation -Encoding utf8BOM -WhatIf:$false
$nonIssueStatuses = @('Reconciled', 'NoAccounts', 'WhatIf')
$issues = @($latestRows | Where-Object Status -NotIn $nonIssueStatuses)
$issuesPath = Join-Path $runDirectory 'issues.csv'
$issues | Export-Csv -LiteralPath $issuesPath -NoTypeInformation -Encoding utf8BOM -WhatIf:$false

$manifest.Status = if ($WhatIfPreference) { 'Planned' } elseif ($issues.Count) { 'CompletedWithIssues' } else { 'Completed' }
$manifest.CompletedAt = [DateTimeOffset]::UtcNow.ToString('o')
$manifest.DurationSeconds = [Math]::Round(([DateTimeOffset]::UtcNow - $startedAt).TotalSeconds, 2)
$manifest.ReconciledAccounts = @($latestRows | Where-Object Status -EQ 'Reconciled').Count
$manifest.PreservedDirectLinks = [int](($latestRows | ForEach-Object {
            [int](Get-FastPASPropertyValue $_ @('PreservedDirectLinks'))
        } | Measure-Object -Sum).Sum)
$manifest.PreservedDependents = [int](($latestRows | ForEach-Object {
            [int](Get-FastPASPropertyValue $_ @('PreservedDependents'))
        } | Measure-Object -Sum).Sum)
$manifest.PreservedDependentLinks = [int](($latestRows | ForEach-Object {
            [int](Get-FastPASPropertyValue $_ @('PreservedDependentLinks'))
        } | Measure-Object -Sum).Sum)
$manifest.IssueCount = $issues.Count
$manifest.ResultCount = $latestRows.Count
$manifest.Artifacts = @([IO.Path]::GetFileName($planPath), 'all-attempts.csv', 'results.csv', 'issues.csv')
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM -WhatIf:$false

$warnings = @(
    $(if ($relationshipMode -eq 'FullFidelity') {
            'FullFidelity preserves direct links plus dependent-account platform properties, management settings, and links. ' +
            'Account groups and historical artifacts remain unsupported and are blocked rather than discarded.'
        } else {
            'Only the current secret and supported account metadata are transferred. Password history, audit history, recordings, requests, links, and account-group membership are not moved.'
        }),
    'FastPAS never writes account secrets to its plan, manifest, checkpoint, result, issue, or audit files.',
    'Use a dedicated least-privilege OAuth or direct PVWA automation identity. Increase concurrency only while monitoring PVWA and Vault health.'
)
$summary = "Safe transfer run $runId reconciled $($manifest.ReconciledAccounts) account(s), " +
"preserved $($manifest.PreservedDependents) dependent(s), and has $($issues.Count) result(s) requiring attention."
New-FastPASResult -Success ($issues.Count -eq 0) -Summary $summary -Data $latestRows -Warnings $warnings -Artifacts @($manifestPath, $planPath, $attemptsPath, $resultsPath, $issuesPath) -AuditEvents @()
