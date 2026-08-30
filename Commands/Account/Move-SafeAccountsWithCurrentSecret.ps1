[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    $Context,
    [hashtable]$Arguments = @{},
    [string]$OutputPath,
    [switch]$NonInteractive,
    [switch]$Force
)

$csvPath = [string]$Arguments.CsvPath
if (-not $csvPath -or -not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
    throw 'CsvPath must identify an existing CSV with exactly two columns: OldSafe and NewSafe.'
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

$results = [Collections.Generic.List[object]]::new()
$outputDirectory = Get-FastPASOutputDirectory $OutputPath
$checkpointPath = Join-Path $outputDirectory ("account_safe_transfer_checkpoint_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))

function Save-TransferCheckpoint {
    $safeRows = @($results | Select-Object OldSafe, NewSafe, SourceAccountId, DestinationAccountId, AccountName, PlatformId, Status, Detail)
    $safeRows | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $checkpointPath -Encoding utf8NoBOM -WhatIf:$false
}

foreach ($mapping in $normalizedMappings) {
    $oldSafe = $mapping.OldSafe
    $newSafe = $mapping.NewSafe
    try {
        $null = Resolve-FastPASSafe -Context $Context -SafeName $oldSafe
        $null = Resolve-FastPASSafe -Context $Context -SafeName $newSafe
        $accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -Query @{filter = "safeName eq $oldSafe" } -CollectionNames @('value', 'Accounts'))
    }
    catch {
        $results.Add([pscustomobject]@{
                OldSafe = $oldSafe; NewSafe = $newSafe; SourceAccountId = ''; DestinationAccountId = ''
                AccountName = ''; PlatformId = ''; Status = 'SafeValidationFailed'; Detail = $_.Exception.Message
            })
        Save-TransferCheckpoint
        continue
    }

    if (-not $accounts.Count) {
        $results.Add([pscustomobject]@{
                OldSafe = $oldSafe; NewSafe = $newSafe; SourceAccountId = ''; DestinationAccountId = ''
                AccountName = ''; PlatformId = ''; Status = 'NoAccounts'; Detail = 'The source safe contained no visible accounts.'
            })
        Save-TransferCheckpoint
        continue
    }

    foreach ($listedAccount in $accounts) {
        $sourceId = Get-FastPASObjectString $listedAccount @('id', 'ID', 'accountId')
        $destinationId = ''
        $accountName = Get-FastPASObjectString $listedAccount @('name', 'Name')
        $platformId = Get-FastPASObjectString $listedAccount @('platformId', 'PlatformID')
        $status = 'Completed'
        $detail = ''
        $retrievedSecret = $null
        $creationBody = $null
        try {
            if (-not $sourceId) { throw "An account returned from safe '$oldSafe' did not include an account ID." }
            $account = Resolve-FastPASAccount -Context $Context -AccountId $sourceId
            $accountName = Get-FastPASObjectString $account @('name', 'Name')
            $platformId = Get-FastPASObjectString $account @('platformId', 'PlatformID')
            $address = Get-FastPASObjectString $account @('address', 'Address')
            $userName = Get-FastPASObjectString $account @('userName', 'UserName', 'username')
            if (-not $accountName -or -not $platformId) { throw 'The source account is missing its name or platform ID.' }

            $duplicates = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -Query @{
                    search = $accountName
                    filter = "safeName eq $newSafe"
                } -CollectionNames @('value', 'Accounts') | Where-Object {
                    (Get-FastPASObjectString $_ @('name', 'Name')) -eq $accountName
                })
            if ($duplicates.Count) { throw "Destination safe '$newSafe' already contains an account named '$accountName'." }

            if (-not $PSCmdlet.ShouldProcess("$oldSafe/$accountName", "Retrieve current secret, create in '$newSafe', verify, then delete source")) {
                $status = 'WhatIf'
                $detail = 'Validated only. No secret was retrieved and no mutation was sent.'
            }
            else {
                $retrieveParameters = @{
                    Context = $Context
                    Method = 'POST'
                    Path = "Accounts/$([uri]::EscapeDataString($sourceId))/Password/Retrieve"
                    Body = @{reason = 'FastPAS current-password-only safe transfer' }
                    NoRetry = $true
                }
                $retrievedSecret = Invoke-FastPASApiRequest @retrieveParameters
                if ($retrievedSecret -isnot [string]) {
                    $retrievedSecret = Get-FastPASObjectString $retrievedSecret @('password', 'Password', 'content', 'Content', 'secret', 'Secret')
                }
                if ([string]::IsNullOrEmpty([string]$retrievedSecret)) { throw 'CyberArk returned an empty current secret; the source account was not changed.' }

                $creationBody = [ordered]@{
                    name = $accountName
                    address = $address
                    userName = $userName
                    platformId = $platformId
                    safeName = $newSafe
                    secretType = $(if (Get-FastPASObjectString $account @('secretType', 'SecretType')) {
                            Get-FastPASObjectString $account @('secretType', 'SecretType')
                        } else { 'password' })
                    secret = [string]$retrievedSecret
                }
                $platformProperties = Get-FastPASPropertyValue $account @('platformAccountProperties', 'PlatformAccountProperties')
                if ($null -ne $platformProperties) { $creationBody.platformAccountProperties = $platformProperties }
                $sourceManagement = Get-FastPASPropertyValue $account @('secretManagement', 'SecretManagement')
                if ($null -ne $sourceManagement) {
                    $creationBody.secretManagement = [ordered]@{}
                    $automatic = Get-FastPASPropertyValue $sourceManagement @('automaticManagementEnabled', 'AutomaticManagementEnabled')
                    $reason = Get-FastPASObjectString $sourceManagement @('manualManagementReason', 'ManualManagementReason')
                    if ($null -ne $automatic) { $creationBody.secretManagement.automaticManagementEnabled = [bool]$automatic }
                    if ($reason) { $creationBody.secretManagement.manualManagementReason = $reason }
                }
                $remoteAccess = Get-FastPASPropertyValue $account @('remoteMachinesAccess', 'RemoteMachinesAccess')
                if ($null -ne $remoteAccess) { $creationBody.remoteMachinesAccess = $remoteAccess }

                $created = Invoke-FastPASApiRequest -Context $Context -Method POST -Path 'Accounts' -Body $creationBody -NoRetry
                $destinationId = Get-FastPASObjectString $created @('id', 'ID', 'accountId')
                if (-not $destinationId) { throw 'CyberArk created no verifiable destination account ID; the source account was not deleted.' }
                $verified = Resolve-FastPASAccount -Context $Context -AccountId $destinationId
                if ((Get-FastPASObjectString $verified @('safeName', 'SafeName')) -ne $newSafe -or
                    (Get-FastPASObjectString $verified @('platformId', 'PlatformID')) -ne $platformId -or
                    (Get-FastPASObjectString $verified @('name', 'Name')) -ne $accountName) {
                    throw 'Destination verification did not match the requested safe, platform, and account name. The source account was not deleted.'
                }

                try {
                    $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path "Accounts/$([uri]::EscapeDataString($sourceId))" -NoRetry
                    $detail = 'Current secret and supported account metadata were copied, verified, and the source account was deleted.'
                }
                catch {
                    $status = 'DuplicateNeedsCleanup'
                    $detail = "Destination account '$destinationId' was created and verified, but source deletion failed: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $status = 'Failed'
            $detail = $_.Exception.Message
        }
        finally {
            if ($creationBody -is [Collections.IDictionary] -and $creationBody.Contains('secret')) { $creationBody.secret = $null }
            $retrievedSecret = $null
        }
        $results.Add([pscustomobject]@{
                OldSafe = $oldSafe; NewSafe = $newSafe; SourceAccountId = $sourceId
                DestinationAccountId = $destinationId; AccountName = $accountName; PlatformId = $platformId
                Status = $status; Detail = $detail
            })
        Save-TransferCheckpoint
    }
}

$data = @($results)
$resultPath = Export-FastPASCsv $data $OutputPath 'account_safe_transfer_results'
$failed = @($data | Where-Object Status -In @('Failed', 'SafeValidationFailed', 'DuplicateNeedsCleanup')).Count
$moved = @($data | Where-Object Status -EQ 'Completed').Count
$warnings = @(
    'Only the current secret is transferred. Password history, prior versions, audit history, recordings, requests, and account links are not moved.',
    'Rows marked DuplicateNeedsCleanup require an operator to review both accounts; FastPAS intentionally does not delete either copy automatically.'
)
$resultParameters = @{
    Success = ($failed -eq 0)
    Summary = "Current-secret-only safe transfer processed $($data.Count) account result(s): $moved moved and $failed requiring attention."
    Data = $data
    Warnings = $warnings
    Artifacts = @($checkpointPath, $resultPath)
    AuditEvents = @($data)
}
New-FastPASResult @resultParameters
