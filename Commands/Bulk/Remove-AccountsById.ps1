[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)

$csvPath = [string]$Arguments['CsvPath']
if (-not $csvPath -or -not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
    throw 'CsvPath must identify an existing account-deletions CSV file.'
}

$items = @(Import-Csv -LiteralPath $csvPath)
if (-not $items.Count) { throw 'The CSV contains no account data rows.' }
if ($items[0].PSObject.Properties.Name -notcontains 'AccountID') {
    throw "The CSV requires one column named 'AccountID'."
}

# Validate the complete file before issuing the first destructive request.
$accountIds = [Collections.Generic.List[string]]::new()
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
for ($index = 0; $index -lt $items.Count; $index++) {
    $accountId = Get-FastPASRowString $items[$index] @('AccountID')
    $csvRow = $index + 2
    if (-not $accountId) { throw "AccountID is blank on CSV row $csvRow. No accounts were deleted." }
    if (-not $seen.Add($accountId)) {
        throw "Duplicate AccountID '$accountId' was found on CSV row $csvRow. No accounts were deleted."
    }
    $accountIds.Add($accountId)
}

$results = [Collections.Generic.List[object]]::new()
foreach ($accountId in $accountIds) {
    $status = 'Deleted'
    $detail = 'Account deleted.'
    try {
        if (-not $PSCmdlet.ShouldProcess($accountId, 'Permanently delete CyberArk account')) {
            $status = 'WhatIf'
            $detail = 'Preview only; no delete request was sent.'
        }
        else {
            # Never retry an ambiguous destructive request. A failed row is
            # recorded for operator review instead of risking a duplicate call.
            $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE `
                -Path "Accounts/$([uri]::EscapeDataString($accountId))" -NoRetry
        }
    }
    catch {
        $status = 'Failed'
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{
            AccountID = $accountId
            Status = $status
            Detail = $detail
        })
}

$data = @($results)
$csv = Export-FastPASCsv $data $OutputPath 'account_deletions_result'
$failed = @($data | Where-Object Status -EQ 'Failed').Count
$deleted = @($data | Where-Object Status -EQ 'Deleted').Count
$previewed = @($data | Where-Object Status -EQ 'WhatIf').Count
$summary = "Account deletion complete: $deleted deleted, $previewed previewed, $failed failed."
New-FastPASResult -Success ($failed -eq 0) -Summary $summary -Data $data -Artifacts @($csv) -AuditEvents @($data)
