[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify an onboarding workbench CSV.' }
$items = @(Import-Csv -LiteralPath $path);
if (-not $items.Count) { throw 'The CSV contains no decisions.' };
if ($items.Count -gt 1000) { throw 'Onboarding decisions are limited to 1000 rows per run.' }
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $action = (Get-FastPASRowString $item @('Action'));
    if ($action -in @('', 'Review', 'Skip')) { continue };
    $id = Get-FastPASRowString $item @('DiscoveredAccountId');
    $status = 'Completed';
    $detail = ''
    try {
        if ($action -notin @('Onboard', 'Ignore')) { throw "Unsupported Action '$action'. Use Onboard, Ignore, Review, or Skip." };
        if (-not $id) { throw 'DiscoveredAccountId is required.' }
        $duplicateId = Get-FastPASRowString $item @('DuplicateAccountId')
        $body = $null
        if ($duplicateId -and $action -eq 'Onboard') { throw "DuplicateAccountId '$duplicateId' is populated. Clear it only after validating the duplicate." }
        if ($action -eq 'Onboard') {
            $platformId = Get-FastPASRowString $item @('RecommendedPlatformId')
            $safeName = Get-FastPASRowString $item @('RecommendedSafeName')
            if (-not $platformId) { throw 'RecommendedPlatformId is required for Onboard.' }
            if (-not $safeName) { throw 'RecommendedSafeName is required for Onboard.' }
            $body = [ordered]@{platformID = $platformId; safeName = $safeName}
            $shouldReconcile = Get-FastPASRowString $item @('ShouldReconcileAccount')
            if ($shouldReconcile) { $body.shouldReconcileAccount = ConvertTo-FastPASStrictBoolean $shouldReconcile 'ShouldReconcileAccount' }
        }
        if (-not $PSCmdlet.ShouldProcess($id, "$action discovered account")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Ignore') {
            $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path "DiscoveredAccounts/$([uri]::EscapeDataString($id))";
            $detail = 'Discovered item cleared from the pending list.'
        }
        else {
            $created = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "DiscoveredAccounts/$([uri]::EscapeDataString($id))/Onboard" -Body $body;
            $detail = "Discovered account onboarding accepted$(if($created){": $(Get-FastPASObjectString $created @('id','ID') 'response returned')"}else{'.'})."
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{Action = $action;
            DiscoveredAccountId = $id;
            UserName = Get-FastPASRowString $item @('UserName');
            Address = Get-FastPASRowString $item @('Address');
            SafeName = Get-FastPASRowString $item @('RecommendedSafeName');
            PlatformId = Get-FastPASRowString $item @('RecommendedPlatformId');
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'discovered_onboarding_results';
$failed = @($data | Where-Object Status -EQ Failed).Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) onboarding decision(s): $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
