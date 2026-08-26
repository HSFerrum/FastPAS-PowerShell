[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify an onboarding workbench CSV.' }
$items = @(Import-Csv -LiteralPath $path);
if (-not $items.Count) { throw 'The CSV contains no decisions.' };
if ($items.Count -gt 1000) { throw 'Onboarding decisions are limited to 1000 rows per run.' }
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $action = ([string]$item.Action).Trim();
    if ($action -in @('', 'Review', 'Skip')) { continue };
    $id = [string]$item.DiscoveredAccountId;
    $status = 'Completed';
    $detail = ''
    try {
        if ($action -notin @('Onboard', 'Ignore')) { throw "Unsupported Action '$action'. Use Onboard, Ignore, Review, or Skip." };
        if (-not $id) { throw 'DiscoveredAccountId is required.' }
        if ($item.DuplicateAccountId -and $action -eq 'Onboard') { throw "DuplicateAccountId '$($item.DuplicateAccountId)' is populated. Clear it only after validating the duplicate." }
        if (-not $PSCmdlet.ShouldProcess($id, "$action discovered account")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Ignore') {
            $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path "DiscoveredAccounts/$([uri]::EscapeDataString($id))";
            $detail = 'Discovered item cleared from the pending list.'
        }
        else {
            foreach ($required in 'RecommendedPlatformId', 'RecommendedSafeName') { if (-not $item.$required) { throw "$required is required for Onboard." } }
            $body = [ordered]@{platformID = [string]$item.RecommendedPlatformId;
                safeName = [string]$item.RecommendedSafeName
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$item.ShouldReconcileAccount)) { $body.shouldReconcileAccount = ConvertTo-FastPASStrictBoolean $item.ShouldReconcileAccount 'ShouldReconcileAccount' }
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
            UserName = [string]$item.UserName;
            Address = [string]$item.Address;
            SafeName = [string]$item.RecommendedSafeName;
            PlatformId = [string]$item.RecommendedPlatformId;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'discovered_onboarding_results';
$failed = @($data | Where-Object Status -EQ Failed).Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) onboarding decision(s): $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
