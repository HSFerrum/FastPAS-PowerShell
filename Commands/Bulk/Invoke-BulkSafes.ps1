[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$csvPath = [string]$Arguments['CsvPath'];
if (-not $csvPath -or -not(Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'CsvPath must identify an existing bulk-safes CSV file.' }
$items = @(Import-Csv -LiteralPath $csvPath);
if (-not $items.Count) { throw 'The CSV contains no data rows.' };
if ($items.Count -gt 1000) { throw 'Bulk safe operations are limited to 1000 rows.' }
foreach ($required in 'Action', 'SafeName') { if ($items[0].PSObject.Properties.Name -notcontains $required) { throw "The CSV requires a '$required' column." } }
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $action = [string]$item.Action;
    $name = [string]$item.SafeName;
    $status = 'Completed';
    $detail = ''
    try {
        if ($action -notin @('Create', 'Update', 'Delete')) { throw "Unsupported Action '$action'. Use Create, Update, or Delete." }
        if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 28) { throw 'SafeName is required and cannot exceed 28 characters.' }
        if (-not $PSCmdlet.ShouldProcess($name, "$action CyberArk safe")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Create') {
            $body = [ordered]@{safeName = $name;
                description = [string]$item.Description;
                olacEnabled = $false
            }
            if ($item.ManagingCPM) { $body.managingCPM = [string]$item.ManagingCPM };
            if ($item.NumberOfDaysRetention) {
                $body.numberOfDaysRetention = [int]$item.NumberOfDaysRetention
            }
            elseif ($item.NumberOfVersionsRetention) {
                $body.numberOfVersionsRetention = [int]$item.NumberOfVersionsRetention
            }
            else {
                $body.numberOfVersionsRetention = 5
            }
            $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path 'Safes' -Body $body;
            $detail = 'Safe created.'
        }
        else {
            $safe = Resolve-FastPASSafe -Context $Context -SafeName $name;
            $id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId');
            $path = "Safes/$([uri]::EscapeDataString($id))"
            if ($action -eq 'Delete') {
                $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path $path;
                $detail = 'Safe deleted.'
            }
            else {
                $body = [ordered]@{safeName = $name;
                    description = [string]$item.Description;
                    olacEnabled = $false
                };
                if ($item.ManagingCPM) { $body.managingCPM = [string]$item.ManagingCPM };
                if ($item.NumberOfDaysRetention) { $body.numberOfDaysRetention = [int]$item.NumberOfDaysRetention }elseif ($item.NumberOfVersionsRetention) { $body.numberOfVersionsRetention = [int]$item.NumberOfVersionsRetention };
                $null = Invoke-FastPASApiRequest -Context $Context -Method PUT -Path $path -Body $body;
                $detail = 'Safe updated.'
            }
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{Action = $action;
            SafeName = $name;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'bulk_safes_result';
$failed = @($data | Where-Object Status -EQ 'Failed').Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Bulk safe operation complete: $($data.Count-$failed) succeeded/previewed, $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
