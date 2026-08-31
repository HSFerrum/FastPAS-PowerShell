[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$csvEncoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
$csvPath = [string]$Arguments['CsvPath'];
if (-not $csvPath -or -not(Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'CsvPath must identify an existing safe CPM assignment CSV file.' }
$items = @(Import-Csv -LiteralPath $csvPath);
if (-not $items.Count) { throw 'The CSV contains no data rows.' };
if ($items.Count -gt 5000) { throw 'Safe CPM imports are limited to 5000 rows.' }
foreach ($required in 'SafeName', 'ManagingCPM') { if ($items[0].PSObject.Properties.Name -notcontains $required) { throw "The CSV requires a '$required' column." } }
$outputDirectory = Get-FastPASOutputDirectory $OutputPath;
$checkpoint = Join-Path $outputDirectory ("safe_cpm_remaining_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
$work = [Collections.Generic.List[object]]::new();
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $safeName = Get-FastPASRowString $item @('SafeName');
    $desiredRaw = [string]$item.ManagingCPM
    if (-not $safeName) {
        $results.Add([pscustomobject]@{SafeName = '';
                PreviousManagingCPM = '';
                DesiredManagingCPM = '';
                Status = 'Failed';
                Detail = 'SafeName is required.'
            });
        continue
    }
    if (-not $seen.Add($safeName)) {
        $results.Add([pscustomobject]@{SafeName = $safeName;
                PreviousManagingCPM = '';
                DesiredManagingCPM = $desiredRaw;
                Status = 'Failed';
                Detail = 'Duplicate safe row in CSV.'
            });
        continue
    }
    if ([string]::IsNullOrWhiteSpace($desiredRaw)) {
        $results.Add([pscustomobject]@{SafeName = $safeName;
                PreviousManagingCPM = [string]$item.CurrentManagingCPM;
                DesiredManagingCPM = '';
                Status = 'Skipped';
                Detail = 'ManagingCPM is blank.'
            });
        continue
    }
    $desired = if ($desiredRaw.Trim() -match '^(?i:NULL|<NONE>)$') { '' }else { $desiredRaw.Trim() };
    $work.Add([pscustomobject]@{Source = $item;
            SafeName = $safeName;
            Desired = $desired
        })
}
$remaining = [Collections.Generic.List[object]]::new();
foreach ($entry in $work) { $remaining.Add($entry.Source) }
function Save-RemainingCheckpoint {
    if ($WhatIfPreference) { return };
    if ($remaining.Count) { @($remaining) | Export-Csv -LiteralPath $checkpoint -NoTypeInformation -Encoding $csvEncoding }else { if (Test-Path -LiteralPath $checkpoint) { Remove-Item -LiteralPath $checkpoint -Force } }
}
Save-RemainingCheckpoint
foreach ($entry in $work) {
    $item = $entry.Source;
    $safeName = $entry.SafeName;
    $desired = $entry.Desired;
    $previous = '';
    $status = 'Updated';
    $detail = ''
    try {
        $safe = Resolve-FastPASSafe -Context $Context -SafeName $safeName;
        $id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId');
        if (-not $id) { throw "Safe '$safeName' did not return a safeUrlId." };
        $safe = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Safes/$([uri]::EscapeDataString($id))";
        $previous = Get-FastPASObjectString $safe @('managingCPM', 'ManagingCPM')
        $snapshotHash = Get-FastPASRowString $item @('SnapshotHash');
        $exportedCurrent = Get-FastPASRowString $item @('CurrentManagingCPM')
        if ($snapshotHash -and $snapshotHash -ne (Get-FastPASSafeSnapshotHash $safe)) { throw 'Snapshot conflict: the safe changed after export. Re-export before applying this row.' }
        if (-not $snapshotHash -and $item.PSObject.Properties.Name -contains 'CurrentManagingCPM' -and $previous -ne $exportedCurrent) { throw "Snapshot conflict: current ManagingCPM is '$previous', not exported value '$exportedCurrent'." }
        if ($previous -eq $desired) {
            $status = 'Skipped';
            $detail = 'Safe already has the requested ManagingCPM.'
        }
        elseif (-not $PSCmdlet.ShouldProcess($safeName, "Change ManagingCPM from '$previous' to '$desired'")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        else {
            $body = New-FastPASSafeUpdateBody -Safe $safe -ManagingCPM $desired;
            $null = Invoke-FastPASApiRequest -Context $Context -Method PUT -Path "Safes/$([uri]::EscapeDataString($id))" -Body $body
            $verified = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Safes/$([uri]::EscapeDataString($id))";
            $actual = Get-FastPASObjectString $verified @('managingCPM', 'ManagingCPM');
            if ($actual -ne $desired) { throw "Post-update verification returned ManagingCPM '$actual'." };
            $detail = 'ManagingCPM updated and verified.'
        }
        if ($status -in @('Updated', 'Skipped', 'WhatIf')) { $remaining.Remove($item) | Out-Null }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{SafeName = $safeName;
            PreviousManagingCPM = $previous;
            DesiredManagingCPM = $desired;
            Status = $status;
            Detail = $detail
        });
    Save-RemainingCheckpoint
}
$data = @($results);
$resultCsv = Export-FastPASCsv $data $OutputPath 'safe_cpm_import_result';
$failed = @($data | Where-Object Status -EQ 'Failed').Count;
$artifacts = [Collections.Generic.List[string]]::new();
$artifacts.Add($resultCsv);
if (Test-Path -LiteralPath $checkpoint) { $artifacts.Add($checkpoint) }
$updatedCount = @($data | Where-Object Status -EQ 'Updated').Count
$skippedCount = @($data | Where-Object Status -EQ 'Skipped').Count
$summary = "Safe CPM import: $updatedCount updated, $skippedCount skipped, $failed failed."
New-FastPASResult -Success ($failed -eq 0) -Summary $summary -Data $data -Artifacts @($artifacts) -AuditEvents @($data)
