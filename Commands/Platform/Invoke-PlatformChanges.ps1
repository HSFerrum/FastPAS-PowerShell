[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify a platform-changes CSV.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The CSV contains no changes.' };
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $id = [string]$item.PlatformId;
    $property = ([string]$item.Property).Trim().TrimStart('/');
    $status = 'Completed';
    $detail = '';
    try {
        if (-not $id -or -not $property) { throw 'PlatformId and Property are required.' };
        if ($property -notmatch '^(Policy|General)(/[A-Za-z][A-Za-z0-9_-]*)+$') { throw 'Property must be a documented target-settings path beginning with Policy/ or General/.' };
        $settingsPath = "Platforms/targets/$([uri]::EscapeDataString($id))/settings";
        $before = Invoke-FastPASApiRequest -Context $Context -Method GET -Path $settingsPath;
        $hash = Get-FastPASObjectHash $before;
        if (-not $item.ExpectedHash -or $item.ExpectedHash -ne $hash) { throw "Platform changed since export. ExpectedHash is required and must equal '$hash'." }
        if (-not $PSCmdlet.ShouldProcess("$id/$property", 'Replace platform property')) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        else {
            $value = [string]$item.NewValue;
            if ($value -match '^(?i:true|false)$') { $value = [bool]::Parse($value) }elseif ($value -match '^-?\d+$') { $value = [int64]$value };
            $body = @(@{op = 'replace';
                    path = $property;
                    value = $value
                });
            $null = Invoke-FastPASApiRequest -Context $Context -Method PATCH -Path $settingsPath -Body $body;
            $after = Invoke-FastPASApiRequest -Context $Context -Method GET -Path $settingsPath;
            $detail = "Change sent and verified; new hash $(Get-FastPASObjectHash $after)."
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    };
    $results.Add([pscustomobject]@{PlatformId = $id;
            Property = $property;
            NewValue = [string]$item.NewValue;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'platform_change_results';
$failed = @($data | Where-Object Status -EQ Failed).Count;
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) guarded platform change(s): $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
