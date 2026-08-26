[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$safes = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -CollectionNames @('value', 'Safes'));
$rows = [Collections.Generic.List[object]]::new();
$warnings = [Collections.Generic.List[string]]::new()
foreach ($summary in $safes) {
    $name = Get-FastPASObjectString $summary @('safeName', 'SafeName');
    $id = Get-FastPASObjectString $summary @('safeUrlId', 'SafeUrlId');
    if (-not $name -or -not $id) {
        $warnings.Add('Skipped a safe missing SafeName or SafeUrlId.');
        continue
    }
    try {
        $safe = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Safes/$([uri]::EscapeDataString($id))"
        $versions = Get-FastPASPropertyValue $safe @('numberOfVersionsRetention', 'NumberOfVersionsRetention');
        $days = Get-FastPASPropertyValue $safe @('numberOfDaysRetention', 'NumberOfDaysRetention');
        if (($null -eq $versions -or "$versions" -eq '') -and ($null -eq $days -or "$days" -eq '')) { throw 'Safe details did not return a retention setting.' }
        $current = Get-FastPASObjectString $safe @('managingCPM', 'ManagingCPM')
        $rows.Add([pscustomobject][ordered]@{CpmUpdateMode = 'VerifiedSnapshot';
                SafeName = $name;
                SafeUrlId = $id;
                SnapshotHash = Get-FastPASSafeSnapshotHash $safe;
                CurrentManagingCPM = $current;
                ManagingCPM = $current;
                Description = Get-FastPASObjectString $safe @('description', 'Description');
                OLACEnabled = [bool](Get-FastPASPropertyValue $safe @('olacEnabled', 'OLACEnabled'));
                NumberOfVersionsRetention = $versions;
                NumberOfDaysRetention = $days
            })
    }
    catch { $warnings.Add("${name}: $($_.Exception.Message)") }
}
$data = @($rows | Sort-Object SafeName);
$csv = Export-FastPASCsv $data $OutputPath 'safe_cpm_assignments';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'safe_cpm_assignments' 'FastPAS Safe CPM Assignments' @{Safes = $data.Count;
    CPMs = @($data.ManagingCPM | Where-Object { $_ } | Sort-Object -Unique).Count;
    Mode = 'Verified snapshot'
}
New-FastPASResult -Success $true -Summary "Exported $($data.Count) verified safe CPM assignment snapshot(s). Edit only ManagingCPM; use NULL or <NONE> to clear it." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
