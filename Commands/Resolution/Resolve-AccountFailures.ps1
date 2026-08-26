[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$raw = $Arguments['AccountIds']
$ids = @()
if ($raw -is [Collections.IEnumerable] -and $raw -isnot [string]) { $ids = @($raw) }elseif ($raw) { $ids = @(([string]$raw) -split '[,;\s]+' ) }
$ids = @($ids | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ } | Sort-Object -Unique)
if ($ids.Count -eq 0) { throw 'AccountIds must contain at least one account ID.' }
if ($ids.Count -gt 500) { throw 'A remediation run is limited to 500 accounts.' }
if (@($ids | Where-Object { $_ -match '[/\\?#]' }).Count) { throw 'One or more account IDs contain unsupported path characters.' }
$results = [Collections.Generic.List[object]]::new();
$pending = [Collections.Generic.List[object]]::new()
foreach ($id in $ids) {
    try { $account = Resolve-FastPASAccount -Context $Context -AccountId $id }catch {
        $results.Add([pscustomobject]@{AccountId = $id;
                AccountName = '';
                SafeName = '';
                WasLocked = $false;
                Unlocked = $false;
                AutomaticManagementEnabled = $false;
                ReconcileStarted = $false;
                Resolved = $false;
                CompletionStatus = 'failed';
                FinalManagementStatus = '';
                Detail = "Account lookup failed: $($_.Exception.Message)"
            });
        continue
    }
    $row = ConvertTo-FastPASAccountRow $account;
    $lockedBy = Get-FastPASObjectString $account @('lockedBy', 'LockedBy');
    $wasLocked = $row.Locked -or [bool]$lockedBy
    $result = [pscustomobject]@{AccountId = $row.AccountId;
        AccountName = $row.Name;
        SafeName = $row.SafeName;
        WasLocked = $wasLocked;
        Unlocked = $false;
        AutomaticManagementEnabled = $false;
        ReconcileStarted = $false;
        Resolved = $false;
        CompletionStatus = 'pending';
        FinalManagementStatus = $row.ManagementStatus;
        Detail = 'Pending.'
    }
    if (-not $PSCmdlet.ShouldProcess("$($row.SafeName)/$($row.Name) [$id]", 'Unlock if needed, enable management, reconcile, and verify')) {
        $result.CompletionStatus = 'whatif';
        $result.Detail = 'WhatIf: no mutation was sent.';
        $results.Add($result);
        continue
    }
    $path = "Accounts/$([uri]::EscapeDataString($id))"
    try {
        if ($wasLocked) {
            $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "$path/Unlock";
            $result.Unlocked = $true
        }
        $patch = @(@{op = 'replace';
                path = '/secretManagement/automaticManagementEnabled';
                value = $true
            })
        $null = Invoke-FastPASApiRequest -Context $Context -Method PATCH -Path $path -Body $patch;
        $result.AutomaticManagementEnabled = $true
        $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "$path/Reconcile";
        $result.ReconcileStarted = $true;
        $result.CompletionStatus = 'processing';
        $result.Detail = 'Reconcile started; awaiting CPM completion.'
        $results.Add($result);
        $pending.Add([pscustomobject]@{Result = $result;
                Path = $path
            })
    }
    catch {
        $result.CompletionStatus = 'failed';
        $result.Detail = $_.Exception.Message;
        $results.Add($result)
    }
}
for ($attempt = 0;
    $attempt -lt 30 -and $pending.Count -gt 0;
    $attempt++) {
    if ($attempt -gt 0) { Start-Sleep -Seconds 10 }
    $remaining = [Collections.Generic.List[object]]::new()
    foreach ($item in $pending) {
        try {
            $account = Invoke-FastPASApiRequest -Context $Context -Method GET -Path $item.Path
            $management = Get-FastPASPropertyValue $account @('secretManagement', 'SecretManagement');
            $status = Get-FastPASObjectString $management @('status', 'Status');
            $reason = Get-FastPASObjectString $management @('manualManagementReason', 'failureReason', 'lastTaskFailureReason');
            $automatic = Get-FastPASPropertyValue $management @('automaticManagementEnabled', 'AutomaticManagementEnabled')
            $item.Result.FinalManagementStatus = $status
            if ($automatic -eq $true -and $status -match '^(?i:success|succeeded|successful)$') {
                $item.Result.Resolved = $true;
                $item.Result.CompletionStatus = 'completed';
                $item.Result.Detail = 'CPM completed successfully.'
            }
            else {
                $item.Result.Detail = "Reconcile still processing. Status: $(if($status){$status}else{'unknown'}). $reason";
                $remaining.Add($item)
            }
        }
        catch {
            $item.Result.Detail = "Status check failed: $($_.Exception.Message)";
            $remaining.Add($item)
        }
    }
    $pending = $remaining
}
foreach ($item in $pending) {
    $item.Result.CompletionStatus = 'timed_out';
    $item.Result.Detail = "Timed out after five minutes waiting for CPM. Last status: $($item.Result.FinalManagementStatus)."
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'account_remediation';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'account_remediation' 'FastPAS Account Remediation' @{Requested = $data.Count;
    Resolved = @($data | Where-Object Resolved).Count;
    Unresolved = @($data | Where-Object { -not $_.Resolved -and $_.CompletionStatus -ne 'whatif' }).Count;
    WhatIf = @($data | Where-Object CompletionStatus -EQ 'whatif').Count
}
$success = @($data | Where-Object { -not $_.Resolved -and $_.CompletionStatus -notin @('whatif') }).Count -eq 0
$resolvedCount = @($data | Where-Object Resolved).Count
$unresolvedCount = @($data | Where-Object { -not $_.Resolved -and $_.CompletionStatus -ne 'whatif' }).Count
$summary = "Remediation complete: $resolvedCount resolved, $unresolvedCount unresolved."
New-FastPASResult -Success $success -Summary $summary -Data $data -Artifacts @($csv, $html) -AuditEvents @($data)
