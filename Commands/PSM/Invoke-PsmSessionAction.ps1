[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify a PSM session-actions CSV.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The CSV contains no actions.' };
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $id = [string]$item.SessionId;
    $action = ([string]$item.Action).Trim();
    $status = 'Completed';
    $detail = '';
    try {
        if ($action -notin @('Suspend', 'Resume', 'Terminate')) { throw 'Action must be Suspend, Resume, or Terminate.' };
        if (-not $id) { throw 'SessionId is required.' };
        if (-not $item.Reason) { throw 'Reason is required for the audit trail.' };
        if (-not $PSCmdlet.ShouldProcess($id, "$action PSM session")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        else {
            $body = @{reason = [string]$item.Reason };
            $paths = @("LiveSessions/$([uri]::EscapeDataString($id))/$($action.ToLowerInvariant())", "PSM/LiveSessions/$([uri]::EscapeDataString($id))/$($action.ToLowerInvariant())");
            $last = $null;
            $done = $false;
            foreach ($endpoint in $paths) {
                try {
                    $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path $endpoint -Body $body;
                    $done = $true;
                    break
                }
                catch { $last = $_ }
            };
            if (-not $done) { throw $last };
            $detail = "$action request accepted."
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    };
    $results.Add([pscustomobject]@{SessionId = $id;
            Action = $action;
            Reason = [string]$item.Reason;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'psm_session_action_results';
$failed = @($data | Where-Object Status -EQ Failed).Count;
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) PSM session action(s): $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
