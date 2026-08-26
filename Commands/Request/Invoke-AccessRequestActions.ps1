[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify an access-request-actions CSV.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The CSV contains no actions.' };
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $action = ([string]$item.Action).Trim();
    $id = [string]$item.RequestId;
    $status = 'Completed';
    $detail = '';
    try {
        if ($action -notin @('Create', 'Approve', 'Reject')) { throw 'Action must be Create, Approve, or Reject.' };
        if ($action -ne 'Create' -and -not $id) { throw 'RequestId is required for Approve and Reject.' };
        if (-not $item.Reason) { throw 'Reason is required.' };
        $target = if ($id) { $id }else { [string]$item.AccountId };
        if (-not $PSCmdlet.ShouldProcess($target, "$action access request")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Create') {
            if (-not $item.AccountId) { throw 'AccountId is required for Create.' };
            $from = if ($item.From) { [DateTimeOffset]::Parse([string]$item.From) }else { [DateTimeOffset]::UtcNow };
            $to = if ($item.To) { [DateTimeOffset]::Parse([string]$item.To) }else { $from.AddHours(1) };
            if ($to -le $from) { throw 'To must be later than From.' };
            $body = @{AccountId = [string]$item.AccountId;
                Reason = [string]$item.Reason;
                FromDate = $from.ToUnixTimeSeconds();
                ToDate = $to.ToUnixTimeSeconds();
                MultipleAccessRequired = ("$($item.MultipleAccessRequired)" -match '^(?i:true|yes|1)$')
            };
            $created = Invoke-FastPASApiRequest -Context $Context -Method POST -Path 'MyRequests' -Body $body;
            $id = Get-FastPASObjectString $created @('RequestID', 'requestId', 'id');
            $detail = 'Access request created.'
        }
        else {
            $verb = if ($action -eq 'Approve') { 'Confirm' }else { 'Reject' };
            $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "IncomingRequests/$([uri]::EscapeDataString($id))/$verb" -Body @{reason = [string]$item.Reason };
            $detail = "$action request accepted."
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    };
    $results.Add([pscustomobject]@{Action = $action;
            RequestId = $id;
            AccountId = [string]$item.AccountId;
            Reason = [string]$item.Reason;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'access_request_action_results';
$failed = @($data | Where-Object Status -EQ Failed).Count;
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) access-request action(s): $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
