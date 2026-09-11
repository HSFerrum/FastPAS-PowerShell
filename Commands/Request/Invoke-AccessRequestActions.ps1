[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify an access-request-actions CSV.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The CSV contains no actions.' };
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $action = Get-FastPASRowString $item @('Action');
    $id = Get-FastPASRowString $item @('RequestId');
    $status = 'Completed';
    $detail = '';
    try {
        if ($action -notin @('Create', 'Approve', 'Reject')) { throw 'Action must be Create, Approve, or Reject.' };
        if ($action -ne 'Create' -and -not $id) { throw 'RequestId is required for Approve and Reject.' };
        $reason = Get-FastPASRowString $item @('Reason')
        if (-not $reason) { throw 'Reason is required.' };
        $accountId = Get-FastPASRowString $item @('AccountId')
        $body = $null
        if ($action -eq 'Create') {
            if (-not $accountId) { throw 'AccountId is required for Create.' };
            $fromText = Get-FastPASRowString $item @('From')
            $toText = Get-FastPASRowString $item @('To')
            $from = if ($fromText) { [DateTimeOffset]::Parse($fromText) }else { [DateTimeOffset]::UtcNow };
            $to = if ($toText) { [DateTimeOffset]::Parse($toText) }else { $from.AddHours(1) };
            if ($to -le $from) { throw 'To must be later than From.' };
            $multipleText = Get-FastPASRowString $item @('MultipleAccessRequired')
            $multiple = if ($multipleText) { ConvertTo-FastPASStrictBoolean $multipleText 'MultipleAccessRequired' }else { $false }
            $body = @{AccountId = $accountId; Reason = $reason; FromDate = $from.ToUnixTimeSeconds(); ToDate = $to.ToUnixTimeSeconds(); MultipleAccessRequired = $multiple}
        }
        $target = if ($id) { $id }else { $accountId };
        if (-not $PSCmdlet.ShouldProcess($target, "$action access request")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Create') {
            $created = Invoke-FastPASApiRequest -Context $Context -Method POST -Path 'MyRequests' -Body $body;
            $id = Get-FastPASObjectString $created @('RequestID', 'requestId', 'id');
            $detail = 'Access request created.'
        }
        else {
            $verb = if ($action -eq 'Approve') { 'Confirm' }else { 'Reject' };
            $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "IncomingRequests/$([uri]::EscapeDataString($id))/$verb" -Body @{reason = $reason };
            $detail = "$action request accepted."
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    };
    $results.Add([pscustomobject]@{Action = $action;
            RequestId = $id;
            AccountId = Get-FastPASRowString $item @('AccountId');
            Reason = Get-FastPASRowString $item @('Reason');
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'access_request_action_results';
$failed = @($data | Where-Object Status -EQ Failed).Count;
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) access-request action(s): $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
