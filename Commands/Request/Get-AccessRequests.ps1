[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$query = @{expired = 'false' };
if ("$($Arguments['OnlyWaiting'])" -match '^(?i:true|yes|1)$') { $query.onlyWaiting = 'true' }else { $query.onlyWaiting = 'false' };
$statusFilter = [string]$Arguments['Status'];
$warnings = [Collections.Generic.List[string]]::new();
$requests = [Collections.Generic.List[object]]::new()
foreach ($queue in 'MyRequests', 'IncomingRequests') {
    foreach ($request in @(Get-FastPASOptionalItems -Context $Context -Paths @($queue) -Query $query -CollectionNames @($queue, 'value', 'Requests', 'requests') -Warnings $warnings)) {
        $requests.Add([pscustomobject]@{Queue = $queue;
                Request = $request
            })
    }
}
$rows = foreach ($entry in $requests) {
    $request = $entry.Request;
    $account = Get-FastPASPropertyValue $request @('AccountDetails', 'accountDetails', 'account');
    $status = Get-FastPASObjectString $request @('Status', 'status');
    if ($statusFilter -and $status -notlike "*$statusFilter*") { continue };
    [pscustomobject][ordered]@{Queue = $entry.Queue;
        RequestId = Get-FastPASObjectString $request @('RequestID', 'requestId', 'id');
        Status = $status;
        Requestor = Get-FastPASObjectString $request @('UserName', 'userName', 'Requestor', 'requestor');
        AccountId = Get-FastPASObjectString $account @('AccountID', 'accountId', 'id');
        AccountName = Get-FastPASObjectString $account @('AccountName', 'accountName', 'name');
        SafeName = Get-FastPASObjectString $account @('SafeName', 'safeName');
        Reason = Get-FastPASObjectString $request @('Reason', 'reason');
        From = Get-FastPASObjectString $request @('FromDate', 'fromDate', 'from');
        To = Get-FastPASObjectString $request @('ToDate', 'toDate', 'to');
        Ticket = Get-FastPASObjectString $request @('TicketingSystemProperties', 'ticketId', 'TicketId');
        Confirmations = @(Get-FastPASPropertyValue $request @('Confirmations', 'confirmations')).Count;
        Detail = ($request | ConvertTo-Json -Compress -Depth 30)
    }
}
$data = @($rows | Sort-Object Status, From);
$csv = Export-FastPASCsv $data $OutputPath 'access_request_queue';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'access_request_queue' 'FastPAS Dual-Control Request and Approval Queue' @{Requests = $data.Count;
    Incoming = @($data | Where-Object Queue -EQ IncomingRequests).Count;
    Mine = @($data | Where-Object Queue -EQ MyRequests).Count;
    Waiting = @($data | Where-Object Status -Match '(?i)wait|pending').Count;
    Approved = @($data | Where-Object Status -Match '(?i)approve|confirm').Count;
    Requestors = @($data | ForEach-Object Requestor | Where-Object { $_ } | Sort-Object -Unique).Count
}
New-FastPASResult -Success $true -Summary "Returned $($data.Count) access request(s)." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
