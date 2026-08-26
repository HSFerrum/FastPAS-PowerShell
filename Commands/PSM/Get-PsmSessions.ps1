[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$days = if ($Arguments['LookbackDays']) { [int]$Arguments['LookbackDays'] }else { 7 };
if ($days -lt 1 -or $days -gt 3650) { throw 'LookbackDays must be between 1 and 3650.' };
$user = [string]$Arguments['UserName'];
$warnings = [Collections.Generic.List[string]]::new();
$rows = [Collections.Generic.List[object]]::new()
$live = @(Get-FastPASOptionalItems -Context $Context -Paths @('LiveSessions', 'PSM/LiveSessions') -CollectionNames @('value', 'LiveSessions', 'Sessions') -Warnings $warnings)
$to = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds();
$from = [DateTimeOffset]::UtcNow.AddDays(-$days).ToUnixTimeSeconds();
$history = @(Get-FastPASOptionalItems -Context $Context -Paths @('Recordings') -Query @{fromTime = $from;
        toTime = $to;
        sort = '-PSMStartTime'
    } -CollectionNames @('value', 'Recordings') -Warnings $warnings)
foreach ($pair in @(@('Active', $live), @('Historical', $history))) {
    foreach ($session in @($pair[1])) {
        $username = Get-FastPASObjectString $session @('User', 'UserName', 'userName', 'Username');
        if ($user -and $username -notlike "*$user*") { continue };
        $rows.Add([pscustomobject][ordered]@{SessionType = $pair[0];
                SessionId = Get-FastPASObjectString $session @('SessionID', 'sessionId', 'RecordingID', 'recordingId', 'id');
                Status = Get-FastPASObjectString $session @('Status', 'status', 'SessionStatus') $(if ($pair[0] -eq 'Active') { 'Active' }else { 'Recorded' });
                UserName = $username;
                AccountName = Get-FastPASObjectString $session @('AccountName', 'Account', 'accountName');
                SafeName = Get-FastPASObjectString $session @('SafeName', 'Safe', 'safeName');
                Target = Get-FastPASObjectString $session @('Address', 'Target', 'RemoteMachine', 'address');
                ConnectionComponent = Get-FastPASObjectString $session @('ConnectionComponentID', 'connectionComponentId', 'Protocol');
                StartTime = Get-FastPASObjectString $session @('PSMStartTime', 'StartTime', 'startTime');
                Duration = Get-FastPASObjectString $session @('Duration', 'duration');
                Detail = ($session | ConvertTo-Json -Compress -Depth 20)
            })
    }
}
$data = @($rows | Sort-Object SessionType, StartTime -Descending);
$csv = Export-FastPASCsv $data $OutputPath 'psm_sessions';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'psm_sessions' 'FastPAS PSM Session and Incident Console' @{Active = @($data | Where-Object SessionType -EQ Active).Count;
    Historical = @($data | Where-Object SessionType -EQ Historical).Count;
    Users = @($data | ForEach-Object UserName | Where-Object { $_ } | Sort-Object -Unique).Count;
    Targets = @($data | ForEach-Object Target | Where-Object { $_ } | Sort-Object -Unique).Count
}
New-FastPASResult -Success $true -Summary "Returned $($data.Count) PSM session record(s). Use psm.sessions.action with an exported action CSV for active-session control." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
