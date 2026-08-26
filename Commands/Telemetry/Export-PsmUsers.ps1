[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$lookback = if ($Arguments['LookbackDays']) { [int]$Arguments['LookbackDays'] }else { 90 };
if ($lookback -lt 1 -or $lookback -gt 3650) { throw 'LookbackDays must be between 1 and 3650.' }
$to = [DateTimeOffset]::UtcNow;
$from = $to.AddDays(-$lookback)
$recordings = @(Get-FastPASPagedItems -Context $Context -Path 'Recordings' -Query @{fromTime = $from.ToUnixTimeSeconds();
        toTime = $to.ToUnixTimeSeconds();
        sort = '-PSMStartTime'
    } -CollectionNames @('Recordings', 'value'))
function Convert-PsmTime($value) {
    if ($null -eq $value -or -not "$value") { return $null };
    $epoch = 0L;
    if ([int64]::TryParse("$value", [ref]$epoch)) { return $(if ([Math]::Abs($epoch).ToString().Length -gt 10) { [DateTimeOffset]::FromUnixTimeMilliseconds($epoch) }else { [DateTimeOffset]::FromUnixTimeSeconds($epoch) }) };
    $parsed = [DateTimeOffset]::MinValue;
    if ([DateTimeOffset]::TryParse("$value", [ref]$parsed)) { return $parsed };
    return $null
}
$rows = [Collections.Generic.List[object]]::new()
foreach ($group in @($recordings | Group-Object { Get-FastPASObjectString $_ @('PSMVaultUserName', 'UserName', 'VaultUserName', 'Username') '<unknown>' })) {
    if ($group.Name -eq '<unknown>') { continue };
    $times = @($group.Group | ForEach-Object { Convert-PsmTime (Get-FastPASPropertyValue $_ @('PSMStartTime', 'StartTime', 'Start', 'CreationDate')) } | Where-Object { $_ } | Sort-Object)
    $rows.Add([pscustomobject]@{UserName = $group.Name;
            SessionCount = $group.Count;
            FirstSession = if ($times.Count) { $times[0].ToString('s') }else { '' };
            LastSession = if ($times.Count) { $times[-1].ToString('s') }else { '' };
            Protocols = @($group.Group | ForEach-Object { Get-FastPASObjectString $_ @('Protocol', 'PSMProtocol') } | Where-Object { $_ } | Sort-Object -Unique) -join '; ';
            Clients = @($group.Group | ForEach-Object { Get-FastPASObjectString $_ @('Client', 'PSMClientApp') } | Where-Object { $_ } | Sort-Object -Unique) -join '; ';
            Safes = @($group.Group | ForEach-Object { Get-FastPASObjectString $_ @('SafeName') } | Where-Object { $_ } | Sort-Object -Unique) -join '; ';
            RemoteMachines = @($group.Group | ForEach-Object { Get-FastPASObjectString $_ @('RemoteMachine', 'AccountAddress') } | Where-Object { $_ } | Sort-Object -Unique) -join '; '
        })
}
$data = @($rows | Sort-Object @{Expression = 'SessionCount';
        Descending = $true
    }, UserName);
$csv = Export-FastPASCsv $data $OutputPath 'psm_users';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'psm_users' 'FastPAS PSM Users' @{Users = $data.Count;
    Sessions = $recordings.Count;
    Window = "$lookback days"
}
New-FastPASResult -Success $true -Summary "Summarized $($recordings.Count) PSM recording(s) across $($data.Count) vault user(s)." -Data $data -Artifacts @($csv, $html)
