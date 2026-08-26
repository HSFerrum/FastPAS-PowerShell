[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$lookback = if ($Arguments['LookbackDays']) { [int]$Arguments['LookbackDays'] }else { 7 }
if ($lookback -lt 1 -or $lookback -gt 365) { throw 'LookbackDays must be between 1 and 365.' }
$failures = [Collections.Generic.List[object]]::new();
$warnings = [Collections.Generic.List[string]]::new()
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -CollectionNames @('value', 'Accounts'))
foreach ($account in $accounts) {
    $row = ConvertTo-FastPASAccountRow $account
    $management = Get-FastPASPropertyValue $account @('secretManagement', 'SecretManagement')
    $automatic = Get-FastPASPropertyValue $management @('automaticManagementEnabled', 'AutomaticManagementEnabled')
    if ($row.ManagementStatus -ieq 'failure' -or $row.FailureReason) {
        $failures.Add([pscustomobject]@{Service = 'CPM';
                FailureType = if ($row.FailureReason) { $row.FailureReason }else { 'Password management failed' };
                AccountId = $row.AccountId;
                AccountName = $row.Name;
                SafeName = $row.SafeName;
                UserName = $row.UserName;
                Address = $row.Address;
                PlatformId = $row.PlatformId;
                Detail = $row.FailureReason;
                Resolvable = $true
            })
    }
    if ($automatic -eq $false) {
        $failures.Add([pscustomobject]@{Service = 'CPM';
                FailureType = 'Automatic management disabled';
                AccountId = $row.AccountId;
                AccountName = $row.Name;
                SafeName = $row.SafeName;
                UserName = $row.UserName;
                Address = $row.Address;
                PlatformId = $row.PlatformId;
                Detail = 'Automatic password management is disabled.';
                Resolvable = $true
            })
    }
}
$to = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds();
$from = [DateTimeOffset]::UtcNow.AddDays(-$lookback).ToUnixTimeSeconds()
try {
    $recordings = @(Get-FastPASPagedItems -Context $Context -Path 'Recordings' -Query @{fromTime = $from;
            toTime = $to;
            sort = '-PSMStartTime'
        } -CollectionNames @('value', 'Recordings'))
    foreach ($recording in $recordings) {
        $status = Get-FastPASObjectString $recording @('Status', 'SessionStatus', 'RecordingStatus')
        $detail = Get-FastPASObjectString $recording @('FailureReason', 'Error', 'Message', 'Details')
        if ("$status $detail" -notmatch '(?i)fail|error|disconnect|terminated|denied|timeout|exception') { continue }
        $failures.Add([pscustomobject]@{
                Service = 'PSM';
                FailureType = if ($detail) { $detail }elseif ($status) { $status }else { 'PSM connection failed' }
                AccountId = Get-FastPASObjectString $recording @('AccountID', 'accountId');
                AccountName = Get-FastPASObjectString $recording @('AccountName', 'Account') 'Unknown account'
                SafeName = Get-FastPASObjectString $recording @('SafeName', 'Safe') 'Unknown safe';
                UserName = Get-FastPASObjectString $recording @('User', 'Username', 'AccountUsername')
                Address = Get-FastPASObjectString $recording @('Address', 'RemoteMachine', 'Target');
                PlatformId = Get-FastPASObjectString $recording @('PlatformID', 'Platform')
                Detail = if ($detail) { $detail }else { $status };
                Resolvable = $false
            })
    }
}
catch { $warnings.Add("PSM recording evidence was unavailable; CPM analysis is still complete. $($_.Exception.Message)") }
$rows = @($failures | Sort-Object Service, FailureType, SafeName, AccountName)
$csv = Export-FastPASCsv $rows $OutputPath 'account_failures'
$html = Export-FastPASHtmlDashboard $rows $OutputPath 'account_failures' 'FastPAS Account Failure Analysis' @{AccountsScanned = $accounts.Count;
    Failures = $rows.Count;
    CPM = @($rows | Where-Object Service -EQ CPM).Count;
    PSM = @($rows | Where-Object Service -EQ PSM).Count;
    Resolvable = @($rows | Where-Object Resolvable).Count
}
New-FastPASResult -Success $true -Summary "Found $($rows.Count) failure signal(s) across $($accounts.Count) account(s)." -Data $rows -Warnings @($warnings) -Artifacts @($csv, $html)
