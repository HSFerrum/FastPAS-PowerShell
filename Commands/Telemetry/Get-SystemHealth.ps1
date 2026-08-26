[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$warnings = [Collections.Generic.List[string]]::new();
$rows = [Collections.Generic.List[object]]::new();
$components = @()
try {
    $summary = Invoke-FastPASApiRequest -Context $Context -Method GET -Path 'ComponentsMonitoringSummary';
    $components = @(Get-FastPASPropertyValue $summary @('Components', 'components'));
    foreach ($vault in @(Get-FastPASPropertyValue $summary @('Vaults', 'vaults'))) {
        $components += @([pscustomobject]@{ComponentType = 'EPV';
                ComponentName = 'EPV';
                Status = if ([bool](Get-FastPASPropertyValue $vault @('IsLoggedOn', 'isLoggedOn'))) { 'Connected' }else { 'Disconnected' };
                Address = Get-FastPASObjectString $vault @('IP', 'ip');
                Role = Get-FastPASObjectString $vault @('Role', 'role');
                Detail = $vault
            })
    }
}
catch { $warnings.Add("Component monitoring summary is unavailable for this tenant or role: $($_.Exception.Message)") }
foreach ($component in $components) {
    $status = Get-FastPASObjectString $component @('status', 'Status', 'componentStatus', 'ComponentStatus') 'Unknown';
    $rows.Add([pscustomobject][ordered]@{ComponentType = Get-FastPASObjectString $component @('componentType', 'ComponentType', 'type', 'Type') 'CyberArk';
            ComponentName = Get-FastPASObjectString $component @('componentName', 'ComponentName', 'name', 'Name', 'componentID', 'ComponentID');
            Status = $status;
            Address = Get-FastPASObjectString $component @('address', 'Address', 'hostName', 'HostName');
            LastHeartbeat = Get-FastPASObjectString $component @('lastLogonDate', 'LastLogonDate', 'lastHeartbeat', 'LastHeartbeat');
            Version = Get-FastPASObjectString $component @('version', 'Version');
            Load = Get-FastPASObjectString $component @('load', 'Load', 'activeSessions', 'ActiveSessions');
            Detail = ($component | ConvertTo-Json -Compress -Depth 20)
        })
}
$componentIds = @($components | ForEach-Object { Get-FastPASObjectString $_ @('componentID', 'ComponentID') } | Where-Object { $_ -in @('PVWA', 'SessionManagement', 'CPM', 'AIM', 'PTA') } | Sort-Object -Unique)
foreach ($componentId in $componentIds) {
    try {
        $detailResponse = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "ComponentsMonitoringDetails/$componentId";
        foreach ($detailItem in @(Get-FastPASPropertyValue $detailResponse @('ComponentsDetails', 'componentsDetails'))) {
            $rows.Add([pscustomobject][ordered]@{ComponentType = $componentId;
                    ComponentName = Get-FastPASObjectString $detailItem @('ComponentSpecificStat', 'componentName', 'ComponentName', 'Name') $componentId;
                    Status = Get-FastPASObjectString $detailItem @('IsLoggedOn', 'status', 'Status') 'Observed';
                    Address = Get-FastPASObjectString $detailItem @('IP', 'address', 'Address');
                    LastHeartbeat = Get-FastPASObjectString $detailItem @('LastLogonDate', 'lastHeartbeat');
                    Version = Get-FastPASObjectString $detailItem @('Version', 'version');
                    Load = '';
                    Detail = ($detailItem | ConvertTo-Json -Compress -Depth 20)
                })
        }
    }
    catch { $warnings.Add("Component detail '$componentId' is unavailable: $($_.Exception.Message)") }
}
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -CollectionNames @('value', 'Accounts'));
$cpmGroups = $accounts | Group-Object { $management = Get-FastPASPropertyValue $_ @('secretManagement', 'SecretManagement');
    Get-FastPASObjectString $management @('managingCPM', 'ManagingCPM') 'Unassigned' }
foreach ($group in $cpmGroups) {
    $failed = @($group.Group | Where-Object { (Get-FastPASObjectString (Get-FastPASPropertyValue $_ @('secretManagement', 'SecretManagement')) @('status', 'Status')) -match '(?i)fail|error' }).Count;
    $rows.Add([pscustomobject]@{ComponentType = 'CPM workload';
            ComponentName = $group.Name;
            Status = if ($failed) { 'Degraded' }else { 'Observed' };
            Address = '';
            LastHeartbeat = '';
            Version = '';
            Load = $group.Count;
            Detail = "$failed account management failure(s)"
        })
}
$live = @(Get-FastPASOptionalItems -Context $Context -Paths @('LiveSessions', 'PSM/LiveSessions') -CollectionNames @('value', 'LiveSessions', 'Sessions') -Warnings $warnings)
if ($live.Count) {
    $rows.Add([pscustomobject]@{ComponentType = 'PSM workload';
            ComponentName = 'Active sessions';
            Status = 'Observed';
            Address = '';
            LastHeartbeat = '';
            Version = '';
            Load = $live.Count;
            Detail = 'Active sessions returned by the tenant.'
        })
}
$data = @($rows | Sort-Object ComponentType, ComponentName);
$csv = Export-FastPASCsv $data $OutputPath 'system_health';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'system_health' 'FastPAS Component Health and Capacity' @{Components = @($components).Count;
    Unhealthy = @($data | Where-Object Status -Match '(?i)fail|error|down|degraded').Count;
    Accounts = $accounts.Count;
    ActivePSMSessions = $live.Count;
    CPMWorkloads = $cpmGroups.Count
}
New-FastPASResult -Success $true -Summary "Collected $($data.Count) component and workload signal(s). Endpoint restrictions are shown as warnings." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
