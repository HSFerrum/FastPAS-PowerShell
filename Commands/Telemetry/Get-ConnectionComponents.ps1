[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$lookback = if ($Arguments['LookbackDays']) { [int]$Arguments['LookbackDays'] }else { 7 }
if ($lookback -lt 1 -or $lookback -gt 365) { throw 'LookbackDays must be between 1 and 365.' }
$to = [DateTimeOffset]::UtcNow;
$from = $to.AddDays(-$lookback)
$recordings = @(Get-FastPASPagedItems -Context $Context -Path 'Recordings' -Query @{fromTime = $from.ToUnixTimeSeconds();
        toTime = $to.ToUnixTimeSeconds();
        sort = '-PSMStartTime'
    } -CollectionNames @('value', 'Recordings'))
$usage = @{}
foreach ($recording in $recordings) {
    $component = Get-FastPASObjectString $recording @('ConnectionComponent', 'connectionComponent', 'ConnectionComponentID', 'connectionComponentId', 'Client', 'client', 'Protocol', 'protocol') 'Unknown PSM component'
    $method = Get-FastPASObjectString $recording @('Protocol', 'protocol')
    if (-not $usage.ContainsKey($component)) {
        $usage[$component] = [ordered]@{Count = 0;
            Methods = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        }
    }
    $usage[$component].Count++
    if ($method) { $null = $usage[$component].Methods.Add($method) }
}
$total = $recordings.Count
$rows = @($usage.GetEnumerator() | ForEach-Object { [pscustomobject]@{
            Component = $_.Key;
            TotalConnections = $_.Value.Count
            PercentOfTotal = if ($total) { [Math]::Round(($_.Value.Count / $total) * 100, 1) }else { 0 }
            AccessMethods = (@($_.Value.Methods | Sort-Object) -join '; ')
            WindowStart = $from.ToString('u');
            WindowEnd = $to.ToString('u')
        } } | Sort-Object @{Expression = 'TotalConnections';
        Descending = $true
    }, Component)
$csv = Export-FastPASCsv $rows $OutputPath 'component_usage'
$html = Export-FastPASHtmlDashboard $rows $OutputPath 'component_usage' 'FastPAS Most Used Components' @{TotalConnections = $total;
    Components = $rows.Count;
    Window = "$lookback days";
    Source = 'PSM Recordings'
}
New-FastPASResult -Success $true -Summary "Found $($rows.Count) connection component(s) across $total session recording(s) in the past $lookback day(s)." -Data $rows -Artifacts @($csv, $html)
