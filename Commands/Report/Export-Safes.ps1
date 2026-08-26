[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$query = @{};
if ($Arguments['Search']) { $query.search = [string]$Arguments['Search'] }
$safes = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -Query $query -CollectionNames @('value', 'Safes'))
$rows = @($safes | ForEach-Object { [pscustomobject]@{
            SafeName = Get-FastPASObjectString $_ @('safeName', 'SafeName');
            SafeUrlId = Get-FastPASObjectString $_ @('safeUrlId', 'SafeUrlId')
            Description = Get-FastPASObjectString $_ @('description', 'Description');
            ManagingCPM = Get-FastPASObjectString $_ @('managingCPM', 'ManagingCPM')
            NumberOfVersionsRetention = Get-FastPASPropertyValue $_ @('numberOfVersionsRetention', 'NumberOfVersionsRetention')
            NumberOfDaysRetention = Get-FastPASPropertyValue $_ @('numberOfDaysRetention', 'NumberOfDaysRetention');
            Creator = Get-FastPASObjectString $_ @('creator', 'Creator')
        } } | Sort-Object SafeName)
$csv = Export-FastPASCsv $rows $OutputPath 'safe_inventory';
$html = Export-FastPASHtmlDashboard $rows $OutputPath 'safe_inventory' 'FastPAS Safe Inventory' @{Safes = $rows.Count;
    ManagingCPMs = @($rows.ManagingCPM | Where-Object { $_ } | Sort-Object -Unique).Count
}
New-FastPASResult -Success $true -Summary "Exported $($rows.Count) safe(s)." -Data $rows -Artifacts @($csv, $html)
