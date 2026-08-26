[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$platforms = @(Get-FastPASPagedItems -Context $Context -Path 'Platforms/Targets' -CollectionNames @('Platforms', 'platforms', 'value') -Limit 100)
$search = [string]$Arguments['Search']
$rows = @($platforms | ForEach-Object { $details = Get-FastPASPropertyValue $_ @('Details', 'details');
        [pscustomobject]@{
            PlatformId = Get-FastPASObjectString $_ @('ID', 'id', 'PlatformID', 'platformId');
            Name = if ($details) { Get-FastPASObjectString $details @('PolicyName', 'policyName', 'Name', 'name') }else { Get-FastPASObjectString $_ @('Name', 'name') }
            Active = Get-FastPASPropertyValue $_ @('Active', 'active');
            SystemType = if ($details) { Get-FastPASObjectString $details @('SystemType', 'systemType') }else { Get-FastPASObjectString $_ @('SystemType', 'systemType') }
            PlatformType = Get-FastPASObjectString $_ @('PlatformType', 'platformType');
            Description = if ($details) { Get-FastPASObjectString $details @('Description', 'description') }else { Get-FastPASObjectString $_ @('Description', 'description') }
        } } | Where-Object { -not $search -or $_.PlatformId -like "*$search*" -or $_.Name -like "*$search*" } | Sort-Object PlatformId)
$csv = Export-FastPASCsv $rows $OutputPath 'platform_inventory';
$html = Export-FastPASHtmlDashboard $rows $OutputPath 'platform_inventory' 'FastPAS Target Platforms' @{Platforms = $rows.Count;
    Active = @($rows | Where-Object Active -EQ $true).Count
}
New-FastPASResult -Success $true -Summary "Exported $($rows.Count) target platform(s)." -Data $rows -Artifacts @($csv, $html)
