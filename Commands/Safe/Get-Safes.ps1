[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$query = @{}
if ($Arguments['Search']) { $query.search = [string]$Arguments['Search'] }
$items = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -Query $query -CollectionNames @('value', 'Safes'))
$rows = @($items | ForEach-Object { [pscustomobject]@{
            SafeName = Get-FastPASObjectString $_ @('safeName', 'SafeName');
            SafeUrlId = Get-FastPASObjectString $_ @('safeUrlId', 'SafeUrlId')
            Description = Get-FastPASObjectString $_ @('description', 'Description');
            ManagingCPM = Get-FastPASObjectString $_ @('managingCPM', 'ManagingCPM')
            Creator = Get-FastPASObjectString $_ @('creator', 'Creator')
        } } | Sort-Object SafeName)
New-FastPASResult -Success $true -Summary "Returned $($rows.Count) safe(s)." -Data $rows
