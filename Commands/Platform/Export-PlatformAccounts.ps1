[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -CollectionNames @('value', 'Accounts'))
$platformId = [string]$Arguments['PlatformId']
$rows = @($accounts | ForEach-Object { ConvertTo-FastPASAccountRow $_ } | Where-Object { -not $platformId -or $_.PlatformId -eq $platformId } | Sort-Object PlatformId, SafeName, Name)
$csv = Export-FastPASCsv $rows $OutputPath 'accounts_by_platform';
$html = Export-FastPASHtmlDashboard $rows $OutputPath 'accounts_by_platform' 'FastPAS Accounts by Platform' @{Accounts = $rows.Count;
    Platforms = @($rows.PlatformId | Sort-Object -Unique).Count;
    Safes = @($rows.SafeName | Sort-Object -Unique).Count
}
New-FastPASResult -Success $true -Summary "Exported $($rows.Count) account(s) across $(@($rows.PlatformId|Sort-Object -Unique).Count) platform(s)." -Data $rows -Artifacts @($csv, $html)
