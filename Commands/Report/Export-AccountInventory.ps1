[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$query = @{};
if ($Arguments['Search']) { $query.search = [string]$Arguments['Search'] };
if ($Arguments['SafeName']) { $query.filter = "safeName eq $([string]$Arguments['SafeName'])" }
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -Query $query -CollectionNames @('value', 'Accounts'))
$rows = @($accounts | ForEach-Object { ConvertTo-FastPASAccountRow $_ } | Sort-Object SafeName, Name)
$csv = Export-FastPASCsv -Data $rows -OutputPath $OutputPath -Prefix 'account_inventory'
$html = Export-FastPASHtmlDashboard -Data $rows -OutputPath $OutputPath -Prefix 'account_inventory' -Title 'FastPAS Account Inventory' -Metrics @{Accounts = $rows.Count;
    Safes = @($rows.SafeName | Sort-Object -Unique).Count;
    Failures = @($rows | Where-Object ManagementStatus -EQ 'failure').Count
}
New-FastPASResult -Success $true -Summary "Exported $($rows.Count) account(s)." -Data $rows -Artifacts @($csv, $html)
