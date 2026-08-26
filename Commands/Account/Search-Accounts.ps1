[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$query = @{}
if ($Arguments['Search']) { $query.search = [string]$Arguments['Search'] }
if ($Arguments['SafeName']) { $query.filter = "safeName eq $([string]$Arguments['SafeName'])" }
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -Query $query -CollectionNames @('value', 'Accounts'))
$rows = @($accounts | ForEach-Object { ConvertTo-FastPASAccountRow $_ })
New-FastPASResult -Success $true -Summary "Returned $($rows.Count) account(s)." -Data $rows
