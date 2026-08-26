[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$id = [string]$Arguments['AccountId']
if ([string]::IsNullOrWhiteSpace($id)) { throw 'AccountId is required.' }
$account = Resolve-FastPASAccount -Context $Context -AccountId $id
New-FastPASResult -Success $true -Summary "Returned account '$id'." -Data @($account)
