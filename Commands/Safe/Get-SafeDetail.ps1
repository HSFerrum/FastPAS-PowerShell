[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$name = [string]$Arguments['SafeName']
if ([string]::IsNullOrWhiteSpace($name)) { throw 'SafeName is required.' }
$safe = Resolve-FastPASSafe -Context $Context -SafeName $name
$id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId')
$detail = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Safes/$([uri]::EscapeDataString($id))"
New-FastPASResult -Success $true -Summary "Returned details for safe '$name'." -Data @($detail)
