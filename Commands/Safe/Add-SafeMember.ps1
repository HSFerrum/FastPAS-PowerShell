[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$safeName = [string]$Arguments['SafeName'];
$memberName = [string]$Arguments['MemberName']
if ([string]::IsNullOrWhiteSpace($safeName) -or [string]::IsNullOrWhiteSpace($memberName)) { throw 'SafeName and MemberName are required.' }
$memberType = if ($Arguments['MemberType']) { [string]$Arguments['MemberType'] }else { 'user' }
if ($memberType -notin @('user', 'group')) { throw 'MemberType must be user or group.' }
$role = if ($Arguments['Role']) { [string]$Arguments['Role'] }else { 'Viewer' }
if ($role -notin @('Viewer', 'Operator', 'Manager')) { throw 'Role must be Viewer, Operator, or Manager.' }
$safe = Resolve-FastPASSafe -Context $Context -SafeName $safeName;
$id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId')
$body = [ordered]@{memberName = $memberName;
    searchIn = if ($Arguments['SearchIn']) { [string]$Arguments['SearchIn'] }else { 'Vault' };
    memberType = $memberType;
    permissions = (Get-FastPASSafePermissions $role)
}
if (-not $PSCmdlet.ShouldProcess("$memberName on $safeName", "Add safe member with $role role")) {
    return New-FastPASResult -Success $true -Summary "WhatIf: would add '$memberName' to '$safeName' as $role." -Data @([pscustomobject]$body)
}
$created = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "Safes/$([uri]::EscapeDataString($id))/Members" -Body $body
New-FastPASResult -Success $true -Summary "Added '$memberName' to '$safeName' as $role." -Data @($created) -AuditEvents @([pscustomobject]@{Action = 'AddSafeMember';
        Safe = $safeName;
        Member = $memberName;
        Role = $role
    })
