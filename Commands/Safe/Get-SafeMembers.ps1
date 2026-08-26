[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$name = [string]$Arguments['SafeName']
if ([string]::IsNullOrWhiteSpace($name)) { throw 'SafeName is required.' }
$safe = Resolve-FastPASSafe -Context $Context -SafeName $name
$id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId')
$members = @(Get-FastPASPagedItems -Context $Context -Path "Safes/$([uri]::EscapeDataString($id))/Members" -CollectionNames @('value', 'Members') -Limit 100)
$rows = @($members | ForEach-Object {
        $permissions = Get-FastPASPropertyValue $_ @('permissions', 'Permissions')
        [pscustomobject]@{SafeName = $name;
            MemberName = Get-FastPASObjectString $_ @('memberName', 'MemberName', 'userName');
            MemberType = Get-FastPASObjectString $_ @('memberType', 'MemberType');
            MemberId = Get-FastPASObjectString $_ @('memberId', 'MemberId');
            Permissions = ($permissions | ConvertTo-Json -Compress -Depth 10)
        }
    })
New-FastPASResult -Success $true -Summary "Returned $($rows.Count) member(s) for '$name'." -Data $rows
