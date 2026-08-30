[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$safeQuery = @{};
if ($Arguments['SafeName']) { $safeQuery.search = [string]$Arguments['SafeName'] }
$safes = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -Query $safeQuery -CollectionNames @('value', 'Safes'))
$rows = [Collections.Generic.List[object]]::new();
$warnings = [Collections.Generic.List[string]]::new()
foreach ($safe in $safes) {
    $name = Get-FastPASObjectString $safe @('safeName', 'SafeName');
    if ($Arguments['SafeName'] -and $name -ne [string]$Arguments['SafeName']) { continue }
    $safeUrlId = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId')
    $identifiers = @($safeUrlId, $name | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $members = $null
    $lookupErrors = [Collections.Generic.List[string]]::new()
    foreach ($identifier in $identifiers) {
        try {
            $members = @(Get-FastPASPagedItems -Context $Context -Path "Safes/$([uri]::EscapeDataString($identifier))/Members" -CollectionNames @('value', 'Members') -Limit 100)
            break
        }
        catch {
            $lookupErrors.Add($_.Exception.Message)
            if ($_.Exception.Message -notmatch '(?i)HTTP\s+404') { break }
        }
    }
    if ($null -eq $members) {
        $warnings.Add("${name}: $($lookupErrors -join ' Alternate identifier also failed: ')")
        continue
    }
    foreach ($member in $members) {
        $permissions = Get-FastPASPropertyValue $member @('permissions', 'Permissions');
        $memberType = Get-FastPASObjectString $member @('memberType', 'MemberType') 'user';
        $record = [ordered]@{
            SafeName = $name;
            UserName = Get-FastPASObjectString $member @('memberName', 'MemberName', 'userName');
            MemberType = $memberType
            IdentityType = if ($memberType -match '(?i)group') { 'GROUP' }else { 'USER' };
            IsGroup = ($memberType -match '(?i)group')
            UserLocation = Get-FastPASObjectString $member @('searchIn', 'SearchIn', 'memberLocation', 'MemberLocation') 'Vault'
        }
        foreach ($entry in (Get-FastPASPermissionColumnMap).GetEnumerator()) { $record[$entry.Key] = Get-FastPASPropertyValue $permissions @($entry.Value) }
        $rows.Add([pscustomobject]$record)
    }
}
$data = @($rows | Sort-Object SafeName, @{Expression = { if ($_.IsGroup) { 0 }else { 1 } } }, UserName);
$csv = Export-FastPASCsv $data $OutputPath 'safe_membership';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'safe_membership' 'FastPAS Safe Membership' @{Safes = @($data.SafeName | Sort-Object -Unique).Count;
    Members = $data.Count;
    Groups = @($data | Where-Object IsGroup).Count;
    Users = @($data | Where-Object { -not $_.IsGroup }).Count
}
New-FastPASResult -Success $true -Summary "Exported $($data.Count) safe membership row(s)." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
