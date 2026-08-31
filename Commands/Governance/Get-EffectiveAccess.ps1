[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$principal = [string]$Arguments['Principal'];
$safeFilter = [string]$Arguments['SafeName'];
$rows = [Collections.Generic.List[object]]::new();
$warnings = [Collections.Generic.List[string]]::new()
$groups = @(Get-FastPASOptionalItems -Context $Context -Paths @('UserGroups') -Query @{includeMembers = 'true' } -CollectionNames @('value', 'UserGroups', 'Groups') -Warnings $warnings);
$groupMap = @{}
foreach ($group in $groups) {
    $groupName = Get-FastPASObjectString $group @('groupName', 'GroupName', 'name', 'Name');
    if ($groupName) { $groupMap[$groupName] = @(Get-FastPASPropertyValue $group @('members', 'Members')) }
}
$safes = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -Query $(if ($safeFilter) { @{search = $safeFilter } }else { @{} }) -CollectionNames @('value', 'Safes'))
foreach ($safe in $safes) {
    $safeName = Get-FastPASObjectString $safe @('safeName', 'SafeName');
    if ($safeFilter -and $safeName -ne $safeFilter) { continue };
    $id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId');
    if (-not $id) { continue }
    try {
        $members = @(Get-FastPASPagedItems -Context $Context -Path "Safes/$([uri]::EscapeDataString($id))/Members" -CollectionNames @('value', 'Members'))
        foreach ($member in $members) {
            $name = Get-FastPASObjectString $member @('memberName', 'MemberName', 'userName');
            $memberType = Get-FastPASObjectString $member @('memberType', 'MemberType') 'Unknown';
            $principals = [Collections.Generic.List[object]]::new();
            $principals.Add([pscustomobject]@{Name = $name;
                    Type = $memberType;
                    Path = if ($memberType -match '(?i)group|role') { 'GroupOrRole' }else { 'Direct' };
                    SourceGroup = ''
                })
            if ($memberType -match '(?i)group' -and $groupMap.ContainsKey($name)) {
                foreach ($groupMember in @($groupMap[$name])) {
                    $expanded = if ($groupMember -is [string]) { [string]$groupMember }else { Get-FastPASObjectString $groupMember @('memberName', 'MemberName', 'userName', 'UserName', 'name', 'Name') };
                    if ($expanded) {
                        $principals.Add([pscustomobject]@{Name = $expanded;
                                Type = 'EffectiveUser';
                                Path = "Group:$name";
                                SourceGroup = $name
                            })
                    }
                }
            }
            $p = Get-FastPASPropertyValue $member @('permissions', 'Permissions');
            $retrieve = [bool](Get-FastPASPropertyValue $p @('retrieveAccounts', 'RetrieveAccounts'));
            $use = [bool](Get-FastPASPropertyValue $p @('useAccounts', 'UseAccounts'));
            $manage = [bool](Get-FastPASPropertyValue $p @('manageSafeMembers', 'ManageSafeMembers'));
            $authorize = [bool](Get-FastPASPropertyValue $p @('requestsAuthorizationLevel1', 'RequestsAuthorizationLevel1', 'requestsAuthorizationLevel2', 'RequestsAuthorizationLevel2'))
            foreach ($resolved in $principals) {
                if ($principal -and $resolved.Name -notlike "*$principal*") { continue };
                $rows.Add([pscustomobject][ordered]@{Principal = $resolved.Name;
                        PrincipalType = $resolved.Type;
                        SafeName = $safeName;
                        AccessPath = $resolved.Path;
                        SourceGroup = $resolved.SourceGroup;
                        ListAccounts = [bool](Get-FastPASPropertyValue $p @('listAccounts', 'ListAccounts'));
                        UseAccounts = $use;
                        RetrieveAccounts = $retrieve;
                        ManageMembers = $manage;
                        AuthorizeRequests = $authorize;
                        Risk = if ($retrieve -and $manage) { 'High' }elseif ($retrieve -or $manage) { 'Medium' }else { 'Low' };
                        Permissions = ($p | ConvertTo-Json -Compress -Depth 10)
                    })
            }
        }
    }
    catch { $warnings.Add("Safe '$safeName' members were unavailable: $($_.Exception.Message)") }
}
$users = @(Get-FastPASOptionalItems -Context $Context -Paths @('Users') -CollectionNames @('value', 'Users') -Warnings $warnings)
$deploymentType = if ($Context.PSObject.Properties['DeploymentType'] -and $Context.DeploymentType) { [string]$Context.DeploymentType }
elseif ($Context.Profile.PSObject.Properties['DeploymentType'] -and $Context.Profile.DeploymentType) { [string]$Context.Profile.DeploymentType }
else { 'ispss' }
$license = @()
if ($deploymentType -eq 'ispss') {
    try { $license = @(Invoke-FastPASApiRequest -Context $Context -Method GET -Path 'licenses/pcloud/') }
    catch { $warnings.Add("Privilege Cloud license data is unavailable for this tenant or role: $($_.Exception.Message)") }
}
$data = @($rows | Sort-Object Principal, SafeName);
$csv = Export-FastPASCsv $data $OutputPath 'effective_access';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'effective_access' 'FastPAS Effective Access and License Governance' @{Safes = $safes.Count;
    Assignments = $data.Count;
    Principals = @($data | ForEach-Object Principal | Where-Object { $_ } | Sort-Object -Unique).Count;
    HighRisk = @($data | Where-Object Risk -EQ High).Count;
    VaultUsers = $users.Count;
    LicenseRecords = $license.Count
}
$licenseArtifact = if ($license.Count) { Export-FastPASJson $license $OutputPath 'license_capacity' }else { $null }
$summary = "Exported $($data.Count) direct/group/effective assignments across $($safes.Count) safes; $($groups.Count) groups were available for expansion."
$artifacts = @($csv, $html, $licenseArtifact | Where-Object { $_ })
New-FastPASResult -Success $true -Summary $summary -Data $data -Warnings @($warnings) -Artifacts $artifacts
