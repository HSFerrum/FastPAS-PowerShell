[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$passwordAge = if ($Arguments['PasswordAgeDays']) { [int]$Arguments['PasswordAgeDays'] }else { 90 }
$inactiveDays = if ($Arguments['InactiveDays']) { [int]$Arguments['InactiveDays'] }else { 90 }
if ($passwordAge -lt 1 -or $passwordAge -gt 3650) { throw 'PasswordAgeDays must be between 1 and 3650.' }
if ($inactiveDays -lt 1 -or $inactiveDays -gt 3650) { throw 'InactiveDays must be between 1 and 3650.' }
$findings = [Collections.Generic.List[object]]::new();
$warnings = [Collections.Generic.List[string]]::new()
function Add-Finding {
    param($Severity, $Category, $ObjectType, $Name, $Safe, $Detail, $Recommendation)

    $findings.Add([pscustomobject][ordered]@{Severity = $severity;
            Category = $category;
            ObjectType = $objectType;
            Name = $name;
            SafeName = $safe;
            Detail = $detail;
            Recommendation = $recommendation
        })
}
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -CollectionNames @('value', 'Accounts'))
$duplicateGroups = $accounts | Group-Object { "$(Get-FastPASObjectString $_ @('safeName','SafeName'))|$(Get-FastPASObjectString $_ @('userName','UserName'))|$(Get-FastPASObjectString $_ @('address','Address'))" } | Where-Object Count -GT 1
foreach ($group in $duplicateGroups) {
    Add-Finding -Severity High -Category 'Duplicate account' -ObjectType Account `
        -Name $group.Name.Split('|')[1] -Safe $group.Name.Split('|')[0] `
        -Detail "$($group.Count) accounts share the same safe, username, and address." `
        -Recommendation 'Review and retire unintended duplicates.'
}
foreach ($account in $accounts) {
    $row = ConvertTo-FastPASAccountRow $account;
    $management = Get-FastPASPropertyValue $account @('secretManagement', 'SecretManagement')
    if ($row.Locked) {
        Add-Finding -Severity High -Category 'Locked account' -ObjectType Account -Name $row.Name -Safe $row.SafeName `
            -Detail 'The Vault account is locked.' -Recommendation 'Validate ownership and unlock when appropriate.'
    }
    if ($row.ManagementStatus -match '(?i)fail|error' -or $row.FailureReason) {
        $failureDetail = if ($row.FailureReason) { $row.FailureReason } else { $row.ManagementStatus }
        Add-Finding -Severity High -Category 'CPM failure' -ObjectType Account -Name $row.Name -Safe $row.SafeName `
            -Detail $failureDetail -Recommendation 'Investigate the platform, reconcile account, connectivity, and target state.'
    }
    if ($row.AutomaticManagementEnabled -eq $false) {
        Add-Finding -Severity Medium -Category 'Automatic management disabled' -ObjectType Account -Name $row.Name -Safe $row.SafeName `
            -Detail 'Automatic password management is disabled.' -Recommendation 'Confirm the exception is approved or re-enable automatic management.'
    }
    $changed = ConvertFrom-FastPASEpoch (Get-FastPASPropertyValue $management @('lastModifiedTime', 'LastModifiedTime', 'lastPasswordChange', 'LastPasswordChange'))
    if ($changed -and $changed -lt [DateTimeOffset]::UtcNow.AddDays(-$passwordAge)) {
        Add-Finding -Severity Medium -Category 'Password age' -ObjectType Account -Name $row.Name -Safe $row.SafeName `
            -Detail "Last managed change was $($changed.ToString('u'))." -Recommendation 'Rotate or document the approved exception.'
    }
    if (-not $row.PlatformId) {
        Add-Finding -Severity High -Category 'Missing platform' -ObjectType Account -Name $row.Name -Safe $row.SafeName `
            -Detail 'No target platform was returned.' -Recommendation 'Assign a valid platform.'
    }
}
$safes = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -CollectionNames @('value', 'Safes'))
foreach ($safe in $safes) {
    $name = Get-FastPASObjectString $safe @('safeName', 'SafeName');
    $id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId');
    if (-not $id) { continue }
    try {
        $members = @(Get-FastPASPagedItems -Context $Context -Path "Safes/$([uri]::EscapeDataString($id))/Members" -CollectionNames @('value', 'Members'))
        $safeAccounts = @($accounts | Where-Object { (Get-FastPASObjectString $_ @('safeName', 'SafeName')) -eq $name })
        if (-not $safeAccounts.Count) {
            Add-Finding -Severity Low -Category 'Empty safe' -ObjectType Safe -Name $name -Safe $name `
                -Detail 'The safe contains no returned accounts.' -Recommendation 'Confirm the safe is still required.'
        }
        if (-not $members.Count) {
            Add-Finding -Severity Critical -Category 'No safe members' -ObjectType Safe -Name $name -Safe $name `
                -Detail 'The safe has no returned members.' -Recommendation 'Restore an approved owner group immediately.'
            continue
        }
        $managers = @($members | Where-Object { [bool](Get-FastPASPropertyValue (Get-FastPASPropertyValue $_ @('permissions', 'Permissions')) @('manageSafeMembers', 'ManageSafeMembers', 'manageSafe', 'ManageSafe')) })
        if (-not $managers.Count) {
            Add-Finding -Severity High -Category 'Missing owner' -ObjectType Safe -Name $name -Safe $name `
                -Detail 'No member with safe-management permissions was returned.' -Recommendation 'Assign an approved owner group.'
        }
        foreach ($member in $members) {
            $permissions = Get-FastPASPropertyValue $member @('permissions', 'Permissions');
            $memberName = Get-FastPASObjectString $member @('memberName', 'MemberName', 'userName')
            if ([bool](Get-FastPASPropertyValue $permissions @('retrieveAccounts', 'RetrieveAccounts')) -and [bool](Get-FastPASPropertyValue $permissions @('manageSafeMembers', 'ManageSafeMembers'))) {
                Add-Finding -Severity Medium -Category 'Broad safe privilege' -ObjectType 'Safe member' -Name $memberName -Safe $name `
                    -Detail 'The principal can retrieve accounts and manage safe members.' -Recommendation 'Validate separation of duties and least privilege.'
            }
        }
    }
    catch { $warnings.Add("Safe '$name' could not be fully assessed: $($_.Exception.Message)") }
}
$users = @(Get-FastPASOptionalItems -Context $Context -Paths @('Users') -CollectionNames @('value', 'Users') -Warnings $warnings)
foreach ($user in $users) {
    $name = Get-FastPASObjectString $user @('username', 'userName', 'UserName', 'name');
    $last = ConvertFrom-FastPASEpoch (Get-FastPASPropertyValue $user @('lastSuccessfulLoginDate', 'LastSuccessfulLoginDate', 'lastLogin'))
    if ([bool](Get-FastPASPropertyValue $user @('suspended', 'Suspended', 'isSuspended'))) {
        Add-Finding -Severity Medium -Category 'Suspended user' -ObjectType User -Name $name -Safe '' `
            -Detail 'The Vault user is suspended.' -Recommendation 'Confirm whether access should be removed.'
    }
    if ($last -and $last -lt [DateTimeOffset]::UtcNow.AddDays(-$inactiveDays)) {
        Add-Finding -Severity Medium -Category 'Inactive user' -ObjectType User -Name $name -Safe '' `
            -Detail "Last successful login was $($last.ToString('u'))." -Recommendation 'Review the entitlement and disable unused identities.'
    }
}
$severityOrder = @{Critical = 0;
    High = 1;
    Medium = 2;
    Low = 3
};
$data = @($findings | Sort-Object @{Expression = { $severityOrder[$_.Severity] } }, Category, SafeName, Name)
$csv = Export-FastPASCsv $data $OutputPath 'compliance_posture';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'compliance_posture' 'FastPAS Compliance and Hygiene Command Center' @{Critical = @($data | Where-Object Severity -EQ Critical).Count;
    High = @($data | Where-Object Severity -EQ High).Count;
    Medium = @($data | Where-Object Severity -EQ Medium).Count;
    Accounts = $accounts.Count;
    Safes = $safes.Count
}
$highPriorityCount = @($data | Where-Object Severity -In 'Critical', 'High').Count
$summary = "Completed compliance assessment: $($data.Count) finding(s), including $highPriorityCount critical/high."
New-FastPASResult -Success $true -Summary $summary -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
