[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$safeName = [string]$Arguments['SafeName'];
$max = if ($Arguments['MaxAccounts']) { [int]$Arguments['MaxAccounts'] }else { 500 };
if ($max -lt 1 -or $max -gt 10000) { throw 'MaxAccounts must be between 1 and 10000.' }
$query = if ($safeName) { @{filter = "safeName eq $safeName" } }else { @{} };
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -Query $query -CollectionNames @('value', 'Accounts') | Select-Object -First $max);
$rows = [Collections.Generic.List[object]]::new();
$warnings = [Collections.Generic.List[string]]::new();
$accountIds = @{};
foreach ($a in $accounts) { $accountIds[(Get-FastPASObjectString $a @('id', 'ID'))] = $true }
foreach ($summary in $accounts) {
    $id = Get-FastPASObjectString $summary @('id', 'ID');
    if (-not $id) { continue };
    try { $account = Resolve-FastPASAccount $Context $id }catch {
        $warnings.Add("Account '$id' details were unavailable: $($_.Exception.Message)");
        continue
    }
    $source = ConvertTo-FastPASAccountRow $account;
    $links = @(Get-FastPASPropertyValue $account @('linkedAccounts', 'LinkedAccounts'))
    foreach ($property in @(@('logonAccount', 'LogonAccount'), @('reconcileAccount', 'ReconcileAccount'), @('dependencies', 'Dependencies'), @('usages', 'Usages'))) {
        $value = Get-FastPASPropertyValue $account $property;
        if ($value) { $links += @($value) }
    }
    if (-not $links.Count) {
        $rows.Add([pscustomobject]@{SourceAccountId = $id;
                SourceAccount = $source.Name;
                SafeName = $source.SafeName;
                RelationshipType = 'None returned';
                TargetAccountId = '';
                TargetAccount = '';
                TargetSafe = '';
                State = 'Unmapped';
                Detail = 'No linked/dependent relationship was returned by account details.'
            });
        continue
    }
    foreach ($link in $links) {
        $targetId = Get-FastPASObjectString $link @('accountId', 'AccountID', 'id', 'ID');
        $type = Get-FastPASObjectString $link @('type', 'Type', 'relationshipType', 'RelationshipType', 'extraPasswordIndex') 'Dependent';
        $targetName = Get-FastPASObjectString $link @('name', 'Name', 'accountName', 'AccountName');
        $targetSafe = Get-FastPASObjectString $link @('safe', 'Safe', 'safeName', 'SafeName');
        $rows.Add([pscustomobject]@{SourceAccountId = $id;
                SourceAccount = $source.Name;
                SafeName = $source.SafeName;
                RelationshipType = $type;
                TargetAccountId = $targetId;
                TargetAccount = $targetName;
                TargetSafe = $targetSafe;
                State = if ($targetId -and -not $accountIds.ContainsKey($targetId)) { 'ExternalOrMissing' }elseif (-not $targetId -and -not $targetName) { 'Broken' }else { 'Linked' };
                Detail = ($link | ConvertTo-Json -Compress -Depth 20)
            })
    }
}
$data = @($rows | Sort-Object State, SafeName, SourceAccount, RelationshipType);
$csv = Export-FastPASCsv $data $OutputPath 'account_relationships';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'account_relationships' 'FastPAS Linked and Dependent Account Relationships' @{AccountsScanned = $accounts.Count;
    Relationships = @($data | Where-Object RelationshipType -NE 'None returned').Count;
    Unmapped = @($data | Where-Object State -EQ Unmapped).Count;
    Broken = @($data | Where-Object State -EQ Broken).Count
}
New-FastPASResult -Success $true -Summary "Mapped relationship data for $($accounts.Count) account(s). MaxAccounts prevents an accidental tenant-wide detail-call storm." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
