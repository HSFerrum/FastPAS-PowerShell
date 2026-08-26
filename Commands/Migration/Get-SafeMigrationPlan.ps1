[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify a safe-account-migrations CSV.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The CSV contains no migration rows.' };
$rows = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $id = [string]$item.AccountId;
    $destination = [string]$item.DestinationSafeName;
    $state = 'Ready';
    $detail = 'Validated';
    $hash = '';
    $source = '';
    $name = '';
    $links = 'Unknown';
    try {
        if (-not $id -or -not $destination) { throw 'AccountId and DestinationSafeName are required.' };
        $account = Resolve-FastPASAccount $Context $id;
        $source = Get-FastPASObjectString $account @('safeName', 'SafeName');
        $name = Get-FastPASObjectString $account @('name', 'Name');
        $hash = Get-FastPASObjectHash $account;
        if ($source -eq $destination) { throw 'Source and destination safes are the same.' };
        $null = Resolve-FastPASSafe $Context $destination;
        $dupes = @(Get-FastPASPagedItems -Context $Context -Path Accounts -Query @{search = $name;
                filter = "safeName eq $destination"
            } -CollectionNames @('value', 'Accounts') | Where-Object { (Get-FastPASObjectString $_ @('name', 'Name')) -eq $name });
        if ($dupes.Count) { throw "Destination already contains $($dupes.Count) account(s) named '$name'." };
        $linked = @(Get-FastPASPropertyValue $account @('linkedAccounts', 'LinkedAccounts', 'logonAccount', 'LogonAccount', 'reconcileAccount', 'ReconcileAccount'));
        $links = if ($linked.Count) { "$($linked.Count) returned relationship object(s); verify after move." }else { 'No relationship objects returned.' }
    }
    catch {
        $state = 'Blocked';
        $detail = $_.Exception.Message
    };
    $rows.Add([pscustomobject][ordered]@{AccountId = $id;
            AccountName = $name;
            SourceSafeName = $source;
            DestinationSafeName = $destination;
            ExpectedAccountHash = $hash;
            State = $state;
            RelationshipCheck = $links;
            Detail = $detail
        })
}
$data = @($rows);
$csv = Export-FastPASCsv $data $OutputPath 'safe_migration_plan';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'safe_migration_plan' 'FastPAS Safe-to-Safe Account Migration Plan' @{Accounts = $data.Count;
    Ready = @($data | Where-Object State -EQ Ready).Count;
    Blocked = @($data | Where-Object State -EQ Blocked).Count;
    DestinationSafes = @($data | ForEach-Object DestinationSafeName | Where-Object { $_ } | Sort-Object -Unique).Count
}
$readyCount = @($data | Where-Object State -EQ Ready).Count
$blockedCount = @($data | Where-Object State -EQ Blocked).Count
$summary = "Planned $($data.Count) migration(s): $readyCount ready and $blockedCount blocked. Apply the generated plan, not the original input."
New-FastPASResult -Success $true -Summary $summary -Data $data -Artifacts @($csv, $html)
