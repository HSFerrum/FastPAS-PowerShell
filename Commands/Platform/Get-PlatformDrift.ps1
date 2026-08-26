[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$platformId = [string]$Arguments['PlatformId'];
$baselinePath = [string]$Arguments['BaselinePath'];
$warnings = [Collections.Generic.List[string]]::new();
$platforms = @(Get-FastPASPagedItems -Context $Context -Path 'Platforms/Targets' -CollectionNames @('Platforms', 'value', 'TargetPlatforms'))
if (-not $platforms.Count) { $platforms = @(Get-FastPASPagedItems -Context $Context -Path 'Platforms' -CollectionNames @('Platforms', 'value', 'TargetPlatforms')) }
$snapshots = [Collections.Generic.List[object]]::new();
foreach ($summary in $platforms) {
    $id = Get-FastPASObjectString $summary @('ID', 'id', 'PlatformID', 'platformId');
    if ($platformId -and $id -ne $platformId) { continue };
    $details = $null;
    $scope = 'LegacyDetails';
    try {
        $details = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Platforms/targets/$([uri]::EscapeDataString($id))/settings";
        $scope = 'TargetSettings'
    }
    catch {
        try {
            $details = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Platforms/$([uri]::EscapeDataString($id))";
            $warnings.Add("Platform '$id' target settings are unavailable; captured legacy read-only details instead. Drift apply is not supported for this snapshot.")
        }
        catch {
            $warnings.Add("Platform '$id' details were unavailable: $($_.Exception.Message)");
            continue
        }
    };
    $snapshots.Add([pscustomobject][ordered]@{PlatformId = $id;
            PlatformName = Get-FastPASObjectString $details @('PolicyName', 'policyName', 'Name', 'name') $id;
            Scope = $scope;
            Enabled = Get-FastPASPropertyValue $summary @('Active', 'active', 'Enabled', 'enabled');
            Hash = Get-FastPASObjectHash $details;
            Details = $details
        })
}
$baseline = @{};
if ($baselinePath) {
    if (-not(Test-Path -LiteralPath $baselinePath -PathType Leaf)) { throw 'BaselinePath does not identify an existing JSON baseline.' };
    $raw = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json -Depth 100;
    foreach ($entry in @($raw)) { $baseline[[string]$entry.PlatformId] = $entry }
}
$rows = foreach ($entry in $snapshots) {
    $old = if ($baseline.ContainsKey($entry.PlatformId)) { $baseline[$entry.PlatformId] }else { $null };
    [pscustomobject]@{PlatformId = $entry.PlatformId;
        PlatformName = $entry.PlatformName;
        Scope = $entry.Scope;
        Enabled = $entry.Enabled;
        CurrentHash = $entry.Hash;
        BaselineHash = if ($old) { [string]$old.Hash }else { '' };
        State = if (-not $baselinePath) { 'Baseline captured' }elseif (-not $old) { 'New' }elseif ([string]$old.Hash -eq $entry.Hash) { 'Unchanged' }else { 'Drifted' };
        ChangedPaths = if ($old -and [string]$old.Hash -ne $entry.Hash) { 'Configuration hash differs; inspect the current and baseline JSON.' }else { '' }
    }
}
$json = Export-FastPASJson @($snapshots) $OutputPath 'platform_baseline';
$data = @($rows | Sort-Object State, PlatformId);
$csv = Export-FastPASCsv $data $OutputPath 'platform_drift';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'platform_drift' 'FastPAS Platform Configuration Drift' @{Platforms = $data.Count;
    Drifted = @($data | Where-Object State -EQ Drifted).Count;
    New = @($data | Where-Object State -EQ New).Count;
    Unchanged = @($data | Where-Object State -EQ Unchanged).Count
}
$summary = if ($baselinePath) {
    "Compared $($data.Count) platform(s) with the supplied baseline."
}
else {
    "Captured a full baseline for $($data.Count) platform(s)."
}
New-FastPASResult -Success $true -Summary $summary -Data $data -Warnings @($warnings) -Artifacts @($json, $csv, $html)
